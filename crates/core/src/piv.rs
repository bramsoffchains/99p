//! Minimal PIV APDU client (SPEC §7) over the `SmartCard` transport.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use zeroize::Zeroize;

use crate::card::SmartCard;
use crate::crypto;
use crate::error::{Error, Result};
use crate::secret::SecretBytes;

pub const PIV_AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];
pub const SLOT_MGMT: u8 = 0x9B;
pub const ALG_3DES: u8 = 0x03;
pub const ALG_AES192: u8 = 0x0A;
pub const ALG_AES256: u8 = 0x0C;
pub const ALG_ECCP256: u8 = 0x11;
pub const DEFAULT_MGMT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

pub const SW_OK: u16 = 0x9000;
pub const SW_SECURITY: u16 = 0x6982;
pub const SW_NOT_FOUND: u16 = 0x6A82;
/// "Referenced data not found": what a YubiKey 5.7 returns for the metadata
/// of an empty slot.
pub const SW_REF_NOT_FOUND: u16 = 0x6A88;
pub const SW_NVM_FULL: u16 = 0x6A84;
/// PIN or PUK blocked ("authentication method blocked").
pub const SW_BLOCKED: u16 = 0x6983;

/// PIV references for VERIFY / CHANGE REFERENCE DATA.
pub const REF_PIN: u8 = 0x80;
pub const REF_PUK: u8 = 0x81;
pub const DEFAULT_PIN: &[u8] = b"123456";
pub const DEFAULT_PUK: &[u8] = b"12345678";
/// PIN tries set at provisioning (SPEC §8.1), the YubiKey maximum. There is
/// no PUK: it is blocked, so the 255th wrong passphrase bricks the vault.
pub const PIN_RETRIES: u8 = 255;

/// A PIN or PUK padded with 0xFF to 8 bytes, as PIV requires.
pub fn pad_pin(pin: &[u8]) -> Result<[u8; 8]> {
    if pin.len() < 6 || pin.len() > 8 {
        return Err(Error::Invalid("PIN length"));
    }
    let mut out = [0xFF; 8];
    out[..pin.len()].copy_from_slice(pin);
    Ok(out)
}

/// Single-block ECB with a management key (`encrypt = false` decrypts).
pub fn mgmt_block(alg: u8, key: &[u8], block: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    fn run<C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit>(
        key: &[u8],
        block: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>> {
        let c = C::new_from_slice(key).map_err(|_| Error::Invalid("management key length"))?;
        let mut b = aes::cipher::Array::try_from(block).map_err(|_| Error::Format("block size"))?;
        if encrypt {
            c.encrypt_block(&mut b)
        } else {
            c.decrypt_block(&mut b)
        }
        Ok(b.to_vec())
    }
    match alg {
        ALG_3DES => run::<des::TdesEde3>(key, block, encrypt),
        ALG_AES192 => run::<aes::Aes192>(key, block, encrypt),
        ALG_AES256 => run::<aes::Aes256>(key, block, encrypt),
        _ => Err(Error::Unsupported("management key algorithm")),
    }
}

pub fn mgmt_block_len(alg: u8) -> usize {
    if alg == ALG_3DES { 8 } else { 16 }
}

/// BER-TLV length.
pub fn ber_len(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0x7f => out.push(n as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, n as u8]),
        _ => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
}

pub fn ber_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    out.extend_from_slice(tag);
    ber_len(out, value.len());
    out.extend_from_slice(value);
}

/// Parses BER-TLV with 1-byte tags, or 2-byte tags for `5F xx` / `7F xx`.
pub fn ber_parse(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    let bad = Error::Format("BER-TLV");
    while !b.is_empty() {
        let (tag, rest) = if (b[0] == 0x5F || b[0] == 0x7F) && b.len() > 1 {
            (u16::from_be_bytes([b[0], b[1]]), &b[2..])
        } else {
            (u16::from(b[0]), &b[1..])
        };
        let (len, rest) = match rest.first() {
            Some(&n) if n < 0x80 => (n as usize, &rest[1..]),
            Some(0x81) if rest.len() > 1 => (rest[1] as usize, &rest[2..]),
            Some(0x82) if rest.len() > 2 => {
                (u16::from_be_bytes([rest[1], rest[2]]) as usize, &rest[3..])
            }
            _ => return Err(bad),
        };
        if rest.len() < len {
            return Err(bad);
        }
        out.push((tag, &rest[..len]));
        b = &rest[len..];
    }
    Ok(out)
}

fn find(items: &[(u16, &[u8])], tag: u16) -> Result<Vec<u8>> {
    items
        .iter()
        .find(|i| i.0 == tag)
        .map(|i| i.1.to_vec())
        .ok_or(Error::Format("missing TLV tag"))
}

/// Parsed slot metadata: `(tag, value)` pairs.
pub type Metadata = Vec<(u8, Vec<u8>)>;

pub struct Piv<C: SmartCard> {
    pub card: C,
}

impl<C: SmartCard> Piv<C> {
    pub fn new(card: C) -> Self {
        Piv { card }
    }

    /// Sends one command with chaining and GET RESPONSE. Returns data and SW.
    pub fn transceive(&mut self, hdr: [u8; 4], data: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut blocks: Vec<&[u8]> = data.chunks(255).collect();
        if blocks.is_empty() {
            blocks.push(&[]);
        }
        let last = blocks.len() - 1;
        let mut resp = Vec::new();
        for (i, blk) in blocks.iter().enumerate() {
            let mut apdu = hdr.to_vec();
            if i != last {
                apdu[0] |= 0x10;
            }
            if !blk.is_empty() {
                apdu.push(blk.len() as u8);
                apdu.extend_from_slice(blk);
            }
            apdu.push(0); // Le
            let r = self.card.transmit(&apdu);
            apdu.zeroize();
            resp = r?;
            if resp.len() < 2 {
                return Err(Error::Format("short response"));
            }
            if i != last {
                let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
                if sw != SW_OK {
                    return Ok((Vec::new(), sw));
                }
            }
        }
        let mut out = Vec::new();
        loop {
            let n = resp.len();
            let (sw1, sw2) = (resp[n - 2], resp[n - 1]);
            out.extend_from_slice(&resp[..n - 2]);
            resp.zeroize();
            if sw1 != 0x61 {
                return Ok((out, u16::from_be_bytes([sw1, sw2])));
            }
            resp = self.card.transmit(&[0x00, 0xC0, 0x00, 0x00, sw2])?;
            if resp.len() < 2 {
                return Err(Error::Format("short response"));
            }
        }
    }

    fn cmd(&mut self, hdr: [u8; 4], data: &[u8], context: &'static str) -> Result<Vec<u8>> {
        let (resp, sw) = self.transceive(hdr, data)?;
        match sw {
            SW_OK => Ok(resp),
            SW_NOT_FOUND | SW_REF_NOT_FOUND => Err(Error::NotFound),
            SW_NVM_FULL => Err(Error::Capacity {
                needed: data.len(),
                available: 0,
            }),
            sw => Err(Error::Card { sw, context }),
        }
    }

    pub fn select(&mut self) -> Result<()> {
        self.cmd([0x00, 0xA4, 0x04, 0x00], &PIV_AID, "select")
            .map(|_| ())
    }

    pub fn version(&mut self) -> Result<[u8; 3]> {
        let v = self.cmd([0x00, 0xFD, 0x00, 0x00], &[], "version")?;
        v.get(..3)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Format("version"))
    }

    pub fn serial(&mut self) -> Result<u32> {
        let v = self.cmd([0x00, 0xF8, 0x00, 0x00], &[], "serial")?;
        Ok(u32::from_be_bytes(
            v.get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Format("serial"))?,
        ))
    }

    /// Slot metadata TLV (fw ≥ 5.3), or `None` if the slot is empty.
    pub fn metadata(&mut self, slot: u8) -> Result<Option<Metadata>> {
        match self.cmd([0x00, 0xF7, 0x00, slot], &[], "metadata") {
            Ok(v) => Ok(Some(
                ber_parse(&v)?
                    .into_iter()
                    .map(|(t, v)| (t as u8, v.to_vec()))
                    .collect(),
            )),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Uncompressed public key in `slot`, if any.
    pub fn slot_pubkey(&mut self, slot: u8) -> Result<Option<Vec<u8>>> {
        let Some(md) = self.metadata(slot)? else {
            return Ok(None);
        };
        let Some((_, pk)) = md.iter().find(|(t, _)| *t == 0x04) else {
            return Ok(None);
        };
        Ok(Some(find(&ber_parse(pk)?, 0x86)?))
    }

    /// `(algorithm, is_default)` of the management key.
    pub fn mgmt_key_info(&mut self) -> Result<(u8, bool)> {
        let md = self.metadata(SLOT_MGMT)?.ok_or(Error::NotFound)?;
        let get = |t| {
            md.iter()
                .find(|(x, _)| *x == t)
                .and_then(|(_, v)| v.first().copied())
        };
        Ok((get(0x01).unwrap_or(ALG_3DES), get(0x05) == Some(1)))
    }

    pub fn get_data(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
        let t = tag.to_be_bytes();
        match self.cmd(
            [0x00, 0xCB, 0x3F, 0xFF],
            &[0x5C, 0x03, t[1], t[2], t[3]],
            "get data",
        ) {
            Ok(v) => {
                let items = ber_parse(&v)?;
                Ok(Some(find(&items, 0x53)?))
            }
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Writes an object; an empty value deletes it. Needs management key auth.
    pub fn put_data(&mut self, tag: u32, value: &[u8]) -> Result<()> {
        let t = tag.to_be_bytes();
        let mut d = vec![0x5C, 0x03, t[1], t[2], t[3]];
        ber_tlv(&mut d, &[0x53], value);
        match self.cmd([0x00, 0xDB, 0x3F, 0xFF], &d, "put data") {
            Err(Error::Capacity { .. }) => Err(Error::Capacity {
                needed: value.len(),
                available: 0,
            }),
            Err(Error::Card {
                sw: SW_SECURITY, ..
            }) => Err(Error::ManagementKey),
            r => r.map(|_| ()),
        }
    }

    /// Mutual authentication with the management key.
    pub fn authenticate(&mut self, alg: u8, key: &[u8]) -> Result<()> {
        let n = mgmt_block_len(alg);
        let hdr = [0x00, 0x87, alg, SLOT_MGMT];
        let r = self
            .cmd(hdr, &[0x7C, 0x02, 0x80, 0x00], "mgmt auth")
            .map_err(|e| match e {
                Error::Card { .. } => Error::ManagementKey,
                e => e,
            })?;
        let outer = ber_parse(&r)?;
        let witness_enc = find(&ber_parse(&find(&outer, 0x7C)?)?, 0x80)?;
        let mut witness = mgmt_block(alg, key, &witness_enc, false)?;
        let challenge: Vec<u8> = crypto::random_bytes::<16>()?[..n].to_vec();
        let mut inner = Vec::new();
        ber_tlv(&mut inner, &[0x80], &witness);
        ber_tlv(&mut inner, &[0x81], &challenge);
        let mut d = Vec::new();
        ber_tlv(&mut d, &[0x7C], &inner);
        witness.zeroize();
        let r = self.cmd(hdr, &d, "mgmt auth").map_err(|e| match e {
            Error::Card { .. } => Error::ManagementKey,
            e => e,
        })?;
        let resp = find(&ber_parse(&find(&ber_parse(&r)?, 0x7C)?)?, 0x82)?;
        if resp != mgmt_block(alg, key, &challenge, true)? {
            return Err(Error::ManagementKey);
        }
        Ok(())
    }

    /// SET MANAGEMENT KEY (requires prior authentication).
    pub fn set_mgmt_key(&mut self, alg: u8, key: &[u8]) -> Result<()> {
        let mut d = vec![alg, SLOT_MGMT, key.len() as u8];
        d.extend_from_slice(key);
        let r = self.cmd([0x00, 0xFF, 0xFF, 0xFF], &d, "set mgmt key");
        d.zeroize();
        r.map(|_| ())
    }

    /// Generates a P-256 key with PIN policy ALWAYS and touch policy ALWAYS.
    /// Returns the uncompressed public key.
    pub fn generate_p256(&mut self, slot: u8) -> Result<Vec<u8>> {
        let d = [
            0xAC,
            0x09,
            0x80,
            0x01,
            ALG_ECCP256,
            0xAA,
            0x01,
            0x03,
            0xAB,
            0x01,
            0x02,
        ];
        let r = self.cmd([0x00, 0x47, 0x00, slot], &d, "generate")?;
        let outer = ber_parse(&r)?;
        let pk = find(&ber_parse(&find(&outer, 0x7F49)?)?, 0x86)?;
        crypto::parse_pubkey(&pk)?;
        Ok(pk)
    }

    /// Maps a VERIFY / RESET RETRY status word to the PIN errors.
    fn pin_status(sw: u16, context: &'static str) -> Result<()> {
        match sw {
            SW_OK => Ok(()),
            SW_BLOCKED => Err(Error::PinBlocked),
            sw if sw & 0xFFF0 == 0x63C0 => Err(Error::WrongPin {
                tries_left: (sw & 0x0F) as u8,
            }),
            sw => Err(Error::Card { sw, context }),
        }
    }

    /// VERIFY the PIN (`REF_PIN`). A wrong PIN costs one try.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<()> {
        let mut d = pad_pin(pin)?;
        let r = self.transceive([0x00, 0x20, 0x00, REF_PIN], &d);
        d.zeroize();
        match Self::pin_status(r?.1, "verify") {
            // The status word caps the count at 15; metadata has the real one.
            Err(Error::WrongPin { .. }) => Err(Error::WrongPin {
                tries_left: self.pin_tries_left()?,
            }),
            r => r,
        }
    }

    /// Clears the card's PIN-verified status (VERIFY with P1 = 0xFF, SP 800-73-4).
    pub fn reset_pin_status(&mut self) -> Result<()> {
        match self.transceive([0x00, 0x20, 0xFF, REF_PIN], &[])?.1 {
            SW_OK => Ok(()),
            sw => Err(Error::Card { sw, context: "reset PIN status" }),
        }
    }

    /// Remaining PIN tries, without using one (VERIFY with no data). The
    /// status word holds only 4 bits, so counts above 15 read as 15; fw ≥ 5.3
    /// metadata gives the real number.
    pub fn pin_tries_left(&mut self) -> Result<u8> {
        if let Ok(Some(md)) = self.metadata(REF_PIN) {
            if let Some((_, v)) = md.iter().find(|(t, _)| *t == 0x06) {
                if v.len() == 2 {
                    return Ok(v[1]);
                }
            }
        }
        let (_, sw) = self.transceive([0x00, 0x20, 0x00, REF_PIN], &[])?;
        match Self::pin_status(sw, "verify") {
            Ok(()) => Ok(PIN_RETRIES),
            Err(Error::WrongPin { tries_left }) => Ok(tries_left),
            Err(Error::PinBlocked) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// `(is_default, retries_left)` of the PIN (`REF_PIN`) or PUK (`REF_PUK`),
    /// from metadata (fw ≥ 5.3). `None` on older firmware.
    pub fn pin_info(&mut self, reference: u8) -> Result<Option<(bool, u8)>> {
        let Some(md) = self.metadata(reference)? else {
            return Ok(None);
        };
        let get = |t| md.iter().find(|(x, _)| *x == t).map(|(_, v)| v.clone());
        let default = get(0x05).is_some_and(|v| v.first() == Some(&1));
        let left = get(0x06).and_then(|v| v.get(1).copied()).unwrap_or(0);
        Ok(Some((default, left)))
    }

    /// CHANGE REFERENCE DATA for the PIN or the PUK.
    pub fn change_reference(&mut self, reference: u8, old: &[u8], new: &[u8]) -> Result<()> {
        let mut d = pad_pin(old)?.to_vec();
        d.extend_from_slice(&pad_pin(new)?);
        let r = self.transceive([0x00, 0x24, 0x00, reference], &d);
        d.zeroize();
        Self::pin_status(r?.1, "change PIN")
    }

    /// RESET RETRY COUNTER: unblocks the PIN with the PUK and sets a new PIN.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<()> {
        let mut d = pad_pin(puk)?.to_vec();
        d.extend_from_slice(&pad_pin(new_pin)?);
        let r = self.transceive([0x00, 0x2C, 0x00, REF_PIN], &d);
        d.zeroize();
        Self::pin_status(r?.1, "unblock PIN")
    }

    /// YubiKey SET PIN RETRIES. Needs management key auth and a verified PIN;
    /// resets the PIN and PUK to their factory defaults.
    pub fn set_pin_retries(&mut self, pin: u8, puk: u8) -> Result<()> {
        self.cmd([0x00, 0xFA, pin, puk], &[], "set PIN retries")
            .map(|_| ())
    }

    /// YubiKey PIV reset. Only works once both PIN and PUK are blocked.
    pub fn reset(&mut self) -> Result<()> {
        self.cmd([0x00, 0xFB, 0x00, 0x00], &[], "PIV reset").map(|_| ())
    }

    /// ECDH with the on-card key; the user must touch the key, and the PIN
    /// must have been verified right before (PIN policy ALWAYS).
    pub fn ecdh(&mut self, slot: u8, point_uncompressed: &[u8]) -> Result<SecretBytes> {
        let mut inner = vec![0x82, 0x00];
        ber_tlv(&mut inner, &[0x85], point_uncompressed);
        let mut d = Vec::new();
        ber_tlv(&mut d, &[0x7C], &inner);
        let mut r = self.cmd([0x00, 0x87, ALG_ECCP256, slot], &d, "ecdh")?;
        let z = find(&ber_parse(&find(&ber_parse(&r)?, 0x7C)?)?, 0x82);
        r.zeroize();
        let mut z = z?;
        let s = SecretBytes::new(&z);
        z.zeroize();
        if s.len() != 32 {
            return Err(Error::Format("ECDH output"));
        }
        Ok(s)
    }
}
