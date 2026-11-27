//! `MockYubiKey`: an in-memory YubiKey 5 PIV applet at the APDU level, with
//! fault injection for tearing tests. Not a security boundary.

use std::collections::BTreeMap;

use p256::SecretKey;

use crate::card::SmartCard;
use crate::container::OBJ_MAX;
use crate::crypto;
use crate::error::{Error, Result};
use crate::piv::{self, ber_parse, ber_tlv};

/// Total NVM shared by all certificates and data objects.
pub const NVM_TOTAL: usize = 51_200;

/// What a PUT DATA does to its object when the card is pulled mid-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tear {
    /// The object keeps its old value.
    NotApplied,
    /// The object disappears.
    Deleted,
    /// Only a prefix of the new value is stored.
    Truncated,
    /// The object holds random bytes.
    Garbage,
}

pub const ALL_TEARS: [Tear; 4] = [
    Tear::NotApplied,
    Tear::Deleted,
    Tear::Truncated,
    Tear::Garbage,
];

#[derive(Clone)]
pub struct MockYubiKey {
    pub serial: u32,
    pub firmware: [u8; 3],
    /// NVM already used by other certificates (attestation and the user's).
    pub nvm_other: usize,
    /// Whether the user touches the key when it blinks.
    pub touch: bool,
    /// Number of touches consumed (ECDH operations).
    pub touches: u32,
    pub objects: BTreeMap<u32, Vec<u8>>,
    mgmt_alg: u8,
    mgmt_key: Vec<u8>,
    mgmt_default: bool,
    slots: BTreeMap<u8, (SecretKey, u8)>,
    authed: bool,
    /// PIN and PUK, padded to 8 bytes, with `(max, left)` retry counters.
    pin: [u8; 8],
    puk: [u8; 8],
    pin_tries: (u8, u8),
    puk_tries: (u8, u8),
    pin_verified: bool,
    witness: Option<Vec<u8>>,
    chain: Vec<u8>,
    pending: Vec<u8>,
    removed: bool,
    tear: Option<(usize, Tear)>,
    put_count: usize,
    unplug_after: Option<usize>,
    reader: String,
}

impl MockYubiKey {
    /// A factory-fresh YubiKey 5 on firmware 5.4.3 (3DES default management key).
    pub fn new(serial: u32) -> Self {
        Self::with_firmware(serial, [5, 4, 3])
    }

    /// Firmware 5.7 and later ship an AES-192 default management key.
    pub fn with_firmware(serial: u32, firmware: [u8; 3]) -> Self {
        let alg = if firmware >= [5, 7, 0] {
            piv::ALG_AES192
        } else {
            piv::ALG_3DES
        };
        MockYubiKey {
            serial,
            firmware,
            nvm_other: 0,
            touch: true,
            touches: 0,
            objects: BTreeMap::new(),
            mgmt_alg: alg,
            mgmt_key: piv::DEFAULT_MGMT_KEY.to_vec(),
            mgmt_default: true,
            slots: BTreeMap::new(),
            authed: false,
            pin: piv::pad_pin(piv::DEFAULT_PIN).unwrap(),
            puk: piv::pad_pin(piv::DEFAULT_PUK).unwrap(),
            pin_tries: (3, 3),
            puk_tries: (3, 3),
            pin_verified: false,
            witness: None,
            chain: Vec::new(),
            pending: Vec::new(),
            removed: false,
            tear: None,
            put_count: 0,
            unplug_after: None,
            reader: format!("Mock YubiKey {serial}"),
        }
    }

    /// Sets a non-default management key, as a user might have done.
    pub fn set_custom_mgmt_key(&mut self, alg: u8, key: &[u8]) {
        self.mgmt_alg = alg;
        self.mgmt_key = key.to_vec();
        self.mgmt_default = false;
    }

    pub fn mgmt_key(&self) -> (u8, &[u8]) {
        (self.mgmt_alg, &self.mgmt_key)
    }

    /// Tears the `n`-th PUT DATA from now (0-based) and unplugs the card.
    pub fn arm_tear(&mut self, n: usize, mode: Tear) {
        self.tear = Some((n, mode));
        self.put_count = 0;
    }

    /// True once an armed tear has fired.
    pub fn tear_fired(&self) -> bool {
        self.tear.is_none() && self.removed
    }

    /// Unplugs the card after `n` more APDUs have been processed.
    pub fn unplug_after(&mut self, n: usize) {
        self.unplug_after = Some(n);
    }

    pub fn unplug(&mut self) {
        self.removed = true;
    }

    /// Reinserts the card: volatile state (auth, chaining) is lost.
    pub fn replug(&mut self) {
        self.removed = false;
        self.authed = false;
        self.pin_verified = false;
        self.witness = None;
        self.chain.clear();
        self.pending.clear();
        self.tear = None;
        self.unplug_after = None;
    }

    /// PIN tries left before it blocks.
    pub fn pin_tries_left(&self) -> u8 {
        self.pin_tries.1
    }

    /// Sets a PIN, as a user might have done with ykman.
    pub fn set_custom_pin(&mut self, pin: &[u8]) {
        self.pin = piv::pad_pin(pin).unwrap();
    }

    pub fn nvm_used(&self) -> usize {
        self.nvm_other + self.objects.values().map(Vec::len).sum::<usize>()
    }

    fn respond(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if data.len() > 256 {
            self.pending = data.split_off(256);
            let left = self.pending.len().min(255) as u8;
            data.extend_from_slice(&[0x61, if self.pending.len() >= 256 { 0 } else { left }]);
        } else {
            data.extend_from_slice(&[0x90, 0x00]);
        }
        data
    }

    fn sw(sw: u16) -> Vec<u8> {
        sw.to_be_bytes().to_vec()
    }

    fn process(&mut self, apdu: &[u8]) -> Vec<u8> {
        if apdu.len() < 4 {
            return Self::sw(0x6700);
        }
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let data = if apdu.len() > 5 {
            &apdu[5..(5 + apdu[4] as usize).min(apdu.len())]
        } else {
            &[][..]
        };
        if ins == 0xC0 {
            let rest = std::mem::take(&mut self.pending);
            return self.respond(rest);
        }
        self.pending.clear();
        if cla & 0x10 != 0 {
            self.chain.extend_from_slice(data);
            return Self::sw(0x9000);
        }
        let mut full = std::mem::take(&mut self.chain);
        full.extend_from_slice(data);
        match self.dispatch(ins, p1, p2, &full) {
            Ok(r) => self.respond(r),
            Err(sw) => Self::sw(sw),
        }
    }

    fn dispatch(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        d: &[u8],
    ) -> core::result::Result<Vec<u8>, u16> {
        let fw_meta = self.firmware >= [5, 3, 0];
        match ins {
            0xA4 => {
                if d == piv::PIV_AID {
                    Ok(Vec::new())
                } else {
                    Err(0x6A82)
                }
            }
            0xFD => Ok(self.firmware.to_vec()),
            0xF8 => Ok(self.serial.to_be_bytes().to_vec()),
            0xF7 if fw_meta => self.metadata(p2),
            0xCB => {
                let tag = Self::object_tag(d)?;
                let v = self.objects.get(&tag).ok_or(0x6A82u16)?;
                let mut out = Vec::new();
                ber_tlv(&mut out, &[0x53], v);
                Ok(out)
            }
            0xDB => self.put_data(d),
            0x87 if p2 == piv::SLOT_MGMT => self.mgmt_auth(p1, d),
            0x87 if p1 == piv::ALG_ECCP256 => self.ecdh(p2, d),
            0xFF => {
                if !self.authed {
                    return Err(0x6982);
                }
                let (alg, len) = (
                    *d.first().ok_or(0x6A80u16)?,
                    *d.get(2).ok_or(0x6A80u16)? as usize,
                );
                let key = d.get(3..3 + len).ok_or(0x6A80u16)?;
                piv::mgmt_block(alg, key, &[0u8; 16][..piv::mgmt_block_len(alg)], true)
                    .map_err(|_| 0x6A80u16)?;
                self.mgmt_alg = alg;
                self.mgmt_key = key.to_vec();
                self.mgmt_default = false;
                Ok(Vec::new())
            }
            0x20 if p2 == piv::REF_PIN => {
                if d.is_empty() {
                    return match (self.pin_verified, self.pin_tries.1) {
                        (true, _) => Ok(Vec::new()),
                        (_, 0) => Err(piv::SW_BLOCKED),
                        (_, n) => Err(0x63C0 | u16::from(n.min(15))),
                    };
                }
                let pin = self.pin;
                self.pin_verified = false;
                Self::check(&mut self.pin_tries, &pin, d)?;
                self.pin_verified = true;
                Ok(Vec::new())
            }
            0x24 if p2 == piv::REF_PIN || p2 == piv::REF_PUK => {
                if d.len() != 16 {
                    return Err(0x6A80);
                }
                let (cur, tries) = if p2 == piv::REF_PIN {
                    (self.pin, &mut self.pin_tries)
                } else {
                    (self.puk, &mut self.puk_tries)
                };
                Self::check(tries, &cur, &d[..8])?;
                let new: [u8; 8] = d[8..].try_into().unwrap();
                if p2 == piv::REF_PIN {
                    self.pin = new;
                } else {
                    self.puk = new;
                }
                Ok(Vec::new())
            }
            0x2C if p2 == piv::REF_PIN => {
                if d.len() != 16 {
                    return Err(0x6A80);
                }
                let puk = self.puk;
                Self::check(&mut self.puk_tries, &puk, &d[..8])?;
                self.pin = d[8..].try_into().unwrap();
                self.pin_tries.1 = self.pin_tries.0;
                Ok(Vec::new())
            }
            0xFA => {
                if !self.authed || !self.pin_verified {
                    return Err(0x6982);
                }
                if p1 == 0 || p2 == 0 {
                    return Err(0x6A86);
                }
                self.pin_tries = (p1, p1);
                self.puk_tries = (p2, p2);
                self.pin = piv::pad_pin(piv::DEFAULT_PIN).unwrap();
                self.puk = piv::pad_pin(piv::DEFAULT_PUK).unwrap();
                self.pin_verified = false;
                Ok(Vec::new())
            }
            0xFB => {
                if self.pin_tries.1 != 0 || self.puk_tries.1 != 0 {
                    return Err(0x6985);
                }
                let mut fresh = Self::with_firmware(self.serial, self.firmware);
                fresh.objects.clear();
                fresh.nvm_other = self.nvm_other;
                *self = fresh;
                Ok(Vec::new())
            }
            0x47 => {
                if !self.authed {
                    return Err(0x6982);
                }
                let policy = ber_parse(d)
                    .ok()
                    .and_then(|o| o.first().map(|i| i.1.to_vec()))
                    .and_then(|inner| {
                        ber_parse(&inner)
                            .ok()?
                            .iter()
                            .find(|i| i.0 == 0xAA)
                            .and_then(|i| i.1.first().copied())
                    })
                    .unwrap_or(0x01);
                let sk = loop {
                    if let Ok(k) =
                        SecretKey::from_slice(&crypto::random_bytes::<32>().map_err(|_| 0x6F00u16)?)
                    {
                        break k;
                    }
                };
                let pk = crypto::pubkey_uncompressed(&sk.public_key());
                self.slots.insert(p2, (sk, policy));
                let mut inner = Vec::new();
                ber_tlv(&mut inner, &[0x86], &pk);
                let mut out = Vec::new();
                ber_tlv(&mut out, &[0x7F, 0x49], &inner);
                Ok(out)
            }
            _ => Err(0x6D00),
        }
    }

    fn object_tag(d: &[u8]) -> core::result::Result<u32, u16> {
        match d {
            [0x5C, 0x03, a, b, c, ..] => Ok(u32::from_be_bytes([0, *a, *b, *c])),
            _ => Err(0x6A80),
        }
    }

    /// Checks a PIN or PUK attempt; a wrong one returns its status word.
    fn check(tries: &mut (u8, u8), expected: &[u8; 8], given: &[u8]) -> core::result::Result<(), u16> {
        if tries.1 == 0 {
            return Err(piv::SW_BLOCKED);
        }
        if given == expected {
            tries.1 = tries.0;
            return Ok(());
        }
        tries.1 -= 1;
        Err(if tries.1 == 0 {
            piv::SW_BLOCKED
        } else {
            0x63C0 | u16::from(tries.1.min(15))
        })
    }

    fn metadata(&self, slot: u8) -> core::result::Result<Vec<u8>, u16> {
        let mut out = Vec::new();
        if slot == piv::REF_PIN || slot == piv::REF_PUK {
            let (value, default, tries) = if slot == piv::REF_PIN {
                (self.pin, piv::DEFAULT_PIN, self.pin_tries)
            } else {
                (self.puk, piv::DEFAULT_PUK, self.puk_tries)
            };
            ber_tlv(&mut out, &[0x01], &[0xFF]);
            ber_tlv(&mut out, &[0x05], &[u8::from(value == piv::pad_pin(default).unwrap())]);
            ber_tlv(&mut out, &[0x06], &[tries.0, tries.1]);
            return Ok(out);
        }
        if slot == piv::SLOT_MGMT {
            ber_tlv(&mut out, &[0x01], &[self.mgmt_alg]);
            ber_tlv(&mut out, &[0x02], &[0x00, 0x01]);
            ber_tlv(&mut out, &[0x05], &[self.mgmt_default as u8]);
            return Ok(out);
        }
        // A real YubiKey 5.7 answers 6A88 (not 6A82) for an empty slot.
        let (sk, policy) = self.slots.get(&slot).ok_or(piv::SW_REF_NOT_FOUND)?;
        ber_tlv(&mut out, &[0x01], &[piv::ALG_ECCP256]);
        ber_tlv(&mut out, &[0x02], &[*policy, 0x02]);
        ber_tlv(&mut out, &[0x03], &[0x01]);
        let mut pk = Vec::new();
        ber_tlv(
            &mut pk,
            &[0x86],
            &crypto::pubkey_uncompressed(&sk.public_key()),
        );
        ber_tlv(&mut out, &[0x04], &pk);
        Ok(out)
    }

    fn put_data(&mut self, d: &[u8]) -> core::result::Result<Vec<u8>, u16> {
        if !self.authed {
            return Err(0x6982);
        }
        let tag = Self::object_tag(d)?;
        let items = ber_parse(&d[5..]).map_err(|_| 0x6A80u16)?;
        let value = items
            .iter()
            .find(|i| i.0 == 0x53)
            .ok_or(0x6A80u16)?
            .1
            .to_vec();
        if value.len() > OBJ_MAX {
            return Err(0x6A84);
        }
        let old = self.objects.get(&tag).map_or(0, Vec::len);
        if self.nvm_used() - old + value.len() > NVM_TOTAL {
            return Err(0x6A84);
        }
        if let Some((n, mode)) = self.tear {
            if self.put_count == n {
                self.tear = None;
                self.removed = true;
                match mode {
                    Tear::NotApplied => {}
                    Tear::Deleted => {
                        self.objects.remove(&tag);
                    }
                    Tear::Truncated => {
                        let r = crypto::random_u64().unwrap_or(0) as usize;
                        let keep = if value.is_empty() { 0 } else { r % value.len() };
                        self.objects.insert(tag, value[..keep].to_vec());
                    }
                    Tear::Garbage => {
                        let mut g = vec![0u8; value.len().max(1)];
                        getrandom::fill(&mut g).ok();
                        self.objects.insert(tag, g);
                    }
                }
                return Err(0xFFFF); // never seen: the transport reports removal
            }
            self.put_count += 1;
        }
        if value.is_empty() {
            self.objects.remove(&tag);
        } else {
            self.objects.insert(tag, value);
        }
        Ok(Vec::new())
    }

    fn mgmt_auth(&mut self, alg: u8, d: &[u8]) -> core::result::Result<Vec<u8>, u16> {
        if alg != self.mgmt_alg {
            return Err(0x6A80);
        }
        let n = piv::mgmt_block_len(alg);
        let outer = ber_parse(d).map_err(|_| 0x6A80u16)?;
        let inner = ber_parse(outer.first().ok_or(0x6A80u16)?.1).map_err(|_| 0x6A80u16)?;
        let get = |t: u16| inner.iter().find(|i| i.0 == t).map(|i| i.1);
        let enc =
            |m: &Self, b: &[u8]| piv::mgmt_block(alg, &m.mgmt_key, b, true).map_err(|_| 0x6A80u16);
        let mut out = Vec::new();
        match (get(0x80), get(0x81)) {
            (Some([]), None) => {
                self.authed = false;
                let w = crypto::random_bytes::<16>().map_err(|_| 0x6F00u16)?[..n].to_vec();
                let mut i = Vec::new();
                ber_tlv(&mut i, &[0x80], &enc(self, &w)?);
                self.witness = Some(w);
                ber_tlv(&mut out, &[0x7C], &i);
                Ok(out)
            }
            (Some(w), Some(c)) => {
                let expected = self.witness.take().ok_or(0x6982u16)?;
                if w != expected.as_slice() || c.len() != n {
                    return Err(0x6982);
                }
                self.authed = true;
                let mut i = Vec::new();
                ber_tlv(&mut i, &[0x82], &enc(self, c)?);
                ber_tlv(&mut out, &[0x7C], &i);
                Ok(out)
            }
            _ => Err(0x6A80),
        }
    }

    fn ecdh(&mut self, slot: u8, d: &[u8]) -> core::result::Result<Vec<u8>, u16> {
        let (sk, policy) = self.slots.get(&slot).ok_or(0x6A82u16)?;
        let (sk, policy) = (sk.clone(), *policy);
        let outer = ber_parse(d).map_err(|_| 0x6A80u16)?;
        let inner = ber_parse(outer.first().ok_or(0x6A80u16)?.1).map_err(|_| 0x6A80u16)?;
        let point = inner.iter().find(|i| i.0 == 0x85).ok_or(0x6A80u16)?.1;
        let pk = crypto::parse_pubkey(point).map_err(|_| 0x6A80u16)?;
        // PIN policy ALWAYS: the PIN must be verified right before each use.
        if policy == 0x03 && !std::mem::take(&mut self.pin_verified) {
            return Err(0x6982);
        }
        if !self.touch {
            return Err(0x6982);
        }
        self.touches += 1;
        let z = sk.diffie_hellman(&pk);
        let mut i = Vec::new();
        ber_tlv(&mut i, &[0x82], z.raw_secret_bytes().as_slice());
        let mut out = Vec::new();
        ber_tlv(&mut out, &[0x7C], &i);
        Ok(out)
    }
}

impl SmartCard for MockYubiKey {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if self.removed {
            return Err(Error::CardRemoved);
        }
        if let Some(n) = self.unplug_after.as_mut() {
            if *n == 0 {
                self.removed = true;
                return Err(Error::CardRemoved);
            }
            *n -= 1;
        }
        let r = self.process(apdu);
        if self.removed {
            return Err(Error::CardRemoved);
        }
        Ok(r)
    }

    fn reader_id(&self) -> &str {
        &self.reader
    }
}
