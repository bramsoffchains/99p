//! Manifest (SPEC §3) and bank image (SPEC §4) codecs, plus sealing and opening.

use p256::PublicKey;

use crate::crypto;
use crate::error::{Error, Result};
use crate::secret::SecretBytes;

pub const OBJ_MAX: usize = 3052;
pub const MANIFEST_TAG: u32 = 0x5F_C200;
pub const BANK_A_TAG: u32 = 0x5F_C210;
pub const BANK_B_TAG: u32 = 0x5F_C220;
pub const CHUNKS_PER_BANK: usize = 8;
pub const MANIFEST_LEN: usize = 88;
pub const HEADER_LEN: usize = 216;
pub const VAULT_SLOT: u8 = 0x82;

/// Data object tag of chunk `i` in `bank` (0 = A, 1 = B). Single-bank mode
/// uses bank 0 with chunks 0..16, spanning both ranges.
pub fn chunk_tag(bank: u8, i: usize) -> u32 {
    let i = i + bank as usize * CHUNKS_PER_BANK;
    if i < CHUNKS_PER_BANK {
        BANK_A_TAG + i as u32
    } else {
        BANK_B_TAG + (i - CHUNKS_PER_BANK) as u32
    }
}

pub fn bank_capacity(single_bank: bool) -> usize {
    OBJ_MAX * CHUNKS_PER_BANK * if single_bank { 2 } else { 1 }
}

/// Largest `ct_len` that fits a bank.
pub fn max_ct_len(single_bank: bool) -> usize {
    (bank_capacity(single_bank) - HEADER_LEN) / 1024 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub single_bank: bool,
    pub active_bank: u8,
    pub uuid: [u8; 16],
    pub revision: u64,
    pub image_len: u32,
    pub chunk_count: u8,
    pub digest: [u8; 32],
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MANIFEST_LEN);
        b.extend_from_slice(b"99PM");
        b.push(1);
        b.push(self.single_bank as u8);
        b.push(self.active_bank);
        b.push(0);
        b.extend_from_slice(&self.uuid);
        b.extend_from_slice(&self.revision.to_le_bytes());
        b.extend_from_slice(&self.image_len.to_le_bytes());
        b.push(self.chunk_count);
        b.extend_from_slice(&[0; 3]);
        b.extend_from_slice(&self.digest);
        let check = crypto::sha256(&[b"99p/v1/manifest", &b]);
        b.extend_from_slice(&check[..16]);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != MANIFEST_LEN || &b[..4] != b"99PM" || b[4] != 1 {
            return Err(Error::Format("manifest header"));
        }
        let check = crypto::sha256(&[b"99p/v1/manifest", &b[..72]]);
        if check[..16] != b[72..88] {
            return Err(Error::Format("manifest check"));
        }
        let m = Manifest {
            single_bank: b[5] & 1 != 0,
            active_bank: b[6],
            uuid: b[8..24].try_into().unwrap(),
            revision: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            image_len: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            chunk_count: b[36],
            digest: b[40..72].try_into().unwrap(),
        };
        if m.active_bank > 1 || (m.single_bank && m.active_bank != 0) {
            return Err(Error::Format("manifest bank"));
        }
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankHeader {
    pub single_bank: bool,
    pub slot: u8,
    pub uuid: [u8; 16],
    pub revision: u64,
    pub salt: [u8; 16],
    pub card_fpr: [u8; 8],
    pub card_serial: u32,
    pub eph_pub: [u8; 33],
    pub wrap_nonce: [u8; 12],
    pub payload_nonce: [u8; 12],
    pub ct_len: u32,
    pub wrapped_dek: [u8; 48],
    pub digest: [u8; 32],
}

impl BankHeader {
    /// First 136 bytes (everything before `wrapped_dek`), which is `AAD_wrap`.
    fn encode_prefix(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN);
        b.extend_from_slice(b"99PV");
        b.extend_from_slice(&1u16.to_le_bytes());
        b.push(self.single_bank as u8);
        b.push(self.slot);
        b.extend_from_slice(&self.uuid);
        b.extend_from_slice(&self.revision.to_le_bytes());
        b.push(crypto::KDF_ID);
        b.extend_from_slice(&[0; 11]);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.card_fpr);
        b.extend_from_slice(&self.card_serial.to_le_bytes());
        b.extend_from_slice(&self.eph_pub);
        b.extend_from_slice(&self.wrap_nonce);
        b.extend_from_slice(&self.payload_nonce);
        b.extend_from_slice(&[0; 3]);
        b.extend_from_slice(&self.ct_len.to_le_bytes());
        debug_assert_eq!(b.len(), 136);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN || &b[..4] != b"99PV" {
            return Err(Error::Format("bank header"));
        }
        if u16::from_le_bytes([b[4], b[5]]) != 1 {
            return Err(Error::Unsupported("container version"));
        }
        if b[32] != crypto::KDF_ID {
            return Err(Error::Unsupported("KDF"));
        }
        if b[6] & !1 != 0 || b[33..44].iter().any(|&x| x != 0) || b[129..132] != [0, 0, 0] {
            return Err(Error::Format("reserved bits set"));
        }
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let h = BankHeader {
            single_bank: b[6] & 1 != 0,
            slot: b[7],
            uuid: b[8..24].try_into().unwrap(),
            revision: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            salt: b[44..60].try_into().unwrap(),
            card_fpr: b[60..68].try_into().unwrap(),
            card_serial: u32_at(68),
            eph_pub: b[72..105].try_into().unwrap(),
            wrap_nonce: b[105..117].try_into().unwrap(),
            payload_nonce: b[117..129].try_into().unwrap(),
            ct_len: u32_at(132),
            wrapped_dek: b[136..184].try_into().unwrap(),
            digest: b[184..216].try_into().unwrap(),
        };
        let ct = h.ct_len as usize;
        if ct == 0 || ct % 1024 != 0 || ct > max_ct_len(h.single_bank) {
            return Err(Error::Format("ct_len"));
        }
        Ok(h)
    }

    pub fn image_len(&self) -> usize {
        HEADER_LEN + self.ct_len as usize
    }
}

/// Parses a full bank image and checks its digest.
pub fn parse_image(image: &[u8]) -> Result<BankHeader> {
    let h = BankHeader::decode(image)?;
    if image.len() != h.image_len() {
        return Err(Error::Format("image length"));
    }
    if crypto::sha256(&[&image[..184], &image[HEADER_LEN..]]) != h.digest {
        return Err(Error::Format("image digest"));
    }
    Ok(h)
}

/// Everything needed to seal a bank image except the plaintext.
pub struct SealParams<'a> {
    pub single_bank: bool,
    pub uuid: [u8; 16],
    pub revision: u64,
    pub salt: [u8; 16],
    pub card_pub: &'a PublicKey,
    pub card_serial: u32,
    /// `P`, derived from the passphrase (SPEC §5.1).
    pub p: &'a [u8],
}

/// Builds a bank image (SPEC §5.2) from a padded plaintext (`payload::pack`).
pub fn seal_image(sp: &SealParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ct_len = plaintext.len() + 16;
    let max = max_ct_len(sp.single_bank);
    if ct_len % 1024 != 0 {
        return Err(Error::Invalid("plaintext not padded"));
    }
    if ct_len > max {
        return Err(Error::Capacity {
            needed: ct_len,
            available: max,
        });
    }
    let fpr = crypto::card_fpr(&crypto::pubkey_uncompressed(sp.card_pub));
    let (eph_pub, z) = crypto::ephemeral_ecdh(sp.card_pub)?;
    let mut h = BankHeader {
        single_bank: sp.single_bank,
        slot: VAULT_SLOT,
        uuid: sp.uuid,
        revision: sp.revision,
        salt: sp.salt,
        card_fpr: fpr,
        card_serial: sp.card_serial,
        eph_pub,
        wrap_nonce: crypto::random_bytes()?,
        payload_nonce: crypto::random_bytes()?,
        ct_len: ct_len as u32,
        wrapped_dek: [0; 48],
        digest: [0; 32],
    };
    let kek = crypto::card_kek(z.as_slice(), sp.p, &sp.uuid, &fpr, &eph_pub, sp.revision);
    drop(z);
    let dek = SecretBytes::new(&crypto::random_bytes::<32>()?);
    let mut image = h.encode_prefix();
    let wrapped = crypto::seal(kek.as_slice(), &h.wrap_nonce, dek.as_slice(), &image)?;
    drop(kek);
    h.wrapped_dek = wrapped.try_into().unwrap();
    image.extend_from_slice(&h.wrapped_dek);
    let ct = crypto::seal(dek.as_slice(), &h.payload_nonce, plaintext, &image)?;
    h.digest = crypto::sha256(&[&image, &ct]);
    image.extend_from_slice(&h.digest);
    image.extend_from_slice(&ct);
    Ok(image)
}

/// Decrypts a bank image given `Z` (from the card's ECDH on `eph_pub`) and `P`.
pub fn open_image(image: &[u8], h: &BankHeader, z: &[u8], p: &[u8]) -> Result<SecretBytes> {
    let kek = crypto::card_kek(z, p, &h.uuid, &h.card_fpr, &h.eph_pub, h.revision);
    let dek = crypto::open(kek.as_slice(), &h.wrap_nonce, &h.wrapped_dek, &image[..136])?;
    crypto::open(
        dek.as_slice(),
        &h.payload_nonce,
        &image[HEADER_LEN..],
        &image[..184],
    )
}

/// Splits an image into object-sized chunks.
pub fn chunks(image: &[u8]) -> impl Iterator<Item = &[u8]> {
    image.chunks(OBJ_MAX)
}
