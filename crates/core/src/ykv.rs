//! Encrypted `.ykv` export and import (SPEC §13.1), wrapped to every known
//! YubiKey and optionally to a printable recovery key.

use zeroize::Zeroize;

use crate::card::SmartCard;
use crate::codec;
use crate::crypto;
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::payload;
use crate::piv::Piv;
use crate::secret::SecretBytes;

const PREFIX_LEN: usize = 61; // through recipient_count
const RECIPIENT_LEN: usize = 102;
const TYPE_CARD: u8 = 1;
const TYPE_RECOVERY: u8 = 2;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Inputs for an export, taken from an unlocked session.
pub struct ExportParams<'a> {
    pub vault: &'a Vault,
    pub uuid: [u8; 16],
    pub revision: u64,
    pub salt: [u8; 16],
    pub p: &'a [u8],
}

fn base32(bytes: &[u8]) -> String {
    let (mut acc, mut bits, mut out) = (0u32, 0, String::new());
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn rk_check(r: &[u8]) -> String {
    base32(&crypto::sha256(&[r])[..2])
}

/// Formats a 20-byte recovery key as 8 groups of 4 characters plus a check group.
pub fn format_recovery_key(r: &[u8; 20]) -> String {
    let s = base32(r);
    let mut groups: Vec<&str> = (0..8).map(|i| &s[i * 4..i * 4 + 4]).collect();
    let check = rk_check(r);
    groups.push(&check);
    groups.join("-")
}

/// Parses a recovery key, tolerating case, spaces, dashes, O for 0 and I/L for 1.
pub fn parse_recovery_key(text: &str) -> Result<SecretBytes> {
    let mut vals = Vec::new();
    for c in text.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = CROCKFORD
            .iter()
            .position(|&x| x as char == c)
            .ok_or(Error::Invalid("recovery key character"))?;
        vals.push(v as u32);
    }
    if vals.len() != 36 {
        return Err(Error::Invalid("recovery key length"));
    }
    let mut r = [0u8; 20];
    let (mut acc, mut bits, mut i) = (0u32, 0, 0);
    for &v in &vals[..32] {
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            r[i] = (acc >> bits) as u8;
            i += 1;
        }
    }
    let check: String = vals[32..]
        .iter()
        .map(|&v| CROCKFORD[v as usize] as char)
        .collect();
    let ok = check == rk_check(&r);
    let s = SecretBytes::new(&r);
    r.zeroize();
    if !ok {
        return Err(Error::Invalid("recovery key check failed"));
    }
    Ok(s)
}

fn rk_id(r: &[u8]) -> [u8; 8] {
    crypto::sha256(&[b"99p/v1/rk-id", r])[..8]
        .try_into()
        .unwrap()
}

fn rk_kek(r: &[u8], p: &[u8], uuid: &[u8; 16]) -> SecretBytes {
    crypto::hkdf32(b"99p/v1/recovery", &[r, p], uuid)
}

/// Builds a `.ykv` file. Returns the file and, if requested, the recovery
/// key text, which the app shows once.
pub fn export(ep: &ExportParams, with_recovery_key: bool) -> Result<(Vec<u8>, Option<String>)> {
    let cards: Vec<_> = ep.vault.known_keys.iter().collect();
    let n = cards.len() + with_recovery_key as usize;
    if n == 0 || n > 255 {
        return Err(Error::Invalid("number of recipients"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"99PX");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&ep.uuid);
    out.extend_from_slice(&ep.revision.to_le_bytes());
    out.push(crypto::KDF_ID);
    out.extend_from_slice(&[0; 11]);
    out.extend_from_slice(&ep.salt);
    out.push(n as u8);
    debug_assert_eq!(out.len(), PREFIX_LEN);
    let prefix = out.clone();
    let dek = SecretBytes::new(&crypto::random_bytes::<32>()?);
    let mut wrap = |kind: u8, id: [u8; 8], eph: [u8; 33], kek: &SecretBytes| -> Result<()> {
        let nonce: [u8; 12] = crypto::random_bytes()?;
        let mut r = vec![kind];
        r.extend_from_slice(&id);
        r.extend_from_slice(&eph);
        r.extend_from_slice(&nonce);
        let aad = [&prefix[..], &r[..]].concat();
        r.extend_from_slice(&crypto::seal(kek.as_slice(), &nonce, dek.as_slice(), &aad)?);
        out.extend_from_slice(&r);
        Ok(())
    };
    for k in &cards {
        let pk = crypto::parse_pubkey(&k.piv_pubkey)?;
        let id = crypto::card_fpr(&k.piv_pubkey);
        let (eph, z) = crypto::ephemeral_ecdh(&pk)?;
        let kek = crypto::card_kek(z.as_slice(), ep.p, &ep.uuid, &id, &eph, ep.revision);
        wrap(TYPE_CARD, id, eph, &kek)?;
    }
    let mut rk_text = None;
    if with_recovery_key {
        let mut r: [u8; 20] = crypto::random_bytes()?;
        let kek = rk_kek(&r, ep.p, &ep.uuid);
        wrap(TYPE_RECOVERY, rk_id(&r), [0; 33], &kek)?;
        rk_text = Some(format_recovery_key(&r));
        r.zeroize();
    }
    let nonce: [u8; 12] = crypto::random_bytes()?;
    let mut body = codec::encode_vault(ep.vault);
    let mut pt = payload::pack(&body, false);
    body.zeroize();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&((pt.len() + 16) as u32).to_le_bytes());
    let ct = crypto::seal(dek.as_slice(), &nonce, &pt, &out);
    pt.zeroize();
    out.extend_from_slice(&ct?);
    Ok((out, rk_text))
}

struct Parsed<'a> {
    uuid: [u8; 16],
    salt: [u8; 16],
    revision: u64,
    prefix: &'a [u8],
    recipients: Vec<&'a [u8]>,
    payload_aad: &'a [u8],
    nonce: [u8; 12],
    ct: &'a [u8],
}

fn parse(f: &[u8]) -> Result<Parsed<'_>> {
    let bad = Error::Format(".ykv file");
    if f.len() < PREFIX_LEN || &f[..4] != b"99PX" {
        return Err(bad);
    }
    if u16::from_le_bytes([f[4], f[5]]) != 1 || f[32] != crypto::KDF_ID || f[33..44].iter().any(|&x| x != 0) {
        return Err(Error::Unsupported(".ykv version"));
    }
    let u32_at = |o: usize| u32::from_le_bytes(f[o..o + 4].try_into().unwrap());
    let n = f[60] as usize;
    let end = PREFIX_LEN + n * RECIPIENT_LEN;
    if f.len() < end + 16 {
        return Err(bad);
    }
    let ct_len = u32_at(end + 12) as usize;
    if f.len() != end + 16 + ct_len {
        return Err(bad);
    }
    Ok(Parsed {
        uuid: f[8..24].try_into().unwrap(),
        revision: u64::from_le_bytes(f[24..32].try_into().unwrap()),
        salt: f[44..60].try_into().unwrap(),
        prefix: &f[..PREFIX_LEN],
        recipients: f[PREFIX_LEN..end].chunks(RECIPIENT_LEN).collect(),
        payload_aad: &f[..end + 16],
        nonce: f[end..end + 12].try_into().unwrap(),
        ct: &f[end + 16..],
    })
}

fn unwrap_dek(p: &Parsed, r: &[u8], kek: &SecretBytes) -> Result<SecretBytes> {
    let aad = [p.prefix, &r[..54]].concat();
    crypto::open(
        kek.as_slice(),
        r[42..54].try_into().unwrap(),
        &r[54..],
        &aad,
    )
}

fn finish(p: &Parsed, dek: &SecretBytes) -> Result<Vault> {
    let pt = crypto::open(dek.as_slice(), &p.nonce, p.ct, p.payload_aad)?;
    let (_, body) = payload::unpack(pt.as_slice())?;
    codec::decode_vault(body.as_slice())
}

/// Opens a `.ykv` with the passphrase and the printed recovery key.
pub fn open_with_recovery_key(file: &[u8], pass: &[u8], recovery_key: &str) -> Result<Vault> {
    let p = parse(file)?;
    let r = parse_recovery_key(recovery_key)?;
    let id = rk_id(r.as_slice());
    let rec = p
        .recipients
        .iter()
        .find(|x| x[0] == TYPE_RECOVERY && x[1..9] == id)
        .ok_or(Error::Decrypt)?;
    let pk = crypto::derive_passphrase_key(pass, &p.salt);
    let dek = unwrap_dek(&p, rec, &rk_kek(r.as_slice(), pk.as_slice(), &p.uuid))?;
    finish(&p, &dek)
}

/// Opens a `.ykv` with the passphrase and an inserted YubiKey (one touch).
pub fn open_with_card<C: SmartCard>(piv: &mut Piv<C>, file: &[u8], pass: &[u8]) -> Result<Vault> {
    let p = parse(file)?;
    piv.select()?;
    let pubkey = piv
        .slot_pubkey(crate::container::VAULT_SLOT)?
        .ok_or(Error::Decrypt)?;
    let id = crypto::card_fpr(&pubkey);
    let rec = p
        .recipients
        .iter()
        .find(|x| x[0] == TYPE_CARD && x[1..9] == id)
        .ok_or(Error::Decrypt)?;
    let pk = crypto::derive_passphrase_key(pass, &p.salt);
    let eph: [u8; 33] = rec[9..42].try_into().unwrap();
    let e = crypto::pubkey_uncompressed(&crypto::parse_pubkey(&eph)?);
    piv.verify_pin(&crypto::derive_pin(pk.as_slice()))?;
    let z = piv.ecdh(crate::container::VAULT_SLOT, &e)?;
    let kek = crypto::card_kek(z.as_slice(), pk.as_slice(), &p.uuid, &id, &eph, p.revision);
    let dek = unwrap_dek(&p, rec, &kek)?;
    finish(&p, &dek)
}
