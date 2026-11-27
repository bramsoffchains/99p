//! Crypto primitives, SPEC §5: P-256 ECDH, HKDF-SHA256 and ChaCha20-Poly1305.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::SecretBytes;

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

pub fn random_u64() -> Result<u64> {
    getrandom::u64().map_err(|_| Error::Rng)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `kdf_id` in bank headers and `.ykv` files: `P = HKDF-SHA256(pass, salt)`,
/// no stretching. The card's PIN counter limits guessing instead (SPEC §5.1).
pub const KDF_ID: u8 = 2;

/// `P = HKDF-SHA256(salt, ikm = pass, info = "99p/v1/pass")`, in locked memory.
pub fn derive_passphrase_key(pass: &[u8], salt: &[u8; 16]) -> SecretBytes {
    hkdf32(salt, &[pass], b"99p/v1/pass")
}

/// The 8-character PIV PIN derived from `P` (SPEC §5.1): HKDF, then 6 bits
/// per character from a 64-symbol alphabet (48 bits). Never shown to the user.
pub fn derive_pin(p: &[u8]) -> [u8; 8] {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let k = hkdf32(b"99p/v1/pin", &[p], b"");
    let mut pin = [0u8; 8];
    for (o, b) in pin.iter_mut().zip(k.as_slice()) {
        *o = ALPHABET[(b & 63) as usize];
    }
    pin
}

/// `card_fpr = SHA-256(SEC1 uncompressed pubkey)[0..8]`.
pub fn card_fpr(pubkey_uncompressed: &[u8]) -> [u8; 8] {
    sha256(&[pubkey_uncompressed])[..8].try_into().unwrap()
}

pub fn parse_pubkey(sec1: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(sec1).map_err(|_| Error::Format("invalid P-256 public key"))
}

pub fn pubkey_uncompressed(pk: &PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    pk.to_sec1_point(false).as_bytes().to_vec()
}

pub fn pubkey_compressed(pk: &PublicKey) -> [u8; 33] {
    use p256::elliptic_curve::sec1::ToSec1Point;
    pk.to_sec1_point(true).as_bytes().try_into().unwrap()
}

/// Software half of the ephemeral-static ECDH used on save: returns `(E, Z)`.
pub fn ephemeral_ecdh(card_pub: &PublicKey) -> Result<([u8; 33], SecretBytes)> {
    let sk = loop {
        let mut b = random_bytes::<32>()?;
        let k = SecretKey::from_slice(&b);
        b.zeroize();
        if let Ok(k) = k {
            break k;
        }
    };
    let e_pub = pubkey_compressed(&sk.public_key());
    let shared = sk.diffie_hellman(card_pub);
    Ok((
        e_pub,
        SecretBytes::new(shared.raw_secret_bytes().as_slice()),
    ))
}

/// HKDF-SHA256 to 32 bytes.
pub fn hkdf32(salt: &[u8], ikm: &[&[u8]], info: &[u8]) -> SecretBytes {
    let mut buf = Vec::new();
    for p in ikm {
        buf.extend_from_slice(p);
    }
    let h = Hkdf::<Sha256>::new(Some(salt), &buf);
    buf.zeroize();
    let mut out = SecretBytes::zeroed(32);
    h.expand(info, out.as_mut_slice()).unwrap();
    out
}

/// KEK for a YubiKey recipient (SPEC §5.2).
pub fn card_kek(
    z: &[u8],
    p: &[u8],
    uuid: &[u8; 16],
    fpr: &[u8; 8],
    e_pub: &[u8; 33],
    rev: u64,
) -> SecretBytes {
    let mut info = Vec::with_capacity(65);
    info.extend_from_slice(uuid);
    info.extend_from_slice(fpr);
    info.extend_from_slice(e_pub);
    info.extend_from_slice(&rev.to_le_bytes());
    hkdf32(b"99p/v1/kek", &[z, p], &info)
}

pub fn seal(key: &[u8], nonce: &[u8; 12], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid("key length"))?;
    c.encrypt(nonce.into(), Payload { msg, aad })
        .map_err(|_| Error::Invalid("AEAD seal"))
}

pub fn open(key: &[u8], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<SecretBytes> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid("key length"))?;
    let mut pt = c
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)?;
    let s = SecretBytes::new(&pt);
    pt.zeroize();
    Ok(s)
}
