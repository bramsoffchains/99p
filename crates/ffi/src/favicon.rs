//! Favicon cache keys (SPEC §10). The app owns the files; this only derives
//! the opaque filename and seals or opens the PNG.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
use sha2::Sha256;
use p99_core::{Error, Result, crypto};
use zeroize::Zeroizing;

const MAX_PNG: usize = 8 * 1024;

fn keys(vault_secret: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(b"99p/v1/favicons"), vault_secret);
    let (mut name, mut enc) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    hk.expand(b"name", &mut name[..]).expect("32 bytes");
    hk.expand(b"enc", &mut enc[..]).expect("32 bytes");
    (name, enc)
}

pub fn name(vault_secret: &[u8; 32], host: &str) -> String {
    let (k_name, _) = keys(vault_secret);
    let mac = hmac::Hmac::<Sha256>::new_from_slice(&k_name[..]).expect("any key length")
        .chain_update(host.as_bytes())
        .finalize()
        .into_bytes();
    mac[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Checks the PNG signature and a 32×32 IHDR.
fn is_png_32(png: &[u8]) -> bool {
    png.len() <= MAX_PNG
        && png.len() >= 24
        && png[..8] == *b"\x89PNG\r\n\x1a\n"
        && png[12..16] == *b"IHDR"
        && png[16..20] == 32u32.to_be_bytes()
        && png[20..24] == 32u32.to_be_bytes()
}

pub fn seal(vault_secret: &[u8; 32], host: &str, png: &[u8]) -> Result<Vec<u8>> {
    if !is_png_32(png) {
        return Err(Error::Invalid("favicon must be a 32x32 PNG of at most 8 KiB"));
    }
    let (_, k_enc) = keys(vault_secret);
    let file = name(vault_secret, host);
    let nonce = crypto::random_bytes::<12>()?;
    let ct = ChaCha20Poly1305::new_from_slice(&k_enc[..])
        .expect("32-byte key")
        .encrypt(&Nonce::from(nonce), Payload { msg: png, aad: file.as_bytes() })
        .map_err(|_| Error::Invalid("encrypt"))?;
    Ok([&nonce[..], &ct].concat())
}

pub fn open(vault_secret: &[u8; 32], host: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 + 16 {
        return Err(Error::Decrypt);
    }
    let (_, k_enc) = keys(vault_secret);
    let file = name(vault_secret, host);
    let nonce: [u8; 12] = blob[..12].try_into().expect("12");
    ChaCha20Poly1305::new_from_slice(&k_enc[..])
        .expect("32-byte key")
        .decrypt(&Nonce::from(nonce), Payload { msg: &blob[12..], aad: file.as_bytes() })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png() -> Vec<u8> {
        let mut p = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        p.extend_from_slice(&32u32.to_be_bytes());
        p.extend_from_slice(&32u32.to_be_bytes());
        p.extend_from_slice(&[8, 6, 0, 0, 0]);
        p
    }

    #[test]
    fn seal_open() {
        let s = [7u8; 32];
        let n = name(&s, "github.com");
        assert_eq!(n.len(), 32);
        assert_ne!(n, name(&s, "gitlab.com"));
        assert_ne!(n, name(&[8u8; 32], "github.com"));
        let blob = seal(&s, "github.com", &png()).unwrap();
        assert_eq!(open(&s, "github.com", &blob).unwrap(), png());
        // Bound to the host and the vault.
        assert_eq!(open(&s, "gitlab.com", &blob), Err(Error::Decrypt));
        assert_eq!(open(&[8u8; 32], "github.com", &blob), Err(Error::Decrypt));
        assert!(seal(&s, "x", b"not a png").is_err());
    }
}
