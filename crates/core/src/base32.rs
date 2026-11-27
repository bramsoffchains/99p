//! RFC 4648 base32 (standard alphabet), as used by TOTP secrets.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes without `=` padding (the form authenticator apps expect).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes case-insensitively, ignoring spaces, hyphens and trailing `=`.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    let trimmed = text.trim_end_matches(|c: char| c == '=' || c.is_whitespace());
    for c in trimmed.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'-' | b'\t' => continue,
            _ => return Err(Error::Format("invalid base32 character")),
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];
        for (plain, enc) in cases {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn lenient_decode() {
        assert_eq!(decode("mzxw 6ytb-oi======").unwrap(), b"foobar");
        assert!(decode("MZX1").is_err());
    }
}
