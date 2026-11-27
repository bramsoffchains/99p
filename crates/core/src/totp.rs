//! RFC 6238 TOTP and the packed field value format (SPEC §6.4):
//! `flags: u8 || period: u8 || secret`, flags bits 0-1 = algorithm,
//! bits 2-3 = digits − 6, period 0 = 30 s.

use crate::error::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub algorithm: Algorithm,
    /// 6, 7 or 8.
    pub digits: u8,
    /// Seconds, 1..=255.
    pub period: u8,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        }
    }
}

/// Builds the packed field value. 30 s is stored as 0 (canonical default).
pub fn pack(params: Params, secret: &[u8]) -> Result<Vec<u8>> {
    if !(6..=8).contains(&params.digits) || params.period == 0 {
        return Err(Error::Invalid(
            "TOTP digits must be 6-8 and period non-zero",
        ));
    }
    if secret.is_empty() {
        return Err(Error::Invalid("empty TOTP secret"));
    }
    let flags = params.algorithm as u8 | ((params.digits - 6) << 2);
    let period = if params.period == 30 {
        0
    } else {
        params.period
    };
    let mut v = Vec::with_capacity(2 + secret.len());
    v.extend_from_slice(&[flags, period]);
    v.extend_from_slice(secret);
    Ok(v)
}

/// Splits a packed field value into params and the raw secret.
pub fn unpack(value: &[u8]) -> Result<(Params, &[u8])> {
    let [flags, period, secret @ ..] = value else {
        return Err(Error::Format("TOTP value too short"));
    };
    let algorithm = match flags & 3 {
        0 => Algorithm::Sha1,
        1 => Algorithm::Sha256,
        2 => Algorithm::Sha512,
        _ => return Err(Error::Format("unknown TOTP algorithm")),
    };
    let digits = 6 + ((flags >> 2) & 3);
    if digits > 8 || flags >> 4 != 0 || secret.is_empty() {
        return Err(Error::Format("bad TOTP flags"));
    }
    let period = if *period == 0 { 30 } else { *period };
    Ok((
        Params {
            algorithm,
            digits,
            period,
        },
        secret,
    ))
}

fn mac<M: Mac + KeyInit>(secret: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <M as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// RFC 4226 HOTP value for `counter`.
pub fn hotp(algorithm: Algorithm, secret: &[u8], counter: u64, digits: u8) -> u32 {
    let msg = counter.to_be_bytes();
    let h = match algorithm {
        Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(secret, &msg),
        Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(secret, &msg),
        Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(secret, &msg),
    };
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits as u32)
}

/// A code for display: zero-padded digits and seconds until it changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub code: String,
    pub remaining_secs: u32,
    pub period: u32,
}

/// TOTP code at Unix time `now` for raw params and secret.
pub fn code(params: Params, secret: &[u8], now: u64) -> Code {
    let period = params.period.max(1) as u64;
    let v = hotp(params.algorithm, secret, now / period, params.digits);
    Code {
        code: format!("{:0width$}", v, width = params.digits as usize),
        remaining_secs: (period - now % period) as u32,
        period: period as u32,
    }
}

/// TOTP code at Unix time `now` for a packed field value.
pub fn code_for_field(value: &[u8], now: u64) -> Result<Code> {
    let (params, secret) = unpack(value)?;
    Ok(code(params, secret, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B. Seeds are the ASCII digits repeated to the hash size.
    const S1: &[u8] = b"12345678901234567890";
    const S256: &[u8] = b"12345678901234567890123456789012";
    const S512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_vectors() {
        let table: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in table {
            let p = |algorithm| Params {
                algorithm,
                digits: 8,
                period: 30,
            };
            assert_eq!(code(p(Algorithm::Sha1), S1, t).code, c1, "sha1 t={t}");
            assert_eq!(
                code(p(Algorithm::Sha256), S256, t).code,
                c256,
                "sha256 t={t}"
            );
            assert_eq!(
                code(p(Algorithm::Sha512), S512, t).code,
                c512,
                "sha512 t={t}"
            );
        }
    }

    #[test]
    fn rfc4226_six_digits() {
        let expected = [755224, 287082, 359152, 969429, 338314];
        for (i, e) in expected.iter().enumerate() {
            assert_eq!(hotp(Algorithm::Sha1, S1, i as u64, 6), *e);
        }
    }

    #[test]
    fn pack_roundtrip_and_remaining() {
        for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
            for digits in 6..=8 {
                for period in [30, 60, 15] {
                    let p = Params {
                        algorithm,
                        digits,
                        period,
                    };
                    let v = pack(p, S1).unwrap();
                    assert_eq!(unpack(&v).unwrap(), (p, S1));
                }
            }
        }
        assert_eq!(pack(Params::default(), b"k").unwrap(), [0, 0, b'k']);
        let c = code_for_field(&pack(Params::default(), S1).unwrap(), 59).unwrap();
        assert_eq!((c.code.as_str(), c.remaining_secs), ("287082", 1));
        assert!(unpack(&[0x03, 0, 1]).is_err());
        assert!(unpack(&[0x10, 0, 1]).is_err());
        assert!(unpack(&[0, 0]).is_err());
        assert!(pack(
            Params {
                digits: 9,
                ..Params::default()
            },
            S1
        )
        .is_err());
    }
}
