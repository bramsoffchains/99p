//! `otpauth://totp/...` URIs: parsed on import, generated on export (SPEC §6.4).

use crate::base32;
use crate::error::{Error, Result};
use crate::totp::{Algorithm, Params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuth {
    pub issuer: Option<String>,
    pub account: String,
    pub params: Params,
    pub secret: Vec<u8>,
}

impl OtpAuth {
    /// The packed TOTP field value (SPEC §6.4).
    pub fn packed(&self) -> Result<Vec<u8>> {
        crate::totp::pack(self.params, &self.secret)
    }
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = b.get(i + 1).and_then(|c| hex(*c));
                let l = b.get(i + 2).and_then(|c| hex(*c));
                match (h, l) {
                    (Some(h), Some(l)) => out.push(h << 4 | l),
                    _ => return Err(Error::Format("bad percent escape in otpauth URI")),
                }
                i += 3;
                continue;
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| Error::Format("otpauth URI is not UTF-8"))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// Parses an `otpauth://totp/` URI. HOTP is out of scope for v1.
pub fn parse(uri: &str) -> Result<OtpAuth> {
    let uri = uri.trim();
    let rest = uri
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
        .map(|_| &uri[10..])
        .ok_or(Error::Format("not an otpauth:// URI"))?;
    let (kind, rest) = rest
        .split_once('/')
        .ok_or(Error::Format("otpauth URI has no label"))?;
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::Unsupported("only otpauth://totp is supported"));
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label)?;
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label.trim().to_string()),
    };
    let mut params = Params::default();
    let mut secret = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32::decode(&v)?),
            "issuer" if !v.is_empty() => issuer = Some(v),
            "algorithm" => {
                params.algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(Error::Unsupported("TOTP algorithm")),
                }
            }
            "digits" => {
                params.digits = v
                    .parse()
                    .ok()
                    .filter(|d| (6..=8).contains(d))
                    .ok_or(Error::Unsupported("TOTP digits must be 6, 7 or 8"))?
            }
            "period" => {
                params.period = v
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or(Error::Unsupported("TOTP period must be 1-255 seconds"))?
            }
            _ => {}
        }
    }
    let secret = secret
        .filter(|s| !s.is_empty())
        .ok_or(Error::Format("otpauth URI has no secret"))?;
    Ok(OtpAuth {
        issuer,
        account,
        params,
        secret,
    })
}

/// Emits a URI accepted by common authenticator apps. Default parameters are omitted.
pub fn emit(o: &OtpAuth) -> String {
    let label = match &o.issuer {
        Some(i) => format!("{}:{}", percent_encode(i), percent_encode(&o.account)),
        None => percent_encode(&o.account),
    };
    let mut uri = format!(
        "otpauth://totp/{label}?secret={}",
        base32::encode(&o.secret)
    );
    if let Some(i) = &o.issuer {
        uri += &format!("&issuer={}", percent_encode(i));
    }
    let p = o.params;
    if p.algorithm != Algorithm::Sha1 {
        uri += match p.algorithm {
            Algorithm::Sha256 => "&algorithm=SHA256",
            _ => "&algorithm=SHA512",
        };
    }
    if p.digits != 6 {
        uri += &format!("&digits={}", p.digits);
    }
    if p.period != 30 {
        uri += &format!("&period={}", p.period);
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_google_example() {
        let o =
            parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
                .unwrap();
        assert_eq!(o.issuer.as_deref(), Some("Example"));
        assert_eq!(o.account, "alice@google.com");
        assert_eq!(o.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(o.params, Params::default());
    }

    #[test]
    fn parse_params_and_escapes() {
        let o = parse("OTPAUTH://TOTP/ACME%20Co%3Ajohn%40x.com?secret=jbswy3dpehpk3pxp&algorithm=sha256&digits=8&period=60").unwrap();
        assert_eq!(o.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(o.account, "john@x.com");
        assert_eq!(
            o.params,
            Params {
                algorithm: Algorithm::Sha256,
                digits: 8,
                period: 60
            }
        );
    }

    #[test]
    fn roundtrip() {
        let o = OtpAuth {
            issuer: Some("Big & Co".into()),
            account: "me:you@x".into(),
            params: Params {
                algorithm: Algorithm::Sha512,
                digits: 7,
                period: 45,
            },
            secret: vec![1, 2, 3, 4, 5, 250],
        };
        assert_eq!(parse(&emit(&o)).unwrap().secret, o.secret);
        assert_eq!(parse(&emit(&o)).unwrap().params, o.params);
        assert_eq!(parse(&emit(&o)).unwrap().issuer, o.issuer);
    }

    #[test]
    fn rejects() {
        assert!(parse("otpauth://hotp/x?secret=JBSWY3DP&counter=1").is_err());
        assert!(parse("otpauth://totp/x").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DP&digits=10").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DP&period=300").is_err());
        assert!(parse("otpauth://totp/%zz?secret=JBSWY3DP").is_err());
        assert!(parse("https://example.com").is_err());
    }
}
