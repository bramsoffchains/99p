//! Plaintext framing before AEAD, SPEC §6.1: header, optional raw DEFLATE, 1 KiB padding.

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::SecretBytes;

pub const SCHEMA_V: u16 = 1;
const INFLATE_CAP: usize = 1 << 20;

/// `ct_len` for a stored body of `body_len` bytes.
pub fn ct_len_for(body_len: usize) -> usize {
    (12 + body_len + 16).div_ceil(1024) * 1024
}

/// Frames `body`, compressing it when that helps, and pads to `ct_len − 16`.
/// With `pad = false` (exports) no padding is added.
pub fn pack(body: &[u8], pad: bool) -> Vec<u8> {
    let mut z = miniz_oxide::deflate::compress_to_vec(body, 10);
    let (method, stored): (u8, &[u8]) = if z.len() < body.len() {
        (1, &z)
    } else {
        (0, body)
    };
    let total = if pad {
        ct_len_for(stored.len()) - 16
    } else {
        12 + stored.len()
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&SCHEMA_V.to_le_bytes());
    out.push(method);
    out.push(0);
    out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(stored);
    out.resize(total, 0);
    z.zeroize();
    out
}

/// Returns `(schema_v, body)`. A newer `schema_v` is reported to the caller,
/// which opens the vault read-only.
pub fn unpack(pt: &[u8]) -> Result<(u16, SecretBytes)> {
    if pt.len() < 12 || pt[3] != 0 {
        return Err(Error::Format("payload header"));
    }
    let schema = u16::from_le_bytes([pt[0], pt[1]]);
    let body_len = u32::from_le_bytes(pt[4..8].try_into().unwrap()) as usize;
    let raw_len = u32::from_le_bytes(pt[8..12].try_into().unwrap()) as usize;
    let stored = pt
        .get(12..12 + body_len)
        .ok_or(Error::Format("payload body length"))?;
    if raw_len > INFLATE_CAP {
        return Err(Error::Format("payload too large"));
    }
    let body = match pt[2] {
        0 => SecretBytes::new(stored),
        1 => {
            let mut v = miniz_oxide::inflate::decompress_to_vec_with_limit(stored, raw_len)
                .map_err(|_| Error::Format("inflate"))?;
            let ok = v.len() == raw_len;
            let s = SecretBytes::new(&v);
            v.zeroize();
            if !ok {
                return Err(Error::Format("inflated length"));
            }
            s
        }
        _ => return Err(Error::Unsupported("compression method")),
    };
    Ok((schema, body))
}
