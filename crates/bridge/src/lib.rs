//! `ykvault-bridge` (workstream E): Chrome native messaging (stdin/stdout,
//! native-endian u32 length + JSON) <-> Unix socket to the menu bar app
//! (little-endian u32 length + JSON). Protocol: `docs/SPEC.md` §12.
//!
//! The bridge is a dumb relay. It never parses message contents beyond a
//! size and UTF-8 check, and it wipes every buffer after relaying it.

use std::io::{self, Read, Write};

/// Maximum message size on both legs (SPEC §12.1).
pub const MAX_MSG: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    /// Chrome side: native byte order.
    Native,
    /// Socket side: little-endian.
    Little,
}

/// Reads one frame. Returns `Ok(None)` on a clean EOF before the length.
pub fn read_frame(r: &mut impl Read, e: Endian) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let n = match e {
        Endian::Native => u32::from_ne_bytes(len),
        Endian::Little => u32::from_le_bytes(len),
    } as usize;
    if n == 0 || n > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    if std::str::from_utf8(&buf).is_err() {
        wipe(&mut buf);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame is not UTF-8"));
    }
    Ok(Some(buf))
}

/// Writes one frame and flushes.
pub fn write_frame(w: &mut impl Write, e: Endian, msg: &[u8]) -> io::Result<()> {
    if msg.is_empty() || msg.len() > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad frame length"));
    }
    let n = msg.len() as u32;
    let len = match e {
        Endian::Native => n.to_ne_bytes(),
        Endian::Little => n.to_le_bytes(),
    };
    w.write_all(&len)?;
    w.write_all(msg)?;
    w.flush()
}

/// Overwrites a buffer with zeros in a way the optimiser keeps.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned &mut u8.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Relays frames from `r` to `w` until EOF, wiping each one afterwards.
pub fn relay(r: &mut impl Read, re: Endian, w: &mut impl Write, we: Endian) -> io::Result<()> {
    while let Some(mut msg) = read_frame(r, re)? {
        let res = write_frame(w, we, &msg);
        wipe(&mut msg);
        res?;
    }
    Ok(())
}

/// Chrome passes the caller as `chrome-extension://<32 a-p chars>/`.
/// Returns it only if it has exactly that shape (so it is safe to embed in JSON).
pub fn caller_origin(arg: &str) -> Option<&str> {
    let id = arg.strip_prefix("chrome-extension://")?.strip_suffix('/')?;
    (id.len() == 32 && id.bytes().all(|c| (b'a'..=b'p').contains(&c))).then_some(arg)
}

/// First message the bridge sends to the app on every connection.
pub fn bridge_hello(caller: Option<&str>) -> String {
    match caller {
        Some(c) => format!(
            r#"{{"v":1,"type":"bridge_hello","bridge_version":"{}","caller_origin":"{c}"}}"#,
            env!("CARGO_PKG_VERSION")
        ),
        None => format!(
            r#"{{"v":1,"type":"bridge_hello","bridge_version":"{}"}}"#,
            env!("CARGO_PKG_VERSION")
        ),
    }
}

/// Error message sent to the extension when the app cannot be reached.
pub fn error_msg(code: &str) -> String {
    format!(r#"{{"v":1,"type":"error","code":"{code}"}}"#)
}

pub mod peer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_both_endians() {
        for e in [Endian::Native, Endian::Little] {
            let mut out = Vec::new();
            write_frame(&mut out, e, br#"{"v":1}"#).unwrap();
            write_frame(&mut out, e, br#"{"v":1,"type":"x"}"#).unwrap();
            let mut r = &out[..];
            assert_eq!(read_frame(&mut r, e).unwrap().unwrap(), br#"{"v":1}"#);
            assert_eq!(read_frame(&mut r, e).unwrap().unwrap(), br#"{"v":1,"type":"x"}"#);
            assert!(read_frame(&mut r, e).unwrap().is_none());
        }
        let mut out = Vec::new();
        write_frame(&mut out, Endian::Little, b"ab").unwrap();
        assert_eq!(&out[..4], &[2, 0, 0, 0]);
    }

    #[test]
    fn rejects_oversize_empty_truncated_and_non_utf8() {
        let mut big = ((MAX_MSG + 1) as u32).to_le_bytes().to_vec();
        big.extend(vec![b'a'; MAX_MSG + 1]);
        assert!(read_frame(&mut &big[..], Endian::Little).is_err());
        assert!(read_frame(&mut &0u32.to_le_bytes()[..], Endian::Little).is_err());
        let mut trunc = 10u32.to_le_bytes().to_vec();
        trunc.extend(b"abc");
        assert!(read_frame(&mut &trunc[..], Endian::Little).is_err());
        let mut bad = 2u32.to_le_bytes().to_vec();
        bad.extend([0xff, 0xfe]);
        assert!(read_frame(&mut &bad[..], Endian::Little).is_err());
        assert!(write_frame(&mut Vec::new(), Endian::Little, &vec![b'a'; MAX_MSG + 1]).is_err());
        // Exactly the maximum is fine.
        let mut ok = Vec::new();
        write_frame(&mut ok, Endian::Native, &vec![b'a'; MAX_MSG]).unwrap();
        assert_eq!(read_frame(&mut &ok[..], Endian::Native).unwrap().unwrap().len(), MAX_MSG);
    }

    #[test]
    fn relay_converts_endianness() {
        let mut input = Vec::new();
        write_frame(&mut input, Endian::Native, b"one").unwrap();
        write_frame(&mut input, Endian::Native, b"two").unwrap();
        let mut out = Vec::new();
        relay(&mut &input[..], Endian::Native, &mut out, Endian::Little).unwrap();
        let mut r = &out[..];
        assert_eq!(read_frame(&mut r, Endian::Little).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut r, Endian::Little).unwrap().unwrap(), b"two");
    }

    #[test]
    fn caller_origin_shape() {
        let good = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
        assert_eq!(caller_origin(good), Some(good));
        assert_eq!(caller_origin("chrome-extension://abc/"), None);
        assert_eq!(caller_origin("chrome-extension://abcdefghijklmnopabcdefghijklmnoz/"), None);
        assert_eq!(caller_origin("chrome-extension://abcdefghijklmnopabcdefghijklmnop\"/"), None);
        assert!(bridge_hello(Some(good)).contains(good));
        assert!(!bridge_hello(None).contains("caller_origin"));
    }

    #[test]
    fn wipe_zeroes() {
        let mut b = b"secret".to_vec();
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
    }
}
