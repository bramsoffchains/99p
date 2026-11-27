//! TLV codec, SPEC §6.2: `tag: u8 || len: LEB128 || value`.

use crate::error::{Error, Result};

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos).ok_or(Error::Format("truncated varint"))?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return Err(Error::Format("varint overflow"));
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(Error::Format("varint too long"))
}

pub fn varint_value(v: &[u8]) -> Result<u64> {
    let mut pos = 0;
    let n = get_varint(v, &mut pos)?;
    if pos != v.len() {
        return Err(Error::Format("trailing bytes after varint"));
    }
    Ok(n)
}

/// Appends TLV items to a buffer.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn bytes(&mut self, tag: u8, value: &[u8]) {
        self.buf.push(tag);
        put_varint(&mut self.buf, value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    pub fn uint(&mut self, tag: u8, v: u64) {
        let mut tmp = Vec::with_capacity(10);
        put_varint(&mut tmp, v);
        self.bytes(tag, &tmp);
    }

    pub fn flag(&mut self, tag: u8, v: bool) {
        if v {
            self.bytes(tag, &[1]);
        }
    }
}

/// Iterates over the TLV items in a buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<(u8, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = self.buf[self.pos];
        self.pos += 1;
        let item = get_varint(self.buf, &mut self.pos).and_then(|len| {
            let end = self
                .pos
                .checked_add(len as usize)
                .filter(|&e| e <= self.buf.len());
            let end = end.ok_or(Error::Format("TLV value runs past end"))?;
            let v = &self.buf[self.pos..end];
            self.pos = end;
            Ok((tag, v))
        });
        if item.is_err() {
            self.pos = self.buf.len();
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(varint_value(&b).unwrap(), v);
        }
        assert!(varint_value(&[0x80]).is_err());
        assert!(varint_value(&[0xff; 11]).is_err());
    }

    #[test]
    fn tlv_roundtrip_and_truncation() {
        let mut w = Writer::default();
        w.bytes(1, b"abc");
        w.uint(2, 1000);
        let items: Vec<_> = Reader::new(&w.buf).collect::<Result<_>>().unwrap();
        assert_eq!(items, vec![(1, &b"abc"[..]), (2, &[0xe8, 0x07][..])]);
        let cut = &w.buf[..w.buf.len() - 1];
        assert!(Reader::new(cut).any(|i| i.is_err()));
    }
}
