//! Minimal JSON reader and writer for plaintext import/export (no serde).
//! Numbers are kept as their source text; callers convert what they need.

use crate::error::{Error, Result};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Drop for Value {
    fn drop(&mut self) {
        // Parsed exports hold passwords; wipe strings as they go.
        match self {
            Value::String(s) | Value::Number(s) => s.zeroize(),
            Value::Object(o) => o.iter_mut().for_each(|(k, _)| k.zeroize()),
            _ => {}
        }
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> &[Value] {
        match self {
            Value::Array(a) => a,
            _ => &[],
        }
    }
}

const MAX_DEPTH: usize = 32;

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

pub fn parse(text: &str) -> Result<Value> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(Error::Format("trailing data after JSON"));
    }
    Ok(v)
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && b" \t\r\n".contains(&self.b[self.i]) {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn eat(&mut self, c: u8) -> Result<()> {
        self.ws();
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(Error::Format("unexpected JSON character"))
        }
    }
    fn lit(&mut self, s: &str, v: Value) -> Result<Value> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            Err(Error::Format("bad JSON literal"))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::Format("JSON nested too deeply"));
        }
        self.ws();
        match self.peek().ok_or(Error::Format("unexpected end of JSON"))? {
            b'n' => self.lit("null", Value::Null),
            b't' => self.lit("true", Value::Bool(true)),
            b'f' => self.lit("false", Value::Bool(false)),
            b'"' => Ok(Value::String(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(a));
                        }
                        _ => return Err(Error::Format("expected , or ] in JSON")),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut o = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Object(o));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return Err(Error::Format("expected JSON object key"));
                    }
                    let k = self.string()?;
                    self.eat(b':')?;
                    o.push((k, self.value(depth + 1)?));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(o));
                        }
                        _ => return Err(Error::Format("expected , or } in JSON")),
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                let n = std::str::from_utf8(&self.b[start..self.i]).unwrap_or_default();
                n.parse::<f64>()
                    .map_err(|_| Error::Format("bad JSON number"))?;
                Ok(Value::Number(n.to_string()))
            }
            _ => Err(Error::Format("unexpected JSON character")),
        }
    }
    fn hex4(&mut self) -> Result<u32> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .ok_or(Error::Format("short \\u escape"))?;
        let s = std::str::from_utf8(h).map_err(|_| Error::Format("bad \\u escape"))?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| Error::Format("bad \\u escape"))
    }
    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let c = self
                .peek()
                .ok_or(Error::Format("unterminated JSON string"))?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(Error::Format("bad JSON escape"))?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp)
                                && self.b[self.i..].starts_with(b"\\u")
                            {
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Error::Format("bad JSON surrogate pair"));
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            char::from_u32(cp).ok_or(Error::Format("bad JSON surrogate"))?
                        }
                        _ => return Err(Error::Format("bad JSON escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return Err(Error::Format("control character in JSON string")),
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|e| {
            let mut b = e.into_bytes();
            b.zeroize();
            Error::Format("JSON string is not UTF-8")
        })
    }
}

/// Appends `s` as a JSON string literal.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Writes `v` compactly.
pub fn write(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write(out, x);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let src = r#"{"a":[1,-2.5e3,true,false,null],"s":"q\"\\\n\t\u0001é😀","o":{}}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("s").unwrap().as_str().unwrap(), "q\"\\\n\t\u{1}é😀");
        let mut out = String::new();
        write(&mut out, &v);
        assert_eq!(parse(&out).unwrap(), v);
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
        assert_eq!(
            parse(" [ 1 , 2 ] ").unwrap().as_array()[1].as_u64(),
            Some(2)
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\"}",
            "tru",
            "\"\u{1}\"",
            "1 2",
            "\"\\x\"",
            "{1:2}",
            "01x",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&deep).is_err());
    }
}
