//! Plaintext import and export (SPEC §13.2): CSV compatible with Chrome,
//! 1Password and Bitwarden, and the lossless `99p-v1` JSON format.
//! Callers must warn the user and write files 0600.

use crate::error::{Error, Result};
use crate::json::{self, Value};
use crate::model::{Entry, EntryKind, Field, FieldKind, Timestamp};
use crate::{crypto, host, otpauth, totp};
use zeroize::{Zeroize, Zeroizing};

/// Entries parsed from a file, plus rows that were skipped (1-based line of the record, reason).
#[derive(Debug, Default)]
pub struct Import {
    pub entries: Vec<Entry>,
    pub skipped: Vec<(usize, &'static str)>,
}

fn text_field(kind: FieldKind, value: &str) -> Field {
    Field {
        kind,
        label: None,
        value: value.as_bytes().to_vec(),
    }
}

fn custom(kind: FieldKind, label: &str, value: &str) -> Field {
    Field {
        kind,
        label: Some(label.to_string()),
        value: value.as_bytes().to_vec(),
    }
}

fn field_text(e: &Entry, kind: FieldKind) -> Option<&str> {
    e.fields
        .iter()
        .find(|f| f.kind == kind)
        .and_then(|f| std::str::from_utf8(&f.value).ok())
}

// ---------------------------------------------------------------- CSV

/// RFC 4180 records with the 1-based line each starts on.
fn parse_csv(text: &str) -> Result<Vec<(usize, Zeroizing<Vec<String>>)>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row = Zeroizing::new(Vec::new());
    let mut cell = String::new();
    let (mut line, mut start, mut quoted, mut any) = (1usize, 1usize, false, false);
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            match c {
                '"' if it.peek() == Some(&'"') => {
                    it.next();
                    cell.push('"');
                }
                '"' => quoted = false,
                '\n' => {
                    line += 1;
                    cell.push(c);
                }
                _ => cell.push(c),
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut cell)),
            '\r' if it.peek() == Some(&'\n') => {}
            '\n' => {
                row.push(std::mem::take(&mut cell));
                if row.iter().any(|c| !c.is_empty()) {
                    rows.push((
                        start,
                        std::mem::replace(&mut row, Zeroizing::new(Vec::new())),
                    ));
                }
                row.clear();
                line += 1;
                start = line;
                any = false;
                continue;
            }
            _ => cell.push(c),
        }
        any = true;
    }
    if quoted {
        return Err(Error::Format("unterminated quote in CSV"));
    }
    if any || !cell.is_empty() {
        row.push(std::mem::take(&mut cell));
    }
    if row.iter().any(|c| !c.is_empty()) {
        rows.push((start, row));
    }
    Ok(rows)
}

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Name,
    Url,
    Username,
    Password,
    Note,
    Totp,
    Type,
    Fields,
    Ignore,
    Other,
}

fn column(header: &str) -> Col {
    match header.trim().to_ascii_lowercase().as_str() {
        "name" | "title" => Col::Name,
        "url" | "urls" | "website" | "login_uri" | "uri" => Col::Url,
        "username" | "login_username" | "user name" | "email" => Col::Username,
        "password" | "login_password" => Col::Password,
        "note" | "notes" => Col::Note,
        "otpauth" | "totp" | "login_totp" | "one-time password" | "otp" => Col::Totp,
        "type" => Col::Type,
        "fields" => Col::Fields,
        "folder" | "favorite" | "archived" | "tags" | "reprompt" | "collections" => Col::Ignore,
        _ => Col::Other,
    }
}

/// A TOTP value from an `otpauth://` URI or a bare base32 secret.
fn parse_totp(s: &str) -> Result<Vec<u8>> {
    if s.trim_start()
        .to_ascii_lowercase()
        .starts_with("otpauth://")
    {
        otpauth::parse(s)?.packed()
    } else {
        totp::pack(
            totp::Params::default(),
            &Zeroizing::new(crate::base32::decode(s)?),
        )
    }
}

/// Imports a CSV export from Chrome, 1Password, Bitwarden or 99passwords.
pub fn import_csv(text: &str, now: Timestamp) -> Result<Import> {
    let mut rows = parse_csv(text)?.into_iter();
    let (_, header) = rows.next().ok_or(Error::Format("empty CSV"))?;
    let cols: Vec<Col> = header.iter().map(|h| column(h)).collect();
    if !cols.contains(&Col::Password) && !cols.contains(&Col::Note) {
        return Err(Error::Format("CSV has no password or note column"));
    }
    let mut out = Import::default();
    for (line, row) in rows {
        let mut name = String::new();
        let mut is_note = false;
        let mut hosts = Vec::new();
        let mut fields = Vec::new();
        let mut note = None;
        for (i, v) in row.iter().enumerate() {
            let v = v.as_str();
            if v.trim().is_empty() {
                continue;
            }
            match cols.get(i).copied().unwrap_or(Col::Other) {
                Col::Name => name = v.trim().to_string(),
                Col::Url => {
                    for u in v
                        .split([',', '\n'])
                        .map(str::trim)
                        .filter(|u| !u.is_empty())
                    {
                        // Only web URLs become hosts; app links etc. are kept as text.
                        let web = match u.split_once("://") {
                            Some((scheme, _)) => {
                                matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
                            }
                            None => true,
                        };
                        match host::normalize(u) {
                            Ok(h) if web && h.contains('.') => {
                                if !hosts.contains(&h) {
                                    hosts.push(h)
                                }
                            }
                            _ => fields.push(custom(FieldKind::CustomText, "URL", u)),
                        }
                    }
                }
                Col::Username => fields.push(text_field(FieldKind::Username, v)),
                Col::Password => fields.push(text_field(FieldKind::Password, v)),
                Col::Note => note = Some(v),
                Col::Totp => match parse_totp(v) {
                    Ok(t) => fields.push(Field {
                        kind: FieldKind::Totp,
                        label: None,
                        value: t,
                    }),
                    Err(_) => fields.push(custom(FieldKind::CustomSecret, "One-time password", v)),
                },
                Col::Type => is_note = matches!(v.trim(), "note" | "securenote" | "2"),
                Col::Fields => {
                    // Bitwarden: one "label: value" per line.
                    for l in v.lines().filter(|l| !l.trim().is_empty()) {
                        let (k, val) = l.split_once(": ").unwrap_or(("Field", l));
                        fields.push(custom(FieldKind::CustomText, k.trim(), val));
                    }
                }
                Col::Ignore => {}
                Col::Other => {
                    let label = header.get(i).map_or("Field", |h| h.trim());
                    fields.push(custom(FieldKind::CustomText, label, v))
                }
            }
        }
        if let Some(n) = note {
            fields.push(text_field(FieldKind::Note, n));
        }
        if fields.is_empty() && hosts.is_empty() {
            out.skipped.push((line, "row has no usable data"));
            continue;
        }
        if name.is_empty() {
            name = hosts.first().cloned().unwrap_or_else(|| "Untitled".into());
        }
        let has_login = fields
            .iter()
            .any(|f| matches!(f.kind, FieldKind::Username | FieldKind::Password));
        let kind = if is_note || (!has_login && hosts.is_empty()) {
            EntryKind::Note
        } else {
            EntryKind::Login
        };
        out.entries.push(Entry {
            id: crypto::random_u64()?,
            kind,
            name,
            hosts,
            created_at: now,
            updated_at: now,
            deleted: false,
            fields,
            extra: vec![],
        });
    }
    Ok(out)
}

fn csv_cell(out: &mut String, s: &str) {
    if s.contains([',', '"', '\n', '\r']) || s.starts_with(' ') || s.ends_with(' ') {
        out.push('"');
        out.push_str(&s.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(s);
    }
}

fn totp_uri(e: &Entry, value: &[u8]) -> Option<String> {
    let (params, secret) = totp::unpack(value).ok()?;
    let account = field_text(e, FieldKind::Username)
        .unwrap_or(&e.name)
        .to_string();
    Some(otpauth::emit(&otpauth::OtpAuth {
        issuer: Some(e.name.clone()),
        account,
        params,
        secret: secret.to_vec(),
    }))
}

/// Chrome-compatible CSV (`name,url,username,password,note,otpauth`) of live
/// logins. Lossy: cards, custom fields and extra hosts are left out; use JSON
/// for a full export. Returns the CSV and how many entries were left out.
pub fn export_csv(entries: &[Entry]) -> (Zeroizing<String>, usize) {
    let mut out = Zeroizing::new(String::from("name,url,username,password,note,otpauth\n"));
    let mut left_out = 0;
    for e in entries.iter().filter(|e| !e.deleted) {
        if e.kind != EntryKind::Login {
            left_out += 1;
            continue;
        }
        let url = e
            .hosts
            .first()
            .map(|h| format!("https://{h}/"))
            .unwrap_or_default();
        let otp = e
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .and_then(|f| totp_uri(e, &f.value));
        let cells = [
            e.name.as_str(),
            &url,
            field_text(e, FieldKind::Username).unwrap_or(""),
            field_text(e, FieldKind::Password).unwrap_or(""),
            field_text(e, FieldKind::Note).unwrap_or(""),
            otp.as_deref().unwrap_or(""),
        ];
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            csv_cell(&mut out, c);
        }
        out.push('\n');
        if let Some(mut o) = otp {
            o.zeroize();
        }
    }
    (out, left_out)
}

// ---------------------------------------------------------------- JSON

const FORMAT: &str = "99p-v1";

const FIELD_NAMES: [(FieldKind, &str); 20] = [
    (FieldKind::Username, "username"),
    (FieldKind::Password, "password"),
    (FieldKind::Totp, "totp"),
    (FieldKind::CardNumber, "card_number"),
    (FieldKind::CardExpiry, "card_expiry"),
    (FieldKind::CardCvv, "card_cvv"),
    (FieldKind::CardHolder, "card_holder"),
    (FieldKind::Pin, "pin"),
    (FieldKind::Note, "note"),
    (FieldKind::CustomText, "custom_text"),
    (FieldKind::CustomSecret, "custom_secret"),
    (FieldKind::FirstName, "first_name"),
    (FieldKind::LastName, "last_name"),
    (FieldKind::Email, "email"),
    (FieldKind::Phone, "phone"),
    (FieldKind::Street, "street"),
    (FieldKind::City, "city"),
    (FieldKind::Postcode, "postcode"),
    (FieldKind::Region, "region"),
    (FieldKind::Country, "country"),
];

const KIND_NAMES: [(EntryKind, &str); 5] = [
    (EntryKind::Login, "login"),
    (EntryKind::Card, "card"),
    (EntryKind::Note, "note"),
    (EntryKind::Custom, "custom"),
    (EntryKind::Identity, "identity"),
];

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn n(v: u64) -> Value {
    Value::Number(v.to_string())
}

/// Lossless JSON export of every entry, tombstones included. TOTP values are
/// written as base64 of the packed bytes plus a convenience `otpauth` URI.
pub fn export_json(entries: &[Entry], now: Timestamp) -> Zeroizing<String> {
    let list = entries
        .iter()
        .map(|e| {
            let fields = e
                .fields
                .iter()
                .map(|f| {
                    let mut o = vec![(
                        "kind".into(),
                        s(FIELD_NAMES
                            .iter()
                            .find(|(k, _)| *k == f.kind)
                            .map(|x| x.1)
                            .unwrap_or("")),
                    )];
                    if let Some(l) = &f.label {
                        o.push(("label".into(), s(l)));
                    }
                    match (f.kind, std::str::from_utf8(&f.value)) {
                        (FieldKind::Totp, _) | (_, Err(_)) => {
                            o.push(("value_b64".into(), s(&b64_encode(&f.value))));
                            if let Some(u) = (f.kind == FieldKind::Totp)
                                .then(|| totp_uri(e, &f.value))
                                .flatten()
                            {
                                o.push(("otpauth".into(), Value::String(u)));
                            }
                        }
                        (_, Ok(t)) => o.push(("value".into(), s(t))),
                    }
                    Value::Object(o)
                })
                .collect();
            let extra = e
                .extra
                .iter()
                .map(|(t, v)| {
                    Value::Object(vec![
                        ("tag".into(), n(*t as u64)),
                        ("value_b64".into(), s(&b64_encode(v))),
                    ])
                })
                .collect();
            Value::Object(vec![
                ("id".into(), s(&format!("{:016x}", e.id))),
                (
                    "kind".into(),
                    s(KIND_NAMES
                        .iter()
                        .find(|(k, _)| *k == e.kind)
                        .map(|x| x.1)
                        .unwrap_or("")),
                ),
                ("name".into(), s(&e.name)),
                (
                    "hosts".into(),
                    Value::Array(e.hosts.iter().map(|h| s(h)).collect()),
                ),
                ("created_at".into(), n(e.created_at as u64)),
                ("updated_at".into(), n(e.updated_at as u64)),
                ("deleted".into(), Value::Bool(e.deleted)),
                ("fields".into(), Value::Array(fields)),
                ("extra".into(), Value::Array(extra)),
            ])
        })
        .collect();
    let doc = Value::Object(vec![
        ("format".into(), s(FORMAT)),
        ("exported_at".into(), n(now as u64)),
        ("entries".into(), Value::Array(list)),
    ]);
    let mut out = Zeroizing::new(String::new());
    json::write(&mut out, &doc);
    out.push('\n');
    out
}

fn u32_of(v: Option<&Value>) -> Result<u32> {
    v.and_then(Value::as_u64)
        .and_then(|x| u32::try_from(x).ok())
        .ok_or(Error::Format("bad timestamp in 99p-v1 JSON"))
}

fn entry_from_json(v: &Value) -> Result<Entry> {
    let bad = Error::Format("bad entry in 99p-v1 JSON");
    let id = v
        .get("id")
        .and_then(Value::as_str)
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .ok_or(bad.clone())?;
    let kind_name = v.get("kind").and_then(Value::as_str).ok_or(bad.clone())?;
    let kind = KIND_NAMES
        .iter()
        .find(|(_, n)| *n == kind_name)
        .ok_or(bad.clone())?
        .0;
    let mut fields = Vec::new();
    for f in v.get("fields").map(Value::as_array).unwrap_or(&[]) {
        let kn = f.get("kind").and_then(Value::as_str).ok_or(bad.clone())?;
        let fk = FIELD_NAMES
            .iter()
            .find(|(_, n)| *n == kn)
            .ok_or(bad.clone())?
            .0;
        let value = match (
            f.get("value").and_then(Value::as_str),
            f.get("value_b64").and_then(Value::as_str),
        ) {
            (_, Some(b)) => b64_decode(b)?,
            (Some(t), None) => t.as_bytes().to_vec(),
            (None, None) => return Err(bad),
        };
        if fk == FieldKind::Totp {
            totp::unpack(&value)?;
        }
        let label = f.get("label").and_then(Value::as_str).map(str::to_string);
        fields.push(Field {
            kind: fk,
            label,
            value,
        });
    }
    let mut extra = Vec::new();
    for x in v.get("extra").map(Value::as_array).unwrap_or(&[]) {
        let tag = x
            .get("tag")
            .and_then(Value::as_u64)
            .and_then(|t| u8::try_from(t).ok())
            .ok_or(bad.clone())?;
        let val = b64_decode(
            x.get("value_b64")
                .and_then(Value::as_str)
                .ok_or(bad.clone())?,
        )?;
        extra.push((tag, val));
    }
    let mut hosts = Vec::new();
    for h in v.get("hosts").map(Value::as_array).unwrap_or(&[]) {
        hosts.push(host::normalize(h.as_str().ok_or(bad.clone())?)?);
    }
    Ok(Entry {
        id,
        kind,
        name: v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        hosts,
        created_at: u32_of(v.get("created_at"))?,
        updated_at: u32_of(v.get("updated_at"))?,
        deleted: v.get("deleted").and_then(Value::as_bool).unwrap_or(false),
        fields,
        extra,
    })
}

/// Imports a `99p-v1` JSON export, keeping entry ids so a re-import merges.
pub fn import_json(text: &str) -> Result<Import> {
    let doc = json::parse(text)?;
    if doc.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(Error::Unsupported("not a 99p-v1 JSON export"));
    }
    let mut out = Import::default();
    for (i, e) in doc
        .get("entries")
        .map(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        match entry_from_json(e) {
            Ok(e) => out.entries.push(e),
            Err(_) => out.skipped.push((i + 1, "malformed entry")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = B64
            .iter()
            .position(|&x| x == c)
            .ok_or(Error::Format("bad base64"))? as u32;
        buf = buf << 6 | v;
        bits += 6;
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

    fn pw(e: &Entry) -> Option<&str> {
        field_text(e, FieldKind::Password)
    }

    #[test]
    fn base64_roundtrip() {
        for (p, e) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(p.as_bytes()), e);
            assert_eq!(b64_decode(e).unwrap(), p.as_bytes());
        }
    }

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\r\n\
                   GitHub,https://github.com/login,octo,\"p,a\"\"ss\",\"line1\nline2\"\r\n\
                   ,https://www.Example.com/,me,secret,\r\n\
                   ,,,,\r\n";
        let r = import_csv(csv, 100).unwrap();
        assert_eq!(r.entries.len(), 2);
        let g = &r.entries[0];
        assert_eq!(
            (g.name.as_str(), g.hosts.as_slice(), g.kind),
            ("GitHub", &["github.com".to_string()][..], EntryKind::Login)
        );
        assert_eq!(pw(g), Some("p,a\"ss"));
        assert_eq!(field_text(g, FieldKind::Note), Some("line1\nline2"));
        assert_eq!(r.entries[1].name, "www.example.com");
        assert_ne!(r.entries[0].id, r.entries[1].id);
    }

    #[test]
    fn onepassword_csv() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Mail,mail.example.com,a@b.c,pw1,otpauth://totp/Mail:a?secret=JBSWY3DPEHPK3PXP,false,false,,hi\n";
        let r = import_csv(csv, 1).unwrap();
        let e = &r.entries[0];
        assert_eq!(e.hosts, ["mail.example.com"]);
        let t = e.fields.iter().find(|f| f.kind == FieldKind::Totp).unwrap();
        assert_eq!(totp::unpack(&t.value).unwrap().1, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(e.fields.len(), 4); // username, password, totp, note
    }

    #[test]
    fn bitwarden_csv() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,Bank,,\"PIN: 1234\nQ: blue\",0,\"https://bank.com,https://app.bank.com\",me,pw,JBSWY3DPEHPK3PXP\n\
                   ,,note,Wifi,the code is 42,,0,,,,\n\
                   ,,login,App,,,0,androidapp://com.x,me,pw2,\n";
        let r = import_csv(csv, 1).unwrap();
        let bank = &r.entries[0];
        assert_eq!(bank.hosts, ["bank.com", "app.bank.com"]);
        assert!(bank
            .fields
            .iter()
            .any(|f| f.label.as_deref() == Some("PIN") && f.value == b"1234"));
        assert!(bank.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert_eq!(r.entries[1].kind, EntryKind::Note);
        let app = &r.entries[2];
        assert!(app.hosts.is_empty());
        assert!(app.fields.iter().any(|f| f.label.as_deref() == Some("URL")));
    }

    #[test]
    fn csv_errors() {
        assert!(import_csv("", 0).is_err());
        assert!(import_csv("a,b\n1,2\n", 0).is_err());
        assert!(import_csv("name,password\n\"x,y\n", 0).is_err());
    }

    fn sample() -> Vec<Entry> {
        let totp = totp::pack(
            totp::Params {
                algorithm: totp::Algorithm::Sha256,
                digits: 8,
                period: 60,
            },
            &[9; 20],
        )
        .unwrap();
        vec![
            Entry {
                id: u64::MAX - 5,
                kind: EntryKind::Login,
                name: "Git \"Hub\", Inc".into(),
                hosts: vec!["github.com".into(), "gist.github.com".into()],
                created_at: 10,
                updated_at: 20,
                deleted: false,
                fields: vec![
                    text_field(FieldKind::Username, "octo"),
                    text_field(FieldKind::Password, "p\nw,\"x\""),
                    Field {
                        kind: FieldKind::Totp,
                        label: None,
                        value: totp,
                    },
                    custom(FieldKind::CustomSecret, "API key", "k"),
                    Field {
                        kind: FieldKind::CustomText,
                        label: Some("bin".into()),
                        value: vec![0xff, 0],
                    },
                ],
                extra: vec![(0x42, vec![1, 2, 3])],
            },
            Entry {
                id: 7,
                kind: EntryKind::Card,
                name: "Visa".into(),
                hosts: vec![],
                created_at: 1,
                updated_at: 2,
                deleted: false,
                fields: vec![text_field(FieldKind::CardNumber, "4111111111111111")],
                extra: vec![],
            },
            Entry {
                id: 9,
                kind: EntryKind::Identity,
                name: "Me".into(),
                hosts: vec![],
                created_at: 4,
                updated_at: 5,
                deleted: false,
                fields: vec![
                    text_field(FieldKind::FirstName, "Ada"),
                    text_field(FieldKind::LastName, "Lovelace"),
                    text_field(FieldKind::Email, "ada@example.com"),
                    text_field(FieldKind::Street, "1 Analytical Way\nFlat 2"),
                    text_field(FieldKind::Country, "GB"),
                ],
                extra: vec![],
            },
            Entry {
                id: 8,
                kind: EntryKind::Login,
                name: String::new(),
                hosts: vec![],
                created_at: 0,
                updated_at: 3,
                deleted: true,
                fields: vec![],
                extra: vec![],
            },
        ]
    }

    #[test]
    fn json_is_lossless() {
        let entries = sample();
        let text = export_json(&entries, 99);
        let back = import_json(&text).unwrap();
        assert!(back.skipped.is_empty());
        assert_eq!(back.entries, entries);
        assert!(text.contains("otpauth://totp/"));
    }

    #[test]
    fn json_rejects_other_formats() {
        assert!(import_json(r#"{"format":"other","entries":[]}"#).is_err());
        let r = import_json(r#"{"format":"99p-v1","entries":[{"id":"zz"}]}"#).unwrap();
        assert_eq!(r.skipped, [(1, "malformed entry")]);
    }

    #[test]
    fn csv_export_roundtrips_logins() {
        let (csv, left_out) = export_csv(&sample());
        assert_eq!(left_out, 2); // the card and the identity; the tombstone is not counted
        let back = import_csv(&csv, 5).unwrap();
        assert_eq!(back.entries.len(), 1);
        let e = &back.entries[0];
        assert_eq!(e.name, "Git \"Hub\", Inc");
        assert_eq!(e.hosts, ["github.com"]);
        assert_eq!(pw(e), Some("p\nw,\"x\""));
        let orig = sample();
        let t = |e: &Entry| {
            e.fields
                .iter()
                .find(|f| f.kind == FieldKind::Totp)
                .unwrap()
                .value
                .clone()
        };
        assert_eq!(t(e), t(&orig[0]));
    }
}
