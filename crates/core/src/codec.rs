//! Vault body encoding (SPEC §6.3 to §6.5). Unknown tags are kept in `extra`.

use crate::error::{Error, Result};
use crate::model::*;
use crate::tlv::{Reader, Writer, varint_value};

fn u32_of(v: &[u8]) -> Result<u32> {
    u32::try_from(varint_value(v)?).map_err(|_| Error::Format("integer too large"))
}

fn u8_of(v: &[u8]) -> Result<u8> {
    match v {
        [b] => Ok(*b),
        _ => Err(Error::Format("expected one byte")),
    }
}

fn bool_of(v: &[u8]) -> Result<bool> {
    Ok(u8_of(v)? != 0)
}

fn string_of(v: &[u8]) -> Result<String> {
    String::from_utf8(v.to_vec()).map_err(|_| Error::Format("invalid UTF-8"))
}

fn arr<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into()
        .map_err(|_| Error::Format("wrong fixed length"))
}

pub fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut w = Writer::default();
    w.uint(0x01, e.id);
    w.bytes(0x02, &[e.kind as u8]);
    if !e.deleted {
        w.bytes(0x03, e.name.as_bytes());
        for h in &e.hosts {
            w.bytes(0x04, h.as_bytes());
        }
    }
    w.uint(0x05, e.updated_at.into());
    if !e.deleted {
        for f in &e.fields {
            let mut fw = Writer::default();
            fw.bytes(0x01, &[f.kind as u8]);
            if let Some(l) = &f.label {
                fw.bytes(0x02, l.as_bytes());
            }
            fw.bytes(0x03, &f.value);
            w.bytes(0x06, &fw.buf);
            zeroize::Zeroize::zeroize(&mut fw.buf);
        }
    }
    w.flag(0x07, e.deleted);
    if !e.deleted {
        w.uint(0x08, e.created_at.into());
    }
    for (t, v) in &e.extra {
        w.bytes(*t, v);
    }
    w.buf
}

fn decode_field(buf: &[u8]) -> Result<Option<Field>> {
    let mut kind = None;
    let mut label = None;
    let mut value = Vec::new();
    for item in Reader::new(buf) {
        let (t, v) = item?;
        match t {
            0x01 => match FieldKind::from_u8(u8_of(v)?) {
                Some(k) => kind = Some(k),
                None => return Ok(None),
            },
            0x02 => label = Some(string_of(v)?),
            0x03 => value = v.to_vec(),
            _ => {}
        }
    }
    let kind = kind.ok_or(Error::Format("field without kind"))?;
    Ok(Some(Field { kind, label, value }))
}

pub fn decode_entry(buf: &[u8]) -> Result<Entry> {
    let mut e = Entry {
        id: 0,
        kind: EntryKind::Login,
        name: String::new(),
        hosts: Vec::new(),
        created_at: 0,
        updated_at: 0,
        deleted: false,
        fields: Vec::new(),
        extra: Vec::new(),
    };
    let mut have_id = false;
    for item in Reader::new(buf) {
        let (t, v) = item?;
        match t {
            0x01 => {
                e.id = varint_value(v)?;
                have_id = true;
            }
            0x02 => e.kind = EntryKind::from_u8(u8_of(v)?).ok_or(Error::Format("entry kind"))?,
            0x03 => e.name = string_of(v)?,
            0x04 => e.hosts.push(string_of(v)?),
            0x05 => e.updated_at = u32_of(v)?,
            0x06 => match decode_field(v)? {
                Some(f) => e.fields.push(f),
                // Unknown field kind from a newer app: keep it verbatim.
                None => e.extra.push((t, v.to_vec())),
            },
            0x07 => e.deleted = bool_of(v)?,
            0x08 => e.created_at = u32_of(v)?,
            _ => e.extra.push((t, v.to_vec())),
        }
    }
    if !have_id {
        return Err(Error::Format("entry without id"));
    }
    Ok(e)
}

fn encode_known_key(k: &KnownKey) -> Vec<u8> {
    let mut w = Writer::default();
    w.uint(0x01, k.serial.into());
    w.bytes(0x02, k.label.as_bytes());
    w.bytes(0x03, &k.piv_pubkey);
    w.bytes(0x04, &[k.slot]);
    w.bytes(0x05, &[k.mgmt_alg as u8]);
    w.bytes(0x06, &k.mgmt_key);
    w.uint(0x07, k.last_synced_rev);
    w.bytes(0x08, &k.firmware);
    w.uint(0x09, k.added_at.into());
    if let Some((alg, key)) = &k.mgmt_key_prev {
        let mut p = Writer::default();
        p.bytes(0x01, &[*alg as u8]);
        p.bytes(0x02, key);
        w.bytes(0x0A, &p.buf);
        zeroize::Zeroize::zeroize(&mut p.buf);
    }
    w.buf
}

fn decode_known_key(buf: &[u8]) -> Result<KnownKey> {
    let mut k = KnownKey {
        serial: 0,
        label: String::new(),
        firmware: [0; 3],
        slot: 0x82,
        piv_pubkey: Vec::new(),
        mgmt_alg: MgmtKeyAlg::Aes256,
        mgmt_key: Vec::new(),
        mgmt_key_prev: None,
        last_synced_rev: 0,
        added_at: 0,
    };
    let alg = |v: &[u8]| MgmtKeyAlg::from_u8(u8_of(v)?).ok_or(Error::Format("mgmt alg"));
    for item in Reader::new(buf) {
        let (t, v) = item?;
        match t {
            0x01 => k.serial = u32_of(v)?,
            0x02 => k.label = string_of(v)?,
            0x03 => k.piv_pubkey = v.to_vec(),
            0x04 => k.slot = u8_of(v)?,
            0x05 => k.mgmt_alg = alg(v)?,
            0x06 => k.mgmt_key = v.to_vec(),
            0x07 => k.last_synced_rev = varint_value(v)?,
            0x08 => k.firmware = arr(v)?,
            0x09 => k.added_at = u32_of(v)?,
            0x0A => {
                let (mut a, mut key) = (None, Vec::new());
                for item in Reader::new(v) {
                    let (t, v) = item?;
                    match t {
                        0x01 => a = Some(alg(v)?),
                        0x02 => key = v.to_vec(),
                        _ => {}
                    }
                }
                k.mgmt_key_prev = Some((a.ok_or(Error::Format("prev alg"))?, key));
            }
            _ => {}
        }
    }
    Ok(k)
}

/// Encodes the vault body. The caller zeroizes the result.
pub fn encode_vault(v: &Vault) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(0x01, &v.vault_secret);
    w.uint(0x02, v.created_at.into());
    w.bytes(0x03, &v.head);
    let anc: Vec<u8> = v.ancestors.iter().flatten().copied().collect();
    w.bytes(0x04, &anc);
    let mut s = Writer::default();
    s.uint(0x01, v.settings.idle_lock_secs.into());
    s.uint(0x02, v.settings.clipboard_clear_secs.into());
    s.flag(0x03, v.settings.single_bank);
    w.bytes(0x05, &s.buf);
    for e in &v.entries {
        let mut b = encode_entry(e);
        w.bytes(0x10, &b);
        zeroize::Zeroize::zeroize(&mut b);
    }
    for k in &v.known_keys {
        let mut b = encode_known_key(k);
        w.bytes(0x20, &b);
        zeroize::Zeroize::zeroize(&mut b);
    }
    for (t, val) in &v.extra {
        w.bytes(*t, val);
    }
    w.buf
}

pub fn decode_vault(buf: &[u8]) -> Result<Vault> {
    let mut v = Vault {
        vault_secret: [0; 32],
        created_at: 0,
        head: [0; 8],
        ancestors: Vec::new(),
        settings: Settings::default(),
        entries: Vec::new(),
        known_keys: Vec::new(),
        extra: Vec::new(),
    };
    let mut have_secret = false;
    for item in Reader::new(buf) {
        let (t, val) = item?;
        match t {
            0x01 => {
                v.vault_secret = arr(val)?;
                have_secret = true;
            }
            0x02 => v.created_at = u32_of(val)?,
            0x03 => v.head = arr(val)?,
            0x04 => {
                if val.len() % 8 != 0 {
                    return Err(Error::Format("ancestors length"));
                }
                v.ancestors = val.chunks(8).map(|c| arr(c).unwrap()).collect();
            }
            0x05 => {
                for item in Reader::new(val) {
                    let (t, x) = item?;
                    match t {
                        0x01 => v.settings.idle_lock_secs = u32_of(x)?,
                        0x02 => v.settings.clipboard_clear_secs = u32_of(x)?,
                        0x03 => v.settings.single_bank = bool_of(x)?,
                        _ => {}
                    }
                }
            }
            0x10 => v.entries.push(decode_entry(val)?),
            0x20 => v.known_keys.push(decode_known_key(val)?),
            _ => v.extra.push((t, val.to_vec())),
        }
    }
    if !have_secret {
        return Err(Error::Format("vault without secret"));
    }
    Ok(v)
}
