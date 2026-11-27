//! Decrypted vault model (schema_v 1). Wire encoding: `docs/SPEC.md` §6.
//!
//! These types hold secrets. Workstream A adds `Drop` impls that zeroize every
//! `String`/`Vec<u8>` (no `zeroize_derive`, to avoid proc-macros).

/// Unix time in seconds.
pub type Timestamp = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    Login = 1,
    Card = 2,
    Note = 3,
    Custom = 4,
    /// Name, email, phone and postal address for form autofill.
    Identity = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldKind {
    Username = 0x01,
    Password = 0x02,
    /// Value is packed TOTP params + raw secret, see SPEC §6.4.
    Totp = 0x03,
    CardNumber = 0x04,
    /// Value is `YYYY-MM`.
    CardExpiry = 0x05,
    CardCvv = 0x06,
    CardHolder = 0x07,
    Pin = 0x08,
    Note = 0x09,
    CustomText = 0x10,
    CustomSecret = 0x11,
    // Identity fields (UTF-8, not secret).
    FirstName = 0x20,
    LastName = 0x21,
    Email = 0x22,
    Phone = 0x23,
    /// Street address; may hold several lines separated by `\n`.
    Street = 0x24,
    City = 0x25,
    Postcode = 0x26,
    /// State, province or region.
    Region = 0x27,
    Country = 0x28,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    /// Only meaningful for `CustomText` / `CustomSecret`.
    pub label: Option<String>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Random u64, unique across all clones (enables merge without coordination).
    pub id: u64,
    pub kind: EntryKind,
    pub name: String,
    /// Normalised hostnames (lowercase, no scheme/port/path), SPEC §6.6.
    pub hosts: Vec<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Tombstone: kept (without name/fields) so deletions survive merges.
    pub deleted: bool,
    pub fields: Vec<Field>,
    /// Unknown TLV items, preserved verbatim for forward compatibility.
    pub extra: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MgmtKeyAlg {
    /// PIV algorithm id 0x03, 24-byte key (firmware < 5.4.2).
    TripleDes = 0x03,
    /// PIV algorithm id 0x0A, 24-byte key (the factory default on firmware >= 5.7).
    Aes192 = 0x0A,
    /// PIV algorithm id 0x0C, 32-byte key (firmware >= 5.4.2).
    Aes256 = 0x0C,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownKey {
    pub serial: u32,
    pub label: String,
    pub firmware: [u8; 3],
    /// PIV slot holding the vault key (default 0x82).
    pub slot: u8,
    /// SEC1 uncompressed P-256 public key (65 bytes).
    pub piv_pubkey: Vec<u8>,
    pub mgmt_alg: MgmtKeyAlg,
    pub mgmt_key: Vec<u8>,
    /// Previous management key, kept until a rotation is confirmed on-card
    /// (SPEC §8.2 crash-safe rotation).
    pub mgmt_key_prev: Option<(MgmtKeyAlg, Vec<u8>)>,
    pub last_synced_rev: u64,
    pub added_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub idle_lock_secs: u32,
    pub clipboard_clear_secs: u32,
    /// Explicit opt-in to the ~48 KB single-bank layout (not tear-safe).
    pub single_bank: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_lock_secs: 300,
            clipboard_clear_secs: 30,
            single_bank: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    /// Stable 32-byte secret, never rotated; root for derived keys such as the
    /// favicon cache key (SPEC §10). The DEK, by contrast, rotates every save.
    pub vault_secret: [u8; 32],
    pub created_at: Timestamp,
    /// Random id of the save that produced this content.
    pub head: [u8; 8],
    /// Previous save ids, newest first, at most 32. Used for divergence
    /// detection between clones (SPEC §9.2).
    pub ancestors: Vec<[u8; 8]>,
    pub settings: Settings,
    pub entries: Vec<Entry>,
    pub known_keys: Vec<KnownKey>,
    pub extra: Vec<(u8, Vec<u8>)>,
}

impl Vault {
    /// When the vault content last changed: the newest entry change
    /// (deletions included, as tombstones keep their time), or creation.
    pub fn updated_at(&self) -> Timestamp {
        self.entries.iter().map(|e| e.updated_at).fold(self.created_at, Timestamp::max)
    }
}

// ---- zeroize on drop (hand-written, no zeroize_derive) ----

use zeroize::Zeroize;

fn wipe_extra(extra: &mut [(u8, Vec<u8>)]) {
    for (_, v) in extra.iter_mut() {
        v.zeroize();
    }
}

impl Drop for Field {
    fn drop(&mut self) {
        if let Some(l) = self.label.as_mut() {
            l.zeroize();
        }
        self.value.zeroize();
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.name.zeroize();
        for h in self.hosts.iter_mut() {
            h.zeroize();
        }
        wipe_extra(&mut self.extra);
    }
}

impl Drop for KnownKey {
    fn drop(&mut self) {
        self.label.zeroize();
        self.mgmt_key.zeroize();
        if let Some((_, k)) = self.mgmt_key_prev.as_mut() {
            k.zeroize();
        }
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.vault_secret.zeroize();
        wipe_extra(&mut self.extra);
    }
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => EntryKind::Login,
            2 => EntryKind::Card,
            3 => EntryKind::Note,
            4 => EntryKind::Custom,
            5 => EntryKind::Identity,
            _ => return None,
        })
    }
}

impl FieldKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        use FieldKind::*;
        Some(match v {
            0x01 => Username,
            0x02 => Password,
            0x03 => Totp,
            0x04 => CardNumber,
            0x05 => CardExpiry,
            0x06 => CardCvv,
            0x07 => CardHolder,
            0x08 => Pin,
            0x09 => Note,
            0x10 => CustomText,
            0x11 => CustomSecret,
            0x20 => FirstName,
            0x21 => LastName,
            0x22 => Email,
            0x23 => Phone,
            0x24 => Street,
            0x25 => City,
            0x26 => Postcode,
            0x27 => Region,
            0x28 => Country,
            _ => return None,
        })
    }
}

impl MgmtKeyAlg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(MgmtKeyAlg::TripleDes),
            0x0A => Some(MgmtKeyAlg::Aes192),
            0x0C => Some(MgmtKeyAlg::Aes256),
            _ => None,
        }
    }
}

impl Entry {
    /// A new, empty entry with a random id.
    pub fn new(kind: EntryKind, name: &str) -> crate::Result<Self> {
        Ok(Entry {
            id: crate::crypto::random_u64()?,
            kind,
            name: name.to_string(),
            hosts: Vec::new(),
            created_at: 0,
            updated_at: 0,
            deleted: false,
            fields: Vec::new(),
            extra: Vec::new(),
        })
    }

    pub fn field(&self, kind: FieldKind) -> Option<&Field> {
        self.fields.iter().find(|f| f.kind == kind)
    }
}

impl Field {
    pub fn new(kind: FieldKind, value: &[u8]) -> Self {
        Field {
            kind,
            label: None,
            value: value.to_vec(),
        }
    }
}
