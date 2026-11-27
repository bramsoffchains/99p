//! Session API used by the FFI and the CLI: provision, unlock, lock, list,
//! upsert, delete, capacity, clone and sync.

use zeroize::Zeroize;

use crate::card::SmartCard;
use crate::codec;
use crate::container::{self, SealParams, VAULT_SLOT};
use crate::crypto;
use crate::error::{Error, Result};
use crate::merge::{self, Relation};
use crate::model::{Entry, KnownKey, MgmtKeyAlg, Settings, Vault};
use crate::payload;
use crate::piv::{self, Piv};
use crate::secret::SecretBytes;
use crate::store;

const TOMBSTONE_TTL: u32 = 365 * 24 * 3600;

pub struct ProvisionOptions {
    /// User-visible name of the YubiKey, e.g. "Keychain key".
    pub label: String,
    /// Current management key (raw bytes) when the card does not use the
    /// factory default. Without it, provisioning stops with `ManagementKey`
    /// instead of overwriting anything.
    pub current_mgmt_key: Option<Vec<u8>>,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        ProvisionOptions {
            label: "YubiKey".into(),
            current_mgmt_key: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    /// Ciphertext bytes the vault needs now (a multiple of 1024).
    pub used: usize,
    /// Most ciphertext bytes the current layout can hold.
    pub capacity: usize,
    pub single_bank: bool,
    pub revision: u64,
}

struct Unlocked {
    vault: Vault,
    p: SecretBytes,
    salt: [u8; 16],
    uuid: [u8; 16],
    revision: u64,
    active_bank: Option<u8>,
    read_only: bool,
    /// Serials of cards that hold the current vault (and so its management
    /// keys). Only those may finish a management key rotation (SPEC §8.2).
    on_card: Vec<u32>,
}

/// Seconds since the Unix epoch (0 if the clock is before it).
pub fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

pub struct Session<C: SmartCard> {
    piv: Piv<C>,
    pub serial: u32,
    pub firmware: [u8; 3],
    state: Option<Unlocked>,
    clock: fn() -> u32,
}

fn identify<D: SmartCard>(piv: &mut Piv<D>) -> Result<(u32, [u8; 3])> {
    piv.select()?;
    let fw = piv.version()?;
    Ok((piv.serial()?, fw))
}

/// SPEC §8.1 steps 1 to 6 and §8.2 step 1. Sets the PIN derived from `p`
/// with 255 tries and blocks the PUK, so the PIN cannot be reset. Leaves the card authenticated with its current
/// management key, which the returned record keeps as `mgmt_key_prev` until
/// the rotation completes.
fn provision_card<D: SmartCard>(
    piv: &mut Piv<D>,
    serial: u32,
    fw: [u8; 3],
    label: &str,
    current: Option<&[u8]>,
    p: &[u8],
    now: u32,
) -> Result<KnownKey> {
    let (alg, key) = if fw >= [5, 3, 0] {
        let (alg, is_default) = piv.mgmt_key_info()?;
        match (is_default, current) {
            (true, _) => (alg, piv::DEFAULT_MGMT_KEY.to_vec()),
            (false, Some(k)) => (alg, k.to_vec()),
            (false, None) => return Err(Error::ManagementKey),
        }
    } else {
        (
            piv::ALG_3DES,
            current.map_or(piv::DEFAULT_MGMT_KEY.to_vec(), <[u8]>::to_vec),
        )
    };
    if fw >= [5, 3, 0] && piv.metadata(VAULT_SLOT)?.is_some() {
        return Err(Error::Invalid("slot 0x82 already holds a key"));
    }
    let not_default = Error::Invalid(
        "this YubiKey's PIV PIN or PUK is not the factory default; reset its PIV application first",
    );
    for r in [piv::REF_PIN, piv::REF_PUK] {
        if fw >= [5, 3, 0] && piv.pin_info(r)?.is_some_and(|(default, _)| !default) {
            return Err(not_default);
        }
    }
    let old_alg = MgmtKeyAlg::from_u8(alg).ok_or(Error::Unsupported("management key algorithm"))?;
    piv.authenticate(alg, &key)?;
    // SET PIN RETRIES needs the management key and the PIN, and resets both
    // PIN and PUK to their defaults, so it comes first. The PUK gets one try,
    // which a wrong PUK then uses up: nothing can reset the PIN afterwards.
    match piv.verify_pin(piv::DEFAULT_PIN) {
        Err(Error::WrongPin { .. } | Error::PinBlocked) => return Err(not_default),
        r => r?,
    }
    piv.set_pin_retries(piv::PIN_RETRIES, 1)?;
    match piv.unblock_pin(b"00000000", piv::DEFAULT_PIN) {
        Err(Error::WrongPin { .. } | Error::PinBlocked) => {}
        Ok(()) => return Err(Error::Invalid("the PUK could not be blocked")),
        Err(e) => return Err(e),
    }
    let mut pin = crypto::derive_pin(p);
    let r = piv.change_reference(piv::REF_PIN, piv::DEFAULT_PIN, &pin);
    pin.zeroize();
    r?;
    piv.authenticate(alg, &key)?;
    let pubkey = piv.generate_p256(VAULT_SLOT)?;
    let (new_alg, new_key) = if fw >= [5, 4, 2] {
        (MgmtKeyAlg::Aes256, crypto::random_bytes::<32>()?.to_vec())
    } else {
        (
            MgmtKeyAlg::TripleDes,
            crypto::random_bytes::<24>()?.to_vec(),
        )
    };
    let kk = KnownKey {
        serial,
        label: label.to_string(),
        firmware: fw,
        slot: VAULT_SLOT,
        piv_pubkey: pubkey,
        mgmt_alg: new_alg,
        mgmt_key: new_key,
        mgmt_key_prev: Some((old_alg, key)),
        last_synced_rev: 0,
        added_at: now,
    };
    Ok(kk)
}

/// Authenticates with the card's management key from `known_keys`, finishing
/// a pending rotation when that is safe.
fn auth_card<D: SmartCard>(piv: &mut Piv<D>, u: &mut Unlocked, serial: u32) -> Result<()> {
    let may_rotate = u.on_card.contains(&serial);
    let kk = u
        .vault
        .known_keys
        .iter_mut()
        .find(|k| k.serial == serial)
        .ok_or(Error::Invalid("unknown YubiKey"))?;
    let (alg, key) = (kk.mgmt_alg as u8, kk.mgmt_key.clone());
    let res = match piv.authenticate(alg, &key) {
        Ok(()) => {
            kk.mgmt_key_prev = None;
            Ok(())
        }
        Err(Error::ManagementKey) => match kk.mgmt_key_prev.clone() {
            Some((palg, pkey)) => {
                piv.authenticate(palg as u8, &pkey)?;
                if may_rotate {
                    piv.set_mgmt_key(alg, &key)?;
                    piv.authenticate(alg, &key)?;
                    kk.mgmt_key_prev = None;
                }
                Ok(())
            }
            None => Err(Error::ManagementKey),
        },
        Err(e) => Err(e),
    };
    let mut key = key;
    key.zeroize();
    res
}

/// Seals the current vault for `serial` and writes it to the bank that is
/// not `in_use` (SPEC §9.2). Returns the new revision and the bank written.
fn write_card<D: SmartCard>(
    piv: &mut Piv<D>,
    u: &mut Unlocked,
    serial: u32,
    in_use: Option<u8>,
) -> Result<(u64, u8)> {
    auth_card(piv, u, serial)?;
    let single = u.vault.settings.single_bank;
    let target = match (single, in_use) {
        (true, _) | (false, None) => 0,
        (false, Some(b)) => 1 - b,
    };
    let seen = store::read_bank_header(piv, target)?.map_or(0, |h| h.revision);
    let revision = u.revision.max(seen) + 1;
    let kk = u
        .vault
        .known_keys
        .iter()
        .find(|k| k.serial == serial)
        .unwrap();
    let card_pub = crypto::parse_pubkey(&kk.piv_pubkey)?;
    let mut body = codec::encode_vault(&u.vault);
    let mut pt = payload::pack(&body, true);
    body.zeroize();
    let sp = SealParams {
        single_bank: single,
        uuid: u.uuid,
        revision,
        salt: u.salt,
        card_pub: &card_pub,
        card_serial: serial,
        p: u.p.as_slice(),
    };
    let image = container::seal_image(&sp, &pt);
    pt.zeroize();
    store::write(piv, &image?, target)?;
    if !u.on_card.contains(&serial) {
        u.on_card.push(serial);
    }
    if let Some(k) = u.vault.known_keys.iter_mut().find(|k| k.serial == serial) {
        k.last_synced_rev = revision;
    }
    Ok((revision, target))
}

/// Saves to the card the session was opened on.
fn write_primary<C: SmartCard>(piv: &mut Piv<C>, u: &mut Unlocked, serial: u32) -> Result<()> {
    let (rev, bank) = write_card(piv, u, serial, u.active_bank)?;
    u.revision = rev;
    u.active_bank = Some(bank);
    Ok(())
}

/// Unlock half of SPEC §5.3 on any card: ECDH (touch), then decrypt and decode.
fn decrypt_loaded<D: SmartCard>(
    piv: &mut Piv<D>,
    l: &store::Loaded,
    p: &[u8],
) -> Result<(Vault, bool)> {
    let e = crypto::pubkey_uncompressed(&crypto::parse_pubkey(&l.header.eph_pub)?);
    piv.verify_pin(&crypto::derive_pin(p))?;
    let z = piv.ecdh(l.header.slot, &e)?;
    let pt = container::open_image(&l.image, &l.header, z.as_slice(), p)?;
    drop(z);
    let (schema, body) = payload::unpack(pt.as_slice())?;
    let vault = codec::decode_vault(body.as_slice()).map_err(|e| {
        if schema > payload::SCHEMA_V {
            Error::Unsupported("newer vault schema")
        } else {
            e
        }
    })?;
    Ok((vault, schema > payload::SCHEMA_V))
}

impl<C: SmartCard> Session<C> {
    /// Opens a card. Needs no touch and no passphrase.
    pub fn open(card: C) -> Result<Self> {
        let mut piv = Piv::new(card);
        let (serial, firmware) = identify(&mut piv)?;
        Ok(Session {
            piv,
            serial,
            firmware,
            state: None,
            clock: unix_now,
        })
    }

    /// Creates a new vault on a fresh card (SPEC §8).
    pub fn provision(card: C, pass: &[u8], opts: &ProvisionOptions) -> Result<Self> {
        let mut s = Self::open(card)?;
        let now = (s.clock)();
        let salt = crypto::random_bytes()?;
        let p = crypto::derive_passphrase_key(pass, &salt);
        let kk = provision_card(
            &mut s.piv,
            s.serial,
            s.firmware,
            &opts.label,
            opts.current_mgmt_key.as_deref(),
            p.as_slice(),
            now,
        )?;
        let vault = Vault {
            vault_secret: crypto::random_bytes()?,
            created_at: now,
            head: crypto::random_bytes()?,
            ancestors: Vec::new(),
            settings: Settings::default(),
            entries: Vec::new(),
            known_keys: vec![kk],
            extra: Vec::new(),
        };
        s.state = Some(Unlocked {
            vault,
            p,
            salt,
            uuid: crypto::random_bytes()?,
            revision: 0,
            active_bank: None,
            read_only: false,
            on_card: Vec::new(),
        });
        // Two saves: the first stores the new management key while the card
        // still uses the old one; the second switches the card over (§8.2).
        s.save()?;
        s.save()?;
        Ok(s)
    }

    /// PIN tries left on this card before it blocks. Costs no try.
    pub fn pin_tries_left(&mut self) -> Result<u8> {
        let r = self.piv.select().and_then(|_| self.piv.pin_tries_left());
        self.guard(r)
    }

    /// Encrypted `.ykv` export to every known YubiKey and, optionally, a new
    /// recovery key (returned once, for the user to print).
    pub fn export_ykv(&self, with_recovery_key: bool) -> Result<(Vec<u8>, Option<String>)> {
        let u = self.unlocked()?;
        crate::ykv::export(
            &crate::ykv::ExportParams {
                vault: &u.vault,
                uuid: u.uuid,
                revision: u.revision,
                salt: u.salt,
                p: u.p.as_slice(),
            },
            with_recovery_key,
        )
    }

    /// Opens a `.ykv` with this session's card (one touch).
    pub fn open_ykv(&mut self, file: &[u8], pass: &[u8]) -> Result<Vault> {
        let r = crate::ykv::open_with_card(&mut self.piv, file, pass);
        self.guard(r)
    }

    /// Merges the entries of an imported vault (SPEC §9.4 rules) and saves.
    /// Known keys are not imported.
    pub fn import_merge(&mut self, imported: &Vault) -> Result<()> {
        self.mutate(|v, _| {
            let mut only_entries = v.clone();
            only_entries.entries = imported.entries.clone();
            only_entries.head = imported.head;
            let merged = merge::merge(v, &only_entries);
            v.entries = merged.entries.clone();
        })
    }

    /// Overrides the clock (tests).
    pub fn set_clock(&mut self, clock: fn() -> u32) {
        self.clock = clock;
    }

    pub fn card(&self) -> &C {
        &self.piv.card
    }

    pub fn card_mut(&mut self) -> &mut C {
        &mut self.piv.card
    }

    pub fn into_card(mut self) -> C {
        self.lock();
        let Session { piv, .. } = self;
        piv.card
    }

    pub fn has_vault(&mut self) -> Result<bool> {
        match store::load(&mut self.piv) {
            Ok(_) => Ok(true),
            Err(Error::NoValidVault) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn guard<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.as_ref().err() == Some(&Error::CardRemoved) {
            self.lock();
        }
        r
    }

    /// SPEC §5.3: reads the vault, checks the PIN, then asks for one touch.
    pub fn unlock(&mut self, pass: &[u8]) -> Result<()> {
        let r = self.unlock_inner(pass);
        self.guard(r)
    }

    fn unlock_inner(&mut self, pass: &[u8]) -> Result<()> {
        self.lock();
        self.piv.select()?;
        let l = store::load(&mut self.piv)?;
        let p = crypto::derive_passphrase_key(pass, &l.header.salt);
        let (vault, read_only) = decrypt_loaded(&mut self.piv, &l, p.as_slice())?;
        self.state = Some(Unlocked {
            vault,
            p,
            salt: l.header.salt,
            uuid: l.header.uuid,
            revision: l.header.revision,
            active_bank: Some(l.bank),
            read_only,
            on_card: vec![self.serial],
        });
        Ok(())
    }

    /// Wipes every secret from memory and, if it was unlocked, clears the
    /// card's PIN-verified status (best effort).
    pub fn lock(&mut self) {
        if self.state.take().is_some() {
            let _ = self.piv.reset_pin_status();
        }
    }

    /// Call from the PC/SC removal watcher.
    pub fn on_card_removed(&mut self) {
        self.state = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.is_some()
    }

    fn unlocked(&self) -> Result<&Unlocked> {
        self.state.as_ref().ok_or(Error::Locked)
    }

    pub fn vault(&self) -> Result<&Vault> {
        Ok(&self.unlocked()?.vault)
    }

    /// Revision of the bank this session last read or wrote.
    pub fn revision(&self) -> Result<u64> {
        Ok(self.unlocked()?.revision)
    }

    /// Live entries (tombstones excluded).
    pub fn entries(&self) -> Result<impl Iterator<Item = &Entry>> {
        Ok(self.unlocked()?.vault.entries.iter().filter(|e| !e.deleted))
    }

    pub fn entry(&self, id: u64) -> Result<Option<&Entry>> {
        Ok(self.entries()?.find(|e| e.id == id))
    }

    /// Applies `f` to the vault and saves; on failure the change is undone.
    fn mutate(&mut self, f: impl FnOnce(&mut Vault, u32)) -> Result<()> {
        let now = (self.clock)();
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        if u.read_only {
            return Err(Error::Unsupported("vault was written by a newer version"));
        }
        let backup = u.vault.clone();
        f(&mut u.vault, now);
        let r = self.save();
        if r.is_err() {
            if let Some(u) = self.state.as_mut() {
                let single = u.vault.settings.single_bank || backup.settings.single_bank;
                u.vault = backup;
                // Single-bank: a save that ran out of NVM midway has already
                // overwritten part of the only copy, so put the previous vault back.
                if single && matches!(r, Err(Error::Capacity { .. })) {
                    self.save()?;
                }
            }
        }
        r
    }

    /// Inserts or replaces an entry by id and saves. Returns the id.
    pub fn upsert(&mut self, entry: Entry) -> Result<u64> {
        let id = entry.id;
        self.upsert_many(vec![entry])?;
        Ok(id)
    }

    /// Inserts or replaces several entries with a single save (imports).
    pub fn upsert_many(&mut self, entries: Vec<Entry>) -> Result<()> {
        self.mutate(move |v, now| {
            for mut entry in entries {
                entry.updated_at = now;
                entry.deleted = false;
                match v.entries.iter_mut().find(|e| e.id == entry.id) {
                    Some(e) => {
                        entry.created_at = e.created_at;
                        *e = entry;
                    }
                    None => {
                        entry.created_at = now;
                        v.entries.push(entry);
                    }
                }
            }
        })
    }

    /// Replaces an entry by a tombstone and saves.
    pub fn delete(&mut self, id: u64) -> Result<()> {
        if self.entry(id)?.is_none() {
            return Err(Error::Invalid("no such entry"));
        }
        self.mutate(|v, now| {
            if let Some(e) = v.entries.iter_mut().find(|e| e.id == id) {
                e.deleted = true;
                e.updated_at = now;
                e.name.zeroize();
                e.name.clear();
                e.hosts.clear();
                e.fields.clear();
                e.extra.clear();
                e.created_at = 0;
            }
        })
    }

    pub fn update_settings(&mut self, settings: Settings) -> Result<()> {
        self.mutate(|v, _| v.settings = settings)
    }

    pub fn capacity(&self) -> Result<Capacity> {
        let u = self.unlocked()?;
        let mut body = codec::encode_vault(&u.vault);
        let mut pt = payload::pack(&body, true);
        body.zeroize();
        let used = pt.len() + 16;
        pt.zeroize();
        let single = u.vault.settings.single_bank;
        Ok(Capacity {
            used,
            capacity: container::max_ct_len(single),
            single_bank: single,
            revision: u.revision,
        })
    }

    /// New head for the next save; prunes old tombstones.
    fn bump(&mut self) -> Result<()> {
        let now = (self.clock)();
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        let v = &mut u.vault;
        v.entries
            .retain(|e| !e.deleted || now.saturating_sub(e.updated_at) < TOMBSTONE_TTL);
        v.ancestors.insert(0, v.head);
        v.ancestors.truncate(32);
        v.head = crypto::random_bytes()?;
        Ok(())
    }

    /// Saves the vault to this card (no touch).
    pub fn save(&mut self) -> Result<()> {
        let r = self.save_inner();
        self.guard(r)
    }

    fn save_inner(&mut self) -> Result<()> {
        self.bump()?;
        let serial = self.serial;
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        write_primary(&mut self.piv, u, serial)
    }

    /// Provisions `backup` and copies the vault to it (SPEC §9.4). The backup
    /// gets its own slot-0x82 key and management key; it then lists both cards.
    pub fn clone_to<D: SmartCard>(
        &mut self,
        backup: D,
        label: &str,
        current_mgmt_key: Option<&[u8]>,
    ) -> Result<()> {
        let now = (self.clock)();
        let mut bp = Piv::new(backup);
        let (serial, fw) = identify(&mut bp)?;
        if self.vault()?.known_keys.iter().any(|k| k.serial == serial) {
            return Err(Error::Invalid("this YubiKey is already a clone; use sync"));
        }
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        let kk = provision_card(&mut bp, serial, fw, label, current_mgmt_key, u.p.as_slice(), now)?;
        u.vault.known_keys.push(kk);
        self.bump()?;
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        let r = write_card(&mut bp, u, serial, None)
            .and_then(|(_, bank)| write_card(&mut bp, u, serial, Some(bank)));
        if let Err(e) = r {
            u.vault.known_keys.retain(|k| k.serial != serial);
            return Err(e);
        }
        // Same head as the backup, so the two cards start in sync.
        let r = write_primary(&mut self.piv, u, self.serial);
        self.guard(r)
    }

    /// Compares and reconciles with another card holding the same vault.
    /// Costs one touch on `other`.
    pub fn sync_with<D: SmartCard>(&mut self, other: D) -> Result<Relation> {
        let r = self.sync_inner(other);
        self.guard(r)
    }

    fn sync_inner<D: SmartCard>(&mut self, other: D) -> Result<Relation> {
        let mut op = Piv::new(other);
        let (serial, _) = identify(&mut op)?;
        let l = store::load(&mut op)?;
        let u = self.state.as_mut().ok_or(Error::Locked)?;
        if l.header.uuid != u.uuid {
            return Err(Error::Invalid("this YubiKey holds a different vault"));
        }
        if l.header.salt != u.salt {
            return Err(Error::Invalid("the passphrase differs on this YubiKey"));
        }
        let (theirs, _) = decrypt_loaded(&mut op, &l, u.p.as_slice())?;
        let rel = merge::relation(&u.vault, &theirs);
        match rel {
            Relation::InSync => {}
            Relation::TheyAreStale => {
                write_card(&mut op, u, serial, Some(l.bank))?;
            }
            Relation::WeAreStale => {
                u.vault = theirs;
                if !u.on_card.contains(&serial) {
                    u.on_card.push(serial);
                }
                write_primary(&mut self.piv, u, self.serial)?;
            }
            Relation::Diverged => {
                u.vault = merge::merge(&u.vault, &theirs);
                self.bump()?;
                let u = self.state.as_mut().unwrap();
                write_card(&mut op, u, serial, Some(l.bank))?;
                write_primary(&mut self.piv, u, self.serial)?;
            }
        }
        // Revisions differ per card; record the other key as current in this
        // card's numbering, so `last_synced_rev < revision` means "behind".
        let u = self.state.as_mut().unwrap();
        let rev = u.revision;
        if let Some(k) = u.vault.known_keys.iter_mut().find(|k| k.serial == serial) {
            k.last_synced_rev = rev;
        }
        Ok(rel)
    }
}
