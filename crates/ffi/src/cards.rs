//! The cards behind the FFI: real YubiKeys over PC/SC (macOS) and in-memory
//! `MockYubiKey`s for development. Both go through the core's PIV client.

use std::any::Any;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use p99_core::mock::MockYubiKey;
use p99_core::model::{Entry, EntryKind, Field, FieldKind};
use p99_core::session::ProvisionOptions;
use p99_core::{Error, Result, Session, SmartCard, crypto};

pub const DEMO_PASSPHRASE: &str = "correct horse battery staple";

/// Runs right before the card waits for a touch.
pub type TouchHook = Arc<Mutex<Option<Box<dyn Fn() + Send>>>>;

struct Mock {
    id: String,
    present: bool,
    card: Arc<Mutex<MockYubiKey>>,
    tx: Arc<MockTx>,
}

/// The mock's stand-in for a PC/SC transaction: one holder at a time, so
/// another handle (say, a card listing) cannot slip APDUs into the middle of
/// a multi-APDU save on the same mock.
#[derive(Default)]
struct MockTx {
    held: Mutex<bool>,
    cv: Condvar,
}

impl MockTx {
    fn acquire(&self) {
        let mut h = lock(&self.held);
        while *h {
            h = self.cv.wait(h).unwrap_or_else(|e| e.into_inner());
        }
        *h = true;
    }

    fn release(&self) {
        *lock(&self.held) = false;
        self.cv.notify_one();
    }
}

static MOCKS: Mutex<Vec<Mock>> = Mutex::new(Vec::new());
static TOUCH_MS: Mutex<u64> = Mutex::new(0);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

enum Inner {
    Mock(Arc<Mutex<MockYubiKey>>, Arc<MockTx>),
    #[cfg(target_os = "macos")]
    Pcsc(p99_pcsc::PcscCard),
}

pub struct Card {
    id: String,
    inner: Inner,
    pub touch: TouchHook,
    /// Nesting depth of `begin`/`end`; the PC/SC transaction spans depth > 0.
    depth: usize,
    /// APDUs sent outside a transaction (tests assert there are none).
    pub outside: usize,
}

impl Card {
    pub fn is_mock(&self) -> bool {
        matches!(self.inner, Inner::Mock(..))
    }

    /// Starts (or nests into) one exclusive PC/SC transaction, so a
    /// multi-APDU operation (unlock, save, clone, sync) cannot be interleaved
    /// with another app's APDUs. Mocks take their own exclusive lock.
    pub fn begin(&mut self) -> Result<()> {
        if self.depth == 0 {
            match &mut self.inner {
                Inner::Mock(_, tx) => tx.acquire(),
                #[cfg(target_os = "macos")]
                Inner::Pcsc(p) => p.begin()?,
            }
        }
        self.depth += 1;
        Ok(())
    }

    pub fn end(&mut self) {
        if self.depth == 0 {
            return;
        }
        self.depth -= 1;
        if self.depth == 0 {
            match &mut self.inner {
                Inner::Mock(_, tx) => tx.release(),
                #[cfg(target_os = "macos")]
                Inner::Pcsc(p) => p.end(),
            }
        }
    }

    /// Calls `on_removed` from a watcher thread when a real card leaves its
    /// reader. Mock removal is reported by `set_present` instead.
    pub fn watch_removal(&self, on_removed: impl FnOnce(&str) + Send + 'static) -> Option<Box<dyn Any + Send>> {
        match &self.inner {
            Inner::Mock(..) => {
                drop(on_removed);
                None
            }
            #[cfg(target_os = "macos")]
            Inner::Pcsc(p) => p.watch_removal(on_removed).ok().map(|w| Box::new(w) as Box<dyn Any + Send>),
        }
    }
}

const ECDH_HEADER: [u8; 4] = [0x00, 0x87, 0x11, 0x82];

impl SmartCard for Card {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if self.depth == 0 {
            self.outside += 1;
        }
        if apdu.starts_with(&ECDH_HEADER) {
            if let Some(f) = lock(&self.touch).as_ref() {
                f();
            }
            if self.is_mock() {
                std::thread::sleep(Duration::from_millis(*lock(&TOUCH_MS)));
            }
        }
        match &mut self.inner {
            // A lone APDU outside a transaction still waits its turn.
            Inner::Mock(m, tx) if self.depth == 0 => {
                tx.acquire();
                let r = lock(m).transmit(apdu);
                tx.release();
                r
            }
            Inner::Mock(m, _) => lock(m).transmit(apdu),
            #[cfg(target_os = "macos")]
            Inner::Pcsc(p) => p.transmit(apdu),
        }
    }

    fn reader_id(&self) -> &str {
        &self.id
    }
}

impl Drop for Card {
    /// A handle dropped mid-transaction must not leave its mock locked.
    fn drop(&mut self) {
        if self.depth > 0 && self.is_mock() {
            self.depth = 1;
            self.end();
        }
    }
}

pub fn open(id: &str) -> Result<Card> {
    let touch = TouchHook::default();
    if id.starts_with("mock:") {
        let mocks = lock(&MOCKS);
        let m = mocks.iter().find(|m| m.id == id).ok_or(Error::NotFound)?;
        if !m.present {
            return Err(Error::CardRemoved);
        }
        return Ok(Card { id: id.into(), inner: Inner::Mock(m.card.clone(), m.tx.clone()), touch, depth: 0, outside: 0 });
    }
    #[cfg(target_os = "macos")]
    {
        let p = p99_pcsc::PcscCard::open(Some(id)).map_err(|_| Error::CardRemoved)?;
        Ok(Card { id: id.into(), inner: Inner::Pcsc(p), touch, depth: 0, outside: 0 })
    }
    #[cfg(not(target_os = "macos"))]
    Err(Error::NotFound)
}

pub struct Listed {
    pub id: String,
    pub serial: u32,
    pub has_vault: bool,
    pub mock: bool,
}

/// Readers with a YubiKey. `busy` readers have an open session and are not
/// touched (opening a second PC/SC handle and dropping it resets the card).
pub fn list(busy: &[(String, u32)]) -> Vec<Listed> {
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut ids: Vec<(String, bool)> = lock(&MOCKS).iter().filter(|m| m.present).map(|m| (m.id.clone(), true)).collect();
    #[cfg(target_os = "macos")]
    ids.extend(p99_pcsc::yubikey_readers().unwrap_or_default().into_iter().map(|r| (r, false)));
    let mut out = vec![];
    for (id, mock) in ids {
        if let Some((_, serial)) = busy.iter().find(|(r, _)| *r == id) {
            out.push(Listed { id, serial: *serial, has_vault: true, mock });
            continue;
        }
        let Ok(mut card) = open(&id) else { continue };
        if card.begin().is_err() {
            continue;
        }
        let probe = Session::open(&mut card).map(|mut s| (s.serial, s.has_vault().unwrap_or(false)));
        card.end();
        let Ok((serial, has_vault)) = probe else { continue };
        out.push(Listed { id, serial, has_vault, mock });
    }
    out
}

pub fn provision_options(label: &str) -> ProvisionOptions {
    ProvisionOptions {
        label: label.into(),
        current_mgmt_key: None,
    }
}

/// Adds `count` mock cards and returns the first id. With `demo`, the first
/// one holds a small vault whose passphrase is [`DEMO_PASSPHRASE`].
pub fn enable_mocks(count: u32, demo: bool, touch_ms: u64) -> Result<String> {
    *lock(&TOUCH_MS) = touch_ms;
    let first = {
        let mut mocks = lock(&MOCKS);
        let first = format!("mock:{}", mocks.len());
        for _ in 0..count {
            let n = mocks.len() as u32;
            let serial = 10_000_001 + n;
            mocks.push(Mock {
                id: format!("mock:{n}"),
                present: true,
                card: Arc::new(Mutex::new(MockYubiKey::with_firmware(serial, [5, 7, 1]))),
                tx: Arc::default(),
            });
        }
        first
    };
    if demo && count > 0 {
        // In one transaction, so a card listing cannot interleave with it.
        let mut card = open(&first)?;
        card.begin()?;
        let opts = provision_options("Mock YubiKey");
        let r = Session::provision(&mut card, DEMO_PASSPHRASE.as_bytes(), &opts)
            .and_then(|mut s| s.upsert_many(demo_entries()?));
        card.end();
        r?;
    }
    Ok(first)
}

/// Unplugs or replugs a mock card.
pub fn set_present(id: &str, present: bool) -> Result<()> {
    let mut mocks = lock(&MOCKS);
    let m = mocks.iter_mut().find(|m| m.id == id).ok_or(Error::NotFound)?;
    m.present = present;
    let mut card = lock(&m.card);
    if present { card.replug() } else { card.unplug() }
    Ok(())
}

fn demo_entries() -> Result<Vec<Entry>> {
    let f = |kind, v: &str| Field { kind, label: None, value: v.as_bytes().to_vec() };
    let mk = |kind, name: &str, hosts: &[&str], fields| -> Result<Entry> {
        Ok(Entry {
            id: crypto::random_u64()?,
            kind,
            name: name.into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            created_at: 0,
            updated_at: 0,
            deleted: false,
            fields,
            extra: vec![],
        })
    };
    let totp = [&[0u8, 0][..], b"12345678901234567890"].concat();
    Ok(vec![
        mk(EntryKind::Login, "GitHub", &["github.com"], vec![
            f(FieldKind::Username, "octocat"),
            f(FieldKind::Password, "correct-horse-battery"),
            Field { kind: FieldKind::Totp, label: None, value: totp },
        ])?,
        mk(EntryKind::Login, "Google", &["accounts.google.com", "google.com"], vec![
            f(FieldKind::Username, "alice@example.com"),
            f(FieldKind::Password, "hunter2hunter2"),
        ])?,
        mk(EntryKind::Card, "Visa", &[], vec![
            f(FieldKind::CardHolder, "B. Rams"),
            f(FieldKind::CardNumber, "4111111111111111"),
            f(FieldKind::CardExpiry, "2029-04"),
            f(FieldKind::CardCvv, "123"),
        ])?,
        mk(EntryKind::Note, "Wi-Fi", &[], vec![f(FieldKind::Note, "SSID home, key swordfish")])?,
    ])
}
