//! Plain C ABI for the macOS app (workstream D). The hand-written header in
//! `include/p99.h` is the contract; see `docs/SPEC.md` §11.
//!
//! Cards are real YubiKeys over PC/SC (macOS) or in-memory mocks (`cards.rs`),
//! all driven through the core's Session API.

#![allow(clippy::missing_safety_doc)]

mod cards;
mod favicon;

use std::ffi::{CStr, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, Weak};

use p99_core::model::{Entry, EntryKind, Field, FieldKind, Vault};
use p99_core::{base32, crypto, generator, host, json, otpauth, totp};
use p99_core::{Error, Result, Session, SmartCard};
use zeroize::Zeroize;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P99Status {
    Ok = 0,
    CardRemoved = 1,
    Card = 2,
    NotFound = 3,
    Capacity = 4,
    MgmtKey = 5,
    Decrypt = 6,
    NoVault = 7,
    Format = 8,
    Unsupported = 9,
    Invalid = 10,
    Rng = 11,
    Locked = 12,
    TouchTimeout = 13,
    WrongPin = 14,
    PinBlocked = 15,
    Panic = 255,
}

fn status(e: &Error) -> P99Status {
    match e {
        Error::CardRemoved => P99Status::CardRemoved,
        Error::Card { sw: 0x6982, context: "ecdh" } => P99Status::TouchTimeout,
        Error::Card { .. } => P99Status::Card,
        Error::NotFound => P99Status::NotFound,
        Error::Capacity { .. } => P99Status::Capacity,
        Error::ManagementKey => P99Status::MgmtKey,
        Error::Decrypt => P99Status::Decrypt,
        Error::NoValidVault => P99Status::NoVault,
        Error::Format(_) => P99Status::Format,
        Error::Unsupported(_) => P99Status::Unsupported,
        Error::Invalid(_) => P99Status::Invalid,
        Error::Rng => P99Status::Rng,
        Error::Locked => P99Status::Locked,
        Error::WrongPin { .. } => P99Status::WrongPin,
        Error::PinBlocked => P99Status::PinBlocked,
    }
}

/// Text of the most recent error, for `p99_last_error`.
static LAST_ERROR: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn set_last_error(m: String) {
    *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = m;
}

/// Runs `f`, never letting a panic unwind into Swift.
fn guard(f: impl FnOnce() -> Result<()>) -> P99Status {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => P99Status::Ok,
        Ok(Err(e)) => {
            set_last_error(e.to_string());
            status(&e)
        }
        Err(_) => {
            set_last_error("internal error".into());
            P99Status::Panic
        }
    }
}

/// UTF-8 text describing the most recent failed call (any thread).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_last_error(out: *mut P99Buf) {
    if out.is_null() {
        return;
    }
    let m = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    unsafe { *out = P99Buf::from_vec(m.into_bytes()) };
}

// ---------------------------------------------------------------- buffers

#[repr(C)]
#[derive(Debug)]
pub struct P99Buf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl P99Buf {
    pub const EMPTY: P99Buf = P99Buf { ptr: std::ptr::null_mut(), len: 0 };
    fn from_vec(v: Vec<u8>) -> P99Buf {
        let b = v.into_boxed_slice();
        let len = b.len();
        P99Buf { ptr: Box::into_raw(b) as *mut u8, len }
    }
}

fn put(out: *mut P99Buf, v: Vec<u8>) -> Result<()> {
    if out.is_null() {
        return Err(Error::Invalid("null out"));
    }
    unsafe { out.write(P99Buf::from_vec(v)) };
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_buf_free(buf: P99Buf) {
    if buf.ptr.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        let mut b = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) };
        b.zeroize();
    });
}

unsafe fn cstr<'a>(p: *const c_char) -> Result<&'a str> {
    if p.is_null() {
        return Err(Error::Invalid("null string"));
    }
    unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| Error::Invalid("not UTF-8"))
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8]> {
    match (p.is_null(), len) {
        (_, 0) => Ok(&[]),
        (true, _) => Err(Error::Invalid("null buffer")),
        (false, _) => Ok(unsafe { std::slice::from_raw_parts(p, len) }),
    }
}

// ---------------------------------------------------------------- sessions

pub type P99RemovalFn = Option<unsafe extern "C" fn(ctx: *mut c_void, reader_id: *const c_char)>;
pub type P99TouchFn = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

#[derive(Clone, Copy)]
struct Callback<F> {
    f: F,
    ctx: usize,
}

struct State {
    reader: String,
    session: Session<cards::Card>,
    removal: Option<Callback<P99RemovalFn>>,
    /// PC/SC removal watcher; dropped with the session.
    _watcher: Option<Box<dyn std::any::Any + Send>>,
}

impl State {
    fn vault(&self) -> Result<&Vault> {
        self.session.vault()
    }
}

pub struct P99Session(Arc<Mutex<State>>);

static SESSIONS: Mutex<Vec<Weak<Mutex<State>>>> = Mutex::new(Vec::new());

fn live_sessions() -> Vec<Arc<Mutex<State>>> {
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect()
}

unsafe fn session<'a>(s: *mut P99Session) -> Result<std::sync::MutexGuard<'a, State>> {
    if s.is_null() {
        return Err(Error::Invalid("null session"));
    }
    Ok(unsafe { &*s }.0.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Runs `f` inside one PC/SC transaction on the session's card, so a
/// multi-APDU operation is never interleaved with another app.
fn txn<R>(st: &mut State, f: impl FnOnce(&mut Session<cards::Card>) -> Result<R>) -> Result<R> {
    if let Err(e) = st.session.card_mut().begin() {
        st.session.lock();
        return Err(e);
    }
    let r = f(&mut st.session);
    st.session.card_mut().end();
    r
}

/// Opens a session on `card` inside one transaction.
fn open_in_txn(mut card: cards::Card) -> Result<Session<cards::Card>> {
    card.begin()?;
    let r = Session::open(card);
    r.map(|mut s| {
        s.card_mut().end();
        s
    })
}

fn new_session(session: Session<cards::Card>, out: *mut *mut P99Session) -> Result<()> {
    if out.is_null() {
        return Err(Error::Invalid("null out"));
    }
    let reader = session.card().reader_id().to_owned();
    let watcher = session.card().watch_removal(on_removed);
    let state = Arc::new(Mutex::new(State { reader, session, removal: None, _watcher: watcher }));
    let mut all = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|w| w.strong_count() > 0);
    all.push(Arc::downgrade(&state));
    unsafe { out.write(Box::into_raw(Box::new(P99Session(state)))) };
    Ok(())
}

/// Locks every session on `reader`, then runs their removal callbacks.
fn on_removed(reader: &str) {
    let mut calls = vec![];
    for s in live_sessions() {
        let mut st = s.lock().unwrap_or_else(|e| e.into_inner());
        if st.reader == reader {
            st.session.on_card_removed();
            calls.extend(st.removal);
        }
    }
    let Ok(id) = std::ffi::CString::new(reader) else { return };
    for c in calls {
        if let Some(f) = c.f {
            unsafe { f(c.ctx as *mut c_void, id.as_ptr()) };
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_list_cards(out_json: *mut P99Buf) -> P99Status {
    guard(|| {
        // Readers we already hold are reported from their session.
        let busy: Vec<(String, u32)> = live_sessions()
            .iter()
            .filter_map(|s| s.try_lock().ok().map(|st| (st.reader.clone(), st.session.serial)))
            .collect();
        let mut s = String::from("[");
        for (i, c) in cards::list(&busy).iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"id\":");
            json::write_str(&mut s, &c.id);
            s.push_str(&format!(",\"serial\":{},\"has_vault\":{},\"mock\":{}}}", c.serial, c.has_vault, c.mock));
        }
        s.push(']');
        put(out_json, s.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_open(reader_id: *const c_char, out: *mut *mut P99Session) -> P99Status {
    guard(|| {
        let reader = unsafe { cstr(reader_id) }?;
        new_session(open_in_txn(cards::open(reader)?)?, out)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_provision(
    reader_id: *const c_char,
    pass: *const u8,
    pass_len: usize,
    label: *const c_char,
    out: *mut *mut P99Session,
) -> P99Status {
    guard(|| {
        let reader = unsafe { cstr(reader_id) }?;
        let label = if label.is_null() { "YubiKey" } else { unsafe { cstr(label) }? };
        let pass = unsafe { bytes(pass, pass_len) }?;
        // Any passphrase the user wants, as long as there is one.
        if pass.is_empty() {
            return Err(Error::Invalid("the passphrase is empty"));
        }
        let mut card = cards::open(reader)?;
        let opts = cards::provision_options(label);
        card.begin()?;
        let has_vault = Session::open(&mut card).and_then(|mut p| p.has_vault());
        let r = match has_vault {
            Ok(true) => Err(Error::Invalid("card already holds a vault")),
            Ok(false) => Session::provision(card, pass, &opts),
            Err(e) => Err(e),
        };
        let mut session = r?;
        session.card_mut().end();
        new_session(session, out)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_close(s: *mut P99Session) {
    if s.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let b = unsafe { Box::from_raw(s) };
        b.0.lock().unwrap_or_else(|e| e.into_inner()).session.lock();
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_set_touch_callback(s: *mut P99Session, f: P99TouchFn, ctx: *mut c_void) {
    let _ = guard(|| {
        let st = unsafe { session(s) }?;
        let cb = Callback { f, ctx: ctx as usize };
        *st.session.card().touch.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
            if let Some(f) = cb.f {
                unsafe { f(cb.ctx as *mut c_void) };
            }
        }));
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_unlock(s: *mut P99Session, pass: *const u8, pass_len: usize) -> P99Status {
    guard(|| {
        let pass = unsafe { bytes(pass, pass_len) }?;
        txn(&mut *unsafe { session(s) }?, |s| s.unlock(pass))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_pin_tries(s: *mut P99Session, out_left: *mut u32) -> P99Status {
    guard(|| {
        if out_left.is_null() {
            return Err(Error::Invalid("null out"));
        }
        let n = txn(&mut *unsafe { session(s) }?, |s| s.pin_tries_left())?;
        unsafe { out_left.write(u32::from(n)) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_lock(s: *mut P99Session) {
    let _ = guard(|| {
        unsafe { session(s) }?.session.lock();
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_is_unlocked(s: *mut P99Session) -> bool {
    let mut r = false;
    let _ = guard(|| {
        r = unsafe { session(s) }?.session.is_unlocked();
        Ok(())
    });
    r
}

fn is_secret(k: FieldKind) -> bool {
    use FieldKind::*;
    !matches!(
        k,
        Username | CardHolder | CardExpiry | CustomText | FirstName | LastName | Email | Phone | Street | City | Postcode | Region | Country
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_list_entries(s: *mut P99Session, host: *const c_char, out_json: *mut P99Buf) -> P99Status {
    guard(|| {
        let host = if host.is_null() { None } else { Some(host::normalize(unsafe { cstr(host) }?)?) };
        let host = host.as_deref();
        let st = unsafe { session(s) }?;
        let v = st.vault()?;
        let mut list: Vec<(u8, &Entry)> = v
            .entries
            .iter()
            .filter(|e| !e.deleted)
            .filter_map(|e| match host {
                None => Some((0, e)),
                Some(h) => e.hosts.iter().filter_map(|eh| host::match_rank(h, eh)).min().map(|r| (r, e)),
            })
            .collect();
        list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase())));
        let mut o = String::from("[");
        for (i, (rank, e)) in list.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"id\":\"{}\",\"kind\":{},\"name\":", e.id, e.kind as u8));
            json::write_str(&mut o, &e.name);
            o.push_str(",\"hosts\":[");
            for (j, h) in e.hosts.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                json::write_str(&mut o, h);
            }
            o.push_str("],\"username\":");
            match e.fields.iter().find(|f| f.kind == FieldKind::Username) {
                Some(f) => json::write_str(&mut o, &String::from_utf8_lossy(&f.value)),
                None => o.push_str("null"),
            }
            let has_totp = e.fields.iter().any(|f| f.kind == FieldKind::Totp);
            o.push_str(&format!(",\"has_totp\":{has_totp},\"created_at\":{},\"updated_at\":{},\"rank\":{rank},\"fields\":[", e.created_at, e.updated_at));
            for (j, f) in e.fields.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                o.push_str(&format!("{{\"kind\":{},\"secret\":{},\"label\":", f.kind as u8, is_secret(f.kind)));
                match &f.label {
                    Some(l) => json::write_str(&mut o, l),
                    None => o.push_str("null"),
                }
                // Non-secret values ride along so the detail view needs no reveal.
                o.push_str(",\"value\":");
                if is_secret(f.kind) {
                    o.push_str("null");
                } else {
                    json::write_str(&mut o, &String::from_utf8_lossy(&f.value));
                }
                o.push('}');
            }
            o.push_str("]}");
        }
        o.push(']');
        put(out_json, o.into_bytes())
    })
}

fn entry(v: &Vault, id: u64) -> Result<&Entry> {
    v.entries.iter().find(|e| e.id == id && !e.deleted).ok_or(Error::NotFound)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_reveal_field(s: *mut P99Session, entry_id: u64, field_index: u32, out: *mut P99Buf) -> P99Status {
    guard(|| {
        let st = unsafe { session(s) }?;
        let e = entry(st.vault()?, entry_id)?;
        let f = e.fields.get(field_index as usize).ok_or(Error::NotFound)?;
        let value = if f.kind == FieldKind::Totp {
            // Editing shows the secret as base32.
            base32::encode(totp::unpack(&f.value)?.1).into_bytes()
        } else {
            f.value.clone()
        };
        put(out, value)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_totp_now(
    s: *mut P99Session,
    entry_id: u64,
    unix_time: u64,
    out_code: *mut P99Buf,
    out_seconds_left: *mut u32,
) -> P99Status {
    guard(|| {
        let st = unsafe { session(s) }?;
        let e = entry(st.vault()?, entry_id)?;
        let f = e.fields.iter().find(|f| f.kind == FieldKind::Totp).ok_or(Error::NotFound)?;
        let c = totp::code_for_field(&f.value, unix_time)?;
        if !out_seconds_left.is_null() {
            unsafe { out_seconds_left.write(c.remaining_secs) };
        }
        put(out_code, c.code.into_bytes())
    })
}

fn field_kind(n: u64) -> Result<FieldKind> {
    u8::try_from(n).ok().and_then(FieldKind::from_u8).ok_or(Error::Invalid("field kind"))
}

/// Parses the SPEC §11.3 entry JSON.
fn parse_entry(input: &[u8]) -> Result<Entry> {
    let bad = Error::Invalid("entry json");
    let text = std::str::from_utf8(input).map_err(|_| bad.clone())?;
    let v = json::parse(text).map_err(|_| bad.clone())?;
    let id = match v.get("id") {
        None | Some(json::Value::Null) => 0,
        Some(x) => x.as_str().and_then(|s| s.parse().ok()).ok_or(bad.clone())?,
    };
    let kind = v
        .get("kind")
        .and_then(json::Value::as_u64)
        .and_then(|k| u8::try_from(k).ok())
        .and_then(EntryKind::from_u8)
        .ok_or(bad.clone())?;
    let name = v.get("name").and_then(json::Value::as_str).ok_or(bad.clone())?.to_owned();
    let mut hosts = vec![];
    for h in v.get("hosts").map(json::Value::as_array).unwrap_or_default() {
        let h = host::normalize(h.as_str().ok_or(bad.clone())?)?;
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    let mut fields = vec![];
    for f in v.get("fields").map(json::Value::as_array).unwrap_or_default() {
        let kind = field_kind(f.get("kind").and_then(json::Value::as_u64).ok_or(bad.clone())?)?;
        let label = f.get("label").and_then(json::Value::as_str).map(str::to_owned);
        let raw = f.get("value").and_then(json::Value::as_str).ok_or(bad.clone())?;
        let value = if kind == FieldKind::Totp {
            if raw.starts_with("otpauth://") {
                otpauth::parse(raw)?.packed()?
            } else {
                totp::pack(totp::Params::default(), &base32::decode(raw)?)?
            }
        } else {
            raw.as_bytes().to_vec()
        };
        fields.push(Field { kind, label, value });
    }
    Ok(Entry { id, kind, name, hosts, created_at: 0, updated_at: 0, deleted: false, fields, extra: vec![] })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_upsert_entry(s: *mut P99Session, json_ptr: *const u8, len: usize, out_id: *mut u64) -> P99Status {
    guard(|| {
        let mut e = parse_entry(unsafe { bytes(json_ptr, len) }?)?;
        let mut st = unsafe { session(s) }?;
        if e.id == 0 || st.session.entry(e.id)?.is_none() {
            e.id = crypto::random_u64()?;
        }
        let id = txn(&mut st, |s| s.upsert(e))?;
        if !out_id.is_null() {
            unsafe { out_id.write(id) };
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_delete_entry(s: *mut P99Session, entry_id: u64) -> P99Status {
    guard(|| {
        let mut st = unsafe { session(s) }?;
        if st.session.entry(entry_id)?.is_none() {
            return Err(Error::NotFound);
        }
        txn(&mut st, |s| s.delete(entry_id))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_set_removal_callback(s: *mut P99Session, f: P99RemovalFn, ctx: *mut c_void) {
    let _ = guard(|| {
        unsafe { session(s) }?.removal = Some(Callback { f, ctx: ctx as usize });
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_capacity(s: *mut P99Session, out_json: *mut P99Buf) -> P99Status {
    guard(|| {
        let st = &unsafe { session(s) }?.session;
        let c = st.capacity()?;
        let updated = st.vault()?.updated_at();
        let mode = if c.single_bank { "single" } else { "ab" };
        put(out_json, format!("{{\"used\":{},\"capacity\":{},\"mode\":\"{mode}\",\"revision\":{},\"updated_at\":{updated}}}", c.used, c.capacity, c.revision).into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_gen_password(length: u32, class_flags: u32, out: *mut P99Buf) -> P99Status {
    guard(|| {
        let o = generator::PasswordOptions {
            length: length as usize,
            lowercase: class_flags & 1 != 0,
            uppercase: class_flags & 2 != 0,
            digits: class_flags & 4 != 0,
            symbols: class_flags & 8 != 0,
            avoid_ambiguous: class_flags & 16 != 0,
        };
        put(out, generator::password(&o)?.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_gen_passphrase(words: u32, separator: u8, out: *mut P99Buf) -> P99Status {
    guard(|| {
        if !separator.is_ascii() {
            return Err(Error::Invalid("separator must be ASCII"));
        }
        let o = generator::PassphraseOptions { words: words as usize, separator: (separator as char).to_string(), ..Default::default() };
        put(out, generator::passphrase(&o)?.into_bytes())
    })
}

fn vault_secret(s: *mut P99Session) -> Result<[u8; 32]> {
    Ok(unsafe { session(s) }?.vault()?.vault_secret)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_favicon_name(s: *mut P99Session, host: *const c_char, out_hex: *mut P99Buf) -> P99Status {
    guard(|| {
        let mut k = vault_secret(s)?;
        let r = put(out_hex, favicon::name(&k, unsafe { cstr(host) }?).into_bytes());
        k.zeroize();
        r
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_favicon_seal(s: *mut P99Session, host: *const c_char, png: *const u8, len: usize, out: *mut P99Buf) -> P99Status {
    guard(|| {
        let mut k = vault_secret(s)?;
        let r = favicon::seal(&k, unsafe { cstr(host) }?, unsafe { bytes(png, len) }?);
        k.zeroize();
        put(out, r?)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_favicon_open(s: *mut P99Session, host: *const c_char, blob: *const u8, len: usize, out_png: *mut P99Buf) -> P99Status {
    guard(|| {
        let mut k = vault_secret(s)?;
        let r = favicon::open(&k, unsafe { cstr(host) }?, unsafe { bytes(blob, len) }?);
        k.zeroize();
        put(out_png, r?)
    })
}

// ---------------------------------------------------------------- backup keys

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_known_keys(s: *mut P99Session, out_json: *mut P99Buf) -> P99Status {
    guard(|| {
        let st = unsafe { session(s) }?;
        let rev = st.session.revision()?;
        let mut o = format!("{{\"revision\":{rev},\"keys\":[");
        for (i, k) in st.vault()?.known_keys.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"serial\":{},\"label\":", k.serial));
            json::write_str(&mut o, &k.label);
            o.push_str(&format!(
                ",\"last_synced_rev\":{},\"added_at\":{},\"this\":{}}}",
                k.last_synced_rev,
                k.added_at,
                k.serial == st.session.serial
            ));
        }
        o.push_str("]}");
        put(out_json, o.into_bytes())
    })
}

/// Opens a second card for clone or sync, sharing the session's touch hook.
fn other_card(st: &State, reader: *const c_char) -> Result<cards::Card> {
    let reader = unsafe { cstr(reader) }?;
    if reader == st.reader {
        return Err(Error::Invalid("plug in a second YubiKey"));
    }
    let mut c = cards::open(reader)?;
    c.touch = st.session.card().touch.clone();
    c.begin()?;
    Ok(c)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_clone_to(s: *mut P99Session, backup_reader: *const c_char, label: *const c_char) -> P99Status {
    guard(|| {
        let mut st = unsafe { session(s) }?;
        let label = if label.is_null() { "Backup YubiKey" } else { unsafe { cstr(label) }? };
        let mut backup = other_card(&st, backup_reader)?;
        let r = (|| {
            if Session::open(&mut backup)?.has_vault()? {
                return Err(Error::Invalid("this YubiKey already holds a vault"));
            }
            txn(&mut st, |s| s.clone_to(&mut backup, label, None))
        })();
        backup.end();
        r
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_sync_with(s: *mut P99Session, other_reader: *const c_char, out_relation: *mut u32) -> P99Status {
    guard(|| {
        use p99_core::merge::Relation;
        let mut st = unsafe { session(s) }?;
        let mut other = other_card(&st, other_reader)?;
        let r = txn(&mut st, |s| s.sync_with(&mut other));
        other.end();
        let code = match r? {
            Relation::InSync => 0,
            Relation::TheyAreStale => 1,
            Relation::WeAreStale => 2,
            Relation::Diverged => 3,
        };
        if !out_relation.is_null() {
            unsafe { out_relation.write(code) };
        }
        Ok(())
    })
}

// ---------------------------------------------------------------- export / import

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_export_backup(
    s: *mut P99Session,
    with_recovery_key: bool,
    out_file: *mut P99Buf,
    out_recovery: *mut P99Buf,
) -> P99Status {
    guard(|| {
        let st = unsafe { session(s) }?;
        let (file, rk) = st.session.export_backup(with_recovery_key)?;
        if !out_recovery.is_null() {
            unsafe { out_recovery.write(P99Buf::EMPTY) };
            if let Some(rk) = rk {
                put(out_recovery, rk.into_bytes())?;
            }
        }
        put(out_file, file)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_import_backup(
    s: *mut P99Session,
    file: *const u8,
    len: usize,
    pass: *const u8,
    pass_len: usize,
    recovery_key: *const c_char,
    out_count: *mut u32,
) -> P99Status {
    guard(|| {
        let file = unsafe { bytes(file, len) }?;
        let pass = unsafe { bytes(pass, pass_len) }?;
        let rk = if recovery_key.is_null() { None } else { Some(unsafe { cstr(recovery_key) }?) };
        let mut st = unsafe { session(s) }?;
        let count = txn(&mut st, |s| {
            let imported = match rk {
                Some(rk) => p99_core::backup::open_with_recovery_key(file, pass, rk)?,
                None => s.open_backup(file, pass)?,
            };
            s.import_merge(&imported)?;
            Ok(imported.entries.iter().filter(|e| !e.deleted).count() as u32)
        })?;
        if !out_count.is_null() {
            unsafe { out_count.write(count) };
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_export_plain(s: *mut P99Session, format: u32, out: *mut P99Buf) -> P99Status {
    guard(|| {
        use p99_core::interop;
        let st = unsafe { session(s) }?;
        let entries = &st.vault()?.entries;
        let text = match format {
            0 => interop::export_csv(entries).0,
            1 => interop::export_json(entries, p99_core::session::unix_now()),
            _ => return Err(Error::Invalid("format")),
        };
        put(out, text.as_bytes().to_vec())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_import_plain(s: *mut P99Session, data: *const u8, len: usize, out_json: *mut P99Buf) -> P99Status {
    guard(|| {
        use p99_core::interop;
        let text = std::str::from_utf8(unsafe { bytes(data, len) }?).map_err(|_| Error::Invalid("not UTF-8"))?;
        let text = text.trim_start_matches('\u{feff}');
        let imp = if text.trim_start().starts_with('{') {
            interop::import_json(text)?
        } else {
            interop::import_csv(text, p99_core::session::unix_now())?
        };
        let n = imp.entries.len();
        let mut st = unsafe { session(s) }?;
        if n > 0 {
            txn(&mut st, |s| s.upsert_many(imp.entries))?;
        }
        let mut o = format!("{{\"imported\":{n},\"skipped\":[");
        for (i, (line, why)) in imp.skipped.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"line\":{line},\"reason\":"));
            json::write_str(&mut o, why);
            o.push('}');
        }
        o.push_str("]}");
        put(out_json, o.into_bytes())
    })
}

// ---------------------------------------------------------------- mock control

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_mock_enable(cards: u32, flags: u32, touch_ms: u32) -> P99Status {
    guard(|| cards::enable_mocks(cards, flags & 1 != 0, touch_ms as u64).map(drop))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn p99_mock_set_present(reader_id: *const c_char, present: bool) -> P99Status {
    guard(|| {
        let reader = unsafe { cstr(reader_id) }?;
        cards::set_present(reader, present)?;
        if !present {
            on_removed(reader);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests;
