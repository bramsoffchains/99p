//! Drives the C ABI exactly as Swift does.

use super::*;
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};

static SERIAL: Mutex<()> = Mutex::new(());

fn take(b: YkvBuf) -> String {
    let s = String::from_utf8(unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()).unwrap();
    unsafe { ykv_buf_free(b) };
    s
}

fn call(f: impl FnOnce(*mut YkvBuf) -> YkvStatus) -> std::result::Result<String, YkvStatus> {
    let mut b = YkvBuf::EMPTY;
    match f(&mut b) {
        YkvStatus::Ok => Ok(take(b)),
        e => Err(e),
    }
}

/// A fresh demo card (passphrase `DEMO_PASSPHRASE`) and an unlocked session on it.
fn demo() -> (CString, *mut YkvSession) {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let reader = CString::new(cards::enable_mocks(1, true, 0).unwrap()).unwrap();
    let mut s = std::ptr::null_mut();
    unsafe {
        assert_eq!(ykv_open(reader.as_ptr(), &mut s), YkvStatus::Ok);
        let p = cards::DEMO_PASSPHRASE;
        assert_eq!(ykv_unlock(s, p.as_ptr(), p.len()), YkvStatus::Ok);
    }
    (reader, s)
}

fn first_id(list: &str) -> u64 {
    let v = json::parse(list).unwrap();
    v.as_array()[0].get("id").unwrap().as_str().unwrap().parse().unwrap()
}

#[test]
fn unlock_list_reveal_lock() {
    let (_r, s) = demo();
    unsafe {
        let all = call(|b| ykv_list_entries(s, std::ptr::null(), b)).unwrap();
        assert_eq!(json::parse(&all).unwrap().as_array().len(), 4);
        assert!(!all.contains("correct-horse-battery"), "listing must not carry secrets");
        let host = CString::new("gist.github.com").unwrap();
        let gh = call(|b| ykv_list_entries(s, host.as_ptr(), b)).unwrap();
        assert!(gh.contains("\"name\":\"GitHub\"") && gh.contains("\"rank\":1"), "{gh}");
        let id = first_id(&gh);
        assert_eq!(call(|b| ykv_reveal_field(s, id, 1, b)).unwrap(), "correct-horse-battery");
        let mut left = 0;
        assert_eq!(call(|b| ykv_totp_now(s, id, 59, b, &mut left)).unwrap(), "287082");
        assert_eq!(left, 1);
        ykv_lock(s);
        assert_eq!(call(|b| ykv_reveal_field(s, id, 1, b)), Err(YkvStatus::Locked));
        ykv_close(s);
    }
}

#[test]
fn wrong_passphrase_and_touch_callback() {
    let (r, s) = demo();
    static TOUCHED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn touched(_: *mut c_void) {
        TOUCHED.fetch_add(1, Ordering::SeqCst);
    }
    unsafe {
        ykv_close(s);
        let mut s = std::ptr::null_mut();
        assert_eq!(ykv_open(r.as_ptr(), &mut s), YkvStatus::Ok);
        ykv_set_touch_callback(s, Some(touched), std::ptr::null_mut());
        // The card refuses the wrong PIN before it asks for a touch.
        assert_eq!(ykv_unlock(s, b"nope nope".as_ptr(), 9), YkvStatus::WrongPin);
        assert!(!ykv_is_unlocked(s));
        assert_eq!(TOUCHED.load(Ordering::SeqCst), 0);
        let mut left = 0;
        assert_eq!(ykv_pin_tries(s, &mut left), YkvStatus::Ok);
        assert_eq!(left, 254);
        let p = cards::DEMO_PASSPHRASE;
        assert_eq!(ykv_unlock(s, p.as_ptr(), p.len()), YkvStatus::Ok);
        assert_eq!(TOUCHED.load(Ordering::SeqCst), 1);
        assert_eq!(ykv_pin_tries(s, &mut left), YkvStatus::Ok);
        assert_eq!(left, 255);
        ykv_close(s);
    }
}

#[test]
fn upsert_update_delete_persist() {
    let (r, s) = demo();
    unsafe {
        let j = br#"{"kind":1,"name":"Example","hosts":["App.Example.com."],"fields":[{"kind":1,"value":"me"},{"kind":2,"value":"p\u00e4ss"},{"kind":3,"value":"GEZD GNBV"}]}"#;
        let mut id = 0;
        assert_eq!(ykv_upsert_entry(s, j.as_ptr(), j.len(), &mut id), YkvStatus::Ok);
        assert_ne!(id, 0);
        assert_eq!(call(|b| ykv_reveal_field(s, id, 1, b)).unwrap(), "päss");
        assert_eq!(call(|b| ykv_reveal_field(s, id, 2, b)).unwrap(), "GEZDGNBV");
        let upd = format!(r#"{{"id":"{id}","kind":1,"name":"Renamed","hosts":["app.example.com"],"fields":[]}}"#);
        let mut id2 = 0;
        assert_eq!(ykv_upsert_entry(s, upd.as_ptr(), upd.len(), &mut id2), YkvStatus::Ok);
        assert_eq!(id, id2);
        // Survives lock + unlock, i.e. it reached the card.
        ykv_lock(s);
        let p = cards::DEMO_PASSPHRASE;
        assert_eq!(ykv_unlock(s, p.as_ptr(), p.len()), YkvStatus::Ok);
        let host = CString::new("app.example.com").unwrap();
        let l = call(|b| ykv_list_entries(s, host.as_ptr(), b)).unwrap();
        assert!(l.contains("Renamed") && l.contains("\"username\":null"), "{l}");
        assert_eq!(ykv_delete_entry(s, id), YkvStatus::Ok);
        assert_eq!(call(|b| ykv_list_entries(s, host.as_ptr(), b)).unwrap(), "[]");
        assert_eq!(ykv_delete_entry(s, id), YkvStatus::NotFound);
        let cap = call(|b| ykv_capacity(s, b)).unwrap();
        assert!(cap.contains("\"capacity\":23552") && cap.contains("\"mode\":\"ab\""), "{cap}");
        assert!(!cap.contains("\"updated_at\":0}"), "{cap}");
        assert_eq!(ykv_upsert_entry(s, b"{".as_ptr(), 1, &mut id), YkvStatus::Invalid);
        ykv_close(s);
        let _ = r;
    }
}

#[test]
fn capacity_limit() {
    let (_r, s) = demo();
    let mut id = 0;
    let mut last = YkvStatus::Ok;
    for _ in 0..20 {
        // Random text, so compression cannot shrink it.
        let o = generator::PasswordOptions { length: 128, symbols: false, ..Default::default() };
        let big: String = (0..24).map(|_| generator::password(&o).unwrap()).collect();
        let j = format!(r#"{{"kind":3,"name":"n","fields":[{{"kind":9,"value":"{big}"}}]}}"#);
        last = unsafe { ykv_upsert_entry(s, j.as_ptr(), j.len(), &mut id) };
        if last != YkvStatus::Ok {
            break;
        }
    }
    assert_eq!(last, YkvStatus::Capacity);
    unsafe { ykv_close(s) };
}

#[test]
fn removal_locks_and_calls_back() {
    let (r, s) = demo();
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn removed(ctx: *mut c_void, reader: *const c_char) {
        assert_eq!(ctx as usize, 42);
        assert!(unsafe { CStr::from_ptr(reader) }.to_str().unwrap().starts_with("mock:"));
        CALLS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe {
        ykv_set_removal_callback(s, Some(removed), 42 as *mut c_void);
        assert_eq!(ykv_mock_set_present(r.as_ptr(), false), YkvStatus::Ok);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert!(!ykv_is_unlocked(s));
        let p = cards::DEMO_PASSPHRASE;
        assert_eq!(ykv_unlock(s, p.as_ptr(), p.len()), YkvStatus::CardRemoved);
        assert_eq!(ykv_mock_set_present(r.as_ptr(), true), YkvStatus::Ok);
        assert_eq!(ykv_unlock(s, p.as_ptr(), p.len()), YkvStatus::Ok);
        ykv_close(s);
    }
}

/// Reads a buffer written by a call that cannot fail.
unsafe fn call_void(f: impl FnOnce(*mut YkvBuf)) -> String {
    let mut b = YkvBuf::EMPTY;
    f(&mut b);
    let s = String::from_utf8(unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()).unwrap();
    unsafe { ykv_buf_free(b) };
    s
}

#[test]
fn provision_and_list_cards() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let r = CString::new(cards::enable_mocks(1, false, 0).unwrap()).unwrap();
    unsafe {
        let cards = call(|b| ykv_list_cards(b)).unwrap();
        assert!(cards.contains(&format!("\"id\":\"{}\",\"serial\"", r.to_str().unwrap())));
        let mut s = std::ptr::null_mut();
        assert_eq!(ykv_provision(r.as_ptr(), b"".as_ptr(), 0, std::ptr::null(), &mut s), YkvStatus::Invalid);
        assert_eq!(call_void(|b| ykv_last_error(b)), "invalid argument: the passphrase is empty");
        // Any non-empty passphrase is the user's choice.
        let p = "short";
        assert_eq!(ykv_provision(r.as_ptr(), p.as_ptr(), p.len(), std::ptr::null(), &mut s), YkvStatus::Ok);
        assert!(ykv_is_unlocked(s));
        assert_eq!(call(|b| ykv_list_entries(s, std::ptr::null(), b)).unwrap(), "[]");
        let mut s2 = std::ptr::null_mut();
        assert_eq!(ykv_provision(r.as_ptr(), p.as_ptr(), p.len(), std::ptr::null(), &mut s2), YkvStatus::Invalid);
        assert_eq!(call_void(|b| ykv_last_error(b)), "invalid argument: card already holds a vault");
        ykv_close(s);
    }
}

#[test]
fn generators_and_nulls() {
    unsafe {
        assert_eq!(call(|b| ykv_gen_password(24, 15, b)).unwrap().len(), 24);
        assert_eq!(call(|b| ykv_gen_passphrase(5, b' ', b)).unwrap().split(' ').count(), 5);
        assert_eq!(ykv_gen_password(2, 15, std::ptr::null_mut()), YkvStatus::Invalid);
        assert_eq!(ykv_lock_null_is_safe(), ());
        ykv_buf_free(YkvBuf::EMPTY);
        let mut s = std::ptr::null_mut();
        assert_eq!(ykv_open(std::ptr::null(), &mut s), YkvStatus::Invalid);
    }
}

unsafe fn ykv_lock_null_is_safe() {
    unsafe {
        ykv_lock(std::ptr::null_mut());
        ykv_close(std::ptr::null_mut());
    }
}

#[test]
fn favicon_roundtrip() {
    let (_r, s) = demo();
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    png.extend_from_slice(&[0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0]);
    let host = CString::new("github.com").unwrap();
    unsafe {
        let name = call(|b| ykv_favicon_name(s, host.as_ptr(), b)).unwrap();
        assert_eq!(name.len(), 32);
        let mut sealed = YkvBuf::EMPTY;
        assert_eq!(ykv_favicon_seal(s, host.as_ptr(), png.as_ptr(), png.len(), &mut sealed), YkvStatus::Ok);
        let mut opened = YkvBuf::EMPTY;
        assert_eq!(ykv_favicon_open(s, host.as_ptr(), sealed.ptr, sealed.len, &mut opened), YkvStatus::Ok);
        assert_eq!(std::slice::from_raw_parts(opened.ptr, opened.len), &png[..]);
        ykv_buf_free(sealed);
        ykv_buf_free(opened);
        ykv_close(s);
    }
}

fn apdus_outside_txn(s: *mut YkvSession) -> usize {
    unsafe { session(s) }.unwrap().session.card().outside
}

fn keys(s: *mut YkvSession) -> (u64, Vec<(u64, u64, bool)>) {
    let k = call(|b| unsafe { ykv_known_keys(s, b) }).unwrap();
    let v = json::parse(&k).unwrap();
    let rev = v.get("revision").unwrap().as_u64().unwrap();
    let list = v.get("keys").unwrap().as_array().iter().map(|k| {
        (
            k.get("serial").unwrap().as_u64().unwrap(),
            k.get("last_synced_rev").unwrap().as_u64().unwrap(),
            matches!(k.get("this"), Some(json::Value::Bool(true))),
        )
    }).collect();
    (rev, list)
}

#[test]
fn clone_sync_and_transactions() {
    let (_r, s) = demo();
    let b = CString::new(cards::enable_mocks(1, false, 0).unwrap()).unwrap();
    unsafe {
        let label = CString::new("Spare").unwrap();
        assert_eq!(ykv_clone_to(s, b.as_ptr(), label.as_ptr()), YkvStatus::Ok);
        assert_eq!(ykv_clone_to(s, b.as_ptr(), label.as_ptr()), YkvStatus::Invalid);
        let (rev, k) = keys(s);
        assert_eq!(k.len(), 2);
        assert!(k.iter().all(|(_, synced, _)| *synced >= rev), "{rev} {k:?}");

        // A save on the main key leaves the backup behind; a sync catches it up.
        let j = br#"{"kind":3,"name":"New","fields":[{"kind":9,"value":"x"}]}"#;
        let mut id = 0;
        assert_eq!(ykv_upsert_entry(s, j.as_ptr(), j.len(), &mut id), YkvStatus::Ok);
        let (rev, k) = keys(s);
        assert!(k.iter().any(|(_, synced, this)| !this && *synced < rev));
        let mut rel = 9;
        assert_eq!(ykv_sync_with(s, b.as_ptr(), &mut rel), YkvStatus::Ok);
        assert_eq!(rel, 1);
        let (rev, k) = keys(s);
        assert!(k.iter().all(|(_, synced, _)| *synced >= rev), "{rev} {k:?}");
        assert_eq!(ykv_sync_with(s, b.as_ptr(), &mut rel), YkvStatus::Ok);
        assert_eq!(rel, 0);
        assert_eq!(ykv_sync_with(s, _r.as_ptr(), &mut rel), YkvStatus::Invalid);

        // The backup opens on its own with the same passphrase.
        let mut s2 = std::ptr::null_mut();
        assert_eq!(ykv_open(b.as_ptr(), &mut s2), YkvStatus::Ok);
        let p = cards::DEMO_PASSPHRASE;
        assert_eq!(ykv_unlock(s2, p.as_ptr(), p.len()), YkvStatus::Ok);
        let all = call(|o| ykv_list_entries(s2, std::ptr::null(), o)).unwrap();
        assert_eq!(json::parse(&all).unwrap().as_array().len(), 5);
        assert_eq!(apdus_outside_txn(s2), 0);
        ykv_close(s2);

        assert_eq!(apdus_outside_txn(s), 0, "every APDU runs inside a PC/SC transaction");
        ykv_close(s);
    }
}

#[test]
fn ykv_and_plaintext_round_trips() {
    let (_r, s) = demo();
    let p = cards::DEMO_PASSPHRASE;
    unsafe {
        let (mut file, mut rk) = (YkvBuf::EMPTY, YkvBuf::EMPTY);
        assert_eq!(ykv_export_ykv(s, false, &mut file, &mut rk), YkvStatus::Ok);
        assert!(rk.ptr.is_null());
        let mut n = 0;
        assert_eq!(ykv_import_ykv(s, file.ptr, file.len, p.as_ptr(), p.len(), std::ptr::null(), &mut n), YkvStatus::Ok);
        assert_eq!(n, 4);
        assert_eq!(ykv_import_ykv(s, file.ptr, file.len, b"wrong pass".as_ptr(), 10, std::ptr::null(), &mut n), YkvStatus::WrongPin);
        ykv_buf_free(file);

        let (mut file, mut rk) = (YkvBuf::EMPTY, YkvBuf::EMPTY);
        assert_eq!(ykv_export_ykv(s, true, &mut file, &mut rk), YkvStatus::Ok);
        let key = CString::new(take(rk)).unwrap();
        assert_eq!(ykv_import_ykv(s, file.ptr, file.len, p.as_ptr(), p.len(), key.as_ptr(), &mut n), YkvStatus::Ok);
        ykv_buf_free(file);

        let csv = call(|b| ykv_export_plain(s, 0, b)).unwrap();
        assert!(csv.starts_with("name,url,username,password") && csv.contains("correct-horse-battery"), "{csv}");
        let json_text = call(|b| ykv_export_plain(s, 1, b)).unwrap();
        assert!(json_text.contains("99p-v1"));
        assert_eq!(call(|b| ykv_export_plain(s, 7, b)), Err(YkvStatus::Invalid));

        // CSV import adds new items; JSON import of our own export replaces by id.
        let one = "name,url,username,password\nShop,https://shop.example/login,me,pw1\nbroken\n";
        let r = call(|b| ykv_import_plain(s, one.as_ptr(), one.len(), b)).unwrap();
        assert!(r.starts_with("{\"imported\":1,\"skipped\":["), "{r}");
        let r = call(|b| ykv_import_plain(s, json_text.as_ptr(), json_text.len(), b)).unwrap();
        assert!(r.starts_with("{\"imported\":4,"), "{r}");
        let all = call(|b| ykv_list_entries(s, std::ptr::null(), b)).unwrap();
        assert_eq!(json::parse(&all).unwrap().as_array().len(), 5);
        assert_eq!(apdus_outside_txn(s), 0);
        ykv_close(s);
    }
}

#[test]
fn identity_fields_are_listed_in_clear() {
    let (_r, s) = demo();
    unsafe {
        let j = br#"{"kind":5,"name":"Me","hosts":[],"fields":[{"kind":32,"value":"Ada"},{"kind":34,"value":"ada@example.com"},{"kind":40,"value":"GB"}]}"#;
        let mut id = 0;
        assert_eq!(ykv_upsert_entry(s, j.as_ptr(), j.len(), &mut id), YkvStatus::Ok);
        let all = call(|b| ykv_list_entries(s, std::ptr::null(), b)).unwrap();
        assert!(all.contains(r#""kind":5,"name":"Me""#), "{all}");
        assert!(all.contains(r#"{"kind":34,"secret":false,"label":null,"value":"ada@example.com"}"#), "{all}");
        let bad = br#"{"kind":6,"name":"x","fields":[]}"#;
        assert_eq!(ykv_upsert_entry(s, bad.as_ptr(), bad.len(), &mut id), YkvStatus::Invalid);
        ykv_close(s);
    }
}

/// A save is many APDUs; listing cards from another thread must not slip in
/// between them (it once turned Capacity into Format about 1 run in 10).
#[test]
fn listing_does_not_interleave_with_a_save() {
    let (_r, s) = demo();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lister = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = call(|b| unsafe { ykv_list_cards(b) });
            }
        })
    };
    let mut id = 0;
    let mut last = YkvStatus::Ok;
    for _ in 0..20 {
        let o = generator::PasswordOptions { length: 128, symbols: false, ..Default::default() };
        let big: String = (0..24).map(|_| generator::password(&o).unwrap()).collect();
        let j = format!(r#"{{"kind":3,"name":"n","fields":[{{"kind":9,"value":"{big}"}}]}}"#);
        last = unsafe { ykv_upsert_entry(s, j.as_ptr(), j.len(), &mut id) };
        if last != YkvStatus::Ok {
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    lister.join().unwrap();
    assert_eq!(last, YkvStatus::Capacity);
    unsafe { ykv_close(s) };
}
