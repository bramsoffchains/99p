#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};

use ykvault_core::crypto;
use ykvault_core::mock::MockYubiKey;
use ykvault_core::model::{Entry, EntryKind, Field, FieldKind};
use ykvault_core::session::{ProvisionOptions, Session};

pub const PASS: &[u8] = b"correct horse battery staple";

static NOW: AtomicU32 = AtomicU32::new(1_750_000_000);

pub fn clock() -> u32 {
    NOW.load(Ordering::SeqCst)
}

pub fn tick(secs: u32) {
    NOW.fetch_add(secs, Ordering::SeqCst);
}

pub fn opts() -> ProvisionOptions {
    ProvisionOptions {
        label: "Primary".into(),
        current_mgmt_key: None,
    }
}

pub fn provision(card: MockYubiKey) -> Session<MockYubiKey> {
    let mut s = Session::provision(card, PASS, &opts()).expect("provision");
    s.set_clock(clock);
    s
}

pub fn unlock(card: MockYubiKey) -> Session<MockYubiKey> {
    let mut s = Session::open(card).expect("open");
    s.set_clock(clock);
    s.unlock(PASS).expect("unlock");
    s
}

pub fn random_string(len: usize) -> String {
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    let b: [u8; 64] = crypto::random_bytes().unwrap();
    b.iter()
        .take(len)
        .map(|x| CS[*x as usize % CS.len()] as char)
        .collect()
}

pub fn login(name: &str, host: &str, user: &str) -> Entry {
    let mut e = Entry::new(EntryKind::Login, name).unwrap();
    e.hosts.push(host.into());
    e.fields
        .push(Field::new(FieldKind::Username, user.as_bytes()));
    e.fields.push(Field::new(
        FieldKind::Password,
        random_string(20).as_bytes(),
    ));
    e
}

/// Comparable view of a vault's live content.
pub fn snapshot(s: &Session<MockYubiKey>) -> Vec<(u64, String, Vec<Vec<u8>>)> {
    let mut v: Vec<_> = s
        .entries()
        .unwrap()
        .map(|e| {
            (
                e.id,
                e.name.clone(),
                e.fields.iter().map(|f| f.value.clone()).collect(),
            )
        })
        .collect();
    v.sort();
    v
}
