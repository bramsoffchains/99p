//! How many items really fit on a key, saving one item at a time like a user
//! would, until the core refuses with `Error::Capacity`.
//! `cargo test --release --test capacity -- --ignored --nocapture` prints a table.

mod common;
use common::*;

use ykvault_core::mock::MockYubiKey;
use ykvault_core::model::{Entry, EntryKind, Field, FieldKind};
use ykvault_core::Error;

const SITES: &[&str] = &[
    "github.com",
    "google.com",
    "amazon.com",
    "netflix.com",
    "apple.com",
    "microsoft.com",
    "linkedin.com",
    "reddit.com",
    "dropbox.com",
    "paypal.com",
    "ebay.com",
    "spotify.com",
    "slack.com",
    "notion.so",
    "figma.com",
    "atlassian.net",
    "stripe.com",
    "booking.com",
    "airbnb.com",
    "ikea.com",
];
const USERS: &[&str] = &[
    "alice@example.com",
    "alice",
    "a.lovelace@example.org",
    "admin",
];
const WORDS: &[&str] = &[
    "wifi", "router", "password", "door", "code", "garage", "alarm", "office", "account", "number",
    "recovery", "backup", "phone", "the", "is", "and", "for", "my", "bank", "pin", "server", "ssh",
    "key", "license",
];

fn rnd(n: usize) -> usize {
    let b: [u8; 4] = ykvault_core::crypto::random_bytes().unwrap();
    u32::from_le_bytes(b) as usize % n
}

fn host(i: usize) -> String {
    let site = SITES[i % SITES.len()];
    if i < SITES.len() {
        site.into()
    } else {
        format!("app{}.{site}", i / SITES.len())
    }
}

fn totp() -> Field {
    let mut v = vec![0u8, 0u8];
    v.extend_from_slice(&ykvault_core::crypto::random_bytes::<20>().unwrap());
    Field::new(FieldKind::Totp, &v)
}

fn login_with_totp(i: usize, totp_every: usize) -> Entry {
    let site = SITES[i % SITES.len()];
    let mut e = login(
        &format!("{} {i}", site.split('.').next().unwrap()),
        &host(i),
        USERS[i % USERS.len()],
    );
    if i % totp_every == 0 {
        e.fields.push(totp());
    }
    e
}

fn note(i: usize) -> Entry {
    let mut e = Entry::new(EntryKind::Note, &format!("Note {i}")).unwrap();
    let text: Vec<&str> = (0..50).map(|_| WORDS[rnd(WORDS.len())]).collect();
    let mut s = text.join(" ");
    s.push(' ');
    s.push_str(&random_string(16));
    e.fields.push(Field::new(FieldKind::Note, s.as_bytes()));
    e
}

fn card(i: usize) -> Entry {
    let mut e = Entry::new(EntryKind::Card, &format!("Card {i}")).unwrap();
    let num: String = (0..16).map(|_| char::from(b'0' + rnd(10) as u8)).collect();
    let cvv: String = (0..3).map(|_| char::from(b'0' + rnd(10) as u8)).collect();
    e.fields
        .push(Field::new(FieldKind::CardHolder, b"ALICE EXAMPLE"));
    e.fields
        .push(Field::new(FieldKind::CardNumber, num.as_bytes()));
    e.fields.push(Field::new(FieldKind::CardExpiry, b"2029-04"));
    e.fields
        .push(Field::new(FieldKind::CardCvv, cvv.as_bytes()));
    e
}

fn api_key(i: usize) -> Entry {
    let mut e = Entry::new(EntryKind::Custom, &format!("API key {i}")).unwrap();
    let mut f = Field::new(FieldKind::CustomSecret, random_string(40).as_bytes());
    f.label = Some("token".into());
    e.fields.push(f);
    e
}

/// Saves items one by one until the key is full. Returns the count that fit.
fn fill(single_bank: bool, nvm_other: usize, make: fn(usize) -> Entry) -> usize {
    let mut card = MockYubiKey::new(7000);
    card.nvm_other = nvm_other;
    let mut s = provision(card);
    if single_bank {
        let mut st = s.vault().unwrap().settings.clone();
        st.single_bank = true;
        s.update_settings(st).unwrap();
    }
    let mut n = 0;
    loop {
        tick(60);
        match s.upsert(make(n)) {
            Ok(_) => n += 1,
            Err(Error::Capacity { .. }) => break,
            Err(e) => panic!("after {n} items: {e:?}"),
        }
    }
    // Everything that was saved reads back from the card.
    let r = unlock(s.into_card());
    assert_eq!(r.entries().unwrap().count(), n);
    n
}

fn logins(i: usize) -> Entry {
    login_with_totp(i, 5)
}
fn logins_all_totp(i: usize) -> Entry {
    login_with_totp(i, 1)
}
/// Per 20 items: 16 logins (1 in 5 with TOTP), 2 notes, 1 card, 1 API key.
fn mixed(i: usize) -> Entry {
    match i % 20 {
        16 | 17 => note(i),
        18 => card(i),
        19 => api_key(i),
        _ => login_with_totp(i, 5),
    }
}

#[test]
#[ignore = "slow; run with --release -- --ignored --nocapture"]
fn how_many_fit() {
    let cases: [(&str, fn(usize) -> Entry); 4] = [
        ("logins, 1 in 5 with TOTP", logins),
        ("logins, all with TOTP", logins_all_totp),
        ("mixed: logins, notes, cards, API keys", mixed),
        ("notes only (~300 chars)", note),
    ];
    println!("\n| Content | A/B (tear-safe) | Single-bank |");
    println!("|---|---|---|");
    for (name, make) in cases {
        let ab = fill(false, 0, make);
        let single = fill(true, 0, make);
        println!("| {name} | {ab} | {single} |");
    }
    // A key that already holds other certificates (e.g. 3 × ~1.5 KB).
    let ab = fill(false, 4_500, mixed);
    let single = fill(true, 4_500, mixed);
    println!("| mixed, with 4.5 KB of other certificates on the key | {ab} | {single} |");
}

/// A single-bank save that runs out of NVM partway (the card answers 6A84
/// after some chunks are written) must leave the previous vault readable.
#[test]
fn single_bank_full_nvm_keeps_vault() {
    let n = fill(true, 44_000, logins);
    assert!(n > 0);
}
