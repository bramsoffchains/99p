//! 500-entry compression benchmark (`cargo test --test benchmark -- --nocapture`
//! prints the numbers). Realistic logins: 20-character random passwords, one
//! in five with TOTP.

mod common;
use common::*;

use ykvault_core::codec;
use ykvault_core::container;
use ykvault_core::mock::MockYubiKey;
use ykvault_core::model::{Entry, Field, FieldKind, Vault};
use ykvault_core::payload;

const SITES: &[&str] = &[
    "github.com",
    "google.com",
    "amazon.com",
    "netflix.com",
    "apple.com",
    "microsoft.com",
    "linkedin.com",
    "twitter.com",
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
];
const USERS: &[&str] = &[
    "alice@example.com",
    "alice",
    "a.lovelace@example.org",
    "admin",
];

fn entries(n: usize) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            let site = SITES[i % SITES.len()];
            let host = if i < SITES.len() {
                site.to_string()
            } else {
                format!("app{}.{site}", i / SITES.len())
            };
            let mut e = login(
                &format!("{} {i}", site.split('.').next().unwrap()),
                &host,
                USERS[i % USERS.len()],
            );
            if i % 5 == 0 {
                let mut v = vec![0u8, 0u8];
                v.extend_from_slice(&ykvault_core::crypto::random_bytes::<20>().unwrap());
                e.fields.push(Field::new(FieldKind::Totp, &v));
            }
            e.created_at = 1_700_000_000 + i as u32;
            e.updated_at = e.created_at;
            e
        })
        .collect()
}

fn ct_len(base: &Vault, entries: &[Entry]) -> (usize, usize, usize) {
    let mut v = base.clone();
    v.entries = entries.to_vec();
    let body = codec::encode_vault(&v);
    let pt = payload::pack(&body, true);
    (
        body.len(),
        u32::from_le_bytes(pt[4..8].try_into().unwrap()) as usize,
        pt.len() + 16,
    )
}

#[test]
fn five_hundred_entries() {
    let mut s = provision(MockYubiKey::new(4001));
    let base = s.vault().unwrap().clone();
    let all = entries(500);
    let (body, deflated, ct) = ct_len(&base, &all);
    let ab = container::max_ct_len(false);
    let single = container::max_ct_len(true);
    // Largest count that fits the default, tear-safe A/B layout.
    let fit_ab = (0..=500)
        .rev()
        .step_by(10)
        .find(|&n| ct_len(&base, &all[..n]).2 <= ab)
        .unwrap();
    println!("500 entries: body {body} B, deflated {deflated} B, ciphertext {ct} B");
    println!("A/B bank holds {ab} B (about {fit_ab} such entries); single-bank holds {single} B");
    assert!(
        fit_ab >= 400,
        "A/B mode should hold at least 400 realistic logins"
    );
    assert!(ct <= single, "500 entries must fit single-bank mode");

    // Real saves: A/B if it fits (imports share one timestamp, which
    // compresses better), otherwise the explicit single-bank opt-in.
    match s.upsert_many(all.clone()) {
        Ok(()) => println!("500 imported entries saved in A/B mode"),
        Err(ykvault_core::Error::Capacity { .. }) => {
            let mut st = base.settings.clone();
            st.single_bank = true;
            s.update_settings(st).unwrap();
            s.upsert_many(all).unwrap();
            println!("500 imported entries saved in single-bank mode");
        }
        Err(e) => panic!("{e:?}"),
    }
    let r = unlock(s.into_card());
    assert_eq!(r.entries().unwrap().count(), 500);
}
