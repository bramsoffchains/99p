//! SPEC §9.3 tear matrix: every PUT DATA of a save × every tear mode must
//! leave exactly the old or exactly the new vault.

mod common;
use common::*;

use p99_core::Error;
use p99_core::mock::{ALL_TEARS, MockYubiKey};
use p99_core::model::{Entry, EntryKind, Field, FieldKind};

/// A vault of about 10 KB of ciphertext, so a save spans several chunks.
fn big_vault(single_bank: bool, extra_saves: usize) -> MockYubiKey {
    let mut s = provision(MockYubiKey::new(3001));
    if single_bank {
        let mut st = s.vault().unwrap().settings.clone();
        st.single_bank = true;
        s.update_settings(st).unwrap();
    }
    let mut e = Entry::new(EntryKind::Note, "noise").unwrap();
    let noise: Vec<u8> = (0..9000)
        .map(|_| p99_core::crypto::random_bytes::<1>().unwrap()[0])
        .collect();
    e.fields.push(Field::new(FieldKind::CustomSecret, &noise));
    s.upsert(e).unwrap();
    for i in 0..extra_saves {
        s.upsert(login(&format!("pre {i}"), "pre.com", "u"))
            .unwrap();
    }
    s.into_card()
}

fn run_matrix(single_bank: bool, extra_saves: usize) -> usize {
    let base = big_vault(single_bank, extra_saves);
    let old = snapshot(&unlock(base.clone()));
    let mut trials = 0;
    for mode in ALL_TEARS {
        for k in 0.. {
            let mut s = unlock(base.clone());
            s.card_mut().arm_tear(k, mode);
            // The edit grows the vault so the new image has more chunks.
            let mut e = login("new entry", "new.com", "me");
            let noise: Vec<u8> = (0..4000).map(|i| (i * 7 + k) as u8).collect();
            e.fields.push(Field::new(FieldKind::CustomSecret, &noise));
            let mut expected_new = None;
            let r = s.upsert(e);
            if r.is_ok() {
                expected_new = Some(snapshot(&s));
            }
            let mut card = s.into_card();
            let fired = card.tear_fired();
            card.replug();
            let mut s = p99_core::Session::open(card).unwrap();
            match s.unlock(PASS) {
                Ok(()) => {
                    let got = snapshot(&s);
                    let is_new = got.len() == old.len() + 1;
                    assert!(got == old || is_new, "{mode:?} at put {k}: mixed vault");
                    if let Some(n) = expected_new {
                        assert_eq!(got, n);
                    }
                    // The card stays writable after recovery.
                    s.upsert(login("after", "after.com", "u")).unwrap();
                    p99_core::Session::open(s.into_card())
                        .unwrap()
                        .unlock(PASS)
                        .unwrap();
                }
                Err(Error::NoValidVault) if single_bank => {}
                Err(e) => panic!("{mode:?} at put {k}: {e:?}"),
            }
            trials += 1;
            if !fired {
                assert!(r.is_ok());
                break;
            }
        }
    }
    trials
}

#[test]
fn tear_matrix_from_bank_a() {
    let n = run_matrix(false, 0);
    assert!(
        n >= 4 * 6,
        "expected several PUT DATA per save, got {n} trials"
    );
}

#[test]
fn tear_matrix_from_bank_b() {
    run_matrix(false, 1);
}

#[test]
fn single_bank_tears_are_detected_not_mixed() {
    run_matrix(true, 0);
}

#[test]
fn torn_manifest_falls_back_to_scan() {
    use p99_core::container::MANIFEST_TAG;
    let mut card = big_vault(false, 0);
    let before = snapshot(&unlock(card.clone()));
    card.objects.insert(MANIFEST_TAG, vec![0xAB; 40]);
    let s = unlock(card.clone());
    assert_eq!(snapshot(&s), before);
    card.objects.remove(&MANIFEST_TAG);
    let mut s = unlock(card);
    assert_eq!(snapshot(&s), before);
    assert_eq!(s.card().touches, 1, "no extra touch for recovery");
    // The next save rewrites the manifest.
    s.upsert(login("x", "x.com", "x")).unwrap();
    assert!(s.card().objects.contains_key(&MANIFEST_TAG));
}
