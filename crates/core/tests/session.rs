mod common;
use common::*;

use ykvault_core::Error;
use ykvault_core::merge::Relation;
use ykvault_core::mock::MockYubiKey;
use ykvault_core::model::{Entry, EntryKind, Field, FieldKind};
use ykvault_core::piv;
use ykvault_core::session::{ProvisionOptions, Session};

#[test]
fn provision_unlock_roundtrip() {
    let mut s = provision(MockYubiKey::new(1001));
    let mut e = login("GitHub", "github.com", "alice");
    e.fields.push(Field {
        kind: FieldKind::CustomText,
        label: Some("Recovery".into()),
        value: b"abc".to_vec(),
    });
    // Unknown TLV items survive a save and load.
    e.extra.push((0x7E, b"from the future".to_vec()));
    let id = s.upsert(e).unwrap();
    let before = snapshot(&s);
    let card = s.into_card();
    assert_eq!(
        card.touches, 0,
        "provisioning and saving never need a touch"
    );

    let s = unlock(card);
    assert_eq!(snapshot(&s), before);
    let e = s.entry(id).unwrap().unwrap();
    assert_eq!(e.extra, vec![(0x7E, b"from the future".to_vec())]);
    assert_eq!(e.fields[2].label.as_deref(), Some("Recovery"));
    assert_eq!(s.card().touches, 1, "one touch per unlock");
    // The card's management key was rotated away from the default.
    assert_ne!(s.card().mgmt_key().1, &piv::DEFAULT_MGMT_KEY[..]);
    assert_eq!(s.card().mgmt_key().0, piv::ALG_AES256);
    assert!(s.vault().unwrap().known_keys[0].mgmt_key_prev.is_none());
}

#[test]
fn wrong_passphrase_and_no_touch() {
    let card = provision(MockYubiKey::new(1002)).into_card();
    let mut s = Session::open(card).unwrap();
    assert_eq!(s.pin_tries_left(), Ok(255));
    // A wrong passphrase gives a wrong PIN: refused before any touch.
    assert_eq!(s.unlock(b"wrong"), Err(Error::WrongPin { tries_left: 254 }));
    assert_eq!(s.card().touches, 0);
    assert_eq!(s.pin_tries_left(), Ok(254));
    assert!(!s.is_unlocked());
    s.card_mut().touch = false;
    assert!(matches!(
        s.unlock(PASS),
        Err(Error::Card { sw: 0x6982, .. })
    ));
    s.card_mut().touch = true;
    s.unlock(PASS).unwrap();
    assert_eq!(s.pin_tries_left(), Ok(255), "a correct PIN resets the counter");
}

#[test]
fn pin_policy_always_needs_the_pin_for_every_ecdh() {
    let s = provision(MockYubiKey::new(1020));
    let pk = s.vault().unwrap().known_keys[0].piv_pubkey.clone();
    let mut card = s.into_card();
    // Touching alone no longer releases Z: ECDH without the PIN is refused.
    let mut p = piv::Piv::new(&mut card);
    p.select().unwrap();
    assert!(matches!(
        p.ecdh(0x82, &pk),
        Err(Error::Card { sw: 0x6982, .. })
    ));
    // The PIN and PUK are no longer the factory defaults.
    assert_eq!(p.pin_info(piv::REF_PIN).unwrap(), Some((false, 255)));
    // The PUK is blocked: nothing can reset the PIN.
    assert_eq!(p.pin_info(piv::REF_PUK).unwrap(), Some((true, 0)));
    assert_eq!(card.touches, 0);
}

#[test]
fn the_255th_wrong_passphrase_bricks_the_vault() {
    let s = provision(MockYubiKey::new(1021));
    let mut s = Session::open(s.into_card()).unwrap();
    for _ in 0..254 {
        assert!(matches!(s.unlock(b"guess"), Err(Error::WrongPin { .. })));
    }
    assert_eq!(s.unlock(b"guess"), Err(Error::PinBlocked));
    assert_eq!(s.unlock(PASS), Err(Error::PinBlocked), "even the right one");
    assert_eq!(s.pin_tries_left(), Ok(0));
    assert_eq!(s.card().touches, 0);
}

#[test]
fn provisioning_refuses_a_card_with_a_custom_pin() {
    let mut card = MockYubiKey::new(1022);
    card.set_custom_pin(b"654321");
    assert!(matches!(
        Session::provision(card, PASS, &opts()),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn delete_leaves_tombstone_and_lock_wipes() {
    let mut s = provision(MockYubiKey::new(1003));
    let id = s.upsert(login("a", "a.com", "u")).unwrap();
    s.delete(id).unwrap();
    assert!(s.entry(id).unwrap().is_none());
    let t = s
        .vault()
        .unwrap()
        .entries
        .iter()
        .find(|e| e.id == id)
        .unwrap();
    assert!(t.deleted && t.name.is_empty() && t.fields.is_empty());
    s.lock();
    assert_eq!(s.vault().err(), Some(Error::Locked));
}

#[test]
fn unplug_locks_the_session() {
    let mut s = provision(MockYubiKey::new(1004));
    s.card_mut().unplug();
    assert_eq!(
        s.upsert(login("a", "a.com", "u")).err(),
        Some(Error::CardRemoved)
    );
    assert!(!s.is_unlocked());
}

#[test]
fn custom_management_key_is_never_overwritten_blindly() {
    let custom = [7u8; 24];
    let mut card = MockYubiKey::new(1005);
    card.set_custom_mgmt_key(piv::ALG_3DES, &custom);
    let r = Session::provision(card.clone(), PASS, &opts());
    assert_eq!(r.err(), Some(Error::ManagementKey));
    let wrong = ProvisionOptions {
        current_mgmt_key: Some(vec![9u8; 24]),
        ..opts()
    };
    assert_eq!(
        Session::provision(card.clone(), PASS, &wrong).err(),
        Some(Error::ManagementKey)
    );
    let right = ProvisionOptions {
        current_mgmt_key: Some(custom.to_vec()),
        ..opts()
    };
    let s = Session::provision(card, PASS, &right).unwrap();
    assert_ne!(s.card().mgmt_key().1, &custom[..]);
}

#[test]
fn firmware_variants() {
    // 5.7: AES-192 factory default, rotated to AES-256.
    let s = provision(MockYubiKey::with_firmware(1006, [5, 7, 2]));
    assert_eq!(s.card().mgmt_key().0, piv::ALG_AES256);
    // 5.2: no metadata command, 3DES default and 3DES replacement.
    let s = provision(MockYubiKey::with_firmware(1007, [5, 2, 7]));
    assert_eq!(s.card().mgmt_key().0, piv::ALG_3DES);
    let s = unlock(s.into_card());
    assert!(s.is_unlocked());
}

#[test]
fn occupied_slot_is_refused() {
    let card = provision(MockYubiKey::new(1008)).into_card();
    let r = Session::provision(card, PASS, &opts());
    assert!(matches!(
        r.err(),
        Some(Error::Invalid(_)) | Some(Error::ManagementKey)
    ));
}

#[test]
fn capacity_limit_and_rollback() {
    let mut s = provision(MockYubiKey::new(1009));
    let mut n = 0;
    loop {
        let mut e = Entry::new(EntryKind::Note, "blob").unwrap();
        e.fields
            .push(Field::new(FieldKind::Note, random_string(60).as_bytes()));
        let noise: [u8; 64] = ykvault_core::crypto::random_bytes().unwrap();
        e.fields.push(Field::new(FieldKind::CustomSecret, &noise));
        match s.upsert(e) {
            Ok(_) => n += 1,
            Err(Error::Capacity { needed, available }) => {
                assert!(needed > available);
                break;
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(
        s.entries().unwrap().count(),
        n,
        "failed save is rolled back in RAM"
    );
    let cap = s.capacity().unwrap();
    assert!(cap.used <= cap.capacity && cap.capacity == 23_552);
    let before = snapshot(&s);
    let s = unlock(s.into_card());
    assert_eq!(snapshot(&s), before);
}

#[test]
fn single_bank_mode_holds_more() {
    let mut s = provision(MockYubiKey::new(1010));
    let mut settings = s.vault().unwrap().settings.clone();
    settings.single_bank = true;
    s.update_settings(settings).unwrap();
    assert_eq!(s.capacity().unwrap().capacity, 48_128);
    for _ in 0..40 {
        let mut e = Entry::new(EntryKind::Note, "blob").unwrap();
        let noise: [u8; 700] = std::array::from_fn(|i| {
            ykvault_core::crypto::random_bytes::<1>().unwrap()[0] ^ i as u8
        });
        e.fields.push(Field::new(FieldKind::CustomSecret, &noise));
        s.upsert(e).unwrap();
    }
    assert!(s.capacity().unwrap().used > 23_552);
    let before = snapshot(&s);
    let s = unlock(s.into_card());
    assert_eq!(snapshot(&s), before);
}

#[test]
fn card_nvm_full_reports_capacity() {
    let mut card = MockYubiKey::new(1011);
    card.nvm_other = 51_200 - 500;
    let r = Session::provision(card, PASS, &opts());
    assert!(matches!(r.err(), Some(Error::Capacity { .. })));
}

#[test]
fn rollback_relabel_is_rejected() {
    use ykvault_core::container::{self, BANK_A_TAG, BANK_B_TAG, MANIFEST_TAG, Manifest};
    let mut s = provision(MockYubiKey::new(1012));
    s.upsert(login("old", "old.com", "u")).unwrap();
    // Remember the bank image with "old" in it, then save twice more.
    let m = Manifest::decode(&s.card().objects[&MANIFEST_TAG]).unwrap();
    let base = if m.active_bank == 0 {
        BANK_A_TAG
    } else {
        BANK_B_TAG
    };
    let mut old: Vec<u8> = (0..m.chunk_count as u32)
        .flat_map(|i| s.card().objects[&(base + i)].clone())
        .collect();
    s.upsert(login("new", "new.com", "u")).unwrap();
    s.upsert(login("newer", "newer.com", "u")).unwrap();
    let mut card = s.into_card();
    // Relabel the old image with a higher revision and a fresh digest.
    let rev = Manifest::decode(&card.objects[&MANIFEST_TAG])
        .unwrap()
        .revision
        + 10;
    old[24..32].copy_from_slice(&rev.to_le_bytes());
    let digest = ykvault_core::crypto::sha256(&[&old[..184], &old[216..]]);
    old[184..216].copy_from_slice(&digest);
    let h = container::parse_image(&old).unwrap();
    for (i, c) in container::chunks(&old).enumerate() {
        card.objects.insert(base + i as u32, c.to_vec());
    }
    let m = Manifest {
        revision: rev,
        digest: h.digest,
        active_bank: m.active_bank,
        ..m
    };
    card.objects.insert(MANIFEST_TAG, m.encode());
    let mut s = Session::open(card).unwrap();
    assert_eq!(s.unlock(PASS), Err(Error::Decrypt));
}

#[test]
fn management_key_crash_points() {
    let fresh = MockYubiKey::new(1013);
    for n in 0.. {
        let mut card = fresh.clone();
        card.unplug_after(n);
        match Session::provision(&mut card, PASS, &opts()) {
            Ok(_) => {
                assert!(n > 20, "provisioning should take more than 20 APDUs");
                break;
            }
            Err(Error::CardRemoved) => {}
            Err(e) => panic!("crash point {n}: {e:?}"),
        }
        card.replug();
        let mut s = Session::open(&mut card).unwrap();
        if s.has_vault().unwrap() {
            s.set_clock(clock);
            s.unlock(PASS)
                .unwrap_or_else(|e| panic!("crash point {n}: unlock {e:?}"));
            s.upsert(login("after", "a.com", "u"))
                .unwrap_or_else(|e| panic!("crash point {n}: save {e:?}"));
            let kk = s.vault().unwrap().known_keys[0].clone();
            assert!(kk.mgmt_key_prev.is_none());
            drop(s);
            assert_eq!(card.mgmt_key().1, &kk.mgmt_key[..], "crash point {n}");
        } else {
            drop(s);
            assert_eq!(
                card.mgmt_key().1,
                &piv::DEFAULT_MGMT_KEY[..],
                "crash point {n}: key lost"
            );
        }
    }
}

#[test]
fn clone_diverge_merge() {
    let mut a = provision(MockYubiKey::new(2001));
    let shared = a.upsert(login("Shared", "shared.com", "me")).unwrap();
    let mut b_card = MockYubiKey::new(2002);
    a.clone_to(&mut b_card, "Backup", None).unwrap();
    assert_eq!(a.vault().unwrap().known_keys.len(), 2);
    assert_eq!(
        a.clone_to(&mut b_card, "Again", None).err(),
        Some(Error::Invalid("this YubiKey is already a clone; use sync"))
    );
    let a_card = a.into_card();
    assert_ne!(
        b_card.mgmt_key().1,
        a_card.mgmt_key().1,
        "each card has its own management key"
    );
    let mut b = unlock(b_card.clone());
    assert!(b.entry(shared).unwrap().is_some());
    assert_eq!(b.vault().unwrap().known_keys.len(), 2);

    // In sync right after cloning.
    let mut a = unlock(a_card);
    assert_eq!(a.sync_with(&mut b_card).unwrap(), Relation::InSync);

    // Edit both sides independently.
    tick(10);
    let only_a = a.upsert(login("Only A", "a.com", "a")).unwrap();
    let mut e = a.entry(shared).unwrap().unwrap().clone();
    e.name = "Shared (A edit)".into();
    a.upsert(e).unwrap();
    tick(10);
    let only_b = b.upsert(login("Only B", "b.com", "b")).unwrap();
    let mut e = b.entry(shared).unwrap().unwrap().clone();
    e.name = "Shared (B edit, newer)".into();
    b.upsert(e).unwrap();
    let del = b.upsert(login("Doomed", "d.com", "d")).unwrap();
    b.delete(del).unwrap();
    b_card = b.into_card();

    assert_eq!(a.sync_with(&mut b_card).unwrap(), Relation::Diverged);
    assert!(a.entry(only_a).unwrap().is_some() && a.entry(only_b).unwrap().is_some());
    assert_eq!(
        a.entry(shared).unwrap().unwrap().name,
        "Shared (B edit, newer)"
    );
    assert!(a.entry(del).unwrap().is_none());
    let merged = snapshot(&a);
    assert_eq!(a.sync_with(&mut b_card).unwrap(), Relation::InSync);
    let b = unlock(b_card.clone());
    assert_eq!(snapshot(&b), merged);
    let a_card = a.into_card();

    // A stale backup is updated; a stale primary adopts the backup.
    let mut a = unlock(a_card);
    a.upsert(login("Later", "l.com", "l")).unwrap();
    assert_eq!(a.sync_with(&mut b_card).unwrap(), Relation::TheyAreStale);
    let mut b = unlock(b_card.clone());
    assert_eq!(snapshot(&b), snapshot(&a));
    b.upsert(login("On B", "onb.com", "x")).unwrap();
    let mut b_card = b.into_card();
    assert_eq!(a.sync_with(&mut b_card).unwrap(), Relation::WeAreStale);
    let b = unlock(b_card);
    assert_eq!(snapshot(&a), snapshot(&b));
}
