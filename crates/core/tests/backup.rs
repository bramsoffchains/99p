mod common;
use common::*;

use p99_core::Error;
use p99_core::mock::MockYubiKey;
use p99_core::piv::Piv;
use p99_core::backup;

#[test]
fn export_and_import() {
    let mut a = provision(MockYubiKey::new(5001));
    a.upsert(login("GitHub", "github.com", "me")).unwrap();
    let mut backup = MockYubiKey::new(5002);
    a.clone_to(&mut backup, "Backup", None).unwrap();
    let (file, rk) = a.export_backup(true).unwrap();
    let rk = rk.unwrap();
    assert_eq!(rk.len(), 9 * 4 + 8);
    let want = snapshot(&a);

    // Recovery key + passphrase, sloppy typing tolerated.
    let typed = rk.to_lowercase().replace('-', " ").replace('0', "o");
    let v = backup::open_with_recovery_key(&file, PASS, &typed).unwrap();
    assert_eq!(v.entries.len(), want.len());
    assert_eq!(
        backup::open_with_recovery_key(&file, b"wrong", &rk).err(),
        Some(Error::Decrypt)
    );
    let mut bad = rk.clone().into_bytes();
    bad[0] = if bad[0] == b'A' { b'B' } else { b'A' };
    assert!(backup::open_with_recovery_key(&file, PASS, std::str::from_utf8(&bad).unwrap()).is_err());

    // Either card + passphrase.
    let v = backup::open_with_card(&mut Piv::new(&mut backup), &file, PASS).unwrap();
    assert_eq!(v.entries.len(), want.len());
    let v2 = a.open_backup(&file, PASS).unwrap();
    assert_eq!(v2.vault_secret, v.vault_secret);
    // A card that is not a recipient cannot open it.
    let mut stranger = provision(MockYubiKey::new(5003)).into_card();
    assert_eq!(
        backup::open_with_card(&mut Piv::new(&mut stranger), &file, PASS).err(),
        Some(Error::Decrypt)
    );

    // Tampering is detected.
    let mut t = file.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert_eq!(
        backup::open_with_recovery_key(&t, PASS, &rk).err(),
        Some(Error::Decrypt)
    );

    // Import into another vault merges entries.
    let mut other = provision(MockYubiKey::new(5004));
    other.upsert(login("Mine", "mine.com", "x")).unwrap();
    other.import_merge(&v).unwrap();
    assert_eq!(other.entries().unwrap().count(), want.len() + 1);
    assert_eq!(other.vault().unwrap().known_keys.len(), 1);
}
