//! `99p` CLI: small hardware admin commands for a real YubiKey.
//!
//!   99p info              serial, firmware, PIN/PUK tries, slot 0x82 policy
//!   99p piv-reset SERIAL  blocks PIN and PUK, then resets the PIV
//!                             application. Wipes the vault. SERIAL confirms.

#[cfg(target_os = "macos")]
fn main() {
    use p99_core::piv::{self, Piv};
    use p99_core::{Error, Result};
    use p99_pcsc::PcscCard;

    fn run(args: &[String]) -> Result<()> {
        let card = PcscCard::open(None).map_err(|_| Error::CardRemoved)?;
        let mut piv = Piv::new(card);
        piv.select()?;
        let serial = piv.serial()?;
        let fw = piv.version()?;
        match args.first().map(String::as_str) {
            Some("info") => {
                println!("serial {serial}, firmware {}.{}.{}", fw[0], fw[1], fw[2]);
                for (name, r) in [("PIN", piv::REF_PIN), ("PUK", piv::REF_PUK)] {
                    if let Some((default, left)) = piv.pin_info(r)? {
                        println!("{name}: {left} tries left, default: {default}");
                    }
                }
                match piv.metadata(0x82)? {
                    Some(md) => {
                        let pol = md.iter().find(|(t, _)| *t == 0x02).map(|(_, v)| v.clone());
                        println!("slot 0x82: key present, policy (pin, touch) = {pol:02X?}");
                    }
                    None => println!("slot 0x82: empty"),
                }
                Ok(())
            }
            Some("piv-reset") if args.get(1) == Some(&serial.to_string()) => {
                // A reset only works once both PIN and PUK are blocked.
                let bad = b"\x00\x00\x00\x00\x00\x00\x00\x00";
                loop {
                    match piv.verify_pin(bad) {
                        Err(Error::WrongPin { .. }) => {}
                        Err(Error::PinBlocked) => break,
                        r => return r.and(Err(Error::Invalid("PIN accepted"))),
                    }
                }
                loop {
                    match piv.unblock_pin(bad, bad) {
                        Err(Error::WrongPin { .. }) => {}
                        Err(Error::PinBlocked) => break,
                        r => return r.and(Err(Error::Invalid("PUK accepted"))),
                    }
                }
                piv.reset()?;
                println!("PIV application of YubiKey {serial} reset");
                Ok(())
            }
            Some("piv-reset") => {
                eprintln!("type the serial ({serial}) to confirm: 99p piv-reset {serial}");
                std::process::exit(2)
            }
            _ => {
                eprintln!("usage: 99p info | 99p piv-reset SERIAL");
                std::process::exit(2)
            }
        }
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("99p: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("99p: needs macOS (PC/SC)");
    std::process::exit(2);
}
