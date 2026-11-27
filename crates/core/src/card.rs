//! The only boundary between the core and real hardware.
//!
//! The PIV APDU client (`piv` module, workstream A) is written against this
//! trait. `MockYubiKey` (tests) and the macOS PC/SC transport
//! (`ykvault-pcsc`, workstream C) both implement it, so every byte the core
//! sends to a real YubiKey is also exercised by the automated tests.

use crate::error::Result;

pub trait SmartCard {
    /// Sends one short or extended command APDU and returns the full response
    /// (`data || SW1 || SW2`). Implementations do not interpret status words,
    /// do not chain and do not issue GET RESPONSE; the PIV client does that.
    ///
    /// Must return `Error::CardRemoved` if the card left the reader, including
    /// when that happens mid-command.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;

    /// Stable identifier of the reader, used to pair removal events with a
    /// session. Not shown to users.
    fn reader_id(&self) -> &str;
}

/// Lets a caller lend a card (`&mut card`) to a `Piv` client or a session
/// without giving up ownership, e.g. to write a backup key during a clone.
impl<T: SmartCard + ?Sized> SmartCard for &mut T {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).transmit(apdu)
    }

    fn reader_id(&self) -> &str {
        (**self).reader_id()
    }
}
