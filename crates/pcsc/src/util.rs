//! Platform-independent helpers, unit-tested on Linux as well.

use core::fmt;

/// PC/SC return codes we act on (`LONG` values from `winscard.h`).
pub(crate) mod code {
    pub const SUCCESS: u32 = 0;
    pub const E_CANCELLED: u32 = 0x8010_0002;
    pub const E_INSUFFICIENT_BUFFER: u32 = 0x8010_0008;
    pub const E_TIMEOUT: u32 = 0x8010_000A;
    pub const E_NO_SERVICE: u32 = 0x8010_001D;
    pub const E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
}

/// Reader state bits (`SCARD_STATE_*`).
pub(crate) mod state {
    pub const UNAWARE: u32 = 0x0000;
    pub const CHANGED: u32 = 0x0002;
    pub const UNKNOWN: u32 = 0x0004;
    pub const UNAVAILABLE: u32 = 0x0008;
    pub const EMPTY: u32 = 0x0010;
    pub const PRESENT: u32 = 0x0020;
}

/// Errors from reader discovery and connection. Once a card is connected,
/// `SmartCard::transmit` reports every transport failure as
/// `p99_core::Error::CardRemoved`, as the trait requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcscError {
    /// A PC/SC call failed with this return code.
    Scard { op: &'static str, code: u32 },
    /// No reader with a YubiKey whose PIV application answers SELECT.
    NoYubiKey,
}

impl fmt::Display for PcscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcscError::Scard { op, code } => write!(f, "{op} failed: 0x{code:08X}"),
            PcscError::NoYubiKey => write!(f, "no YubiKey with PIV found"),
        }
    }
}

impl std::error::Error for PcscError {}

impl From<PcscError> for p99_core::Error {
    fn from(_: PcscError) -> Self {
        p99_core::Error::CardRemoved
    }
}

/// Splits a PC/SC multi-string (`"a\0b\0\0"`) into reader names.
pub fn parse_reader_list(buf: &[u8]) -> Vec<String> {
    buf.split(|&b| b == 0)
        .take_while(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// SPEC §7.5 reader filter: the name contains "YubiKey".
pub fn is_yubikey_reader(name: &str) -> bool {
    name.contains("YubiKey")
}

/// What the removal watcher does after one `SCardGetStatusChange`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Nothing happened; wait again with this as the current state.
    Wait(u32),
    /// The card or its reader is gone (or PC/SC failed: lock to be safe).
    Removed,
}

pub(crate) fn classify(rv: u32, event_state: u32, current: u32) -> Step {
    match rv {
        code::SUCCESS => {
            let gone = state::UNKNOWN | state::UNAVAILABLE | state::EMPTY;
            if event_state & gone != 0 || event_state & state::PRESENT == 0 {
                Step::Removed
            } else {
                Step::Wait(event_state & !state::CHANGED)
            }
        }
        code::E_TIMEOUT | code::E_CANCELLED => Step::Wait(current),
        // Unknown reader, service stopped, or anything else: fail safe.
        _ => Step::Removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multistring() {
        let buf = b"Yubico YubiKey OTP+FIDO+CCID\0Other Reader\0\0garbage";
        assert_eq!(
            parse_reader_list(buf),
            ["Yubico YubiKey OTP+FIDO+CCID", "Other Reader"]
        );
        assert!(parse_reader_list(b"\0").is_empty());
        assert!(parse_reader_list(b"").is_empty());
        assert_eq!(parse_reader_list(b"one"), ["one"]);
    }

    #[test]
    fn filters_yubikeys() {
        assert!(is_yubikey_reader("Yubico YubiKey OTP+FIDO+CCID"));
        assert!(is_yubikey_reader("Yubico YubiKey CCID 01"));
        assert!(!is_yubikey_reader("Gemalto PC Twin Reader"));
    }

    #[test]
    fn classifies_status_changes() {
        let present = state::PRESENT | state::CHANGED | 0x0001_0000;
        assert_eq!(
            classify(0, present, 0),
            Step::Wait(state::PRESENT | 0x0001_0000)
        );
        assert_eq!(classify(0, state::EMPTY | state::CHANGED, 0), Step::Removed);
        assert_eq!(classify(0, state::UNAVAILABLE, 0), Step::Removed);
        assert_eq!(classify(0, state::UNKNOWN, 0), Step::Removed);
        assert_eq!(classify(0, state::UNAWARE, 0), Step::Removed);
        assert_eq!(classify(code::E_TIMEOUT, 0, 7), Step::Wait(7));
        assert_eq!(classify(code::E_CANCELLED, 0, 7), Step::Wait(7));
        assert_eq!(classify(0x8010_0009, 0, 7), Step::Removed);
        assert_eq!(classify(0x8010_001E, 0, 7), Step::Removed);
    }

    #[test]
    fn maps_to_core_error() {
        let e: p99_core::Error = PcscError::NoYubiKey.into();
        assert_eq!(e, p99_core::Error::CardRemoved);
    }
}
