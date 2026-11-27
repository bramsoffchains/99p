//! macOS PC/SC transport (workstream C, SPEC §7.5).
//!
//! Links `PCSC.framework` directly through hand-declared externs (no `pcsc`
//! crate, no build script) and provides:
//! - [`yubikey_readers`]: reader enumeration filtered to YubiKeys,
//! - [`PcscCard`]: `ykvault_core::SmartCard` over T=1 in shared mode, with
//!   [`PcscCard::transaction`] around multi-APDU operations,
//! - [`RemovalWatcher`]: a thread on `SCardGetStatusChange` that calls back
//!   once when the YubiKey goes away.
//!
//! The pure helpers (reader-list parsing, filtering, status classification)
//! build and are tested on every platform; the FFI part is macOS only.

#![forbid(unsafe_op_in_unsafe_fn)]
// The status helpers are only called by the macOS module (and tests).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod util;

pub use util::{PcscError, is_yubikey_reader, parse_reader_list};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod sys;

#[cfg(target_os = "macos")]
pub use macos::{PcscCard, RemovalWatcher, yubikey_readers};
