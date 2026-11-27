//! ykvault-core: the offline heart of 99passwords.
//!
//! Formats and crypto are specified in `docs/SPEC.md`. Layers, bottom up:
//! `tlv`/`codec` (schema), `payload` (compression and padding), `crypto`,
//! `container` (manifest and bank image), `piv` (APDU client over
//! `SmartCard`), `store` (A/B banks), `merge`, and `session` (the API used by
//! the FFI and CLI). `mock` emulates a YubiKey 5 at the APDU level.
//!
//! Hard rules (see `docs/SPEC.md` §1): no async runtime, no networking, no TLS,
//! no proc-macros, no C build scripts.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod base32;
pub mod card;
pub mod codec;
pub mod container;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod host;
pub mod interop;
pub mod json;
pub mod merge;
#[cfg(feature = "mock")]
pub mod mock;
pub mod model;
pub mod otpauth;
pub mod payload;
pub mod piv;
pub mod secret;
pub mod session;
pub mod store;
pub mod tlv;
pub mod totp;
pub mod ykv;

pub use card::SmartCard;
pub use error::{Error, Result};
pub use secret::SecretBytes;
pub use session::Session;
