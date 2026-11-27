use core::fmt;

/// Every fallible core operation returns this error. Messages never contain
/// secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The card was removed or the transport failed mid-command.
    CardRemoved,
    /// The card answered with an unexpected status word.
    Card { sw: u16, context: &'static str },
    /// A PIV object or slot was not found (SW 6A82).
    NotFound,
    /// The card's NVM is full (SW 6A84) or the vault exceeds the layout.
    Capacity { needed: usize, available: usize },
    /// Management key authentication failed.
    ManagementKey,
    /// Wrong passphrase, wrong card, or tampered ciphertext. Deliberately
    /// indistinguishable.
    Decrypt,
    /// Neither bank holds a complete, verifiable vault.
    NoValidVault,
    /// Malformed binary data.
    Format(&'static str),
    /// The vault was written by a newer, incompatible schema/container.
    Unsupported(&'static str),
    /// Invalid argument from the caller.
    Invalid(&'static str),
    /// OS randomness failure.
    Rng,
    /// The session is locked.
    Locked,
    /// The passphrase-derived PIN was refused; `tries_left` before the PIN blocks.
    WrongPin { tries_left: u8 },
    /// Too many wrong passphrases: the PIN is blocked until the PUK unblocks it.
    PinBlocked,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CardRemoved => write!(f, "YubiKey removed or not responding"),
            Error::Card { sw, context } => write!(f, "card error {sw:04X} during {context}"),
            Error::NotFound => write!(f, "object not found on card"),
            Error::Capacity { needed, available } => {
                write!(
                    f,
                    "vault needs {needed} bytes but only {available} are available"
                )
            }
            Error::ManagementKey => write!(f, "PIV management key authentication failed"),
            Error::Decrypt => write!(f, "wrong passphrase, wrong YubiKey, or corrupted vault"),
            Error::NoValidVault => write!(f, "no valid vault found on this YubiKey"),
            Error::Format(m) => write!(f, "malformed data: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported format: {m}"),
            Error::Invalid(m) => write!(f, "invalid argument: {m}"),
            Error::Rng => write!(f, "system random number generator failed"),
            Error::Locked => write!(f, "vault is locked"),
            Error::WrongPin { tries_left } => {
                write!(f, "wrong passphrase, {tries_left} tries left on this YubiKey")
            }
            Error::PinBlocked => write!(f, "too many wrong passphrases: the YubiKey PIN is blocked"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
