//! CSPRNG password and passphrase generator. Uniform choices by rejection
//! sampling over `getrandom`, so there is no modulo bias.

use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&*+-./:;=?@^_~()[]{}";
/// Removed when `avoid_ambiguous` is set.
const AMBIGUOUS: &str = "0O1lI|5S2Z8B";

/// Uniform random index in `0..n` (n > 0).
pub fn random_below(n: u32) -> Result<u32> {
    assert!(n > 0);
    // Accept only x below the largest multiple of n that fits in 2^32.
    let limit = (1u64 << 32) - (1u64 << 32) % n as u64;
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).map_err(|_| Error::Rng)?;
        let x = u32::from_le_bytes(b);
        if (x as u64) < limit {
            return Ok(x % n);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

fn classes(o: &PasswordOptions) -> Vec<Vec<char>> {
    [
        (o.lowercase, LOWER),
        (o.uppercase, UPPER),
        (o.digits, DIGITS),
        (o.symbols, SYMBOLS),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !(o.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect()
}

/// A random password that contains at least one character of every selected
/// class. Whole candidates are rejected until that holds, which keeps the
/// result uniform over all valid passwords.
pub fn password(o: &PasswordOptions) -> Result<String> {
    let cls = classes(o);
    if cls.is_empty() {
        return Err(Error::Invalid("select at least one character class"));
    }
    if o.length < cls.len().max(4) || o.length > 128 {
        return Err(Error::Invalid("password length must be 4-128"));
    }
    let all: Vec<char> = cls.concat();
    loop {
        let mut pw = String::with_capacity(o.length);
        for _ in 0..o.length {
            pw.push(all[random_below(all.len() as u32)? as usize]);
        }
        if cls.iter().all(|set| pw.chars().any(|c| set.contains(&c))) {
            return Ok(pw);
        }
        zeroize::Zeroize::zeroize(&mut pw);
    }
}

/// Approximate entropy in bits: `length × log2(alphabet size)`.
pub fn password_entropy(o: &PasswordOptions) -> f64 {
    let n: usize = classes(o).iter().map(Vec::len).sum();
    if n == 0 {
        return 0.0;
    }
    o.length as f64 * (n as f64).log2()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    /// Appends one random digit to one random word.
    pub add_digit: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            add_digit: false,
        }
    }
}

#[cfg(feature = "eff-wordlist")]
pub fn eff_wordlist() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        include_str!("../data/eff_large_wordlist.txt")
            .lines()
            .filter_map(|l| l.split('\t').nth(1))
            .collect()
    })
}

/// A random passphrase from `wordlist` (the EFF large list by default).
pub fn passphrase_from(list: &[&str], o: &PassphraseOptions) -> Result<String> {
    if !(3..=20).contains(&o.words) {
        return Err(Error::Invalid("passphrase must have 3-20 words"));
    }
    if list.len() < 2 {
        return Err(Error::Invalid("wordlist too small"));
    }
    let digit_at = if o.add_digit {
        Some(random_below(o.words as u32)? as usize)
    } else {
        None
    };
    let mut out = String::new();
    for i in 0..o.words {
        if i > 0 {
            out.push_str(&o.separator);
        }
        let w = list[random_below(list.len() as u32)? as usize];
        let mut chars = w.chars();
        if let (true, Some(first)) = (o.capitalize, chars.next()) {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        } else {
            out.push_str(w);
        }
        if digit_at == Some(i) {
            out.push(char::from(b'0' + random_below(10)? as u8));
        }
    }
    Ok(out)
}

#[cfg(feature = "eff-wordlist")]
pub fn passphrase(o: &PassphraseOptions) -> Result<String> {
    passphrase_from(eff_wordlist(), o)
}

/// Entropy in bits, assuming the attacker knows the wordlist and options.
pub fn passphrase_entropy(list_len: usize, o: &PassphraseOptions) -> f64 {
    let mut bits = o.words as f64 * (list_len as f64).log2();
    if o.add_digit {
        bits += 10f64.log2() + (o.words as f64).log2();
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_below_is_in_range_and_covers() {
        let mut seen = [0u32; 7];
        for _ in 0..7000 {
            seen[random_below(7).unwrap() as usize] += 1;
        }
        assert!(seen.iter().all(|&c| c > 800), "{seen:?}");
        assert_eq!(random_below(1).unwrap(), 0);
    }

    #[test]
    fn password_respects_options() {
        let o = PasswordOptions {
            length: 12,
            symbols: false,
            avoid_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..200 {
            let p = password(&o).unwrap();
            assert_eq!(p.chars().count(), 12);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c)));
        }
        let pin = PasswordOptions {
            length: 6,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..Default::default()
        };
        assert!(password(&pin).unwrap().chars().all(|c| c.is_ascii_digit()));
        assert_ne!(
            password(&Default::default()).unwrap(),
            password(&Default::default()).unwrap()
        );
    }

    #[test]
    fn password_rejects_bad_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(password(&none).is_err());
        assert!(password(&PasswordOptions {
            length: 3,
            ..Default::default()
        })
        .is_err());
        assert!(password(&PasswordOptions {
            length: 129,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn entropy_estimates() {
        // 26+26+10+24 = 86 symbols, 20 chars ≈ 128.5 bits.
        let e = password_entropy(&PasswordOptions::default());
        assert!((e - 20.0 * 86f64.log2()).abs() < 1e-9);
        let e = passphrase_entropy(7776, &PassphraseOptions::default());
        assert!((e - 64.62).abs() < 0.01, "{e}");
    }

    #[test]
    fn eff_wordlist_is_complete() {
        let l = eff_wordlist();
        assert_eq!(l.len(), 7776);
        assert_eq!((l[0], l[7775]), ("abacus", "zoom"));
        let mut s = l.to_vec();
        s.sort();
        s.dedup();
        assert_eq!(s.len(), 7776);
    }

    #[test]
    fn passphrase_shape() {
        let o = PassphraseOptions {
            words: 6,
            separator: " ".into(),
            capitalize: true,
            add_digit: true,
        };
        let p = passphrase(&o).unwrap();
        let words: Vec<&str> = p.split(' ').collect();
        assert_eq!(words.len(), 6);
        assert!(words
            .iter()
            .all(|w| w.chars().next().unwrap().is_uppercase()));
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        assert!(passphrase(&PassphraseOptions {
            words: 2,
            ..Default::default()
        })
        .is_err());
    }
}
