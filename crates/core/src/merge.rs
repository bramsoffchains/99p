//! Clone divergence detection and merge (SPEC §9.4).

use crate::codec::encode_entry;
use crate::model::{Entry, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Same head: nothing to do.
    InSync,
    /// Their head is one of our ancestors: they need our version.
    TheyAreStale,
    /// Our head is one of their ancestors: adopt theirs.
    WeAreStale,
    /// Both changed independently: merge.
    Diverged,
}

pub fn relation(ours: &Vault, theirs: &Vault) -> Relation {
    if ours.head == theirs.head {
        Relation::InSync
    } else if ours.ancestors.contains(&theirs.head) {
        Relation::TheyAreStale
    } else if theirs.ancestors.contains(&ours.head) {
        Relation::WeAreStale
    } else {
        Relation::Diverged
    }
}

/// `a` wins over `b`: newer `updated_at`, ties broken by the greater encoding.
fn wins(a: &Entry, b: &Entry) -> bool {
    (a.updated_at, encode_entry(a)) > (b.updated_at, encode_entry(b))
}

/// Merges `theirs` into a copy of `ours`. The result keeps our head and puts
/// their head first in `ancestors`, so the next save lists both old heads.
pub fn merge(ours: &Vault, theirs: &Vault) -> Vault {
    let mut out = ours.clone();
    for t in &theirs.entries {
        match out.entries.iter_mut().find(|e| e.id == t.id) {
            Some(e) => {
                if wins(t, e) {
                    *e = t.clone();
                }
            }
            None => out.entries.push(t.clone()),
        }
    }
    for k in &theirs.known_keys {
        match out.known_keys.iter_mut().find(|x| x.serial == k.serial) {
            Some(x) => {
                if k.added_at > x.added_at {
                    *x = k.clone();
                }
            }
            None => out.known_keys.push(k.clone()),
        }
    }
    out.ancestors.retain(|h| *h != theirs.head);
    out.ancestors.insert(0, theirs.head);
    out.ancestors.truncate(32);
    out
}
