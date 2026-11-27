//! A/B bank storage on the card: save (SPEC §9.2) and load with fallback (§9.3).

use crate::card::SmartCard;
use crate::container::{self, BankHeader, CHUNKS_PER_BANK, MANIFEST_TAG, Manifest, OBJ_MAX};
use crate::error::{Error, Result};
use crate::piv::Piv;

/// A verified bank image read from the card.
pub struct Loaded {
    pub header: BankHeader,
    pub image: Vec<u8>,
    pub bank: u8,
}

fn chunks_in_layout(single: bool) -> usize {
    CHUNKS_PER_BANK * if single { 2 } else { 1 }
}

/// Header of chunk 0 of `bank`, if it parses. Reads one object.
pub fn read_bank_header<C: SmartCard>(piv: &mut Piv<C>, bank: u8) -> Result<Option<BankHeader>> {
    let Some(c0) = piv.get_data(container::chunk_tag(bank, 0))? else {
        return Ok(None);
    };
    Ok(BankHeader::decode(&c0)
        .ok()
        .filter(|h| !(bank == 1 && h.single_bank)))
}

/// Reads and verifies a full bank image. `None` if it is missing or invalid.
pub fn read_bank<C: SmartCard>(piv: &mut Piv<C>, bank: u8) -> Result<Option<Loaded>> {
    let Some(mut image) = piv.get_data(container::chunk_tag(bank, 0))? else {
        return Ok(None);
    };
    let Ok(h) = BankHeader::decode(&image) else {
        return Ok(None);
    };
    if bank == 1 && h.single_bank {
        return Ok(None);
    }
    let len = h.image_len();
    let n = len.div_ceil(OBJ_MAX);
    for i in 1..n {
        match piv.get_data(container::chunk_tag(bank, i))? {
            Some(c) => image.extend_from_slice(&c),
            None => return Ok(None),
        }
    }
    if image.len() != len {
        return Ok(None);
    }
    match container::parse_image(&image) {
        Ok(header) => Ok(Some(Loaded {
            header,
            image,
            bank,
        })),
        Err(_) => Ok(None),
    }
}

pub fn read_manifest<C: SmartCard>(piv: &mut Piv<C>) -> Result<Option<Manifest>> {
    Ok(piv
        .get_data(MANIFEST_TAG)?
        .and_then(|b| Manifest::decode(&b).ok()))
}

/// SPEC §9.3. Needs no PIN, touch or key.
pub fn load<C: SmartCard>(piv: &mut Piv<C>) -> Result<Loaded> {
    let m = read_manifest(piv)?;
    if let Some(m) = &m {
        if let Some(l) = read_bank(piv, m.active_bank)? {
            let h = &l.header;
            if h.uuid == m.uuid && h.revision == m.revision && h.digest == m.digest {
                return Ok(l);
            }
        }
    }
    let mut best: Option<Loaded> = None;
    for bank in [0u8, 1] {
        let Some(l) = read_bank(piv, bank)? else {
            continue;
        };
        if m.as_ref().is_some_and(|m| m.uuid != l.header.uuid) {
            continue;
        }
        let better = match &best {
            None => true,
            Some(b) => {
                l.header.revision > b.header.revision
                    || (l.header.revision == b.header.revision
                        && m.as_ref().is_some_and(|m| m.active_bank == bank))
            }
        };
        if better {
            best = Some(l);
        }
    }
    best.ok_or(Error::NoValidVault)
}

/// Writes `image` to `target` and flips the manifest (SPEC §9.2 steps 3 to 6).
/// The management key must already be authenticated.
pub fn write<C: SmartCard>(piv: &mut Piv<C>, image: &[u8], target: u8) -> Result<Manifest> {
    let h = container::parse_image(image)?;
    let parts: Vec<&[u8]> = container::chunks(image).collect();
    let tag = |i| container::chunk_tag(target, i);
    for (i, c) in parts.iter().enumerate() {
        piv.put_data(tag(i), c)?;
    }
    for i in parts.len()..chunks_in_layout(h.single_bank) {
        if piv.get_data(tag(i))?.is_some() {
            piv.put_data(tag(i), &[])?;
        }
    }
    let read_back = |piv: &mut Piv<C>| -> Result<bool> {
        let mut got = Vec::with_capacity(image.len());
        for i in 0..parts.len() {
            got.extend_from_slice(&piv.get_data(tag(i))?.unwrap_or_default());
        }
        Ok(got == image)
    };
    if !read_back(piv)? && !read_back(piv)? {
        return Err(Error::Format("bank verification failed after write"));
    }
    let m = Manifest {
        single_bank: h.single_bank,
        active_bank: target,
        uuid: h.uuid,
        revision: h.revision,
        image_len: image.len() as u32,
        chunk_count: parts.len() as u8,
        digest: h.digest,
    };
    let mb = m.encode();
    piv.put_data(MANIFEST_TAG, &mb)?;
    if piv.get_data(MANIFEST_TAG)?.as_deref() != Some(&mb[..]) {
        return Err(Error::Format("manifest verification failed after write"));
    }
    Ok(m)
}
