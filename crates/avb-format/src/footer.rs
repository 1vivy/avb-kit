//! The fixed 64-byte `AVBf` footer at the end of a footered partition.

use crate::framing::{Error, Result, u32_at, u64_at};

/// Size of the `AVBf` footer.
pub const FOOTER_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Footer {
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
}

/// Parse the exact 64 bytes at `image_size - 64`. Original metadata need not
/// be usable: an empty region with valid footer geometry can be grafted.
pub fn parse_footer(bytes: &[u8], image_size: u64) -> Result<Footer> {
    if bytes.len() != FOOTER_SIZE {
        return Err(Error::Truncated);
    }
    if &bytes[..4] != b"AVBf" {
        return Err(Error::Magic);
    }
    if u32_at(bytes, 4)? != 1 || u32_at(bytes, 8)? != 0 {
        return Err(Error::Version);
    }
    if bytes[36..].iter().any(|byte| *byte != 0) {
        return Err(Error::Reserved);
    }
    let footer = Footer {
        original_image_size: u64_at(bytes, 12)?,
        vbmeta_offset: u64_at(bytes, 20)?,
        vbmeta_size: u64_at(bytes, 28)?,
    };
    let limit = image_size
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or(Error::FooterGeometry)?;
    if footer.original_image_size > footer.vbmeta_offset
        || footer
            .vbmeta_offset
            .checked_add(footer.vbmeta_size)
            .ok_or(Error::Overflow)?
            > limit
    {
        return Err(Error::FooterGeometry);
    }
    Ok(footer)
}

/// Compute a serialized footer from explicit geometry (validated by planning).
pub fn replacement_footer(footer: Footer) -> [u8; FOOTER_SIZE] {
    let mut bytes = [0; FOOTER_SIZE];
    bytes[..4].copy_from_slice(b"AVBf");
    bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
    bytes[12..20].copy_from_slice(&footer.original_image_size.to_be_bytes());
    bytes[20..28].copy_from_slice(&footer.vbmeta_offset.to_be_bytes());
    bytes[28..36].copy_from_slice(&footer.vbmeta_size.to_be_bytes());
    bytes
}
