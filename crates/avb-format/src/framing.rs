//! Structural framing admission for one standalone `AVB0` image.

use core::fmt;

/// Size of the `AVB0` vbmeta header.
pub(crate) const HEADER_SIZE: usize = 256;

/// Result of the structural framing checks.
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Magic,
    Version,
    Reserved,
    ReleaseString,
    Overflow,
    BlockAlignment,
    MetadataBounds,
    DescriptorBounds,
    TrailingData,
    FooterGeometry,
    ReplacementDoesNotFit,
    ReadBounds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated AVB structure",
            Self::Magic => "invalid AVB magic",
            Self::Version => "unsupported AVB version",
            Self::Reserved => "nonzero reserved AVB bytes",
            Self::ReleaseString => "vbmeta release string lacks terminating NUL",
            Self::Overflow => "AVB offset arithmetic overflow",
            Self::BlockAlignment => "AVB block size is not 64-byte aligned",
            Self::MetadataBounds => "vbmeta field lies outside its block",
            Self::DescriptorBounds => "invalid descriptor extent",
            Self::TrailingData => "nonzero bytes after standalone vbmeta",
            Self::FooterGeometry => "footer metadata overlaps payload or end footer",
            Self::ReplacementDoesNotFit => "replacement metadata does not fit before footer",
            Self::ReadBounds => "logical read lies outside image",
        })
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vbmeta {
    size: u64,
}

impl Vbmeta {
    pub fn size(self) -> u64 {
        self.size
    }
}

pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or(Error::Truncated)?;
    Ok(u64::from_be_bytes(
        value.try_into().map_err(|_| Error::Truncated)?,
    ))
}

pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes(
        value.try_into().map_err(|_| Error::Truncated)?,
    ))
}

fn bounded(offset: u64, size: u64, limit: u64) -> Result<()> {
    if offset.checked_add(size).ok_or(Error::Overflow)? > limit {
        return Err(Error::MetadataBounds);
    }
    Ok(())
}

/// Validate structural bounds of standalone AVB0 metadata. Zero file padding
/// is accepted but excluded from `size()`. Cryptographic admission stays in AVB.
pub fn validate_vbmeta(bytes: &[u8]) -> Result<Vbmeta> {
    if bytes.len() < HEADER_SIZE {
        return Err(Error::Truncated);
    }
    if &bytes[..4] != b"AVB0" {
        return Err(Error::Magic);
    }
    if u32_at(bytes, 4)? != 1 || u32_at(bytes, 8)? > 4 {
        return Err(Error::Version);
    }
    if bytes[176..256].iter().any(|byte| *byte != 0) {
        return Err(Error::Reserved);
    }
    if bytes[175] != 0 {
        return Err(Error::ReleaseString);
    }
    let auth = u64_at(bytes, 12)?;
    let aux = u64_at(bytes, 20)?;
    if auth & 63 != 0 || aux & 63 != 0 {
        return Err(Error::BlockAlignment);
    }
    let aux_start = (HEADER_SIZE as u64)
        .checked_add(auth)
        .ok_or(Error::Overflow)?;
    let size = aux_start.checked_add(aux).ok_or(Error::Overflow)?;
    let end = usize::try_from(size).map_err(|_| Error::Overflow)?;
    if end > bytes.len() {
        return Err(Error::Truncated);
    }
    for (offset, limit) in [(32, auth), (48, auth), (64, aux), (80, aux), (96, aux)] {
        bounded(u64_at(bytes, offset)?, u64_at(bytes, offset + 8)?, limit)?;
    }
    let descriptors_offset = u64_at(bytes, 96)?;
    let descriptors_size = u64_at(bytes, 104)?;
    let start = usize::try_from(aux_start + descriptors_offset).map_err(|_| Error::Overflow)?;
    let stop = usize::try_from(aux_start + descriptors_offset + descriptors_size)
        .map_err(|_| Error::Overflow)?;
    let mut cursor = start;
    while cursor < stop {
        if stop - cursor < 16 {
            return Err(Error::DescriptorBounds);
        }
        let following = u64_at(bytes, cursor + 8)?;
        if following & 7 != 0 {
            return Err(Error::DescriptorBounds);
        }
        let length = following.checked_add(16).ok_or(Error::Overflow)?;
        let length = usize::try_from(length).map_err(|_| Error::Overflow)?;
        cursor = cursor.checked_add(length).ok_or(Error::Overflow)?;
        if cursor > stop {
            return Err(Error::DescriptorBounds);
        }
    }
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(Error::TrailingData);
    }
    Ok(Vbmeta { size })
}
