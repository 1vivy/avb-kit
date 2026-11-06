//! Footer-located metadata extraction without allocation.

use crate::footer::{FOOTER_SIZE, parse_footer};
use crate::framing::Error;
use crate::vbmeta::{Defect, VBMETA_MAX_SIZE, exact_metadata};
use core::fmt;

/// Why a footer-located metadata extent could not be recovered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtractError<E> {
    /// The partition or its footer is unusable.
    Malformed(Defect),
    /// The caller's backing read failed.
    Read(E),
    /// The footer declares more metadata than [`VBMETA_MAX_SIZE`].
    TooLarge { size: u64 },
    /// The caller's output buffer is smaller than the declared extent.
    BufferTooSmall { size: u64 },
}

impl<E> From<Defect> for ExtractError<E> {
    fn from(defect: Defect) -> Self {
        Self::Malformed(defect)
    }
}

impl<E: fmt::Display> fmt::Display for ExtractError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(defect) => write!(f, "{defect}"),
            Self::Read(error) => write!(f, "backing read failed: {error}"),
            Self::TooLarge { size } => write!(
                f,
                "footer declares {size} metadata bytes, above the {VBMETA_MAX_SIZE}-byte limit"
            ),
            Self::BufferTooSmall { size } => write!(
                f,
                "output buffer is smaller than the declared {size}-byte metadata extent"
            ),
        }
    }
}

/// The exact metadata extent a footered partition's footer declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbmdExtent {
    pub offset: u64,
    pub size: u64,
}

/// Read the final 64 bytes, validate the footer and return its metadata extent.
///
/// This is the same two-step libavb performs, with the same 64 KiB bound on the
/// declared size. `read_at(offset, out)` must fill `out` exactly.
pub fn vbmd_extent<E>(
    image_size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<VbmdExtent, ExtractError<E>> {
    let footer_offset = image_size
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or(ExtractError::Malformed(Defect::Truncated))?;
    let mut footer = [0u8; FOOTER_SIZE];
    read_at(footer_offset, &mut footer).map_err(ExtractError::Read)?;
    let parsed = parse_footer(&footer, image_size)
        .map_err(|error| ExtractError::Malformed(Defect::Framing(error)))?;
    if parsed.vbmeta_size > VBMETA_MAX_SIZE {
        return Err(ExtractError::TooLarge {
            size: parsed.vbmeta_size,
        });
    }
    Ok(VbmdExtent {
        offset: parsed.vbmeta_offset,
        size: parsed.vbmeta_size,
    })
}

/// Extract footer-located metadata into `out` and validate its exact extent.
///
/// `out` must hold at least the declared metadata size. The returned slice is
/// `out[..size]`; bytes after the exact extent are not considered.
pub fn extract_vbmd<E>(
    image_size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    out: &mut [u8],
) -> Result<&[u8], ExtractError<E>> {
    let extent = vbmd_extent(image_size, &mut read_at)?;
    let size = usize::try_from(extent.size)
        .map_err(|_| ExtractError::Malformed(Defect::Framing(Error::Overflow)))?;
    let metadata = out
        .get_mut(..size)
        .ok_or(ExtractError::BufferTooSmall { size: extent.size })?;
    read_at(extent.offset, &mut *metadata).map_err(ExtractError::Read)?;
    exact_metadata(metadata).map_err(ExtractError::Malformed)
}
