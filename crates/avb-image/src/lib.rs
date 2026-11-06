//! Placement and graft-image primitives: **where** OEM metadata goes inside a
//! footered partition, and the full graft image that results.
//!
//! This crate is the shared half of two consumers that used to keep their own
//! copies of the same arithmetic:
//!
//! * `ablwrap/crates/avbview` plans a read view for a live partition whose
//!   payload extent it reads from the payload header ([`Extent::Header`]);
//! * `ablwrap/crates/pack` plans a replacement for a stock image whose payload
//!   extent its own footer already declares ([`Extent::Footer`]).
//!
//! Both reduce to one [`plan`]: a [`WritePlan`] of plain data (metadata extent,
//! footer extent, image size, payload extent used and the evidence for it). All
//! reads happen through the caller's `read_at` closure and all writes through
//! [`apply`]'s `write_at` closure or [`materialize`]; **this crate never opens a
//! file, touches a device, or holds a partition-sized buffer it did not receive**.
//!
//! # The three placements
//!
//! * [`Placement::KeepOriginal`] replaces the metadata **where it already is**
//!   and is exactly [`avb_graft::plan_graft`]: the stock 64-byte footer locates
//!   the metadata, a footerless image is refused, and metadata that does not fit
//!   below the footer is refused.
//! * [`Placement::Tail`] moves the metadata into the partition's tail padding,
//!   block aligned, just below the final 64-byte footer — what a partition's own
//!   geometry allows when the stock placement is unusable or the partition is
//!   freshly initialized.
//! * [`Placement::At(offset)`] puts it at an explicit block-aligned offset.
//!
//! A payload extent is never invented. [`Extent`] states where the claim comes
//! from, and the plan reports in [`WritePlan::evidence`] which one it actually
//! used — including [`Evidence::ZeroTail`], where nothing was known and the
//! whole replaced region had to be zero before anything could be placed there.
//!
//! # What a plan guarantees
//!
//! * the image size never changes, and nothing outside the metadata extent and
//!   the last 64 bytes moves: [`materialize`] copies the original and writes
//!   exactly those two extents, and [`apply`] writes only those two;
//! * the payload the evidence names is never overlapped
//!   ([`Error::PayloadOverlap`]);
//! * a region that is not already padding is never claimed
//!   ([`Error::PlacementOccupied`] for a stock footer, [`Error::TailNotUnused`]
//!   for an unknown extent);
//! * the result is structurally admitted by `avb-graft` before it is returned,
//!   so [`WritePlan::graft`] cannot fail for a plan this crate produced.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// Block granularity for synthesized footered-metadata placement.
pub const BLOCK_SIZE: u64 = 4096;

/// The canonical layout and read view, re-exported so a consumer needs one
/// dependency: everything about *how a read is composed* stays in `avb-graft`.
pub use avb_graft::{
    FOOTER_SIZE, Footer, Graft, ReadError as GraftReadError, parse_footer, plan_graft,
    replacement_footer, validate_vbmeta,
};

/// A placement or payload-evidence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The image or block geometry is unusable.
    Geometry,
    /// A recognized payload header is malformed.
    Header,
    /// Offset arithmetic overflowed.
    Overflow,
    /// Structural admission by `avb-graft` failed.
    Graft(avb_graft::Error),
    /// The metadata cannot fit below the partition's final 64-byte footer.
    DoesNotFit {
        image_size: u64,
        metadata_size: u64,
    },
    /// An explicit offset is not a multiple of the block size.
    Alignment { offset: u64, block_size: u64 },
    /// The plan would overwrite bytes that are not tail padding.
    PlacementOccupied { offset: u64, length: u64 },
    /// The payload extent reaches into the placement.
    PayloadOverlap {
        payload_end: u64,
        metadata_offset: u64,
    },
    /// The replaced region is not all zero and its extent is unknown.
    TailNotUnused { offset: u64 },
    /// The original image's length does not match the plan.
    SizeMismatch { image_size: u64, actual: u64 },
    /// A read or write would leave the image.
    Bounds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Geometry => f.write_str("unusable partition or block geometry"),
            Self::Header => f.write_str("malformed payload header"),
            Self::Overflow => f.write_str("offset arithmetic overflow"),
            Self::Graft(error) => write!(f, "avb-graft rejected the image: {error}"),
            Self::DoesNotFit {
                image_size,
                metadata_size,
            } => write!(
                f,
                "{metadata_size} metadata bytes do not fit above the 64-byte footer of a {image_size}-byte partition"
            ),
            Self::Alignment { offset, block_size } => {
                write!(f, "offset {offset} is not a multiple of {block_size}")
            }
            Self::PlacementOccupied { offset, length } => write!(
                f,
                "synthesized {length}-byte metadata region at offset {offset} is not zero tail padding"
            ),
            Self::PayloadOverlap {
                payload_end,
                metadata_offset,
            } => write!(
                f,
                "payload extends to {payload_end}, past metadata offset {metadata_offset}"
            ),
            Self::TailNotUnused { offset } => write!(
                f,
                "the replaced region from {offset} is not all zero and the payload extent is unknown"
            ),
            Self::SizeMismatch { image_size, actual } => write!(
                f,
                "plan is for a {image_size}-byte image but the original is {actual} bytes"
            ),
            Self::Bounds => f.write_str("read or write lies outside the image"),
        }
    }
}

impl core::error::Error for Error {}

/// A caller's read failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError<E> {
    /// The placement itself is unusable.
    Layout(Error),
    /// The caller's backing read failed.
    Original(E),
}

impl<E> From<Error> for ReadError<E> {
    fn from(error: Error) -> Self {
        Self::Layout(error)
    }
}

impl<E: fmt::Display> fmt::Display for ReadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layout(error) => write!(f, "{error}"),
            Self::Original(error) => write!(f, "{error}"),
        }
    }
}

/// Where the metadata goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    /// Replace the metadata exactly where the stock footer already points:
    /// [`avb_graft::plan_graft`]'s own rule, including its refusals. The
    /// metadata offset is unchanged and only the footer's `vbmeta_size` moves.
    KeepOriginal,
    /// Move the metadata into the partition's tail padding, block aligned, just
    /// below the final 64-byte footer.
    Tail,
    /// Place the metadata at this block-aligned offset.
    At(u64),
}

/// A payload header format whose declared extent can be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadHeader {
    /// Android boot image, formats 0..4 — `boot`, `vendor_boot`, `recovery`,
    /// `init_boot` — including `recovery_dtbo`, `dtb` and the v4 signature.
    AndroidBoot,
    /// DTBO/DTB table: `total` in the table header.
    DtboTable,
}

/// Where the payload extent is taken from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Extent {
    /// The stock image's own 64-byte footer declares it, and the region the
    /// metadata will occupy must already be padding except where that footer's
    /// metadata lies. This is the packaging rule for a stock (OEM) image.
    Footer,
    /// The caller measured it.
    Known(u64),
    /// The payload's own header declares it. A header of that format that is
    /// *malformed* is refused ([`Error::Header`]) rather than guessed at.
    Header(PayloadHeader),
    /// Nothing is known: the whole replaced region must be zero.
    ZeroTail,
}

/// The evidence the plan actually used, reported for the caller's log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Evidence {
    /// [`Placement::KeepOriginal`]: the metadata stays where the stock footer
    /// points, so no extent had to be derived.
    Stock,
    /// The stock footer's `original_image_size`.
    Footer,
    /// A caller-supplied extent.
    Known,
    /// An Android boot header of this version.
    BootHeader { version: u32 },
    /// A DTBO table header.
    DtboTable,
    /// Nothing was known and the replaced region was all zero.
    ZeroTail,
}

/// What a payload header declared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadExtent {
    /// First byte after the payload.
    pub end: u64,
    /// Android boot header version (`0..=4`), or `None` for a DTBO table.
    pub version: Option<u32>,
}

/// The exact metadata bytes, and where they go.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataExtent {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// The 64-byte footer to serve, and where it goes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FooterExtent {
    pub offset: u64,
    pub bytes: [u8; FOOTER_SIZE],
}

/// A complete, plain-data placement: what to serve, where, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritePlan {
    /// Partition size the plan was derived from. It never changes.
    pub image_size: u64,
    /// The placement that was asked for.
    pub placement: Placement,
    /// How the payload extent was established.
    pub evidence: Evidence,
    /// The payload extent the synthesized footer declares.
    pub original_image_size: u64,
    /// Metadata extent to serve.
    pub metadata: MetadataExtent,
    /// Footer extent to serve, at the image's last 64 bytes.
    pub footer: FooterExtent,
}

impl WritePlan {
    /// The `avb-graft` read view over this plan: the original payload with the
    /// planned metadata and footer served in place, composed without allocating
    /// the image.
    ///
    /// A plan this crate returned always succeeds here; the `Result` exists
    /// because the view re-validates the same structural rules a hand-built
    /// plan could break.
    pub fn graft(&self) -> Result<Graft<'_>, avb_graft::Error> {
        plan_graft(self.image_size, &self.footer.bytes, &self.metadata.bytes)
    }

    /// The payload region this plan protects: `[0, original_image_size)`.
    pub fn payload_range(&self) -> core::ops::Range<u64> {
        0..self.original_image_size
    }
}

/// Plan where `metadata` goes inside an `image_size`-byte partition.
///
/// The evidence for the payload extent is `extent`; for
/// [`Placement::KeepOriginal`] it is the stock footer itself and `extent` is
/// ignored. `read_at` serves the caller's image; every read is bounds-checked
/// against `image_size` first, and nothing is written.
pub fn plan<E>(
    placement: Placement,
    extent: Extent,
    image_size: u64,
    block_size: u64,
    metadata: &[u8],
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<WritePlan, ReadError<E>> {
    geometry(image_size)?;
    if placement != Placement::KeepOriginal {
        block_geometry(block_size)?;
    }
    let metadata_size = validate_vbmeta(metadata)
        .map_err(|error| ReadError::Layout(Error::Graft(error)))?
        .size();
    if placement == Placement::KeepOriginal {
        let mut footer_bytes = [0u8; FOOTER_SIZE];
        read(
            &mut read_at,
            image_size,
            image_size - FOOTER_SIZE as u64,
            &mut footer_bytes,
        )?;
        let original = parse_footer(&footer_bytes, image_size)
            .map_err(|error| ReadError::Layout(Error::Graft(error)))?;
        // Exactly `plan_graft`'s rule: the stock offset stays, the footer is
        // re-serialized with the replacement's size, and refusal comes from the
        // same structural admission.
        let graft = plan_graft(image_size, &footer_bytes, metadata)
            .map_err(|error| ReadError::Layout(Error::Graft(error)))?;
        return Ok(WritePlan {
            image_size,
            placement,
            evidence: Evidence::Stock,
            original_image_size: original.original_image_size,
            metadata: MetadataExtent {
                offset: graft.metadata_offset(),
                bytes: graft.metadata().to_vec(),
            },
            footer: FooterExtent {
                offset: graft.footer_offset(),
                bytes: *graft.footer(),
            },
        });
    }
    let offset = match placement {
        Placement::Tail => tail_offset(image_size, metadata_size, block_size)?,
        Placement::At(offset) if offset % block_size != 0 => {
            return Err(Error::Alignment { offset, block_size }.into());
        }
        Placement::At(offset)
            if offset
                .checked_add(metadata_size)
                .ok_or(Error::Overflow)?
                > image_size - FOOTER_SIZE as u64 =>
        {
            return Err(Error::DoesNotFit {
                image_size,
                metadata_size,
            }
            .into());
        }
        Placement::At(offset) => offset,
        // Handled above, and `Placement` is `Copy`.
        Placement::KeepOriginal => unreachable!(),
    };
    let (payload_end, evidence, stock) =
        locate(extent, image_size, offset, &mut read_at)?;
    if payload_end > offset {
        return Err(Error::PayloadOverlap {
            payload_end,
            metadata_offset: offset,
        }
        .into());
    }
    if let Some(stock) = stock {
        claim(offset, metadata_size, stock, image_size, &mut read_at)?;
    }
    let synthesized = Footer {
        original_image_size: payload_end,
        vbmeta_offset: offset,
        vbmeta_size: metadata_size,
    };
    let graft = plan_graft(image_size, &replacement_footer(synthesized), metadata)
        .map_err(|error| ReadError::Layout(Error::Graft(error)))?;
    Ok(WritePlan {
        image_size,
        placement,
        evidence,
        original_image_size: payload_end,
        metadata: MetadataExtent {
            offset: graft.metadata_offset(),
            bytes: graft.metadata().to_vec(),
        },
        footer: FooterExtent {
            offset: graft.footer_offset(),
            bytes: *graft.footer(),
        },
    })
}

/// Compose the full graft image: the original's payload bytes untouched, with
/// the planned metadata and footer applied, at the original's size.
///
/// `original` must be the whole `image_size`-byte partition image; the result is
/// byte-identical to it except inside the metadata extent and the last 64 bytes.
pub fn materialize(original: &[u8], plan: &WritePlan) -> Result<Vec<u8>, Error> {
    let actual = original.len() as u64;
    if actual != plan.image_size {
        return Err(Error::SizeMismatch {
            image_size: plan.image_size,
            actual,
        });
    }
    let mut out = original.to_vec();
    splice(&mut out, plan.metadata.offset, &plan.metadata.bytes)?;
    splice(&mut out, plan.footer.offset, &plan.footer.bytes)?;
    Ok(out)
}

/// Apply the plan in place through the caller's writer: metadata first, then the
/// footer, and nothing else — the payload and the image size are untouched.
pub fn apply<E>(
    plan: &WritePlan,
    mut write_at: impl FnMut(u64, &[u8]) -> Result<(), E>,
) -> Result<(), ReadError<E>> {
    write_at(plan.metadata.offset, &plan.metadata.bytes).map_err(ReadError::Original)?;
    write_at(plan.footer.offset, &plan.footer.bytes).map_err(ReadError::Original)?;
    Ok(())
}

/// The Android boot image extent (`boot`, `vendor_boot`, `recovery`,
/// `init_boot`), formats 0..4: header, kernel, ramdisk and, per version, the
/// second stage, `recovery_dtbo`, `dtb` and the v4 signature.
///
/// A header of a version this parser does not know, or one whose own fields
/// contradict its version, is [`Error::Header`] — never guessed at.
pub fn boot_extent(header: &[u8]) -> Result<PayloadExtent, Error> {
    if header.get(..8) != Some(b"ANDROID!") {
        return Err(Error::Header);
    }
    let version = u32_at(header, 40)?;
    if version >= 3 {
        if version > 4 || le32(header, 20)? != if version == 3 { 1580 } else { 1584 } {
            return Err(Error::Header);
        }
        let mut end = add(4096, align(le32(header, 8)?, 4096)?)?;
        end = add(end, align(le32(header, 12)?, 4096)?)?;
        if version == 4 {
            end = add(end, align(le32(header, 1580)?, 4096)?)?;
        }
        return Ok(PayloadExtent {
            end,
            version: Some(version),
        });
    }
    let page = le32(header, 36)?;
    let minimum: u64 = match version {
        0 => 1632,
        1 => 1648,
        2 => 1660,
        _ => return Err(Error::Header),
    };
    if !page.is_power_of_two() || page < minimum {
        return Err(Error::Header);
    }
    if version > 0 && le32(header, 1644)? != minimum {
        return Err(Error::Header);
    }
    let mut end = page;
    for at in [8, 16, 24] {
        end = add(end, align(le32(header, at)?, page)?)?;
    }
    if version > 0 {
        let size = le32(header, 1632)?;
        if size != 0 {
            let offset = le64(header, 1636)?;
            if offset < end || offset % page != 0 {
                return Err(Error::Header);
            }
            end = add(offset, align(size, page)?)?;
        }
    }
    if version == 2 {
        end = add(end, align(le32(header, 1648)?, page)?)?;
    }
    Ok(PayloadExtent {
        end,
        version: Some(version),
    })
}

/// The DTBO/DTB table extent: `total` from the table header.
pub fn dtbo_extent(header: &[u8]) -> Result<PayloadExtent, Error> {
    if header.get(..4) != Some(&[0xd7, 0xb7, 0xab, 0x1e]) {
        return Err(Error::Header);
    }
    let total = u32::from_be_bytes(
        header
            .get(4..8)
            .ok_or(Error::Header)?
            .try_into()
            .map_err(|_| Error::Header)?,
    ) as u64;
    let header_size = u32::from_be_bytes(
        header
            .get(8..12)
            .ok_or(Error::Header)?
            .try_into()
            .map_err(|_| Error::Header)?,
    ) as u64;
    if header_size < 32 || total < header_size {
        return Err(Error::Header);
    }
    Ok(PayloadExtent {
        end: total,
        version: None,
    })
}

/// [`boot_extent`] or [`dtbo_extent`], by format.
pub fn payload_extent(header: &[u8], format: PayloadHeader) -> Result<PayloadExtent, Error> {
    match format {
        PayloadHeader::AndroidBoot => boot_extent(header),
        PayloadHeader::DtboTable => dtbo_extent(header),
    }
}

/// `(image_size - 64 - metadata_size)` rounded down to the block size.
fn tail_offset(image_size: u64, metadata_size: u64, block_size: u64) -> Result<u64, Error> {
    let limit = image_size
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or(Error::Geometry)?;
    let start = limit.checked_sub(metadata_size).ok_or(Error::DoesNotFit {
        image_size,
        metadata_size,
    })?;
    Ok(start & !(block_size - 1))
}

/// Read the payload extent per `extent`, and hand back the stock footer when the
/// footer was the evidence, so the region check can exclude the OEM metadata.
fn locate<E>(
    extent: Extent,
    image_size: u64,
    offset: u64,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<(u64, Evidence, Option<Footer>), ReadError<E>> {
    match extent {
        Extent::Known(end) => Ok((end, Evidence::Known, None)),
        Extent::Header(format) => {
            // Every payload header this crate reads lives in the first block.
            let mut header = [0u8; BLOCK_SIZE as usize];
            let count = core::cmp::min(BLOCK_SIZE, image_size) as usize;
            read(read_at, image_size, 0, &mut header[..count])?;
            let declared =
                payload_extent(&header[..count], format).map_err(ReadError::Layout)?;
            let evidence = match declared.version {
                Some(version) => Evidence::BootHeader { version },
                None => Evidence::DtboTable,
            };
            Ok((declared.end, evidence, None))
        }
        Extent::ZeroTail => {
            let mut buffer = [0u8; BLOCK_SIZE as usize];
            let mut at = offset;
            while at < image_size {
                let count = core::cmp::min(buffer.len() as u64, image_size - at) as usize;
                read(read_at, image_size, at, &mut buffer[..count])?;
                if buffer[..count].iter().any(|byte| *byte != 0) {
                    return Err(Error::TailNotUnused { offset: at }.into());
                }
                at += count as u64;
            }
            Ok((offset, Evidence::ZeroTail, None))
        }
        Extent::Footer => {
            let mut footer_bytes = [0u8; FOOTER_SIZE];
            read(
                read_at,
                image_size,
                image_size - FOOTER_SIZE as u64,
                &mut footer_bytes,
            )?;
            let stock = parse_footer(&footer_bytes, image_size)
                .map_err(|error| ReadError::Layout(Error::Graft(error)))?;
            Ok((stock.original_image_size, Evidence::Footer, Some(stock)))
        }
    }
}

/// A stock footer's own placement: the region we are about to fill must already
/// be padding, except exactly where the OEM metadata lies.
fn claim<E>(
    offset: u64,
    metadata_size: u64,
    stock: Footer,
    image_size: u64,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<(), ReadError<E>> {
    let count = usize::try_from(metadata_size).map_err(|_| Error::Bounds)?;
    let mut buffer = vec![0u8; count];
    read(read_at, image_size, offset, &mut buffer)?;
    let oem_start = stock.vbmeta_offset;
    let oem_end = stock
        .vbmeta_offset
        .checked_add(stock.vbmeta_size)
        .ok_or(Error::Overflow)?;
    for (index, byte) in buffer.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        let at = offset + index as u64;
        if at >= oem_start && at < oem_end {
            continue;
        }
        return Err(Error::PlacementOccupied {
            offset: at,
            length: metadata_size,
        }
        .into());
    }
    Ok(())
}

/// The image must at least hold a footer.
fn geometry(image_size: u64) -> Result<(), Error> {
    if image_size < FOOTER_SIZE as u64 {
        return Err(Error::Geometry);
    }
    Ok(())
}

/// A placement offset is computed from the block size, so it must be a real
/// block. Whether a *partition* size is a whole number of blocks is the
/// caller's own geometry check (a partition table's, or a device's).
fn block_geometry(block_size: u64) -> Result<(), Error> {
    if block_size < 64 || !block_size.is_power_of_two() {
        return Err(Error::Geometry);
    }
    Ok(())
}

/// A caller read, bounds-checked against the image before the callback runs.
fn read<E>(
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    image_size: u64,
    offset: u64,
    out: &mut [u8],
) -> Result<(), ReadError<E>> {
    if offset
        .checked_add(out.len() as u64)
        .ok_or(Error::Overflow)?
        > image_size
    {
        return Err(Error::Bounds.into());
    }
    read_at(offset, out).map_err(ReadError::Original)
}

fn splice(out: &mut [u8], offset: u64, bytes: &[u8]) -> Result<(), Error> {
    let start = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    let end = start.checked_add(bytes.len()).ok_or(Error::Bounds)?;
    let slot = out.get_mut(start..end).ok_or(Error::Bounds)?;
    slot.copy_from_slice(bytes);
    Ok(())
}

fn align(n: u64, page: u64) -> Result<u64, Error> {
    Ok(add(n, page - 1)? & !(page - 1))
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}

fn le32(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u32_at(bytes, at)? as u64)
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let value = bytes.get(at..at + 4).ok_or(Error::Header)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| Error::Header)?,
    ))
}

fn le64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let value = bytes.get(at..at + 8).ok_or(Error::Header)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::Header)?,
    ))
}
