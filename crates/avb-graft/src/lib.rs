#![no_std]
#![forbid(unsafe_code)]
//! Allocation-free AVB graft overlay, not signature or payload verification.
//!
//! Wire framing (the `AVB0` header, `AVBf` footer, structural validation and
//! exact metadata extent) lives in `avb-format` and is re-exported here, so a
//! caller of this crate needs one dependency. This crate adds the in-place
//! replacement plan and the read view that serves replacement metadata and a
//! replacement footer over an original image without allocating it.

pub use avb_format::{
    Error, FOOTER_SIZE, Footer, HEADER_SIZE, Vbmeta, parse_footer, replacement_footer,
    validate_vbmeta,
};

#[derive(Clone, Debug)]
pub struct Graft<'a> {
    image_size: u64,
    metadata_offset: u64,
    metadata: &'a [u8],
    footer: [u8; FOOTER_SIZE],
}

pub fn plan_graft<'a>(
    image_size: u64,
    footer_bytes: &[u8],
    metadata: &'a [u8],
) -> Result<Graft<'a>, Error> {
    let original = parse_footer(footer_bytes, image_size)?;
    let size = validate_vbmeta(metadata)?.size();
    if original
        .vbmeta_offset
        .checked_add(size)
        .ok_or(Error::Overflow)?
        > image_size - FOOTER_SIZE as u64
    {
        return Err(Error::ReplacementDoesNotFit);
    }
    Ok(Graft {
        image_size,
        metadata_offset: original.vbmeta_offset,
        metadata: &metadata[..size as usize],
        footer: replacement_footer(Footer {
            vbmeta_size: size,
            ..original
        }),
    })
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReadError<E> {
    Layout(Error),
    Original(E),
}

impl<'a> Graft<'a> {
    pub fn image_size(&self) -> u64 {
        self.image_size
    }
    pub fn metadata_offset(&self) -> u64 {
        self.metadata_offset
    }
    pub fn metadata(&self) -> &'a [u8] {
        self.metadata
    }
    pub fn footer_offset(&self) -> u64 {
        self.image_size - FOOTER_SIZE as u64
    }
    pub fn footer(&self) -> &[u8; FOOTER_SIZE] {
        &self.footer
    }

    /// Serve a logical read without whole-image allocation. The callback sees
    /// only original extents; each overlay is copied directly into the caller.
    pub fn read<E>(
        &self,
        offset: u64,
        out: &mut [u8],
        mut read_original: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<(), ReadError<E>> {
        if offset
            .checked_add(out.len() as u64)
            .ok_or(ReadError::Layout(Error::ReadBounds))?
            > self.image_size
        {
            return Err(ReadError::Layout(Error::ReadBounds));
        }
        let metadata_end = self.metadata_offset + self.metadata.len() as u64;
        let mut position = offset;
        let mut remaining = out;
        while !remaining.is_empty() {
            let (end, overlay) = if position < self.metadata_offset {
                (self.metadata_offset, None)
            } else if position < metadata_end {
                (metadata_end, Some((self.metadata, self.metadata_offset)))
            } else if position < self.footer_offset() {
                (self.footer_offset(), None)
            } else {
                (
                    self.image_size,
                    Some((&self.footer[..], self.footer_offset())),
                )
            };
            let count = core::cmp::min(end - position, remaining.len() as u64) as usize;
            let (part, rest) = remaining.split_at_mut(count);
            if let Some((bytes, start)) = overlay {
                let index = (position - start) as usize;
                part.copy_from_slice(&bytes[index..index + count]);
            } else {
                read_original(position, part).map_err(ReadError::Original)?;
            }
            position += count as u64;
            remaining = rest;
        }
        Ok(())
    }

    /// In-memory adapter with the same read-boundary semantics as physical I/O.
    pub fn copy_from(&self, original: &[u8], offset: u64, out: &mut [u8]) -> Result<(), Error> {
        if original.len() as u64 != self.image_size {
            return Err(Error::ReadBounds);
        }
        self.read(offset, out, |position, part| {
            let start = usize::try_from(position).map_err(|_| Error::ReadBounds)?;
            let bytes = original
                .get(start..start + part.len())
                .ok_or(Error::ReadBounds)?;
            part.copy_from_slice(bytes);
            Ok(())
        })
        .map_err(|error| match error {
            ReadError::Layout(error) | ReadError::Original(error) => error,
        })
    }
}
