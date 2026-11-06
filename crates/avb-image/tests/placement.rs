//! Placement and graft-image tests.
//!
//! The point of this crate is that two consumers' placement rules become one
//! implementation, so the tests here are the *moved* vectors of both: the
//! `avb-graft` geometry cases that `Placement::KeepOriginal` must reproduce
//! exactly, ablwrap's packager tail-placement and refusal cases, avbview's
//! header/zero-tail cases, and the byte-level graft assertions of the gobbl
//! `avb-graft apply` recipe.

use avb_image::{
    BLOCK_SIZE, Error, Evidence, Extent, FOOTER_SIZE, PayloadHeader, Placement, ReadError, apply,
    materialize, parse_footer, plan,
};
use std::path::Path;

// --------------------------------------------------------------- fixed vectors

/// A structurally valid `AVB0` block, as `avb-graft`'s own layout vectors use.
fn metadata() -> Vec<u8> {
    let mut bytes = vec![0; 320];
    bytes[..4].copy_from_slice(b"AVB0");
    bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
    bytes[20..28].copy_from_slice(&64_u64.to_be_bytes());
    bytes
}

/// The footer of `avb-graft`'s layout vectors, at the end of a 512-byte image
/// with an empty metadata region at offset 128.
fn stock_footer() -> Vec<u8> {
    let mut bytes = vec![0x5a; 512];
    let footer = avb_image::replacement_footer(avb_image::Footer {
        original_image_size: 73,
        vbmeta_offset: 128,
        vbmeta_size: 0,
    });
    bytes[512 - FOOTER_SIZE..].copy_from_slice(&footer);
    bytes
}

fn copy(bytes: &[u8], at: u64, out: &mut [u8]) -> Result<(), ()> {
    let start = at as usize;
    out.copy_from_slice(bytes.get(start..start + out.len()).ok_or(())?);
    Ok(())
}

/// A stock footered image: payload, OEM metadata at `oem_offset`, zeros, footer.
fn stock(image_size: usize, payload_size: usize, oem_offset: usize, meta: &[u8]) -> Vec<u8> {
    assert!(oem_offset + meta.len() <= image_size - FOOTER_SIZE);
    let mut image = vec![0u8; image_size];
    for (index, byte) in image[..payload_size].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    image[oem_offset..oem_offset + meta.len()].copy_from_slice(meta);
    let footer = avb_image::replacement_footer(avb_image::Footer {
        original_image_size: payload_size as u64,
        vbmeta_offset: oem_offset as u64,
        vbmeta_size: meta.len() as u64,
    });
    image[image_size - FOOTER_SIZE..].copy_from_slice(&footer);
    image
}

/// An Android boot image of the given size with a zeroed payload.
fn boot(size: usize, version: u32) -> Vec<u8> {
    let mut bytes = vec![0x57u8; size];
    bytes[..4096].fill(0);
    bytes[..8].copy_from_slice(b"ANDROID!");
    bytes[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    let header_size: u32 = if version == 3 { 1580 } else { 1584 };
    bytes[20..24].copy_from_slice(&header_size.to_le_bytes());
    bytes[40..44].copy_from_slice(&version.to_le_bytes());
    bytes
}

// ------------------------------------------------- KeepOriginal == plan_graft

/// `Placement::KeepOriginal` is `avb-graft`'s own rule, proven on its own
/// vectors: the metadata offset does not move, only `vbmeta_size` does, and the
/// refusals are the same refusals.
#[test]
fn keep_original_is_plan_graft() {
    let image = stock_footer();
    let meta = metadata();
    let kept = plan(
        Placement::KeepOriginal,
        Extent::Footer,
        image.len() as u64,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&image, at, out),
    )
    .unwrap();
    assert_eq!(kept.metadata.offset, 128);
    assert_eq!(kept.footer.offset, 512 - FOOTER_SIZE as u64);
    assert_eq!(kept.original_image_size, 73);
    assert_eq!(kept.evidence, Evidence::Stock);
    let written = parse_footer(&kept.footer.bytes, 512).unwrap();
    assert_eq!(written.vbmeta_size, meta.len() as u64);
    assert_eq!(written.vbmeta_offset, 128);
    assert_eq!(written.original_image_size, 73);

    // `avb-graft`'s own verdicts, through this crate.
    // A 511-byte image whose footer says the metadata starts at 128: 320 bytes
    // do not fit above its last 64 bytes.
    let mut small = stock_footer();
    small.truncate(511);
    let footer = avb_image::replacement_footer(avb_image::Footer {
        original_image_size: 73,
        vbmeta_offset: 128,
        vbmeta_size: 0,
    });
    small[511 - FOOTER_SIZE..].copy_from_slice(&footer);
    assert_eq!(
        plan(
            Placement::KeepOriginal,
            Extent::Footer,
            511,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&small, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Graft(avb_graft::Error::ReplacementDoesNotFit))
    );
    let mut footerless = image.clone();
    let tail = footerless.len() - FOOTER_SIZE;
    footerless[tail..].fill(0);
    assert_eq!(
        plan(
            Placement::KeepOriginal,
            Extent::Footer,
            512,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&footerless, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Graft(avb_graft::Error::Magic))
    );
    // Too small to hold a footer at all.
    assert_eq!(
        plan(
            Placement::KeepOriginal,
            Extent::Footer,
            32,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Geometry)
    );
}

// ------------------------------------------- Tail + stock footer == the packager

#[test]
fn tail_with_footer_evidence_matches_the_packager() {
    let meta = metadata();
    let image = stock(32768, 8192, 8192, &meta);
    let placed = plan(
        Placement::Tail,
        Extent::Footer,
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&image, at, out),
    )
    .unwrap();
    let expected = (32768 - 64 - meta.len() as u64) & !(BLOCK_SIZE - 1);
    assert_eq!(placed.metadata.offset, expected);
    assert_eq!(placed.evidence, Evidence::Footer);
    assert_eq!(placed.original_image_size, 8192);
    let footer = parse_footer(&placed.footer.bytes, 32768).unwrap();
    assert_eq!(footer.original_image_size, 8192);
    assert_eq!(footer.vbmeta_offset, expected);
    assert_eq!(footer.vbmeta_size, meta.len() as u64);

    // A trimmed image reproduces the stock offset exactly.
    let trimmed = stock(8192 + meta.len() + 64, 8192, 8192, &meta);
    let placed = plan(
        Placement::Tail,
        Extent::Footer,
        trimmed.len() as u64,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&trimmed, at, out),
    )
    .unwrap();
    assert_eq!(placed.metadata.offset, 8192);
}

#[test]
fn tail_refuses_occupied_padding_and_a_reaching_payload() {
    let meta = metadata();
    let mut dirty = stock(32768, 8192, 8192, &meta);
    let at = ((32768 - 64 - meta.len() as u64) & !(BLOCK_SIZE - 1)) as usize + 5;
    dirty[at] = 0xab;
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Footer,
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&dirty, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::PlacementOccupied { .. })
    ));

    // A payload extent reaching into the placement is refused as well.
    let payload_size = 99600usize;
    assert!(!payload_size.is_multiple_of(4096));
    let image_size = payload_size + 64 + meta.len();
    let long = stock(image_size, payload_size, payload_size, &meta);
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Footer,
            image_size as u64,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&long, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::PayloadOverlap { .. })
    ));

    // Metadata that cannot fit above the footer at all.
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Footer,
            256,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&stock(256, 64, 64, &meta), at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::DoesNotFit { .. })
    ));
}

// ------------------------------------------------- Tail + header == the avbview

#[test]
fn tail_with_header_evidence_matches_the_view_planner() {
    let meta = metadata();
    let image = boot(32768, 4);
    let placed = plan(
        Placement::Tail,
        Extent::Header(PayloadHeader::AndroidBoot),
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&image, at, out),
    )
    .unwrap();
    assert_eq!(placed.metadata.offset, 28672);
    assert_eq!(placed.evidence, Evidence::BootHeader { version: 4 });
    // The v4 header declares a 4096-byte kernel, an empty ramdisk and no boot
    // signature yet, page aligned.
    assert_eq!(placed.original_image_size, 8192);
    let footer = parse_footer(&placed.footer.bytes, 32768).unwrap();
    assert_eq!(footer.original_image_size, 8192);
    assert_eq!(footer.vbmeta_offset, 28672);

    // A v4 signature block is inside the payload extent too.
    let mut signed = boot(32768, 4);
    signed[1580..1584].copy_from_slice(&1_u32.to_le_bytes());
    let placed = plan(
        Placement::Tail,
        Extent::Header(PayloadHeader::AndroidBoot),
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&signed, at, out),
    )
    .unwrap();
    assert_eq!(placed.original_image_size, 12288);

    // A payload whose extent reaches the placement is refused.
    let mut long = boot(32768, 4);
    long[8..12].copy_from_slice(&28672_u32.to_le_bytes());
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Header(PayloadHeader::AndroidBoot),
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&long, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::PayloadOverlap { .. })
    ));

    // A recognized but malformed header is refused, never replaced by a guess.
    let mut bad = boot(32768, 4);
    bad[40..44].copy_from_slice(&9_u32.to_le_bytes());
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Header(PayloadHeader::AndroidBoot),
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&bad, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Header)
    ));
}

#[test]
fn tail_with_dtbo_evidence_and_zero_tail() {
    let meta = metadata();
    let mut dtbo = vec![0u8; 32768];
    dtbo[..4].copy_from_slice(&[0xd7, 0xb7, 0xab, 0x1e]);
    dtbo[4..8].copy_from_slice(&8192_u32.to_be_bytes());
    dtbo[8..12].copy_from_slice(&32_u32.to_be_bytes());
    let placed = plan(
        Placement::Tail,
        Extent::Header(PayloadHeader::DtboTable),
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&dtbo, at, out),
    )
    .unwrap();
    assert_eq!(placed.evidence, Evidence::DtboTable);
    assert_eq!(placed.original_image_size, 8192);

    // Unknown extent: anything nonzero in the replaced region is refused.
    let mut unknown = vec![0u8; 32768];
    unknown[30000] = 1;
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::ZeroTail,
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&unknown, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::TailNotUnused { .. })
    ));
    let placed = plan(
        Placement::Tail,
        Extent::ZeroTail,
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&unknown, at, out),
    );
    let mut clean = unknown.clone();
    clean[28672..].fill(0);
    assert!(
        placed.is_err(),
        "the payload region is untouched by the rule"
    );
    let placed = plan(
        Placement::Tail,
        Extent::ZeroTail,
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&clean, at, out),
    )
    .unwrap();
    assert_eq!(placed.evidence, Evidence::ZeroTail);
    assert_eq!(placed.original_image_size, placed.metadata.offset);

    // Caller-supplied extent.
    let placed = plan(
        Placement::Tail,
        Extent::Known(4096),
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&clean, at, out),
    )
    .unwrap();
    assert_eq!(placed.evidence, Evidence::Known);
    assert_eq!(placed.original_image_size, 4096);
}

#[test]
fn explicit_offset_is_block_aligned_and_checked() {
    let meta = metadata();
    let image = stock(32768, 4096, 4096, &meta);
    let placed = plan(
        Placement::At(16384),
        Extent::Known(4096),
        32768,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&image, at, out),
    )
    .unwrap();
    assert_eq!(placed.metadata.offset, 16384);
    assert_eq!(placed.placement, Placement::At(16384));

    assert!(matches!(
        plan(
            Placement::At(16385),
            Extent::Known(4096),
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Alignment { .. })
    ));
    // Overlapping the payload the caller declared.
    assert!(matches!(
        plan(
            Placement::At(4096),
            Extent::Known(8192),
            32768,
            BLOCK_SIZE,
            &meta,
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::PayloadOverlap { .. })
    ));
    // A metadata block whose auxiliary block alone is a whole 4096 bytes cannot
    // fit at the only aligned offset of an 8192-byte image.
    let mut large = metadata();
    large[20..28].copy_from_slice(&4096_u64.to_be_bytes());
    large.resize(256 + 4096, 0);
    assert!(matches!(
        plan(
            Placement::At(4096),
            Extent::Known(64),
            8192,
            BLOCK_SIZE,
            &large,
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::DoesNotFit { .. })
    ));
    // A block size that is not a block at all.
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Known(4096),
            32768,
            1000,
            &meta,
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Geometry)
    ));
    // Metadata that is not structurally valid never places.
    assert!(matches!(
        plan(
            Placement::Tail,
            Extent::Known(4096),
            32768,
            BLOCK_SIZE,
            &vec![0u8; 4096],
            |at, out| copy(&image, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Graft(avb_graft::Error::Magic))
    ));
}

// ------------------------------------------- the graft image itself (the recipe)

/// The byte-level contract of `avb-graft apply`, which this crate now serves
/// from memory: size equal, payload untouched, the replacement readable back at
/// the planned offset, idempotent re-application, and refusals that never
/// produce an image.
#[test]
fn materialize_reproduces_the_apply_recipe() {
    let original = stock(32768, 4096, 4096, &metadata());
    let replacement = {
        let mut bytes = metadata();
        bytes[7] = 1; // a *different* metadata block than the stock one
        bytes
    };
    let placed = plan(
        Placement::KeepOriginal,
        Extent::Footer,
        original.len() as u64,
        BLOCK_SIZE,
        &replacement,
        |at, out| copy(&original, at, out),
    )
    .unwrap();
    let grafted = materialize(&original, &placed).unwrap();

    // Size preserved, payload prefix identical.
    assert_eq!(grafted.len(), original.len());
    assert_eq!(grafted[..4096], original[..4096]);

    // extract(grafted) == replacement: the footer locates exactly the metadata.
    let footer = parse_footer(
        &grafted[grafted.len() - FOOTER_SIZE..],
        grafted.len() as u64,
    )
    .unwrap();
    let at = footer.vbmeta_offset as usize;
    assert_eq!(
        &grafted[at..at + footer.vbmeta_size as usize],
        &replacement[..]
    );
    assert_eq!(footer.original_image_size, 4096);

    // Idempotent: re-applying the same plan changes nothing.
    let again = plan(
        Placement::KeepOriginal,
        Extent::Footer,
        grafted.len() as u64,
        BLOCK_SIZE,
        &replacement,
        |at, out| copy(&grafted, at, out),
    )
    .unwrap();
    assert_eq!(materialize(&grafted, &again).unwrap(), grafted);

    // The same, through the write-through helper: only the two extents.
    let mut written: Vec<(u64, Vec<u8>)> = Vec::new();
    apply(&placed, |at, bytes| {
        written.push((at, bytes.to_vec()));
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].0, placed.metadata.offset);
    assert_eq!(written[0].1, placed.metadata.bytes);
    assert_eq!(written[1].0, placed.footer.offset);
    assert_eq!(written[1].1.to_vec(), placed.footer.bytes.to_vec());

    // A footerless original is refused, and nothing is produced.
    let mut footerless = original.clone();
    let tail = footerless.len() - FOOTER_SIZE;
    footerless[tail..].fill(0);
    assert!(matches!(
        plan(
            Placement::KeepOriginal,
            Extent::Footer,
            footerless.len() as u64,
            BLOCK_SIZE,
            &replacement,
            |at, out| copy(&footerless, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Graft(avb_graft::Error::Magic))
    ));
    // Metadata that does not fit is refused too: 320 bytes at the stock offset
    // 64 of a 384-byte image leaves only 320 usable bytes below the footer.
    let tight = stock(384, 64, 64, &[]);
    assert!(matches!(
        plan(
            Placement::KeepOriginal,
            Extent::Footer,
            tight.len() as u64,
            BLOCK_SIZE,
            &replacement,
            |at, out| copy(&tight, at, out),
        )
        .unwrap_err(),
        ReadError::Layout(Error::Graft(avb_graft::Error::ReplacementDoesNotFit))
    ));

    // A wrong-length original is refused instead of being padded or truncated.
    assert_eq!(
        materialize(&grafted[..grafted.len() - 1], &placed).unwrap_err(),
        Error::SizeMismatch {
            image_size: 32768,
            actual: 32767
        }
    );
}

/// The read view composes the same bytes as the materialized image.
#[test]
fn graft_read_view_matches_materialized_bytes() {
    let original = stock(32768, 8192, 8192, &metadata());
    let meta = metadata();
    let placed = plan(
        Placement::Tail,
        Extent::Footer,
        original.len() as u64,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&original, at, out),
    )
    .unwrap();
    let grafted = materialize(&original, &placed).unwrap();
    let view = placed.graft().unwrap();
    for (at, count) in [(0u64, 32768usize), (8191, 3), (28671, 259), (32704, 64)] {
        let mut out = vec![0u8; count];
        view.read(at, &mut out, |at, out| copy(&original, at, out))
            .unwrap();
        assert_eq!(out, grafted[at as usize..at as usize + count], "at {at}");
    }
}

// ------------------------------------------------------------- real capture

const CAPTURE: &str =
    "/home/vivy/Projects/efisp-projects/gbl_root_canoe/.work/recovery-diagnosis-20260906/device";

fn capture(name: &str) -> Option<Vec<u8>> {
    let path = Path::new(CAPTURE).join(name);
    if !path.is_file() {
        eprintln!("SKIP: required capture is absent: {}", path.display());
        return None;
    }
    Some(std::fs::read(path).expect("capture is readable"))
}

/// One real stock partition, planned both ways.
#[test]
fn real_capture_stock_placement() {
    let Some(boot) = capture("boot_a.img") else {
        return;
    };
    let size = boot.len() as u64;
    let stock = parse_footer(&boot[boot.len() - FOOTER_SIZE..], size).unwrap();
    let meta = boot
        [stock.vbmeta_offset as usize..(stock.vbmeta_offset + stock.vbmeta_size) as usize]
        .to_vec();
    assert_eq!(meta.len(), 2368);

    // Keeping the stock placement reproduces the stock image byte for byte: the
    // footer is re-serialized from the same three numbers.
    let kept = plan(
        Placement::KeepOriginal,
        Extent::Footer,
        size,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&boot, at, out),
    )
    .unwrap();
    assert_eq!(kept.metadata.offset, stock.vbmeta_offset);
    assert_eq!(kept.original_image_size, stock.original_image_size);
    assert_eq!(materialize(&boot, &kept).unwrap(), boot);

    // Tail placement moves the metadata into the partition's last block and keeps
    // the payload: the stock payload region and the grafted one are identical.
    let placed = plan(
        Placement::Tail,
        Extent::Footer,
        size,
        BLOCK_SIZE,
        &meta,
        |at, out| copy(&boot, at, out),
    )
    .unwrap();
    assert_eq!(size - placed.metadata.offset, 4096);
    assert_eq!(placed.original_image_size, stock.original_image_size);
    assert_eq!(placed.evidence, Evidence::Footer);
    let grafted = materialize(&boot, &placed).unwrap();
    assert_eq!(grafted.len(), boot.len());
    assert_eq!(
        grafted[..placed.original_image_size as usize],
        boot[..stock.original_image_size as usize]
    );
    // The payload extent the stock footer declared is what the new one declares,
    // and the metadata is readable back at the planned offset.
    let written = parse_footer(&grafted[grafted.len() - FOOTER_SIZE..], size).unwrap();
    assert_eq!(written.original_image_size, stock.original_image_size);
    assert_eq!(written.vbmeta_offset, placed.metadata.offset);
    assert_eq!(
        &grafted[placed.metadata.offset as usize
            ..(placed.metadata.offset + written.vbmeta_size) as usize],
        &meta[..]
    );
    // Nothing outside the metadata extent and the footer changed.
    for at in 0..boot.len() {
        let touched = (at as u64) >= placed.metadata.offset
            && (at as u64) < placed.metadata.offset + meta.len() as u64
            || (at as u64) >= size - FOOTER_SIZE as u64;
        if !touched {
            assert_eq!(grafted[at], boot[at], "byte {at} moved");
        }
    }
}
