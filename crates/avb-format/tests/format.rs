use avb_format::Footer;
use avb_format::{
    CHAIN_PARTITION_FLAG_DO_NOT_USE_AB, ChainPartition, Defect, Descriptor, Error, ExtractError,
    Property, VbmetaInfo, descriptors, exact_metadata, inspect, parse_footer, replacement_footer,
    validate_vbmeta, vbmd_extent, vbmeta_entry,
};

fn metadata() -> Vec<u8> {
    let mut bytes = vec![0; 320];
    bytes[..4].copy_from_slice(b"AVB0");
    bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
    bytes[20..28].copy_from_slice(&64_u64.to_be_bytes());
    bytes
}

/// Untrusted metadata may not overflow a block, truncate a descriptor, or
/// smuggle nonzero image bytes behind a standalone metadata header.
#[test]
fn metadata_bounds_reject_truncation_overflow_and_descriptor_escape() {
    let good = metadata();
    for length in 0..good.len() {
        assert!(validate_vbmeta(&good[..length]).is_err());
    }
    for (offset, value, expected) in [
        (12, u64::MAX - 63, Error::Overflow),
        (20, 63, Error::BlockAlignment),
        (64, 65, Error::MetadataBounds),
        (96, 65, Error::MetadataBounds),
        (104, 8, Error::DescriptorBounds),
    ] {
        let mut bytes = good.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        assert_eq!(validate_vbmeta(&bytes), Err(expected));
    }
    let mut bytes = good.clone();
    bytes[104..112].copy_from_slice(&16_u64.to_be_bytes());
    bytes[264..272].copy_from_slice(&64_u64.to_be_bytes());
    assert_eq!(validate_vbmeta(&bytes), Err(Error::DescriptorBounds));
    bytes[264..272].copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(validate_vbmeta(&bytes).unwrap().size(), 320);
    bytes.push(0);
    assert_eq!(validate_vbmeta(&bytes).unwrap().size(), 320);
    bytes.push(1);
    assert_eq!(validate_vbmeta(&bytes), Err(Error::TrailingData));
}

fn descriptor(tag: u64, body: &[u8]) -> Vec<u8> {
    let mut body = body.to_vec();
    while !body.len().is_multiple_of(8) {
        body.push(0);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn chain_descriptor(rollback: u32, flags: u32, name: &str, key: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&rollback.to_be_bytes());
    body.extend_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(&(key.len() as u32).to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    body.resize(76, 0);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(key);
    descriptor(4, &body)
}

fn property(key: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(key.len() as u64).to_be_bytes());
    body.extend_from_slice(&(value.len() as u64).to_be_bytes());
    body.extend_from_slice(key.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    descriptor(0, &body)
}

fn hash_descriptor(name: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 116];
    body[0..8].copy_from_slice(&8192_u64.to_be_bytes());
    body[8..14].copy_from_slice(b"sha256");
    body[40..44].copy_from_slice(&(name.len() as u32).to_be_bytes());
    body[44..48].copy_from_slice(&(salt.len() as u32).to_be_bytes());
    body[48..52].copy_from_slice(&(digest.len() as u32).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(salt);
    body.extend_from_slice(digest);
    descriptor(2, &body)
}

fn hashtree_descriptor(name: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 164];
    body[0..4].copy_from_slice(&1_u32.to_be_bytes());
    body[4..12].copy_from_slice(&8192_u64.to_be_bytes());
    body[56..62].copy_from_slice(b"sha256");
    body[88..92].copy_from_slice(&(name.len() as u32).to_be_bytes());
    body[92..96].copy_from_slice(&(salt.len() as u32).to_be_bytes());
    body[96..100].copy_from_slice(&(digest.len() as u32).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(salt);
    body.extend_from_slice(digest);
    descriptor(1, &body)
}

fn kernel_cmdline(text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&(text.len() as u32).to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    descriptor(3, &body)
}

/// A structurally valid, deliberately **unsigned** `AVB0` image.
fn build_vbmeta(public_key: &[u8], descriptors: &[Vec<u8>]) -> Vec<u8> {
    let mut region = Vec::new();
    for item in descriptors {
        region.extend_from_slice(item);
    }
    let descriptors_size = region.len() as u64;
    let public_key_offset = descriptors_size;
    let public_key_size = public_key.len() as u64;
    let aux = (descriptors_size + public_key_size).div_ceil(64) * 64;
    let mut out = vec![0u8; 256 + aux as usize];
    out[0..4].copy_from_slice(b"AVB0");
    out[4..8].copy_from_slice(&1u32.to_be_bytes());
    out[20..28].copy_from_slice(&aux.to_be_bytes());
    out[64..72].copy_from_slice(&public_key_offset.to_be_bytes());
    out[72..80].copy_from_slice(&public_key_size.to_be_bytes());
    out[104..112].copy_from_slice(&descriptors_size.to_be_bytes());
    out[256..256 + region.len()].copy_from_slice(&region);
    let key_at = 256 + descriptors_size as usize;
    out[key_at..key_at + public_key.len()].copy_from_slice(public_key);
    out
}

fn padded(image: &[u8], size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    out[..image.len()].copy_from_slice(image);
    out
}

#[test]
fn inspect_parses_typed_descriptors_and_borrows_the_key() {
    let key = vec![0x11u8; 64];
    let image = build_vbmeta(
        &key,
        &[
            property("com.android.build.boot.security_patch", "2026-01-05"),
            chain_descriptor(7, CHAIN_PARTITION_FLAG_DO_NOT_USE_AB, "boot", &key),
            hash_descriptor("system", b"salt", &[0xab; 32]),
            hashtree_descriptor("vendor", b"pepper", &[0xcd; 32]),
            kernel_cmdline("androidboot.verifiedbootstate=green"),
        ],
    );
    let info: VbmetaInfo<'_> = inspect(&image).expect("synthetic image is valid");
    assert_eq!(info.size, image.len());
    assert_eq!(info.header.algorithm, 0);
    assert_eq!(info.public_key, key.as_slice());

    let found: Vec<Descriptor<'_>> = info
        .descriptors
        .clone()
        .collect::<Result<_, _>>()
        .expect("descriptors parse");
    assert_eq!(found.len(), 5);
    assert_eq!(found[0].tag(), 0);
    let Descriptor::Property(Property {
        key: property_key,
        value,
    }) = found[0]
    else {
        panic!("first descriptor is a property");
    };
    assert_eq!(property_key, "com.android.build.boot.security_patch");
    assert_eq!(value, "2026-01-05");
    let Descriptor::ChainPartition(ChainPartition {
        rollback_index_location,
        flags,
        name,
        public_key,
    }) = found[1]
    else {
        panic!("second descriptor is a chain partition");
    };
    assert_eq!(rollback_index_location, 7);
    assert_eq!(flags, CHAIN_PARTITION_FLAG_DO_NOT_USE_AB);
    assert_eq!(name, "boot");
    assert_eq!(public_key, key.as_slice());
    assert!(matches!(
        found[2],
        Descriptor::Hash(hash) if hash.partition_name == "system" && hash.salt == b"salt"
    ));
    assert!(matches!(
        found[3],
        Descriptor::Hashtree(tree) if tree.partition_name == "vendor" && tree.salt == b"pepper"
    ));
    assert!(matches!(
        found[4],
        Descriptor::KernelCmdline(line) if line.cmdline.starts_with("androidboot")
    ));

    let padded_image = padded(&image, 4096);
    assert_eq!(exact_metadata(&padded_image).unwrap(), image.as_slice());
    let (exact, entry) = vbmeta_entry(&padded_image).unwrap();
    assert_eq!(exact, image.as_slice());
    assert_eq!(entry.size, image.len());
}

#[test]
fn descriptor_framing_errors_are_typed_and_stop_iteration() {
    let mut item = descriptors(&[0u8; 8]);
    assert_eq!(item.next(), Some(Err(Defect::DescriptorBounds)));
    assert_eq!(item.next(), None);
}

#[test]
fn inspect_rejects_malformed_descriptor_bodies() {
    let key = vec![0x22u8; 64];
    let mut malformed_property = property("com.android.build.boot.os_version", "15");
    // Key length claims bytes beyond the descriptor body.
    malformed_property[16..24].copy_from_slice(&4096_u64.to_be_bytes());
    let image = build_vbmeta(&key, &[malformed_property]);
    assert_eq!(inspect(&image).unwrap_err(), Defect::Property);

    let mut oversized = build_vbmeta(&key, &[]);
    oversized[104..112].copy_from_slice(&16_u64.to_be_bytes());
    oversized.resize(oversized.len() + 72, 0);
    oversized[264..272].copy_from_slice(&64_u64.to_be_bytes());
    assert_eq!(
        inspect(&oversized).unwrap_err(),
        Defect::Framing(Error::DescriptorBounds)
    );

    assert_eq!(
        inspect(&vec![0u8; 4096]).unwrap_err(),
        Defect::Framing(Error::Magic)
    );
}

/// Admission ignores a malformed kernel command line; the typed iterator
/// reports it when a caller asks for that descriptor.
#[test]
fn inspect_defers_kernel_cmdline_parsing_to_iteration() {
    let key = vec![0x33u8; 64];
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&1024_u32.to_be_bytes());
    let image = build_vbmeta(&key, &[descriptor(3, &body)]);
    assert!(inspect(&image).is_ok());
    let mut iter = inspect(&image).unwrap().descriptors;
    assert_eq!(iter.next(), Some(Err(Defect::Descriptor)));
    assert_eq!(iter.next(), None);
}

fn build_footered(image_size: usize, payload_size: usize, metadata: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; image_size];
    for (index, byte) in image[..payload_size].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    image[payload_size..payload_size + metadata.len()].copy_from_slice(metadata);
    let at = image.len() - 64;
    let footer = &mut image[at..];
    footer[..4].copy_from_slice(b"AVBf");
    footer[4..8].copy_from_slice(&1u32.to_be_bytes());
    footer[12..20].copy_from_slice(&(payload_size as u64).to_be_bytes());
    footer[20..28].copy_from_slice(&(payload_size as u64).to_be_bytes());
    footer[28..36].copy_from_slice(&(metadata.len() as u64).to_be_bytes());
    image
}

#[test]
fn extract_vbmd_reports_footer_defects_and_read_failures() {
    let metadata = build_vbmeta(&[0x66u8; 64], &[]);
    let image = build_footered(4096, 1024, &metadata);
    let size = image.len() as u64;
    let read_all = |at: u64, out: &mut [u8]| -> Result<(), ()> {
        out.copy_from_slice(&image[at as usize..at as usize + out.len()]);
        Ok(())
    };
    let mut out = vec![0u8; 64 * 1024];
    assert_eq!(
        avb_format::extract_vbmd(size, read_all, &mut out).unwrap(),
        metadata.as_slice()
    );
    assert_eq!(
        vbmd_extent(size, |at, out: &mut [u8]| {
            out.copy_from_slice(&image[at as usize..at as usize + out.len()]);
            Ok::<(), ()>(())
        })
        .unwrap(),
        avb_format::VbmdExtent {
            offset: 1024,
            size: metadata.len() as u64
        }
    );

    let mut oversized = build_footered(200_000, 1000, &metadata);
    let at = oversized.len() - 64;
    oversized[at + 28..at + 36].copy_from_slice(&(70_000u64).to_be_bytes());
    assert_eq!(
        vbmd_extent(oversized.len() as u64, |at, out: &mut [u8]| {
            out.copy_from_slice(&oversized[at as usize..at as usize + out.len()]);
            Ok::<(), ()>(())
        }),
        Err(ExtractError::TooLarge { size: 70_000 })
    );

    let bare = vec![0u8; 4096];
    assert!(matches!(
        vbmd_extent(4096, |at, out: &mut [u8]| {
            out.copy_from_slice(&bare[at as usize..at as usize + out.len()]);
            Ok::<(), ()>(())
        }),
        Err(ExtractError::Malformed(Defect::Framing(_)))
    ));

    assert_eq!(
        vbmd_extent(size, |_, _: &mut [u8]| Err(7)),
        Err(ExtractError::Read(7))
    );
    assert!(matches!(
        vbmd_extent(32, |_, _: &mut [u8]| Ok::<(), ()>(())),
        Err(ExtractError::Malformed(Defect::Truncated))
    ));

    let mut short = vec![0u8; metadata.len() - 1];
    assert_eq!(
        avb_format::extract_vbmd(
            size,
            |at: u64, out: &mut [u8]| {
                out.copy_from_slice(&image[at as usize..at as usize + out.len()]);
                Ok::<(), ()>(())
            },
            &mut short
        ),
        Err(ExtractError::BufferTooSmall {
            size: metadata.len() as u64
        })
    );
}

#[test]
fn footer_round_trips_and_rejects_nonzero_reserved_bytes() {
    let footer = replacement_footer(Footer {
        original_image_size: 73,
        vbmeta_offset: 128,
        vbmeta_size: 320,
    });
    assert_eq!(parse_footer(&footer, 512).unwrap().vbmeta_offset, 128);
    let mut broken = footer;
    broken[40] = 1;
    assert_eq!(parse_footer(&broken, 512), Err(Error::Reserved));
    assert!(parse_footer(&footer[..63], 512).is_err());
}
