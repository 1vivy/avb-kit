//! Synthetic fixtures for the libavb walk shape, out-of-order supply, chained
//! metadata rejection, footer extraction, and the AOSP SHA-512 cmdline golden.
//!
//! The synthetic images are deliberately unsigned: they prove the walk,
//! ordering and rejection behaviour and never claim verification. The AOSP
//! fixture is a real signed SHA-512 root and its recorded
//! `androidboot.vbmeta.digest`.

use avb_chain::{
    CmdlineDigest, Defect, ExtractError, HashAlg, KeyBlob, Kind, Plan, ROOT_NAME,
    VBMETA_FLAG_VERIFICATION_DISABLED, VBMETA_MAX_SIZE, Verdict, exact_metadata, extract_vbmd, hex,
    inspect, sha256, vbmeta_entry,
};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/aosp")
        .join(name)
}

// ------------------------------------------------------------- synthetic AVB

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

fn chain_descriptor(rollback: u32, name: &str, key: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&rollback.to_be_bytes());
    body.extend_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(&(key.len() as u32).to_be_bytes());
    body.resize(76, 0);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(key);
    descriptor(4, &body)
}

fn property_descriptor(key: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(key.len() as u64).to_be_bytes());
    body.extend_from_slice(&(value.len() as u64).to_be_bytes());
    body.extend_from_slice(key.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    descriptor(0, &body)
}

fn hash_descriptor(name: &str) -> Vec<u8> {
    let mut body = vec![0u8; 116];
    body[40..44].copy_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    descriptor(2, &body)
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

/// A footered stock image: payload, metadata at the payload end, then a footer.
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

/// Exact metadata extent of a synthetic image.
fn exact(image: &[u8]) -> &[u8] {
    exact_metadata(image).expect("synthetic image is valid")
}

// --------------------------------------------------------------------- walk

#[test]
fn synthetic_walk_orders_chains_and_accepts_any_supply_order() {
    let key = vec![0x11u8; 64];
    let boot = build_vbmeta(&key, &[]);
    let vbmeta_x = build_vbmeta(&key, &[]);
    let dtbo = build_vbmeta(&key, &[]);
    let root = build_vbmeta(
        &key,
        &[
            chain_descriptor(4, "boot", &key),
            chain_descriptor(3, "vbmeta_x", &key),
            chain_descriptor(1, "dtbo", &key),
        ],
    );

    let mut plan = Plan::new_unverified(&padded(&root, 4096)).expect("unsigned root walks");
    let names: Vec<String> = plan.needs().into_iter().map(|need| need.name).collect();
    assert_eq!(names, ["boot", "vbmeta_x", "dtbo"]);
    assert_eq!(plan.needs()[0].kind, Kind::Footered);
    assert_eq!(plan.needs()[1].kind, Kind::Vbmeta);
    assert_eq!(plan.needs()[2].kind, Kind::Footered);
    assert_eq!(plan.needs()[1].rollback_index_location, 3);
    assert_eq!(plan.needs()[1].expected_key_sha256, sha256(&key));
    assert_eq!(plan.needs()[1].parent, "vbmeta");
    assert_eq!(plan.needs()[0].parent, "vbmeta");
    assert!(plan.needs().iter().all(|need| need.parent == ROOT_NAME));

    // Supply in reverse of visit order; the plan's order is the walk's order,
    // not the arrival order.
    assert!(plan.supply("dtbo", exact(&dtbo)).is_err());
    assert!(plan.supply("vbmeta_x", exact(&vbmeta_x)).is_err());
    assert!(plan.supply("boot", exact(&boot)).is_err());
    let order: Vec<&str> = plan
        .ordered_images()
        .iter()
        .map(|image| image.name)
        .collect();
    assert_eq!(order, ["vbmeta", "boot", "vbmeta_x", "dtbo"]);
    // Unsigned throughout, so nothing is complete and everything is reported.
    assert!(!plan.complete());
    assert_eq!(plan.rejected().len(), 4);
    assert!(plan.rejected().iter().all(|(_, v)| *v == Verdict::Unsigned));
    assert!(plan.missing().is_empty());
}

#[test]
fn chained_image_carrying_a_chain_descriptor_is_invalid_metadata() {
    let key = vec![0x12u8; 64];
    // root -> vbmeta_x; libavb permits the chain descriptor only in the main
    // image, so vbmeta_x's own chain to dtbo is invalid metadata.
    let dtbo = build_vbmeta(&key, &[]);
    let middle = build_vbmeta(&key, &[chain_descriptor(2, "dtbo", &key)]);
    let boot = build_vbmeta(&key, &[]);
    let root = build_vbmeta(
        &key,
        &[
            chain_descriptor(4, "boot", &key),
            chain_descriptor(3, "vbmeta_x", &key),
        ],
    );

    let mut plan = Plan::new_unverified(&padded(&root, 4096)).expect("unsigned root walks");
    let rejected = plan.supply("vbmeta_x", exact(&middle)).unwrap_err();
    assert_eq!(
        rejected.verdict,
        Verdict::Malformed(Defect::ChainInChainedImage("vbmeta_x".to_owned()))
    );
    // The invalid image is recorded, but it exposed no child.
    assert_eq!(plan.missing(), ["boot"]);
    assert_eq!(plan.ordered_images().len(), 2);
    let order: Vec<&str> = plan
        .ordered_images()
        .iter()
        .map(|image| image.name)
        .collect();
    assert_eq!(order, ["vbmeta", "vbmeta_x"]);
    // dtbo was never demanded, so supplying it is unknown rather than a walk.
    assert_eq!(
        plan.supply("dtbo", exact(&dtbo)).unwrap_err().verdict,
        Verdict::Malformed(Defect::UnknownPartition("dtbo".to_owned()))
    );
    assert!(plan.supply("boot", exact(&boot)).is_err());
}

#[test]
fn synthetic_duplicate_chain_inside_one_image_is_refused() {
    let key = vec![0x22u8; 64];
    let image = build_vbmeta(
        &key,
        &[
            chain_descriptor(1, "boot", &key),
            chain_descriptor(2, "boot", &key),
        ],
    );
    assert_eq!(
        inspect(&image).unwrap_err(),
        Defect::DuplicateChain("boot".to_owned())
    );
    assert_eq!(
        Plan::new_unverified(&padded(&image, 4096)).unwrap_err(),
        Defect::DuplicateChain("boot".to_owned())
    );
}

#[test]
fn synthetic_root_chaining_its_own_name_is_refused() {
    let key = vec![0x33u8; 64];
    let image = build_vbmeta(&key, &[chain_descriptor(1, "vbmeta", &key)]);
    assert_eq!(
        Plan::new_unverified(&padded(&image, 4096)).unwrap_err(),
        Defect::ReservedChainName("vbmeta".to_owned())
    );
}

#[test]
fn synthetic_zero_rollback_location_and_unknown_supply_are_typed() {
    let key = vec![0x44u8; 64];
    let image = build_vbmeta(&key, &[chain_descriptor(0, "boot", &key)]);
    assert_eq!(
        inspect(&image).unwrap_err(),
        Defect::RollbackIndexLocationZero("boot".to_owned())
    );

    let root = build_vbmeta(&key, &[chain_descriptor(1, "boot", &key)]);
    let mut plan = Plan::new_unverified(&padded(&root, 4096)).unwrap();
    let verdict = plan.supply("dtbo", &root).unwrap_err().verdict;
    assert_eq!(
        verdict,
        Verdict::Malformed(Defect::UnknownPartition("dtbo".to_owned()))
    );
}

#[test]
fn unsigned_images_are_rejected_but_still_walked() {
    let key = vec![0x55u8; 64];
    let boot = build_vbmeta(&key, &[]);
    let root = build_vbmeta(&key, &[chain_descriptor(1, "boot", &key)]);
    let mut plan = Plan::new_unverified(&padded(&root, 4096)).unwrap();
    assert_eq!(plan.root_verdict(), &Verdict::Unsigned);
    let rejected = plan.supply("boot", &boot).unwrap_err();
    assert_eq!(rejected.verdict, Verdict::Unsigned);
    // The walk still records it, so the digest can be reported for an artifact
    // that is explicitly built from unverified metadata.
    let images: Vec<&str> = plan
        .ordered_images()
        .iter()
        .map(|image| image.name)
        .collect();
    assert_eq!(images, ["vbmeta", "boot"]);
    assert!(!plan.complete());
    assert_eq!(plan.rejected().len(), 2);
    let digest = plan.vbmeta_digest_with(HashAlg::Sha256);
    assert_eq!(
        digest.total_size,
        (exact(&padded(&root, 4096)).len() + exact(&boot).len()) as u64
    );
    let mut together = exact(&padded(&root, 4096)).to_vec();
    together.extend_from_slice(exact(&boot));
    assert_eq!(digest.digest, sha256(&together));
}

#[test]
fn supplying_one_partition_twice_is_typed() {
    let key = vec![0x56u8; 64];
    let boot = build_vbmeta(&key, &[]);
    let root = build_vbmeta(&key, &[chain_descriptor(1, "boot", &key)]);
    let mut plan = Plan::new_unverified(&padded(&root, 4096)).unwrap();
    assert!(plan.supply("boot", exact(&boot)).is_err());
    assert_eq!(
        plan.supply("boot", exact(&boot)).unwrap_err().verdict,
        Verdict::Malformed(Defect::AlreadySupplied("boot".to_owned()))
    );
}

// ------------------------------------------------- coverage and properties

#[test]
fn coverage_and_properties_are_exposed_in_descriptor_order() {
    let key = vec![0x57u8; 64];
    let image = build_vbmeta(
        &key,
        &[
            property_descriptor("a.first", "1"),
            hash_descriptor("init_boot"),
            property_descriptor("a.first", "2"),
            hash_descriptor("boot"),
            property_descriptor("b.second", "3"),
        ],
    );
    let info = inspect(&image).expect("synthetic image is valid");
    assert_eq!(info.hashed, ["init_boot", "boot"]);
    assert_eq!(info.covered, ["init_boot", "boot"]);
    let properties: Vec<(&str, &str)> = info
        .properties
        .iter()
        .map(|property| (property.key.as_str(), property.value.as_str()))
        .collect();
    assert_eq!(
        properties,
        [("a.first", "1"), ("a.first", "2"), ("b.second", "3")]
    );

    let plan = Plan::new_unverified(&padded(&image, 4096)).unwrap();
    assert_eq!(plan.root_properties().len(), 3);
    assert_eq!(plan.payload_hashed(), ["init_boot", "boot"]);
    assert_eq!(plan.covered()[0].1, ["init_boot", "boot"]);
}

#[test]
fn kind_follows_the_libavb_partition_name_rule() {
    for name in ["vbmeta", "vbmeta_system", "vbmeta_vendor", "vbmeta_x"] {
        assert_eq!(Kind::of(name), Kind::Vbmeta);
    }
    for name in ["boot", "dtbo", "recovery", "system"] {
        assert_eq!(Kind::of(name), Kind::Footered);
    }
    assert_eq!(Kind::Vbmeta.name(), "vbmeta");
    assert_eq!(Kind::Footered.name(), "footered");
}

// ------------------------------------------------------------- extraction

#[test]
fn extract_vbmd_reports_footer_defects_and_read_failures() {
    let metadata = build_vbmeta(&[0x66u8; 64], &[]);
    let image = build_footered(4096, 1024, &metadata);
    let size = image.len() as u64;
    let read_all = |at: u64, out: &mut [u8]| -> Result<(), ()> {
        out.copy_from_slice(&image[at as usize..at as usize + out.len()]);
        Ok(())
    };
    assert_eq!(extract_vbmd(size, read_all).unwrap(), metadata);

    // A footer that declares more than the 64 KiB metadata bound. The partition
    // has to be large enough for that footer to be geometrically valid at all.
    let mut oversized = build_footered(200_000, 1000, &metadata);
    let at = oversized.len() - 64;
    oversized[at + 28..at + 36].copy_from_slice(&(70_000u64).to_be_bytes());
    assert_eq!(
        extract_vbmd(oversized.len() as u64, |at, out: &mut [u8]| {
            out.copy_from_slice(&oversized[at as usize..at as usize + out.len()]);
            Ok::<(), ()>(())
        }),
        Err(ExtractError::TooLarge { size: 70_000 })
    );

    // No footer at all.
    let bare = vec![0u8; 4096];
    assert!(matches!(
        extract_vbmd(4096, |at, out: &mut [u8]| {
            out.copy_from_slice(&bare[at as usize..at as usize + out.len()]);
            Ok::<(), ()>(())
        }),
        Err(ExtractError::Malformed(_))
    ));

    // A backing read that fails is reported as the caller's error.
    assert_eq!(
        extract_vbmd(size, |_, _: &mut [u8]| Err(7)),
        Err(ExtractError::Read(7))
    );

    // A partition smaller than a footer.
    assert!(matches!(
        extract_vbmd(32, |_, _: &mut [u8]| Ok::<(), ()>(())),
        Err(ExtractError::Malformed(_))
    ));
    assert!(VBMETA_MAX_SIZE >= metadata.len() as u64);
}

#[test]
fn supply_from_reads_a_footered_partition_through_the_reader() {
    let key = vec![0x67u8; 64];
    let metadata = build_vbmeta(&key, &[]);
    let image = build_footered(4096, 1024, &metadata);
    let root = build_vbmeta(&key, &[chain_descriptor(1, "boot", &key)]);
    let mut plan = Plan::new_unverified(&padded(&root, 4096)).unwrap();
    let rejected = plan
        .supply_from("boot", image.len() as u64, |at, out: &mut [u8]| {
            let start = usize::try_from(at).map_err(|_| "offset")?;
            let part = image.get(start..start + out.len()).ok_or("short read")?;
            out.copy_from_slice(part);
            Ok::<(), &'static str>(())
        })
        .unwrap_err();
    assert_eq!(rejected.verdict, Verdict::Unsigned);
    assert_eq!(plan.ordered_images()[1].name, "boot");
}

// ------------------------------------------------------- explicit trust

#[test]
fn signed_root_tampering_is_rejected_with_the_right_verdict() {
    let image = std::fs::read(fixture("vbmeta_v4_v4_init_boot_a.img"))
        .expect("AOSP fixture is in the repository");
    let info = inspect(&image).expect("AOSP root is structurally valid");

    // A flipped byte in the stored hash is a hash mismatch: the hash covers the
    // header and the whole auxiliary block.
    let hash_at = 256 + info.header.hash_offset as usize;
    let mut broken_hash = image.clone();
    broken_hash[hash_at + 3] ^= 0x40;
    assert_eq!(Plan::new(&broken_hash).unwrap_err(), Verdict::HashMismatch);

    // A flipped byte in the signature is a signature mismatch.
    let signature_at = 256 + info.header.signature_offset as usize;
    let mut broken_signature = image.clone();
    broken_signature[signature_at + 8] ^= 0x01;
    assert_eq!(
        Plan::new(&broken_signature).unwrap_err(),
        Verdict::SignatureMismatch
    );

    // A corrupted descriptor length is caught structurally, before any crypto.
    let descriptors_at =
        256 + info.header.auth_size as usize + info.header.descriptors_offset as usize;
    let mut broken_descriptor = image;
    broken_descriptor[descriptors_at + 10] ^= 0x40;
    assert!(matches!(
        Plan::new(&broken_descriptor).unwrap_err(),
        Verdict::Malformed(_)
    ));
}

#[test]
fn explicit_trust_accepts_only_a_supplied_key() {
    let image = std::fs::read(fixture("vbmeta_v4_v4_init_boot_a.img"))
        .expect("AOSP fixture is in the repository");
    let info = inspect(&image).expect("AOSP root is structurally valid");
    let key = KeyBlob::from_blob(info.public_key.clone()).expect("embedded key is valid");

    let plan = Plan::with_trusted_keys(&image, std::slice::from_ref(&key))
        .expect("supplied key trusts the root");
    assert!(plan.is_trusted());
    assert_eq!(
        plan.root_verdict(),
        &Verdict::Verified {
            key_sha256: info.public_key_sha256,
            trusted: true,
        }
    );
    assert_eq!(plan.trusted_keys().len(), 1);
    assert_eq!(plan.trusted_keys()[0], key);

    assert_eq!(
        Plan::with_trusted_keys(&image, &[]).unwrap_err(),
        Verdict::Malformed(Defect::NoTrustedKey)
    );

    // A self-verifying root is untrusted, not silently trusted.
    let plan = Plan::new(&image).expect("the root self-verifies");
    assert!(!plan.is_trusted());
    assert_eq!(
        plan.root_verdict(),
        &Verdict::Verified {
            key_sha256: info.public_key_sha256,
            trusted: false,
        }
    );

    // The fields are public so a caller can present evidence it already
    // validated; this blob is not the root's key.
    let foreign = KeyBlob {
        blob: vec![0u8; 1032],
        num_bits: 4096,
    };
    assert_eq!(
        Plan::with_trusted_keys(&image, &[foreign]).unwrap_err(),
        Verdict::UntrustedKey {
            actual: info.public_key_sha256,
        }
    );
}

// --------------------------------------------------- the SHA-512 side (AOSP)

/// AOSP's own SHA-512-signed fixture, and the digest AOSP recorded for it.
///
/// `vbmeta_v4_v4_init_boot_a.digest.txt` is the `androidboot.vbmeta.digest`
/// AOSP libbootloader's test data records for that root, and it is exactly
/// SHA-512 over the root's 3712-byte extent — an expectation this crate did not
/// produce. The fixture is copied into this repository under its original
/// Apache-2.0 terms.
#[test]
fn sha512_root_matches_the_digest_aosp_recorded() {
    let image = std::fs::read(fixture("vbmeta_v4_v4_init_boot_a.img"))
        .expect("AOSP fixture is in the repository");
    let recorded = std::fs::read_to_string(fixture("vbmeta_v4_v4_init_boot_a.digest.txt"))
        .expect("recorded digest is in the repository")
        .trim()
        .to_owned();
    assert_eq!(recorded.len(), 128, "the recorded digest is a SHA-512 one");

    let info = inspect(&image).expect("the AOSP fixture is structurally valid");
    assert_eq!(info.header.algorithm, 5, "SHA512_RSA4096");
    assert_eq!(info.size, image.len(), "the file is exactly the image");
    let plan = Plan::new(&image).expect("the fixture verifies against its own embedded key");
    assert!(
        plan.complete(),
        "the root chains nothing: it is the whole set"
    );
    assert_eq!(plan.root_algorithm(), 5);
    assert_eq!(plan.digest_algorithm(), Some(HashAlg::Sha512));

    let cmdline = plan
        .libavb_cmdline_digest()
        .expect("libavb emits androidboot.vbmeta.* for this root");
    assert_eq!(cmdline.hash_alg, HashAlg::Sha512);
    assert_eq!(cmdline.size, image.len() as u64);
    assert_eq!(cmdline.name(), "sha512");
    assert_eq!(cmdline.hex(), recorded);
    assert_eq!(plan.vbmeta_digest_with(HashAlg::Sha512).hex(), recorded);

    // The same extents under a caller-chosen SHA-256 are the caller's value,
    // not a stock platform VBH.
    let sha256_digest = plan.vbmeta_digest_with(HashAlg::Sha256);
    assert_eq!(sha256_digest.algorithm, HashAlg::Sha256);
    assert_eq!(sha256_digest.total_size, image.len() as u64);
    assert_ne!(sha256_digest.hex(), recorded);
    assert_eq!(sha256_digest.hex(), hex(&sha256(&image)));
    assert_eq!(
        sha256_digest.digest,
        plan.vbmeta_digest_with(HashAlg::Sha256).digest
    );
    assert_eq!(
        plan.libavb_cmdline_digest(),
        Some(CmdlineDigest {
            hash_alg: HashAlg::Sha512,
            digest: plan.vbmeta_digest_with(HashAlg::Sha512).digest,
            size: image.len() as u64,
        })
    );
}

/// libavb's cmdline hash switch, including the types this crate never verifies.
#[test]
fn libavb_hash_choice_matches_the_c_switch_and_a_disabled_root_emits_nothing() {
    for value in [0u32, 1, 2, 3, 7, 8] {
        assert_eq!(
            HashAlg::libavb_cmdline(value),
            Some(HashAlg::Sha256),
            "algorithm_type {value}"
        );
    }
    for value in [4u32, 5, 6] {
        assert_eq!(
            HashAlg::libavb_cmdline(value),
            Some(HashAlg::Sha512),
            "algorithm_type {value}"
        );
    }
    for value in [9u32, 42, u32::MAX] {
        assert_eq!(
            HashAlg::libavb_cmdline(value),
            None,
            "algorithm_type {value}"
        );
    }
    assert_eq!(HashAlg::from_algorithm_type(7), None);
    assert_eq!(HashAlg::from_algorithm_type(8), None);
    assert_eq!(HashAlg::from_algorithm_type(0), None);
    assert_eq!(HashAlg::from_algorithm_type(5), Some(HashAlg::Sha512));

    let image = std::fs::read(fixture("vbmeta_v4_v4_init_boot_a.img"))
        .expect("AOSP fixture is in the repository");
    let mut disabled = image.clone();
    disabled[120..124].copy_from_slice(&VBMETA_FLAG_VERIFICATION_DISABLED.to_be_bytes());
    // The flag sits inside the authentication hash, so the image no longer
    // verifies; the structural walk still reaches the header it needs.
    let flagged = Plan::new_unverified(&disabled).expect("still structurally valid");
    assert_eq!(flagged.root_verdict(), &Verdict::HashMismatch);
    assert_eq!(
        flagged.libavb_cmdline_digest(),
        None,
        "a verification-disabled root gets no libavb cmdline digest"
    );
    let exact = exact_metadata(&disabled).expect("header");
    assert_eq!(
        flagged.vbmeta_digest_with(HashAlg::Sha256).hex(),
        hex(&sha256(exact))
    );
}

// -------------------------------------------------------------- entry point

#[test]
fn vbmeta_entry_trims_padding_and_keeps_the_owned_info() {
    let key = vec![0x68u8; 64];
    let image = build_vbmeta(&key, &[]);
    let padded = padded(&image, 4096);
    let (entry, info) = vbmeta_entry(&padded).expect("padded image is valid");
    assert_eq!(entry, image);
    assert_eq!(info.size, image.len());
    assert_eq!(info.public_key, key);
}
