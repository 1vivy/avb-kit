//! Goldens from the real canoe capture, plus synthetic fixtures for the walk
//! shape, out-of-order supply, recursive chains and hostile input.
//!
//! The crypto paths are exercised against **real OEM signatures**; the synthetic
//! fixtures are deliberately unsigned (they cannot be signed here), so they prove
//! the walk, ordering and rejection behaviour and never claim verification.

use avb_meta::{
    AblKey, AblKeys, CmdlineDigest, Defect, ExtractError, HashAlg, Kind, Plan,
    VBMETA_FLAG_VERIFICATION_DISABLED, Verdict, abl_keys, extract_vbmd, hex, inspect,
    rsa_pkcs1_verify, sha256, sha512, sha512_concat,
};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CAPTURE: &str =
    "/home/vivy/Projects/efisp-projects/gbl_root_canoe/.work/recovery-diagnosis-20260906/device";
const CHAINS: &str = "/home/vivy/Projects/efisp-projects/.work/phone-layout/20261004T013922Z";
/// The exact canoe stock PE named in `evidence/emu-report.md` section 1.
const CANOE_PE: &str = "/home/vivy/Ghidra/inputs/canoe-abl-parallel-20260902/abl_b.LinuxLoader.efi";
/// File offset of the 1032-byte OEM key in that PE (evidence section 1).
const CANOE_KEY_OFFSET: usize = 452022;
/// `SET_BOOTSTATE` public-key digest for the locked OEM run.
const ROOT_KEY: &str = "8d897f62492ea617f777bad41a5711ab621fcac1efc1865b890328ee8c3853bb";
/// The system/vendor chained key.
const SYSTEM_KEY: &str = "1aef65cb06c0146a2071ed14eeb05f09a296bef1e20d0a1e81ef813bed0599c2";
/// Recorded `SET_VBH` for the complete six-image metadata set.
const EVIDENCE_VBH: &str = "bc9bbd83c4be79f36d5c9b1724a865f83d8c26c3c76f96abe4c7fd082d7ccc47";
const EVIDENCE_TOTAL: u64 = 19776;
/// AOSP libbootloader's SHA-512-signed (`SHA512_RSA4096`) GBL testdata and the
/// digest AOSP itself recorded for the root (`.../vbmeta_v4_v4_init_boot_a.img`
/// and `.../vbmeta_v4_v4_init_boot_a.digest.txt`). Apache-2.0 test data, read in
/// place and never copied into this repository.
const AOSP_SHA512_DIR: &str = "/home/vivy/Projects/efisp-projects/gobbl-aosp/bootable/libbootloader/gbl/libgbl/testdata/android";

fn read(path: &str) -> Option<Vec<u8>> {
    let path = Path::new(path);
    if !path.is_file() {
        eprintln!("SKIP: required capture is absent: {}", path.display());
        return None;
    }
    Some(std::fs::read(path).expect("capture is readable"))
}

/// Read a footered partition's metadata through the public helper.
fn footered_metadata(path: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("partition is readable");
    let size = file.metadata().expect("metadata").len();
    let mut reader = |at: u64, out: &mut [u8]| -> Result<(), std::io::Error> {
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(out)
    };
    extract_vbmd(size, &mut reader).expect("footer metadata")
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
    &image[..inspect(image).expect("synthetic image is valid").size]
}

#[test]
fn synthetic_walk_orders_recursive_chains_and_accepts_any_supply_order() {
    let key = vec![0x11u8; 64];
    // root -> {boot, vbmeta_x}; vbmeta_x -> vbmeta_y; vbmeta_y -> dtbo.
    let dtbo = build_vbmeta(&key, &[]);
    let deep = build_vbmeta(&key, &[chain_descriptor(1, "dtbo", &key)]);
    let middle = build_vbmeta(&key, &[chain_descriptor(2, "vbmeta_y", &key)]);
    let boot = build_vbmeta(&key, &[]);
    let root = build_vbmeta(
        &key,
        &[
            chain_descriptor(4, "boot", &key),
            chain_descriptor(3, "vbmeta_x", &key),
        ],
    );

    let mut plan = Plan::new_unverified(&padded(&root, 4096)).expect("unsigned root walks");
    let names: Vec<String> = plan.needs().into_iter().map(|need| need.name).collect();
    assert_eq!(names, ["boot", "vbmeta_x"]);
    assert_eq!(plan.needs()[0].kind, Kind::Footered);
    assert_eq!(plan.needs()[1].kind, Kind::Vbmeta);
    assert_eq!(plan.needs()[1].rollback_index_location, 3);
    assert_eq!(plan.needs()[1].expected_key_sha256, sha256(&key));
    assert_eq!(plan.needs()[1].parent, "vbmeta");

    // vbmeta_x exposes its own child, which is not a need until then.
    assert!(plan.supply("vbmeta_x", exact(&middle)).is_err());
    let names: Vec<String> = plan.needs().into_iter().map(|need| need.name).collect();
    assert_eq!(names, ["boot", "vbmeta_y"]);
    assert_eq!(plan.needs()[1].parent, "vbmeta_x");

    assert!(plan.supply("vbmeta_y", exact(&deep)).is_err());
    let names: Vec<String> = plan.needs().into_iter().map(|need| need.name).collect();
    assert_eq!(names, ["boot", "dtbo"]);
    assert_eq!(plan.needs()[1].parent, "vbmeta_y");

    // Supply the remaining two in reverse of visit order; the plan's order is
    // the walk's order, not the arrival order.
    assert!(plan.supply("dtbo", exact(&dtbo)).is_err());
    assert!(plan.supply("boot", exact(&boot)).is_err());
    let order: Vec<&str> = plan
        .ordered_images()
        .iter()
        .map(|image| image.name)
        .collect();
    assert_eq!(order, ["vbmeta", "boot", "vbmeta_x", "vbmeta_y", "dtbo"]);
    // Unsigned throughout, so nothing is complete and everything is reported.
    assert!(!plan.complete());
    assert_eq!(plan.rejected().len(), 5);
    assert!(plan.rejected().iter().all(|(_, v)| *v == Verdict::Unsigned));
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
fn synthetic_two_parents_demanding_one_partition_are_refused() {
    let key = vec![0x23u8; 64];
    let boot = build_vbmeta(&key, &[]);
    let middle = build_vbmeta(&key, &[chain_descriptor(2, "boot", &key)]);
    let root = build_vbmeta(
        &key,
        &[
            chain_descriptor(1, "boot", &key),
            chain_descriptor(3, "vbmeta_x", &key),
        ],
    );
    let mut plan = Plan::new_unverified(&padded(&root, 4096)).unwrap();
    assert!(plan.supply("boot", exact(&boot)).is_err());
    assert_eq!(
        plan.supply("vbmeta_x", exact(&middle)).unwrap_err().verdict,
        Verdict::Malformed(Defect::DuplicatePartition("boot".to_owned()))
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
    assert_eq!(
        plan.vbmeta_digest().total_size,
        (exact(&padded(&root, 4096)).len() + exact(&boot).len()) as u64
    );
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
        Err(ExtractError::Malformed(Defect::Graft(_)))
    ));

    // A backing read that fails is reported as the caller's error.
    assert_eq!(
        extract_vbmd(size, |_, _: &mut [u8]| Err(7)),
        Err(ExtractError::Read(7))
    );

    // A partition smaller than a footer.
    assert!(matches!(
        extract_vbmd(32, |_, _: &mut [u8]| Ok::<(), ()>(())),
        Err(ExtractError::Malformed(Defect::Truncated))
    ));
}

// ------------------------------------------------------------------ abl_keys

#[test]
fn abl_keys_recovers_the_canoe_key_and_refuses_a_tampered_one() {
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);
    for key in keys.keys() {
        eprintln!(
            "abl_keys: offset {} bits {} sha256 {}",
            key.file_offset,
            key.num_bits,
            hex(&key.sha256)
        );
    }
    let found = keys
        .keys()
        .iter()
        .find(|key| key.file_offset == CANOE_KEY_OFFSET)
        .expect("the embedded OEM key is recovered by structure alone");
    assert_eq!(found.num_bits, 4096);
    assert_eq!(hex(&found.sha256), ROOT_KEY);
    assert_eq!(found.blob.len(), 1032);

    // Corrupting n0inv must make the blob stop being reported: the arithmetic
    // self-consistency checks are what separate a key from a byte pattern.
    let mut tampered = pe.clone();
    tampered[CANOE_KEY_OFFSET + 4] ^= 0xff;
    assert!(
        !abl_keys(&tampered)
            .keys()
            .iter()
            .any(|key| key.file_offset == CANOE_KEY_OFFSET)
    );
    // Corrupting rr (the last byte of the blob) likewise.
    let mut tampered = pe.clone();
    let last = CANOE_KEY_OFFSET + found.blob.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        !abl_keys(&tampered)
            .keys()
            .iter()
            .any(|key| key.file_offset == CANOE_KEY_OFFSET)
    );

    // The trust anchor is the first key in file order, which on this PE is the
    // key the ABL byte-compares against.
    assert_eq!(
        keys.anchor().map(|key| key.file_offset),
        Some(CANOE_KEY_OFFSET)
    );
    assert_eq!(
        keys.anchor().map(|key| hex(&key.sha256)),
        Some(ROOT_KEY.to_owned())
    );
}

/// The 13 `ablrepo` ABL fixtures: the first key per product, recomputed here.
///
/// The stock ABL's `AvbValidateVbmetaPublicKey` byte-compares the root vbmeta's
/// key against the first key embedded in its own image, so the anchor per
/// product is exactly this. The oracle's key-scan cross-check
/// (`oracle/tests/key-scan-cross-check.rs`) compares the same
/// first keys against `fw_image::scan_avb_keys`.
#[test]
fn ablrepo_first_key_per_product_is_the_anchor() {
    let directory = "/home/vivy/Projects/efisp-projects/gbl_root_canoe/ablrepo";
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("SKIP: {directory} is not readable: {error}");
            return;
        }
    };
    type Product = (String, usize, Option<(String, usize, u32)>, usize);
    let mut products: Vec<Product> = Vec::new();
    for entry in entries.flatten() {
        let image = entry.path().join("abl.img");
        if !image.is_file() {
            continue;
        }
        let bytes = std::fs::read(&image).expect("fixture is readable");
        let keys = abl_keys(&bytes);
        let anchor = keys
            .anchor()
            .map(|key| (hex(&key.sha256), key.file_offset, key.num_bits));
        if let Some((_, offset, bits)) = &anchor {
            assert!(matches!(bits, 2048 | 4096 | 8192));
            assert!(
                keys.keys().iter().all(|key| key.file_offset >= *offset),
                "keys are reported in file order, so the anchor is the first"
            );
        }
        products.push((
            entry.file_name().to_string_lossy().into_owned(),
            bytes.len(),
            anchor,
            keys.len(),
        ));
    }
    products.sort();
    assert_eq!(
        products.len(),
        13,
        "the ablrepo fixture set is 13 products; found {}",
        products.len()
    );
    let keyed = products.iter().filter(|row| row.2.is_some()).count();
    for (product, size, anchor, count) in &products {
        match anchor {
            Some((sha256, offset, bits)) => eprintln!(
                "ablrepo {product}: {size} bytes, anchor {sha256} ({bits} bits) @ {offset}, {count} key(s)"
            ),
            None => eprintln!(
                "ablrepo {product}: {size} bytes, no structurally complete AVB key in the file"
            ),
        }
    }
    eprintln!("ablrepo: {keyed} of 13 fixtures carry a complete AVB key");
}

#[test]
fn abl_keys_finds_nothing_in_random_data() {
    let mut state = 0x1234_5678u32;
    let noise: Vec<u8> = (0..4096)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    assert!(abl_keys(&noise).is_empty());
    assert!(abl_keys(&[]).is_empty());
    assert!(abl_keys(&[0u8; 8]).is_empty());
}

// ------------------------------------------------------------ real goldens

#[test]
fn real_capture_walk_verifies_every_image_and_reproduces_the_recorded_digest() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    for name in ["boot", "dtbo", "recovery"] {
        if !Path::new(&format!("{CAPTURE}/{name}_a.img")).is_file() {
            eprintln!("SKIP: required capture is absent: {CAPTURE}/{name}_a.img");
            return;
        }
    }
    let (Some(system), Some(vendor)) = (
        read(&format!("{CHAINS}/vbmeta_system_b.img")),
        read(&format!("{CHAINS}/vbmeta_vendor_b.img")),
    ) else {
        return;
    };
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);
    let plan = Plan::anchored(&root, &keys).expect("the real root verifies against the ABL key");
    assert!(plan.is_anchored());
    assert_eq!(plan.root_metadata().len(), 8448);
    assert_eq!(hex(&plan.root_info().public_key_sha256), ROOT_KEY);
    assert_eq!(plan.root_algorithm(), 2);
    assert_eq!(plan.digest_algorithm(), HashAlg::Sha256);
    assert_eq!(plan.root_properties().os_version.as_deref(), Some("16"));
    assert_eq!(
        plan.root_properties().security_patch.as_deref(),
        Some("2026-08-01")
    );

    // The walk alone — before any image is supplied — yields the five needs in
    // libavb visit order, with the right kinds and the right demanded keys.
    let needs = plan.needs();
    let names: Vec<&str> = needs.iter().map(|need| need.name.as_str()).collect();
    assert_eq!(
        names,
        ["boot", "dtbo", "recovery", "vbmeta_system", "vbmeta_vendor"]
    );
    assert_eq!(
        needs.iter().map(|need| need.kind).collect::<Vec<_>>(),
        [
            Kind::Footered,
            Kind::Footered,
            Kind::Footered,
            Kind::Vbmeta,
            Kind::Vbmeta
        ]
    );
    assert_eq!(
        needs
            .iter()
            .map(|need| need.rollback_index_location)
            .collect::<Vec<_>>(),
        [4, 3, 1, 2, 5]
    );
    assert_eq!(hex(&needs[0].expected_key_sha256), ROOT_KEY);
    assert_eq!(hex(&needs[3].expected_key_sha256), SYSTEM_KEY);
    assert_eq!(hex(&needs[4].expected_key_sha256), SYSTEM_KEY);
    assert!(needs.iter().all(|need| need.parent == "vbmeta"));

    let mut plan = plan;
    for (name, size) in [("boot", 2368usize), ("dtbo", 2240), ("recovery", 2240)] {
        let metadata = footered_metadata(&format!("{CAPTURE}/{name}_a.img"));
        assert_eq!(metadata.len(), size);
        let accepted = plan
            .supply(name, &metadata)
            .expect("footered image verifies");
        assert_eq!(accepted.kind, Kind::Footered);
        assert!(accepted.anchored);
        assert_eq!(accepted.metadata_len, size);
    }
    assert_eq!(
        plan.supply("vbmeta_system", &system).unwrap().metadata_len,
        2624
    );
    assert_eq!(
        plan.supply("vbmeta_vendor", &vendor).unwrap().metadata_len,
        1856
    );
    assert!(plan.complete(), "rejected: {:?}", plan.rejected());
    assert!(plan.missing().is_empty());

    let digest = plan.vbmeta_digest();
    assert_eq!(digest.hex(), EVIDENCE_VBH);
    assert_eq!(digest.total_size, EVIDENCE_TOTAL);
    assert_eq!(digest.algorithm, HashAlg::Sha256);

    // The other hashes over the same ordered extents, on this SHA-256-signed
    // root: libavb's cmdline digest is the SHA-256 one, the SHA-512 value is
    // different, and the DICE authority hash takes the keys, not the metadata.
    assert_eq!(
        plan.libavb_cmdline_digest(),
        Some(CmdlineDigest {
            hash_alg: HashAlg::Sha256,
            digest: digest.digest.clone(),
            size: EVIDENCE_TOTAL,
        }),
        "a SHA-256 root feeds libavb a SHA-256 cmdline digest"
    );
    let sha512_digest = plan.vbmeta_digest_with(HashAlg::Sha512);
    assert_eq!(sha512_digest.algorithm, HashAlg::Sha512);
    assert_eq!(sha512_digest.digest.len(), 64);
    assert_eq!(sha512_digest.total_size, EVIDENCE_TOTAL);
    assert_ne!(sha512_digest.hex(), EVIDENCE_VBH);
    let keys: Vec<Vec<u8>> = plan
        .supplied_info()
        .iter()
        .map(|(_, info)| info.public_key.clone())
        .collect();
    assert_eq!(
        plan.authority_sha512(),
        Some(sha512_concat(
            &keys.iter().map(Vec::as_slice).collect::<Vec<_>>()
        )),
        "the DICE authority is SHA-512 over the keys of every image, in visit order"
    );
    assert_ne!(
        plan.authority_sha512().map(|authority| hex(&authority)),
        Some(sha512_digest.hex()),
        "the authority hash is over the keys, not the metadata"
    );
    // The two chained images share one key, which the authority hash keeps
    // twice: dropping the repeat changes the value.
    let deduped: Vec<&[u8]> = {
        let mut unique: Vec<&[u8]> = Vec::new();
        for key in &keys {
            if !unique.contains(&key.as_slice()) {
                unique.push(key.as_slice());
            }
        }
        unique
    };
    assert_ne!(
        sha512_concat(&deduped),
        sha512_concat(&keys.iter().map(Vec::as_slice).collect::<Vec<_>>())
    );

    let order: Vec<&str> = plan
        .ordered_images()
        .iter()
        .map(|image| image.name)
        .collect();
    assert_eq!(
        order,
        [
            "vbmeta",
            "boot",
            "dtbo",
            "recovery",
            "vbmeta_system",
            "vbmeta_vendor"
        ]
    );
    assert_eq!(
        plan.ordered_images()
            .iter()
            .map(|image| image.metadata.len())
            .collect::<Vec<_>>(),
        [8448, 2368, 2240, 2240, 2624, 1856]
    );

    // The properties the ABL prefers come from the boot metadata.
    assert_eq!(plan.properties().os_version.as_deref(), Some("16"));
    assert_eq!(
        plan.properties().security_patch.as_deref(),
        Some("2026-08-01")
    );
    assert_eq!(
        plan.properties_source(),
        "from the boot metadata properties the ABL prefers"
    );

    // Hash-descriptor partitions: the ones libavb would load and hash in full.
    assert_eq!(
        plan.payload_hashed(),
        [
            "init_boot",
            "vendor_boot",
            "boot",
            "dtbo",
            "recovery",
            "pvmfw"
        ]
    );
    // Coverage evidence for the identity check.
    let covered = plan.covered();
    let system_covered = covered
        .iter()
        .find(|(name, _)| name == "vbmeta_system")
        .expect("system coverage");
    assert_eq!(
        system_covered.1,
        ["pvmfw", "product", "system", "system_ext"]
    );
    let vendor_covered = covered
        .iter()
        .find(|(name, _)| name == "vbmeta_vendor")
        .expect("vendor coverage");
    assert_eq!(vendor_covered.1, ["vendor"]);
}

#[test]
fn real_capture_flipped_bytes_are_rejected_with_the_right_verdict() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    if !Path::new(&format!("{CAPTURE}/boot_a.img")).is_file() {
        eprintln!("SKIP: required capture is absent: {CAPTURE}/boot_a.img");
        return;
    }
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);

    // A flipped byte in the stored hash is a hash mismatch: the hash covers the
    // header and the whole auxiliary block.
    let info = inspect(&root).unwrap();
    let hash_at = 256 + info.header.hash_offset as usize;
    let mut broken_root = root.clone();
    broken_root[hash_at + 3] ^= 0x40;
    assert_eq!(
        Plan::anchored(&broken_root, &keys).unwrap_err(),
        Verdict::HashMismatch
    );

    // A corrupted descriptor length is caught structurally, before any crypto.
    let descriptors_at =
        256 + info.header.auth_size as usize + info.header.descriptors_offset as usize;
    let mut broken_descriptor = root.clone();
    broken_descriptor[descriptors_at + 10] ^= 0x40;
    assert!(matches!(
        Plan::anchored(&broken_descriptor, &keys).unwrap_err(),
        Verdict::Malformed(_)
    ));

    // A flipped byte in the signature is a signature mismatch.
    let info = inspect(&system).unwrap();
    let signature_at = 256 + info.header.signature_offset as usize;
    let mut broken_signature = system.clone();
    broken_signature[signature_at + 8] ^= 0x01;
    let mut plan = Plan::anchored(&root, &keys).unwrap();
    assert_eq!(
        plan.supply("vbmeta_system", &broken_signature)
            .unwrap_err()
            .verdict,
        Verdict::SignatureMismatch
    );
    assert!(!plan.complete());
    assert_eq!(plan.rejected().len(), 1);

    // A flipped byte in a footered image's metadata is a hash mismatch.
    let mut metadata = footered_metadata(&format!("{CAPTURE}/boot_a.img"));
    let boot_hash_at = 256 + inspect(&metadata).unwrap().header.hash_offset as usize;
    metadata[boot_hash_at] ^= 0x08;
    let mut plan = Plan::anchored(&root, &keys).unwrap();
    assert_eq!(
        plan.supply("boot", &metadata).unwrap_err().verdict,
        Verdict::HashMismatch
    );
}

#[test]
fn real_capture_vendor_bytes_under_the_system_name_are_rejected() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    let Some(vendor) = read(&format!("{CHAINS}/vbmeta_vendor_b.img")) else {
        return;
    };
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);

    // Both images are signed by the *same* key, so the key comparison cannot
    // separate them; the rejection comes from signed coverage.
    assert_eq!(
        inspect(&system).unwrap().public_key_sha256,
        inspect(&vendor).unwrap().public_key_sha256
    );

    let mut plan = Plan::anchored(&root, &keys).unwrap();
    let rejected = plan.supply("vbmeta_system", &vendor).unwrap_err();
    assert_eq!(
        rejected.verdict,
        Verdict::WrongPartition {
            need: "vbmeta_system".to_owned(),
            covered: vec!["vendor".to_owned()],
        }
    );
    // The same bytes under their own name verify.
    let mut plan = Plan::anchored(&root, &keys).unwrap();
    assert!(plan.supply("vbmeta_vendor", &vendor).is_ok());
    assert!(plan.supply("vbmeta_system", &system).is_ok());
}

#[test]
fn real_capture_unanchored_and_foreign_key_root() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    let root_key = sha256(&inspect(&root).unwrap().public_key);

    // Without an ABL key the root is reported UNANCHORED, not silently trusted.
    let plan = Plan::new(&root).expect("the root self-verifies");
    assert_eq!(
        plan.root_verdict(),
        &Verdict::Verified {
            key_sha256: root_key,
            anchored: false,
        }
    );
    assert!(!plan.is_anchored());

    // A different (real, well-formed) key as the anchor is a key mismatch.
    let system_key = inspect(&system).unwrap().public_key;
    let foreign = AblKey {
        file_offset: 0,
        num_bits: 2048,
        sha256: sha256(&system_key),
        blob: system_key.clone(),
    };
    assert_eq!(
        Plan::anchored(&root, &AblKeys::from_keys(vec![foreign.clone()])).unwrap_err(),
        Verdict::KeyMismatch {
            expected: sha256(&system_key),
            actual: root_key,
        }
    );
    assert_eq!(
        Plan::anchored(&root, &AblKeys::default()).unwrap_err(),
        Verdict::Malformed(Defect::NoAnchorKey)
    );

    // FIRST-KEY RULE: a root signed by a key that is *embedded* but not the
    // first is UNANCHORED — never silently anchored — and only an explicit
    // `extra_trusted` entry makes it anchored. The real pair is used with the
    // roles swapped, so both keys are genuine AVB keys in file order.
    let later = AblKey {
        file_offset: CANOE_KEY_OFFSET,
        num_bits: 4096,
        sha256: root_key,
        blob: inspect(&root).unwrap().public_key,
    };
    let keys = AblKeys::from_keys(vec![foreign.clone(), later.clone()]);
    let unanchored = Plan::anchored(&root, &keys).unwrap_err();
    assert_eq!(
        unanchored,
        Verdict::Verified {
            key_sha256: root_key,
            anchored: false,
        },
        "a root signed by a later embedded key must be UNANCHORED"
    );
    assert!(unanchored.anchored() == Some(false));
    assert!(unanchored.is_verified(), "it still self-verifies");

    // The explicit opt-in: the same later key, now trusted by the caller.
    let plan = Plan::anchored_with_extra(&root, &keys, &[later])
        .expect("the extra trusted key anchors the root");
    assert!(plan.is_anchored());
    assert_eq!(
        plan.trust_anchor().map(|key| key.sha256),
        Some(sha256(&system_key))
    );
    assert_eq!(plan.trusted_keys().len(), 2, "anchor first, then the extra");
    assert_eq!(plan.key_set().len(), 2, "both embedded keys stay reported");
}

#[test]
fn real_capture_root_signature_verifies_against_its_own_embedded_key() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let info = inspect(&root).unwrap();
    let auth_start = 256;
    let aux_start = auth_start + info.header.auth_size as usize;
    let digest = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&root[..256]);
        hasher.update(&root[aux_start..aux_start + info.header.aux_size as usize]);
        hasher.finalize().to_vec()
    };
    let stored = &root[auth_start + info.header.hash_offset as usize..][..digest.len()];
    assert_eq!(stored, digest.as_slice(), "stored hash covers header + aux");
    let signature = &root[auth_start + info.header.signature_offset as usize..]
        [..info.header.signature_size as usize];
    assert!(rsa_pkcs1_verify(
        &info.public_key,
        signature,
        &digest,
        HashAlg::Sha256
    ));
    let mut wrong = digest.clone();
    wrong[0] ^= 0x01;
    assert!(!rsa_pkcs1_verify(
        &info.public_key,
        signature,
        &wrong,
        HashAlg::Sha256
    ));
    assert!(!rsa_pkcs1_verify(
        &info.public_key,
        signature,
        &digest,
        HashAlg::Sha512
    ));
}

#[test]
fn real_capture_supply_reports_unknown_and_duplicate_partitions() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);
    let mut plan = Plan::anchored(&root, &keys).unwrap();
    assert_eq!(
        plan.supply("init_boot", &system).unwrap_err().verdict,
        Verdict::Malformed(Defect::UnknownPartition("init_boot".to_owned()))
    );
    assert!(plan.supply("vbmeta_system", &system).is_ok());
    assert_eq!(
        plan.supply("vbmeta_system", &system).unwrap_err().verdict,
        Verdict::Malformed(Defect::DuplicatePartition("vbmeta_system".to_owned()))
    );
    assert_eq!(plan.needs().len(), 4);
}

/// A slice-backed `read_at`, exactly the shape a file, a firmware-zip range, a
/// browser blob or a BlockIo handle presents to `avb-meta`.
fn reader(image: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), String> + '_ {
    move |at, out| {
        let start = usize::try_from(at).map_err(|_| "offset does not fit".to_owned())?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| "range overflow".to_owned())?;
        let part = image
            .get(start..end)
            .ok_or_else(|| "short read".to_owned())?;
        out.copy_from_slice(part);
        Ok(())
    }
}

#[test]
fn real_capture_reader_path_reproduces_the_recorded_digest() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let mut plan = Plan::anchored(&root, &abl_keys(&pe)).expect("anchored root");

    // Footered images: the metadata extent is located through the footer by the
    // helper, so no whole-partition buffer is needed by the walk itself.
    for name in ["boot", "dtbo", "recovery"] {
        let path = format!("{CAPTURE}/{name}_a.img");
        let Some(image) = read(&path) else {
            return;
        };
        let size = image.len() as u64;
        let accepted = plan
            .supply_from(name, size, reader(&image))
            .unwrap_or_else(|rejected| panic!("{name}: {rejected}"));
        assert!(accepted.anchored);
    }
    for (name, path) in [
        ("vbmeta_system", format!("{CHAINS}/vbmeta_system_b.img")),
        ("vbmeta_vendor", format!("{CHAINS}/vbmeta_vendor_b.img")),
    ] {
        let Some(image) = read(&path) else {
            return;
        };
        let size = image.len() as u64;
        plan.supply_from(name, size, reader(&image))
            .unwrap_or_else(|rejected| panic!("{name}: {rejected}"));
    }
    assert!(plan.complete());
    assert_eq!(plan.vbmeta_digest().hex(), EVIDENCE_VBH);
    assert_eq!(plan.vbmeta_digest().total_size, EVIDENCE_TOTAL);

    // A failing backing read is a typed rejection, not a panic.
    let mut plan = Plan::anchored(&root, &abl_keys(&pe)).unwrap();
    let rejected = plan
        .supply_from(
            "vbmeta_system",
            4096,
            |_, _: &mut [u8]| Err("io".to_owned()),
        )
        .unwrap_err();
    assert_eq!(
        rejected.verdict,
        Verdict::Malformed(Defect::Read("io".to_owned()))
    );
}

// --------------------------------------------------- the SHA-512 side (AOSP)

/// AOSP's own SHA-512-signed fixture, and the digest AOSP recorded for it.
///
/// `vbmeta_v4_v4_init_boot_a.digest.txt` is the `androidboot.vbmeta.digest` AOSP
/// libbootloader's test data records for that root, and it is exactly
/// SHA-512 over the root's 3712-byte extent — an expectation this crate did not
/// produce. The point of the test is that a SHA-512 root feeds **SHA-512** to
/// the cmdline while the ABL/TEE VBH over the same bytes stays SHA-256.
#[test]
fn sha512_root_matches_the_digest_aosp_recorded() {
    let Some(image) = read(&format!("{AOSP_SHA512_DIR}/vbmeta_v4_v4_init_boot_a.img")) else {
        return;
    };
    let recorded = match std::fs::read_to_string(format!(
        "{AOSP_SHA512_DIR}/vbmeta_v4_v4_init_boot_a.digest.txt"
    )) {
        Ok(text) => text.trim().to_owned(),
        Err(error) => {
            eprintln!("SKIP: no recorded digest beside the fixture: {error}");
            return;
        }
    };
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
    assert_eq!(plan.digest_algorithm(), HashAlg::Sha512);

    let cmdline = plan
        .libavb_cmdline_digest()
        .expect("libavb emits androidboot.vbmeta.* for this root");
    assert_eq!(cmdline.hash_alg, HashAlg::Sha512);
    assert_eq!(cmdline.size, image.len() as u64);
    assert_eq!(cmdline.name(), "sha512");
    assert_eq!(cmdline.hex(), recorded);
    assert_eq!(plan.vbmeta_digest_with(HashAlg::Sha512).hex(), recorded);

    // The ABL/TEE value over the same extent is the other hash.
    assert_eq!(plan.vbmeta_digest().algorithm, HashAlg::Sha256);
    assert_eq!(plan.vbmeta_digest().total_size, image.len() as u64);
    assert_ne!(plan.vbmeta_digest().hex(), recorded);
    assert_eq!(plan.vbmeta_digest().hex(), hex(&sha256(&image)));

    // One image, so the DICE authority is SHA-512 over its single key.
    assert_eq!(plan.authority_sha512(), Some(sha512(&info.public_key)));
}

/// libavb's cmdline hash switch, including the types this crate never verifies.
#[test]
fn libavb_hash_choice_matches_the_c_switch_and_a_disabled_root_emits_nothing() {
    // `avb_cmdline.c:306-359`: NONE and the SHA-256 RSA types — and both ML-DSA
    // types — are SHA-256; the SHA-512 RSA types are SHA-512; the C switch has
    // no default for anything else, and `_AVB_ALGORITHM_NUM_TYPES` traps.
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
    // The authentication-hash mapping is narrower on purpose: an ML-DSA image
    // carries no external hash, so it cannot be *verified* here at all.
    assert_eq!(HashAlg::from_algorithm_type(7), None);
    assert_eq!(HashAlg::from_algorithm_type(8), None);
    assert_eq!(HashAlg::from_algorithm_type(0), None);
    assert_eq!(HashAlg::from_algorithm_type(5), Some(HashAlg::Sha512));

    // A root that disables verification emits no `androidboot.vbmeta.*` at all
    // (`avb_slot_verify.c:1599-1601` skips `avb_append_options()` entirely), so
    // there is no digest to report even though the extents are known.
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let plain = Plan::new(&root).expect("the real root self-verifies");
    assert_eq!(
        plain.libavb_cmdline_digest().map(|digest| digest.hash_alg),
        Some(HashAlg::Sha256)
    );
    let mut disabled = root.clone();
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
    // The ABL's own SHA-256 value is still computable over what is supplied.
    assert_eq!(flagged.vbmeta_digest().algorithm, HashAlg::Sha256);
    assert_eq!(
        flagged.vbmeta_digest().hex(),
        hex(&sha256(
            &disabled[..inspect(&disabled).expect("header").size]
        ))
    );
}
