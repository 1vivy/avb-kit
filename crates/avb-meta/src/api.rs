//! A flat, owned projection of this crate for binding generators.
//!
//! Everything here is deliberately simple enough for `flutter_rust_bridge`-style
//! codegen to consume without hints: plain structs and `String`/`Vec` fields, no
//! lifetimes, no references in the public edge types, no serde, and no new
//! dependencies. It is a thin projection over the typed API — [`crate::Plan`] and
//! [`crate::abl_keys`] — not a second implementation: every field is a `Display`
//! string or a scalar taken from a verdict or a key the typed API already
//! produced.
//!
//! Feature `api` (off by default) enables it; it requires `verify`, because the
//! walk cannot exist without signature verification. Fallible entry points
//! return [`ApiError`] (a code plus a message); nothing here panics on hostile
//! input, since every read is bounds-checked in the layers below.
//!
//! This surface is **provision only**: what a device should be served, and when
//! a stored image must replace an on-slot one, is a consumer's policy (ablwrap's
//! `ablwrap-resolve`), so there is no `resolve` here.
//!
//! ```text
//! needs(root, abl_pe)                       -> NeedsReport     (what is missing)
//! supply(root, abl_pe, images)              -> NeedsReport     (after supplying)
//! abl_keys_report(pe)                       -> Vec<KeyInfo>    (the trust anchor)
//! ```

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Plan;
use crate::rsa::AblKeys;

/// A plain error: a stable machine-readable code plus a human message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

/// One partition image supplied to [`supply`], as raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuppliedImage {
    /// Base partition name, without an `_a`/`_b` suffix.
    pub name: String,
    /// The whole partition image, exactly as read from the device or a firmware
    /// image: a `vbmeta*` image (padding included) or a footered partition.
    pub bytes: Vec<u8>,
}

/// One AVB key recovered from an ABL image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyInfo {
    pub file_offset: usize,
    pub num_bits: u32,
    pub sha256_hex: String,
    /// True for the **first** key in file order: the ABL's trust anchor, the one
    /// the stock `AvbValidateVbmetaPublicKey` byte-compares against.
    pub is_anchor: bool,
}

/// One discovered partition, in the walk's visit order, with its status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeedInfo {
    pub name: String,
    pub kind: String,
    pub rollback_index_location: u32,
    /// SHA-256 of the key the parent's chain descriptor demands, as hex.
    pub demanded_key_sha256_hex: String,
    /// `"missing"`, `"accepted"` or `"rejected: <verdict>"`.
    pub status: String,
}

/// A supplied image that verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedInfo {
    pub name: String,
    pub kind: String,
    pub metadata_len: usize,
    pub metadata_sha256_hex: String,
    pub key_sha256_hex: String,
    pub anchored: bool,
    /// Position in the walk's visit order.
    pub index: usize,
}

/// A supplied image that did not verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedInfo {
    pub name: String,
    pub verdict: String,
}

/// The state of a walk: what it discovered, what it has, and the digest once
/// every image is supplied and verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeedsReport {
    /// The root's verdict as a string (`verified against key … (anchored)`,
    /// `hash mismatch`, …).
    pub root_verdict: String,
    /// Whether the root's key is the ABL's first embedded key.
    pub anchored: bool,
    /// Every discovered partition in visit order — the root excluded — whether it
    /// was supplied or not.
    pub needs: Vec<NeedInfo>,
    /// Partitions named by a hash descriptor: the ABL hashes their payload and
    /// the wrapper never substitutes a vbmeta for them.
    pub payload_hashed: Vec<String>,
    pub os_version: Option<String>,
    pub security_patch: Option<String>,
    pub accepted: Vec<AcceptedInfo>,
    pub rejected: Vec<RejectedInfo>,
    pub missing: Vec<String>,
    /// Every discovered image is supplied and verified. Combine with
    /// `anchored`: an unanchored set can be complete without being trusted.
    pub complete: bool,
    /// The ABL/TEE VBH: SHA-256 over the ordered exact extents, once `complete`
    /// (`SET_VBH`; always SHA-256 whatever the metadata is signed with).
    pub digest_hex: Option<String>,
    /// `androidboot.vbmeta.size`, once `complete`.
    pub size: Option<u64>,
    /// The same ordered extents hashed with SHA-512, once `complete`. This is the
    /// profile `vbmeta_sha512`.
    pub sha512_hex: Option<String>,
    /// The AVF DICE authority: SHA-512 over every supplied image's embedded
    /// public key in visit order, once `complete`. This is the profile `authority_sha512`.
    /// `None` until every image is supplied and verified.
    pub authority_sha512_hex: Option<String>,
    /// `androidboot.vbmeta.hash_alg` (`"sha256"`/`"sha512"`) as libavb would
    /// emit it, chosen by the **root's** algorithm, once `complete`; `None` while
    /// the set is incomplete and when libavb emits no `androidboot.vbmeta.*` at
    /// all (the root disables verification, or its algorithm is one libavb's
    /// switch does not cover).
    pub libavb_hash_alg: Option<String>,
    /// `androidboot.vbmeta.digest` as libavb would emit it, once `complete` —
    /// note this is **not** [`NeedsReport::digest_hex`]: it is hashed with
    /// [`NeedsReport::libavb_hash_alg`].
    pub libavb_digest_hex: Option<String>,
    /// `androidboot.vbmeta.size` as libavb would emit it, once `complete`.
    pub libavb_size: Option<u64>,
}

/// Every AVB key in `pe`, in file order, with the trust anchor marked.
///
/// Never fails: an image with no key yields an empty vector.
pub fn abl_keys_report(pe: Vec<u8>) -> Vec<KeyInfo> {
    let keys = crate::abl_keys(&pe);
    keys.keys()
        .iter()
        .enumerate()
        .map(|(index, key)| KeyInfo {
            file_offset: key.file_offset,
            num_bits: key.num_bits,
            sha256_hex: crate::hex(&key.sha256),
            is_anchor: index == 0,
        })
        .collect()
}

/// Walk `root` and report what is still needed.
///
/// `abl_pe` is the ABL image the keys are recovered from; `None` reports the
/// root as unanchored. The walk is structural, so a root that does not anchor
/// still yields its needs list, with a `root_verdict` that says so.
pub fn needs(root: Vec<u8>, abl_pe: Option<Vec<u8>>) -> Result<NeedsReport, ApiError> {
    report(root, abl_pe, &[])
}

/// [`needs`], with `images` supplied and verified.
///
/// Stateless on purpose: the same root plus an accumulating list of images
/// returns the updated report, so a caller can add one image at a time.
pub fn supply(
    root: Vec<u8>,
    abl_pe: Option<Vec<u8>>,
    images: &[SuppliedImage],
) -> Result<NeedsReport, ApiError> {
    report(root, abl_pe, images)
}

fn report(
    root: Vec<u8>,
    abl_pe: Option<Vec<u8>>,
    images: &[SuppliedImage],
) -> Result<NeedsReport, ApiError> {
    let keys = abl_pe.map(|pe| crate::abl_keys(&pe)).unwrap_or_default();
    let (mut plan, root_verdict) = open(&root, &keys)?;
    for image in images {
        // Both outcomes are recorded in the plan and reported below; the image
        // may be a whole partition, so the footer path is used when it applies.
        let _ = plan.supply_from(&image.name, image.bytes.len() as u64, |at, out| {
            let start = usize::try_from(at).map_err(|_| "offset does not fit".to_string())?;
            let end = start
                .checked_add(out.len())
                .ok_or_else(|| "range overflow".to_string())?;
            let slice = image
                .bytes
                .get(start..end)
                .ok_or_else(|| "short read".to_string())?;
            out.copy_from_slice(slice);
            Ok::<(), String>(())
        });
    }
    Ok(build_report(&plan, root_verdict))
}

/// Open a plan over `root`, with the string the caller should see as its verdict.
///
/// With keys, the root must anchor; when it does not, that refusal is the
/// reported verdict and the structural walk is still performed, so a caller can
/// ask "what would this root need?" without pretending it is trusted.
fn open(root: &[u8], keys: &AblKeys) -> Result<(Plan, String), ApiError> {
    match Plan::anchored(root, keys) {
        Ok(plan) => {
            let verdict = plan.root_verdict().to_string();
            Ok((plan, verdict))
        }
        Err(_verdict) if keys.is_empty() => {
            let plan = Plan::new_unverified(root)
                .map_err(|defect| ApiError::new("malformed", defect.to_string()))?;
            let verdict = plan.root_verdict().to_string();
            Ok((plan, verdict))
        }
        Err(verdict) => {
            let refused = verdict.to_string();
            let plan = Plan::new_unverified(root)
                .map_err(|defect| ApiError::new("malformed", defect.to_string()))?;
            Ok((plan, refused))
        }
    }
}

fn build_report(plan: &Plan, root_verdict: String) -> NeedsReport {
    let images = plan.ordered_images();
    let accepted: Vec<AcceptedInfo> = images
        .iter()
        .filter(|image| image.verdict.is_verified())
        .enumerate()
        .map(|(index, image)| AcceptedInfo {
            name: image.name.to_string(),
            kind: image.kind.name().to_string(),
            metadata_len: image.metadata.len(),
            metadata_sha256_hex: crate::hex(&image.metadata_sha256),
            key_sha256_hex: crate::hex(&image.key_sha256),
            anchored: image.anchored,
            index,
        })
        .collect();
    let rejected: Vec<RejectedInfo> = plan
        .rejected()
        .into_iter()
        .map(|(name, verdict)| RejectedInfo {
            name,
            verdict: verdict.to_string(),
        })
        .collect();
    let needs: Vec<NeedInfo> = plan
        .walk_order()
        .into_iter()
        .filter(|node| node.name != crate::ROOT_NAME)
        .map(|node| {
            let status = if accepted.iter().any(|entry| entry.name == node.name) {
                "accepted".to_string()
            } else if let Some(entry) = rejected.iter().find(|entry| entry.name == node.name) {
                format!("rejected: {}", entry.verdict)
            } else {
                "missing".to_string()
            };
            NeedInfo {
                name: node.name.to_string(),
                kind: node.kind.name().to_string(),
                rollback_index_location: node.rollback_index_location,
                demanded_key_sha256_hex: node
                    .expected_key_sha256
                    .map(|key| crate::hex(&key))
                    .unwrap_or_default(),
                status,
            }
        })
        .collect();
    let properties = plan.properties();
    let complete = plan.complete();
    // The ABL/TEE VBH is always SHA-256. The SHA-512 variant over the same
    // ordered extents is the profile `vbmeta_sha512`. The libavb cmdline pair
    // uses the root's algorithm, and is absent when the root disables
    // verification. All three describe a complete set, so none is reported
    // from a partial one: a partial hash under a "the digest" name would be
    // worse than no value.
    let digest = complete.then(|| plan.vbmeta_digest());
    let sha512 = complete.then(|| plan.vbmeta_digest_with(crate::HashAlg::Sha512));
    let authority = plan
        .authority_sha512()
        .map(|authority| crate::hex(&authority));
    let cmdline = if complete {
        plan.libavb_cmdline_digest()
    } else {
        None
    };
    NeedsReport {
        root_verdict,
        anchored: plan.is_anchored(),
        needs,
        payload_hashed: plan.payload_hashed(),
        os_version: properties.os_version,
        security_patch: properties.security_patch,
        accepted,
        rejected,
        missing: plan.missing(),
        complete,
        digest_hex: digest.as_ref().map(|digest| digest.hex()),
        size: digest.map(|digest| digest.total_size),
        sha512_hex: sha512.map(|digest| digest.hex()),
        authority_sha512_hex: authority,
        libavb_hash_alg: cmdline.as_ref().map(|digest| digest.name().to_owned()),
        libavb_digest_hex: cmdline.as_ref().map(|digest| digest.hex()),
        libavb_size: cmdline.map(|digest| digest.size),
    }
}

#[cfg(all(test, feature = "api", feature = "std"))]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use std::eprintln;
    use std::path::Path;

    const CAPTURE: &str = "/home/vivy/Projects/efisp-projects/gbl_root_canoe/.work/recovery-diagnosis-20260906/device";
    const LATER: &str = "/home/vivy/Projects/efisp-projects/.work/phone-layout/20261004T013922Z";
    const CANOE_PE: &str =
        "/home/vivy/Ghidra/inputs/canoe-abl-parallel-20260902/abl_b.LinuxLoader.efi";
    const EVIDENCE_VBH: &str = "bc9bbd83c4be79f36d5c9b1724a865f83d8c26c3c76f96abe4c7fd082d7ccc47";
    const EVIDENCE_TOTAL: u64 = 19776;
    const ANCHOR_KEY: &str = "8d897f62492ea617f777bad41a5711ab621fcac1efc1865b890328ee8c3853bb";
    const ANCHOR_OFFSET: usize = 452022;

    fn read(path: &str) -> Option<Vec<u8>> {
        let path = Path::new(path);
        if !path.is_file() {
            eprintln!("SKIP: required capture is absent: {}", path.display());
            return None;
        }
        Some(std::fs::read(path).expect("capture is readable"))
    }

    /// The six real images of one OEM generation, or `None` with the exact
    /// missing path printed.
    fn fixture() -> Option<(Vec<u8>, Vec<SuppliedImage>)> {
        let names = [
            ("vbmeta_a.img", CAPTURE),
            ("boot_a.img", CAPTURE),
            ("dtbo_a.img", CAPTURE),
            ("recovery_a.img", CAPTURE),
            ("vbmeta_system_b.img", LATER),
            ("vbmeta_vendor_b.img", LATER),
        ];
        for (name, directory) in names {
            if !Path::new(&format!("{directory}/{name}")).is_file() {
                eprintln!("SKIP: required capture is absent: {directory}/{name}");
                return None;
            }
        }
        let root = std::fs::read(format!("{CAPTURE}/vbmeta_a.img")).expect("root");
        let images = vec![
            SuppliedImage {
                name: "boot".to_owned(),
                bytes: std::fs::read(format!("{CAPTURE}/boot_a.img")).expect("boot"),
            },
            SuppliedImage {
                name: "dtbo".to_owned(),
                bytes: std::fs::read(format!("{CAPTURE}/dtbo_a.img")).expect("dtbo"),
            },
            SuppliedImage {
                name: "recovery".to_owned(),
                bytes: std::fs::read(format!("{CAPTURE}/recovery_a.img")).expect("recovery"),
            },
            SuppliedImage {
                name: "vbmeta_system".to_owned(),
                bytes: std::fs::read(format!("{LATER}/vbmeta_system_b.img")).expect("system"),
            },
            SuppliedImage {
                name: "vbmeta_vendor".to_owned(),
                bytes: std::fs::read(format!("{LATER}/vbmeta_vendor_b.img")).expect("vendor"),
            },
        ];
        Some((root, images))
    }

    #[test]
    fn needs_then_supply_reaches_the_recorded_digest() {
        let Some((root, mut images)) = fixture() else {
            return;
        };
        let Some(pe) = read(CANOE_PE) else {
            return;
        };

        // The trust anchor, from the flat key report.
        let keys = abl_keys_report(pe.clone());
        let anchor = keys.first().expect("the ABL has at least one key");
        assert!(anchor.is_anchor);
        assert_eq!(anchor.sha256_hex, ANCHOR_KEY);
        assert_eq!(anchor.file_offset, ANCHOR_OFFSET);
        assert_eq!(anchor.num_bits, 4096);
        assert!(keys.iter().skip(1).all(|key| !key.is_anchor));

        // What is needed, before anything is supplied.
        let report = needs(root.clone(), Some(pe.clone())).expect("the real root walks");
        assert!(report.anchored);
        assert!(!report.complete);
        assert_eq!(
            report
                .needs
                .iter()
                .map(|need| need.name.as_str())
                .collect::<Vec<_>>(),
            ["boot", "dtbo", "recovery", "vbmeta_system", "vbmeta_vendor"]
        );
        assert_eq!(report.needs[0].kind, "footered");
        assert_eq!(report.needs[3].kind, "vbmeta");
        assert_eq!(report.needs[3].rollback_index_location, 2);
        assert!(report.needs.iter().all(|need| need.status == "missing"));
        assert_eq!(report.needs[0].demanded_key_sha256_hex, ANCHOR_KEY);
        // Before anything is supplied, only the root's own hash descriptors are
        // visible; the chained images contribute the rest once supplied.
        assert_eq!(report.payload_hashed, ["init_boot", "vendor_boot"]);
        assert_eq!(report.os_version.as_deref(), Some("16"));
        assert_eq!(report.security_patch.as_deref(), Some("2026-08-01"));
        assert!(report.root_verdict.contains("anchored"), "{report:?}");
        assert!(report.digest_hex.is_none());
        // The three digests all describe a complete set, so none is reported
        // from a partial one — not even libavb's hash-algorithm choice.
        assert!(report.sha512_hex.is_none(), "{report:?}");
        assert!(report.authority_sha512_hex.is_none(), "{report:?}");
        assert!(report.libavb_hash_alg.is_none(), "{report:?}");
        assert!(report.libavb_digest_hex.is_none(), "{report:?}");
        assert!(report.libavb_size.is_none(), "{report:?}");

        // Supply them in reverse order: the walk's order is not arrival order.
        images.reverse();
        let report = supply(root.clone(), Some(pe), &images).expect("supplied images are judged");
        assert!(report.complete, "rejected: {:?}", report.rejected);
        assert!(report.accepted.len() == 6);
        assert!(report.missing.is_empty());
        assert!(report.needs.iter().all(|need| need.status == "accepted"));
        assert_eq!(report.digest_hex.as_deref(), Some(EVIDENCE_VBH));
        assert_eq!(report.size, Some(EVIDENCE_TOTAL));
        // The same extents, hashed the other way, and the root's own algorithm:
        // this capture is SHA-256-signed, so libavb's cmdline digest is the
        // SHA-256 one and the SHA-512 value is a different 128-character digest.
        assert_eq!(report.libavb_hash_alg.as_deref(), Some("sha256"));
        assert_eq!(report.libavb_digest_hex.as_deref(), Some(EVIDENCE_VBH));
        assert_eq!(report.libavb_size, Some(EVIDENCE_TOTAL));
        let sha512 = report.sha512_hex.as_deref().expect("a complete set");
        assert_eq!(sha512.len(), 128);
        assert_ne!(sha512, EVIDENCE_VBH);
        // The DICE authority: SHA-512 over the six embedded public keys.
        let authority = report
            .authority_sha512_hex
            .as_deref()
            .expect("a complete, verified set");
        assert_eq!(authority.len(), 128);
        assert_ne!(authority, sha512);
        assert_eq!(
            report.payload_hashed,
            [
                "init_boot",
                "vendor_boot",
                "boot",
                "dtbo",
                "recovery",
                "pvmfw"
            ]
        );
        assert_eq!(
            report
                .accepted
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [
                "vbmeta",
                "boot",
                "dtbo",
                "recovery",
                "vbmeta_system",
                "vbmeta_vendor"
            ]
        );

        // A rejected image is a status, not a panic: flip a byte of the stored
        // authentication hash, which the footer locates.
        let mut broken = images.clone();
        let boot = broken
            .iter_mut()
            .find(|image| image.name == "boot")
            .expect("boot is in the set");
        let size = boot.bytes.len() as u64;
        let footer = avb_graft::parse_footer(&boot.bytes[boot.bytes.len() - 64..], size)
            .expect("the stock image has a valid footer");
        let hash_at = footer.vbmeta_offset as usize + 256;
        boot.bytes[hash_at] ^= 0x01;
        let report = supply(root, Some(read(CANOE_PE).expect("pe")), &broken).expect("judged");
        assert!(!report.complete);
        let status = &report
            .needs
            .iter()
            .find(|need| need.name == "boot")
            .expect("boot is needed")
            .status;
        assert!(status.starts_with("rejected:"), "{status}");
    }

    #[test]
    fn hostile_input_is_a_typed_error_not_a_panic() {
        // Not a vbmeta image at all.
        let error = needs(vec![0u8; 16], None).expect_err("garbage is refused");
        assert!(error.code == "malformed", "{error:?}");
        assert!(!error.message.is_empty());

        let error = needs(Vec::new(), Some(vec![0u8; 32])).expect_err("empty root");
        assert_eq!(error.code, "malformed");

        let Some((root, _)) = fixture() else {
            return;
        };

        // A root that verifies but is not anchored when no keys are supplied:
        // the walk still reports its needs, and the verdict says UNANCHORED.
        let report = needs(root, None).expect("no keys: structural walk");
        assert!(!report.anchored);
        assert!(report.root_verdict.contains("UNANCHORED"), "{report:?}");
        assert_eq!(report.needs.len(), 5);

        // The refusal path (no anchor key, neither candidate verifying, a stored
        // set that does not verify) is policy and is tested where it lives:
        // ablwrap's `ablwrap-resolve` crate.
    }
}
