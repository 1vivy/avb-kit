//! Portable AVB metadata walking, authentication and embedded ABL key discovery.
//!
//! This crate is the one place that answers "which images does this root
//! `vbmeta` need, and are the ones I have the right ones?". It uses `std` but no
//! filesystem, no threads and no environment, so it builds for
//! `wasm32-unknown-unknown` as well as for the host.
//!
//! # The walk, and why it is a walk
//!
//! libavb's `load_and_verify_vbmeta()` loads one vbmeta image, **appends it to
//! `vbmeta_images`**, and only then walks that image's descriptors in order,
//! recursing into every `AVB_DESCRIPTOR_TAG_CHAIN_PARTITION` descriptor. Each
//! recursive call appends its own image before walking that image's descriptors,
//! so `vbmeta_images` is a depth-first pre-order traversal in descriptor order.
//! Two hashes are taken over those images in exactly that order, using each
//! image's *exact* extent (`256 + authentication_data_block_size +
//! auxiliary_data_block_size`) with no partition padding, and they are not the
//! same value:
//!
//! * the OEM ABL's own VBH (`SET_VBH`, and what KeyMint's rollback compares
//!   against) is **always SHA-256** — [`Plan::vbmeta_digest`];
//! * `androidboot.vbmeta.digest` is what libavb's `avb_append_options()` writes,
//!   hashed with the **root's** algorithm: SHA-256 for a SHA-256 (or ML-DSA)
//!   root, SHA-512 for a SHA-512 root, and nothing at all when the root disables
//!   verification — [`Plan::libavb_cmdline_digest`]; [`Plan::vbmeta_digest_with`]
//!   takes either hash explicitly.
//!
//! Source: `.refs/mu_aloha_platforms/Platforms/QcomModulePkg/Library/avb/libavb/
//! avb_slot_verify.c` — append-before-recursion at lines ~725-750, the
//! descriptor loop at ~790, the recursive chain call at ~853-865, and the digest
//! loop at ~1249-1255. Two deliberate differences from that file, stated so that
//! nothing is implied about it:
//!
//! * that source **rejects** a chain descriptor found in a non-main image
//!   (~822-829); this crate recurses instead, as the owner requires, so a
//!   chained vbmeta may itself chain further images;
//! * libavb appends an image that two different parents both demand, hashing it
//!   twice; this crate refuses the duplicate
//!   ([`Defect::DuplicatePartition`]) rather than silently double-counting.
//!
//! Whether a name is a whole-partition vbmeta or a footer-located metadata
//! extent is libavb's own rule (~429-435): names starting with `vbmeta` are
//! whole-partition, every other name is located through the 64-byte footer, with
//! a start-of-partition fallback in that source when no valid footer exists.
//!
//! # Anchoring
//!
//! The OEM root key is embedded in the ABL image, and the ABL byte-compares the
//! root `vbmeta`'s public key against it: the stock `AvbValidateVbmetaPublicKey`
//! trusts only the **first** embedded key. [`abl_keys`] recovers every such key
//! from an image by
//! structure alone, in file order, and [`AblKeys::anchor`] is the first one.
//! [`Plan::anchored`] accepts the root only when its embedded key is that
//! anchor; a root signed by a *later* embedded key is reported
//! `Verified { anchored: false }` — UNANCHORED, never silently trusted — unless
//! the caller states that it trusts that key through
//! [`Plan::anchored_with_extra`]. A root that was never compared against an ABL
//! key at all (no key set supplied) is reported UNANCHORED too.
//!
//! Chained images verify against their parent's chain-descriptor key: the
//! authentication block is checked exactly as `avb_vbmeta_image_verify()` does
//! (hash over header+auxiliary block, then the RSA signature), and the signing
//! key is then compared byte-for-byte with the key the parent demanded.
//!
//! # Substitution policy is a consumer's, not this crate's
//!
//! This crate **provides** primitives; it does not decide what a device should
//! be served. A launch-time resolver — ablwrap's `avb=auto` rule, on-slot first
//! and the whole stored set when the root does not verify — is `ablwrap`'s own
//! policy and lives in its `ablwrap-resolve` crate, built only on the public
//! primitives here: [`Plan::anchored`] for the root, [`Plan::needs`] for visit
//! order, [`Plan::judge`] to compare a candidate against the demand without
//! recording it, [`Plan::supply`] to record the choice, [`extract_vbmd`] to lift
//! a footered partition's metadata, [`Plan::vbmeta_digest`] for the ABL's own
//! SHA-256 VBH and [`Plan::libavb_cmdline_digest`] for what libavb would put in
//! `androidboot.vbmeta.digest`.
//!
//! # What is *not* cryptographic, and is not claimed to be
//!
//! AVB does not bind a partition name to a vbmeta image. Two chained images
//! signed by the same key are interchangeable to libavb: on the real canoe
//! capture `vbmeta_system` and `vbmeta_vendor` carry the *same* 2048-bit key
//! (`1aef65cb…`), so a key comparison cannot tell them apart. [`Verdict::
//! WrongPartition`] therefore comes from the image's own signed descriptor
//! coverage: a demanded `vbmeta_<group>` must declare coverage for `<group>`, and
//! any other demanded partition must be covered by name. That is avbtool's group
//! convention, not a signature check, and it is skipped when the metadata names
//! no partition at all (property-only metadata). [`Plan::covered`] exposes the
//! evidence for a caller that wants to judge for itself.
//!
//! # Limits, taken from the reference
//!
//! [`VBMETA_MAX_SIZE`] (64 KiB) bounds one metadata extent and
//! [`MAX_VBMETA_IMAGES`] (32) bounds the number of images, matching
//! `avb_slot_verify.c`. Nothing here panics on hostile input: every read is
//! bounds-checked and every size is computed with checked arithmetic.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

/// `std` is used only for `std::error::Error` implementations.
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "api")]
pub mod api;
pub mod meta;
#[cfg(feature = "verify")]
pub mod plan;
pub mod rsa;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "digest")]
use sha2::{Digest, Sha256};

pub use meta::{
    ChainDescriptor, DESCRIPTOR_TAG_CHAIN_PARTITION, DESCRIPTOR_TAG_HASH, DESCRIPTOR_TAG_HASHTREE,
    DESCRIPTOR_TAG_KERNEL_CMDLINE, DESCRIPTOR_TAG_PROPERTY, Defect, HEADER_SIZE, Header,
    MAX_VBMETA_IMAGES, VBMETA_FLAG_HASHTREE_DISABLED, VBMETA_FLAG_VERIFICATION_DISABLED,
    VBMETA_MAX_SIZE, VbmetaInfo, exact_metadata, inspect, vbmeta_entry,
};
#[cfg(feature = "digest")]
pub use plan::{CmdlineDigest, VbmetaDigest};
#[cfg(feature = "verify")]
pub use plan::{ExtractError, Plan, ROOT_NAME, WalkNode, extract_vbmd};
#[cfg(feature = "verify")]
pub use rsa::rsa_pkcs1_verify;
pub use rsa::{AblKey, AblKeys, RSA_KEY_HEADER_SIZE, abl_keys, key_blob_len};

/// Which hash a digest is taken with, chosen explicitly.
///
/// Two different hashes are in play in AVB and they are not interchangeable:
///
/// * the **authentication hash** of one image, which is whatever the image's own
///   `algorithm_type` says (`from_algorithm_type`), and
/// * the **cmdline digest** over the ordered image set, which libavb derives from
///   the *root's* `algorithm_type` (`libavb_cmdline`) — the Qualcomm ABL's own
///   `SET_VBH` is SHA-256 over the same ordered set regardless
///   ([`Plan::vbmeta_digest`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlg {
    Sha256,
    Sha512,
}

impl HashAlg {
    /// The hash of an `algorithm_type`, or `None` for NONE and for the ML-DSA
    /// types (which carry no external hash and are not verified here).
    pub fn from_algorithm_type(value: u32) -> Option<Self> {
        match value {
            1..=3 => Some(Self::Sha256),
            4..=6 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// libavb's choice of `androidboot.vbmeta.digest` for a *root's*
    /// `algorithm_type`, exactly as `avb_append_options()` switches on it
    /// (`external/avb/libavb/avb_cmdline.c:306-359`):
    ///
    /// * `NONE` and the SHA-256 RSA types — **and both ML-DSA types** — use
    ///   SHA-256;
    /// * the SHA-512 RSA types use SHA-512;
    /// * any other value emits nothing (the C switch has no default, and
    ///   `_AVB_ALGORITHM_NUM_TYPES` traps), so this returns `None`.
    ///
    /// This is *not* the authentication hash: an ML-DSA-signed root feeds a
    /// SHA-256 cmdline digest even though its own authentication block has no
    /// external hash at all.
    pub fn libavb_cmdline(algorithm_type: u32) -> Option<Self> {
        match algorithm_type {
            0..=3 | 7 | 8 => Some(Self::Sha256),
            4..=6 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Digest length in bytes.
    pub fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Whether this algorithm emits an empty digest.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// `"sha256"` or `"sha512"`, as `androidboot.vbmeta.hash_alg` spells it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Signature size in bytes for the RSA variant of this algorithm type.
    pub fn key_bytes(algorithm_type: u32) -> Option<usize> {
        match algorithm_type {
            1 | 4 => Some(256),
            2 | 5 => Some(512),
            3 | 6 => Some(1024),
            _ => None,
        }
    }
}

/// A digest selected at run time, without a trait object.
#[cfg(feature = "digest")]
pub(crate) enum Hasher {
    Sha256(Sha256),
    Sha512(sha2::Sha512),
}

#[cfg(feature = "digest")]
impl Hasher {
    pub(crate) fn new(algorithm: HashAlg) -> Self {
        match algorithm {
            HashAlg::Sha256 => Self::Sha256(Sha256::new()),
            HashAlg::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha512(hasher) => hasher.update(bytes),
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// The `com.android.build.boot.*` property the observed canoe ABL prefers over
/// the boot header (`evidence/emu-report.md` section 5).
pub const OS_VERSION_KEY: &str = "com.android.build.boot.os_version";
/// Companion security-patch property.
pub const SECURITY_PATCH_KEY: &str = "com.android.build.boot.security_patch";

/// Which partition class a demanded image belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Kind {
    /// A whole `vbmeta*` partition image (root or chained).
    Vbmeta,
    /// Metadata located through a footer in some other partition (`boot`,
    /// `dtbo`, ...).
    Footered,
}

impl Kind {
    /// libavb's own rule: a partition name starting with `vbmeta` is a
    /// whole-partition vbmeta, anything else is read through a footer.
    pub fn of(partition: &str) -> Self {
        if partition.starts_with("vbmeta") {
            Self::Vbmeta
        } else {
            Self::Footered
        }
    }

    /// `"vbmeta"` or `"footered"`, for reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::Vbmeta => "vbmeta",
            Self::Footered => "footered",
        }
    }
}

/// SHA-256 of `bytes`.
///
/// Available with the `digest` feature, which is what `sha2` is gated on.
#[cfg(feature = "digest")]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// SHA-256 over the concatenation of `parts`, without copying them together.
#[cfg(feature = "digest")]
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// SHA-512 of bytes, including an AVB-serialized public key.
#[cfg(feature = "digest")]
pub fn sha512(bytes: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(bytes).into()
}

/// SHA-512 over ordered parts without joining or deduplicating them.
///
/// For GBL's DICE authority hash the parts are every admitted vbmeta public
/// key in visit order, including repeated equal keys.
#[cfg(feature = "digest")]
pub fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = sha2::Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Lower-case hex encoding of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The two build properties the observed ABL reports out of AVB metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Properties {
    pub os_version: Option<String>,
    pub security_patch: Option<String>,
}

impl Properties {
    /// First non-empty source wins; mirrors the ABL's boot-first lookup.
    pub fn or(&self, fallback: &Self) -> Self {
        Self {
            os_version: self
                .os_version
                .clone()
                .or_else(|| fallback.os_version.clone()),
            security_patch: self
                .security_patch
                .clone()
                .or_else(|| fallback.security_patch.clone()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.os_version.is_none() && self.security_patch.is_none()
    }
}

/// One image still required by the plan, in libavb visit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Need {
    /// Partition base name, without an `_a`/`_b` suffix.
    pub name: String,
    /// Whole-partition vbmeta or footer-located metadata.
    pub kind: Kind,
    /// Rollback index location the parent's chain descriptor names.
    pub rollback_index_location: u32,
    /// SHA-256 of the key the parent demands for this image.
    pub expected_key_sha256: [u8; 32],
    /// Partition that demanded this image (`vbmeta` for the root's children).
    pub parent: String,
}

/// What happened to one supplied image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The authentication block verified and the signing key is the demanded
    /// one. `anchored` is false only for a root that was not compared against an
    /// ABL key (UNANCHORED).
    Verified {
        key_sha256: [u8; 32],
        anchored: bool,
    },
    /// Signed, but by a different key than the one demanded.
    KeyMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The RSA signature over the authentication hash did not verify.
    SignatureMismatch,
    /// The stored hash does not match header+auxiliary data.
    HashMismatch,
    /// `algorithm_type == AVB_ALGORITHM_TYPE_NONE`: nothing to verify.
    Unsigned,
    /// Structurally unusable.
    Malformed(Defect),
    /// Signed and key-correct, but the signed content is not the demanded
    /// partition's (see the crate docs: a coverage convention, not a signature).
    WrongPartition { need: String, covered: Vec<String> },
}

impl Verdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// `Some(anchored)` for a verified image, `None` otherwise.
    pub fn anchored(&self) -> Option<bool> {
        match self {
            Self::Verified { anchored, .. } => Some(*anchored),
            _ => None,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified {
                key_sha256,
                anchored,
            } => write!(
                f,
                "verified against key {} ({})",
                hex(key_sha256),
                if *anchored { "anchored" } else { "UNANCHORED" }
            ),
            Self::KeyMismatch { expected, actual } => write!(
                f,
                "key mismatch: expected {}, found {}",
                hex(expected),
                hex(actual)
            ),
            Self::SignatureMismatch => f.write_str("signature mismatch"),
            Self::HashMismatch => f.write_str("hash mismatch"),
            Self::Unsigned => f.write_str("unsigned (algorithm_type NONE)"),
            Self::Malformed(defect) => write!(f, "malformed: {defect}"),
            Self::WrongPartition { need, covered } => write!(
                f,
                "wrong partition: supplied for {need}, whose signed coverage is [{}]",
                covered.join(", ")
            ),
        }
    }
}

/// A supplied image that verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accepted {
    pub name: String,
    pub kind: Kind,
    pub metadata_len: usize,
    pub metadata_sha256: [u8; 32],
    pub key_sha256: [u8; 32],
    pub anchored: bool,
    /// Position in [`Plan::ordered_images`].
    pub index: usize,
}

/// A supplied image that did not verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rejected {
    pub name: String,
    pub verdict: Verdict,
}

impl Rejected {
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.verdict)
    }
}

/// One supplied image as the plan sees it, in libavb visit order.
#[derive(Clone, Debug)]
pub struct Image<'a> {
    pub name: &'a str,
    pub kind: Kind,
    /// The exact metadata extent that is hashed into the vbmeta digest.
    pub metadata: &'a [u8],
    pub metadata_sha256: [u8; 32],
    pub key_sha256: [u8; 32],
    pub anchored: bool,
    pub verdict: &'a Verdict,
}
