//! `libavb`-semantics planning over a root `vbmeta` and the images it chains.
//!
//! This crate answers one question: given a root vbmeta image that a caller
//! trusts, which images does it demand, and are the ones supplied the right
//! ones? It mirrors `avb_slot_verify.c`:
//!
//! * a root image is verified against the key the *caller* supplies; this crate
//!   never selects a key from a device image and has no "first embedded key"
//!   rule;
//! * only the main (`root`) vbmeta may carry chain-partition descriptors, and a
//!   chain descriptor in a chained image is invalid metadata;
//! * a chain descriptor's public key is compared byte-for-byte with the key
//!   embedded in the chained image, and that image's authentication block is
//!   verified first;
//! * images are recorded depth-first in descriptor order, and the ordered set
//!   feeds the metadata digests;
//! * `androidboot.vbmeta.*` is emitted from the root's algorithm, and nothing
//!   is emitted when the root sets verification-disabled.
//!
//! Platform conventions are not part of this crate. Selecting a key from an ABL
//! image, treating the first such key as an anchor, preferring `boot` metadata
//! properties, judging a signed image by the partition names it covers, and
//! naming a fixed SHA-256 metadata digest a stock Qualcomm `SET_VBH` value all
//! belong to the caller. The evidence needed for those decisions is public
//! here: [`Plan::covered`], [`Plan::supplied_info`], [`Plan::root_properties`],
//! and [`Plan::vbmeta_digest_with`].
//!
//! [`Plan::new_unverified`] exists for callers that deliberately build an
//! artifact from unverified metadata. Every verdict is still recorded, so
//! nothing is reported as verified that is not.
//!
//! # Limits
//!
//! [`VBMETA_MAX_SIZE`] (64 KiB) bounds one metadata extent and
//! [`MAX_VBMETA_IMAGES`] (32) bounds the number of images, both taken from
//! libavb. Every read is bounds-checked; nothing here panics on hostile input.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod meta;
pub mod plan;

pub use avb_format::{
    HEADER_SIZE, MAX_VBMETA_IMAGES, VBMETA_FLAG_HASHTREE_DISABLED,
    VBMETA_FLAG_VERIFICATION_DISABLED, VBMETA_MAX_SIZE,
};
pub use avb_verify::HashAlg;
pub use avb_verify::sha256;
pub use meta::{ChainDescriptor, VbmetaInfo, exact_metadata, inspect, vbmeta_entry};
pub use plan::{
    CmdlineDigest, ExtractError, Plan, ROOT_NAME, VbmetaDigest, WalkNode, extract_vbmd,
};

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// An AVB RSA public key blob the caller explicitly trusts.
///
/// The blob is byte-for-byte the `AvbRSAPublicKeyHeader`, modulus and `rr`
/// serialization. [`KeyBlob::from_blob`] accepts only a blob whose geometry and
/// arithmetic self-consistency are valid. The fields stay public because a
/// caller may need to build a blob from evidence it already validated; this
/// crate does not re-interpret an altered blob as trusted on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBlob {
    /// The serialized public key.
    pub blob: Vec<u8>,
    /// `key_num_bits` of the blob.
    pub num_bits: u32,
}

impl KeyBlob {
    /// Validate `blob` and keep it as a trust input.
    pub fn from_blob(blob: Vec<u8>) -> Result<Self, Defect> {
        let num_bits = avb_format::validate_key_blob(&blob).ok_or(Defect::KeyBlob)?;
        Ok(Self { blob, num_bits })
    }

    /// [`KeyBlob::from_blob`] for a borrowed blob.
    pub fn from_bytes(blob: &[u8]) -> Result<Self, Defect> {
        Self::from_blob(blob.to_vec())
    }

    /// Signature length in bytes for this key.
    pub fn signature_len(&self) -> usize {
        self.num_bits as usize / 8
    }
}

/// Why a chain image is structurally unusable, or a caller's input is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Defect {
    /// The `avb-format` parser rejected the image or a descriptor.
    Format(avb_format::Defect),
    /// `algorithm_type` is neither NONE nor one of the six RSA algorithms.
    Algorithm(u32),
    /// The embedded hash size does not match the algorithm.
    HashSize { expected: usize, found: usize },
    /// The embedded signature size does not match the key.
    SignatureSize { expected: usize, found: usize },
    /// The embedded public key blob is not a usable AVB RSA key.
    KeyBlob,
    /// A size or offset did not fit in the target integer.
    Overflow,
    /// A chain descriptor names rollback index location 0, which libavb rejects.
    RollbackIndexLocationZero(String),
    /// A chain descriptor names `vbmeta`, which is the root entry.
    ReservedChainName(String),
    /// One image describes the same chain partition twice. libavb would load
    /// both; this plan refuses because images are addressed by name.
    DuplicateChain(String),
    /// A chained image carries a chain descriptor; libavb permits that only in
    /// the main image.
    ChainInChainedImage(String),
    /// The partition was already supplied to this plan.
    AlreadySupplied(String),
    /// A partition was supplied that the plan does not require.
    UnknownPartition(String),
    /// A caller requested explicit trust but supplied no key.
    NoTrustedKey,
    /// More than [`MAX_VBMETA_IMAGES`] images were discovered.
    TooManyImages(usize),
    /// A caller-supplied backing read failed.
    Read(String),
}

impl From<avb_format::Defect> for Defect {
    fn from(defect: avb_format::Defect) -> Self {
        Self::Format(defect)
    }
}

impl fmt::Display for Defect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(defect) => write!(f, "{defect}"),
            Self::Algorithm(value) => write!(f, "unsupported algorithm_type {value}"),
            Self::HashSize { expected, found } => write!(
                f,
                "embedded hash is {found} bytes, algorithm requires {expected}"
            ),
            Self::SignatureSize { expected, found } => write!(
                f,
                "embedded signature is {found} bytes, key requires {expected}"
            ),
            Self::KeyBlob => f.write_str("embedded public key is not an AVB RSA key"),
            Self::Overflow => f.write_str("size or offset overflowed"),
            Self::RollbackIndexLocationZero(name) => {
                write!(f, "chain partition {name} names rollback index location 0")
            }
            Self::ReservedChainName(name) => {
                write!(
                    f,
                    "chain partition {name} collides with the root entry name"
                )
            }
            Self::DuplicateChain(name) => {
                write!(f, "one image describes chain partition {name} twice")
            }
            Self::ChainInChainedImage(name) => write!(
                f,
                "chained image {name} carries a chain descriptor, which libavb permits only in the main image"
            ),
            Self::AlreadySupplied(name) => {
                write!(f, "partition {name} was already supplied")
            }
            Self::UnknownPartition(name) => {
                write!(f, "the plan does not require a partition named {name}")
            }
            Self::NoTrustedKey => f.write_str("explicit trust was requested with no key"),
            Self::TooManyImages(count) => write!(
                f,
                "{count} vbmeta images exceed the libavb limit of {MAX_VBMETA_IMAGES}"
            ),
            Self::Read(message) => write!(f, "backing read failed: {message}"),
        }
    }
}

impl core::error::Error for Defect {}

/// One build property from a property descriptor, in descriptor order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Property {
    pub key: String,
    pub value: String,
}

/// Which partition class a demanded image belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Kind {
    /// A whole `vbmeta*` partition image (root or chained).
    Vbmeta,
    /// Metadata located through a footer in some other partition.
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

/// Lower-case hex encoding of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
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
    /// one. `trusted` is true only when the caller supplied that key for the
    /// root through [`Plan::with_trusted_keys`].
    Verified { key_sha256: [u8; 32], trusted: bool },
    /// Signed, but by a different key than the one the parent demands.
    KeyMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Signed and valid, but by a key the caller did not supply as trusted.
    UntrustedKey { actual: [u8; 32] },
    /// The RSA signature over the authentication hash did not verify.
    SignatureMismatch,
    /// The stored hash does not match header+auxiliary data.
    HashMismatch,
    /// `algorithm_type == AVB_ALGORITHM_TYPE_NONE`: nothing to verify.
    Unsigned,
    /// Structurally unusable.
    Malformed(Defect),
}

impl Verdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// `Some(trusted)` for a verified image, `None` otherwise.
    pub fn trusted(&self) -> Option<bool> {
        match self {
            Self::Verified { trusted, .. } => Some(*trusted),
            _ => None,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified {
                key_sha256,
                trusted,
            } => write!(
                f,
                "verified against key {} ({})",
                hex(key_sha256),
                if *trusted { "trusted" } else { "UNTRUSTED" }
            ),
            Self::KeyMismatch { expected, actual } => write!(
                f,
                "key mismatch: expected {}, found {}",
                hex(expected),
                hex(actual)
            ),
            Self::UntrustedKey { actual } => {
                write!(f, "signed by untrusted key {}", hex(actual))
            }
            Self::SignatureMismatch => f.write_str("signature mismatch"),
            Self::HashMismatch => f.write_str("hash mismatch"),
            Self::Unsigned => f.write_str("unsigned (algorithm_type NONE)"),
            Self::Malformed(defect) => write!(f, "malformed: {defect}"),
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
    pub trusted: bool,
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
    /// The exact metadata extent that feeds the metadata digests.
    pub metadata: &'a [u8],
    pub metadata_sha256: [u8; 32],
    pub key_sha256: [u8; 32],
    pub trusted: bool,
    pub verdict: &'a Verdict,
}
