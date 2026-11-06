#![no_std]
#![forbid(unsafe_code)]
//! Allocation-free AVB wire framing: `AVB0` vbmeta images, `AVBf` footers,
//! typed descriptors and AVB RSA public-key blobs.
//!
//! Wire offsets come from AOSP `external/avb/libavb/{avb_footer.h,
//! avb_vbmeta_image.h, avb_descriptor.h}`; all integers are big-endian. Only
//! the fixed end-of-image footer locates metadata. No marker scanning.
//!
//! This crate is structural only. It does not hash, verify a signature or
//! decide trust; it has no dependencies and no allocator. A caller that hashes
//! or verifies uses `avb-verify`; a caller that walks a metadata chain and
//! records verdicts uses `avb-chain`.
//!
//! Structural admission of a standalone image is [`validate_vbmeta`]. Its
//! `validate_vbmeta()` rules are a superset of `avb_vbmeta_image_verify()`'s
//! own bounds checks: magic, version, 64-byte block alignment,
//! hash/signature/public-key/metadata/descriptor extents inside their blocks,
//! descriptor strides and zero file padding.

pub mod extract;
pub mod footer;
pub mod framing;
pub mod key;
pub mod vbmeta;

pub use extract::{ExtractError, VbmdExtent, extract_vbmd, vbmd_extent};
pub use footer::{FOOTER_SIZE, Footer, parse_footer, replacement_footer};
pub use framing::{Error, Result, Vbmeta, validate_vbmeta};
pub use key::{
    AvbRSAPublicKeyHeader, RSA_KEY_BITS, RSA_KEY_BITS_2048, RSA_KEY_BITS_4096, RSA_KEY_BITS_8192,
    RSA_KEY_HEADER_SIZE, RSA_MAX_KEY_BYTES, key_blob_len, key_is_valid, key_modulus, key_num_bits,
    key_rr, n0inv, rr_is_consistent, validate_key_blob,
};
pub use vbmeta::{
    ChainPartition, DESCRIPTOR_TAG_CHAIN_PARTITION, DESCRIPTOR_TAG_HASH, DESCRIPTOR_TAG_HASHTREE,
    DESCRIPTOR_TAG_KERNEL_CMDLINE, DESCRIPTOR_TAG_PROPERTY, Defect, Descriptor, DescriptorIter,
    Descriptors, HEADER_SIZE, Hash, Hashtree, Header, KernelCmdline, MAX_VBMETA_IMAGES, Property,
    VBMETA_FLAG_HASHTREE_DISABLED, VBMETA_FLAG_VERIFICATION_DISABLED, VBMETA_MAX_SIZE, VbmetaInfo,
    descriptor, descriptors, exact_metadata, header, inspect, vbmeta_entry,
};
