//! Structural reading of one AVB0 metadata image: header, descriptors, chain
//! descriptors, hash/hashtree coverage and the boot build properties.
//!
//! Wire offsets come from `avb_vbmeta_image.h` and `avb_descriptor.h`. Note that
//! this libavb numbers the descriptor tags `HASHTREE = 1` and `HASH = 2`; the
//! two descriptor structs differ in both layout and size, and both were checked
//! against the real canoe capture rather than assumed:
//!
//! ```text
//! tag 0 property        key_num_bytes u64@0  value_num_bytes u64@8  key@16 ...
//! tag 1 hashtree        dm_verity_version u32@0  image_size u64@4  tree_offset@12
//!                       tree_size@20  data_block_size@28  hash_block_size@32
//!                       fec_num_roots@36  fec_offset@40  fec_size@48
//!                       hash_algorithm[32]@56  partition_name_len@88  salt_len@92
//!                       root_digest_len@96  reserved[64]@100  partition_name@164
//! tag 2 hash            image_size u64@0  hash_algorithm[32]@8
//!                       partition_name_len@40  salt_len@44  digest_len@48
//!                       reserved[64]@52  partition_name@116
//! tag 3 kernel cmdline  flags u32@0  kernel_cmdline_length u32@4  text@8
//! tag 4 chain partition rollback_index_location u32@0  partition_name_len u32@4
//!                       public_key_len u32@8  reserved[64]@12  name@76  key@76+len
//! ```
//!
//! All integers are big-endian. Structural admission of the whole image is
//! delegated to the vendored `avb-graft` crate, whose `validate_vbmeta()` is a
//! superset of `avb_vbmeta_image_verify()`'s own bounds checks (magic, version,
//! 64-byte block alignment, hash/signature/public-key/metadata/descriptor
//! extents inside their blocks, descriptor strides, zero padding).

#[cfg(feature = "digest")]
use crate::sha256;
use crate::{Kind, OS_VERSION_KEY, Properties, SECURITY_PATCH_KEY};
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use avb_graft::validate_vbmeta;
use core::fmt;

/// Size of the `AVB0` vbmeta header.
pub const HEADER_SIZE: usize = 256;
/// Maximum size of one vbmeta image, as in `avb_slot_verify.c`.
pub const VBMETA_MAX_SIZE: u64 = 64 * 1024;
/// Maximum number of vbmeta images libavb will load.
pub const MAX_VBMETA_IMAGES: usize = 32;

/// Descriptor tag: property.
pub const DESCRIPTOR_TAG_PROPERTY: u64 = 0;
/// Descriptor tag: dm-verity hash tree.
pub const DESCRIPTOR_TAG_HASHTREE: u64 = 1;
/// Descriptor tag: whole-partition hash.
pub const DESCRIPTOR_TAG_HASH: u64 = 2;
/// Descriptor tag: kernel command line.
pub const DESCRIPTOR_TAG_KERNEL_CMDLINE: u64 = 3;
/// Descriptor tag: chained partition.
pub const DESCRIPTOR_TAG_CHAIN_PARTITION: u64 = 4;

/// `AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED`: dm-verity is off
/// (`avb_vbmeta_image.h:59-62`).
pub const VBMETA_FLAG_HASHTREE_DISABLED: u32 = 1 << 0;
/// `AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED`: libavb parses no descriptors
/// and emits no `androidboot.vbmeta.*` for such a root
/// (`avb_vbmeta_image.h:59-62`, `avb_slot_verify.c:1599-1601`).
pub const VBMETA_FLAG_VERIFICATION_DISABLED: u32 = 1 << 1;

const ALGORITHM_OFFSET: usize = 28;
const AUTH_SIZE_OFFSET: usize = 12;
const AUX_SIZE_OFFSET: usize = 20;
const HASH_OFFSET_OFFSET: usize = 32;
const HASH_SIZE_OFFSET: usize = 40;
const SIGNATURE_OFFSET_OFFSET: usize = 48;
const SIGNATURE_SIZE_OFFSET: usize = 56;
const PUBLIC_KEY_OFFSET_OFFSET: usize = 64;
const PUBLIC_KEY_SIZE_OFFSET: usize = 72;
const DESCRIPTORS_OFFSET_OFFSET: usize = 96;
const DESCRIPTORS_SIZE_OFFSET: usize = 104;
const ROLLBACK_INDEX_OFFSET: usize = 112;
const FLAGS_OFFSET: usize = 120;
/// Fixed part of a chain-partition descriptor body before the name.
const CHAIN_PREFIX: usize = 76;
/// Fixed part of a hash descriptor body before the name.
const HASH_PREFIX: usize = 116;
/// Fixed part of a hashtree descriptor body before the name.
const HASHTREE_PREFIX: usize = 164;

/// Why a metadata image is structurally unusable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Defect {
    /// Fewer bytes than the structure being read.
    Truncated,
    /// Not an `AVB0` vbmeta image.
    Magic,
    /// Unsupported `required_libavb_version_*`.
    Version,
    /// `auth`/`aux` block sizes are not 64-byte aligned.
    BlockAlignment,
    /// A reserved region is not zero, or the release string is not terminated.
    Reserved,
    /// A descriptor extent or stride is outside the descriptor window.
    DescriptorBounds,
    /// A descriptor header is malformed.
    Descriptor,
    /// A property descriptor body is malformed.
    Property,
    /// A hash descriptor body is malformed.
    HashDescriptor,
    /// A hashtree descriptor body is malformed.
    HashtreeDescriptor,
    /// A chain-partition descriptor body is malformed.
    ChainPartition,
    /// A descriptor name is not UTF-8.
    InvalidUtf8,
    /// A size or offset did not fit in the target integer.
    Overflow,
    /// Structural admission by `avb-graft` failed.
    Graft(avb_graft::Error),
    /// `algorithm_type` is neither NONE nor one of the six RSA algorithms.
    Algorithm(u32),
    /// The embedded hash size does not match the algorithm.
    HashSize { expected: usize, found: usize },
    /// The embedded signature size does not match the key.
    SignatureSize { expected: usize, found: usize },
    /// The embedded public key blob is not a usable AVB RSA key.
    KeyBlob,
    /// A chain descriptor names rollback index location 0, which libavb rejects.
    RollbackIndexLocationZero(String),
    /// The root names a chain partition `vbmeta`, which is its own entry.
    ReservedChainName(String),
    /// One image describes the same chain partition twice.
    DuplicateChain(String),
    /// Two images demand the same partition.
    DuplicatePartition(String),
    /// A partition was supplied that the plan does not require.
    UnknownPartition(String),
    /// A root was to be anchored but no ABL key was available.
    NoAnchorKey,
    /// More than [`MAX_VBMETA_IMAGES`] images were discovered.
    TooManyImages(usize),
    /// A caller-supplied backing read failed.
    Read(String),
}

impl fmt::Display for Defect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated AVB structure"),
            Self::Magic => f.write_str("not an AVB0 vbmeta image"),
            Self::Version => f.write_str("unsupported required libavb version"),
            Self::BlockAlignment => f.write_str("vbmeta block size is not 64-byte aligned"),
            Self::Reserved => f.write_str("reserved region is not zero"),
            Self::DescriptorBounds => {
                f.write_str("descriptor extent is outside the descriptor window")
            }
            Self::Descriptor => f.write_str("malformed descriptor"),
            Self::Property => f.write_str("malformed property descriptor"),
            Self::HashDescriptor => f.write_str("malformed hash descriptor"),
            Self::HashtreeDescriptor => f.write_str("malformed hashtree descriptor"),
            Self::ChainPartition => f.write_str("malformed chain-partition descriptor"),
            Self::InvalidUtf8 => f.write_str("descriptor name is not UTF-8"),
            Self::Overflow => f.write_str("size or offset overflowed"),
            Self::Graft(error) => write!(f, "avb-graft rejected the image: {error}"),
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
            Self::DuplicatePartition(name) => {
                write!(f, "partition {name} is demanded twice")
            }
            Self::UnknownPartition(name) => {
                write!(f, "the plan does not require a partition named {name}")
            }
            Self::NoAnchorKey => f.write_str("no AVB public key was found in the ABL image"),
            Self::TooManyImages(count) => {
                write!(
                    f,
                    "{count} vbmeta images exceed the libavb limit of {MAX_VBMETA_IMAGES}"
                )
            }
            Self::Read(message) => write!(f, "backing read failed: {message}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Defect {}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

fn be_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_be_bytes(raw.try_into().ok()?))
}

fn index(value: u64) -> Result<usize, Defect> {
    usize::try_from(value).map_err(|_| Defect::Overflow)
}

/// The header fields this crate needs, already bounds-checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub algorithm: u32,
    pub auth_size: u64,
    pub aux_size: u64,
    pub hash_offset: u64,
    pub hash_size: u64,
    pub signature_offset: u64,
    pub signature_size: u64,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub descriptors_offset: u64,
    pub descriptors_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
}

/// Read the header fields, without validating the image around them.
pub fn header(bytes: &[u8]) -> Result<Header, Defect> {
    if bytes.len() < HEADER_SIZE {
        return Err(Defect::Truncated);
    }
    if bytes.get(..4) != Some(b"AVB0") {
        return Err(Defect::Magic);
    }
    let field = |offset: usize| be_u64(bytes, offset).ok_or(Defect::Truncated);
    Ok(Header {
        algorithm: be_u32(bytes, ALGORITHM_OFFSET).ok_or(Defect::Truncated)?,
        auth_size: field(AUTH_SIZE_OFFSET)?,
        aux_size: field(AUX_SIZE_OFFSET)?,
        hash_offset: field(HASH_OFFSET_OFFSET)?,
        hash_size: field(HASH_SIZE_OFFSET)?,
        signature_offset: field(SIGNATURE_OFFSET_OFFSET)?,
        signature_size: field(SIGNATURE_SIZE_OFFSET)?,
        public_key_offset: field(PUBLIC_KEY_OFFSET_OFFSET)?,
        public_key_size: field(PUBLIC_KEY_SIZE_OFFSET)?,
        descriptors_offset: field(DESCRIPTORS_OFFSET_OFFSET)?,
        descriptors_size: field(DESCRIPTORS_SIZE_OFFSET)?,
        rollback_index: field(ROLLBACK_INDEX_OFFSET)?,
        flags: be_u32(bytes, FLAGS_OFFSET).ok_or(Defect::Truncated)?,
    })
}

/// A parsed chain-partition descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainDescriptor {
    /// Rollback index slot the ABL uses for this partition.
    pub rollback_index_location: u32,
    /// Partition base name, without an `_a`/`_b` suffix.
    pub name: String,
    /// The public key blob the parent demands for this partition.
    pub public_key: Vec<u8>,
    /// SHA-256 of that blob. On the real capture the system/vendor chains carry
    /// `1aef65cb…` and the boot/dtbo/recovery chains `8d897f62…`
    /// (`evidence/emu-report.md` section 5). Present with the `digest` feature.
    #[cfg(feature = "digest")]
    pub public_key_sha256: [u8; 32],
}

/// Everything read out of one vbmeta image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VbmetaInfo {
    /// Exact usable size, excluding zero file padding.
    pub size: usize,
    pub header: Header,
    /// Public key blob embedded in the image.
    pub public_key: Vec<u8>,
    /// SHA-256 of that blob. Present with the `digest` feature.
    #[cfg(feature = "digest")]
    pub public_key_sha256: [u8; 32],
    /// Chain partitions in descriptor order.
    pub chains: Vec<ChainDescriptor>,
    /// `com.android.build.boot.*` properties, if present.
    pub properties: Properties,
    /// Every partition this image names in a hash, hashtree or chain descriptor,
    /// in descriptor order and de-duplicated.
    pub covered: Vec<String>,
    /// Partitions this image names in a *hash* descriptor — the ones libavb
    /// would load and hash in full when they are requested.
    pub hashed: Vec<String>,
}

impl VbmetaInfo {
    /// libavb's own rule for how this partition's image is located.
    pub fn kind_for(partition: &str) -> Kind {
        Kind::of(partition)
    }
}

/// Trim a whole-partition (or padded) image to the exact vbmeta extent.
pub fn exact_metadata(bytes: &[u8]) -> Result<&[u8], Defect> {
    let validated = validate_vbmeta(bytes).map_err(Defect::Graft)?;
    let size = index(validated.size())?;
    bytes.get(..size).ok_or(Defect::Truncated)
}

/// The public key and descriptor window of one vbmeta image.
struct Window<'a> {
    public_key: &'a [u8],
    descriptors: &'a [u8],
}

fn window<'a>(bytes: &'a [u8], head: &Header) -> Result<Window<'a>, Defect> {
    let aux_start = (HEADER_SIZE as u64)
        .checked_add(head.auth_size)
        .ok_or(Defect::Overflow)?;
    let key_start = index(
        aux_start
            .checked_add(head.public_key_offset)
            .ok_or(Defect::Overflow)?,
    )?;
    let key_end = key_start
        .checked_add(index(head.public_key_size)?)
        .ok_or(Defect::Overflow)?;
    let descriptors_start = index(
        aux_start
            .checked_add(head.descriptors_offset)
            .ok_or(Defect::Overflow)?,
    )?;
    let descriptors_end = descriptors_start
        .checked_add(index(head.descriptors_size)?)
        .ok_or(Defect::Overflow)?;
    Ok(Window {
        public_key: bytes.get(key_start..key_end).ok_or(Defect::Truncated)?,
        descriptors: bytes
            .get(descriptors_start..descriptors_end)
            .ok_or(Defect::DescriptorBounds)?,
    })
}

fn parse_chain(body: &[u8]) -> Result<ChainDescriptor, Defect> {
    if body.len() < CHAIN_PREFIX {
        return Err(Defect::ChainPartition);
    }
    let rollback_index_location = be_u32(body, 0).ok_or(Defect::ChainPartition)?;
    // libavb declares both lengths as u32 in `AvbChainPartitionDescriptor`.
    let name_len = index(u64::from(be_u32(body, 4).ok_or(Defect::ChainPartition)?))?;
    let key_len = index(u64::from(be_u32(body, 8).ok_or(Defect::ChainPartition)?))?;
    if name_len == 0 || key_len == 0 {
        return Err(Defect::ChainPartition);
    }
    let name_end = CHAIN_PREFIX.checked_add(name_len).ok_or(Defect::Overflow)?;
    let key_end = name_end.checked_add(key_len).ok_or(Defect::Overflow)?;
    let name_bytes = body
        .get(CHAIN_PREFIX..name_end)
        .ok_or(Defect::ChainPartition)?;
    let key = body.get(name_end..key_end).ok_or(Defect::ChainPartition)?;
    let name = core::str::from_utf8(name_bytes)
        .map_err(|_| Defect::InvalidUtf8)?
        .to_owned();
    if rollback_index_location == 0 {
        return Err(Defect::RollbackIndexLocationZero(name));
    }
    Ok(ChainDescriptor {
        rollback_index_location,
        name,
        public_key: key.to_vec(),
        #[cfg(feature = "digest")]
        public_key_sha256: sha256(key),
    })
}

fn parse_property(body: &[u8], properties: &mut Properties) -> Result<(), Defect> {
    if body.len() < 16 {
        return Err(Defect::Property);
    }
    let key_len = index(be_u64(body, 0).ok_or(Defect::Property)?)?;
    let value_len = index(be_u64(body, 8).ok_or(Defect::Property)?)?;
    let key_end = 16usize.checked_add(key_len).ok_or(Defect::Overflow)?;
    let value_start = key_end.checked_add(1).ok_or(Defect::Overflow)?;
    let value_end = value_start.checked_add(value_len).ok_or(Defect::Overflow)?;
    let terminator = value_end.checked_add(1).ok_or(Defect::Overflow)?;
    if terminator > body.len() || body[key_end] != 0 || body[value_end] != 0 {
        return Err(Defect::Property);
    }
    let key = &body[16..key_end];
    let value = &body[value_start..value_end];
    let slot = if key == OS_VERSION_KEY.as_bytes() {
        Some(&mut properties.os_version)
    } else if key == SECURITY_PATCH_KEY.as_bytes() {
        Some(&mut properties.security_patch)
    } else {
        None
    };
    if let Some(slot) = slot {
        let value = core::str::from_utf8(value).map_err(|_| Defect::InvalidUtf8)?;
        *slot = Some(value.to_owned());
    }
    Ok(())
}

/// The partition name of a hash (tag 2) or hashtree (tag 1) descriptor.
fn partition_name(
    body: &[u8],
    prefix: usize,
    length_offset: usize,
    defect: Defect,
) -> Result<String, Defect> {
    if body.len() < prefix {
        return Err(defect);
    }
    let name_len = index(u64::from(
        be_u32(body, length_offset).ok_or_else(|| defect.clone())?,
    ))?;
    let name_end = prefix.checked_add(name_len).ok_or(Defect::Overflow)?;
    let name = body.get(prefix..name_end).ok_or(defect)?;
    core::str::from_utf8(name)
        .map_err(|_| Defect::InvalidUtf8)
        .map(str::to_owned)
}

/// Walk a descriptor region, dispatching `(tag, body)` in order.
fn walk_descriptors(
    descriptors: &[u8],
    mut visit: impl FnMut(u64, &[u8]) -> Result<(), Defect>,
) -> Result<(), Defect> {
    let mut cursor = 0usize;
    while cursor < descriptors.len() {
        let remaining = descriptors.len() - cursor;
        if remaining < 16 {
            return Err(Defect::DescriptorBounds);
        }
        let tag = be_u64(descriptors, cursor).ok_or(Defect::Descriptor)?;
        let body_len = index(be_u64(descriptors, cursor + 8).ok_or(Defect::Descriptor)?)?;
        let total = 16usize.checked_add(body_len).ok_or(Defect::Overflow)?;
        if total > remaining {
            return Err(Defect::DescriptorBounds);
        }
        let body = &descriptors[cursor + 16..cursor + 16 + body_len];
        visit(tag, body)?;
        cursor += total;
    }
    Ok(())
}

/// Admit one vbmeta image and read its key, chains, coverage and properties.
///
/// Admission requires the exact structural bounds `avb-graft` enforces, so a
/// blob accepted here is servable there.
pub fn inspect(bytes: &[u8]) -> Result<VbmetaInfo, Defect> {
    let validated = validate_vbmeta(bytes).map_err(Defect::Graft)?;
    let size = index(validated.size())?;
    let head = header(bytes)?;
    let view = window(bytes, &head)?;
    let mut chains: Vec<ChainDescriptor> = Vec::new();
    let mut properties = Properties::default();
    let mut covered: Vec<String> = Vec::new();
    let mut hashed: Vec<String> = Vec::new();
    walk_descriptors(view.descriptors, |tag, body| {
        match tag {
            DESCRIPTOR_TAG_CHAIN_PARTITION => {
                let chain = parse_chain(body)?;
                if chains.iter().any(|existing| existing.name == chain.name) {
                    return Err(Defect::DuplicateChain(chain.name));
                }
                if !covered.contains(&chain.name) {
                    covered.push(chain.name.clone());
                }
                chains.push(chain);
            }
            DESCRIPTOR_TAG_PROPERTY => parse_property(body, &mut properties)?,
            DESCRIPTOR_TAG_HASH => {
                let name = partition_name(body, HASH_PREFIX, 40, Defect::HashDescriptor)?;
                if !covered.contains(&name) {
                    covered.push(name.clone());
                }
                hashed.push(name);
            }
            DESCRIPTOR_TAG_HASHTREE => {
                let name = partition_name(body, HASHTREE_PREFIX, 88, Defect::HashtreeDescriptor)?;
                if !covered.contains(&name) {
                    covered.push(name);
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(VbmetaInfo {
        size,
        header: head,
        public_key: view.public_key.to_vec(),
        #[cfg(feature = "digest")]
        public_key_sha256: sha256(view.public_key),
        chains,
        properties,
        covered,
        hashed,
    })
}

/// Admit a whole `vbmeta*` partition image and trim it to the exact vbmeta size.
pub fn vbmeta_entry(image: &[u8]) -> Result<(Vec<u8>, VbmetaInfo), Defect> {
    let info = inspect(image)?;
    let exact = image.get(..info.size).ok_or(Defect::Truncated)?;
    Ok((exact.to_vec(), info))
}
