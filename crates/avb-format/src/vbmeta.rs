//! Structural reading of one AVB0 metadata image: header, typed descriptors,
//! chain partitions and exact metadata extent.
//!
//! Wire offsets come from `avb_vbmeta_image.h` and `avb_descriptor.h`. Note that
//! libavb numbers the descriptor tags `HASHTREE = 1` and `HASH = 2`; the two
//! descriptor structs differ in both layout and size:
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
//! [`validate_vbmeta`], whose rules are a superset of
//! `avb_vbmeta_image_verify()`'s own bounds checks.

use crate::framing::{Error, validate_vbmeta};
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

/// `AVB_CHAIN_PARTITION_DESCRIPTOR_FLAGS_DO_NOT_USE_AB`: libavb applies no slot
/// suffix to this chained partition
/// (`avb_chain_partition_descriptor.h`). It is a negative flag.
pub const CHAIN_PARTITION_FLAG_DO_NOT_USE_AB: u32 = 1 << 0;

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
/// 32-byte algorithm field in a hash or hashtree descriptor.
const ALGORITHM_LEN: usize = 32;

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
    /// Structural admission of a footer or vbmeta image failed.
    Framing(Error),
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
            Self::Framing(error) => write!(f, "AVB framing rejected the image: {error}"),
        }
    }
}

impl From<Error> for Defect {
    fn from(error: Error) -> Self {
        Self::Framing(error)
    }
}

impl core::error::Error for Defect {}

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

/// A property descriptor: `com.android.build.boot.*` and similar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Property<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// A whole-partition hash descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash<'a> {
    pub image_size: u64,
    pub hash_algorithm: &'a str,
    pub partition_name: &'a str,
    pub salt: &'a [u8],
    pub digest: &'a [u8],
}

/// A dm-verity hashtree descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hashtree<'a> {
    pub dm_verity_version: u32,
    pub image_size: u64,
    pub tree_offset: u64,
    pub tree_size: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub fec_num_roots: u32,
    pub fec_offset: u64,
    pub fec_size: u64,
    pub hash_algorithm: &'a str,
    pub partition_name: &'a str,
    pub salt: &'a [u8],
    pub root_digest: &'a [u8],
}

/// A kernel command line descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelCmdline<'a> {
    pub flags: u32,
    pub cmdline: &'a str,
}

/// A chained-partition descriptor.
///
/// `rollback_index_location == 0` is a chain-policy defect, not a framing one;
/// a chain owner rejects it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainPartition<'a> {
    pub rollback_index_location: u32,
    /// `AVB_CHAIN_PARTITION_DESCRIPTOR_FLAGS_*` bits.
    pub flags: u32,
    pub name: &'a str,
    pub public_key: &'a [u8],
}

/// One descriptor with its body already parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Descriptor<'a> {
    Property(Property<'a>),
    Hashtree(Hashtree<'a>),
    Hash(Hash<'a>),
    KernelCmdline(KernelCmdline<'a>),
    ChainPartition(ChainPartition<'a>),
    /// A tag this crate does not read. libavb skips unknown tags.
    Unknown {
        tag: u64,
        body: &'a [u8],
    },
}

impl<'a> Descriptor<'a> {
    /// The wire tag of this descriptor.
    pub fn tag(&self) -> u64 {
        match self {
            Self::Property(_) => DESCRIPTOR_TAG_PROPERTY,
            Self::Hashtree(_) => DESCRIPTOR_TAG_HASHTREE,
            Self::Hash(_) => DESCRIPTOR_TAG_HASH,
            Self::KernelCmdline(_) => DESCRIPTOR_TAG_KERNEL_CMDLINE,
            Self::ChainPartition(_) => DESCRIPTOR_TAG_CHAIN_PARTITION,
            Self::Unknown { tag, .. } => *tag,
        }
    }
}

fn text(bytes: &[u8]) -> Result<&str, Defect> {
    core::str::from_utf8(bytes).map_err(|_| Defect::InvalidUtf8)
}

/// A 32-byte algorithm field, NUL-terminated when shorter.
fn algorithm(field: &[u8], defect: Defect) -> Result<&str, Defect> {
    let field = field.get(..ALGORITHM_LEN).ok_or(defect)?;
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(ALGORITHM_LEN);
    text(&field[..end])
}

fn parse_property(body: &[u8]) -> Result<Property<'_>, Defect> {
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
    Ok(Property {
        key: text(&body[16..key_end])?,
        value: text(&body[value_start..value_end])?,
    })
}

fn parse_hash(body: &[u8]) -> Result<Hash<'_>, Defect> {
    if body.len() < HASH_PREFIX {
        return Err(Defect::HashDescriptor);
    }
    let name_len = index(u64::from(be_u32(body, 40).ok_or(Defect::HashDescriptor)?))?;
    let salt_len = index(u64::from(be_u32(body, 44).ok_or(Defect::HashDescriptor)?))?;
    let digest_len = index(u64::from(be_u32(body, 48).ok_or(Defect::HashDescriptor)?))?;
    let name_end = HASH_PREFIX.checked_add(name_len).ok_or(Defect::Overflow)?;
    let salt_end = name_end.checked_add(salt_len).ok_or(Defect::Overflow)?;
    let digest_end = salt_end.checked_add(digest_len).ok_or(Defect::Overflow)?;
    Ok(Hash {
        image_size: be_u64(body, 0).ok_or(Defect::HashDescriptor)?,
        hash_algorithm: algorithm(
            body.get(8..40).ok_or(Defect::HashDescriptor)?,
            Defect::HashDescriptor,
        )?,
        partition_name: text(
            body.get(HASH_PREFIX..name_end)
                .ok_or(Defect::HashDescriptor)?,
        )?,
        salt: body.get(name_end..salt_end).ok_or(Defect::HashDescriptor)?,
        digest: body
            .get(salt_end..digest_end)
            .ok_or(Defect::HashDescriptor)?,
    })
}

fn parse_hashtree(body: &[u8]) -> Result<Hashtree<'_>, Defect> {
    if body.len() < HASHTREE_PREFIX {
        return Err(Defect::HashtreeDescriptor);
    }
    let name_len = index(u64::from(
        be_u32(body, 88).ok_or(Defect::HashtreeDescriptor)?,
    ))?;
    let salt_len = index(u64::from(
        be_u32(body, 92).ok_or(Defect::HashtreeDescriptor)?,
    ))?;
    let digest_len = index(u64::from(
        be_u32(body, 96).ok_or(Defect::HashtreeDescriptor)?,
    ))?;
    let name_end = HASHTREE_PREFIX
        .checked_add(name_len)
        .ok_or(Defect::Overflow)?;
    let salt_end = name_end.checked_add(salt_len).ok_or(Defect::Overflow)?;
    let digest_end = salt_end.checked_add(digest_len).ok_or(Defect::Overflow)?;
    Ok(Hashtree {
        dm_verity_version: be_u32(body, 0).ok_or(Defect::HashtreeDescriptor)?,
        image_size: be_u64(body, 4).ok_or(Defect::HashtreeDescriptor)?,
        tree_offset: be_u64(body, 12).ok_or(Defect::HashtreeDescriptor)?,
        tree_size: be_u64(body, 20).ok_or(Defect::HashtreeDescriptor)?,
        data_block_size: be_u32(body, 28).ok_or(Defect::HashtreeDescriptor)?,
        hash_block_size: be_u32(body, 32).ok_or(Defect::HashtreeDescriptor)?,
        fec_num_roots: be_u32(body, 36).ok_or(Defect::HashtreeDescriptor)?,
        fec_offset: be_u64(body, 40).ok_or(Defect::HashtreeDescriptor)?,
        fec_size: be_u64(body, 48).ok_or(Defect::HashtreeDescriptor)?,
        hash_algorithm: algorithm(
            body.get(56..88).ok_or(Defect::HashtreeDescriptor)?,
            Defect::HashtreeDescriptor,
        )?,
        partition_name: text(
            body.get(HASHTREE_PREFIX..name_end)
                .ok_or(Defect::HashtreeDescriptor)?,
        )?,
        salt: body
            .get(name_end..salt_end)
            .ok_or(Defect::HashtreeDescriptor)?,
        root_digest: body
            .get(salt_end..digest_end)
            .ok_or(Defect::HashtreeDescriptor)?,
    })
}

fn parse_kernel_cmdline(body: &[u8]) -> Result<KernelCmdline<'_>, Defect> {
    if body.len() < 8 {
        return Err(Defect::Descriptor);
    }
    let len = index(u64::from(be_u32(body, 4).ok_or(Defect::Descriptor)?))?;
    let end = 8usize.checked_add(len).ok_or(Defect::Overflow)?;
    Ok(KernelCmdline {
        flags: be_u32(body, 0).ok_or(Defect::Descriptor)?,
        cmdline: text(body.get(8..end).ok_or(Defect::Descriptor)?)?,
    })
}

fn parse_chain(body: &[u8]) -> Result<ChainPartition<'_>, Defect> {
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
    Ok(ChainPartition {
        rollback_index_location,
        flags: be_u32(body, 12).ok_or(Defect::ChainPartition)?,
        name: text(
            body.get(CHAIN_PREFIX..name_end)
                .ok_or(Defect::ChainPartition)?,
        )?,
        public_key: body.get(name_end..key_end).ok_or(Defect::ChainPartition)?,
    })
}

/// Parse one descriptor body by tag.
pub fn descriptor<'a>(tag: u64, body: &'a [u8]) -> Result<Descriptor<'a>, Defect> {
    Ok(match tag {
        DESCRIPTOR_TAG_PROPERTY => Descriptor::Property(parse_property(body)?),
        DESCRIPTOR_TAG_HASHTREE => Descriptor::Hashtree(parse_hashtree(body)?),
        DESCRIPTOR_TAG_HASH => Descriptor::Hash(parse_hash(body)?),
        DESCRIPTOR_TAG_KERNEL_CMDLINE => Descriptor::KernelCmdline(parse_kernel_cmdline(body)?),
        DESCRIPTOR_TAG_CHAIN_PARTITION => Descriptor::ChainPartition(parse_chain(body)?),
        _ => Descriptor::Unknown { tag, body },
    })
}

/// Iterate a descriptor region, parsing each descriptor in order.
///
/// The iterator yields one error and then stops. An error means the remaining
/// bytes cannot be framed, so no later descriptor is reported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptors<'a> {
    bytes: &'a [u8],
    cursor: usize,
    failed: bool,
}

/// Historical name for [`Descriptors`].
pub type DescriptorIter<'a> = Descriptors<'a>;

impl<'a> Descriptors<'a> {
    /// Iterate `bytes`, which must be a whole descriptor region.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: 0,
            failed: false,
        }
    }

    /// Byte offset of the next unread descriptor.
    pub fn offset(&self) -> usize {
        self.cursor
    }

    /// The raw bytes still unread.
    pub fn remaining(&self) -> &'a [u8] {
        let bytes = self.bytes;
        bytes.get(self.cursor..).unwrap_or(&[])
    }

    fn next_raw(&mut self) -> Option<Result<(u64, &'a [u8]), Defect>> {
        let bytes = self.bytes;
        if self.failed || self.cursor >= bytes.len() {
            return None;
        }
        let remaining = bytes.len() - self.cursor;
        if remaining < 16 {
            self.failed = true;
            return Some(Err(Defect::DescriptorBounds));
        }
        let tag = match be_u64(bytes, self.cursor) {
            Some(tag) => tag,
            None => {
                self.failed = true;
                return Some(Err(Defect::Descriptor));
            }
        };
        let body_len = match be_u64(bytes, self.cursor + 8).map(index) {
            Some(Ok(len)) => len,
            _ => {
                self.failed = true;
                return Some(Err(Defect::Descriptor));
            }
        };
        let Some(total) = 16usize.checked_add(body_len) else {
            self.failed = true;
            return Some(Err(Defect::Overflow));
        };
        if total > remaining {
            self.failed = true;
            return Some(Err(Defect::DescriptorBounds));
        }
        let body = &bytes[self.cursor + 16..self.cursor + total];
        self.cursor += total;
        Some(Ok((tag, body)))
    }
}

impl<'a> Iterator for Descriptors<'a> {
    type Item = Result<Descriptor<'a>, Defect>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_raw()
            .map(|item| item.and_then(|(tag, body)| descriptor(tag, body)))
    }
}

/// The descriptor region of one image, as a fresh iterator.
pub fn descriptors(bytes: &[u8]) -> Descriptors<'_> {
    Descriptors::new(bytes)
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

/// One admitted vbmeta image, borrowed from the input bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VbmetaInfo<'a> {
    /// Exact usable size, excluding zero file padding.
    pub size: usize,
    pub header: Header,
    /// Public key blob embedded in the image.
    pub public_key: &'a [u8],
    /// Descriptors in wire order.
    pub descriptors: Descriptors<'a>,
}

/// Trim a whole-partition (or padded) image to the exact vbmeta extent.
pub fn exact_metadata(bytes: &[u8]) -> Result<&[u8], Defect> {
    let validated = validate_vbmeta(bytes).map_err(Defect::Framing)?;
    let size = index(validated.size())?;
    bytes.get(..size).ok_or(Defect::Truncated)
}

/// Admit one vbmeta image and borrow its key and descriptor region.
///
/// Admission requires the exact structural bounds [`validate_vbmeta`] enforces,
/// so a blob accepted here is servable by a graft. Property, hash, hashtree and
/// chain bodies are parsed to prove their geometry. Unknown tags and kernel
/// command lines are not admission input; [`Descriptors`] parses them on
/// demand.
pub fn inspect(bytes: &[u8]) -> Result<VbmetaInfo<'_>, Defect> {
    let validated = validate_vbmeta(bytes).map_err(Defect::Framing)?;
    let size = index(validated.size())?;
    let head = header(bytes)?;
    let view = window(bytes, &head)?;
    let mut iter = Descriptors::new(view.descriptors);
    while let Some(item) = iter.next_raw() {
        let (tag, body) = item?;
        match tag {
            DESCRIPTOR_TAG_PROPERTY
            | DESCRIPTOR_TAG_HASHTREE
            | DESCRIPTOR_TAG_HASH
            | DESCRIPTOR_TAG_CHAIN_PARTITION => {
                descriptor(tag, body)?;
            }
            _ => {}
        }
    }
    Ok(VbmetaInfo {
        size,
        header: head,
        public_key: view.public_key,
        descriptors: Descriptors::new(view.descriptors),
    })
}

/// Admit a whole `vbmeta*` partition image and borrow its exact extent.
pub fn vbmeta_entry(image: &[u8]) -> Result<(&[u8], VbmetaInfo<'_>), Defect> {
    let info = inspect(image)?;
    let exact = image.get(..info.size).ok_or(Defect::Truncated)?;
    Ok((exact, info))
}
