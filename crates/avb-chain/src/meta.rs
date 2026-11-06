//! Owned reading of one AVB0 metadata image for chain planning.
//!
//! Framing, descriptor geometry and UTF-8 are `avb-format`'s job; this module
//! keeps the owned view the plan needs, plus the chain-specific semantic check
//! libavb applies when it walks descriptors: a chain partition must not name
//! rollback index location 0.
//!
//! A second chain descriptor naming the same partition is refused as well. That
//! is a deliberate API constraint, not a libavb rejection: libavb would load the
//! partition twice and hash both loads, while this plan addresses images by
//! name and cannot represent two entries with one name. The refusal is explicit
//! rather than a silent double count.

use crate::{Defect, Kind, Property};
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use avb_format::Descriptor;
use avb_verify::sha256;

/// A parsed chain-partition descriptor, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainDescriptor {
    /// Rollback index slot the chain uses for this partition.
    pub rollback_index_location: u32,
    /// The descriptor's `flags` word. Bit 0 is `DO_NOT_USE_AB`.
    pub flags: u32,
    /// Partition base name, without an `_a`/`_b` suffix.
    pub name: String,
    /// The public key blob the parent demands for this partition.
    pub public_key: Vec<u8>,
    /// SHA-256 of that blob.
    pub public_key_sha256: [u8; 32],
}

/// Everything read out of one vbmeta image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VbmetaInfo {
    /// Exact usable size, excluding zero file padding.
    pub size: usize,
    /// Header fields, already bounds-checked by `avb-format`.
    pub header: avb_format::Header,
    /// Public key blob embedded in the image.
    pub public_key: Vec<u8>,
    /// SHA-256 of that blob.
    pub public_key_sha256: [u8; 32],
    /// Chain partitions in descriptor order.
    pub chains: Vec<ChainDescriptor>,
    /// Every property descriptor in descriptor order, duplicates preserved.
    pub properties: Vec<Property>,
    /// Every partition this image names in a hash, hashtree or chain
    /// descriptor, in descriptor order and de-duplicated.
    pub covered: Vec<String>,
    /// Partitions this image names in a *hash* descriptor, in descriptor order.
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
    avb_format::exact_metadata(bytes).map_err(Defect::Format)
}

/// Admit one vbmeta image and read its key, chains, coverage and properties.
pub fn inspect(bytes: &[u8]) -> Result<VbmetaInfo, Defect> {
    let avb_format::VbmetaInfo {
        size,
        header,
        public_key,
        descriptors,
    } = avb_format::inspect(bytes)?;
    let public_key_sha256 = sha256(public_key);
    let mut chains: Vec<ChainDescriptor> = Vec::new();
    let mut properties: Vec<Property> = Vec::new();
    let mut covered: Vec<String> = Vec::new();
    let mut hashed: Vec<String> = Vec::new();
    for descriptor in descriptors {
        match descriptor? {
            Descriptor::Property(property) => properties.push(Property {
                key: property.key.to_owned(),
                value: property.value.to_owned(),
            }),
            Descriptor::Hash(hash) => {
                cover(&mut covered, hash.partition_name);
                hashed.push(hash.partition_name.to_owned());
            }
            Descriptor::Hashtree(hashtree) => cover(&mut covered, hashtree.partition_name),
            Descriptor::ChainPartition(chain) => {
                if chains.iter().any(|existing| existing.name == chain.name) {
                    return Err(Defect::DuplicateChain(chain.name.to_owned()));
                }
                if chain.rollback_index_location == 0 {
                    return Err(Defect::RollbackIndexLocationZero(chain.name.to_owned()));
                }
                cover(&mut covered, chain.name);
                chains.push(ChainDescriptor {
                    rollback_index_location: chain.rollback_index_location,
                    flags: chain.flags,
                    name: chain.name.to_owned(),
                    public_key: chain.public_key.to_vec(),
                    public_key_sha256: sha256(chain.public_key),
                });
            }
            Descriptor::KernelCmdline(_) | Descriptor::Unknown { .. } => {}
        }
    }
    Ok(VbmetaInfo {
        size,
        header,
        public_key: public_key.to_vec(),
        public_key_sha256,
        chains,
        properties,
        covered,
        hashed,
    })
}

/// Admit a whole `vbmeta*` partition image and return its exact extent.
pub fn vbmeta_entry(image: &[u8]) -> Result<(Vec<u8>, VbmetaInfo), Defect> {
    let info = inspect(image)?;
    let exact = image
        .get(..info.size)
        .ok_or(Defect::Format(avb_format::Defect::Truncated))?;
    Ok((exact.to_vec(), info))
}

fn cover(covered: &mut Vec<String>, name: &str) {
    if !covered.iter().any(|existing| existing == name) {
        covered.push(name.to_owned());
    }
}
