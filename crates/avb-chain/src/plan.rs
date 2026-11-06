//! Walking a root `vbmeta` into the set of images it chains, verifying each
//! supplied image, and producing libavb's metadata digests.
//!
//! The traversal mirrors `avb_slot_verify.c`: the root image is appended to the
//! ordered set, then its descriptors are walked in order, appending each chained
//! image before that image's own descriptors are examined. Chain descriptors are
//! permitted only in the main image, so the walk is one level deep; a chain
//! descriptor inside a chained image is invalid metadata.
//!
//! Two libavb facts are kept explicit rather than folded into a convenience
//! value: `androidboot.vbmeta.digest` uses the root's algorithm
//! ([`Plan::libavb_cmdline_digest`]), while any other ordered digest is whatever
//! hash the caller asks for ([`Plan::vbmeta_digest_with`]). This crate does not
//! claim a fixed SHA-256 value is a stock Qualcomm VBH.

use crate::meta::{self, VbmetaInfo};
use crate::{
    Accepted, Defect, HEADER_SIZE, HashAlg, Image, KeyBlob, Kind, MAX_VBMETA_IMAGES, Need,
    Property, Rejected, VBMETA_FLAG_VERIFICATION_DISABLED, VBMETA_MAX_SIZE, Verdict, hex, sha256,
};
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use avb_verify::Hasher;
use avb_verify::rsa_pkcs1_verify;
use core::fmt;

/// The partition name of the root metadata entry.
pub const ROOT_NAME: &str = "vbmeta";

/// Why a footer-located metadata extent could not be recovered.
pub use avb_format::ExtractError;

/// Read the metadata extent out of a footered partition without holding the
/// partition in memory.
///
/// This is the allocating wrapper over `avb-format`'s extent reader: the footer
/// is read, the declared extent is bounded by [`VBMETA_MAX_SIZE`], that extent
/// is read, and the result is trimmed to the exact vbmeta size. `read_at` is
/// called once for the footer and once for the metadata.
pub fn extract_vbmd<E>(
    image_size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Vec<u8>, ExtractError<E>> {
    let extent = avb_format::vbmd_extent(image_size, &mut read_at)?;
    let len = usize::try_from(extent.size)
        .map_err(|_| ExtractError::Malformed(avb_format::Defect::Overflow))?;
    let mut metadata = vec![0u8; len];
    read_at(extent.offset, &mut metadata).map_err(ExtractError::Read)?;
    let exact = avb_format::exact_metadata(&metadata).map_err(ExtractError::Malformed)?;
    Ok(exact.to_vec())
}

/// A digest over a set of vbmeta images, in libavb visit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VbmetaDigest {
    /// The hash the caller asked for.
    pub algorithm: HashAlg,
    /// The digest itself.
    pub digest: Vec<u8>,
    /// The `androidboot.vbmeta.size`-style total: the summed exact extents.
    pub total_size: u64,
}

impl VbmetaDigest {
    pub fn hex(&self) -> String {
        hex(&self.digest)
    }
}

/// `androidboot.vbmeta.hash_alg`, `.digest` and `.size` as libavb emits them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmdlineDigest {
    /// The hash the root's `algorithm_type` selects.
    pub hash_alg: HashAlg,
    pub digest: Vec<u8>,
    pub size: u64,
}

impl CmdlineDigest {
    pub fn hex(&self) -> String {
        hex(&self.digest)
    }

    /// `"sha256"` or `"sha512"`, as the cmdline spells it.
    pub fn name(&self) -> &'static str {
        self.hash_alg.name()
    }
}

/// The verified key of one authentication block.
struct Auth {
    key: Vec<u8>,
    key_sha256: [u8; 32],
}

#[derive(Debug)]
struct Node {
    name: String,
    kind: Kind,
    rollback_index_location: u32,
    /// The chain descriptor's `flags` word, zero for the root.
    flags: u32,
    parent: String,
    /// Whether the parent chain reaches a root the caller trusted.
    parent_trusted: bool,
    /// Key the parent's chain descriptor demands, `None` for the root.
    expected_key: Option<Vec<u8>>,
    expected_key_sha256: Option<[u8; 32]>,
    children: Vec<usize>,
    metadata: Option<Vec<u8>>,
    info: Option<VbmetaInfo>,
    verdict: Option<Verdict>,
    key_sha256: Option<[u8; 32]>,
    trusted: bool,
}

/// The walk from one root `vbmeta`, and every image supplied so far.
#[derive(Debug)]
pub struct Plan {
    nodes: Vec<Node>,
    index: BTreeMap<String, usize>,
    /// Every key the caller explicitly trusts for the root.
    keys: Vec<KeyBlob>,
    root_algorithm: u32,
}

impl Plan {
    /// Parse and verify a root `vbmeta` without asserting trust.
    ///
    /// The root must verify against its own embedded key; the verdict is
    /// `Verified { trusted: false }`. A caller that needs a trust decision uses
    /// [`Plan::with_trusted_keys`].
    pub fn new(root: &[u8]) -> Result<Self, Verdict> {
        Self::build(root, Vec::new(), false)
    }

    /// Parse a root `vbmeta`, verify it, and accept it only when its signing key
    /// is one of the caller's `keys`.
    ///
    /// This is the only source of trust. The keys are a set: order carries no
    /// meaning, and no key is selected from a device image. An empty set is a
    /// caller error rather than a silent unanchored success.
    pub fn with_trusted_keys(root: &[u8], keys: &[KeyBlob]) -> Result<Self, Verdict> {
        if keys.is_empty() {
            return Err(Verdict::Malformed(Defect::NoTrustedKey));
        }
        Self::build(root, keys.to_vec(), true)
    }

    /// Walk a root `vbmeta` structurally, without requiring it to verify.
    ///
    /// This exists only for callers that deliberately build an artifact from
    /// unverified metadata; every verdict is still recorded, so nothing is
    /// reported as verified that is not.
    pub fn new_unverified(root: &[u8]) -> Result<Self, Defect> {
        let info = meta::inspect(root)?;
        let exact = root
            .get(..info.size)
            .ok_or(Defect::Format(avb_format::Defect::Truncated))?;
        let keys: Vec<KeyBlob> = Vec::new();
        let verdict = root_verdict(exact, &info, &keys);
        Self::assemble(exact, info, keys, verdict)
    }

    fn build(root: &[u8], keys: Vec<KeyBlob>, require_trusted: bool) -> Result<Self, Verdict> {
        let info = meta::inspect(root).map_err(Verdict::Malformed)?;
        let Some(exact) = root.get(..info.size) else {
            return Err(Verdict::Malformed(Defect::Format(
                avb_format::Defect::Truncated,
            )));
        };
        let verdict = root_verdict(exact, &info, &keys);
        let acceptable =
            verdict.is_verified() && (!require_trusted || verdict.trusted() == Some(true));
        let plan =
            Self::assemble(exact, info, keys, verdict.clone()).map_err(Verdict::Malformed)?;
        if acceptable { Ok(plan) } else { Err(verdict) }
    }

    fn assemble(
        root: &[u8],
        info: VbmetaInfo,
        keys: Vec<KeyBlob>,
        verdict: Verdict,
    ) -> Result<Self, Defect> {
        let trusted = verdict.trusted().unwrap_or(false);
        let root_algorithm = info.header.algorithm;
        let mut plan = Self {
            nodes: vec![Node {
                name: ROOT_NAME.to_owned(),
                kind: Kind::Vbmeta,
                rollback_index_location: 0,
                flags: 0,
                parent: String::new(),
                parent_trusted: trusted,
                expected_key: None,
                expected_key_sha256: None,
                children: Vec::new(),
                metadata: Some(root.to_vec()),
                info: Some(info.clone()),
                verdict: Some(verdict),
                key_sha256: Some(info.public_key_sha256),
                trusted,
            }],
            index: BTreeMap::new(),
            keys,
            root_algorithm,
        };
        plan.index.insert(ROOT_NAME.to_owned(), 0);
        plan.discover(0, &info, trusted, true)?;
        Ok(plan)
    }

    /// Supply one image, verifying it against the key its parent demands.
    ///
    /// The image is recorded either way, so a caller that deliberately builds
    /// from unverified metadata can still see the walk; the returned value
    /// distinguishes verified from rejected.
    pub fn supply(&mut self, name: &str, bytes: &[u8]) -> Result<Accepted, Rejected> {
        let Some(&node) = self.index.get(name) else {
            return Err(Rejected {
                name: name.to_owned(),
                verdict: Verdict::Malformed(Defect::UnknownPartition(name.to_owned())),
            });
        };
        if self.nodes[node].metadata.is_some() {
            return Err(Rejected {
                name: name.to_owned(),
                verdict: Verdict::Malformed(Defect::AlreadySupplied(name.to_owned())),
            });
        }
        let verdict = self.check(node, bytes);
        let metadata_len = self.nodes[node].metadata.as_ref().map_or(0, Vec::len);
        let metadata_sha256 = self.nodes[node]
            .metadata
            .as_ref()
            .map_or([0u8; 32], |bytes| sha256(bytes));
        let index = self
            .preorder()
            .iter()
            .position(|&candidate| candidate == node)
            .unwrap_or(0);
        match verdict {
            Verdict::Verified {
                key_sha256,
                trusted,
            } => Ok(Accepted {
                name: name.to_owned(),
                kind: self.nodes[node].kind,
                metadata_len,
                metadata_sha256,
                key_sha256,
                trusted,
                index,
            }),
            verdict => Err(Rejected {
                name: name.to_owned(),
                verdict,
            }),
        }
    }

    /// Supply one image read through a caller-supplied reader.
    ///
    /// Same verification as [`Plan::supply`], but the bytes come from
    /// `read_at(offset, out)`. A `vbmeta*` image is read from offset 0 up to
    /// libavb's 64 KiB bound; any other name is located through its footer
    /// exactly as libavb locates it.
    pub fn supply_from<E: fmt::Display>(
        &mut self,
        name: &str,
        image_size: u64,
        mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<Accepted, Rejected> {
        let kind = match self.index.get(name) {
            Some(&node) => self.nodes[node].kind,
            None => {
                return Err(Rejected {
                    name: name.to_owned(),
                    verdict: Verdict::Malformed(Defect::UnknownPartition(name.to_owned())),
                });
            }
        };
        let metadata = match kind {
            Kind::Vbmeta => {
                let len = usize::try_from(image_size.min(VBMETA_MAX_SIZE)).unwrap_or(0);
                let mut buffer = vec![0u8; len];
                if let Err(error) = read_at(0, &mut buffer) {
                    return Err(Rejected {
                        name: name.to_owned(),
                        verdict: Verdict::Malformed(Defect::Read(format!("{error}"))),
                    });
                }
                buffer
            }
            Kind::Footered => match extract_vbmd(image_size, &mut read_at) {
                Ok(metadata) => metadata,
                Err(error) => {
                    return Err(Rejected {
                        name: name.to_owned(),
                        verdict: Verdict::Malformed(match error {
                            ExtractError::Malformed(defect) => Defect::Format(defect),
                            ExtractError::Read(error) => Defect::Read(format!("{error}")),
                            ExtractError::TooLarge { size } => Defect::Read(format!(
                                "footer declares {size} metadata bytes, above the {VBMETA_MAX_SIZE}-byte limit"
                            )),
                            ExtractError::BufferTooSmall { size } => Defect::Read(format!(
                                "buffer is smaller than the declared {size}-byte metadata extent"
                            )),
                        }),
                    });
                }
            },
        };
        self.supply(name, &metadata)
    }

    fn check(&mut self, node: usize, bytes: &[u8]) -> Verdict {
        let info = match meta::inspect(bytes) {
            Ok(info) => info,
            Err(defect) => return Verdict::Malformed(defect),
        };
        let Some(exact) = bytes.get(..info.size) else {
            return Verdict::Malformed(Defect::Format(avb_format::Defect::Truncated));
        };
        let mut verdict = self.verdict_for(node, exact, &info);
        let trusted = verdict.trusted().unwrap_or(false);
        let is_main = node == 0;
        if let Err(defect) = self.discover(node, &info, trusted, is_main) {
            // A structural defect in the walk is always reported, whether or not
            // the image itself verified.
            verdict = Verdict::Malformed(defect);
        }
        let key_sha256 = info.public_key_sha256;
        let metadata = exact.to_vec();
        let node = &mut self.nodes[node];
        node.metadata = Some(metadata);
        node.key_sha256 = Some(key_sha256);
        node.trusted = trusted;
        node.verdict = Some(verdict.clone());
        node.info = Some(info);
        verdict
    }

    fn verdict_for(&self, node: usize, exact: &[u8], info: &VbmetaInfo) -> Verdict {
        let auth = match verify_auth(exact, &info.header) {
            Ok(auth) => auth,
            Err(verdict) => return verdict,
        };
        let record = &self.nodes[node];
        let trusted = match &record.expected_key {
            Some(expected) => {
                if auth.key != *expected {
                    return Verdict::KeyMismatch {
                        expected: sha256(expected),
                        actual: auth.key_sha256,
                    };
                }
                record.parent_trusted
            }
            None => match root_key_trust(&self.keys, &auth.key) {
                Some(trusted) => trusted,
                None => {
                    return Verdict::UntrustedKey {
                        actual: auth.key_sha256,
                    };
                }
            },
        };
        Verdict::Verified {
            key_sha256: auth.key_sha256,
            trusted,
        }
    }

    /// Create a pending node for every chain partition `info` demands.
    ///
    /// libavb permits chain descriptors only in the main image; a chained image
    /// that carries one is invalid metadata.
    fn discover(
        &mut self,
        node: usize,
        info: &VbmetaInfo,
        trusted: bool,
        is_main: bool,
    ) -> Result<(), Defect> {
        if !is_main && !info.chains.is_empty() {
            return Err(Defect::ChainInChainedImage(self.nodes[node].name.clone()));
        }
        // Validate every name before mutating anything.
        for chain in &info.chains {
            if chain.name == ROOT_NAME {
                return Err(Defect::ReservedChainName(chain.name.clone()));
            }
            if self.index.contains_key(&chain.name) {
                return Err(Defect::DuplicateChain(chain.name.clone()));
            }
        }
        if self.nodes.len() + info.chains.len() > MAX_VBMETA_IMAGES {
            return Err(Defect::TooManyImages(self.nodes.len() + info.chains.len()));
        }
        let parent = self.nodes[node].name.clone();
        let mut children = Vec::with_capacity(info.chains.len());
        for chain in &info.chains {
            let index = self.nodes.len();
            self.nodes.push(Node {
                name: chain.name.clone(),
                kind: Kind::of(&chain.name),
                rollback_index_location: chain.rollback_index_location,
                flags: chain.flags,
                parent: parent.clone(),
                parent_trusted: trusted,
                expected_key: Some(chain.public_key.clone()),
                expected_key_sha256: Some(chain.public_key_sha256),
                children: Vec::new(),
                metadata: None,
                info: None,
                verdict: None,
                key_sha256: None,
                trusted: false,
            });
            self.index.insert(chain.name.clone(), index);
            children.push(index);
        }
        self.nodes[node].children = children;
        Ok(())
    }

    /// Depth-first pre-order over the discovered tree, children in descriptor
    /// order — the order libavb appends images to `vbmeta_images`.
    fn preorder(&self) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.nodes.len());
        let mut stack = vec![0usize];
        while let Some(node) = stack.pop() {
            out.push(node);
            for &child in self.nodes[node].children.iter().rev() {
                stack.push(child);
            }
        }
        out
    }
}

/// One partition of the walk, supplied or not: the per-partition decision table.
///
/// `expected_key_sha256` is what the parent demands; the verdict carries what
/// was actually found (`Verdict::KeyMismatch { expected, actual }`), so a caller
/// can build a per-partition table without re-deriving anything.
#[derive(Clone, Debug)]
pub struct WalkNode<'a> {
    pub name: &'a str,
    pub kind: Kind,
    pub rollback_index_location: u32,
    pub expected_key_sha256: Option<[u8; 32]>,
    pub parent: &'a str,
    /// The exact metadata extent, once supplied.
    pub metadata: Option<&'a [u8]>,
    pub verdict: Option<&'a Verdict>,
}

impl Plan {
    /// Every discovered partition in libavb visit order, supplied or not.
    pub fn walk_order(&self) -> Vec<WalkNode<'_>> {
        self.preorder()
            .into_iter()
            .map(|node| {
                let record = &self.nodes[node];
                WalkNode {
                    name: &record.name,
                    kind: record.kind,
                    rollback_index_location: record.rollback_index_location,
                    expected_key_sha256: record.expected_key_sha256,
                    parent: &record.parent,
                    metadata: record.metadata.as_deref(),
                    verdict: record.verdict.as_ref(),
                }
            })
            .collect()
    }

    /// Images still required, in visit order.
    pub fn needs(&self) -> Vec<Need> {
        self.preorder()
            .into_iter()
            .filter(|&node| self.nodes[node].metadata.is_none())
            .map(|node| {
                let record = &self.nodes[node];
                Need {
                    name: record.name.clone(),
                    kind: record.kind,
                    rollback_index_location: record.rollback_index_location,
                    flags: record.flags,
                    expected_key_sha256: record.expected_key_sha256.unwrap_or([0u8; 32]),
                    parent: record.parent.clone(),
                }
            })
            .collect()
    }

    /// Names still required, in visit order.
    pub fn missing(&self) -> Vec<String> {
        self.needs().into_iter().map(|need| need.name).collect()
    }

    /// True when every discovered image is supplied and verified.
    pub fn complete(&self) -> bool {
        self.nodes.iter().all(|node| {
            node.metadata.is_some() && node.verdict.as_ref().is_some_and(Verdict::is_verified)
        })
    }

    /// Every supplied image that did not verify, in visit order.
    pub fn rejected(&self) -> Vec<(String, Verdict)> {
        self.preorder()
            .into_iter()
            .filter_map(|node| {
                let record = &self.nodes[node];
                let verdict = record.verdict.as_ref()?;
                (!verdict.is_verified()).then(|| (record.name.clone(), verdict.clone()))
            })
            .collect()
    }

    /// Supplied images in visit order, with their exact metadata.
    pub fn ordered_images(&self) -> Vec<Image<'_>> {
        self.preorder()
            .into_iter()
            .filter_map(|node| {
                let record = &self.nodes[node];
                let metadata = record.metadata.as_deref()?;
                Some(Image {
                    name: &record.name,
                    kind: record.kind,
                    metadata,
                    metadata_sha256: sha256(metadata),
                    key_sha256: record.key_sha256.unwrap_or([0u8; 32]),
                    trusted: record.trusted,
                    verdict: record.verdict.as_ref()?,
                })
            })
            .collect()
    }

    /// The metadata digest over the supplied images in visit order, each image's
    /// exact extent, hashed with the caller's chosen algorithm, with the summed
    /// exact size beside it.
    ///
    /// libavb itself has exactly one fixed choice here:
    /// [`Plan::libavb_cmdline_digest`] uses the root's algorithm. Any other
    /// value is the caller's, and this crate does not label a SHA-256 result a
    /// stock platform VBH.
    ///
    /// The value covers the images supplied *so far*, so a caller reporting an
    /// incomplete set (a plan command) can still show what the digest would be.
    pub fn vbmeta_digest_with(&self, algorithm: HashAlg) -> VbmetaDigest {
        let mut hasher = Hasher::new(algorithm);
        let mut total_size = 0u64;
        for image in self.ordered_images() {
            hasher.update(image.metadata);
            total_size += image.metadata.len() as u64;
        }
        VbmetaDigest {
            algorithm,
            digest: hasher.finish(),
            total_size,
        }
    }

    /// The summed exact extents of the images supplied so far, in visit order.
    ///
    /// This is the `androidboot.vbmeta.size`-style total that accompanies
    /// [`Plan::vbmeta_digest_with`].
    pub fn vbmeta_digest_size(&self) -> u64 {
        self.ordered_images()
            .iter()
            .map(|image| image.metadata.len() as u64)
            .sum()
    }

    /// `androidboot.vbmeta.hash_alg`/`.digest`/`.size` exactly as libavb's
    /// `avb_append_options()` emits them, or `None` when libavb emits nothing.
    ///
    /// The hash is selected by the **root's** `algorithm_type`
    /// ([`HashAlg::libavb_cmdline`]), not by a chained image and not by this
    /// crate's preference. Nothing is emitted when the root sets
    /// [`VBMETA_FLAG_VERIFICATION_DISABLED`]: libavb takes the unverified path
    /// there and never calls `avb_append_options()`.
    pub fn libavb_cmdline_digest(&self) -> Option<CmdlineDigest> {
        if self.root_info().header.flags & VBMETA_FLAG_VERIFICATION_DISABLED != 0 {
            return None;
        }
        let hash_alg = HashAlg::libavb_cmdline(self.root_algorithm)?;
        let digest = self.vbmeta_digest_with(hash_alg);
        Some(CmdlineDigest {
            hash_alg,
            digest: digest.digest,
            size: digest.total_size,
        })
    }

    /// Partitions named by a *hash* descriptor in any supplied image: the ones
    /// libavb loads and hashes in full when they are requested.
    pub fn payload_hashed(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for node in self.preorder() {
            let Some(info) = self.nodes[node].info.as_ref() else {
                continue;
            };
            for name in &info.hashed {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        names
    }

    /// The signed coverage of every supplied image, in visit order.
    ///
    /// This is raw evidence. libavb does not bind a partition name to a vbmeta
    /// image, so a caller that wants to judge whether an image covers the
    /// partition it was supplied for applies its own convention to this value.
    pub fn covered(&self) -> Vec<(String, Vec<String>)> {
        self.preorder()
            .into_iter()
            .filter_map(|node| {
                let record = &self.nodes[node];
                let info = record.info.as_ref()?;
                Some((record.name.clone(), info.covered.clone()))
            })
            .collect()
    }

    /// Judge one candidate image against the demand this plan holds for `name`,
    /// without recording it.
    ///
    /// The verdict is exactly what [`Plan::supply`] would return;
    /// `Malformed(UnknownPartition)` when the plan does not demand that name.
    pub fn judge(&self, name: &str, bytes: &[u8]) -> Verdict {
        let Some(&node) = self.index.get(name) else {
            return Verdict::Malformed(Defect::UnknownPartition(name.to_owned()));
        };
        let info = match meta::inspect(bytes) {
            Ok(info) => info,
            Err(defect) => return Verdict::Malformed(defect),
        };
        let Some(exact) = bytes.get(..info.size) else {
            return Verdict::Malformed(Defect::Format(avb_format::Defect::Truncated));
        };
        self.verdict_for(node, exact, &info)
    }

    /// SHA-256 of the key the plan demands for `name`.
    ///
    /// `None` for the root (which is judged against the caller's keys, not
    /// against a parent's chain descriptor) and for names the plan does not
    /// demand.
    pub fn demanded_key_sha256(&self, name: &str) -> Option<[u8; 32]> {
        self.index
            .get(name)
            .and_then(|&node| self.nodes[node].expected_key_sha256)
    }

    /// Parsed info for a supplied image.
    pub fn image_info(&self, name: &str) -> Option<&VbmetaInfo> {
        self.index
            .get(name)
            .and_then(|&node| self.nodes[node].info.as_ref())
    }

    /// The exact metadata extent of a supplied image.
    pub fn image_metadata(&self, name: &str) -> Option<&[u8]> {
        self.index
            .get(name)
            .and_then(|&node| self.nodes[node].metadata.as_deref())
    }

    /// The verdict for a supplied image.
    pub fn image_verdict(&self, name: &str) -> Option<&Verdict> {
        self.index
            .get(name)
            .and_then(|&node| self.nodes[node].verdict.as_ref())
    }

    /// Every supplied image with its parsed info, in visit order.
    pub fn supplied_info(&self) -> Vec<(&str, &VbmetaInfo)> {
        self.preorder()
            .into_iter()
            .filter_map(|node| {
                let record = &self.nodes[node];
                let info = record.info.as_ref()?;
                Some((record.name.as_str(), info))
            })
            .collect()
    }

    /// The root's `algorithm_type`.
    pub fn root_algorithm(&self) -> u32 {
        self.root_algorithm
    }

    /// The hash of the root's own `algorithm_type`
    /// ([`HashAlg::from_algorithm_type`]), or `None` for an unsigned or
    /// ML-DSA-signed root.
    ///
    /// This is the root's **authentication** hash. It is not necessarily the
    /// cmdline's hash ([`Plan::libavb_cmdline_digest`], which maps an ML-DSA root
    /// to SHA-256).
    pub fn digest_algorithm(&self) -> Option<HashAlg> {
        HashAlg::from_algorithm_type(self.root_algorithm)
    }

    /// The exact root metadata extent.
    pub fn root_metadata(&self) -> &[u8] {
        self.nodes[0].metadata.as_deref().unwrap_or(&[])
    }

    /// The keys this plan trusts for the root.
    pub fn trusted_keys(&self) -> &[KeyBlob] {
        &self.keys
    }

    /// Parsed root metadata.
    pub fn root_info(&self) -> &VbmetaInfo {
        // The root node always carries parsed info.
        self.nodes[0].info.as_ref().expect("root info")
    }

    /// The root's verdict.
    pub fn root_verdict(&self) -> &Verdict {
        self.nodes[0].verdict.as_ref().expect("root verdict")
    }

    /// Whether the root verified against a caller-supplied trusted key.
    pub fn is_trusted(&self) -> bool {
        self.nodes[0].trusted
    }

    /// The root's own property descriptors, in descriptor order.
    pub fn root_properties(&self) -> &[Property] {
        self.nodes[0]
            .info
            .as_ref()
            .map(|info| info.properties.as_slice())
            .unwrap_or_default()
    }

    /// Property descriptors of one supplied image, in descriptor order.
    pub fn image_properties(&self, name: &str) -> Option<&[Property]> {
        self.image_info(name).map(|info| info.properties.as_slice())
    }
}

/// The root's verdict: self-verifying, and trusted only when its key is one the
/// caller explicitly supplied.
///
/// With no keys (`Plan::new`) a self-verifying root is `Verified { trusted:
/// false }`; with keys, any byte-equal key makes it trusted, and no key is an
/// [`Verdict::UntrustedKey`].
fn root_verdict(exact: &[u8], info: &VbmetaInfo, keys: &[KeyBlob]) -> Verdict {
    let auth = match verify_auth(exact, &info.header) {
        Ok(auth) => auth,
        Err(verdict) => return verdict,
    };
    match root_key_trust(keys, &auth.key) {
        Some(trusted) => Verdict::Verified {
            key_sha256: auth.key_sha256,
            trusted,
        },
        None => Verdict::UntrustedKey {
            actual: auth.key_sha256,
        },
    }
}

/// How the root's signing key relates to the keys the caller supplied.
///
/// `None` means keys were supplied and none is the signing key.
fn root_key_trust(keys: &[KeyBlob], key: &[u8]) -> Option<bool> {
    if keys.is_empty() {
        return Some(false);
    }
    keys.iter()
        .any(|candidate| candidate.blob == key)
        .then_some(true)
}

/// Verify one image against its own embedded key: hash, then signature.
fn verify_auth(bytes: &[u8], head: &avb_format::Header) -> Result<Auth, Verdict> {
    let algorithm = match HashAlg::from_algorithm_type(head.algorithm) {
        Some(algorithm) => algorithm,
        None if head.algorithm == 0 => return Err(Verdict::Unsigned),
        None => return Err(Verdict::Malformed(Defect::Algorithm(head.algorithm))),
    };
    let found_hash =
        usize::try_from(head.hash_size).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    if found_hash != algorithm.len() {
        return Err(Verdict::Malformed(Defect::HashSize {
            expected: algorithm.len(),
            found: found_hash,
        }));
    }
    let key_bytes = HashAlg::key_bytes(head.algorithm)
        .ok_or(Verdict::Malformed(Defect::Algorithm(head.algorithm)))?;
    let found_signature =
        usize::try_from(head.signature_size).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    if found_signature != key_bytes {
        return Err(Verdict::Malformed(Defect::SignatureSize {
            expected: key_bytes,
            found: found_signature,
        }));
    }
    let auth_start = HEADER_SIZE as u64;
    let aux_start = auth_start + head.auth_size;
    let stored_hash = region(bytes, auth_start + head.hash_offset, head.hash_size)?;
    let auxiliary = region(bytes, aux_start, head.aux_size)?;
    let mut hasher = Hasher::new(algorithm);
    hasher.update(
        bytes
            .get(..HEADER_SIZE)
            .ok_or(Verdict::Malformed(Defect::Format(
                avb_format::Defect::Truncated,
            )))?,
    );
    hasher.update(auxiliary);
    let computed = hasher.finish();
    if computed != stored_hash {
        return Err(Verdict::HashMismatch);
    }
    let public_key = region(
        bytes,
        aux_start + head.public_key_offset,
        head.public_key_size,
    )?;
    let signature = region(
        bytes,
        auth_start + head.signature_offset,
        head.signature_size,
    )?;
    if !rsa_pkcs1_verify(public_key, signature, &computed, algorithm) {
        return Err(Verdict::SignatureMismatch);
    }
    Ok(Auth {
        key: public_key.to_vec(),
        key_sha256: sha256(public_key),
    })
}

fn region(bytes: &[u8], start: u64, len: u64) -> Result<&[u8], Verdict> {
    let start = usize::try_from(start).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    let len = usize::try_from(len).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    let end = start
        .checked_add(len)
        .ok_or(Verdict::Malformed(Defect::Overflow))?;
    bytes
        .get(start..end)
        .ok_or(Verdict::Malformed(Defect::Format(
            avb_format::Defect::Truncated,
        )))
}
