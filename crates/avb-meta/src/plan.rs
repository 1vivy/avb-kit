//! The plan: walking a root `vbmeta` into the set of images the ABL will load,
//! verifying each supplied image, and producing the metadata digest.
//!
//! See the crate documentation for the libavb behaviour this mirrors, for the two
//! stated deviations, and for the limits of the identity check.

use crate::meta::{self, HEADER_SIZE, MAX_VBMETA_IMAGES, VBMETA_MAX_SIZE, VbmetaInfo};
use crate::rsa::{self, AblKey, AblKeys};
use crate::{
    Accepted, Defect, HashAlg, Hasher, Header, Image, Kind, Need, Properties, Rejected, Verdict,
    hex, sha256,
};
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use avb_graft::{FOOTER_SIZE, parse_footer};
use core::fmt;

/// The partition name of the root metadata entry.
pub const ROOT_NAME: &str = "vbmeta";

/// Why a footer-located metadata extent could not be recovered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtractError<E> {
    /// The partition or its footer is unusable.
    Malformed(Defect),
    /// The caller's backing read failed.
    Read(E),
    /// The footer declares more metadata than [`VBMETA_MAX_SIZE`].
    TooLarge { size: u64 },
}

impl<E> From<Defect> for ExtractError<E> {
    fn from(defect: Defect) -> Self {
        Self::Malformed(defect)
    }
}

impl<E: fmt::Display> fmt::Display for ExtractError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(defect) => write!(f, "{defect}"),
            Self::Read(error) => write!(f, "backing read failed: {error}"),
            Self::TooLarge { size } => write!(
                f,
                "footer declares {size} metadata bytes, above the {VBMETA_MAX_SIZE}-byte limit"
            ),
        }
    }
}

/// Read the OEM metadata extent out of a footered partition without holding the
/// partition in memory.
///
/// `read_at(offset, out)` is called twice: once for the final 64 bytes, and once
/// for the exact metadata extent the footer declares. That is the same two-step
/// libavb performs, with the same 64 KiB bound on the declared size.
pub fn extract_vbmd<E>(
    image_size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Vec<u8>, ExtractError<E>> {
    let footer_offset = image_size
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or(ExtractError::Malformed(Defect::Truncated))?;
    let mut footer = [0u8; FOOTER_SIZE];
    read_at(footer_offset, &mut footer).map_err(ExtractError::Read)?;
    let parsed = parse_footer(&footer, image_size)
        .map_err(|error| ExtractError::Malformed(Defect::Graft(error)))?;
    if parsed.vbmeta_size > VBMETA_MAX_SIZE {
        return Err(ExtractError::TooLarge {
            size: parsed.vbmeta_size,
        });
    }
    let len = usize::try_from(parsed.vbmeta_size)
        .map_err(|_| ExtractError::Malformed(Defect::Overflow))?;
    let mut metadata = vec![0u8; len];
    read_at(parsed.vbmeta_offset, &mut metadata).map_err(ExtractError::Read)?;
    let exact = meta::exact_metadata(&metadata)?;
    Ok(exact.to_vec())
}

/// A digest over a set of vbmeta images, in libavb visit order.
///
/// The same ordered extents feed two different hashes, so which one a value is
/// is always stated by `algorithm`, never implied:
///
/// * [`Plan::vbmeta_digest`] is what the OEM ABL computes for its own VBH
///   (`SET_VBH`, and what KeyMint's rollback compares against) — always SHA-256;
/// * [`Plan::libavb_cmdline_digest`] is what `androidboot.vbmeta.digest` carries
///   — the root's algorithm, so SHA-512 for a SHA-512-signed root;
/// * [`Plan::vbmeta_digest_with`] takes whichever hash the caller asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VbmetaDigest {
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
#[cfg(feature = "digest")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmdlineDigest {
    /// The hash the root's `algorithm_type` selects.
    pub hash_alg: HashAlg,
    pub digest: Vec<u8>,
    pub size: u64,
}

#[cfg(feature = "digest")]
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
    parent: String,
    /// Whether the parent chain reaches an ABL-anchored root.
    parent_anchored: bool,
    /// Key the parent's chain descriptor demands, `None` for the root.
    expected_key: Option<Vec<u8>>,
    expected_key_sha256: Option<[u8; 32]>,
    children: Vec<usize>,
    metadata: Option<Vec<u8>>,
    info: Option<VbmetaInfo>,
    verdict: Option<Verdict>,
    key_sha256: Option<[u8; 32]>,
    anchored: bool,
}

/// The walk from one root `vbmeta`, and every image supplied so far.
#[derive(Debug)]
pub struct Plan {
    nodes: Vec<Node>,
    index: BTreeMap<String, usize>,
    /// Every key the caller supplied, in file order (anchor first).
    keys: AblKeys,
    /// The trusted set: the anchor first, then the explicitly trusted extras.
    /// A root signed by anything else in `keys` is UNANCHORED.
    trusted: Vec<AblKey>,
    root_algorithm: u32,
    /// The root's own authentication hash, for [`Plan::digest_algorithm`].
    digest_algorithm: HashAlg,
}

impl Plan {
    /// Parse and verify a root `vbmeta` that is *not* anchored to an ABL key.
    ///
    /// The root must verify against its own embedded key; the resulting verdict
    /// is `Verified { anchored: false }` — UNANCHORED.
    pub fn new(root: &[u8]) -> Result<Self, Verdict> {
        Self::build(root, AblKeys::default(), Vec::new(), false)
    }

    /// Parse and verify a root `vbmeta` that must be anchored to the ABL's
    /// trust anchor.
    ///
    /// The anchor is the **first** key embedded in the ABL
    /// ([`AblKeys::anchor`]), which is the one the stock ABL's
    /// `AvbValidateVbmetaPublicKey` byte-compares against. A root signed by a
    /// *later* embedded key is reported `Verified { anchored: false }` —
    /// UNANCHORED — and refused here, because the ABL would refuse it; a caller
    /// that means to trust such a key says so through
    /// [`Plan::anchored_with_extra`].
    pub fn anchored(root: &[u8], anchors: &AblKeys) -> Result<Self, Verdict> {
        Self::anchored_with_extra(root, anchors, &[])
    }

    /// [`Plan::anchored`], plus keys the caller explicitly trusts.
    ///
    /// This is the only way a root signed by a later embedded key is accepted as
    /// anchored, and it is deliberately explicit.
    pub fn anchored_with_extra(
        root: &[u8],
        anchors: &AblKeys,
        extra_trusted: &[AblKey],
    ) -> Result<Self, Verdict> {
        let Some(anchor) = anchors.anchor() else {
            return Err(Verdict::Malformed(Defect::NoAnchorKey));
        };
        let mut trusted = Vec::with_capacity(1 + extra_trusted.len());
        trusted.push(anchor.clone());
        for key in extra_trusted {
            if !trusted.iter().any(|existing| existing.blob == key.blob) {
                trusted.push(key.clone());
            }
        }
        Self::build(root, anchors.clone(), trusted, true)
    }

    /// Walk a root `vbmeta` structurally, without requiring it to verify.
    ///
    /// This exists only for callers that deliberately build an artifact from
    /// unverified metadata; every verdict is still recorded, so nothing is
    /// reported as verified that is not.
    pub fn new_unverified(root: &[u8]) -> Result<Self, Defect> {
        let info = meta::inspect(root)?;
        let exact = root.get(..info.size).ok_or(Defect::Truncated)?;
        let keys = AblKeys::default();
        let trusted: Vec<AblKey> = Vec::new();
        let verdict = root_verdict(exact, &info, &keys, &trusted);
        Self::assemble(exact, info, keys, trusted, verdict)
    }

    fn build(
        root: &[u8],
        keys: AblKeys,
        trusted: Vec<AblKey>,
        require_anchored: bool,
    ) -> Result<Self, Verdict> {
        let info = meta::inspect(root).map_err(Verdict::Malformed)?;
        let Some(exact) = root.get(..info.size) else {
            return Err(Verdict::Malformed(Defect::Truncated));
        };
        let verdict = root_verdict(exact, &info, &keys, &trusted);
        // A root that verifies against a key which is not in the trusted set is
        // UNANCHORED: it is reported as such, and it is not enough for callers
        // that asked for an anchored root.
        let acceptable =
            verdict.is_verified() && (!require_anchored || verdict.anchored() == Some(true));
        let plan = Self::assemble(exact, info, keys, trusted, verdict.clone())
            .map_err(Verdict::Malformed)?;
        if acceptable { Ok(plan) } else { Err(verdict) }
    }

    fn assemble(
        root: &[u8],
        info: VbmetaInfo,
        keys: AblKeys,
        trusted: Vec<AblKey>,
        verdict: Verdict,
    ) -> Result<Self, Defect> {
        let anchored = verdict.anchored().unwrap_or(false);
        let digest_algorithm =
            HashAlg::from_algorithm_type(info.header.algorithm).unwrap_or(HashAlg::Sha256);
        let mut plan = Self {
            nodes: vec![Node {
                name: ROOT_NAME.to_owned(),
                kind: Kind::Vbmeta,
                rollback_index_location: 0,
                parent: String::new(),
                parent_anchored: anchored,
                expected_key: None,
                expected_key_sha256: None,
                children: Vec::new(),
                metadata: Some(root.to_vec()),
                info: Some(info.clone()),
                verdict: Some(verdict),
                key_sha256: Some(info.public_key_sha256),
                anchored,
            }],
            index: BTreeMap::new(),
            keys,
            trusted,
            root_algorithm: info.header.algorithm,
            digest_algorithm,
        };
        plan.index.insert(ROOT_NAME.to_owned(), 0);
        plan.discover(0, &info, anchored)?;
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
                verdict: Verdict::Malformed(Defect::DuplicatePartition(name.to_owned())),
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
                anchored,
            } => Ok(Accepted {
                name: name.to_owned(),
                kind: self.nodes[node].kind,
                metadata_len,
                metadata_sha256,
                key_sha256,
                anchored,
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
    /// `read_at(offset, out)`, so a file, a firmware-zip range, a browser blob and
    /// a BlockIo handle all serve the same code. A `vbmeta*` image is read from
    /// offset 0 up to libavb's 64 KiB bound; any other name is located through its
    /// footer exactly as libavb locates it.
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
                            ExtractError::Malformed(defect) => defect,
                            ExtractError::Read(error) => Defect::Read(format!("{error}")),
                            ExtractError::TooLarge { size } => Defect::Read(format!(
                                "footer declares {size} metadata bytes, above the {VBMETA_MAX_SIZE}-byte limit"
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
            return Verdict::Malformed(Defect::Truncated);
        };
        let mut verdict = self.verdict_for(node, exact, &info);
        let anchored = verdict.anchored().unwrap_or(false);
        if let Err(defect) = self.discover(node, &info, anchored) {
            // A structural defect in the walk is always reported, whether or not
            // the image itself verified.
            verdict = Verdict::Malformed(defect);
        }
        let key_sha256 = info.public_key_sha256;
        let metadata = exact.to_vec();
        let node = &mut self.nodes[node];
        node.metadata = Some(metadata);
        node.key_sha256 = Some(key_sha256);
        node.anchored = anchored;
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
        let anchored = match &record.expected_key {
            Some(expected) => {
                if auth.key != *expected {
                    return Verdict::KeyMismatch {
                        expected: sha256(expected),
                        actual: auth.key_sha256,
                    };
                }
                record.parent_anchored
            }
            None => match key_trust(&self.keys, &self.trusted, &auth.key) {
                KeyTrust::Anchored => true,
                KeyTrust::Unanchored => false,
                KeyTrust::Rejected(expected) => {
                    return Verdict::KeyMismatch {
                        expected,
                        actual: auth.key_sha256,
                    };
                }
            },
        };
        if !identity_ok(&record.name, &info.covered) {
            return Verdict::WrongPartition {
                need: record.name.clone(),
                covered: info.covered.clone(),
            };
        }
        Verdict::Verified {
            key_sha256: auth.key_sha256,
            anchored,
        }
    }

    /// Create a pending node for every chain partition `info` demands.
    fn discover(&mut self, node: usize, info: &VbmetaInfo, anchored: bool) -> Result<(), Defect> {
        // Validate every name before mutating anything.
        for chain in &info.chains {
            if chain.name == ROOT_NAME {
                return Err(Defect::ReservedChainName(chain.name.clone()));
            }
            if self.index.contains_key(&chain.name) {
                return Err(Defect::DuplicatePartition(chain.name.clone()));
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
                parent: parent.clone(),
                parent_anchored: anchored,
                expected_key: Some(chain.public_key.clone()),
                expected_key_sha256: Some(chain.public_key_sha256),
                children: Vec::new(),
                metadata: None,
                info: None,
                verdict: None,
                key_sha256: None,
                anchored: false,
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
                    anchored: record.anchored,
                    verdict: record.verdict.as_ref()?,
                })
            })
            .collect()
    }

    /// The OEM ABL's own metadata digest — always **SHA-256** — over the
    /// supplied images in visit order, each image's exact extent
    /// (`256 + authentication_data_block_size + auxiliary_data_block_size`), with
    /// the total size the ABL reports beside it.
    ///
    /// This is the `SET_VBH` value: the observed Qualcomm ABL's
    /// `ComputeVbMetaDigest` is SHA-256 over the ordered extents whatever the
    /// metadata is signed with. KeyMint uses SHA-256, and libavb's cmdline uses
    /// the root's algorithm. [`Plan::libavb_cmdline_digest`] is the other one.
    pub fn vbmeta_digest(&self) -> VbmetaDigest {
        self.vbmeta_digest_with(HashAlg::Sha256)
    }

    /// [`Plan::vbmeta_digest`] with an explicitly chosen hash.
    ///
    /// The value is computed over the images supplied *so far*, in visit order,
    /// so a caller that deliberately reports an incomplete set (a plan command)
    /// can still show what the digest would be; the size is the same sum
    /// `androidboot.vbmeta.size` carries for that set.
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

    /// `androidboot.vbmeta.hash_alg`/`.digest`/`.size` exactly as libavb's
    /// `avb_append_options()` emits them (`avb_cmdline.c:303-359`), or `None`
    /// when libavb emits nothing at all.
    ///
    /// The hash is selected by the **root's** `algorithm_type`, not by any
    /// chained image and not by this crate's own preference
    /// ([`HashAlg::libavb_cmdline`] mirrors the C switch, ML-DSA roots included).
    /// Nothing is emitted when the root sets
    /// [`VBMETA_FLAG_VERIFICATION_DISABLED`](crate::VBMETA_FLAG_VERIFICATION_DISABLED):
    /// `avb_slot_verify.c:1599-1601` takes the unverified path there and never
    /// calls `avb_append_options()`, so a caller that substitutes such a root is
    /// substituting a root with no libavb digest at all.
    #[cfg(feature = "digest")]
    pub fn libavb_cmdline_digest(&self) -> Option<CmdlineDigest> {
        if self.root_info().header.flags & crate::VBMETA_FLAG_VERIFICATION_DISABLED != 0 {
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

    /// The AVF **DICE authority** hash: SHA-512 over the embedded public key of
    /// every supplied image, concatenated in visit order with repeats kept.
    ///
    /// GBL and the profile minter agree on that input. GBL's
    /// `AVFVerificationData::public_key_digest::<Sha512>(None)` hashes
    /// `header_verified().public_key()` of every loaded vbmeta image, the root
    /// included (`libgbl/src/android_boot/avf.rs` at `c6716cc`). The profile
    /// minter (`shared/profile`) hashes the key of each image in the same visit
    /// order, as exactly `public_key_size` bytes at `public_key_offset` of the
    /// auxiliary block. Neither deduplicates equal keys, and no layout-crate
    /// scan is involved.
    ///
    /// `Some` only when every discovered image is supplied and verified, the
    /// state that both paths hash in. `None` otherwise, so a caller can never
    /// mistake a partial hash for the authority value.
    #[cfg(feature = "digest")]
    pub fn authority_sha512(&self) -> Option<[u8; 64]> {
        if !self.complete() {
            return None;
        }
        let keys: Vec<&[u8]> = self
            .supplied_info()
            .iter()
            .map(|(_, info)| info.public_key.as_slice())
            .collect();
        Some(crate::sha512_concat(&keys))
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

    /// The signed coverage of every supplied image: the evidence behind
    /// [`Verdict::WrongPartition`].
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
    /// This is the primitive a launch-time resolver needs to compare an on-slot
    /// candidate with a stored one before choosing between them (ablwrap's
    /// `ablwrap-resolve` crate is the only such caller today). The verdict is
    /// exactly what [`Plan::supply`] would return;
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
            return Verdict::Malformed(Defect::Truncated);
        };
        self.verdict_for(node, exact, &info)
    }

    /// SHA-256 of the key the plan demands for `name`.
    ///
    /// `None` for the root (which is judged against the ABL keys, not against a
    /// parent's chain descriptor) and for names the plan does not demand.
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
    /// ([`HashAlg::from_algorithm_type`]), defaulting to SHA-256 for a root that
    /// is unsigned (`algorithm_type` NONE) or ML-DSA-signed.
    ///
    /// This is the root's **authentication** hash. It is not the ABL's VBH
    /// ([`Plan::vbmeta_digest`], always SHA-256) and not necessarily the
    /// cmdline's hash ([`Plan::libavb_cmdline_digest`], which maps an ML-DSA root
    /// to SHA-256 while this returns SHA-256 only by the default).
    pub fn digest_algorithm(&self) -> HashAlg {
        self.digest_algorithm
    }

    /// The exact root metadata extent.
    pub fn root_metadata(&self) -> &[u8] {
        self.nodes[0].metadata.as_deref().unwrap_or(&[])
    }

    /// The key set this plan trusts, anchor first.
    ///
    /// Index 0 is the ABL's trust anchor; any later entry was passed as
    /// `extra_trusted`.
    pub fn trusted_keys(&self) -> &[AblKey] {
        &self.trusted
    }

    /// Every key the caller supplied, anchor first — including later embedded
    /// keys that are not trusted, so a report can show them.
    pub fn key_set(&self) -> &AblKeys {
        &self.keys
    }

    /// The trust anchor this plan checked the root against.
    pub fn trust_anchor(&self) -> Option<&AblKey> {
        self.trusted.first()
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

    /// Whether the root is anchored to an ABL key.
    pub fn is_anchored(&self) -> bool {
        self.nodes[0].anchored
    }

    /// The root's own build properties.
    pub fn root_properties(&self) -> Properties {
        self.nodes[0]
            .info
            .as_ref()
            .map(|info| info.properties.clone())
            .unwrap_or_default()
    }

    /// The build properties the ABL prefers: `boot` metadata first, else root.
    pub fn properties(&self) -> Properties {
        let boot = self.boot_properties();
        if boot.is_empty() {
            self.root_properties()
        } else {
            boot.or(&self.root_properties())
        }
    }

    fn boot_properties(&self) -> Properties {
        self.index
            .get("boot")
            .and_then(|&node| self.nodes[node].info.as_ref())
            .map(|info| info.properties.clone())
            .unwrap_or_default()
    }

    /// Provenance of [`Plan::properties`], as the evidence report words it.
    pub fn properties_source(&self) -> &'static str {
        if !self.boot_properties().is_empty() {
            "from the boot metadata properties the ABL prefers"
        } else if !self.root_properties().is_empty() {
            "from the root vbmeta properties (no boot metadata supplied)"
        } else {
            "absent: the ABL falls back to the boot header fields"
        }
    }
}

/// Does the signed coverage of an image identify it as the demanded partition?
///
/// AVB does not bind a partition name to a vbmeta image, so this is a convention,
/// not a signature check: `vbmeta_<group>` must declare coverage for `<group>`,
/// and any other name must be covered by itself or a name in its group. An image
/// that names no partition at all cannot be judged this way and is accepted.
fn identity_ok(need: &str, covered: &[String]) -> bool {
    if covered.is_empty() {
        return true;
    }
    let group = need.strip_prefix("vbmeta_");
    covered.iter().any(|name| match group {
        Some(group) => {
            name == group
                || name.starts_with(&format!("{group}_"))
                || group.starts_with(&format!("{name}_"))
        }
        None => {
            name == need
                || name.starts_with(&format!("{need}_"))
                || need.starts_with(&format!("{name}_"))
        }
    })
}

/// Verify one image against its own embedded key: hash, then signature.
fn verify_auth(bytes: &[u8], head: &Header) -> Result<Auth, Verdict> {
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
            .ok_or(Verdict::Malformed(Defect::Truncated))?,
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
    if !rsa::rsa_pkcs1_verify(public_key, signature, &computed, algorithm) {
        return Err(Verdict::SignatureMismatch);
    }
    Ok(Auth {
        key: public_key.to_vec(),
        key_sha256: sha256(public_key),
    })
}

/// The root's verdict: self-verifying, and anchored only when its key is one the
/// caller trusts — the ABL's **first** embedded key, or an explicitly trusted
/// extra.
///
/// A root signed by a later embedded key is `Verified { anchored: false }`,
/// i.e. UNANCHORED: the key is in the ABL, but it is not the one the stock
/// `AvbValidateVbmetaPublicKey` byte-compares against. Any other key is a
/// `KeyMismatch` against the anchor.
fn root_verdict(exact: &[u8], info: &VbmetaInfo, keys: &AblKeys, trusted: &[AblKey]) -> Verdict {
    let auth = match verify_auth(exact, &info.header) {
        Ok(auth) => auth,
        Err(verdict) => return verdict,
    };
    match key_trust(keys, trusted, &auth.key) {
        KeyTrust::Anchored => Verdict::Verified {
            key_sha256: auth.key_sha256,
            anchored: true,
        },
        KeyTrust::Unanchored => Verdict::Verified {
            key_sha256: auth.key_sha256,
            anchored: false,
        },
        KeyTrust::Rejected(expected) => Verdict::KeyMismatch {
            expected,
            actual: auth.key_sha256,
        },
    }
}

/// How the root's signing key relates to the keys the caller supplied.
enum KeyTrust {
    /// The anchor or an explicitly trusted extra.
    Anchored,
    /// Embedded in the ABL, but not the anchor: UNANCHORED. Also the answer
    /// when the caller supplied no keys at all (`Plan::new`).
    Unanchored,
    /// Not a key the caller supplied: rejected against the anchor's digest.
    Rejected([u8; 32]),
}

fn key_trust(keys: &AblKeys, trusted: &[AblKey], key: &[u8]) -> KeyTrust {
    if keys.is_empty() {
        return KeyTrust::Unanchored;
    }
    if trusted.iter().any(|candidate| candidate.blob == key) {
        return KeyTrust::Anchored;
    }
    if keys.keys().iter().any(|candidate| candidate.blob == key) {
        return KeyTrust::Unanchored;
    }
    KeyTrust::Rejected(
        keys.anchor()
            .map(|anchor| anchor.sha256)
            .unwrap_or([0u8; 32]),
    )
}

fn region(bytes: &[u8], start: u64, len: u64) -> Result<&[u8], Verdict> {
    let start = usize::try_from(start).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    let len = usize::try_from(len).map_err(|_| Verdict::Malformed(Defect::Overflow))?;
    let end = start
        .checked_add(len)
        .ok_or(Verdict::Malformed(Defect::Overflow))?;
    bytes
        .get(start..end)
        .ok_or(Verdict::Malformed(Defect::Truncated))
}
