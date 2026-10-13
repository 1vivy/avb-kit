//! AVB's RSA public keys, PKCS#1 v1.5 verification, and structural recovery of
//! the keys an ABL embeds.
//!
//! `AvbRSAPublicKeyHeader` is `key_num_bits` (u32 BE) followed by `n0inv`
//! (u32 BE), then the modulus and `rr = 2^(2*bits) mod modulus`, each
//! `key_num_bits / 8` bytes, big-endian. libavb accepts `key_num_bits` of 2048,
//! 4096 or 8192 and requires the blob length to be exactly
//! `8 + 2 * key_num_bits / 8` (`avb_rsa.c:55-71`).
//!
//! Signature verification mirrors `avb_rsa_verify()`: the signature is raised to
//! the public exponent 65537 modulo the modulus, and the result is compared with
//! the PKCS#1 v1.5 encoding `00 01 FF…FF 00 T H` where `T` is the 19-byte
//! DigestInfo prefix for the hash (`avb_crypto.c`'s padding constants are that
//! same byte string). libavb uses a Montgomery ladder over the key's `n0inv`/`rr`
//! precomputation; this crate uses plain modular exponentiation and therefore
//! needs only the modulus, which is exactly why [`abl_keys`] additionally checks
//! `n0inv` and `rr` for self-consistency — a blob that is not a real AVB key must
//! not be reported as one.
//!
//! The observed canoe ABL byte-compares the root vbmeta's public key against its
//! compiled-in `OEMPublicKey`; on the exact PE
//! `/home/vivy/Ghidra/inputs/canoe-abl-parallel-20260902/abl_b.LinuxLoader.efi`
//! that 1032-byte key (4096 bits) sits at file offset 452022 and hashes to
//! `8d897f62…c3853bb`.

#[cfg(feature = "verify")]
use crate::HashAlg;
#[cfg(feature = "digest")]
use crate::sha256;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "verify")]
use num_bigint::BigUint;

/// Size of `AvbRSAPublicKeyHeader`.
pub const RSA_KEY_HEADER_SIZE: usize = 8;
/// The public exponent AVB uses.
#[cfg(feature = "verify")]
const PUBLIC_EXPONENT: u32 = 65537;
/// PKCS#1 v1.5 DigestInfo prefix for SHA-256 (19 bytes).
#[cfg(feature = "verify")]
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// PKCS#1 v1.5 DigestInfo prefix for SHA-512 (19 bytes).
#[cfg(feature = "verify")]
const SHA512_DIGEST_INFO: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// An AVB RSA public key found inside a PE image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblKey {
    /// File offset of the key blob in the scanned image.
    pub file_offset: usize,
    /// `key_num_bits`.
    pub num_bits: u32,
    /// SHA-256 of the whole blob, which is what the ABL's cmdline reports.
    /// Present with the `digest` feature; the scan itself needs no hash.
    #[cfg(feature = "digest")]
    pub sha256: [u8; 32],
    /// The blob itself, byte-for-byte as the ABL would compare it.
    pub blob: Vec<u8>,
}

impl AblKey {
    /// Signature size in bytes for this key.
    pub fn signature_len(&self) -> usize {
        self.num_bits as usize / 8
    }
}

/// Every structurally self-consistent AVB key found in one image, in file
/// order, and the trust anchor derived from them.
///
/// The stock ABL's `AvbValidateVbmetaPublicKey` byte-compares the root vbmeta's
/// public key against the **first** key embedded in its own image (`fw-image`'s
/// scanner in the shared maos crates records the same rule and dedups
/// equal blobs, `next-gen/maos/shared/fw-image/src/lib.rs:201`). [`AblKeys::anchor`]
/// is therefore the first key in file order,
/// and a later key is reported (`[AblKeys::keys]`, with offsets) but is not an
/// anchor unless a caller passes it as `extra_trusted`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AblKeys {
    keys: Vec<AblKey>,
}

impl AblKeys {
    /// Scan `image` for AVB keys, in file order.
    pub fn scan(image: &[u8]) -> Self {
        Self {
            keys: scan_abl_keys(image),
        }
    }

    /// A set built by the caller, order preserved as given.
    ///
    /// The first entry is the anchor, exactly as a scan's first entry is; hosts
    /// that derive a key set some other way (a pinned anchor plus per-device
    /// keys, a test fixture) use this instead of [`AblKeys::scan`].
    pub fn from_keys(keys: Vec<AblKey>) -> Self {
        Self { keys }
    }

    /// The trust anchor: the first key in file order.
    ///
    /// `None` only when no key was found, which is a refusal to anchor rather
    /// than an unanchored success.
    pub fn anchor(&self) -> Option<&AblKey> {
        self.keys.first()
    }

    /// Every key found, in file order.
    pub fn keys(&self) -> &[AblKey] {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys themselves, consumed.
    pub fn into_keys(self) -> Vec<AblKey> {
        self.keys
    }

    /// The anchor first, then every distinct key of `self` and `extra`.
    ///
    /// This is the order the trust checks use: index 0 is the anchor, the rest
    /// are only accepted when they were explicitly trusted or embedded.
    pub fn trusted_order(&self) -> Vec<AblKey> {
        self.keys.clone()
    }
}

/// Every structurally self-consistent AVB RSA public key in `image`, in file
/// order.
///
/// The scan visits **every** byte offset, because the observed canoe key sits at
/// an even but not 4-byte-aligned offset (452022). A candidate is accepted only
/// when `key_num_bits` is 2048/4096/8192, the blob fits, the modulus is odd and
/// full width, `n0inv` is `-modulus^-1 mod 2^32`, and `rr` is
/// `2^(2*bits) mod modulus`. Those arithmetic checks are what make a reported
/// key evidence rather than a pattern match; see the crate docs for the
/// limitation that structural consistency is not proof the ABL uses the blob.
///
/// Every occurrence is reported with its offset: unlike gobbl's
/// `scan_avb_keys`, which dedups equal blobs, this keeps each offset visible.
pub fn abl_keys(image: &[u8]) -> AblKeys {
    AblKeys::scan(image)
}

/// Blob length for a key of `bits` bits, or `None` for an unsupported size.
pub fn key_blob_len(bits: u32) -> Option<usize> {
    match bits {
        2048 | 4096 | 8192 => Some(RSA_KEY_HEADER_SIZE + 2 * bits as usize / 8),
        _ => None,
    }
}

/// `key_num_bits` of a blob whose length matches, or `None`.
pub fn key_num_bits(blob: &[u8]) -> Option<u32> {
    let bits = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    (key_blob_len(bits)? == blob.len()).then_some(bits)
}

fn modulus(blob: &[u8], bits: u32) -> Option<&[u8]> {
    let len = bits as usize / 8;
    blob.get(RSA_KEY_HEADER_SIZE..RSA_KEY_HEADER_SIZE + len)
}

/// The PKCS#1 v1.5 encoding of `digest` under a `key_bytes`-byte modulus.
#[cfg(feature = "verify")]
fn pkcs1_message(key_bytes: usize, digest: &[u8], algorithm: HashAlg) -> Option<Vec<u8>> {
    let info = match algorithm {
        HashAlg::Sha256 => SHA256_DIGEST_INFO.as_slice(),
        HashAlg::Sha512 => SHA512_DIGEST_INFO.as_slice(),
    };
    let padding = key_bytes.checked_sub(3 + info.len() + digest.len())?;
    let mut out = Vec::with_capacity(key_bytes);
    out.push(0x00);
    out.push(0x01);
    out.resize(2 + padding, 0xff);
    out.push(0x00);
    out.extend_from_slice(info);
    out.extend_from_slice(digest);
    Some(out)
}

/// Verify a PKCS#1 v1.5 RSA signature over `digest` with `blob` as the key.
///
/// Returns `false` for every malformed input; it never panics. Available with
/// the `verify` feature, which is what `num-bigint` is gated on.
#[cfg(feature = "verify")]
pub fn rsa_pkcs1_verify(blob: &[u8], signature: &[u8], digest: &[u8], algorithm: HashAlg) -> bool {
    let Some(bits) = key_num_bits(blob) else {
        return false;
    };
    let Some(modulus) = modulus(blob, bits) else {
        return false;
    };
    let key_bytes = bits as usize / 8;
    if signature.len() != key_bytes || digest.len() != algorithm.len() {
        return false;
    }
    let Some(expected) = pkcs1_message(key_bytes, digest, algorithm) else {
        return false;
    };
    let n = BigUint::from_bytes_be(modulus);
    if n.bits() == 0 {
        return false;
    }
    let recovered = BigUint::from_bytes_be(signature).modpow(&BigUint::from(PUBLIC_EXPONENT), &n);
    let raw = recovered.to_bytes_be();
    if raw.len() > key_bytes {
        return false;
    }
    // Left-pad to the modulus width, then compare in constant time.
    let mut padded = vec![0u8; key_bytes - raw.len()];
    padded.extend_from_slice(&raw);
    let mut difference = 0u8;
    for (a, b) in padded.iter().zip(expected.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// `-1 / n[0] mod 2^32`, where `n[0]` is the least significant 32-bit word.
fn n0inv_of(modulus: &[u8]) -> Option<u32> {
    let word = modulus.get(modulus.len().checked_sub(4)?..)?;
    let n0 = u32::from_be_bytes(word.try_into().ok()?);
    if n0 & 1 == 0 {
        return None;
    }
    let mut inverse: u32 = 1;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inverse)));
    }
    Some(inverse.wrapping_neg())
}

/// `rr == 2^(2*bits) mod modulus`.
///
/// Computed in-crate by modular doubling rather than with a big-integer
/// dependency, so that the key scan (`abl_keys`) stays usable with no
/// dependency at all — it is the one thing in this module a caller may want
/// without signature verification.
fn rr_is_consistent(modulus: &[u8], bits: u32, rr: &[u8]) -> bool {
    let Some(expected) = pow2_mod(2 * bits as usize, modulus) else {
        return false;
    };
    // `pow2_mod` returns the modulus-width form; a real `rr` is stripped of
    // leading zeros, so compare both in the same shape.
    strip_leading_zeros(&expected) == strip_leading_zeros(rr)
}

/// `2^exponent mod modulus`, for a big-endian `modulus` whose top bit is set.
///
/// At most 1024 bytes (8192 bits) of modulus and 16384 of exponent. Each step
/// doubles a value already below the modulus and subtracts the modulus back at
/// most once, so the accumulator needs exactly one byte of headroom and no
/// general division. `None` when the modulus is not full width, in which case
/// the caller's other checks have already rejected the candidate.
fn pow2_mod(exponent: usize, modulus: &[u8]) -> Option<Vec<u8>> {
    let width = modulus.len();
    if width == 0 || modulus.first()? & 0x80 == 0 {
        return None;
    }
    // Widened by one byte so the doubling never overflows.
    let mut wide_modulus = vec![0u8; width + 1];
    wide_modulus[1..].copy_from_slice(modulus);
    let mut value = vec![0u8; width + 1];
    value[width] = 1;
    for _ in 0..exponent {
        // value *= 2, most-significant byte last in memory.
        let mut carry = 0u8;
        for byte in value.iter_mut().rev() {
            let doubled = (*byte as u16) << 1 | carry as u16;
            *byte = doubled as u8;
            carry = (doubled >> 8) as u8;
        }
        // `value < 2 * modulus` and the modulus is full width, so the carry is
        // always zero here and one subtraction is enough to reduce.
        if value.as_slice() >= wide_modulus.as_slice() {
            let mut borrow = 0i16;
            for (byte, sub) in value.iter_mut().rev().zip(wide_modulus.iter().rev()) {
                let difference = *byte as i16 - *sub as i16 - borrow;
                if difference < 0 {
                    *byte = (difference + 256) as u8;
                    borrow = 1;
                } else {
                    *byte = difference as u8;
                    borrow = 0;
                }
            }
        }
    }
    // The widened top byte is zero again after reduction.
    Some(value[1..].to_vec())
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn scan_abl_keys(image: &[u8]) -> Vec<AblKey> {
    let mut found = Vec::new();
    if image.len() <= RSA_KEY_HEADER_SIZE {
        return found;
    }
    for offset in 0..=image.len() - RSA_KEY_HEADER_SIZE {
        let Some(head) = image.get(offset..offset + 4) else {
            continue;
        };
        let bits = u32::from_be_bytes(head.try_into().unwrap());
        let Some(len) = key_blob_len(bits) else {
            continue;
        };
        let Some(blob) = image.get(offset..offset + len) else {
            continue;
        };
        let Some(n0inv_bytes) = blob.get(4..8) else {
            continue;
        };
        let n0inv = u32::from_be_bytes(n0inv_bytes.try_into().unwrap());
        let Some(modulus) = modulus(blob, bits) else {
            continue;
        };
        // Full width and odd, else it is not a usable RSA modulus.
        if modulus.first().is_none_or(|byte| byte & 0x80 == 0)
            || modulus.last().is_none_or(|b| b & 1 == 0)
        {
            continue;
        }
        if n0inv_of(modulus) != Some(n0inv) {
            continue;
        }
        let rr_start = RSA_KEY_HEADER_SIZE + bits as usize / 8;
        let Some(rr) = blob.get(rr_start..rr_start + bits as usize / 8) else {
            continue;
        };
        if !rr_is_consistent(modulus, bits, rr) {
            continue;
        }
        found.push(AblKey {
            file_offset: offset,
            num_bits: bits,
            #[cfg(feature = "digest")]
            sha256: sha256(blob),
            blob: blob.to_vec(),
        });
    }
    found
}

#[cfg(all(test, feature = "verify"))]
mod tests {
    use super::*;

    /// The in-crate modular doubling is the replacement for the big-integer
    /// implementation this module used to call, so it is cross-checked against
    /// `num-bigint` on moduli of both supported key widths and on edge shapes
    /// (all-ones, top bit set, small values near powers of two).
    #[test]
    fn pow2_mod_matches_num_bigint() {
        let cases: [(u32, Vec<u8>); 5] = [
            (2048, alternating_modulus(256)),
            (2048, vec![0xff; 256]),
            (4096, alternating_modulus(512)),
            (4096, {
                let mut m = vec![0u8; 512];
                m[0] = 0x80;
                m[511] = 1;
                m
            }),
            (8192, vec![0xc3; 1024]),
        ];
        for (bits, modulus) in cases {
            assert_eq!(modulus.len() as u32, bits / 8);
            assert_ne!(modulus[0] & 0x80, 0, "the modulus must be full width");
            let expected = {
                let n = BigUint::from_bytes_be(&modulus);
                let value = (BigUint::from(1u32) << (2 * bits as usize)) % &n;
                let bytes = value.to_bytes_be();
                assert!(bytes.len() <= modulus.len());
                let mut padded = vec![0u8; modulus.len() - bytes.len()];
                padded.extend_from_slice(&bytes);
                padded
            };
            let found = pow2_mod(2 * bits as usize, &modulus).expect("full-width modulus");
            assert_eq!(found, expected, "{bits}-bit modulus");
            assert!(rr_is_consistent(&modulus, bits, &expected));
            let mut wrong = expected.clone();
            wrong[modulus.len() - 1] ^= 1;
            assert!(!rr_is_consistent(&modulus, bits, &wrong));
        }
        assert!(pow2_mod(16, &[0x01, 0x02]).is_none(), "not full width");
        assert!(pow2_mod(16, &[]).is_none());
    }

    fn alternating_modulus(width: usize) -> Vec<u8> {
        let mut modulus = vec![0u8; width];
        for (index, byte) in modulus.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { 0xaa } else { 0x55 };
        }
        modulus[0] |= 0x80;
        modulus[width - 1] |= 1;
        modulus
    }
}
