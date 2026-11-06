#![no_std]
#![forbid(unsafe_code)]
//! AVB hash selection, SHA-256/SHA-512 helpers and RSA PKCS#1 v1.5
//! verification.
//!
//! `avb-format` owns the wire framing and the public-key blob's structural
//! checks. This crate owns the arithmetic that judges a signature. It never
//! selects a trust anchor: a caller decides which blob is trusted.
//!
//! Signature verification mirrors `avb_rsa_verify()`: the signature is raised to
//! the public exponent 65537 modulo the modulus, and the result is compared with
//! the PKCS#1 v1.5 encoding `00 01 FF…FF 00 T H` where `T` is the 19-byte
//! DigestInfo prefix for the hash. Verification uses fixed-width Montgomery
//! multiplication over the public key's `n0inv`/`rr` precomputation. There are
//! no private inputs or general-purpose big integers; the only exponent is
//! 65537.

extern crate alloc;

use alloc::vec::Vec;
use avb_format::{AvbRSAPublicKeyHeader, key_modulus, key_rr};
use sha2::{Digest, Sha256};

/// Which hash a digest is taken with, chosen explicitly.
///
/// Two different hashes are in play in AVB and they are not interchangeable:
///
/// * the **authentication hash** of one image, which is whatever the image's own
///   `algorithm_type` says (`from_algorithm_type`), and
/// * the **cmdline digest** over the ordered image set, which libavb derives
///   from the *root's* `algorithm_type` (`libavb_cmdline`).
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
    /// * any other value emits nothing, so this returns `None`.
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
pub enum Hasher {
    Sha256(Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    /// Start a digest with `algorithm`.
    pub fn new(algorithm: HashAlg) -> Self {
        match algorithm {
            HashAlg::Sha256 => Self::Sha256(Sha256::new()),
            HashAlg::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }

    /// Add bytes to the digest.
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha512(hasher) => hasher.update(bytes),
        }
    }

    /// Finish the digest.
    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// SHA-256 over the concatenation of `parts`, without copying them together.
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// SHA-512 of bytes, including an AVB-serialized public key.
pub fn sha512(bytes: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(bytes).into()
}

/// SHA-512 over ordered parts without joining or deduplicating them.
///
/// For GBL's DICE authority hash the parts are every admitted vbmeta public
/// key in visit order, including repeated equal keys.
pub fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = sha2::Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// PKCS#1 v1.5 DigestInfo prefix for SHA-256 (19 bytes).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// PKCS#1 v1.5 DigestInfo prefix for SHA-512 (19 bytes).
const SHA512_DIGEST_INFO: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Verify a PKCS#1 v1.5 RSA signature over `digest` with `blob` as the key.
///
/// Returns `false` for every malformed input; it never panics. All arithmetic
/// is bounded by the supported key widths. The caller chooses whether `blob` is
/// trusted.
pub fn rsa_pkcs1_verify(blob: &[u8], signature: &[u8], digest: &[u8], algorithm: HashAlg) -> bool {
    let Some(header) = AvbRSAPublicKeyHeader::parse(blob) else {
        return false;
    };
    let bits = header.key_num_bits;
    let key_bytes = bits as usize / 8;
    let Some(modulus) = key_modulus(blob) else {
        return false;
    };
    if signature.len() != key_bytes || digest.len() != algorithm.len() {
        return false;
    }
    if modulus[0] & 0x80 == 0 || modulus[key_bytes - 1] & 1 == 0 {
        return false;
    }
    let Some(rr_bytes) = key_rr(blob) else {
        return false;
    };
    let words = key_bytes / 4;
    let mut n = [0u32; 256];
    let mut rr = [0u32; 256];
    let mut base = [0u32; 256];
    let mut value = [0u32; 256];
    let mut scratch = [0u32; 256];
    let n = &mut n[..words];
    let rr = &mut rr[..words];
    let base = &mut base[..words];
    let value = &mut value[..words];
    let scratch = &mut scratch[..words];
    decode_words(modulus, n);
    decode_words(rr_bytes, rr);
    decode_words(signature, base);
    let inverse = header.n0inv;
    if n[0].wrapping_mul(inverse) != u32::MAX {
        return false;
    }
    // Full-width n means any input of this width is below 2*n.
    reduce(base, n);
    montgomery(value, base, rr, n, inverse);
    for _ in 0..8 {
        montgomery(scratch, value, value, n, inverse);
        montgomery(value, scratch, scratch, n, inverse);
    }
    // Multiply by the original, non-Montgomery signature to both add the
    // low exponent bit and leave the Montgomery domain.
    montgomery(scratch, value, base, n, inverse);
    let info = match algorithm {
        HashAlg::Sha256 => &SHA256_DIGEST_INFO,
        HashAlg::Sha512 => &SHA512_DIGEST_INFO,
    };
    let info_at = key_bytes - digest.len() - info.len();
    let digest_at = key_bytes - digest.len();
    let mut difference = 0u8;
    for at in 0..key_bytes {
        let actual = (scratch[words - 1 - at / 4] >> (24 - 8 * (at % 4))) as u8;
        let expected = match at {
            0 => 0,
            1 => 1,
            _ if at < info_at - 1 => 0xff,
            _ if at == info_at - 1 => 0,
            _ if at < digest_at => info[at - info_at],
            _ => digest[at - digest_at],
        };
        difference |= actual ^ expected;
    }
    difference == 0
}

fn decode_words(bytes: &[u8], words: &mut [u32]) {
    for (word, bytes) in words.iter_mut().rev().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
}

fn subtract(value: &mut [u32], modulus: &[u32]) {
    let mut borrow = 0u64;
    for (word, &n) in value.iter_mut().zip(modulus) {
        let sub = u64::from(n) + borrow;
        let original = u64::from(*word);
        *word = original.wrapping_sub(sub) as u32;
        borrow = u64::from(original < sub);
    }
}

fn reduce(value: &mut [u32], modulus: &[u32]) {
    if value.iter().rev().cmp(modulus.iter().rev()).is_ge() {
        subtract(value, modulus);
    }
}

/// Coarsely integrated operand scanning, radix 2^32. Each inner sum fits
/// u64: a 32x32 product plus one word and one carry. The cancelling low word
/// is discarded each round, implementing division by the Montgomery radix.
fn montgomery(out: &mut [u32], a: &[u32], b: &[u32], n: &[u32], inverse: u32) {
    out.fill(0);
    for &word in a {
        let mut product = u64::from(word) * u64::from(b[0]) + u64::from(out[0]);
        let factor = (product as u32).wrapping_mul(inverse);
        let mut reduction = u64::from(factor) * u64::from(n[0]) + u64::from(product as u32);
        for j in 1..n.len() {
            product = (product >> 32) + u64::from(word) * u64::from(b[j]) + u64::from(out[j]);
            reduction =
                (reduction >> 32) + u64::from(factor) * u64::from(n[j]) + u64::from(product as u32);
            out[j - 1] = reduction as u32;
        }
        let carry = (product >> 32) + (reduction >> 32);
        out[n.len() - 1] = carry as u32;
        if carry >> 32 != 0 {
            subtract(out, n);
        }
    }
    reduce(out, n);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use num_bigint::BigUint;

    /// All supported widths, including carries, zero, n-1, and inputs >= n.
    /// Production has no big-integer dependency; this is its arithmetic oracle.
    #[test]
    fn montgomery_exponent_matches_bigint() {
        for width in [256, 512, 1024] {
            for modulus in [alternating_modulus(width), vec![0xff; width]] {
                let n = BigUint::from_bytes_be(&modulus);
                let rr = rr_of(&modulus, width * 8);
                let inverse = avb_format::n0inv(&modulus).unwrap();
                let mut nw = vec![0; width / 4];
                let mut rw = nw.clone();
                decode_words(&modulus, &mut nw);
                decode_words(&rr, &mut rw);
                let mut below = modulus.clone();
                below[width - 1] -= 1;
                for bytes in [vec![0; width], below, vec![0xff; width], vec![0x53; width]] {
                    let mut base = nw.clone();
                    decode_words(&bytes, &mut base);
                    reduce(&mut base, &nw);
                    let mut value = nw.clone();
                    let mut scratch = nw.clone();
                    montgomery(&mut value, &base, &rw, &nw, inverse);
                    for _ in 0..8 {
                        montgomery(&mut scratch, &value, &value, &nw, inverse);
                        montgomery(&mut value, &scratch, &scratch, &nw, inverse);
                    }
                    montgomery(&mut scratch, &value, &base, &nw, inverse);
                    let actual: Vec<u8> = scratch
                        .iter()
                        .rev()
                        .flat_map(|word| word.to_be_bytes())
                        .collect();
                    assert_eq!(
                        BigUint::from_bytes_be(&actual),
                        BigUint::from_bytes_be(&bytes).modpow(&BigUint::from(65537u32), &n)
                    );
                }
            }
        }
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

    fn rr_of(modulus: &[u8], bits: usize) -> Vec<u8> {
        let n = BigUint::from_bytes_be(modulus);
        let value = (BigUint::from(1u32) << (2 * bits)) % &n;
        let bytes = value.to_bytes_be();
        let mut padded = vec![0u8; modulus.len() - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }

    /// A malformed key or signature is a refusal, not a panic.
    #[test]
    fn malformed_inputs_are_refused() {
        assert!(!rsa_pkcs1_verify(&[], &[], &[], HashAlg::Sha256));
        let mut blob = vec![0u8; 1032];
        blob[..4].copy_from_slice(&4096u32.to_be_bytes());
        blob[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(!rsa_pkcs1_verify(
            &blob,
            &[0u8; 512],
            &[0u8; 32],
            HashAlg::Sha256
        ));
    }
}
