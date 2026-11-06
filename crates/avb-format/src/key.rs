//! AVB RSA public-key blobs: geometry, `n0inv` and `rr` self-consistency.
//!
//! `AvbRSAPublicKeyHeader` is `key_num_bits` (u32 BE) followed by `n0inv`
//! (u32 BE), then the modulus and `rr = 2^(2*bits) mod modulus`, each
//! `key_num_bits / 8` bytes, big-endian. libavb accepts `key_num_bits` of 2048,
//! 4096 or 8192 and requires the blob length to be exactly
//! `8 + 2 * key_num_bits / 8` (`avb_rsa.c:55-71`).
//!
//! A blob is structurally usable only when the modulus is full width and odd,
//! `n0inv` is `-modulus^-1 mod 2^32`, and `rr` is `2^(2*bits) mod modulus`.
//! Those arithmetic checks make a key evidence rather than a pattern match.
//! Structural consistency is not proof that a bootloader uses the blob.

/// Size of `AvbRSAPublicKeyHeader`.
pub const RSA_KEY_HEADER_SIZE: usize = 8;
/// Supported key width: 2048 bits.
pub const RSA_KEY_BITS_2048: u32 = 2048;
/// Supported key width: 4096 bits.
pub const RSA_KEY_BITS_4096: u32 = 4096;
/// Supported key width: 8192 bits.
pub const RSA_KEY_BITS_8192: u32 = 8192;
/// Every key width libavb accepts.
pub const RSA_KEY_BITS: [u32; 3] = [RSA_KEY_BITS_2048, RSA_KEY_BITS_4096, RSA_KEY_BITS_8192];
/// Largest accepted modulus in bytes.
pub const RSA_MAX_KEY_BYTES: usize = RSA_KEY_BITS_8192 as usize / 8;

const WIDE: usize = RSA_MAX_KEY_BYTES + 1;

/// The parsed fixed header of an AVB public-key blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvbRSAPublicKeyHeader {
    /// `key_num_bits`.
    pub key_num_bits: u32,
    /// `n0inv = -modulus^-1 mod 2^32`.
    pub n0inv: u32,
}

impl AvbRSAPublicKeyHeader {
    /// Parse a blob whose length matches its declared key width.
    pub fn parse(blob: &[u8]) -> Option<Self> {
        let bits = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
        if key_blob_len(bits)? != blob.len() {
            return None;
        }
        let n0inv = u32::from_be_bytes(blob.get(4..8)?.try_into().ok()?);
        Some(Self {
            key_num_bits: bits,
            n0inv,
        })
    }

    /// Modulus width in bytes.
    pub fn key_bytes(self) -> usize {
        self.key_num_bits as usize / 8
    }
}

/// Blob length for a key of `bits` bits, or `None` for an unsupported size.
pub fn key_blob_len(bits: u32) -> Option<usize> {
    match bits {
        RSA_KEY_BITS_2048 | RSA_KEY_BITS_4096 | RSA_KEY_BITS_8192 => {
            Some(RSA_KEY_HEADER_SIZE + 2 * bits as usize / 8)
        }
        _ => None,
    }
}

/// `key_num_bits` of a blob whose length matches, or `None`.
pub fn key_num_bits(blob: &[u8]) -> Option<u32> {
    AvbRSAPublicKeyHeader::parse(blob).map(|header| header.key_num_bits)
}

/// The modulus bytes of a structurally sized blob.
pub fn key_modulus(blob: &[u8]) -> Option<&[u8]> {
    let header = AvbRSAPublicKeyHeader::parse(blob)?;
    let len = header.key_bytes();
    blob.get(RSA_KEY_HEADER_SIZE..RSA_KEY_HEADER_SIZE + len)
}

/// The `rr = 2^(2*bits) mod modulus` bytes of a structurally sized blob.
pub fn key_rr(blob: &[u8]) -> Option<&[u8]> {
    let header = AvbRSAPublicKeyHeader::parse(blob)?;
    let len = header.key_bytes();
    let start = RSA_KEY_HEADER_SIZE + len;
    blob.get(start..start + len)
}

/// `-1 / n[0] mod 2^32`, where `n[0]` is the least significant 32-bit word.
pub fn n0inv(modulus: &[u8]) -> Option<u32> {
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

fn trim(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

/// Whether `rr == 2^(2*bits) mod modulus`.
///
/// The exponent is computed by modular doubling in fixed buffers, so this
/// function needs no allocation and no big-integer dependency. It returns
/// `false` for a modulus that is not exactly `bits / 8` bytes and full width.
pub fn rr_is_consistent(modulus: &[u8], bits: u32, rr: &[u8]) -> bool {
    let width = bits as usize / 8;
    if width == 0
        || width > RSA_MAX_KEY_BYTES
        || modulus.len() != width
        || rr.len() != width
        || modulus[0] & 0x80 == 0
    {
        return false;
    }
    let mut wide_modulus = [0u8; WIDE];
    wide_modulus[1..=width].copy_from_slice(modulus);
    let mut value = [0u8; WIDE];
    value[width] = 1;
    for _ in 0..(2 * bits as usize) {
        let mut carry = 0u8;
        for byte in value[..=width].iter_mut().rev() {
            let doubled = (*byte as u16) << 1 | carry as u16;
            *byte = doubled as u8;
            carry = (doubled >> 8) as u8;
        }
        // The value stays below 2 * modulus and the modulus is full width, so
        // one subtraction reduces it.
        if value[..=width] >= wide_modulus[..=width] {
            let mut borrow = 0i16;
            for (byte, sub) in value[..=width]
                .iter_mut()
                .rev()
                .zip(wide_modulus[..=width].iter().rev())
            {
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
    trim(&value[1..=width]) == trim(rr)
}

/// Validate a full AVB RSA public-key blob and return its `key_num_bits`.
///
/// Checks the declared width, the exact blob length, a full-width odd modulus,
/// `n0inv` and `rr`. Returns `None` when any check fails.
pub fn validate_key_blob(blob: &[u8]) -> Option<u32> {
    let header = AvbRSAPublicKeyHeader::parse(blob)?;
    let modulus = key_modulus(blob)?;
    let rr = key_rr(blob)?;
    if modulus.first().is_none_or(|byte| byte & 0x80 == 0)
        || modulus.last().is_none_or(|byte| byte & 1 == 0)
    {
        return None;
    }
    if n0inv(modulus) != Some(header.n0inv) {
        return None;
    }
    rr_is_consistent(modulus, header.key_num_bits, rr).then_some(header.key_num_bits)
}

/// Whether `blob` is a structurally self-consistent AVB RSA public key.
pub fn key_is_valid(blob: &[u8]) -> bool {
    validate_key_blob(blob).is_some()
}
