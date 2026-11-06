use avb_format::{
    AvbRSAPublicKeyHeader, RSA_KEY_HEADER_SIZE, key_blob_len, key_is_valid, key_modulus,
    key_num_bits, key_rr, n0inv, rr_is_consistent, validate_key_blob,
};
use num_bigint::BigUint;

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

fn key_blob(bits: u32, modulus: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&bits.to_be_bytes());
    blob.extend_from_slice(&n0inv(modulus).expect("odd modulus").to_be_bytes());
    blob.extend_from_slice(modulus);
    blob.extend_from_slice(&rr_of(modulus, bits as usize));
    blob
}

/// The in-crate modular doubling is cross-checked against `num-bigint` on
/// moduli of both supported key widths and on edge shapes (all-ones, top
/// bit set, small values near powers of two).
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
        let expected = rr_of(&modulus, bits as usize);
        assert_eq!(expected.len(), modulus.len());
        assert!(rr_is_consistent(&modulus, bits, &expected));
        let mut wrong = expected.clone();
        wrong[modulus.len() - 1] ^= 1;
        assert!(!rr_is_consistent(&modulus, bits, &wrong));
    }
    assert!(
        !rr_is_consistent(&[0x01, 0x02], 16, &[0x01, 0x02]),
        "not full width"
    );
    assert!(!rr_is_consistent(&[], 16, &[]));
}

#[test]
fn key_blobs_validate_geometry_n0inv_and_rr() {
    for bits in [2048, 4096, 8192] {
        let modulus = alternating_modulus(bits as usize / 8);
        let blob = key_blob(bits, &modulus);
        assert_eq!(blob.len(), key_blob_len(bits).unwrap());
        assert_eq!(blob.len(), RSA_KEY_HEADER_SIZE + 2 * bits as usize / 8);
        assert_eq!(key_num_bits(&blob), Some(bits));
        assert_eq!(validate_key_blob(&blob), Some(bits));
        assert!(key_is_valid(&blob));
        assert_eq!(key_modulus(&blob), Some(modulus.as_slice()));
        assert_eq!(key_rr(&blob).unwrap().len(), modulus.len());
        let header = AvbRSAPublicKeyHeader::parse(&blob).unwrap();
        assert_eq!(header.key_num_bits, bits);
        assert_eq!(header.n0inv, n0inv(&modulus).unwrap());
        assert_eq!(header.key_bytes(), modulus.len());

        // A wrong `n0inv` is not a usable key.
        let mut wrong_n0inv = blob.clone();
        wrong_n0inv[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(validate_key_blob(&wrong_n0inv), None);
        // Neither is a wrong `rr`.
        let mut wrong_rr = blob.clone();
        let at = blob.len() - 1;
        wrong_rr[at] ^= 1;
        assert_eq!(validate_key_blob(&wrong_rr), None);
        // Nor a blob whose length does not match its declared width.
        assert_eq!(validate_key_blob(&blob[..blob.len() - 1]), None);
        // An even modulus is refused.
        let mut even_blob = blob.clone();
        let last = RSA_KEY_HEADER_SIZE + modulus.len() - 1;
        even_blob[last] &= !1;
        assert_eq!(validate_key_blob(&even_blob), None);
    }
    assert_eq!(key_blob_len(1024), None);
    assert_eq!(key_num_bits(&[0x00, 0x00, 0x08, 0x00]), None);
    assert_eq!(AvbRSAPublicKeyHeader::parse(&[0u8; 4]), None);
}
