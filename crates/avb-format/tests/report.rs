//! Verified-boot result values keep their Android wire meaning.

use avb_format::{AvbDigest, Color, VerificationReport};

#[test]
fn colors_keep_the_keymint_wire_values() {
    assert_eq!(Color::Green as u32, 0);
    assert_eq!(Color::Orange as u32, 1);
    assert_eq!(Color::Yellow as u32, 2);
    assert_eq!(Color::Red as u32, 3);
}

#[test]
fn a_digest_keeps_its_algorithm_and_its_width() {
    let sha256 = AvbDigest::Sha256([0x11; 32]);
    assert_eq!(sha256.as_bytes().len(), 32);
    assert_eq!(sha256.sha256(), Some(&[0x11; 32]));

    let sha512 = AvbDigest::Sha512([0x22; 64]);
    assert_eq!(sha512.as_bytes().len(), 64);
    assert_eq!(sha512.sha256(), None);
}

#[test]
fn a_report_holds_evidence_and_no_trust_decision() {
    let report = VerificationReport {
        color: Color::Orange,
        red_eio: false,
        digest: Some(AvbDigest::Sha256([0x33; 32])),
        os_version: Some(13000),
        security_patch: Some(202401),
    };
    assert_eq!(report.color, Color::Orange);
    assert!(matches!(
        report.digest.map(|digest| digest.as_bytes().len()),
        Some(32)
    ));
    assert_eq!(report.os_version, Some(13000));
}
