//! Android verified-boot result values, without platform trust policy.
//!
//! Colors follow Android Verified Boot's boot-state definitions. The numeric
//! values follow `hardware/interfaces/security/keymint/aidl/.../VerifiedBootState.aidl`.
//! Version fields follow `system/tools/mkbootimg/include/bootimg/bootimg.h`.

/// Android verified-boot state, with KeyMint wire values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Color {
    /// The device trusts the manufacturer's key.
    Green = 0,
    /// The device is unlocked.
    Orange = 1,
    /// The device trusts a user key.
    Yellow = 2,
    /// Verification failed.
    Red = 3,
}

/// Algorithm and bytes of the libavb metadata digest.
///
/// This fixed-size value differs from `avb-chain::VbmetaDigest`, which also
/// records the total metadata size and permits a caller-selected algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvbDigest {
    /// A SHA-256 digest.
    Sha256([u8; 32]),
    /// A SHA-512 digest.
    Sha512([u8; 64]),
}

impl AvbDigest {
    /// Borrows the digest bytes without changing their algorithm.
    ///
    /// # Examples
    /// ```
    /// use avb_format::AvbDigest;
    /// assert_eq!(AvbDigest::Sha512([1; 64]).as_bytes(), &[1; 64]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha256(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }

    /// Borrows a SHA-256 digest. A SHA-512 digest has no SHA-256 representation.
    ///
    /// # Examples
    /// ```
    /// use avb_format::AvbDigest;
    /// assert_eq!(AvbDigest::Sha256([2; 32]).sha256(), Some(&[2; 32]));
    /// assert_eq!(AvbDigest::Sha512([3; 64]).sha256(), None);
    /// ```
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Sha256(bytes) => Some(bytes),
            Self::Sha512(_) => None,
        }
    }
}

/// Verified-boot results and Android version values reported by a verifier.
///
/// The type carries evidence. It does not select keys or decide platform trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Verified-boot state.
    pub color: Color,
    /// Whether dm-verity reported EIO with the base state.
    pub red_eio: bool,
    /// libavb metadata digest, including its algorithm.
    pub digest: Option<AvbDigest>,
    /// Android `(A << 14) | (B << 7) | C` OS version.
    pub os_version: Option<u32>,
    /// Android `(day << 11) | ((year - 2000) << 4) | month` patch level.
    pub security_patch: Option<u32>,
}
