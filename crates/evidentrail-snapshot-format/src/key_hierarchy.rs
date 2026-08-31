use std::error::Error as StdError;
use std::fmt;
use std::num::NonZeroU32;

use evidentrail_schema::ResultId;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const ROOT_KEK_BYTES_V1: usize = 32;
pub const DERIVED_KEY_BYTES_V1: usize = 32;
pub const ROOT_KEY_VERSION_BYTES_V1: usize = 4;
pub const DEK_WRAP_KEY_INFO_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.dek-wrap-key.v1";
pub const SEAL_KEY_INFO_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.seal-key.v1";
pub const DEK_WRAP_KEY_INFO_BYTES_V1: usize =
    DEK_WRAP_KEY_INFO_DOMAIN_V1.len() + ROOT_KEY_VERSION_BYTES_V1;
pub const SEAL_KEY_INFO_BYTES_V1: usize = SEAL_KEY_INFO_DOMAIN_V1.len() + ROOT_KEY_VERSION_BYTES_V1;

/// Stable, contentless error emitted by the V1 key hierarchy primitive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyHierarchyErrorV1 {
    InvalidKeyVersion,
    InvalidRootKek,
    DerivationFailed,
    DerivedKeyCollision,
}

impl KeyHierarchyErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidKeyVersion => "EVIDENTRAIL_KEY_HIERARCHY_INVALID_KEY_VERSION",
            Self::InvalidRootKek => "EVIDENTRAIL_KEY_HIERARCHY_INVALID_ROOT_KEK",
            Self::DerivationFailed => "EVIDENTRAIL_KEY_HIERARCHY_DERIVATION_FAILED",
            Self::DerivedKeyCollision => "EVIDENTRAIL_KEY_HIERARCHY_DERIVED_KEY_COLLISION",
        }
    }
}

impl fmt::Debug for KeyHierarchyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyHierarchyErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KeyHierarchyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KeyHierarchyErrorV1 {}

/// Checked V1 root-key version.
///
/// Its canonical encoding is exactly four unsigned big-endian bytes. Version
/// zero is reserved and cannot be constructed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootKeyVersionV1(NonZeroU32);

impl RootKeyVersionV1 {
    pub const fn new(value: u32) -> Result<Self, KeyHierarchyErrorV1> {
        match NonZeroU32::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(KeyHierarchyErrorV1::InvalidKeyVersion),
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[must_use]
    pub const fn canonical_bytes(self) -> [u8; ROOT_KEY_VERSION_BYTES_V1] {
        self.get().to_be_bytes()
    }
}

impl fmt::Debug for RootKeyVersionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootKeyVersionV1(<redacted>)")
    }
}

/// Build the exact V1 HKDF info for the result-DEK wrapping key.
#[must_use]
pub fn canonical_dek_wrap_key_info_v1(
    version: RootKeyVersionV1,
) -> [u8; DEK_WRAP_KEY_INFO_BYTES_V1] {
    let mut info = [0u8; DEK_WRAP_KEY_INFO_BYTES_V1];
    info[..DEK_WRAP_KEY_INFO_DOMAIN_V1.len()].copy_from_slice(DEK_WRAP_KEY_INFO_DOMAIN_V1);
    info[DEK_WRAP_KEY_INFO_DOMAIN_V1.len()..].copy_from_slice(&version.canonical_bytes());
    info
}

/// Build the exact V1 HKDF info for the result seal key.
#[must_use]
pub fn canonical_seal_key_info_v1(version: RootKeyVersionV1) -> [u8; SEAL_KEY_INFO_BYTES_V1] {
    let mut info = [0u8; SEAL_KEY_INFO_BYTES_V1];
    info[..SEAL_KEY_INFO_DOMAIN_V1.len()].copy_from_slice(SEAL_KEY_INFO_DOMAIN_V1);
    info[SEAL_KEY_INFO_DOMAIN_V1.len()..].copy_from_slice(&version.canonical_bytes());
    info
}

/// Zeroizing owner for one installation root KEK.
///
/// The future key provider can construct this from an authenticated unwrap into
/// a `Zeroizing` buffer. This type offers no public byte export. `Zeroizing`
/// controls this selected allocation but cannot erase caller copies, registers,
/// swap, dependency-internal state, or compiler-created temporaries.
pub struct RootKekV1(Zeroizing<[u8; ROOT_KEK_BYTES_V1]>);

impl RootKekV1 {
    pub fn from_zeroizing(
        bytes: Zeroizing<[u8; ROOT_KEK_BYTES_V1]>,
    ) -> Result<Self, KeyHierarchyErrorV1> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(KeyHierarchyErrorV1::InvalidRootKek);
        }
        Ok(Self(bytes))
    }

    /// Construct deterministic fixture material without widening the
    /// production key-import API.
    #[cfg(test)]
    fn from_test_bytes(bytes: [u8; ROOT_KEK_BYTES_V1]) -> Result<Self, KeyHierarchyErrorV1> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    /// Derive the two result-scoped keys required by ADR 0004.
    ///
    /// HKDF input keying material is this root KEK, salt is the exact 32-byte
    /// `ResultId`, and each info is its fixed domain immediately followed by the
    /// four-byte canonical root-key version. The two outputs have distinct
    /// nominal types and no public byte export.
    pub fn derive_result_keys(
        &self,
        result_id: ResultId,
        version: RootKeyVersionV1,
    ) -> Result<DerivedResultKeysV1, KeyHierarchyErrorV1> {
        let hkdf = Hkdf::<Sha256>::new(Some(result_id.as_bytes()), self.as_bytes());

        let mut dek_wrap_key = Zeroizing::new([0u8; DERIVED_KEY_BYTES_V1]);
        hkdf.expand(
            &canonical_dek_wrap_key_info_v1(version),
            dek_wrap_key.as_mut(),
        )
        .map_err(|_| KeyHierarchyErrorV1::DerivationFailed)?;

        let mut seal_key = Zeroizing::new([0u8; DERIVED_KEY_BYTES_V1]);
        hkdf.expand(&canonical_seal_key_info_v1(version), seal_key.as_mut())
            .map_err(|_| KeyHierarchyErrorV1::DerivationFailed)?;

        let derived = DerivedResultKeysV1 {
            dek_wrap_key: DekWrapKeyV1 {
                bytes: dek_wrap_key,
                result_id,
                root_key_version: version,
            },
            seal_key: SealKeyV1 {
                bytes: seal_key,
                result_id,
                root_key_version: version,
            },
        };
        if derived.dek_wrap_key().as_bytes() == derived.seal_key().as_bytes() {
            return Err(KeyHierarchyErrorV1::DerivedKeyCollision);
        }
        Ok(derived)
    }

    fn as_bytes(&self) -> &[u8; ROOT_KEK_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for RootKekV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootKekV1(<redacted>)")
    }
}

/// Zeroizing owned result-DEK wrapping key derived from a root KEK.
pub struct DekWrapKeyV1 {
    bytes: Zeroizing<[u8; DERIVED_KEY_BYTES_V1]>,
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
}

impl DekWrapKeyV1 {
    #[must_use]
    pub fn view(&self) -> DekWrapKeyViewV1<'_> {
        DekWrapKeyViewV1 {
            bytes: &self.bytes,
            result_id: self.result_id,
            root_key_version: self.root_key_version,
        }
    }
}

impl fmt::Debug for DekWrapKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DekWrapKeyV1(<redacted>)")
    }
}

/// Non-owning, non-exporting view of a derived result-DEK wrapping key.
pub struct DekWrapKeyViewV1<'a> {
    bytes: &'a [u8; DERIVED_KEY_BYTES_V1],
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
}

impl DekWrapKeyViewV1<'_> {
    pub(crate) const fn as_bytes(&self) -> &[u8; DERIVED_KEY_BYTES_V1] {
        self.bytes
    }

    pub(crate) const fn result_id(&self) -> ResultId {
        self.result_id
    }

    pub(crate) const fn root_key_version(&self) -> RootKeyVersionV1 {
        self.root_key_version
    }
}

impl fmt::Debug for DekWrapKeyViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DekWrapKeyViewV1(<redacted>)")
    }
}

/// Zeroizing owned manifest/chain seal key derived from a root KEK.
pub struct SealKeyV1 {
    bytes: Zeroizing<[u8; DERIVED_KEY_BYTES_V1]>,
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
}

impl SealKeyV1 {
    #[must_use]
    pub fn view(&self) -> SealKeyViewV1<'_> {
        SealKeyViewV1 {
            bytes: &self.bytes,
            result_id: self.result_id,
            root_key_version: self.root_key_version,
        }
    }
}

impl fmt::Debug for SealKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealKeyV1(<redacted>)")
    }
}

/// Non-owning, non-exporting view of a derived manifest/chain seal key.
pub struct SealKeyViewV1<'a> {
    bytes: &'a [u8; DERIVED_KEY_BYTES_V1],
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
}

impl SealKeyViewV1<'_> {
    pub(crate) const fn as_bytes(&self) -> &[u8; DERIVED_KEY_BYTES_V1] {
        self.bytes
    }

    pub(crate) const fn result_id(&self) -> ResultId {
        self.result_id
    }

    pub(crate) const fn root_key_version(&self) -> RootKeyVersionV1 {
        self.root_key_version
    }
}

impl fmt::Debug for SealKeyViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealKeyViewV1(<redacted>)")
    }
}

/// The two domain-separated, result-scoped keys derived in one operation.
pub struct DerivedResultKeysV1 {
    dek_wrap_key: DekWrapKeyV1,
    seal_key: SealKeyV1,
}

impl DerivedResultKeysV1 {
    #[must_use]
    pub fn dek_wrap_key(&self) -> DekWrapKeyViewV1<'_> {
        self.dek_wrap_key.view()
    }

    #[must_use]
    pub fn seal_key(&self) -> SealKeyViewV1<'_> {
        self.seal_key.view()
    }

    #[must_use]
    pub fn into_owned_keys(self) -> (DekWrapKeyV1, SealKeyV1) {
        (self.dek_wrap_key, self.seal_key)
    }
}

impl fmt::Debug for DerivedResultKeysV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedResultKeysV1(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> RootKekV1 {
        let mut bytes = [0u8; ROOT_KEK_BYTES_V1];
        for (byte, value) in bytes.iter_mut().zip(0u8..) {
            *byte = value;
        }
        RootKekV1::from_test_bytes(bytes).unwrap()
    }

    fn fixture_version() -> RootKeyVersionV1 {
        RootKeyVersionV1::new(0x0102_0304).unwrap()
    }

    #[test]
    fn version_and_info_encodings_are_exact_and_frozen() {
        assert_eq!(
            RootKeyVersionV1::new(0),
            Err(KeyHierarchyErrorV1::InvalidKeyVersion)
        );
        assert_eq!(
            RootKeyVersionV1::new(1).unwrap().canonical_bytes(),
            [0, 0, 0, 1]
        );
        assert_eq!(
            fixture_version().canonical_bytes(),
            [0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(
            RootKeyVersionV1::new(u32::MAX).unwrap().canonical_bytes(),
            [0xff; ROOT_KEY_VERSION_BYTES_V1]
        );

        let mut expected_wrap = DEK_WRAP_KEY_INFO_DOMAIN_V1.to_vec();
        expected_wrap.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            canonical_dek_wrap_key_info_v1(fixture_version()),
            expected_wrap.as_slice()
        );

        let mut expected_seal = SEAL_KEY_INFO_DOMAIN_V1.to_vec();
        expected_seal.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            canonical_seal_key_info_v1(fixture_version()),
            expected_seal.as_slice()
        );
    }

    #[test]
    fn frozen_result_vectors_match_independent_rfc5869_extract_expand() {
        // Independently frozen with Python stdlib HMAC-SHA-256 using RFC 5869:
        // PRK = HMAC(salt, IKM); one 32-byte block = HMAC(PRK, info || 0x01).
        let derived = fixture_root()
            .derive_result_keys(ResultId::from_bytes([0x11; 32]), fixture_version())
            .unwrap();
        assert_eq!(
            derived.dek_wrap_key().as_bytes(),
            &[
                0xf3, 0xe2, 0x7e, 0xe2, 0x21, 0xd9, 0xb8, 0xa6, 0x53, 0xef, 0xb0, 0x70, 0x9b, 0xa6,
                0x00, 0x99, 0x24, 0x2f, 0xc5, 0xfb, 0x09, 0xb2, 0x88, 0x33, 0xd2, 0xc8, 0x30, 0xf8,
                0xe2, 0xbb, 0x3f, 0x33,
            ]
        );
        assert_eq!(
            derived.seal_key().as_bytes(),
            &[
                0xf3, 0xe5, 0xc3, 0x0b, 0x51, 0xfc, 0x29, 0x4f, 0x17, 0xd1, 0x3d, 0xe5, 0xd7, 0x82,
                0x26, 0x39, 0x60, 0x72, 0x37, 0x33, 0x5a, 0x80, 0x8a, 0x7e, 0xed, 0x53, 0xa8, 0x8e,
                0x0b, 0x16, 0x93, 0xc4,
            ]
        );
    }

    #[test]
    fn pinned_hkdf_dependency_reproduces_rfc5869_sha256_case_one() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            prk.as_slice(),
            &[
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn domains_results_and_versions_are_independent() {
        let root = fixture_root();
        let first = root
            .derive_result_keys(
                ResultId::from_bytes([1; 32]),
                RootKeyVersionV1::new(1).unwrap(),
            )
            .unwrap();
        let other_result = root
            .derive_result_keys(
                ResultId::from_bytes([2; 32]),
                RootKeyVersionV1::new(1).unwrap(),
            )
            .unwrap();
        let other_version = root
            .derive_result_keys(
                ResultId::from_bytes([1; 32]),
                RootKeyVersionV1::new(2).unwrap(),
            )
            .unwrap();
        let replay = root
            .derive_result_keys(
                ResultId::from_bytes([1; 32]),
                RootKeyVersionV1::new(1).unwrap(),
            )
            .unwrap();

        assert_ne!(first.dek_wrap_key().as_bytes(), first.seal_key().as_bytes());
        assert_ne!(
            first.dek_wrap_key().as_bytes(),
            other_result.dek_wrap_key().as_bytes()
        );
        assert_ne!(
            first.seal_key().as_bytes(),
            other_result.seal_key().as_bytes()
        );
        assert_ne!(
            first.dek_wrap_key().as_bytes(),
            other_version.dek_wrap_key().as_bytes()
        );
        assert_ne!(
            first.seal_key().as_bytes(),
            other_version.seal_key().as_bytes()
        );
        assert_eq!(
            first.dek_wrap_key().as_bytes(),
            replay.dek_wrap_key().as_bytes()
        );
        assert_eq!(first.seal_key().as_bytes(), replay.seal_key().as_bytes());
    }

    #[test]
    fn constructors_keys_views_and_failures_are_contentless() {
        let canary = [b'S'; ROOT_KEK_BYTES_V1];
        let root = RootKekV1::from_test_bytes(canary).unwrap();
        let derived = root
            .derive_result_keys(
                ResultId::from_bytes([b'R'; 32]),
                RootKeyVersionV1::new(1).unwrap(),
            )
            .unwrap();
        let rendered = format!(
            "{root:?} {derived:?} {:?} {:?} {:?} {:?} {:?}",
            derived.dek_wrap_key,
            derived.dek_wrap_key(),
            derived.seal_key,
            derived.seal_key(),
            KeyHierarchyErrorV1::InvalidRootKek,
        );
        assert!(!rendered.contains("SSSS"));
        assert!(!rendered.contains("RRRR"));
        assert!(!rendered.contains("e695"));
        assert_eq!(
            RootKekV1::from_test_bytes([0; ROOT_KEK_BYTES_V1]).unwrap_err(),
            KeyHierarchyErrorV1::InvalidRootKek
        );
        assert!(!format!("{:?}", KeyHierarchyErrorV1::InvalidRootKek).contains("SSSS"));
    }

    #[test]
    fn owned_keys_can_be_split_without_exporting_secret_bytes() {
        let keys = fixture_root()
            .derive_result_keys(
                ResultId::from_bytes([3; 32]),
                RootKeyVersionV1::new(9).unwrap(),
            )
            .unwrap();
        let (wrap, seal) = keys.into_owned_keys();
        assert_ne!(wrap.view().as_bytes(), seal.view().as_bytes());
        assert_eq!(format!("{wrap:?}"), "DekWrapKeyV1(<redacted>)");
        assert_eq!(format!("{seal:?}"), "SealKeyV1(<redacted>)");
    }
}
