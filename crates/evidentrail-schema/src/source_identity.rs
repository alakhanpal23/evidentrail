use std::error::Error as StdError;
use std::fmt;
use std::num::NonZeroU32;

use crate::{AdapterIdentity, BindingDigest, BindingId, SourceIdentityDigest, UnixTimestampNanos};

/// Immutable reference to the approved source binding used by a query plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BindingRefV1 {
    id: BindingId,
    version: NonZeroU32,
    digest: BindingDigest,
}

impl BindingRefV1 {
    pub fn new(
        id: BindingId,
        version: u32,
        digest: BindingDigest,
    ) -> Result<Self, BindingRefConstructionError> {
        let version = NonZeroU32::new(version).ok_or(BindingRefConstructionError::ZeroVersion)?;
        Ok(Self {
            id,
            version,
            digest,
        })
    }

    #[must_use]
    pub const fn id(&self) -> BindingId {
        self.id
    }

    #[must_use]
    pub const fn version(&self) -> NonZeroU32 {
        self.version
    }

    #[must_use]
    pub const fn digest(&self) -> BindingDigest {
        self.digest
    }
}

impl fmt::Debug for BindingRefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingRefV1")
            .field("version_present", &true)
            .finish()
    }
}

/// Invalid binding-reference construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BindingRefConstructionError {
    ZeroVersion,
}

impl BindingRefConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroVersion => "EVIDENTRAIL_BINDING_REF_ZERO_VERSION",
        }
    }
}

impl fmt::Debug for BindingRefConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingRefConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for BindingRefConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for BindingRefConstructionError {}

/// Typed evidence used to attest the effective local source identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IdentityProofKindV1 {
    LocalFileMetadata,
    ReplayManifest,
    OtherVersioned { version: u16, code: u16 },
}

impl IdentityProofKindV1 {
    /// Stable contentless code suitable for diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LocalFileMetadata => "local_file_metadata",
            Self::ReplayManifest => "replay_manifest",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for IdentityProofKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityProofKindV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Effective approved source identity and the bounded proof that established
/// it. It intentionally contains no credential, path, or display label.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceIdentityV1 {
    adapter: AdapterIdentity,
    binding: BindingRefV1,
    digest: SourceIdentityDigest,
    proof_kind: IdentityProofKindV1,
    proof_observed_at: UnixTimestampNanos,
    proof_expires_at: Option<UnixTimestampNanos>,
}

impl SourceIdentityV1 {
    pub fn new(
        adapter: AdapterIdentity,
        binding: BindingRefV1,
        digest: SourceIdentityDigest,
        proof_kind: IdentityProofKindV1,
        proof_observed_at: UnixTimestampNanos,
        proof_expires_at: Option<UnixTimestampNanos>,
    ) -> Result<Self, SourceIdentityConstructionError> {
        if proof_expires_at.is_some_and(|expires_at| expires_at.get() <= proof_observed_at.get()) {
            return Err(SourceIdentityConstructionError::ExpiryNotAfterObservation);
        }

        Ok(Self {
            adapter,
            binding,
            digest,
            proof_kind,
            proof_observed_at,
            proof_expires_at,
        })
    }

    #[must_use]
    pub const fn adapter(&self) -> &AdapterIdentity {
        &self.adapter
    }

    #[must_use]
    pub const fn binding(&self) -> &BindingRefV1 {
        &self.binding
    }

    #[must_use]
    pub const fn digest(&self) -> SourceIdentityDigest {
        self.digest
    }

    #[must_use]
    pub const fn proof_kind(&self) -> IdentityProofKindV1 {
        self.proof_kind
    }

    #[must_use]
    pub const fn proof_observed_at(&self) -> UnixTimestampNanos {
        self.proof_observed_at
    }

    #[must_use]
    pub const fn proof_expires_at(&self) -> Option<UnixTimestampNanos> {
        self.proof_expires_at
    }
}

impl fmt::Debug for SourceIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceIdentityV1")
            .field("proof_kind_code", &self.proof_kind.code())
            .field("proof_expires_at_present", &self.proof_expires_at.is_some())
            .finish()
    }
}

/// Invalid source-identity construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SourceIdentityConstructionError {
    ExpiryNotAfterObservation,
}

impl SourceIdentityConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExpiryNotAfterObservation => {
                "EVIDENTRAIL_SOURCE_IDENTITY_EXPIRY_NOT_AFTER_OBSERVATION"
            }
        }
    }
}

impl fmt::Debug for SourceIdentityConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceIdentityConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SourceIdentityConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SourceIdentityConstructionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(version: u32) -> Result<BindingRefV1, BindingRefConstructionError> {
        BindingRefV1::new(
            BindingId::from_bytes([1; 32]),
            version,
            BindingDigest::from_bytes([2; 32]),
        )
    }

    #[test]
    fn binding_version_is_nonzero_and_other_fields_remain_typed() {
        let error = binding(0).unwrap_err();
        assert_eq!(error, BindingRefConstructionError::ZeroVersion);
        assert_eq!(error.code(), "EVIDENTRAIL_BINDING_REF_ZERO_VERSION");

        let binding = binding(u32::MAX).unwrap();
        assert_eq!(binding.id(), BindingId::from_bytes([1; 32]));
        assert_eq!(binding.version().get(), u32::MAX);
        assert_eq!(binding.digest(), BindingDigest::from_bytes([2; 32]));
    }

    #[test]
    fn source_proof_expiry_must_be_after_observation() {
        let adapter = AdapterIdentity::new("file", "1").unwrap();
        let binding_ref = binding(1).unwrap();
        let error = SourceIdentityV1::new(
            adapter,
            binding_ref,
            SourceIdentityDigest::from_bytes([3; 32]),
            IdentityProofKindV1::LocalFileMetadata,
            UnixTimestampNanos::new(10),
            Some(UnixTimestampNanos::new(9)),
        )
        .unwrap_err();

        assert_eq!(
            error,
            SourceIdentityConstructionError::ExpiryNotAfterObservation
        );
        assert_eq!(
            error.code(),
            "EVIDENTRAIL_SOURCE_IDENTITY_EXPIRY_NOT_AFTER_OBSERVATION"
        );

        let equal_error = SourceIdentityV1::new(
            AdapterIdentity::new("file", "1").unwrap(),
            binding(1).unwrap(),
            SourceIdentityDigest::from_bytes([3; 32]),
            IdentityProofKindV1::LocalFileMetadata,
            UnixTimestampNanos::new(10),
            Some(UnixTimestampNanos::new(10)),
        )
        .unwrap_err();
        assert_eq!(
            equal_error,
            SourceIdentityConstructionError::ExpiryNotAfterObservation
        );
    }

    #[test]
    fn source_proof_time_boundaries_and_optional_expiry_are_preserved() {
        let without_expiry = SourceIdentityV1::new(
            AdapterIdentity::new("replay", "1").unwrap(),
            binding(1).unwrap(),
            SourceIdentityDigest::from_bytes([3; 32]),
            IdentityProofKindV1::ReplayManifest,
            UnixTimestampNanos::new(-1),
            None,
        )
        .unwrap();
        assert_eq!(without_expiry.adapter().kind(), "replay");
        assert_eq!(without_expiry.binding().version().get(), 1);
        assert_eq!(
            without_expiry.digest(),
            SourceIdentityDigest::from_bytes([3; 32])
        );
        assert_eq!(
            without_expiry.proof_kind(),
            IdentityProofKindV1::ReplayManifest
        );
        assert_eq!(without_expiry.proof_observed_at().get(), -1);
        assert_eq!(without_expiry.proof_expires_at(), None);

        let later_instant = SourceIdentityV1::new(
            AdapterIdentity::new("file", "1").unwrap(),
            binding(2).unwrap(),
            SourceIdentityDigest::from_bytes([4; 32]),
            IdentityProofKindV1::LocalFileMetadata,
            UnixTimestampNanos::new(i128::MAX - 1),
            Some(UnixTimestampNanos::new(i128::MAX)),
        )
        .unwrap();
        assert_eq!(
            later_instant.proof_expires_at(),
            Some(UnixTimestampNanos::new(i128::MAX))
        );
    }

    #[test]
    fn source_and_binding_debug_are_contentless() {
        const ADAPTER_CANARY: &str = "CANARY_SECRET_PATH_/private/log";
        let binding_ref = BindingRefV1::new(
            BindingId::from_bytes([0xab; 32]),
            41,
            BindingDigest::from_bytes([0xcd; 32]),
        )
        .unwrap();
        let source = SourceIdentityV1::new(
            AdapterIdentity::new(ADAPTER_CANARY, "CANARY_VERSION_TOKEN").unwrap(),
            binding_ref,
            SourceIdentityDigest::from_bytes([0xef; 32]),
            IdentityProofKindV1::OtherVersioned {
                version: 17,
                code: 23,
            },
            UnixTimestampNanos::new(9_876_543_210),
            Some(UnixTimestampNanos::new(9_876_543_211)),
        )
        .unwrap();

        let binding_debug = format!("{:?}", source.binding());
        let source_debug = format!("{source:?}");
        assert_eq!(binding_debug, "BindingRefV1 { version_present: true }");
        assert_eq!(
            source_debug,
            "SourceIdentityV1 { proof_kind_code: \"other_versioned\", proof_expires_at_present: true }"
        );
        for secret in [
            ADAPTER_CANARY,
            "CANARY_VERSION_TOKEN",
            "abab",
            "cdcd",
            "efef",
            "9876543210",
            "17",
            "23",
        ] {
            assert!(!binding_debug.contains(secret));
            assert!(!source_debug.contains(secret));
        }

        let binding_error = binding(0).unwrap_err();
        assert_eq!(
            format!("{binding_error:?}"),
            "BindingRefConstructionError { code: \"EVIDENTRAIL_BINDING_REF_ZERO_VERSION\" }"
        );
        assert_eq!(binding_error.to_string(), binding_error.code());
    }
}
