use std::error::Error as StdError;
use std::fmt;
use std::num::NonZeroU32;

use crate::{
    AdapterIdentity, BindingId, InternalPathPolicyDigest, LOCAL_FILE_ADAPTER_KIND_V1,
    LOCAL_FILE_ADAPTER_VERSION_V1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PolicyDigest, RepositoryIdentityDigest,
    UnixFileObjectIdV1, UnixLocalFileLocatorV1, UnixTimestampNanos,
};

/// Exact literal locator and Unix root object identity approved for one file.
///
/// The locator bytes are sensitive authority material. It contains one
/// canonical root and one nonempty root-relative member path; it grants no
/// wildcard, glob, crawl, or authority over sibling members. This value records
/// the approved root identity but does not attest that the live opened root
/// still has that identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedLocalFileLocatorAuthorityV1 {
    locator: UnixLocalFileLocatorV1,
    root_object_id: UnixFileObjectIdV1,
}

impl ApprovedLocalFileLocatorAuthorityV1 {
    #[must_use]
    pub const fn new(locator: UnixLocalFileLocatorV1, root_object_id: UnixFileObjectIdV1) -> Self {
        Self {
            locator,
            root_object_id,
        }
    }

    #[must_use]
    pub const fn locator(&self) -> &UnixLocalFileLocatorV1 {
        &self.locator
    }

    #[must_use]
    pub const fn root_object_id(&self) -> UnixFileObjectIdV1 {
        self.root_object_id
    }
}

impl fmt::Debug for ApprovedLocalFileLocatorAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedLocalFileLocatorAuthorityV1")
            .field("locator_present", &true)
            .field("root_object_identity_present", &true)
            .finish()
    }
}

/// Constructor-validated authority material for one approved local-file
/// binding.
///
/// The derived [`crate::BindingDigest`] is deliberately excluded to avoid an
/// identity cycle. `evidentrail-wire` places that digest in the canonical artifact,
/// verifies it over a digest-omitting projection, and exposes the resulting
/// [`crate::BindingRefV1`]. This material carries no credential, display label,
/// OS build string, or claim about the live host.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedLocalFileBindingMaterialV1 {
    binding_id: BindingId,
    binding_version: NonZeroU32,
    repository_identity: RepositoryIdentityDigest,
    adapter: AdapterIdentity,
    approved_locator: ApprovedLocalFileLocatorAuthorityV1,
    policy_version: NonZeroU32,
    policy_digest: PolicyDigest,
    internal_path_policy_digest: InternalPathPolicyDigest,
    runtime_profile: LocalFileRuntimeProfileV1,
    snapshot_mode: LocalFileSnapshotModeV1,
    ordering: LocalFileOrderingV1,
    maximum_caps: LocalFilePlanCapsV1,
    valid_from: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
}

impl ApprovedLocalFileBindingMaterialV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding_id: BindingId,
        binding_version: u32,
        repository_identity: RepositoryIdentityDigest,
        adapter: AdapterIdentity,
        approved_locator: ApprovedLocalFileLocatorAuthorityV1,
        policy_version: u32,
        policy_digest: PolicyDigest,
        internal_path_policy_digest: InternalPathPolicyDigest,
        runtime_profile: LocalFileRuntimeProfileV1,
        snapshot_mode: LocalFileSnapshotModeV1,
        ordering: LocalFileOrderingV1,
        maximum_caps: LocalFilePlanCapsV1,
        valid_from: UnixTimestampNanos,
        expires_at: UnixTimestampNanos,
    ) -> Result<Self, ApprovedLocalFileBindingConstructionError> {
        let binding_version = NonZeroU32::new(binding_version)
            .ok_or(ApprovedLocalFileBindingConstructionError::ZeroBindingVersion)?;
        if adapter.kind() != LOCAL_FILE_ADAPTER_KIND_V1 {
            return Err(ApprovedLocalFileBindingConstructionError::UnsupportedAdapterKind);
        }
        if adapter.version() != LOCAL_FILE_ADAPTER_VERSION_V1 {
            return Err(ApprovedLocalFileBindingConstructionError::UnsupportedAdapterVersion);
        }
        let policy_version = NonZeroU32::new(policy_version)
            .ok_or(ApprovedLocalFileBindingConstructionError::ZeroPolicyVersion)?;
        if snapshot_mode != LocalFileSnapshotModeV1::WholeFileFixedHighWater {
            return Err(ApprovedLocalFileBindingConstructionError::UnsupportedSnapshotMode);
        }
        if ordering != LocalFileOrderingV1::SingleFileByteOrder {
            return Err(ApprovedLocalFileBindingConstructionError::UnsupportedOrdering);
        }
        if expires_at.get() <= valid_from.get() {
            return Err(ApprovedLocalFileBindingConstructionError::ExpiryNotAfterValidFrom);
        }

        Ok(Self {
            binding_id,
            binding_version,
            repository_identity,
            adapter,
            approved_locator,
            policy_version,
            policy_digest,
            internal_path_policy_digest,
            runtime_profile,
            snapshot_mode,
            ordering,
            maximum_caps,
            valid_from,
            expires_at,
        })
    }

    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    #[must_use]
    pub const fn binding_version(&self) -> NonZeroU32 {
        self.binding_version
    }

    #[must_use]
    pub const fn repository_identity(&self) -> RepositoryIdentityDigest {
        self.repository_identity
    }

    #[must_use]
    pub const fn adapter(&self) -> &AdapterIdentity {
        &self.adapter
    }

    #[must_use]
    pub const fn approved_locator(&self) -> &ApprovedLocalFileLocatorAuthorityV1 {
        &self.approved_locator
    }

    #[must_use]
    pub const fn policy_version(&self) -> NonZeroU32 {
        self.policy_version
    }

    #[must_use]
    pub const fn policy_digest(&self) -> PolicyDigest {
        self.policy_digest
    }

    #[must_use]
    pub const fn internal_path_policy_digest(&self) -> InternalPathPolicyDigest {
        self.internal_path_policy_digest
    }

    #[must_use]
    pub const fn runtime_profile(&self) -> LocalFileRuntimeProfileV1 {
        self.runtime_profile
    }

    #[must_use]
    pub const fn snapshot_mode(&self) -> LocalFileSnapshotModeV1 {
        self.snapshot_mode
    }

    #[must_use]
    pub const fn ordering(&self) -> LocalFileOrderingV1 {
        self.ordering
    }

    #[must_use]
    pub const fn maximum_caps(&self) -> LocalFilePlanCapsV1 {
        self.maximum_caps
    }

    /// Inclusive start of the approved binding interval.
    #[must_use]
    pub const fn valid_from(&self) -> UnixTimestampNanos {
        self.valid_from
    }

    /// Exclusive end of the approved binding interval.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }
}

impl fmt::Debug for ApprovedLocalFileBindingMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedLocalFileBindingMaterialV1")
            .field("binding_id_present", &true)
            .field("binding_version_present", &true)
            .field("repository_identity_present", &true)
            .field("adapter_present", &true)
            .field("approved_locator_present", &true)
            .field("policy_present", &true)
            .field("internal_path_policy_present", &true)
            .field("runtime_profile_present", &true)
            .field("snapshot_mode_present", &true)
            .field("ordering_present", &true)
            .field("maximum_caps_present", &true)
            .field("validity_interval_present", &true)
            .finish()
    }
}

/// Invalid approved local-file binding authority material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApprovedLocalFileBindingConstructionError {
    ZeroBindingVersion,
    UnsupportedAdapterKind,
    UnsupportedAdapterVersion,
    ZeroPolicyVersion,
    UnsupportedSnapshotMode,
    UnsupportedOrdering,
    ExpiryNotAfterValidFrom,
}

impl ApprovedLocalFileBindingConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroBindingVersion => "EVIDENTRAIL_LOCAL_FILE_BINDING_ZERO_BINDING_VERSION",
            Self::UnsupportedAdapterKind => {
                "EVIDENTRAIL_LOCAL_FILE_BINDING_UNSUPPORTED_ADAPTER_KIND"
            }
            Self::UnsupportedAdapterVersion => {
                "EVIDENTRAIL_LOCAL_FILE_BINDING_UNSUPPORTED_ADAPTER_VERSION"
            }
            Self::ZeroPolicyVersion => "EVIDENTRAIL_LOCAL_FILE_BINDING_ZERO_POLICY_VERSION",
            Self::UnsupportedSnapshotMode => {
                "EVIDENTRAIL_LOCAL_FILE_BINDING_UNSUPPORTED_SNAPSHOT_MODE"
            }
            Self::UnsupportedOrdering => "EVIDENTRAIL_LOCAL_FILE_BINDING_UNSUPPORTED_ORDERING",
            Self::ExpiryNotAfterValidFrom => {
                "EVIDENTRAIL_LOCAL_FILE_BINDING_EXPIRY_NOT_AFTER_VALID_FROM"
            }
        }
    }
}

impl fmt::Debug for ApprovedLocalFileBindingConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedLocalFileBindingConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ApprovedLocalFileBindingConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ApprovedLocalFileBindingConstructionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LocalFileArchitectureV1, LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1,
        LocalFileFilesystemV1, LocalFileOperatingSystemV1,
    };

    fn runtime_profile() -> LocalFileRuntimeProfileV1 {
        LocalFileRuntimeProfileV1::new(
            LocalFileOperatingSystemV1::MacOs,
            LocalFileFilesystemV1::Apfs,
            LocalFileArchitectureV1::Aarch64,
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
            LocalFileCertificationProfileDigest::from_bytes([0x77; 32]),
        )
        .unwrap()
    }

    fn material_with(
        binding_version: u32,
        adapter_kind: &str,
        adapter_version: &str,
        policy_version: u32,
        valid_from: i128,
        expires_at: i128,
    ) -> Result<ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileBindingConstructionError> {
        material_with_semantics(
            binding_version,
            adapter_kind,
            adapter_version,
            policy_version,
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            valid_from,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn material_with_semantics(
        binding_version: u32,
        adapter_kind: &str,
        adapter_version: &str,
        policy_version: u32,
        snapshot_mode: LocalFileSnapshotModeV1,
        ordering: LocalFileOrderingV1,
        valid_from: i128,
        expires_at: i128,
    ) -> Result<ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileBindingConstructionError> {
        ApprovedLocalFileBindingMaterialV1::new(
            BindingId::from_bytes([0x11; 32]),
            binding_version,
            RepositoryIdentityDigest::from_bytes([0x33; 32]),
            AdapterIdentity::new(adapter_kind, adapter_version).unwrap(),
            ApprovedLocalFileLocatorAuthorityV1::new(
                UnixLocalFileLocatorV1::new(
                    b"/var/log".to_vec(),
                    [b"app".to_vec(), b"current.log".to_vec()],
                )
                .unwrap(),
                UnixFileObjectIdV1::new(u64::MAX, 9_007_199_254_740_992),
            ),
            policy_version,
            PolicyDigest::from_bytes([0x44; 32]),
            InternalPathPolicyDigest::from_bytes([0x66; 32]),
            runtime_profile(),
            snapshot_mode,
            ordering,
            LocalFilePlanCapsV1::new(65_536, 1_000, 8_192, 30_000).unwrap(),
            UnixTimestampNanos::new(valid_from),
            UnixTimestampNanos::new(expires_at),
        )
    }

    #[test]
    fn binding_material_retains_exact_typed_authority() {
        let material = material_with(
            3,
            LOCAL_FILE_ADAPTER_KIND_V1,
            LOCAL_FILE_ADAPTER_VERSION_V1,
            7,
            10,
            20,
        )
        .unwrap();

        assert_eq!(material.binding_id(), BindingId::from_bytes([0x11; 32]));
        assert_eq!(material.binding_version().get(), 3);
        assert_eq!(
            material.repository_identity(),
            RepositoryIdentityDigest::from_bytes([0x33; 32])
        );
        assert_eq!(material.adapter().kind(), LOCAL_FILE_ADAPTER_KIND_V1);
        assert_eq!(material.adapter().version(), LOCAL_FILE_ADAPTER_VERSION_V1);
        assert_eq!(
            material.approved_locator().locator(),
            &UnixLocalFileLocatorV1::new(
                b"/var/log".to_vec(),
                [b"app".to_vec(), b"current.log".to_vec()],
            )
            .unwrap()
        );
        assert_eq!(
            material.approved_locator().root_object_id(),
            UnixFileObjectIdV1::new(u64::MAX, 9_007_199_254_740_992)
        );
        assert_eq!(material.policy_version().get(), 7);
        assert_eq!(
            material.snapshot_mode(),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater
        );
        assert_eq!(
            material.ordering(),
            LocalFileOrderingV1::SingleFileByteOrder
        );
        assert_eq!(material.maximum_caps().source_bytes(), 65_536);
        assert_eq!(material.valid_from().get(), 10);
        assert_eq!(material.expires_at().get(), 20);
    }

    #[test]
    fn invalid_binding_authority_fails_with_contentless_codes() {
        let cases = [
            material_with(
                0,
                LOCAL_FILE_ADAPTER_KIND_V1,
                LOCAL_FILE_ADAPTER_VERSION_V1,
                7,
                10,
                20,
            )
            .unwrap_err(),
            material_with(3, "other", LOCAL_FILE_ADAPTER_VERSION_V1, 7, 10, 20).unwrap_err(),
            material_with(3, LOCAL_FILE_ADAPTER_KIND_V1, "1.0.1", 7, 10, 20).unwrap_err(),
            material_with(
                3,
                LOCAL_FILE_ADAPTER_KIND_V1,
                LOCAL_FILE_ADAPTER_VERSION_V1,
                0,
                10,
                20,
            )
            .unwrap_err(),
            material_with(
                3,
                LOCAL_FILE_ADAPTER_KIND_V1,
                LOCAL_FILE_ADAPTER_VERSION_V1,
                7,
                10,
                10,
            )
            .unwrap_err(),
            material_with_semantics(
                3,
                LOCAL_FILE_ADAPTER_KIND_V1,
                LOCAL_FILE_ADAPTER_VERSION_V1,
                7,
                LocalFileSnapshotModeV1::OtherVersioned {
                    version: 1,
                    code: 1,
                },
                LocalFileOrderingV1::SingleFileByteOrder,
                10,
                20,
            )
            .unwrap_err(),
            material_with_semantics(
                3,
                LOCAL_FILE_ADAPTER_KIND_V1,
                LOCAL_FILE_ADAPTER_VERSION_V1,
                7,
                LocalFileSnapshotModeV1::WholeFileFixedHighWater,
                LocalFileOrderingV1::OtherVersioned {
                    version: 1,
                    code: 1,
                },
                10,
                20,
            )
            .unwrap_err(),
        ];

        for error in cases {
            assert_eq!(error.to_string(), error.code());
            assert!(format!("{error:?}").contains(error.code()));
            assert!(!format!("{error:?}").contains("/var/log"));
        }
    }

    #[test]
    fn binding_debug_hides_roots_identities_policies_caps_and_times() {
        let material = material_with(
            3,
            LOCAL_FILE_ADAPTER_KIND_V1,
            LOCAL_FILE_ADAPTER_VERSION_V1,
            7,
            1_700_000_000_000_000_000,
            1_700_000_060_000_000_000,
        )
        .unwrap();
        let debug = format!("{material:?}");
        for secret in [
            "/var/log",
            "11111111",
            "33333333",
            "44444444",
            "66666666",
            "77777777",
            "65536",
            "1700000000000000000",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("approved_locator_present: true"));
        assert!(debug.contains("validity_interval_present: true"));
    }
}
