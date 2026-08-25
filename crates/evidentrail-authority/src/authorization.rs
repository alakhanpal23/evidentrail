use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    BindingRefV1, InternalPathPolicyDigest, PlanId, UnixFileObjectIdV1, UnixTimestampNanos,
};
use evidentrail_wire::{
    ApprovedLocalFileBindingV1, LocalFilePlanBindingNarrowingError,
    VerifiedLocalFilePlanBindingNarrowingV1, VerifiedLocalFilePlanV1,
    verify_local_file_plan_binding_narrowing_v1,
};

use crate::{
    ApprovedBindingReadLeaseV1, BindingRegistryError, InternalPathReadLeaseV1,
    InternalPathRegistryError, InternalPathRegistryV1, LiveApprovedBindingRegistryV1,
};

/// Join verified plan and binding documents to exact live registry records.
///
/// `checked_at` is a trusted wall-clock observation. The returned token holds
/// both read leases, preventing binding and exclusion-registry updates for its
/// lifetime. It remains non-executable: it does not prove live host/profile
/// certification, perform an open, or revalidate the opened handle and complete
/// planned snapshot immediately before the first byte.
pub fn authorize_local_file_plan_with_registries_v1<'binding_registry, 'path_registry>(
    plan: &VerifiedLocalFilePlanV1,
    supplied_binding: &ApprovedLocalFileBindingV1,
    binding_registry: &'binding_registry LiveApprovedBindingRegistryV1,
    internal_paths: &'path_registry InternalPathRegistryV1,
    checked_at: UnixTimestampNanos,
) -> Result<
    RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
    RegistryAuthorizationError,
> {
    if checked_at < plan.material().created_at()
        || checked_at >= plan.material().execute_before()
        || plan
            .material()
            .source_identity()
            .proof_expires_at()
            .is_some_and(|expires_at| checked_at >= expires_at)
    {
        return Err(RegistryAuthorizationError::PlanOutsideValidity);
    }

    let expected_binding = plan.material().source_identity().binding();
    let binding_lease = binding_registry
        .read_lease(
            plan.material().repository_identity(),
            expected_binding,
            checked_at,
        )
        .map_err(RegistryAuthorizationError::from_binding_registry)?;
    if binding_lease.binding().canonical_bytes() != supplied_binding.canonical_bytes() {
        return Err(RegistryAuthorizationError::BindingArtifactMismatch);
    }

    let narrowing =
        verify_local_file_plan_binding_narrowing_v1(plan, binding_lease.binding(), checked_at)
            .map_err(RegistryAuthorizationError::from_narrowing)?;
    let internal_path_lease = internal_paths
        .read_lease_for_locator(
            plan.material().locator(),
            plan.material().internal_path_policy_digest(),
        )
        .map_err(RegistryAuthorizationError::from_internal_paths)?;

    Ok(RegistryAuthorizedLocalFilePlanV1 {
        narrowing,
        binding_lease,
        internal_path_lease,
    })
}

/// Non-executable proof that verified documents matched exact live binding and
/// internal-path registry authority while both read leases remain held.
///
/// Calling [`Self::check_opened_identity_not_internal`] closes only the
/// hard-link-to-internal-object exclusion. It still does not compare the opened
/// handle to every planned snapshot fact or prove host certification, so this
/// type can never be passed directly to a production adapter.
pub struct RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry> {
    narrowing: VerifiedLocalFilePlanBindingNarrowingV1,
    binding_lease: ApprovedBindingReadLeaseV1<'binding_registry>,
    internal_path_lease: InternalPathReadLeaseV1<'path_registry>,
}

impl RegistryAuthorizedLocalFilePlanV1<'_, '_> {
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.narrowing.plan_id()
    }

    #[must_use]
    pub const fn binding_ref(&self) -> &BindingRefV1 {
        self.binding_lease.binding_ref()
    }

    #[must_use]
    pub const fn checked_at(&self) -> UnixTimestampNanos {
        self.narrowing.checked_at()
    }

    #[must_use]
    pub fn internal_path_policy_digest(&self) -> InternalPathPolicyDigest {
        self.internal_path_lease.policy_digest()
    }

    pub fn check_opened_identity_not_internal(
        &self,
        identity: UnixFileObjectIdV1,
    ) -> Result<(), RegistryAuthorizationError> {
        self.internal_path_lease
            .check_opened_identity(identity)
            .map_err(RegistryAuthorizationError::from_internal_paths)
    }
}

impl fmt::Debug for RegistryAuthorizedLocalFilePlanV1<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryAuthorizedLocalFilePlanV1")
            .field("plan_identity_present", &true)
            .field("binding_lease_present", &true)
            .field("internal_path_lease_present", &true)
            .field("executable", &false)
            .finish()
    }
}

/// Contentless failures while joining document and registry authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegistryAuthorizationError {
    BindingStateUnavailable,
    BindingNotCurrent,
    BindingRepositoryMismatch,
    BindingRevoked,
    BindingOutsideValidity,
    BindingArtifactMismatch,
    PlanOutsideValidity,
    PlanDoesNotNarrowBinding,
    InternalPathStateUnavailable,
    InternalPathPolicyMismatch,
    CanonicalPathReserved,
    OpenedIdentityReserved,
}

impl RegistryAuthorizationError {
    const fn from_binding_registry(error: BindingRegistryError) -> Self {
        match error {
            BindingRegistryError::StateUnavailable => Self::BindingStateUnavailable,
            BindingRegistryError::RepositoryMismatch => Self::BindingRepositoryMismatch,
            BindingRegistryError::BindingRevoked => Self::BindingRevoked,
            BindingRegistryError::BindingNotYetValid | BindingRegistryError::BindingExpired => {
                Self::BindingOutsideValidity
            }
            BindingRegistryError::BindingAlreadyInstalled
            | BindingRegistryError::BindingNotFound
            | BindingRegistryError::VersionNotAdvanced
            | BindingRegistryError::BindingReferenceMismatch => Self::BindingNotCurrent,
        }
    }

    const fn from_narrowing(_error: LocalFilePlanBindingNarrowingError) -> Self {
        Self::PlanDoesNotNarrowBinding
    }

    const fn from_internal_paths(error: InternalPathRegistryError) -> Self {
        match error {
            InternalPathRegistryError::StateUnavailable => Self::InternalPathStateUnavailable,
            InternalPathRegistryError::PolicyDigestMismatch => Self::InternalPathPolicyMismatch,
            InternalPathRegistryError::CanonicalPathReserved => Self::CanonicalPathReserved,
            InternalPathRegistryError::OpenedIdentityReserved => Self::OpenedIdentityReserved,
            InternalPathRegistryError::IdentityRegistrationOverflow
            | InternalPathRegistryError::IdentityNotRegistered => {
                Self::InternalPathStateUnavailable
            }
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingStateUnavailable => "EVIDENTRAIL_REGISTRY_AUTH_BINDING_STATE_UNAVAILABLE",
            Self::BindingNotCurrent => "EVIDENTRAIL_REGISTRY_AUTH_BINDING_NOT_CURRENT",
            Self::BindingRepositoryMismatch => "EVIDENTRAIL_REGISTRY_AUTH_REPOSITORY_MISMATCH",
            Self::BindingRevoked => "EVIDENTRAIL_REGISTRY_AUTH_BINDING_REVOKED",
            Self::BindingOutsideValidity => "EVIDENTRAIL_REGISTRY_AUTH_BINDING_OUTSIDE_VALIDITY",
            Self::BindingArtifactMismatch => "EVIDENTRAIL_REGISTRY_AUTH_BINDING_ARTIFACT_MISMATCH",
            Self::PlanOutsideValidity => "EVIDENTRAIL_REGISTRY_AUTH_PLAN_OUTSIDE_VALIDITY",
            Self::PlanDoesNotNarrowBinding => "EVIDENTRAIL_REGISTRY_AUTH_PLAN_NOT_NARROWING",
            Self::InternalPathStateUnavailable => {
                "EVIDENTRAIL_REGISTRY_AUTH_INTERNAL_PATH_STATE_UNAVAILABLE"
            }
            Self::InternalPathPolicyMismatch => "EVIDENTRAIL_REGISTRY_AUTH_INTERNAL_POLICY_MISMATCH",
            Self::CanonicalPathReserved => "EVIDENTRAIL_REGISTRY_AUTH_CANONICAL_PATH_RESERVED",
            Self::OpenedIdentityReserved => "EVIDENTRAIL_REGISTRY_AUTH_OPENED_IDENTITY_RESERVED",
        }
    }
}

impl fmt::Debug for RegistryAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryAuthorizationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for RegistryAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RegistryAuthorizationError {}
