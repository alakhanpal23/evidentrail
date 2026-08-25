use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::{RwLock, RwLockReadGuard};

use evidentrail_schema::{BindingId, BindingRefV1, RepositoryIdentityDigest, UnixTimestampNanos};
use evidentrail_wire::ApprovedLocalFileBindingV1;

/// Process-local registry of currently approved, verified binding artifacts.
///
/// A binding ID has one repository-scoped lineage. Records are never removed,
/// so revocation cannot forget the highest observed version and accidentally
/// permit rollback. Persistence and cross-process coordination are deliberately
/// outside this memory-only slice.
pub struct LiveApprovedBindingRegistryV1 {
    state: RwLock<BindingRegistryState>,
}

impl LiveApprovedBindingRegistryV1 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(BindingRegistryState::default()),
        }
    }

    /// Install the first verified artifact for a binding ID.
    pub fn install(&self, binding: ApprovedLocalFileBindingV1) -> Result<(), BindingRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| BindingRegistryError::StateUnavailable)?;
        let binding_id = binding.binding_ref().id();
        if let Some(existing) = state.records.get(&binding_id) {
            if existing.repository_identity != binding.material().repository_identity() {
                return Err(BindingRegistryError::RepositoryMismatch);
            }
            return Err(BindingRegistryError::BindingAlreadyInstalled);
        }

        state.records.insert(
            binding_id,
            BindingRecord {
                repository_identity: binding.material().repository_identity(),
                binding,
                revoked: false,
            },
        );
        Ok(())
    }

    /// Replace the current record with a strictly newer verified version.
    ///
    /// Replacement is also the only way to make a revoked binding ID current
    /// again, and it still requires a version strictly above the revoked
    /// record. Equal-version replay is rejected even when the digest matches.
    pub fn replace(&self, binding: ApprovedLocalFileBindingV1) -> Result<(), BindingRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| BindingRegistryError::StateUnavailable)?;
        let binding_id = binding.binding_ref().id();
        let current = state
            .records
            .get_mut(&binding_id)
            .ok_or(BindingRegistryError::BindingNotFound)?;
        if current.repository_identity != binding.material().repository_identity() {
            return Err(BindingRegistryError::RepositoryMismatch);
        }
        if binding.binding_ref().version() <= current.binding.binding_ref().version() {
            return Err(BindingRegistryError::VersionNotAdvanced);
        }

        current.binding = binding;
        current.revoked = false;
        Ok(())
    }

    /// Revoke exactly the current record. A stale reference cannot revoke a
    /// later replacement.
    pub fn revoke(
        &self,
        repository_identity: RepositoryIdentityDigest,
        expected_current: &BindingRefV1,
    ) -> Result<(), BindingRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| BindingRegistryError::StateUnavailable)?;
        let current = state
            .records
            .get_mut(&expected_current.id())
            .ok_or(BindingRegistryError::BindingNotFound)?;
        if current.repository_identity != repository_identity {
            return Err(BindingRegistryError::RepositoryMismatch);
        }
        if current.binding.binding_ref() != expected_current {
            return Err(BindingRegistryError::BindingReferenceMismatch);
        }
        if current.revoked {
            return Err(BindingRegistryError::BindingRevoked);
        }

        current.revoked = true;
        Ok(())
    }

    /// Acquire a lease for the exact current, unrevoked binding at `now`.
    ///
    /// `now` must be a trusted wall-clock observation. The returned read guard
    /// prevents replacement or revocation until the lease is dropped.
    pub fn read_lease(
        &self,
        repository_identity: RepositoryIdentityDigest,
        expected_current: &BindingRefV1,
        now: UnixTimestampNanos,
    ) -> Result<ApprovedBindingReadLeaseV1<'_>, BindingRegistryError> {
        let guard = self
            .state
            .read()
            .map_err(|_| BindingRegistryError::StateUnavailable)?;
        let current = guard
            .records
            .get(&expected_current.id())
            .ok_or(BindingRegistryError::BindingNotFound)?;
        if current.repository_identity != repository_identity {
            return Err(BindingRegistryError::RepositoryMismatch);
        }
        if current.binding.binding_ref() != expected_current {
            return Err(BindingRegistryError::BindingReferenceMismatch);
        }
        if current.revoked {
            return Err(BindingRegistryError::BindingRevoked);
        }
        if now < current.binding.material().valid_from() {
            return Err(BindingRegistryError::BindingNotYetValid);
        }
        if now >= current.binding.material().expires_at() {
            return Err(BindingRegistryError::BindingExpired);
        }

        let binding = current.binding.clone();
        Ok(ApprovedBindingReadLeaseV1 {
            _guard: guard,
            binding,
        })
    }
}

impl Default for LiveApprovedBindingRegistryV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LiveApprovedBindingRegistryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveApprovedBindingRegistryV1")
            .field("state_present", &true)
            .finish()
    }
}

#[derive(Default)]
struct BindingRegistryState {
    records: BTreeMap<BindingId, BindingRecord>,
}

struct BindingRecord {
    repository_identity: RepositoryIdentityDigest,
    binding: ApprovedLocalFileBindingV1,
    revoked: bool,
}

/// Read lease proving one exact binding record remained current and unrevoked
/// for the lease lifetime.
pub struct ApprovedBindingReadLeaseV1<'registry> {
    _guard: RwLockReadGuard<'registry, BindingRegistryState>,
    binding: ApprovedLocalFileBindingV1,
}

impl ApprovedBindingReadLeaseV1<'_> {
    #[must_use]
    pub const fn binding_ref(&self) -> &BindingRefV1 {
        self.binding.binding_ref()
    }

    #[must_use]
    pub const fn repository_identity(&self) -> RepositoryIdentityDigest {
        self.binding.material().repository_identity()
    }

    pub(crate) const fn binding(&self) -> &ApprovedLocalFileBindingV1 {
        &self.binding
    }
}

impl fmt::Debug for ApprovedBindingReadLeaseV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedBindingReadLeaseV1")
            .field("binding_reference_present", &true)
            .field("repository_identity_present", &true)
            .finish()
    }
}

/// Contentless live binding-registry failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BindingRegistryError {
    StateUnavailable,
    BindingAlreadyInstalled,
    BindingNotFound,
    RepositoryMismatch,
    VersionNotAdvanced,
    BindingReferenceMismatch,
    BindingRevoked,
    BindingNotYetValid,
    BindingExpired,
}

impl BindingRegistryError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateUnavailable => "EVIDENTRAIL_BINDING_REGISTRY_STATE_UNAVAILABLE",
            Self::BindingAlreadyInstalled => "EVIDENTRAIL_BINDING_REGISTRY_ALREADY_INSTALLED",
            Self::BindingNotFound => "EVIDENTRAIL_BINDING_REGISTRY_NOT_FOUND",
            Self::RepositoryMismatch => "EVIDENTRAIL_BINDING_REGISTRY_REPOSITORY_MISMATCH",
            Self::VersionNotAdvanced => "EVIDENTRAIL_BINDING_REGISTRY_VERSION_NOT_ADVANCED",
            Self::BindingReferenceMismatch => "EVIDENTRAIL_BINDING_REGISTRY_REFERENCE_MISMATCH",
            Self::BindingRevoked => "EVIDENTRAIL_BINDING_REGISTRY_REVOKED",
            Self::BindingNotYetValid => "EVIDENTRAIL_BINDING_REGISTRY_NOT_YET_VALID",
            Self::BindingExpired => "EVIDENTRAIL_BINDING_REGISTRY_EXPIRED",
        }
    }
}

impl fmt::Debug for BindingRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingRegistryError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for BindingRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for BindingRegistryError {}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn poisoned_state_fails_closed() {
        let registry = LiveApprovedBindingRegistryV1::new();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = registry.state.write().unwrap();
            panic!("poison registry for test");
        }));

        let reference = BindingRefV1::new(
            BindingId::from_bytes([1; 32]),
            1,
            evidentrail_schema::BindingDigest::from_bytes([2; 32]),
        )
        .unwrap();
        assert_eq!(
            registry
                .read_lease(
                    RepositoryIdentityDigest::from_bytes([3; 32]),
                    &reference,
                    UnixTimestampNanos::new(0),
                )
                .unwrap_err(),
            BindingRegistryError::StateUnavailable
        );
    }
}
