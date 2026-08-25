//! Memory-only live authority composition for local-file V1.
//!
//! This crate joins verified binding and plan documents with process-local
//! binding and internal-path registry leases. Its strongest output is still a
//! non-executable registry-authorization token: live host certification and
//! opened-handle/snapshot revalidation remain separate release blockers.

mod authorization;
mod binding_registry;
mod internal_paths;

pub use authorization::{
    RegistryAuthorizationError, RegistryAuthorizedLocalFilePlanV1,
    authorize_local_file_plan_with_registries_v1,
};
pub use binding_registry::{
    ApprovedBindingReadLeaseV1, BindingRegistryError, LiveApprovedBindingRegistryV1,
};
pub use internal_paths::{
    CanonicalUnixPathConstructionError, CanonicalUnixPathV1, INTERNAL_PATH_POLICY_DIGEST_DOMAIN_V1,
    InternalPathPolicyConstructionError, InternalPathPolicyV1, InternalPathReadLeaseV1,
    InternalPathRegistryError, InternalPathRegistryV1, MAX_INTERNAL_PATH_POLICY_BYTES_V1,
    MAX_INTERNAL_PATH_PREFIXES_V1,
};
