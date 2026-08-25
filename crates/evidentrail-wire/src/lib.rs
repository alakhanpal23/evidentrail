//! Strict, versioned wire contracts for Evidentrail.
//!
//! This slice covers the approved literal-local-file binding and current
//! local-file query-plan material. Wire bytes remain untrusted until strict
//! decoding, semantic construction, canonical-byte verification, and derived
//! identity checks pass. A separate narrowing verifier relates the exact plan
//! document to the exact binding document. None of these wrappers is an
//! executable capability or proof of live registry, host, or handle state.

mod approved_local_file_binding;
mod canonical;
mod error;
mod local_file_plan;

pub use approved_local_file_binding::{
    APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1, APPROVED_LOCAL_FILE_BINDING_DIGEST_DOMAIN_V1,
    ApprovedBindingVerificationError, ApprovedLocalFileBindingV1,
    LocalFilePlanBindingNarrowingError, VerifiedLocalFilePlanBindingNarrowingV1,
    derive_approved_local_file_binding_digest_v1, encode_approved_local_file_binding_v1,
    verify_approved_local_file_binding_v1, verify_local_file_plan_binding_narrowing_v1,
};
pub use error::PlanVerificationError;
pub use local_file_plan::{
    LOCAL_FILE_PLAN_CONTRACT_V1, LOCAL_FILE_PLAN_DIGEST_DOMAIN_V1, LOCAL_FILE_PLAN_ID_DOMAIN_V1,
    LOCAL_FILE_SOURCE_IDENTITY_DOMAIN_V1, LOCAL_FILE_SOURCE_MEMBER_DOMAIN_V1,
    VerifiedLocalFilePlanV1, derive_local_file_source_identity_digest_v1,
    derive_local_file_source_member_v1, encode_local_file_plan_v1, verify_local_file_plan_v1,
};
