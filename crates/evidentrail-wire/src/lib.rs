//! Strict, versioned wire contracts for Evidentrail.
//!
//! This slice covers the approved literal-local-file binding and current
//! local-file query-plan material. Wire bytes remain untrusted until strict
//! decoding, semantic construction, canonical-byte verification, and derived
//! identity checks pass. A separate narrowing verifier relates the exact plan
//! document to the exact binding document. None of these wrappers is an
//! executable capability or proof of live registry, host, or handle state.

mod approved_local_file_binding;
#[cfg(feature = "bench")]
mod bench;
mod canonical;
#[cfg(any(feature = "ledger", feature = "product", feature = "bench"))]
mod codec;
mod dispatch;
mod error;
#[cfg(feature = "ledger")]
mod fetch;
#[cfg(feature = "ledger")]
mod ledger;
mod local_file_plan;
#[cfg(feature = "product")]
mod log_brief;
#[cfg(feature = "product")]
mod product;
#[cfg(feature = "ledger")]
mod receipts;
mod registry;
mod schema;

pub use approved_local_file_binding::{
    APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1, APPROVED_LOCAL_FILE_BINDING_DIGEST_DOMAIN_V1,
    ApprovedBindingVerificationError, ApprovedLocalFileBindingV1,
    LocalFilePlanBindingNarrowingError, VerifiedLocalFilePlanBindingNarrowingV1,
    derive_approved_local_file_binding_digest_v1, encode_approved_local_file_binding_v1,
    verify_approved_local_file_binding_v1, verify_local_file_plan_binding_narrowing_v1,
};
#[cfg(feature = "bench")]
pub use bench::{
    BENCH_ANNOTATION_MANIFEST_CONTRACT_V1, BENCH_CASE_MANIFEST_CONTRACT_V1,
    BENCH_HIDDEN_EVALUATION_MANIFEST_CONTRACT_V1, BENCH_RUN_MANIFEST_CONTRACT_V1, BenchArtifactV1,
    decode_bench_annotation_manifest_v1, decode_bench_case_manifest_v1,
    decode_bench_hidden_evaluation_manifest_v1, decode_bench_run_manifest_v1,
    encode_bench_annotation_manifest_v1, encode_bench_case_manifest_v1,
    encode_bench_hidden_evaluation_manifest_v1, encode_bench_run_manifest_v1,
    verify_bench_annotation_manifest_v1_against, verify_bench_case_manifest_v1_against,
    verify_bench_hidden_evaluation_manifest_v1_against, verify_bench_run_manifest_v1_against,
};
pub use dispatch::{CanonicalArtifactV1, decode_artifact};
pub use error::{PlanVerificationError, WireErrorV1};
#[cfg(feature = "ledger")]
pub use fetch::{
    FETCH_COMPLETION_CONTRACT_V1, FetchCompletionArtifactV1, decode_fetch_completion_v1,
    encode_fetch_completion_v1, verify_fetch_completion_v1_against,
};
#[cfg(feature = "ledger")]
pub use ledger::{
    EVENT_BLOCK_RECORD_CONTRACT_V1, EVENT_RECORD_CONTRACT_V1, EventBlockRecordArtifactV1,
    EventRecordArtifactV1, TRANSFORMATION_RECEIPT_CONTRACT_V1, TransformationReceiptArtifactV1,
    decode_event_block_record_v1, decode_event_record_v1, decode_transformation_receipt_v1,
    encode_event_block_record_v1, encode_event_record_v1, encode_transformation_receipt_v1,
    verify_event_block_record_v1_against, verify_event_record_v1_against,
    verify_transformation_receipt_v1_against,
};
pub use local_file_plan::{
    LOCAL_FILE_PLAN_CONTRACT_V1, LOCAL_FILE_PLAN_DIGEST_DOMAIN_V1, LOCAL_FILE_PLAN_ID_DOMAIN_V1,
    LOCAL_FILE_SOURCE_IDENTITY_DOMAIN_V1, LOCAL_FILE_SOURCE_MEMBER_DOMAIN_V1,
    VerifiedLocalFilePlanV1, derive_local_file_source_identity_digest_v1,
    derive_local_file_source_member_v1, encode_local_file_plan_v1, verify_local_file_plan_v1,
};
#[cfg(feature = "product")]
pub use log_brief::{
    LOG_BRIEF_CONTRACT_V1, LogBriefArtifactV1, LogBriefVariantV1, decode_log_brief_v1,
    encode_compiled_log_brief_v1, encode_needs_more_log_brief_v1, encode_passthrough_log_brief_v1,
    verify_compiled_log_brief_v1, verify_passthrough_log_brief_v1,
};
#[cfg(feature = "product")]
pub use product::{
    EVIDENCE_REFERENCE_CONTRACT_V1, EXPANSION_REQUEST_CONTRACT_V1, EXPANSION_RESPONSE_CONTRACT_V1,
    EvidenceReferenceArtifactV1, RESULT_STATUS_CONTRACT_V1, ResultStatusArtifactV1,
    decode_evidence_reference_v1, decode_expansion_request_v1, decode_result_status_v1,
    encode_evidence_reference_v1, encode_expansion_request_v1, encode_expansion_response_v1,
    encode_result_status_v1, verify_evidence_reference_v1_against,
    verify_expansion_response_v1_against, verify_result_status_v1_against,
};
#[cfg(feature = "ledger")]
pub use receipts::{
    ACQUISITION_RECEIPT_CHUNK_CONTRACT_V1, ACQUISITION_RECEIPT_CONTRACT_V1,
    ChunkedReceiptArtifactV1, PRESENTATION_RECEIPT_CHUNK_CONTRACT_V1,
    PRESENTATION_RECEIPT_CONTRACT_V1, decode_acquisition_receipt_v1,
    decode_presentation_receipt_v1, encode_acquisition_receipt_v1, encode_presentation_receipt_v1,
    verify_acquisition_receipt_v1_against, verify_presentation_receipt_v1_against,
};
pub use registry::{
    ContractDescriptorV1, IdentityDomainV1, MigrationClassV1, contract_registry_v1,
    migration_registry_v1,
};
pub use schema::{golden_documents_v1, schema_documents_v1};
