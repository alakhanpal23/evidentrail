//! Verified descriptor preflight and byte-exact execution for the local-file
//! V1 contract.
//!
//! The public authorized-preflight path cannot currently mint a successful
//! token because no externally governed certification-profile matrix has been
//! frozen. A separate discovery contract can observe one explicit file's
//! metadata, but cannot read it or grant authority. The descriptor engine and
//! its private test-only certification authority exercise the full preflight
//! and execution contracts without turning a caller assertion into
//! certification.

mod certification_matrix;
mod discovery;
mod execution;
mod preflight;

pub use certification_matrix::{
    HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1, HOST_CERTIFICATION_MATRIX_VERSION_V1,
    LOCAL_FILE_HOST_CERTIFICATION_RECEIPT_DOMAIN_V1,
    LOCAL_FILE_HOST_MATRIX_ALL_CELLS_PASSED_CODE_V1,
    LOCAL_FILE_HOST_MATRIX_PREFLIGHT_NOT_ADMITTED_CODE_V1, LocalFileHostCertificationCellV1,
    LocalFileHostCertificationMatrixErrorV1, LocalFileHostCertificationReceiptDigestV1,
    LocalFileHostCertificationReceiptV1, LocalFileHostIdentityDigestV1,
    run_local_file_host_certification_matrix_v1,
};

pub use discovery::{
    LOCAL_FILE_AUTHORIZATION_NOT_GRANTED_CODE_V1, LOCAL_FILE_CERTIFICATION_NOT_GRANTED_CODE_V1,
    LOCAL_FILE_CONTENT_NOT_READ_CODE_V1, LOCAL_FILE_METADATA_CAPABILITY_CODE_V1,
    LocalFileDiscoveryError, LocalFileMetadataDiscoveryV1, discover_local_file_metadata_v1,
};

pub use execution::{
    LocalFileExecutionError, execute_preflighted_local_file_v1,
    execute_preflighted_local_file_with_cancellation_v1,
};
pub use preflight::{LocalFilePreflightError, PreflightedLocalFileV1, preflight_local_file_v1};

pub use evidentrail_core::EnvelopeSink;
pub use evidentrail_ingest::{Cancellation, CancellationToken};
pub use evidentrail_schema::FetchCompletion;
