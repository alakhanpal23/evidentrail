//! Verified descriptor preflight and byte-exact execution for the local-file
//! V1 contract.
//!
//! The public path cannot currently mint a successful token because no
//! externally governed certification-profile matrix has been frozen. It still
//! performs no content reads and fails with a typed blocker. The descriptor
//! engine and its private test-only certification authority exercise the full
//! preflight and execution contracts without turning a caller assertion into
//! certification.

mod execution;
mod preflight;

pub use execution::{
    LocalFileExecutionError, execute_preflighted_local_file_v1,
    execute_preflighted_local_file_with_cancellation_v1,
};
pub use preflight::{LocalFilePreflightError, PreflightedLocalFileV1, preflight_local_file_v1};

pub use evidentrail_core::EnvelopeSink;
pub use evidentrail_ingest::{Cancellation, CancellationToken};
pub use evidentrail_schema::FetchCompletion;
