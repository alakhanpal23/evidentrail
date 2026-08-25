//! Shared ingestion seams and deterministic in-memory replay for Evidentrail.
//!
//! Production local-file acquisition lives in `evidentrail-local-file`, where a
//! registry-authorized, descriptor-retaining preflight token is required. The
//! historical path-based file adapter is intentionally not compiled or
//! exported from this crate.

mod adapter;
mod deadline;
mod error;
mod replay;

pub use adapter::{Cancellation, CancellationToken, ExecutionContext, SourceAdapter};
pub use deadline::{
    CooperativeDeadline, CooperativeStopReason, DeadlineConstructionError, MonotonicClock,
    SystemMonotonicClock,
};
pub use error::IngestError;
pub use replay::InMemoryReplayAdapter;

pub use evidentrail_core::EnvelopeSink;
pub use evidentrail_schema::bounds::MAX_AUTHORIZED_RECORD_BYTES;
pub use evidentrail_schema::{FetchCompletion, RawEnvelopeV1};
