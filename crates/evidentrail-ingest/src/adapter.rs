use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use evidentrail_core::{EnvelopeSink, PreparedSinkAckExpectation};
use evidentrail_schema::{
    AcknowledgedCounts, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchErrorCode,
    FetchIdentity, FetchTiming, RawEnvelopeIdentityV1, RawEnvelopeV1, SourceCursor,
    SourceIdentityDigest,
};

use crate::IngestError;

/// Immutable identity binding supplied to one adapter execution.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionContext {
    fetch_identity: FetchIdentity,
    source_identity_digest: SourceIdentityDigest,
}

impl ExecutionContext {
    #[must_use]
    pub const fn new(
        fetch_identity: FetchIdentity,
        source_identity_digest: SourceIdentityDigest,
    ) -> Self {
        Self {
            fetch_identity,
            source_identity_digest,
        }
    }

    #[must_use]
    pub const fn fetch_identity(&self) -> &FetchIdentity {
        &self.fetch_identity
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    /// Build the identity shared by every envelope in this execution.
    #[must_use]
    pub fn envelope_identity(&self) -> RawEnvelopeIdentityV1 {
        RawEnvelopeIdentityV1::new(
            self.fetch_identity.retrieval_id(),
            self.fetch_identity.plan_id(),
            self.fetch_identity.plan_digest(),
            self.fetch_identity.adapter().clone(),
            self.source_identity_digest,
        )
    }

    pub(crate) fn matches(&self, identity: &RawEnvelopeIdentityV1) -> bool {
        identity.retrieval_id() == self.fetch_identity.retrieval_id()
            && identity.plan_id() == self.fetch_identity.plan_id()
            && identity.plan_digest() == self.fetch_identity.plan_digest()
            && identity.adapter() == self.fetch_identity.adapter()
            && identity.source_identity_digest() == self.source_identity_digest
    }
}

impl fmt::Debug for ExecutionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionContext")
            .field("fetch_identity", &self.fetch_identity)
            .field("source_identity_digest_present", &true)
            .finish()
    }
}

/// Minimal synchronous source seam. Every envelope must be durably
/// acknowledged before the adapter may acquire or emit the next one.
pub trait SourceAdapter {
    fn execute(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeSink,
    ) -> Result<FetchCompletion, IngestError> {
        self.execute_with_cancellation(context, sink, &NeverCancelled)
    }

    fn execute_with_cancellation(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeSink,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError>;
}

/// Cooperative cancellation checked before every source read or replay emit.
pub trait Cancellation {
    fn is_cancelled(&self) -> bool;
}

/// A cloneable cancellation signal suitable for UI, timeout, or test control.
#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Cancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptStatus {
    Acknowledged,
    SinkStopped,
    AdapterStopped,
}

pub(crate) struct ExecutionSession<'a> {
    context: &'a ExecutionContext,
    acknowledged_records: u64,
    acknowledged_payload_bytes: u64,
    acknowledged_source_bytes: u64,
    first_cursor: Option<SourceCursor>,
    final_cursor: Option<SourceCursor>,
}

impl<'a> ExecutionSession<'a> {
    pub(crate) const fn new(context: &'a ExecutionContext) -> Self {
        Self {
            context,
            acknowledged_records: 0,
            acknowledged_payload_bytes: 0,
            acknowledged_source_bytes: 0,
            first_cursor: None,
            final_cursor: None,
        }
    }

    pub(crate) fn final_cursor(&self) -> Option<SourceCursor> {
        self.final_cursor.clone()
    }

    pub(crate) fn accept(
        &mut self,
        sink: &mut dyn EnvelopeSink,
        envelope: RawEnvelopeV1,
    ) -> AcceptStatus {
        let Ok(payload_bytes) = u64::try_from(envelope.record().payload_len()) else {
            return AcceptStatus::AdapterStopped;
        };
        let Ok(source_bytes) = u64::try_from(envelope.record().source_len()) else {
            return AcceptStatus::AdapterStopped;
        };
        let Some(next_records) = self.acknowledged_records.checked_add(1) else {
            return AcceptStatus::AdapterStopped;
        };
        let Some(next_payload_bytes) = self.acknowledged_payload_bytes.checked_add(payload_bytes)
        else {
            return AcceptStatus::AdapterStopped;
        };
        let Some(next_source_bytes) = self.acknowledged_source_bytes.checked_add(source_bytes)
        else {
            return AcceptStatus::AdapterStopped;
        };
        let acknowledgement_expectation = PreparedSinkAckExpectation::from_envelope(&envelope);
        let cursor = envelope.cursor().cloned();

        let Ok(ack) = sink.accept(envelope) else {
            return AcceptStatus::SinkStopped;
        };
        if acknowledgement_expectation.verify(&ack).is_err() {
            return AcceptStatus::SinkStopped;
        }

        self.acknowledged_records = next_records;
        self.acknowledged_payload_bytes = next_payload_bytes;
        self.acknowledged_source_bytes = next_source_bytes;
        if self.first_cursor.is_none() {
            self.first_cursor.clone_from(&cursor);
        }
        self.final_cursor = cursor;
        AcceptStatus::Acknowledged
    }

    pub(crate) const fn acknowledged(&self) -> AcknowledgedCounts {
        AcknowledgedCounts::new(
            self.acknowledged_records,
            self.acknowledged_payload_bytes,
            self.acknowledged_source_bytes,
        )
    }

    pub(crate) fn boundaries(
        &self,
        high_water_marks: impl IntoIterator<Item = evidentrail_schema::HighWaterMark>,
    ) -> FetchBoundaries {
        FetchBoundaries::new(
            self.first_cursor.clone(),
            self.final_cursor.clone(),
            high_water_marks,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn completion(
        &self,
        timing: FetchTiming,
        members: evidentrail_schema::AttemptCounts,
        pages: evidentrail_schema::AttemptCounts,
        boundaries: FetchBoundaries,
        cap_usage: impl IntoIterator<Item = evidentrail_schema::CapUsage>,
        adapter_outcome: evidentrail_schema::AdapterOutcome,
        error_codes: impl IntoIterator<Item = FetchErrorCode>,
        completeness: FetchCompleteness,
    ) -> Result<FetchCompletion, IngestError> {
        FetchCompletion::new(
            self.context.fetch_identity.clone(),
            timing,
            self.acknowledged(),
            members,
            pages,
            boundaries,
            cap_usage,
            adapter_outcome,
            error_codes,
            completeness,
        )
        .map_err(|_| IngestError::InvalidFetchCompletion)
    }
}
