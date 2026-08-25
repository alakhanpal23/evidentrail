use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use evidentrail_core::EnvelopeSink;
use evidentrail_schema::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_AUTHORIZED_RECORD_BYTES, MAX_RECORD_TERMINATOR_BYTES,
};
use evidentrail_schema::{
    AdapterOutcome, AttemptCounts, CompletenessProof, FetchCompleteness, FetchErrorCode,
    FetchPartialReason, FetchPartialReasons, FetchTiming, LaneKey, RawEnvelopeV1, SourceMember,
    UnixTimestampNanos,
};

use crate::adapter::{AcceptStatus, ExecutionSession};
use crate::{Cancellation, ExecutionContext, FetchCompletion, IngestError, SourceAdapter};

/// Deterministic adapter for bounded envelopes already owned in memory.
///
/// This is not a manifest loader and makes no claim that fixture bytes or
/// metadata were authenticated against an external artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct InMemoryReplayAdapter {
    envelopes: Vec<RawEnvelopeV1>,
    max_records: u64,
    max_source_bytes: u64,
    fixture_source_bytes: u64,
    member_count: u64,
}

impl InMemoryReplayAdapter {
    pub fn new(
        envelopes: impl Into<Vec<RawEnvelopeV1>>,
        max_records: u64,
        max_source_bytes: u64,
    ) -> Result<Self, IngestError> {
        if max_records == 0
            || max_source_bytes == 0
            || max_records > JSON_SAFE_INTEGER_MAX
            || max_source_bytes > JSON_SAFE_INTEGER_MAX
        {
            return Err(IngestError::InvalidLimit);
        }

        let envelopes = envelopes.into();
        let fixture_records =
            u64::try_from(envelopes.len()).map_err(|_| IngestError::InvalidReplayFixture)?;
        if fixture_records > max_records {
            return Err(IngestError::InvalidReplayFixture);
        }

        let mut fixture_source_bytes = 0_u64;
        let mut members = BTreeSet::<SourceMember>::new();
        for envelope in &envelopes {
            let record = envelope.record();
            if record.source_len() > MAX_AUTHORIZED_RECORD_BYTES
                || record.terminator().map_or(0, <[u8]>::len) > MAX_RECORD_TERMINATOR_BYTES
            {
                return Err(IngestError::InvalidReplayFixture);
            }
            let record_source_bytes = u64::try_from(record.source_len())
                .map_err(|_| IngestError::InvalidReplayFixture)?;
            fixture_source_bytes = fixture_source_bytes
                .checked_add(record_source_bytes)
                .ok_or(IngestError::InvalidReplayFixture)?;
            if fixture_source_bytes > max_source_bytes {
                return Err(IngestError::InvalidReplayFixture);
            }
            members.insert(envelope.ordering().lane().member().clone());
        }
        let member_count =
            u64::try_from(members.len()).map_err(|_| IngestError::InvalidReplayFixture)?;

        Ok(Self {
            envelopes,
            max_records,
            max_source_bytes,
            fixture_source_bytes,
            member_count,
        })
    }

    #[must_use]
    pub fn envelopes(&self) -> &[RawEnvelopeV1] {
        &self.envelopes
    }

    #[must_use]
    pub const fn max_records(&self) -> u64 {
        self.max_records
    }

    #[must_use]
    pub const fn max_source_bytes(&self) -> u64 {
        self.max_source_bytes
    }

    #[must_use]
    pub const fn fixture_source_bytes(&self) -> u64 {
        self.fixture_source_bytes
    }

    fn validate_fixture(
        &self,
        context: &ExecutionContext,
        cancellation: &dyn Cancellation,
    ) -> Result<Prevalidation, IngestError> {
        let mut lane_sequences = BTreeMap::<LaneKey, u64>::new();

        for (position, envelope) in self.envelopes.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(Prevalidation::Cancelled);
            }
            let expected_global =
                u64::try_from(position).map_err(|_| IngestError::InvalidReplayFixture)?;
            if !context.matches(envelope.identity())
                || envelope.ordering().acquisition_sequence().get() != expected_global
            {
                return Err(IngestError::InvalidReplayFixture);
            }

            let lane = envelope.ordering().lane();
            let expected_lane = lane_sequences.get(lane).copied().unwrap_or(0);
            if envelope.ordering().lane_sequence().get() != expected_lane {
                return Err(IngestError::InvalidReplayFixture);
            }
            let next_lane = expected_lane
                .checked_add(1)
                .ok_or(IngestError::InvalidReplayFixture)?;
            lane_sequences.insert(lane.clone(), next_lane);
        }

        if cancellation.is_cancelled() {
            Ok(Prevalidation::Cancelled)
        } else {
            Ok(Prevalidation::Ready)
        }
    }
}

impl SourceAdapter for InMemoryReplayAdapter {
    fn execute_with_cancellation(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeSink,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError> {
        let timing = FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(0));
        let mut session = ExecutionSession::new(context);

        if self.validate_fixture(context, cancellation)? == Prevalidation::Cancelled {
            return session.completion(
                timing,
                AttemptCounts::new(self.member_count, 0),
                AttemptCounts::default(),
                session.boundaries([]),
                [],
                AdapterOutcome::Cancelled,
                [],
                FetchCompleteness::partial(
                    FetchPartialReasons::new(FetchPartialReason::Cancelled),
                    None,
                ),
            );
        }

        let mut stopped = None;
        let mut saw_fragment = false;
        let mut cancelled = false;

        for envelope in &self.envelopes {
            if cancellation.is_cancelled() {
                cancelled = true;
                break;
            }
            saw_fragment |= !envelope.state().is_complete();
            match session.accept(sink, envelope.clone()) {
                AcceptStatus::Acknowledged => {}
                AcceptStatus::SinkStopped => {
                    stopped = Some(AcceptStatus::SinkStopped);
                    break;
                }
                AcceptStatus::AdapterStopped => {
                    stopped = Some(AcceptStatus::AdapterStopped);
                    break;
                }
            }
        }

        let completed_members = u64::from(stopped.is_none() && !cancelled) * self.member_count;
        let members = AttemptCounts::new(self.member_count, completed_members);
        let boundaries = session.boundaries([]);

        match (stopped, cancelled) {
            (None, true) => session.completion(
                timing,
                members,
                AttemptCounts::default(),
                boundaries,
                [],
                AdapterOutcome::Cancelled,
                [],
                FetchCompleteness::partial(
                    FetchPartialReasons::new(FetchPartialReason::Cancelled),
                    session.final_cursor(),
                ),
            ),
            (Some(AcceptStatus::SinkStopped), _) => session.completion(
                timing,
                members,
                AttemptCounts::default(),
                boundaries,
                [],
                AdapterOutcome::SinkStopped,
                [FetchErrorCode::SinkFailure],
                FetchCompleteness::partial(
                    FetchPartialReasons::new(FetchPartialReason::SinkFailure),
                    session.final_cursor(),
                ),
            ),
            (Some(AcceptStatus::AdapterStopped), _) => session.completion(
                timing,
                members,
                AttemptCounts::default(),
                boundaries,
                [],
                AdapterOutcome::AdapterStopped,
                [FetchErrorCode::AdapterInvariantViolation],
                FetchCompleteness::partial(
                    FetchPartialReasons::new(FetchPartialReason::OtherVersioned {
                        version: 1,
                        code: 1,
                    }),
                    session.final_cursor(),
                ),
            ),
            (Some(AcceptStatus::Acknowledged), _) => {
                unreachable!("acknowledgement is not terminal")
            }
            (None, false) if saw_fragment => session.completion(
                timing,
                members,
                AttemptCounts::default(),
                boundaries,
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::partial(
                    FetchPartialReasons::new(FetchPartialReason::RecordTruncated),
                    None,
                ),
            ),
            (None, false) => session.completion(
                timing,
                members,
                AttemptCounts::default(),
                boundaries,
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
            ),
        }
    }
}

impl fmt::Debug for InMemoryReplayAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryReplayAdapter")
            .field("envelope_count", &self.envelopes.len())
            .field("source_bytes", &self.fixture_source_bytes)
            .field("max_records", &self.max_records)
            .field("max_source_bytes", &self.max_source_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prevalidation {
    Ready,
    Cancelled,
}
