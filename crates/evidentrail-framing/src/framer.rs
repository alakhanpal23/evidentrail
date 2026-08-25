use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    BlockAssignment, BlockConfidence, BlockIndex, BlockReconciliationError, BlockState, Event,
    EventLedger, FramingPolicy, LaneKey,
};

use crate::classify::{
    RecognitionState, is_joinable_line, is_opaque_line, is_provider_atomic,
    looks_like_orphan_continuation, recognized_continuation, recognized_start,
};

pub const FRAMING_POLICY_NAME_V1: &[u8] = b"evidentrail/source-lane-atomic-framer";
pub const FRAMING_POLICY_VERSION_V1: &[u8] = b"1";

/// Reconstructed blocks contain at most this many source-defined records.
pub const MAX_RECONSTRUCTED_BLOCK_LINES_V1: usize = 256;
/// Reconstructed blocks contain at most this many exact authorized bytes.
pub const MAX_RECONSTRUCTED_BLOCK_BYTES_V1: usize = 1024 * 1024;
/// Nested exception causes/goroutine sections cannot grow parser state beyond
/// this fixed depth.
pub const MAX_RECONSTRUCTED_STATE_DEPTH_V1: u16 = 32;
/// If both records carry adapter-monotonic timestamps, a larger gap is a hard
/// block boundary. Wall/provider timestamps are deliberately ignored.
pub const MAX_CONTINUATION_GAP_NANOS_V1: u64 = 30_000_000_000;

#[must_use]
pub fn source_lane_framing_policy_v1() -> FramingPolicy {
    FramingPolicy::new(FRAMING_POLICY_NAME_V1, FRAMING_POLICY_VERSION_V1)
}

#[derive(PartialEq, Eq)]
pub enum SourceLaneFramingError {
    BlockByteCountOverflow,
    Reconciliation(BlockReconciliationError),
}

impl SourceLaneFramingError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BlockByteCountOverflow => "EVIDENTRAIL_FRAMING_BLOCK_BYTE_COUNT_OVERFLOW",
            Self::Reconciliation(_) => "EVIDENTRAIL_FRAMING_RECONCILIATION_FAILED",
        }
    }
}

impl fmt::Debug for SourceLaneFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceLaneFramingError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SourceLaneFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SourceLaneFramingError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Reconciliation(error) => Some(error),
            Self::BlockByteCountOverflow => None,
        }
    }
}

impl From<BlockReconciliationError> for SourceLaneFramingError {
    fn from(error: BlockReconciliationError) -> Self {
        Self::Reconciliation(error)
    }
}

/// Frame a sealed ledger into one exhaustive primary partition.
///
/// Traversal is canonical by lane key and lane sequence. Global events from a
/// different lane neither terminate nor extend an active block. A continuation
/// is inspected before it is consumed, so a cap or trustworthy time boundary
/// always leaves that event available for its own block.
pub fn frame_source_lanes_v1(
    ledger: &EventLedger,
) -> Result<BlockIndex<'_>, SourceLaneFramingError> {
    let mut lanes = BTreeMap::<LaneKey, Vec<&Event>>::new();
    for event in ledger.events() {
        lanes.entry(event.lane().clone()).or_default().push(event);
    }

    let mut assignments = Vec::with_capacity(ledger.len());
    let policy = source_lane_framing_policy_v1();
    for (lane, events) in lanes {
        frame_lane(&lane, &events, &policy, &mut assignments)?;
    }
    BlockIndex::reconcile(ledger, assignments).map_err(Into::into)
}

fn frame_lane(
    lane: &LaneKey,
    events: &[&Event],
    policy: &FramingPolicy,
    assignments: &mut Vec<BlockAssignment>,
) -> Result<(), SourceLaneFramingError> {
    let mut index = 0;
    while index < events.len() {
        let event = events[index];
        let next = events.get(index + 1).copied();

        if let Some(mut recognition) = recognized_start(event, next) {
            let mut end = index + 1;
            let mut bytes = event.raw().len();
            let mut terminated_by_cap = bytes > MAX_RECONSTRUCTED_BLOCK_BYTES_V1;
            let mut timing_uncertain = false;

            while !terminated_by_cap && end < events.len() {
                let candidate = events[end];
                match monotonic_relation(events[end - 1], candidate) {
                    MonotonicRelation::WithinBound => {}
                    MonotonicRelation::Unavailable => timing_uncertain = true,
                    MonotonicRelation::Boundary => break,
                }
                let candidate_next = eligible_lookahead(recognition, bytes, index, end, events);
                let Some(continuation) =
                    recognized_continuation(recognition, candidate, candidate_next)
                else {
                    break;
                };

                if continuation.state.depth() > MAX_RECONSTRUCTED_STATE_DEPTH_V1
                    || end - index >= MAX_RECONSTRUCTED_BLOCK_LINES_V1
                {
                    terminated_by_cap = true;
                    break;
                }
                let Some(next_bytes) = bytes.checked_add(candidate.raw().len()) else {
                    return Err(SourceLaneFramingError::BlockByteCountOverflow);
                };
                if next_bytes > MAX_RECONSTRUCTED_BLOCK_BYTES_V1 {
                    terminated_by_cap = true;
                    break;
                }
                bytes = next_bytes;
                recognition = continuation.state;
                end += 1;
            }

            if end > index + 1 {
                assignments.push(assignment(
                    lane,
                    &events[index..end],
                    policy,
                    BlockState::Reconstructed,
                    if terminated_by_cap || timing_uncertain {
                        BlockConfidence::Medium
                    } else {
                        BlockConfidence::High
                    },
                ));
                index = end;
                continue;
            }
        }

        let (state, confidence) = singleton_classification(event, next);
        assignments.push(assignment(
            lane,
            &events[index..index + 1],
            policy,
            state,
            confidence,
        ));
        index += 1;
    }
    Ok(())
}

fn assignment(
    lane: &LaneKey,
    events: &[&Event],
    policy: &FramingPolicy,
    state: BlockState,
    confidence: BlockConfidence,
) -> BlockAssignment {
    BlockAssignment::new_same_lane_v1(
        lane.clone(),
        events
            .iter()
            .map(|event| (event.id(), event.lane_sequence())),
        policy.clone(),
        state,
        confidence,
    )
}

/// A lookahead may influence whether the current event is a continuation only
/// when that lookahead could itself be consumed under every hard boundary.
/// This prevents a blank from being swallowed on the strength of a structural
/// record that must remain outside the block.
fn eligible_lookahead<'events>(
    recognition: RecognitionState,
    current_bytes: usize,
    start: usize,
    candidate_index: usize,
    events: &'events [&Event],
) -> Option<&'events Event> {
    let candidate = *events.get(candidate_index)?;
    let lookahead = *events.get(candidate_index.checked_add(1)?)?;
    if candidate_index.checked_sub(start)?.checked_add(2)? > MAX_RECONSTRUCTED_BLOCK_LINES_V1
        || monotonic_relation(candidate, lookahead) == MonotonicRelation::Boundary
    {
        return None;
    }
    let bytes_with_candidate = current_bytes.checked_add(candidate.raw().len())?;
    let bytes_with_lookahead = bytes_with_candidate.checked_add(lookahead.raw().len())?;
    if bytes_with_lookahead > MAX_RECONSTRUCTED_BLOCK_BYTES_V1 {
        return None;
    }
    let continuation = recognized_continuation(recognition, lookahead, None)?;
    (continuation.state.depth() <= MAX_RECONSTRUCTED_STATE_DEPTH_V1).then_some(lookahead)
}

fn singleton_classification(event: &Event, next: Option<&Event>) -> (BlockState, BlockConfidence) {
    if !event.record_state().is_complete() {
        return (BlockState::Ambiguous, BlockConfidence::Unknown);
    }
    if is_provider_atomic(event) {
        return (BlockState::ProviderAtomic, BlockConfidence::Certain);
    }
    if recognized_start(event, next).is_some() || looks_like_orphan_continuation(event) {
        return (BlockState::Ambiguous, BlockConfidence::Low);
    }
    if is_opaque_line(event) || !is_joinable_line(event) {
        return (BlockState::FallbackSingleton, BlockConfidence::Unknown);
    }
    (BlockState::FallbackSingleton, BlockConfidence::Certain)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MonotonicRelation {
    WithinBound,
    Unavailable,
    Boundary,
}

fn monotonic_relation(previous: &Event, next: &Event) -> MonotonicRelation {
    let Some(previous_time) = previous.timestamps().adapter_monotonic_time() else {
        return MonotonicRelation::Unavailable;
    };
    let Some(next_time) = next.timestamps().adapter_monotonic_time() else {
        return MonotonicRelation::Unavailable;
    };
    match next_time.get().checked_sub(previous_time.get()) {
        Some(gap) if gap <= MAX_CONTINUATION_GAP_NANOS_V1 => MonotonicRelation::WithinBound,
        Some(_) | None => MonotonicRelation::Boundary,
    }
}
