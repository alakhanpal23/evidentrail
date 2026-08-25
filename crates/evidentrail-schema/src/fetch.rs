use std::error::Error as StdError;
use std::fmt;

use crate::{
    AdapterIdentity, PartialReason, PartialReasons, PlanDigest, PlanId, ProviderCompleteness,
    RetrievalId, SourceCursor, SourceMember, UnixTimestampNanos, UnknownCompletenessReason,
};

/// Identity binding shared by every terminal fetch status.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchIdentity {
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    adapter: AdapterIdentity,
}

impl FetchIdentity {
    #[must_use]
    pub const fn new(
        retrieval_id: RetrievalId,
        plan_id: PlanId,
        plan_digest: PlanDigest,
        adapter: AdapterIdentity,
    ) -> Self {
        Self {
            retrieval_id,
            plan_id,
            plan_digest,
            adapter,
        }
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn adapter(&self) -> &AdapterIdentity {
        &self.adapter
    }
}

impl fmt::Debug for FetchIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchIdentity")
            .field("retrieval_id_present", &true)
            .field("plan_id_present", &true)
            .field("plan_digest_present", &true)
            .field("adapter", &self.adapter)
            .finish()
    }
}

/// Wall-clock interval during which adapter execution occurred.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FetchTiming {
    started_at: UnixTimestampNanos,
    ended_at: UnixTimestampNanos,
}

impl FetchTiming {
    #[must_use]
    pub const fn new(started_at: UnixTimestampNanos, ended_at: UnixTimestampNanos) -> Self {
        Self {
            started_at,
            ended_at,
        }
    }

    #[must_use]
    pub const fn started_at(self) -> UnixTimestampNanos {
        self.started_at
    }

    #[must_use]
    pub const fn ended_at(self) -> UnixTimestampNanos {
        self.ended_at
    }
}

impl fmt::Debug for FetchTiming {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchTiming")
            .field("started_at_present", &true)
            .field("ended_at_present", &true)
            .finish()
    }
}

/// Counts derived only from durable sink acknowledgements.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AcknowledgedCounts {
    records: u64,
    payload_bytes: u64,
    source_bytes: u64,
}

impl AcknowledgedCounts {
    #[must_use]
    pub const fn new(records: u64, payload_bytes: u64, source_bytes: u64) -> Self {
        Self {
            records,
            payload_bytes,
            source_bytes,
        }
    }

    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }

    #[must_use]
    pub const fn payload_bytes(self) -> u64 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn source_bytes(self) -> u64 {
        self.source_bytes
    }
}

impl fmt::Debug for AcknowledgedCounts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcknowledgedCounts")
            .field("records", &self.records)
            .field("payload_bytes", &self.payload_bytes)
            .field("source_bytes", &self.source_bytes)
            .finish()
    }
}

/// Attempted and completed count for pages or source members.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AttemptCounts {
    attempted: u64,
    completed: u64,
}

impl AttemptCounts {
    #[must_use]
    pub const fn new(attempted: u64, completed: u64) -> Self {
        Self {
            attempted,
            completed,
        }
    }

    #[must_use]
    pub const fn attempted(self) -> u64 {
        self.attempted
    }

    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }
}

impl fmt::Debug for AttemptCounts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptCounts")
            .field("attempted", &self.attempted)
            .field("completed", &self.completed)
            .finish()
    }
}

/// A verified end position for one source member.
#[derive(Clone, PartialEq, Eq)]
pub struct HighWaterMark {
    member: SourceMember,
    cursor: SourceCursor,
}

impl HighWaterMark {
    #[must_use]
    pub const fn new(member: SourceMember, cursor: SourceCursor) -> Self {
        Self { member, cursor }
    }

    #[must_use]
    pub const fn member(&self) -> &SourceMember {
        &self.member
    }

    #[must_use]
    pub const fn cursor(&self) -> &SourceCursor {
        &self.cursor
    }
}

impl fmt::Debug for HighWaterMark {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HighWaterMark")
            .field("member_present", &true)
            .field("cursor_present", &true)
            .finish()
    }
}

/// Optional first/final cursors plus member-specific high-water marks.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FetchBoundaries {
    first_cursor: Option<SourceCursor>,
    final_cursor: Option<SourceCursor>,
    high_water_marks: Vec<HighWaterMark>,
}

impl FetchBoundaries {
    #[must_use]
    pub fn new(
        first_cursor: Option<SourceCursor>,
        final_cursor: Option<SourceCursor>,
        high_water_marks: impl IntoIterator<Item = HighWaterMark>,
    ) -> Self {
        Self {
            first_cursor,
            final_cursor,
            high_water_marks: high_water_marks.into_iter().collect(),
        }
    }

    #[must_use]
    pub const fn first_cursor(&self) -> Option<&SourceCursor> {
        self.first_cursor.as_ref()
    }

    #[must_use]
    pub const fn final_cursor(&self) -> Option<&SourceCursor> {
        self.final_cursor.as_ref()
    }

    #[must_use]
    pub fn high_water_marks(&self) -> &[HighWaterMark] {
        &self.high_water_marks
    }
}

impl fmt::Debug for FetchBoundaries {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchBoundaries")
            .field("first_cursor_present", &self.first_cursor.is_some())
            .field("final_cursor_present", &self.final_cursor.is_some())
            .field("high_water_mark_count", &self.high_water_marks.len())
            .finish()
    }
}

/// Independent acquisition limit whose use is reported at completion.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapKind {
    Records,
    SourceBytes,
    ExpandedBytes,
    Pages,
    Members,
    PerRecordBytes,
    InFlightBytes,
    EncryptedSpoolBytes,
    WallTimeMillis,
    DiagnosticBytes,
    OtherVersioned { version: u16, code: u16 },
}

impl CapKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::SourceBytes => "source_bytes",
            Self::ExpandedBytes => "expanded_bytes",
            Self::Pages => "pages",
            Self::Members => "members",
            Self::PerRecordBytes => "per_record_bytes",
            Self::InFlightBytes => "in_flight_bytes",
            Self::EncryptedSpoolBytes => "encrypted_spool_bytes",
            Self::WallTimeMillis => "wall_time_millis",
            Self::DiagnosticBytes => "diagnostic_bytes",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for CapKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapKind")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapUsage {
    kind: CapKind,
    used: u64,
    limit: u64,
    reached: bool,
}

impl CapUsage {
    /// Records use of one cap.
    ///
    /// `reached` means this cap terminated acquisition. Merely consuming
    /// exactly `limit` units after the planned source was already exhausted is
    /// not a terminating cap and must be recorded as `false`.
    #[must_use]
    pub const fn new(kind: CapKind, used: u64, limit: u64, reached: bool) -> Self {
        Self {
            kind,
            used,
            limit,
            reached,
        }
    }

    #[must_use]
    pub const fn kind(self) -> CapKind {
        self.kind
    }

    #[must_use]
    pub const fn used(self) -> u64 {
        self.used
    }

    #[must_use]
    pub const fn limit(self) -> u64 {
        self.limit
    }

    #[must_use]
    pub const fn reached(self) -> bool {
        self.reached
    }
}

/// Structural contradiction that makes a fetch completion invalid.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FetchConstructionError {
    EndedBeforeStarted,
    CompletedMembersExceedAttempted,
    CompletedPagesExceedAttempted,
    PayloadBytesExceedSourceBytes,
    CompleteWithNonFinishedOutcome,
    CompleteWithErrorCodes,
    CompleteWithTerminatingCap,
    CompleteWithIncompleteMembers,
    CompleteWithIncompletePages,
}

impl FetchConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EndedBeforeStarted => "EVIDENTRAIL_FETCH_ENDED_BEFORE_STARTED",
            Self::CompletedMembersExceedAttempted => {
                "EVIDENTRAIL_FETCH_COMPLETED_MEMBERS_EXCEED_ATTEMPTED"
            }
            Self::CompletedPagesExceedAttempted => "EVIDENTRAIL_FETCH_COMPLETED_PAGES_EXCEED_ATTEMPTED",
            Self::PayloadBytesExceedSourceBytes => "EVIDENTRAIL_FETCH_PAYLOAD_BYTES_EXCEED_SOURCE_BYTES",
            Self::CompleteWithNonFinishedOutcome => {
                "EVIDENTRAIL_FETCH_COMPLETE_WITH_NON_FINISHED_OUTCOME"
            }
            Self::CompleteWithErrorCodes => "EVIDENTRAIL_FETCH_COMPLETE_WITH_ERROR_CODES",
            Self::CompleteWithTerminatingCap => "EVIDENTRAIL_FETCH_COMPLETE_WITH_TERMINATING_CAP",
            Self::CompleteWithIncompleteMembers => "EVIDENTRAIL_FETCH_COMPLETE_WITH_INCOMPLETE_MEMBERS",
            Self::CompleteWithIncompletePages => "EVIDENTRAIL_FETCH_COMPLETE_WITH_INCOMPLETE_PAGES",
        }
    }
}

impl fmt::Debug for FetchConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FetchConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FetchConstructionError {}

impl fmt::Debug for CapUsage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapUsage")
            .field("kind_code", &self.kind.code())
            .field("used", &self.used)
            .field("limit", &self.limit)
            .field("reached", &self.reached)
            .finish()
    }
}

/// Stable terminal outcome of the adapter execution machinery.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterOutcome {
    Finished,
    Cancelled,
    DeadlineExceeded,
    ProviderStopped,
    SourceStopped,
    SinkStopped,
    AdapterStopped,
}

impl AdapterOutcome {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ProviderStopped => "provider_stopped",
            Self::SourceStopped => "source_stopped",
            Self::SinkStopped => "sink_stopped",
            Self::AdapterStopped => "adapter_stopped",
        }
    }
}

impl fmt::Debug for AdapterOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterOutcome")
            .field("code", &self.code())
            .finish()
    }
}

/// Stable, contentless adapter error code. Provider error bodies are excluded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FetchErrorCode {
    AuthenticationChanged,
    PermissionDenied,
    SourceUnavailable,
    SourceChanged,
    ProviderFailure,
    NetworkFailure,
    ChildExitFailure,
    ChildKilled,
    MalformedProviderFraming,
    SourceReadFailure,
    SinkFailure,
    AdapterInvariantViolation,
    OtherVersioned { version: u16, code: u16 },
}

impl FetchErrorCode {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationChanged => "authentication_changed",
            Self::PermissionDenied => "permission_denied",
            Self::SourceUnavailable => "source_unavailable",
            Self::SourceChanged => "source_changed",
            Self::ProviderFailure => "provider_failure",
            Self::NetworkFailure => "network_failure",
            Self::ChildExitFailure => "child_exit_failure",
            Self::ChildKilled => "child_killed",
            Self::MalformedProviderFraming => "malformed_provider_framing",
            Self::SourceReadFailure => "source_read_failure",
            Self::SinkFailure => "sink_failure",
            Self::AdapterInvariantViolation => "adapter_invariant_violation",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for FetchErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchErrorCode")
            .field("code", &self.code())
            .finish()
    }
}

/// Source-specific evidence supporting a provider-complete claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompletenessProof {
    FixedSnapshotVerified,
    PlannedUnixFileSnapshotVerifiedV1,
    ProviderBoundaryExhausted,
    FinalCursorVerified,
    ReplayManifestVerified,
    InMemoryFixtureExhausted,
    OtherVersioned { version: u16, code: u16 },
}

impl CompletenessProof {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixedSnapshotVerified => "fixed_snapshot_verified",
            Self::PlannedUnixFileSnapshotVerifiedV1 => "planned_unix_file_snapshot_verified_v1",
            Self::ProviderBoundaryExhausted => "provider_boundary_exhausted",
            Self::FinalCursorVerified => "final_cursor_verified",
            Self::ReplayManifestVerified => "replay_manifest_verified",
            Self::InMemoryFixtureExhausted => "in_memory_fixture_exhausted",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for CompletenessProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletenessProof")
            .field("code", &self.code())
            .finish()
    }
}

/// Typed reason that a known condition prevented complete acquisition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FetchPartialReason {
    RowCap,
    RecordCountCap,
    SourceByteCap,
    ExpandedByteCap,
    PageCap,
    WallTimeCap,
    Timeout,
    Cancelled,
    BackpressureLimit,
    PaginationIncomplete,
    ProviderCap,
    ProviderTruncation,
    PermissionLimited,
    AuthenticationChanged,
    RetentionBoundary,
    SourceChanged,
    SourceDisappeared,
    SourceReadError,
    ChildExitFailure,
    ChildKilled,
    NetworkFailure,
    MalformedProviderFraming,
    RecordTruncated,
    DecompressionLimit,
    SinkFailure,
    OtherVersioned { version: u16, code: u16 },
}

impl FetchPartialReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RowCap => "row_cap",
            Self::RecordCountCap => "record_count_cap",
            Self::SourceByteCap => "source_byte_cap",
            Self::ExpandedByteCap => "expanded_byte_cap",
            Self::PageCap => "page_cap",
            Self::WallTimeCap => "wall_time_cap",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::BackpressureLimit => "backpressure_limit",
            Self::PaginationIncomplete => "pagination_incomplete",
            Self::ProviderCap => "provider_cap",
            Self::ProviderTruncation => "provider_truncation",
            Self::PermissionLimited => "permission_limited",
            Self::AuthenticationChanged => "authentication_changed",
            Self::RetentionBoundary => "retention_boundary",
            Self::SourceChanged => "source_changed",
            Self::SourceDisappeared => "source_disappeared",
            Self::SourceReadError => "source_read_error",
            Self::ChildExitFailure => "child_exit_failure",
            Self::ChildKilled => "child_killed",
            Self::NetworkFailure => "network_failure",
            Self::MalformedProviderFraming => "malformed_provider_framing",
            Self::RecordTruncated => "record_truncated",
            Self::DecompressionLimit => "decompression_limit",
            Self::SinkFailure => "sink_failure",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }

    const fn into_provider_reason(self) -> PartialReason {
        match self {
            Self::RowCap => PartialReason::RowCap,
            Self::RecordCountCap => PartialReason::RecordCountCap,
            Self::SourceByteCap => PartialReason::SourceByteCap,
            Self::ExpandedByteCap => PartialReason::ExpandedByteCap,
            Self::PageCap => PartialReason::PageCap,
            Self::WallTimeCap => PartialReason::WallTimeCap,
            Self::Timeout => PartialReason::Timeout,
            Self::Cancelled => PartialReason::Cancelled,
            Self::BackpressureLimit => PartialReason::BackpressureLimit,
            Self::PaginationIncomplete => PartialReason::PaginationIncomplete,
            Self::ProviderCap => PartialReason::ProviderCap,
            Self::ProviderTruncation => PartialReason::ProviderTruncation,
            Self::PermissionLimited => PartialReason::PermissionLimited,
            Self::AuthenticationChanged => PartialReason::AuthenticationChanged,
            Self::RetentionBoundary => PartialReason::RetentionBoundary,
            Self::SourceChanged => PartialReason::SourceChanged,
            Self::SourceDisappeared => PartialReason::SourceDisappeared,
            Self::SourceReadError => PartialReason::SourceReadError,
            Self::ChildExitFailure => PartialReason::ChildExitFailure,
            Self::ChildKilled => PartialReason::ChildKilled,
            Self::NetworkFailure => PartialReason::NetworkFailure,
            Self::MalformedProviderFraming => PartialReason::MalformedProviderFraming,
            Self::RecordTruncated => PartialReason::RecordTruncated,
            Self::DecompressionLimit => PartialReason::DecompressionLimit,
            Self::SinkFailure => PartialReason::SinkFailure,
            Self::OtherVersioned { version, code } => {
                PartialReason::OtherVersioned { version, code }
            }
        }
    }
}

impl fmt::Debug for FetchPartialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchPartialReason")
            .field("code", &self.code())
            .finish()
    }
}

/// Structurally non-empty typed partial-reason collection.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchPartialReasons {
    first: FetchPartialReason,
    additional: Vec<FetchPartialReason>,
}

impl FetchPartialReasons {
    #[must_use]
    pub const fn new(first: FetchPartialReason) -> Self {
        Self {
            first,
            additional: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_additional(
        first: FetchPartialReason,
        additional: impl IntoIterator<Item = FetchPartialReason>,
    ) -> Self {
        Self {
            first,
            additional: additional.into_iter().collect(),
        }
    }

    #[must_use]
    pub const fn first(&self) -> FetchPartialReason {
        self.first
    }

    pub fn iter(&self) -> impl Iterator<Item = FetchPartialReason> + '_ {
        std::iter::once(self.first).chain(self.additional.iter().copied())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.additional.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for FetchPartialReasons {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let codes = self
            .iter()
            .map(FetchPartialReason::code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("FetchPartialReasons")
            .field("count", &self.len())
            .field("codes", &codes)
            .finish()
    }
}

/// Typed reason that no complete/partial proof can be made.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FetchUnknownReason {
    ProviderHasNoCompletenessProof,
    RetentionUnobservable,
    HighWaterMarkUnverifiable,
    EventuallyConsistentWindow,
    LiveStreamOpenEnded,
    AdapterCapabilityLimit,
}

impl FetchUnknownReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderHasNoCompletenessProof => "provider_has_no_completeness_proof",
            Self::RetentionUnobservable => "retention_unobservable",
            Self::HighWaterMarkUnverifiable => "high_water_mark_unverifiable",
            Self::EventuallyConsistentWindow => "eventually_consistent_window",
            Self::LiveStreamOpenEnded => "live_stream_open_ended",
            Self::AdapterCapabilityLimit => "adapter_capability_limit",
        }
    }

    const fn into_provider_reason(self) -> UnknownCompletenessReason {
        match self {
            Self::ProviderHasNoCompletenessProof => {
                UnknownCompletenessReason::ProviderHasNoCompletenessProof
            }
            Self::RetentionUnobservable => UnknownCompletenessReason::RetentionUnobservable,
            Self::HighWaterMarkUnverifiable => UnknownCompletenessReason::HighWaterMarkUnverifiable,
            Self::EventuallyConsistentWindow => {
                UnknownCompletenessReason::EventuallyConsistentWindow
            }
            Self::LiveStreamOpenEnded => UnknownCompletenessReason::LiveStreamOpenEnded,
            Self::AdapterCapabilityLimit => UnknownCompletenessReason::AdapterCapabilityLimit,
        }
    }
}

impl fmt::Debug for FetchUnknownReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchUnknownReason")
            .field("code", &self.code())
            .finish()
    }
}

/// Terminal acquisition completeness fact before its summary projection.
#[derive(Clone, PartialEq, Eq)]
pub enum FetchCompleteness {
    Complete {
        proof: CompletenessProof,
    },
    Partial {
        reasons: FetchPartialReasons,
        continuation: Option<SourceCursor>,
    },
    Unknown {
        reason: FetchUnknownReason,
    },
}

impl FetchCompleteness {
    #[must_use]
    pub const fn complete(proof: CompletenessProof) -> Self {
        Self::Complete { proof }
    }

    #[must_use]
    pub const fn partial(reasons: FetchPartialReasons, continuation: Option<SourceCursor>) -> Self {
        Self::Partial {
            reasons,
            continuation,
        }
    }

    #[must_use]
    pub const fn unknown(reason: FetchUnknownReason) -> Self {
        Self::Unknown { reason }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Complete { .. } => "complete",
            Self::Partial { .. } => "partial",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Deterministic, deliberately lossy summary for downstream coverage.
    #[must_use]
    pub fn to_provider_completeness(&self) -> ProviderCompleteness {
        match self {
            Self::Complete { .. } => ProviderCompleteness::Complete,
            Self::Partial {
                reasons,
                continuation,
            } => {
                let mut reasons = reasons.iter().map(FetchPartialReason::into_provider_reason);
                let first = reasons
                    .next()
                    .expect("FetchPartialReasons is non-empty by construction");
                ProviderCompleteness::Partial {
                    reasons: PartialReasons::with_additional(first, reasons),
                    detail: None,
                    continuation: continuation
                        .as_ref()
                        .map(|cursor| cursor.as_bytes().to_vec()),
                }
            }
            Self::Unknown { reason } => {
                ProviderCompleteness::unknown(reason.into_provider_reason())
            }
        }
    }
}

impl fmt::Debug for FetchCompleteness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("FetchCompleteness");
        summary.field("status", &self.code());
        match self {
            Self::Complete { proof } => {
                summary.field("proof_code", &proof.code());
            }
            Self::Partial {
                reasons,
                continuation,
            } => {
                summary
                    .field("reasons", reasons)
                    .field("continuation_present", &continuation.is_some());
            }
            Self::Unknown { reason } => {
                summary.field("reason_code", &reason.code());
            }
        }
        summary.finish()
    }
}

/// Terminal, immutable acquisition fact returned after adapter execution.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchCompletion {
    identity: FetchIdentity,
    timing: FetchTiming,
    acknowledged: AcknowledgedCounts,
    members: AttemptCounts,
    pages: AttemptCounts,
    boundaries: FetchBoundaries,
    cap_usage: Vec<CapUsage>,
    adapter_outcome: AdapterOutcome,
    error_codes: Vec<FetchErrorCode>,
    completeness: FetchCompleteness,
}

impl FetchCompletion {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: FetchIdentity,
        timing: FetchTiming,
        acknowledged: AcknowledgedCounts,
        members: AttemptCounts,
        pages: AttemptCounts,
        boundaries: FetchBoundaries,
        cap_usage: impl IntoIterator<Item = CapUsage>,
        adapter_outcome: AdapterOutcome,
        error_codes: impl IntoIterator<Item = FetchErrorCode>,
        completeness: FetchCompleteness,
    ) -> Result<Self, FetchConstructionError> {
        let cap_usage = cap_usage.into_iter().collect::<Vec<_>>();
        let error_codes = error_codes.into_iter().collect::<Vec<_>>();

        if timing.ended_at.get() < timing.started_at.get() {
            return Err(FetchConstructionError::EndedBeforeStarted);
        }
        if members.completed > members.attempted {
            return Err(FetchConstructionError::CompletedMembersExceedAttempted);
        }
        if pages.completed > pages.attempted {
            return Err(FetchConstructionError::CompletedPagesExceedAttempted);
        }
        if acknowledged.payload_bytes > acknowledged.source_bytes {
            return Err(FetchConstructionError::PayloadBytesExceedSourceBytes);
        }

        if matches!(completeness, FetchCompleteness::Complete { .. }) {
            if adapter_outcome != AdapterOutcome::Finished {
                return Err(FetchConstructionError::CompleteWithNonFinishedOutcome);
            }
            if !error_codes.is_empty() {
                return Err(FetchConstructionError::CompleteWithErrorCodes);
            }
            if cap_usage.iter().any(|usage| usage.reached) {
                return Err(FetchConstructionError::CompleteWithTerminatingCap);
            }
            if members.completed != members.attempted {
                return Err(FetchConstructionError::CompleteWithIncompleteMembers);
            }
            if pages.completed != pages.attempted {
                return Err(FetchConstructionError::CompleteWithIncompletePages);
            }
        }

        Ok(Self {
            identity,
            timing,
            acknowledged,
            members,
            pages,
            boundaries,
            cap_usage,
            adapter_outcome,
            error_codes,
            completeness,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &FetchIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn timing(&self) -> FetchTiming {
        self.timing
    }

    #[must_use]
    pub const fn acknowledged(&self) -> AcknowledgedCounts {
        self.acknowledged
    }

    #[must_use]
    pub const fn member_counts(&self) -> AttemptCounts {
        self.members
    }

    #[must_use]
    pub const fn page_counts(&self) -> AttemptCounts {
        self.pages
    }

    #[must_use]
    pub const fn boundaries(&self) -> &FetchBoundaries {
        &self.boundaries
    }

    #[must_use]
    pub fn cap_usage(&self) -> &[CapUsage] {
        &self.cap_usage
    }

    #[must_use]
    pub const fn adapter_outcome(&self) -> AdapterOutcome {
        self.adapter_outcome
    }

    #[must_use]
    pub fn error_codes(&self) -> &[FetchErrorCode] {
        &self.error_codes
    }

    #[must_use]
    pub const fn completeness(&self) -> &FetchCompleteness {
        &self.completeness
    }

    #[must_use]
    pub fn provider_completeness(&self) -> ProviderCompleteness {
        self.completeness.to_provider_completeness()
    }
}

impl fmt::Debug for FetchCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cap_codes = self
            .cap_usage
            .iter()
            .map(|usage| usage.kind.code())
            .collect::<Vec<_>>();
        let error_codes = self
            .error_codes
            .iter()
            .map(|code| code.code())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("FetchCompletion")
            .field("acknowledged", &self.acknowledged)
            .field("members", &self.members)
            .field("pages", &self.pages)
            .field("boundaries", &self.boundaries)
            .field("cap_codes", &cap_codes)
            .field("adapter_outcome_code", &self.adapter_outcome.code())
            .field("error_codes", &error_codes)
            .field("completeness", &self.completeness)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch_identity(adapter: AdapterIdentity) -> FetchIdentity {
        FetchIdentity::new(
            RetrievalId::from_bytes([41; 32]),
            PlanId::from_bytes([42; 32]),
            PlanDigest::from_bytes([43; 32]),
            adapter,
        )
    }

    fn timing() -> FetchTiming {
        FetchTiming::new(
            UnixTimestampNanos::new(1_000),
            UnixTimestampNanos::new(2_000),
        )
    }

    #[test]
    fn complete_fetch_carries_all_accounting_and_projects_complete() {
        let first_cursor = SourceCursor::new(b"first".to_vec()).unwrap();
        let final_cursor = SourceCursor::new(b"final".to_vec()).unwrap();
        let high_water = HighWaterMark::new(
            SourceMember::new(b"member".to_vec()).unwrap(),
            SourceCursor::new(b"high-water".to_vec()).unwrap(),
        );
        let completion = FetchCompletion::new(
            fetch_identity(AdapterIdentity::new("file", "1.2.3").unwrap()),
            timing(),
            AcknowledgedCounts::new(3, 21, 24),
            AttemptCounts::new(2, 2),
            AttemptCounts::new(4, 4),
            FetchBoundaries::new(
                Some(first_cursor.clone()),
                Some(final_cursor.clone()),
                [high_water],
            ),
            [CapUsage::new(CapKind::SourceBytes, 24, 1_024, false)],
            AdapterOutcome::Finished,
            [],
            FetchCompleteness::complete(CompletenessProof::FixedSnapshotVerified),
        )
        .unwrap();

        assert_eq!(
            completion.identity().retrieval_id(),
            RetrievalId::from_bytes([41; 32])
        );
        assert_eq!(completion.timing().started_at().get(), 1_000);
        assert_eq!(completion.timing().ended_at().get(), 2_000);
        assert_eq!(completion.acknowledged().records(), 3);
        assert_eq!(completion.acknowledged().payload_bytes(), 21);
        assert_eq!(completion.acknowledged().source_bytes(), 24);
        assert_eq!(completion.member_counts(), AttemptCounts::new(2, 2));
        assert_eq!(completion.page_counts(), AttemptCounts::new(4, 4));
        assert_eq!(completion.boundaries().first_cursor(), Some(&first_cursor));
        assert_eq!(completion.boundaries().final_cursor(), Some(&final_cursor));
        assert_eq!(completion.boundaries().high_water_marks().len(), 1);
        assert_eq!(completion.cap_usage().len(), 1);
        assert_eq!(completion.adapter_outcome(), AdapterOutcome::Finished);
        assert!(completion.error_codes().is_empty());
        assert!(completion.provider_completeness().is_complete());
    }

    #[test]
    fn in_memory_fixture_exhaustion_has_a_distinct_contentless_proof() {
        let proof = CompletenessProof::InMemoryFixtureExhausted;
        assert_eq!(proof.code(), "in_memory_fixture_exhausted");
        assert_eq!(
            format!("{proof:?}"),
            "CompletenessProof { code: \"in_memory_fixture_exhausted\" }"
        );
    }

    #[test]
    fn planned_unix_file_snapshot_has_a_distinct_contentless_proof() {
        let proof = CompletenessProof::PlannedUnixFileSnapshotVerifiedV1;
        assert_eq!(proof.code(), "planned_unix_file_snapshot_verified_v1");
        assert_eq!(
            format!("{proof:?}"),
            "CompletenessProof { code: \"planned_unix_file_snapshot_verified_v1\" }"
        );
        assert_ne!(proof, CompletenessProof::FixedSnapshotVerified);
        assert_ne!(proof, CompletenessProof::InMemoryFixtureExhausted);
    }

    #[test]
    fn partial_reasons_are_nonempty_ordered_and_project_deterministically() {
        let continuation = SourceCursor::new(b"next-page".to_vec()).unwrap();
        let reasons = FetchPartialReasons::with_additional(
            FetchPartialReason::PageCap,
            [
                FetchPartialReason::PaginationIncomplete,
                FetchPartialReason::BackpressureLimit,
            ],
        );
        assert!(!reasons.is_empty());
        assert_eq!(reasons.len(), 3);

        let completeness = FetchCompleteness::partial(reasons, Some(continuation.clone()));
        let first_projection = completeness.to_provider_completeness();
        let second_projection = completeness.to_provider_completeness();
        assert_eq!(first_projection, second_projection);

        let ProviderCompleteness::Partial {
            reasons,
            detail,
            continuation: projected_continuation,
        } = first_projection
        else {
            panic!("partial fetch projected to a non-partial provider status");
        };
        assert_eq!(
            reasons.iter().map(PartialReason::code).collect::<Vec<_>>(),
            vec!["page_cap", "pagination_incomplete", "backpressure_limit"]
        );
        assert!(detail.is_none());
        assert_eq!(
            projected_continuation.as_deref(),
            Some(continuation.as_bytes())
        );
    }

    #[test]
    fn unknown_fetch_never_projects_to_complete() {
        let reasons = [
            FetchUnknownReason::ProviderHasNoCompletenessProof,
            FetchUnknownReason::RetentionUnobservable,
            FetchUnknownReason::HighWaterMarkUnverifiable,
            FetchUnknownReason::EventuallyConsistentWindow,
            FetchUnknownReason::LiveStreamOpenEnded,
            FetchUnknownReason::AdapterCapabilityLimit,
        ];

        for reason in reasons {
            let projection = FetchCompleteness::unknown(reason).to_provider_completeness();
            assert!(projection.is_unknown());
            assert!(!projection.is_complete());
            let ProviderCompleteness::Unknown { reason: projected } = projection else {
                panic!("unknown fetch projected to a non-unknown provider status");
            };
            assert_eq!(projected.code(), reason.code());
        }
    }

    #[test]
    fn fetch_debug_hides_identity_timing_members_and_cursors() {
        const ADAPTER_KIND: &str = "CANARY_FETCH_ADAPTER_2ea8";
        const ADAPTER_VERSION: &str = "CANARY_FETCH_VERSION_308a";
        const MEMBER: &[u8] = b"CANARY_FETCH_MEMBER_efea";
        const FIRST_CURSOR: &[u8] = b"CANARY_FIRST_CURSOR_762c";
        const FINAL_CURSOR: &[u8] = b"CANARY_FINAL_CURSOR_b403";
        const HIGH_WATER: &[u8] = b"CANARY_HIGH_WATER_f0d0";
        const CONTINUATION: &[u8] = b"CANARY_CONTINUATION_d508";

        let identity = fetch_identity(AdapterIdentity::new(ADAPTER_KIND, ADAPTER_VERSION).unwrap());
        let retrieval_canary = identity.retrieval_id().to_string();
        let plan_id_canary = identity.plan_id().to_string();
        let plan_digest_canary = identity.plan_digest().to_string();
        let completeness = FetchCompleteness::partial(
            FetchPartialReasons::with_additional(
                FetchPartialReason::ProviderCap,
                [FetchPartialReason::OtherVersioned {
                    version: 1,
                    code: 77,
                }],
            ),
            Some(SourceCursor::new(CONTINUATION.to_vec()).unwrap()),
        );
        let completion = FetchCompletion::new(
            identity.clone(),
            timing(),
            AcknowledgedCounts::new(8, 80, 88),
            AttemptCounts::new(2, 1),
            AttemptCounts::new(4, 3),
            FetchBoundaries::new(
                Some(SourceCursor::new(FIRST_CURSOR.to_vec()).unwrap()),
                Some(SourceCursor::new(FINAL_CURSOR.to_vec()).unwrap()),
                [HighWaterMark::new(
                    SourceMember::new(MEMBER.to_vec()).unwrap(),
                    SourceCursor::new(HIGH_WATER.to_vec()).unwrap(),
                )],
            ),
            [CapUsage::new(CapKind::Pages, 4, 4, true)],
            AdapterOutcome::ProviderStopped,
            [FetchErrorCode::ProviderFailure],
            completeness.clone(),
        )
        .unwrap();

        let rendered = [
            format!("{identity:?}"),
            format!("{:?}", completion.timing()),
            format!("{:?}", completion.boundaries()),
            format!("{completeness:?}"),
            format!("{completion:?}"),
        ];
        let canaries = [
            ADAPTER_KIND,
            ADAPTER_VERSION,
            std::str::from_utf8(MEMBER).unwrap(),
            std::str::from_utf8(FIRST_CURSOR).unwrap(),
            std::str::from_utf8(FINAL_CURSOR).unwrap(),
            std::str::from_utf8(HIGH_WATER).unwrap(),
            std::str::from_utf8(CONTINUATION).unwrap(),
            retrieval_canary.as_str(),
            plan_id_canary.as_str(),
            plan_digest_canary.as_str(),
        ];
        for output in rendered {
            for canary in canaries {
                assert!(!output.contains(canary));
            }
        }

        assert!(format!("{completion:?}").contains("provider_cap"));
        assert!(format!("{completion:?}").contains("provider_failure"));
        assert!(!completion.provider_completeness().is_complete());
    }

    #[allow(clippy::too_many_arguments)]
    fn completion_with(
        timing: FetchTiming,
        acknowledged: AcknowledgedCounts,
        members: AttemptCounts,
        pages: AttemptCounts,
        cap_usage: Vec<CapUsage>,
        adapter_outcome: AdapterOutcome,
        error_codes: Vec<FetchErrorCode>,
        completeness: FetchCompleteness,
    ) -> Result<FetchCompletion, FetchConstructionError> {
        FetchCompletion::new(
            fetch_identity(AdapterIdentity::new("replay", "1").unwrap()),
            timing,
            acknowledged,
            members,
            pages,
            FetchBoundaries::default(),
            cap_usage,
            adapter_outcome,
            error_codes,
            completeness,
        )
    }

    fn complete() -> FetchCompleteness {
        FetchCompleteness::complete(CompletenessProof::ReplayManifestVerified)
    }

    #[test]
    fn construction_rejects_impossible_base_facts() {
        let cases = [
            (
                completion_with(
                    FetchTiming::new(UnixTimestampNanos::new(2), UnixTimestampNanos::new(1)),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::EndedBeforeStarted,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 2),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompletedMembersExceedAttempted,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 2),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompletedPagesExceedAttempted,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 2, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::PayloadBytesExceedSourceBytes,
            ),
        ];

        for (result, expected) in cases {
            assert_eq!(result.unwrap_err(), expected);
        }
    }

    #[test]
    fn complete_claim_rejects_every_false_complete_condition() {
        let cases = [
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::ProviderStopped,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompleteWithNonFinishedOutcome,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![FetchErrorCode::ProviderFailure],
                    complete(),
                ),
                FetchConstructionError::CompleteWithErrorCodes,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(1, 1),
                    vec![CapUsage::new(CapKind::Records, 1, 1, true)],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompleteWithTerminatingCap,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(2, 1),
                    AttemptCounts::new(1, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompleteWithIncompleteMembers,
            ),
            (
                completion_with(
                    timing(),
                    AcknowledgedCounts::new(1, 1, 1),
                    AttemptCounts::new(1, 1),
                    AttemptCounts::new(2, 1),
                    vec![],
                    AdapterOutcome::Finished,
                    vec![],
                    complete(),
                ),
                FetchConstructionError::CompleteWithIncompletePages,
            ),
        ];

        for (result, expected) in cases {
            let error = result.unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(error.to_string(), error.code());
            assert_eq!(
                format!("{error:?}"),
                format!("FetchConstructionError {{ code: \"{}\" }}", error.code())
            );
        }
    }
}
