use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, Instant};

use evidentrail_core::{EnvelopeSink, PreparedSinkAckExpectation};
use evidentrail_ingest::Cancellation;
use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionSequence, AdapterOutcome, AttemptCounts, CapKind, CapUsage,
    CompletenessProof, EnvelopeOrdering, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchErrorCode, FetchPartialReason, FetchPartialReasons, FetchTiming, HighWaterMark, LaneKey,
    LaneSequence, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordFragmentReason,
    RecordState, SourceCursor, SourceStream, UnixTimestampNanos,
};
use rustix::fs;

use crate::preflight::{
    LocalFileExecutionFactsV1, LocalFilePreflightError, PreflightedLocalFileV1,
    observed_filesystem, snapshot_from_stats, validate_filesystems, validate_fresh_authority_time,
    validate_source_identity,
};

/// Consume a descriptor-backed preflight token and stream its exact fixed
/// snapshot into `sink`.
///
/// No plan, execution context, member, cap, path, or identity is accepted from
/// the caller. All such facts are owned by `preflight`. Public success remains
/// unreachable while public preflight is frozen at certification admission.
pub fn execute_preflighted_local_file_v1(
    preflight: PreflightedLocalFileV1<'_, '_>,
    sink: &mut dyn EnvelopeSink,
) -> Result<FetchCompletion, LocalFileExecutionError> {
    execute_preflighted_local_file_with_cancellation_v1(preflight, sink, &NeverCancelledV1)
}

/// Cancellation-aware descriptor execution.
///
/// Cancellation and the fixed monotonic deadline are checked immediately
/// before and after every content read and sink call. Calls already in progress
/// are synchronous and cannot be preempted.
pub fn execute_preflighted_local_file_with_cancellation_v1(
    preflight: PreflightedLocalFileV1<'_, '_>,
    sink: &mut dyn EnvelopeSink,
    cancellation: &dyn Cancellation,
) -> Result<FetchCompletion, LocalFileExecutionError> {
    execute_with(
        preflight,
        sink,
        cancellation,
        &SystemWallClockV1,
        &SystemExecutionMonotonicClockV1,
        &NoopExecutionObserverV1,
    )
}

fn execute_with<W, M, O>(
    preflight: PreflightedLocalFileV1<'_, '_>,
    sink: &mut dyn EnvelopeSink,
    cancellation: &dyn Cancellation,
    wall_clock: &W,
    monotonic_clock: &M,
    observer: &O,
) -> Result<FetchCompletion, LocalFileExecutionError>
where
    W: ExecutionWallClockV1,
    M: ExecutionMonotonicClockV1,
    O: ExecutionObserverV1,
{
    let mut preflight = preflight;
    let deadline =
        FixedExecutionDeadlineV1::start(monotonic_clock, preflight.facts.caps.wall_time_millis())?;
    let started_at = wall_clock.now()?;
    validate_fresh_authority_time(&preflight.facts, &preflight.authority, started_at)
        .map_err(LocalFileExecutionError::from_preflight)?;
    validate_execution_facts(&preflight.facts)?;
    validate_retained_descriptors(&preflight, 0)
        .map_err(LocalFileExecutionError::from_preflight)?;
    observer.after_pre_first_validation();
    // Revalidate the retained descriptors first, then make the sealed live
    // wall-clock observation the final authority check before streaming. This
    // prevents metadata work from consuming the remaining execution interval
    // after the last validity observation.
    validate_retained_descriptors(&preflight, 0)
        .map_err(LocalFileExecutionError::from_preflight)?;
    let ready_at = wall_clock.now()?;
    if ready_at < started_at {
        return Err(LocalFileExecutionError::WallClockUnavailable);
    }
    validate_fresh_authority_time(&preflight.facts, &preflight.authority, ready_at)
        .map_err(LocalFileExecutionError::from_preflight)?;

    let mut accounting = ExecutionAccountingV1::new(&preflight.facts);
    let mut stream = stream_exact_snapshot(
        &mut preflight,
        sink,
        cancellation,
        monotonic_clock,
        &deadline,
        observer,
        &mut accounting,
    );
    if !stream.sink_stopped
        && !stream.adapter_stopped
        && stream.bytes_read != accounting.acknowledged_source_bytes
    {
        stream.adapter_stopped = true;
    }

    let expected_offset = stream.bytes_read;
    stream.post_snapshot_verified =
        validate_retained_descriptors(&preflight, expected_offset).is_ok();

    let final_checkpoint = deadline.checkpoint(monotonic_clock, cancellation);
    stream.observe_checkpoint(final_checkpoint);

    let (ended_at, wall_clock_failed) = match wall_clock.now() {
        Ok(observed) if observed >= started_at => (observed, false),
        Ok(_) | Err(_) => (started_at, true),
    };
    stream.wall_clock_failed = wall_clock_failed;

    finish_execution(
        &preflight.facts,
        &accounting,
        stream,
        FetchTiming::new(started_at, ended_at),
    )
}

fn validate_execution_facts(
    facts: &LocalFileExecutionFactsV1,
) -> Result<(), LocalFileExecutionError> {
    let snapshot = facts.snapshot;
    if snapshot.start_offset() != 0
        || snapshot.high_water_exclusive() != snapshot.size()
        || snapshot.high_water_exclusive() > facts.caps.source_bytes()
        || facts.caps.per_record_bytes() > facts.caps.source_bytes()
    {
        return Err(LocalFileExecutionError::InvalidExecutionFacts);
    }
    Ok(())
}

fn validate_retained_descriptors(
    preflight: &PreflightedLocalFileV1<'_, '_>,
    expected_offset: u64,
) -> Result<(), LocalFilePreflightError> {
    let root_stat = fs::fstat(&preflight.root_fd)
        .map_err(|_| LocalFilePreflightError::RootMetadataUnavailable)?;
    let file_stat = fs::fstat(&preflight.file_fd)
        .map_err(|_| LocalFilePreflightError::FileMetadataUnavailable)?;
    let observed = snapshot_from_stats(&root_stat, &file_stat)?;
    if observed.root() != preflight.facts.snapshot.root() {
        return Err(LocalFilePreflightError::RootIdentityMismatch);
    }
    if observed.file() != preflight.facts.snapshot.file() {
        return Err(LocalFilePreflightError::FileIdentityMismatch);
    }
    if observed != preflight.facts.snapshot {
        return Err(LocalFilePreflightError::SnapshotMismatch);
    }
    validate_source_identity(&preflight.facts, observed)?;
    preflight
        .authority
        .check_opened_identity_not_internal(observed.file())
        .map_err(|error| match error {
            evidentrail_authority::RegistryAuthorizationError::BindingStateUnavailable
            | evidentrail_authority::RegistryAuthorizationError::InternalPathStateUnavailable => {
                LocalFilePreflightError::AuthorityStateUnavailable
            }
            evidentrail_authority::RegistryAuthorizationError::OpenedIdentityReserved => {
                LocalFilePreflightError::InternalIdentityReserved
            }
            _ => LocalFilePreflightError::LiveAuthorityMismatch,
        })?;

    let root_filesystem = fs::fstatfs(&preflight.root_fd)
        .map_err(|_| LocalFilePreflightError::FilesystemUnavailable)?;
    let file_filesystem = fs::fstatfs(&preflight.file_fd)
        .map_err(|_| LocalFilePreflightError::FilesystemUnavailable)?;
    validate_filesystems(
        preflight.facts.runtime_profile,
        observed_filesystem(&root_filesystem),
        observed_filesystem(&file_filesystem),
    )?;

    let offset = fs::seek(&preflight.file_fd, fs::SeekFrom::Current(0))
        .map_err(|_| LocalFilePreflightError::FileOffsetUnavailable)?;
    if offset != expected_offset {
        return Err(LocalFilePreflightError::FileOffsetMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CooperativeStopV1 {
    Continue,
    Cancelled,
    WallTimeCap,
}

#[derive(Clone, Copy)]
struct CheckpointV1 {
    stop: CooperativeStopV1,
    elapsed_millis: u64,
}

struct FixedExecutionDeadlineV1<I> {
    started_at: I,
    deadline: I,
    wall_time_millis: u64,
}

impl<I> FixedExecutionDeadlineV1<I>
where
    I: Copy + Ord,
{
    fn start<C>(clock: &C, wall_time_millis: u64) -> Result<Self, LocalFileExecutionError>
    where
        C: ExecutionMonotonicClockV1<Instant = I>,
    {
        if wall_time_millis == 0 {
            return Err(LocalFileExecutionError::InvalidExecutionFacts);
        }
        let started_at = clock.now();
        let deadline = clock
            .checked_add_millis(started_at, wall_time_millis)
            .ok_or(LocalFileExecutionError::DeadlineUnavailable)?;
        Ok(Self {
            started_at,
            deadline,
            wall_time_millis,
        })
    }

    fn checkpoint<C>(&self, clock: &C, cancellation: &dyn Cancellation) -> CheckpointV1
    where
        C: ExecutionMonotonicClockV1<Instant = I>,
    {
        if cancellation.is_cancelled() {
            return CheckpointV1 {
                stop: CooperativeStopV1::Cancelled,
                elapsed_millis: 0,
            };
        }
        let observed = clock.now();
        let (elapsed_millis, clock_invalid) = match clock.elapsed_millis(self.started_at, observed)
        {
            Some(elapsed) => (elapsed.min(self.wall_time_millis), false),
            None => (self.wall_time_millis, true),
        };
        let stop = if clock_invalid || observed >= self.deadline {
            CooperativeStopV1::WallTimeCap
        } else {
            CooperativeStopV1::Continue
        };
        CheckpointV1 {
            stop,
            elapsed_millis,
        }
    }
}

trait ExecutionMonotonicClockV1 {
    type Instant: Copy + Ord;

    fn now(&self) -> Self::Instant;

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant>;

    fn elapsed_millis(&self, started_at: Self::Instant, ended_at: Self::Instant) -> Option<u64>;
}

struct SystemExecutionMonotonicClockV1;

impl ExecutionMonotonicClockV1 for SystemExecutionMonotonicClockV1 {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant> {
        instant.checked_add(Duration::from_millis(wall_time_millis))
    }

    fn elapsed_millis(&self, started_at: Self::Instant, ended_at: Self::Instant) -> Option<u64> {
        let elapsed = ended_at.checked_duration_since(started_at)?;
        u64::try_from(elapsed.as_millis()).ok()
    }
}

trait ExecutionWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFileExecutionError>;
}

struct SystemWallClockV1;

impl ExecutionWallClockV1 for SystemWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFileExecutionError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| LocalFileExecutionError::WallClockUnavailable)?;
        let nanoseconds = i128::try_from(elapsed.as_nanos())
            .map_err(|_| LocalFileExecutionError::WallClockUnavailable)?;
        Ok(UnixTimestampNanos::new(nanoseconds))
    }
}

trait ExecutionObserverV1 {
    fn after_pre_first_validation(&self);
    fn after_content_read(&self, bytes_read: u64);
    fn after_sink_call(&self, acknowledged_records: u64);
}

struct NoopExecutionObserverV1;

impl ExecutionObserverV1 for NoopExecutionObserverV1 {
    fn after_pre_first_validation(&self) {}

    fn after_content_read(&self, _bytes_read: u64) {}

    fn after_sink_call(&self, _acknowledged_records: u64) {}
}

struct NeverCancelledV1;

impl Cancellation for NeverCancelledV1 {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Default)]
struct StreamOutcomeV1 {
    bytes_read: u64,
    max_record_bytes_used: u64,
    elapsed_millis: u64,
    source_byte_cap: bool,
    per_record_byte_cap: bool,
    record_count_cap: bool,
    cancelled: bool,
    wall_time_cap: bool,
    read_error: bool,
    unexpected_eof: bool,
    saw_fragment: bool,
    sink_stopped: bool,
    adapter_stopped: bool,
    post_snapshot_verified: bool,
    wall_clock_failed: bool,
}

impl StreamOutcomeV1 {
    fn observe_checkpoint(&mut self, checkpoint: CheckpointV1) {
        self.elapsed_millis = self.elapsed_millis.max(checkpoint.elapsed_millis);
        match checkpoint.stop {
            CooperativeStopV1::Continue => {}
            CooperativeStopV1::Cancelled => self.cancelled = true,
            CooperativeStopV1::WallTimeCap => self.wall_time_cap = true,
        }
    }

    const fn stop_content_reads(&self) -> bool {
        self.cancelled
            || self.wall_time_cap
            || self.read_error
            || self.unexpected_eof
            || self.sink_stopped
            || self.adapter_stopped
            || self.source_byte_cap
            || self.per_record_byte_cap
            || self.record_count_cap
    }

    const fn sink_unavailable(&self) -> bool {
        self.sink_stopped || self.adapter_stopped
    }
}

struct ExecutionAccountingV1 {
    envelope_identity: RawEnvelopeIdentityV1,
    lane: LaneKey,
    acknowledged_records: u64,
    acknowledged_payload_bytes: u64,
    acknowledged_source_bytes: u64,
    first_cursor: Option<SourceCursor>,
    final_cursor: Option<SourceCursor>,
}

impl ExecutionAccountingV1 {
    fn new(facts: &LocalFileExecutionFactsV1) -> Self {
        Self {
            envelope_identity: RawEnvelopeIdentityV1::new(
                facts.fetch_identity.retrieval_id(),
                facts.fetch_identity.plan_id(),
                facts.fetch_identity.plan_digest(),
                facts.fetch_identity.adapter().clone(),
                facts.source_identity_digest,
            ),
            lane: LaneKey::new(facts.source_member.clone(), SourceStream::FileMember),
            acknowledged_records: 0,
            acknowledged_payload_bytes: 0,
            acknowledged_source_bytes: 0,
            first_cursor: None,
            final_cursor: None,
        }
    }

    const fn acknowledged(&self) -> AcknowledgedCounts {
        AcknowledgedCounts::new(
            self.acknowledged_records,
            self.acknowledged_payload_bytes,
            self.acknowledged_source_bytes,
        )
    }

    fn boundaries(&self, high_water: Option<HighWaterMark>) -> FetchBoundaries {
        FetchBoundaries::new(
            self.first_cursor.clone(),
            self.final_cursor.clone(),
            high_water,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn stream_exact_snapshot<M, O>(
    preflight: &mut PreflightedLocalFileV1<'_, '_>,
    sink: &mut dyn EnvelopeSink,
    cancellation: &dyn Cancellation,
    clock: &M,
    deadline: &FixedExecutionDeadlineV1<M::Instant>,
    observer: &O,
    accounting: &mut ExecutionAccountingV1,
) -> StreamOutcomeV1
where
    M: ExecutionMonotonicClockV1,
    O: ExecutionObserverV1,
{
    let high_water = preflight.facts.snapshot.high_water_exclusive();
    let caps = preflight.facts.caps;
    let read_limit = high_water.min(caps.source_bytes());
    let mut outcome = StreamOutcomeV1::default();
    let mut record = Vec::new();
    let mut record_start = 0_u64;

    let initial = deadline.checkpoint(clock, cancellation);
    outcome.observe_checkpoint(initial);
    if outcome.stop_content_reads() {
        return outcome;
    }

    loop {
        if outcome.bytes_read == high_water {
            break;
        }
        if accounting.acknowledged_records >= caps.records() {
            outcome.record_count_cap = true;
            break;
        }
        if outcome.bytes_read == read_limit {
            outcome.source_byte_cap = read_limit < high_water;
            break;
        }

        let before_read = deadline.checkpoint(clock, cancellation);
        outcome.observe_checkpoint(before_read);
        if outcome.stop_content_reads() {
            break;
        }

        let mut byte = [0_u8; 1];
        let read_result = rustix::io::read(&preflight.file_fd, &mut byte);
        let after_read = deadline.checkpoint(clock, cancellation);
        let mut interrupted = false;

        match read_result {
            Ok(0) => {
                outcome.unexpected_eof = outcome.bytes_read < high_water;
            }
            Ok(1) => {
                if record.is_empty() {
                    record_start = outcome.bytes_read;
                }
                record.push(byte[0]);
                outcome.bytes_read = outcome.bytes_read.saturating_add(1);
                outcome.max_record_bytes_used = outcome
                    .max_record_bytes_used
                    .max(u64::try_from(record.len()).unwrap_or(u64::MAX));
                observer.after_content_read(outcome.bytes_read);
            }
            Ok(_) => outcome.adapter_stopped = true,
            Err(error) if error == rustix::io::Errno::INTR => interrupted = true,
            Err(_) => outcome.read_error = true,
        }
        outcome.observe_checkpoint(after_read);
        if outcome.stop_content_reads() {
            break;
        }
        if interrupted {
            continue;
        }

        if byte[0] == b'\n' {
            emit_record(
                &mut record,
                RecordState::Complete,
                record_start,
                outcome.bytes_read,
                accounting,
                sink,
                cancellation,
                clock,
                deadline,
                observer,
                &mut outcome,
            );
            if outcome.stop_content_reads() {
                break;
            }
        } else if u64::try_from(record.len()).map_or(true, |length| {
            length >= caps.per_record_bytes() && outcome.bytes_read < high_water
        }) {
            outcome.per_record_byte_cap = true;
            break;
        }
    }

    if !record.is_empty() && !outcome.sink_unavailable() {
        let complete_record = record.ends_with(b"\n")
            || (outcome.bytes_read == high_water
                && !outcome.source_byte_cap
                && !outcome.per_record_byte_cap
                && !outcome.read_error
                && !outcome.unexpected_eof);
        let state = if complete_record {
            RecordState::Complete
        } else {
            outcome.saw_fragment = true;
            RecordState::AdapterFragment {
                reason: fragment_reason(&outcome),
            }
        };
        emit_record(
            &mut record,
            state,
            record_start,
            outcome.bytes_read,
            accounting,
            sink,
            cancellation,
            clock,
            deadline,
            observer,
            &mut outcome,
        );
    }

    outcome
}

const fn fragment_reason(outcome: &StreamOutcomeV1) -> RecordFragmentReason {
    if outcome.source_byte_cap {
        RecordFragmentReason::SourceByteCap
    } else if outcome.per_record_byte_cap {
        RecordFragmentReason::PerRecordByteCap
    } else if outcome.read_error || outcome.unexpected_eof {
        RecordFragmentReason::SourceReadError
    } else if outcome.cancelled {
        RecordFragmentReason::OtherVersioned {
            version: 1,
            code: 2,
        }
    } else if outcome.wall_time_cap {
        RecordFragmentReason::OtherVersioned {
            version: 1,
            code: 3,
        }
    } else {
        RecordFragmentReason::OtherVersioned {
            version: 1,
            code: 1,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_record<M, O>(
    record: &mut Vec<u8>,
    state: RecordState,
    start: u64,
    end_exclusive: u64,
    accounting: &mut ExecutionAccountingV1,
    sink: &mut dyn EnvelopeSink,
    cancellation: &dyn Cancellation,
    clock: &M,
    deadline: &FixedExecutionDeadlineV1<M::Instant>,
    observer: &O,
    outcome: &mut StreamOutcomeV1,
) where
    M: ExecutionMonotonicClockV1,
    O: ExecutionObserverV1,
{
    let before_sink = deadline.checkpoint(clock, cancellation);
    outcome.observe_checkpoint(before_sink);
    if outcome.sink_unavailable() {
        return;
    }

    let Some(cursor) = range_cursor(start, end_exclusive) else {
        outcome.adapter_stopped = true;
        return;
    };
    let mut whole = std::mem::take(record);
    let terminator_start = if whole.ends_with(b"\r\n") {
        whole.len().saturating_sub(2)
    } else if whole.ends_with(b"\n") {
        whole.len().saturating_sub(1)
    } else {
        whole.len()
    };
    let terminator = whole.split_off(terminator_start);
    let sequence = accounting.acknowledged_records;
    let envelope = RawEnvelopeV1::new(
        accounting.envelope_identity.clone(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(sequence),
            accounting.lane.clone(),
            LaneSequence::new(sequence),
        ),
        RecordBytes::framed(whole, terminator),
        state,
    )
    .with_cursor(cursor.clone());
    let expectation = PreparedSinkAckExpectation::from_envelope(&envelope);
    let payload_bytes = u64::try_from(envelope.record().payload_len());
    let source_bytes = u64::try_from(envelope.record().source_len());
    let sink_result = sink.accept(envelope);
    let after_sink = deadline.checkpoint(clock, cancellation);

    let accepted = match (sink_result, payload_bytes, source_bytes) {
        (Ok(ack), Ok(payload_bytes), Ok(source_bytes)) if expectation.verify(&ack).is_ok() => {
            accounting
                .acknowledged_records
                .checked_add(1)
                .zip(
                    accounting
                        .acknowledged_payload_bytes
                        .checked_add(payload_bytes),
                )
                .zip(
                    accounting
                        .acknowledged_source_bytes
                        .checked_add(source_bytes),
                )
                .map(|((records, payload), source)| (records, payload, source))
        }
        (Ok(_), _, _) | (Err(_), _, _) => {
            outcome.sink_stopped = true;
            None
        }
    };
    if let Some((records, payload_bytes, source_bytes)) = accepted {
        accounting.acknowledged_records = records;
        accounting.acknowledged_payload_bytes = payload_bytes;
        accounting.acknowledged_source_bytes = source_bytes;
        if accounting.first_cursor.is_none() {
            accounting.first_cursor = Some(cursor.clone());
        }
        accounting.final_cursor = Some(cursor);
    } else if !outcome.sink_stopped {
        outcome.adapter_stopped = true;
    }
    outcome.observe_checkpoint(after_sink);
    observer.after_sink_call(accounting.acknowledged_records);
}

fn finish_execution(
    facts: &LocalFileExecutionFactsV1,
    accounting: &ExecutionAccountingV1,
    stream: StreamOutcomeV1,
    timing: FetchTiming,
) -> Result<FetchCompletion, LocalFileExecutionError> {
    let high_water_bytes = facts.snapshot.high_water_exclusive();
    let fully_acquired = stream.bytes_read == high_water_bytes
        && accounting.acknowledged_source_bytes == high_water_bytes
        && !stream.source_byte_cap
        && !stream.per_record_byte_cap
        && !stream.record_count_cap
        && !stream.cancelled
        && !stream.wall_time_cap
        && !stream.read_error
        && !stream.unexpected_eof
        && !stream.saw_fragment
        && !stream.sink_stopped
        && !stream.adapter_stopped
        && stream.post_snapshot_verified
        && !stream.wall_clock_failed;

    let high_water = stream.post_snapshot_verified.then(|| {
        HighWaterMark::new(
            facts.source_member.clone(),
            position_cursor(high_water_bytes).expect("fixed cursor domain is non-empty"),
        )
    });
    let boundaries = accounting.boundaries(high_water);
    let cap_usage = [
        CapUsage::new(
            CapKind::SourceBytes,
            stream.bytes_read,
            facts.caps.source_bytes(),
            stream.source_byte_cap,
        ),
        CapUsage::new(
            CapKind::PerRecordBytes,
            stream.max_record_bytes_used,
            facts.caps.per_record_bytes(),
            stream.per_record_byte_cap,
        ),
        CapUsage::new(
            CapKind::Records,
            accounting.acknowledged_records,
            facts.caps.records(),
            stream.record_count_cap,
        ),
        CapUsage::new(
            CapKind::WallTimeMillis,
            stream.elapsed_millis,
            facts.caps.wall_time_millis(),
            stream.wall_time_cap,
        ),
    ];

    if fully_acquired {
        return FetchCompletion::new(
            facts.fetch_identity.clone(),
            timing,
            accounting.acknowledged(),
            AttemptCounts::new(1, 1),
            AttemptCounts::default(),
            boundaries,
            cap_usage,
            AdapterOutcome::Finished,
            [],
            FetchCompleteness::complete(CompletenessProof::PlannedUnixFileSnapshotVerifiedV1),
        )
        .map_err(|_| LocalFileExecutionError::InvalidFetchCompletion);
    }

    let mut reasons = Vec::new();
    if stream.source_byte_cap {
        reasons.push(FetchPartialReason::SourceByteCap);
    }
    if stream.record_count_cap {
        reasons.push(FetchPartialReason::RecordCountCap);
    }
    if stream.wall_time_cap {
        reasons.push(FetchPartialReason::WallTimeCap);
    }
    if stream.cancelled {
        reasons.push(FetchPartialReason::Cancelled);
    }
    if stream.read_error || stream.unexpected_eof {
        reasons.push(FetchPartialReason::SourceReadError);
    }
    if !stream.post_snapshot_verified {
        reasons.push(FetchPartialReason::SourceChanged);
    }
    if stream.saw_fragment || stream.per_record_byte_cap {
        reasons.push(FetchPartialReason::RecordTruncated);
    }
    if stream.sink_stopped {
        reasons.push(FetchPartialReason::SinkFailure);
    }
    if stream.adapter_stopped || stream.wall_clock_failed {
        reasons.push(FetchPartialReason::OtherVersioned {
            version: 1,
            code: 1,
        });
    }
    if reasons.is_empty() {
        reasons.push(FetchPartialReason::SourceChanged);
    }

    let mut error_codes = Vec::new();
    if stream.sink_stopped {
        error_codes.push(FetchErrorCode::SinkFailure);
    }
    if stream.adapter_stopped || stream.wall_clock_failed {
        error_codes.push(FetchErrorCode::AdapterInvariantViolation);
    }
    if stream.read_error || stream.unexpected_eof {
        error_codes.push(FetchErrorCode::SourceReadFailure);
    }
    if !stream.post_snapshot_verified {
        error_codes.push(FetchErrorCode::SourceChanged);
    }

    let adapter_outcome = if stream.sink_stopped {
        AdapterOutcome::SinkStopped
    } else if stream.adapter_stopped || stream.wall_clock_failed {
        AdapterOutcome::AdapterStopped
    } else if stream.cancelled {
        AdapterOutcome::Cancelled
    } else if stream.wall_time_cap {
        AdapterOutcome::DeadlineExceeded
    } else if stream.read_error || stream.unexpected_eof || !stream.post_snapshot_verified {
        AdapterOutcome::SourceStopped
    } else {
        AdapterOutcome::Finished
    };

    let first = reasons[0];
    FetchCompletion::new(
        facts.fetch_identity.clone(),
        timing,
        accounting.acknowledged(),
        AttemptCounts::new(1, 0),
        AttemptCounts::default(),
        boundaries,
        cap_usage,
        adapter_outcome,
        error_codes,
        FetchCompleteness::partial(
            FetchPartialReasons::with_additional(first, reasons.iter().skip(1).copied()),
            None,
        ),
    )
    .map_err(|_| LocalFileExecutionError::InvalidFetchCompletion)
}

fn range_cursor(start: u64, end_exclusive: u64) -> Option<SourceCursor> {
    let mut bytes = b"evidentrail-file-byte-range-v1\0".to_vec();
    bytes.extend_from_slice(&start.to_le_bytes());
    bytes.extend_from_slice(&end_exclusive.to_le_bytes());
    SourceCursor::new(bytes).ok()
}

fn position_cursor(position: u64) -> Option<SourceCursor> {
    let mut bytes = b"evidentrail-file-position-v1\0".to_vec();
    bytes.extend_from_slice(&position.to_le_bytes());
    SourceCursor::new(bytes).ok()
}

/// Contentless local-file execution failures that occur before a checked
/// terminal fetch completion can be constructed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileExecutionError {
    WallClockUnavailable,
    AuthorityOutsideValidity,
    DescriptorValidationFailed,
    InvalidExecutionFacts,
    DeadlineUnavailable,
    InvalidFetchCompletion,
}

impl LocalFileExecutionError {
    const fn from_preflight(error: LocalFilePreflightError) -> Self {
        match error {
            LocalFilePreflightError::WallClockUnavailable
            | LocalFilePreflightError::WallClockRegressed => Self::WallClockUnavailable,
            LocalFilePreflightError::AuthorityOutsideValidity => Self::AuthorityOutsideValidity,
            _ => Self::DescriptorValidationFailed,
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WallClockUnavailable => "EVIDENTRAIL_LOCAL_EXECUTION_WALL_CLOCK_UNAVAILABLE",
            Self::AuthorityOutsideValidity => {
                "EVIDENTRAIL_LOCAL_EXECUTION_AUTHORITY_OUTSIDE_VALIDITY"
            }
            Self::DescriptorValidationFailed => {
                "EVIDENTRAIL_LOCAL_EXECUTION_DESCRIPTOR_VALIDATION_FAILED"
            }
            Self::InvalidExecutionFacts => "EVIDENTRAIL_LOCAL_EXECUTION_INVALID_FACTS",
            Self::DeadlineUnavailable => "EVIDENTRAIL_LOCAL_EXECUTION_DEADLINE_UNAVAILABLE",
            Self::InvalidFetchCompletion => "EVIDENTRAIL_LOCAL_EXECUTION_INVALID_FETCH_COMPLETION",
        }
    }
}

impl fmt::Debug for LocalFileExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileExecutionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFileExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFileExecutionError {}

#[cfg(all(test, target_os = "macos"))]
mod tests;
