use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::{JSON_SAFE_INTEGER_MAX, MAX_AUTHORIZED_RECORD_BYTES};
use evidentrail_schema::{
    AcquisitionSequence, AdapterOutcome, AttemptCounts, CapKind, CapUsage, EncodingHint,
    EnvelopeOrdering, EnvelopeTimestamps, FetchCompleteness, FetchErrorCode, FetchPartialReason,
    FetchPartialReasons, FetchTiming, FetchUnknownReason, LaneKey, LaneSequence, NativeEventId,
    NativeMetadata, NativeMetadataField, NativeMetadataValue, RawEnvelopeV1, RawTimestamp,
    RecordBytes, RecordFormatHint, RecordHints, RecordState, SourceCursor, SourceMember,
    SourceStream, SourceTimestamp, UnixTimestampNanos,
};
use sha2::{Digest as _, Sha256};

use crate::adapter::{AcceptStatus, ExecutionSession};
use crate::full_history::{
    HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistoryRecordV1, HistorySyncErrorV1,
};
use crate::{
    Cancellation, EnvelopeBatchSinkV1, EnvelopeBatchV1, ExecutionContext, FetchCompletion,
    IngestError, SourceBatchAdapterV1,
};

pub const CLOUDWATCH_ADAPTER_KIND_V1: &str = "aws-cloudwatch-filter-log-events";
pub const CLOUDWATCH_ADAPTER_VERSION_V1: &str = "1";
const INTEGRITY_CONFLICT_REASON_CODE_V1: u16 = 101;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CloudWatchCapsV1 {
    max_records: u64,
    max_source_bytes: u64,
    max_pages: u64,
    max_record_bytes: u64,
}

impl CloudWatchCapsV1 {
    pub fn new(
        max_records: u64,
        max_source_bytes: u64,
        max_pages: u64,
        max_record_bytes: u64,
    ) -> Result<Self, CloudWatchPlanErrorV1> {
        if [max_records, max_source_bytes, max_pages, max_record_bytes]
            .into_iter()
            .any(|value| value == 0 || value > JSON_SAFE_INTEGER_MAX)
            || max_record_bytes > MAX_AUTHORIZED_RECORD_BYTES as u64
            || max_record_bytes > max_source_bytes
        {
            return Err(CloudWatchPlanErrorV1::InvalidCaps);
        }
        Ok(Self {
            max_records,
            max_source_bytes,
            max_pages,
            max_record_bytes,
        })
    }

    #[must_use]
    pub const fn max_records(self) -> u64 {
        self.max_records
    }

    #[must_use]
    pub const fn max_source_bytes(self) -> u64 {
        self.max_source_bytes
    }

    #[must_use]
    pub const fn max_pages(self) -> u64 {
        self.max_pages
    }

    #[must_use]
    pub const fn max_record_bytes(self) -> u64 {
        self.max_record_bytes
    }
}

impl fmt::Debug for CloudWatchCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchCapsV1")
            .field("max_records", &self.max_records)
            .field("max_source_bytes", &self.max_source_bytes)
            .field("max_pages", &self.max_pages)
            .field("max_record_bytes", &self.max_record_bytes)
            .finish()
    }
}

/// Immutable authorized query scope. Pagination tokens never enter this plan
/// and are valid only inside one execution of its exact digest-bound context.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudWatchPlanV1 {
    account: Vec<u8>,
    region: Vec<u8>,
    log_group: Vec<u8>,
    log_streams: Vec<Vec<u8>>,
    start_time_millis: Option<i64>,
    end_time_millis: Option<i64>,
    filter_pattern: Option<Vec<u8>>,
    caps: CloudWatchCapsV1,
}

impl CloudWatchPlanV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: impl Into<Vec<u8>>,
        region: impl Into<Vec<u8>>,
        log_group: impl Into<Vec<u8>>,
        log_streams: impl IntoIterator<Item = Vec<u8>>,
        start_time_millis: Option<i64>,
        end_time_millis: Option<i64>,
        filter_pattern: Option<Vec<u8>>,
        caps: CloudWatchCapsV1,
    ) -> Result<Self, CloudWatchPlanErrorV1> {
        let account = account.into();
        let region = region.into();
        let log_group = log_group.into();
        let mut log_streams = log_streams.into_iter().collect::<Vec<_>>();
        if account.is_empty()
            || region.is_empty()
            || log_group.is_empty()
            || log_streams.iter().any(Vec::is_empty)
            || start_time_millis
                .zip(end_time_millis)
                .is_some_and(|(start, end)| start >= end)
        {
            return Err(CloudWatchPlanErrorV1::InvalidScope);
        }
        log_streams.sort();
        if log_streams.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CloudWatchPlanErrorV1::DuplicateStream);
        }
        Ok(Self {
            account,
            region,
            log_group,
            log_streams,
            start_time_millis,
            end_time_millis,
            filter_pattern,
            caps,
        })
    }

    #[must_use]
    pub const fn caps(&self) -> CloudWatchCapsV1 {
        self.caps
    }

    #[must_use]
    pub fn account(&self) -> &[u8] {
        &self.account
    }

    #[must_use]
    pub fn region(&self) -> &[u8] {
        &self.region
    }

    #[must_use]
    pub fn log_group(&self) -> &[u8] {
        &self.log_group
    }

    #[must_use]
    pub fn log_streams(&self) -> &[Vec<u8>] {
        &self.log_streams
    }

    #[must_use]
    pub const fn start_time_millis(&self) -> Option<i64> {
        self.start_time_millis
    }

    #[must_use]
    pub const fn end_time_millis(&self) -> Option<i64> {
        self.end_time_millis
    }

    #[must_use]
    pub fn filter_pattern(&self) -> Option<&[u8]> {
        self.filter_pattern.as_deref()
    }
}

impl fmt::Debug for CloudWatchPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchPlanV1")
            .field("account_present", &true)
            .field("region_present", &true)
            .field("log_group_present", &true)
            .field("stream_count", &self.log_streams.len())
            .field(
                "time_bounds_present",
                &(self.start_time_millis.is_some() || self.end_time_millis.is_some()),
            )
            .field("filter_pattern_present", &self.filter_pattern.is_some())
            .field("caps", &self.caps)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CloudWatchFilterRequestV1 {
    plan: CloudWatchPlanV1,
    next_token: Option<Vec<u8>>,
}

impl CloudWatchFilterRequestV1 {
    #[must_use]
    pub const fn plan(&self) -> &CloudWatchPlanV1 {
        &self.plan
    }

    #[must_use]
    pub fn next_token(&self) -> Option<&[u8]> {
        self.next_token.as_deref()
    }
}

impl fmt::Debug for CloudWatchFilterRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchFilterRequestV1")
            .field("plan", &self.plan)
            .field("next_token_present", &self.next_token.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CloudWatchEventV1 {
    pub log_stream: Vec<u8>,
    pub event_id: Vec<u8>,
    pub event_timestamp_millis: i64,
    pub ingestion_timestamp_millis: i64,
    pub message: Vec<u8>,
}

impl fmt::Debug for CloudWatchEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchEventV1")
            .field("log_stream_present", &!self.log_stream.is_empty())
            .field("event_id_present", &!self.event_id.is_empty())
            .field("message_bytes", &self.message.len())
            .field("timestamps_present", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CloudWatchPageV1 {
    events: Vec<CloudWatchEventV1>,
    next_token: Option<Vec<u8>>,
}

impl CloudWatchPageV1 {
    #[must_use]
    pub fn new(events: Vec<CloudWatchEventV1>, next_token: Option<Vec<u8>>) -> Self {
        Self { events, next_token }
    }
}

impl fmt::Debug for CloudWatchPageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchPageV1")
            .field("event_count", &self.events.len())
            .field("next_token_present", &self.next_token.is_some())
            .finish()
    }
}

pub trait CloudWatchTransportV1 {
    fn filter_log_events(
        &self,
        request: &CloudWatchFilterRequestV1,
    ) -> Result<CloudWatchPageV1, CloudWatchTransportErrorV1>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CloudWatchTransportErrorV1 {
    PermissionDenied,
    AuthenticationChanged,
    TokenExpired,
    ThrottlingExhausted,
    NetworkFailure,
    ProviderFailure,
}

impl CloudWatchTransportErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => "EVIDENTRAIL_CLOUDWATCH_PERMISSION_DENIED",
            Self::AuthenticationChanged => "EVIDENTRAIL_CLOUDWATCH_AUTHENTICATION_CHANGED",
            Self::TokenExpired => "EVIDENTRAIL_CLOUDWATCH_TOKEN_EXPIRED",
            Self::ThrottlingExhausted => "EVIDENTRAIL_CLOUDWATCH_THROTTLING_EXHAUSTED",
            Self::NetworkFailure => "EVIDENTRAIL_CLOUDWATCH_NETWORK_FAILURE",
            Self::ProviderFailure => "EVIDENTRAIL_CLOUDWATCH_PROVIDER_FAILURE",
        }
    }
}

impl fmt::Debug for CloudWatchTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchTransportErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CloudWatchTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CloudWatchTransportErrorV1 {}

/// Adapts a complete log-group binding to the provider-neutral history sync.
/// Internal partitions are chosen by the synchronizer; no caller task window,
/// stream subset, or filter pattern can narrow this source.
pub struct CloudWatchHistorySourceV1<T> {
    binding: CloudWatchPlanV1,
    transport: T,
}

impl<T> CloudWatchHistorySourceV1<T> {
    pub fn new(binding: CloudWatchPlanV1, transport: T) -> Result<Self, CloudWatchPlanErrorV1> {
        if !binding.log_streams.is_empty()
            || binding.filter_pattern.is_some()
            || binding.start_time_millis.is_some()
            || binding.end_time_millis.is_some()
        {
            return Err(CloudWatchPlanErrorV1::InvalidScope);
        }
        Ok(Self { binding, transport })
    }
}

impl<T: CloudWatchTransportV1> HistoryPageSourceV1 for CloudWatchHistorySourceV1<T> {
    fn fetch_page(
        &mut self,
        partition: HistoryPartitionV1,
        next_token: Option<&[u8]>,
    ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
        let plan = CloudWatchPlanV1::new(
            self.binding.account.clone(),
            self.binding.region.clone(),
            self.binding.log_group.clone(),
            [],
            Some(partition.start_millis),
            Some(partition.end_millis),
            None,
            self.binding.caps,
        )
        .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        let request = CloudWatchFilterRequestV1 {
            plan,
            next_token: next_token.map(<[u8]>::to_vec),
        };
        let page = self
            .transport
            .filter_log_events(&request)
            .map_err(|error| match error {
                CloudWatchTransportErrorV1::PermissionDenied => {
                    HistorySyncErrorV1::PermissionDenied
                }
                CloudWatchTransportErrorV1::AuthenticationChanged => {
                    HistorySyncErrorV1::AuthenticationChanged
                }
                CloudWatchTransportErrorV1::TokenExpired => HistorySyncErrorV1::TokenExpired,
                CloudWatchTransportErrorV1::ThrottlingExhausted => HistorySyncErrorV1::Throttled,
                CloudWatchTransportErrorV1::NetworkFailure => HistorySyncErrorV1::Network,
                CloudWatchTransportErrorV1::ProviderFailure => HistorySyncErrorV1::Provider,
            })?;
        Ok(HistoryPageV1 {
            records: page
                .events
                .into_iter()
                .map(|event| HistoryRecordV1 {
                    native_id: cloudwatch_native_identity(&request.plan, &event),
                    event_timestamp_millis: event.event_timestamp_millis,
                    bytes: event.message,
                })
                .collect(),
            next_token: page.next_token,
        })
    }
}

pub struct CloudWatchAdapterV1<T> {
    plan: CloudWatchPlanV1,
    transport: T,
}

impl<T> CloudWatchAdapterV1<T> {
    #[must_use]
    pub const fn new(plan: CloudWatchPlanV1, transport: T) -> Self {
        Self { plan, transport }
    }
}

impl<T> fmt::Debug for CloudWatchAdapterV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchAdapterV1")
            .field("plan", &self.plan)
            .field("transport_present", &true)
            .finish()
    }
}

impl<T> SourceBatchAdapterV1 for CloudWatchAdapterV1<T>
where
    T: CloudWatchTransportV1,
{
    fn execute_batches(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeBatchSinkV1,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError> {
        if context.fetch_identity().adapter().kind() != CLOUDWATCH_ADAPTER_KIND_V1
            || context.fetch_identity().adapter().version() != CLOUDWATCH_ADAPTER_VERSION_V1
        {
            return Err(IngestError::AdapterIdentityMismatch);
        }

        let timing = FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(0));
        let caps = self.plan.caps;
        let mut session = ExecutionSession::new(context);
        let mut pages_attempted = 0_u64;
        let mut pages_completed = 0_u64;
        let mut batch_ordinal = 0_u64;
        let mut acquisition_sequence = 0_u64;
        let mut provider_acquisition_ordinal = 0_u64;
        let mut lane_sequences = BTreeMap::<SourceMember, u64>::new();
        let mut seen_native = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut seen_tokens = BTreeSet::<Vec<u8>>::new();
        let mut next_token = None::<Vec<u8>>;
        let mut prior_canonical_key = None::<CloudWatchCanonicalKey>;
        let mut termination = None::<CloudWatchTermination>;

        loop {
            if cancellation.is_cancelled() {
                termination = Some(CloudWatchTermination::Cancelled);
                break;
            }
            if pages_attempted == caps.max_pages {
                termination = Some(CloudWatchTermination::PageCap);
                break;
            }
            pages_attempted += 1;
            let request = CloudWatchFilterRequestV1 {
                plan: self.plan.clone(),
                next_token: next_token.clone(),
            };
            let page = match self.transport.filter_log_events(&request) {
                Ok(page) => page,
                Err(error) => {
                    termination = Some(CloudWatchTermination::Transport(error));
                    break;
                }
            };
            pages_completed += 1;

            let mut page_records = Vec::<PendingCloudWatchRecord>::new();
            for event in page.events {
                let observed_acquisition_ordinal = provider_acquisition_ordinal;
                provider_acquisition_ordinal = provider_acquisition_ordinal
                    .checked_add(1)
                    .ok_or(IngestError::ProviderInvariantViolation)?;
                if event.log_stream.is_empty() || event.event_id.is_empty() {
                    termination = Some(CloudWatchTermination::IntegrityConflict);
                    break;
                }
                let native_identity = cloudwatch_native_identity(&self.plan, &event);
                match seen_native.get(&native_identity) {
                    Some(bytes) if bytes == &event.message => continue,
                    Some(_) => {
                        termination = Some(CloudWatchTermination::IntegrityConflict);
                        break;
                    }
                    None => {
                        seen_native.insert(native_identity.clone(), event.message.clone());
                    }
                }
                if event.message.len() as u64 > caps.max_record_bytes {
                    termination = Some(CloudWatchTermination::PerRecordCap);
                    break;
                }
                if session
                    .acknowledged()
                    .records()
                    .checked_add(page_records.len() as u64)
                    .is_none_or(|value| value >= caps.max_records)
                {
                    termination = Some(CloudWatchTermination::RecordCap);
                    break;
                }
                let Some(next_source_bytes) = session
                    .acknowledged()
                    .source_bytes()
                    .checked_add(event.message.len() as u64)
                else {
                    termination = Some(CloudWatchTermination::SourceByteCap);
                    break;
                };
                let pending_page_bytes = page_records
                    .iter()
                    .map(|record| record.event.message.len() as u64)
                    .sum::<u64>();
                if next_source_bytes
                    .checked_add(pending_page_bytes)
                    .is_none_or(|value| value > caps.max_source_bytes)
                {
                    termination = Some(CloudWatchTermination::SourceByteCap);
                    break;
                }
                let canonical_key = CloudWatchCanonicalKey::new(&self.plan, &event);
                page_records.push(PendingCloudWatchRecord {
                    event,
                    native_identity,
                    provider_acquisition_ordinal: observed_acquisition_ordinal,
                    canonical_key,
                });
            }

            page_records.sort_by(|left, right| left.canonical_key.cmp(&right.canonical_key));
            if page_records.first().is_some_and(|first| {
                prior_canonical_key
                    .as_ref()
                    .is_some_and(|prior| first.canonical_key < *prior)
            }) {
                termination = Some(CloudWatchTermination::IntegrityConflict);
                page_records.clear();
            }

            let mut envelopes = Vec::with_capacity(page_records.len());
            for pending in page_records {
                let member = cloudwatch_source_member(&self.plan, &pending.event)?;
                let lane_sequence = lane_sequences.entry(member.clone()).or_default();
                let envelope = cloudwatch_envelope(
                    context,
                    &pending,
                    member,
                    acquisition_sequence,
                    *lane_sequence,
                )?;
                acquisition_sequence = acquisition_sequence
                    .checked_add(1)
                    .ok_or(IngestError::ProviderInvariantViolation)?;
                *lane_sequence = lane_sequence
                    .checked_add(1)
                    .ok_or(IngestError::ProviderInvariantViolation)?;
                prior_canonical_key = Some(pending.canonical_key);
                envelopes.push(envelope);
            }

            for chunk in envelopes.chunks(crate::MAX_ENVELOPES_PER_BATCH_V1) {
                let batch = EnvelopeBatchV1::new(context, batch_ordinal, chunk.to_vec())
                    .map_err(|_| IngestError::InvalidBatch)?;
                batch_ordinal = batch_ordinal
                    .checked_add(1)
                    .ok_or(IngestError::ProviderInvariantViolation)?;
                match session.accept_batch(sink, &batch) {
                    AcceptStatus::Acknowledged => {}
                    AcceptStatus::SinkStopped => {
                        termination = Some(CloudWatchTermination::SinkStopped);
                        break;
                    }
                    AcceptStatus::AdapterStopped => {
                        termination = Some(CloudWatchTermination::AdapterStopped);
                        break;
                    }
                }
            }
            if termination.is_some() {
                break;
            }

            match page.next_token {
                None => break,
                Some(token) if token.is_empty() || !seen_tokens.insert(token.clone()) => {
                    termination = Some(CloudWatchTermination::PaginationIncomplete);
                    break;
                }
                Some(token) => next_token = Some(token),
            }
        }

        let member_count = u64::try_from(lane_sequences.len())
            .unwrap_or(u64::MAX)
            .max(1);
        let cap_usage = [
            CapUsage::new(
                CapKind::Records,
                session.acknowledged().records(),
                caps.max_records,
                matches!(termination, Some(CloudWatchTermination::RecordCap)),
            ),
            CapUsage::new(
                CapKind::SourceBytes,
                session.acknowledged().source_bytes(),
                caps.max_source_bytes,
                matches!(termination, Some(CloudWatchTermination::SourceByteCap)),
            ),
            CapUsage::new(
                CapKind::Pages,
                pages_attempted,
                caps.max_pages,
                matches!(termination, Some(CloudWatchTermination::PageCap)),
            ),
            CapUsage::new(
                CapKind::PerRecordBytes,
                0,
                caps.max_record_bytes,
                matches!(termination, Some(CloudWatchTermination::PerRecordCap)),
            ),
        ];
        let continuation = next_token.as_deref().map(digest_cursor).transpose()?;
        let (outcome, errors, completeness) = cloudwatch_terminal(termination, continuation);
        session.completion(
            timing,
            AttemptCounts::new(
                member_count,
                u64::from(outcome == AdapterOutcome::Finished) * member_count,
            ),
            AttemptCounts::new(pages_attempted, pages_completed),
            session.boundaries([]),
            cap_usage,
            outcome,
            errors,
            completeness,
        )
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct CloudWatchCanonicalKey {
    event_timestamp_millis: i64,
    ingestion_timestamp_millis: i64,
    account: Vec<u8>,
    region: Vec<u8>,
    log_group: Vec<u8>,
    log_stream: Vec<u8>,
    event_id: Vec<u8>,
}

impl CloudWatchCanonicalKey {
    fn new(plan: &CloudWatchPlanV1, event: &CloudWatchEventV1) -> Self {
        Self {
            event_timestamp_millis: event.event_timestamp_millis,
            ingestion_timestamp_millis: event.ingestion_timestamp_millis,
            account: plan.account.clone(),
            region: plan.region.clone(),
            log_group: plan.log_group.clone(),
            log_stream: event.log_stream.clone(),
            event_id: event.event_id.clone(),
        }
    }
}

struct PendingCloudWatchRecord {
    event: CloudWatchEventV1,
    native_identity: Vec<u8>,
    provider_acquisition_ordinal: u64,
    canonical_key: CloudWatchCanonicalKey,
}

#[derive(Clone, Copy)]
enum CloudWatchTermination {
    Cancelled,
    RecordCap,
    PerRecordCap,
    SourceByteCap,
    PageCap,
    PaginationIncomplete,
    IntegrityConflict,
    SinkStopped,
    AdapterStopped,
    Transport(CloudWatchTransportErrorV1),
}

fn cloudwatch_terminal(
    termination: Option<CloudWatchTermination>,
    continuation: Option<SourceCursor>,
) -> (AdapterOutcome, Vec<FetchErrorCode>, FetchCompleteness) {
    let Some(termination) = termination else {
        return (
            AdapterOutcome::Finished,
            Vec::new(),
            FetchCompleteness::unknown(FetchUnknownReason::EventuallyConsistentWindow),
        );
    };
    let (outcome, error, reason) = match termination {
        CloudWatchTermination::Cancelled => (
            AdapterOutcome::Cancelled,
            None,
            FetchPartialReason::Cancelled,
        ),
        CloudWatchTermination::RecordCap => (
            AdapterOutcome::ProviderStopped,
            None,
            FetchPartialReason::RecordCountCap,
        ),
        CloudWatchTermination::PerRecordCap => (
            AdapterOutcome::ProviderStopped,
            None,
            FetchPartialReason::RecordTruncated,
        ),
        CloudWatchTermination::SourceByteCap => (
            AdapterOutcome::ProviderStopped,
            None,
            FetchPartialReason::SourceByteCap,
        ),
        CloudWatchTermination::PageCap => (
            AdapterOutcome::ProviderStopped,
            None,
            FetchPartialReason::PageCap,
        ),
        CloudWatchTermination::PaginationIncomplete => (
            AdapterOutcome::ProviderStopped,
            Some(FetchErrorCode::ProviderFailure),
            FetchPartialReason::PaginationIncomplete,
        ),
        CloudWatchTermination::IntegrityConflict => (
            AdapterOutcome::AdapterStopped,
            Some(FetchErrorCode::AdapterInvariantViolation),
            FetchPartialReason::OtherVersioned {
                version: 1,
                code: INTEGRITY_CONFLICT_REASON_CODE_V1,
            },
        ),
        CloudWatchTermination::SinkStopped => (
            AdapterOutcome::SinkStopped,
            Some(FetchErrorCode::SinkFailure),
            FetchPartialReason::SinkFailure,
        ),
        CloudWatchTermination::AdapterStopped => (
            AdapterOutcome::AdapterStopped,
            Some(FetchErrorCode::AdapterInvariantViolation),
            FetchPartialReason::OtherVersioned {
                version: 1,
                code: 102,
            },
        ),
        CloudWatchTermination::Transport(error) => match error {
            CloudWatchTransportErrorV1::PermissionDenied => (
                AdapterOutcome::ProviderStopped,
                Some(FetchErrorCode::PermissionDenied),
                FetchPartialReason::PermissionLimited,
            ),
            CloudWatchTransportErrorV1::AuthenticationChanged => (
                AdapterOutcome::ProviderStopped,
                Some(FetchErrorCode::AuthenticationChanged),
                FetchPartialReason::AuthenticationChanged,
            ),
            CloudWatchTransportErrorV1::TokenExpired
            | CloudWatchTransportErrorV1::ThrottlingExhausted => (
                AdapterOutcome::ProviderStopped,
                Some(FetchErrorCode::ProviderFailure),
                FetchPartialReason::PaginationIncomplete,
            ),
            CloudWatchTransportErrorV1::NetworkFailure => (
                AdapterOutcome::ProviderStopped,
                Some(FetchErrorCode::NetworkFailure),
                FetchPartialReason::NetworkFailure,
            ),
            CloudWatchTransportErrorV1::ProviderFailure => (
                AdapterOutcome::ProviderStopped,
                Some(FetchErrorCode::ProviderFailure),
                FetchPartialReason::PaginationIncomplete,
            ),
        },
    };
    (
        outcome,
        error.into_iter().collect(),
        FetchCompleteness::partial(FetchPartialReasons::new(reason), continuation),
    )
}

fn cloudwatch_envelope(
    context: &ExecutionContext,
    pending: &PendingCloudWatchRecord,
    member: SourceMember,
    acquisition_sequence: u64,
    lane_sequence: u64,
) -> Result<RawEnvelopeV1, IngestError> {
    let timestamp_nanos = i128::from(pending.event.event_timestamp_millis)
        .checked_mul(1_000_000)
        .ok_or(IngestError::ProviderInvariantViolation)?;
    let raw_timestamp = pending
        .event
        .event_timestamp_millis
        .to_string()
        .into_bytes();
    let envelope = RawEnvelopeV1::new(
        context.envelope_identity(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(acquisition_sequence),
            LaneKey::new(member, SourceStream::LogStream),
            LaneSequence::new(lane_sequence),
        ),
        RecordBytes::whole(pending.event.message.clone()),
        RecordState::Complete,
    )
    .with_native_event_id(
        NativeEventId::new(pending.native_identity.clone())
            .map_err(|_| IngestError::ProviderInvariantViolation)?,
    )
    .with_cursor(digest_cursor(&pending.native_identity)?)
    .with_timestamps(EnvelopeTimestamps::new(
        Some(SourceTimestamp::new(
            RawTimestamp::new(raw_timestamp)
                .map_err(|_| IngestError::ProviderInvariantViolation)?,
            Some(UnixTimestampNanos::new(timestamp_nanos)),
        )),
        None,
        None,
        None,
    ))
    .with_metadata(NativeMetadata::new([
        NativeMetadataField::new(
            b"provider_acquisition_ordinal".to_vec(),
            NativeMetadataValue::Unsigned(pending.provider_acquisition_ordinal),
        ),
        NativeMetadataField::new(
            b"ingestion_timestamp_millis".to_vec(),
            NativeMetadataValue::Signed(pending.event.ingestion_timestamp_millis),
        ),
    ]))
    .with_hints(RecordHints::new(
        Some(RecordFormatHint::PlainText),
        Some(EncodingHint::Utf8),
    ));
    Ok(envelope)
}

fn cloudwatch_native_identity(plan: &CloudWatchPlanV1, event: &CloudWatchEventV1) -> Vec<u8> {
    encode_fields([
        plan.account.as_slice(),
        plan.region.as_slice(),
        plan.log_group.as_slice(),
        event.log_stream.as_slice(),
        event.event_id.as_slice(),
    ])
}

fn cloudwatch_source_member(
    plan: &CloudWatchPlanV1,
    event: &CloudWatchEventV1,
) -> Result<SourceMember, IngestError> {
    SourceMember::new(encode_fields([
        plan.account.as_slice(),
        plan.region.as_slice(),
        plan.log_group.as_slice(),
        event.log_stream.as_slice(),
    ]))
    .map_err(|_| IngestError::ProviderInvariantViolation)
}

fn encode_fields<const N: usize>(fields: [&[u8]; N]) -> Vec<u8> {
    let capacity = fields.iter().map(|field| field.len() + 8).sum();
    let mut encoded = Vec::with_capacity(capacity);
    for field in fields {
        encoded.extend_from_slice(&(field.len() as u64).to_le_bytes());
        encoded.extend_from_slice(field);
    }
    encoded
}

fn digest_cursor(bytes: &[u8]) -> Result<SourceCursor, IngestError> {
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/cloudwatch/cursor/v1");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    SourceCursor::new(hasher.finalize().to_vec())
        .map_err(|_| IngestError::ProviderInvariantViolation)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CloudWatchPlanErrorV1 {
    InvalidCaps,
    InvalidScope,
    DuplicateStream,
}

impl CloudWatchPlanErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCaps => "EVIDENTRAIL_CLOUDWATCH_INVALID_CAPS",
            Self::InvalidScope => "EVIDENTRAIL_CLOUDWATCH_INVALID_SCOPE",
            Self::DuplicateStream => "EVIDENTRAIL_CLOUDWATCH_DUPLICATE_STREAM",
        }
    }
}

impl fmt::Debug for CloudWatchPlanErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudWatchPlanErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CloudWatchPlanErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CloudWatchPlanErrorV1 {}
