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
use crate::{
    Cancellation, EnvelopeBatchSinkV1, EnvelopeBatchV1, ExecutionContext, FetchCompletion,
    IngestError, SourceBatchAdapterV1,
};

pub const KUBERNETES_ADAPTER_KIND_V1: &str = "kubernetes-pod-logs";
pub const KUBERNETES_ADAPTER_VERSION_V1: &str = "1";
const KUBERNETES_IDENTITY_CONFLICT_CODE_V1: u16 = 201;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KubernetesContainerInstanceKindV1 {
    Current,
    Previous,
}

impl KubernetesContainerInstanceKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

impl fmt::Debug for KubernetesContainerInstanceKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesContainerInstanceKindV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KubernetesContainerInstanceV1 {
    cluster_identity: Vec<u8>,
    namespace: Vec<u8>,
    pod_uid: Vec<u8>,
    container: Vec<u8>,
    container_id: Vec<u8>,
    restart_count: u32,
    instance: KubernetesContainerInstanceKindV1,
}

impl KubernetesContainerInstanceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cluster_identity: impl Into<Vec<u8>>,
        namespace: impl Into<Vec<u8>>,
        pod_uid: impl Into<Vec<u8>>,
        container: impl Into<Vec<u8>>,
        container_id: impl Into<Vec<u8>>,
        restart_count: u32,
        instance: KubernetesContainerInstanceKindV1,
    ) -> Result<Self, KubernetesPlanErrorV1> {
        let value = Self {
            cluster_identity: cluster_identity.into(),
            namespace: namespace.into(),
            pod_uid: pod_uid.into(),
            container: container.into(),
            container_id: container_id.into(),
            restart_count,
            instance,
        };
        if value.cluster_identity.is_empty()
            || value.namespace.is_empty()
            || value.pod_uid.is_empty()
            || value.container.is_empty()
            || value.container_id.is_empty()
        {
            return Err(KubernetesPlanErrorV1::InvalidMember);
        }
        Ok(value)
    }

    #[must_use]
    pub const fn instance(&self) -> KubernetesContainerInstanceKindV1 {
        self.instance
    }

    #[must_use]
    pub fn cluster_identity(&self) -> &[u8] {
        &self.cluster_identity
    }

    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    #[must_use]
    pub fn pod_uid(&self) -> &[u8] {
        &self.pod_uid
    }

    #[must_use]
    pub fn container(&self) -> &[u8] {
        &self.container
    }

    #[must_use]
    pub fn container_id(&self) -> &[u8] {
        &self.container_id
    }

    #[must_use]
    pub const fn restart_count(&self) -> u32 {
        self.restart_count
    }
}

impl fmt::Debug for KubernetesContainerInstanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesContainerInstanceV1")
            .field("cluster_identity_present", &true)
            .field("namespace_present", &true)
            .field("pod_uid_present", &true)
            .field("container_present", &true)
            .field("container_id_present", &true)
            .field("restart_count_present", &true)
            .field("instance", &self.instance)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KubernetesCapsV1 {
    max_records: u64,
    max_source_bytes: u64,
    max_members: u64,
    max_record_bytes: u64,
}

impl KubernetesCapsV1 {
    pub fn new(
        max_records: u64,
        max_source_bytes: u64,
        max_members: u64,
        max_record_bytes: u64,
    ) -> Result<Self, KubernetesPlanErrorV1> {
        if [max_records, max_source_bytes, max_members, max_record_bytes]
            .into_iter()
            .any(|value| value == 0 || value > JSON_SAFE_INTEGER_MAX)
            || max_record_bytes > MAX_AUTHORIZED_RECORD_BYTES as u64
            || max_record_bytes > max_source_bytes
        {
            return Err(KubernetesPlanErrorV1::InvalidCaps);
        }
        Ok(Self {
            max_records,
            max_source_bytes,
            max_members,
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
    pub const fn max_members(self) -> u64 {
        self.max_members
    }

    #[must_use]
    pub const fn max_record_bytes(self) -> u64 {
        self.max_record_bytes
    }
}

impl fmt::Debug for KubernetesCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesCapsV1")
            .field("max_records", &self.max_records)
            .field("max_source_bytes", &self.max_source_bytes)
            .field("max_members", &self.max_members)
            .field("max_record_bytes", &self.max_record_bytes)
            .finish()
    }
}

/// Frozen pod/container set. The transport may retrieve only these exact
/// current/previous instances, always with timestamps enabled and TLS
/// verification required.
#[derive(Clone, PartialEq, Eq)]
pub struct KubernetesPlanV1 {
    members: Vec<KubernetesContainerInstanceV1>,
    caps: KubernetesCapsV1,
}

impl KubernetesPlanV1 {
    pub fn new(
        members: impl IntoIterator<Item = KubernetesContainerInstanceV1>,
        caps: KubernetesCapsV1,
    ) -> Result<Self, KubernetesPlanErrorV1> {
        let members = members.into_iter().collect::<Vec<_>>();
        if members.is_empty() || members.len() as u64 > caps.max_members {
            return Err(KubernetesPlanErrorV1::InvalidMemberCount);
        }
        let mut unique = BTreeSet::new();
        if members.iter().any(|member| !unique.insert(member.clone())) {
            return Err(KubernetesPlanErrorV1::DuplicateMember);
        }
        Ok(Self { members, caps })
    }

    #[must_use]
    pub fn members(&self) -> &[KubernetesContainerInstanceV1] {
        &self.members
    }

    #[must_use]
    pub const fn caps(&self) -> KubernetesCapsV1 {
        self.caps
    }
}

impl fmt::Debug for KubernetesPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesPlanV1")
            .field("frozen_member_count", &self.members.len())
            .field("timestamps_enabled", &true)
            .field("tls_verification_required", &true)
            .field("caps", &self.caps)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KubernetesLogStreamV1 {
    Stdout,
    Stderr,
}

impl KubernetesLogStreamV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    const fn source_stream(self) -> SourceStream {
        match self {
            Self::Stdout => SourceStream::Stdout,
            Self::Stderr => SourceStream::Stderr,
        }
    }
}

impl fmt::Debug for KubernetesLogStreamV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesLogStreamV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct KubernetesLogRecordV1 {
    pub stream: KubernetesLogStreamV1,
    pub provider_timestamp: Option<Vec<u8>>,
    pub parsed_timestamp_nanos: Option<i128>,
    pub payload: Vec<u8>,
    pub terminator: Vec<u8>,
}

impl fmt::Debug for KubernetesLogRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesLogRecordV1")
            .field("stream", &self.stream)
            .field("timestamp_present", &self.provider_timestamp.is_some())
            .field("timestamp_valid", &self.parsed_timestamp_nanos.is_some())
            .field("payload_bytes", &self.payload.len())
            .field("terminator_bytes", &self.terminator.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct KubernetesLogResponseV1 {
    records: Vec<KubernetesLogRecordV1>,
    limit_bytes_was_approximate: bool,
    incomplete_final_line: bool,
    rotation_observed: bool,
    provider_truncated: bool,
}

impl KubernetesLogResponseV1 {
    #[must_use]
    pub fn new(
        records: Vec<KubernetesLogRecordV1>,
        limit_bytes_was_approximate: bool,
        incomplete_final_line: bool,
        rotation_observed: bool,
        provider_truncated: bool,
    ) -> Self {
        Self {
            records,
            limit_bytes_was_approximate,
            incomplete_final_line,
            rotation_observed,
            provider_truncated,
        }
    }
}

impl fmt::Debug for KubernetesLogResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesLogResponseV1")
            .field("record_count", &self.records.len())
            .field(
                "limit_bytes_was_approximate",
                &self.limit_bytes_was_approximate,
            )
            .field("incomplete_final_line", &self.incomplete_final_line)
            .field("rotation_observed", &self.rotation_observed)
            .field("provider_truncated", &self.provider_truncated)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KubernetesLogRequestV1 {
    timestamps: bool,
    limit_bytes: u64,
    insecure_skip_tls_verify_backend: bool,
}

impl KubernetesLogRequestV1 {
    #[must_use]
    pub const fn timestamps(self) -> bool {
        self.timestamps
    }

    #[must_use]
    pub const fn limit_bytes(self) -> u64 {
        self.limit_bytes
    }

    #[must_use]
    pub const fn insecure_skip_tls_verify_backend(self) -> bool {
        self.insecure_skip_tls_verify_backend
    }
}

impl fmt::Debug for KubernetesLogRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesLogRequestV1")
            .field("timestamps", &self.timestamps)
            .field("limit_bytes_present", &true)
            .field("insecure_skip_tls_verify_backend", &false)
            .finish()
    }
}

pub trait KubernetesTransportV1 {
    fn read_logs(
        &self,
        member: &KubernetesContainerInstanceV1,
        request: KubernetesLogRequestV1,
    ) -> Result<KubernetesLogResponseV1, KubernetesTransportErrorV1>;

    fn revalidate(
        &self,
        member: &KubernetesContainerInstanceV1,
    ) -> Result<KubernetesContainerObservationV1, KubernetesTransportErrorV1>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct KubernetesContainerObservationV1 {
    pub pod_uid: Vec<u8>,
    pub container_id: Vec<u8>,
    pub restart_count: u32,
}

impl fmt::Debug for KubernetesContainerObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesContainerObservationV1")
            .field("pod_uid_present", &!self.pod_uid.is_empty())
            .field("container_id_present", &!self.container_id.is_empty())
            .field("restart_count_present", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KubernetesTransportErrorV1 {
    PermissionDenied,
    PreviousInstanceUnavailable,
    SourceUnavailable,
    NetworkFailure,
    ProviderFailure,
    TlsVerificationBypassed,
}

impl KubernetesTransportErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => "EVIDENTRAIL_KUBERNETES_PERMISSION_DENIED",
            Self::PreviousInstanceUnavailable => "EVIDENTRAIL_KUBERNETES_PREVIOUS_UNAVAILABLE",
            Self::SourceUnavailable => "EVIDENTRAIL_KUBERNETES_SOURCE_UNAVAILABLE",
            Self::NetworkFailure => "EVIDENTRAIL_KUBERNETES_NETWORK_FAILURE",
            Self::ProviderFailure => "EVIDENTRAIL_KUBERNETES_PROVIDER_FAILURE",
            Self::TlsVerificationBypassed => "EVIDENTRAIL_KUBERNETES_TLS_BYPASS_REJECTED",
        }
    }
}

impl fmt::Debug for KubernetesTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesTransportErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KubernetesTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KubernetesTransportErrorV1 {}

pub struct KubernetesAdapterV1<T> {
    plan: KubernetesPlanV1,
    transport: T,
}

impl<T> KubernetesAdapterV1<T> {
    #[must_use]
    pub const fn new(plan: KubernetesPlanV1, transport: T) -> Self {
        Self { plan, transport }
    }
}

impl<T> fmt::Debug for KubernetesAdapterV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesAdapterV1")
            .field("plan", &self.plan)
            .field("transport_present", &true)
            .finish()
    }
}

impl<T> SourceBatchAdapterV1 for KubernetesAdapterV1<T>
where
    T: KubernetesTransportV1,
{
    fn execute_batches(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeBatchSinkV1,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError> {
        if context.fetch_identity().adapter().kind() != KUBERNETES_ADAPTER_KIND_V1
            || context.fetch_identity().adapter().version() != KUBERNETES_ADAPTER_VERSION_V1
        {
            return Err(IngestError::AdapterIdentityMismatch);
        }
        let caps = self.plan.caps;
        let timing = FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(0));
        let mut session = ExecutionSession::new(context);
        let mut pending = Vec::<PendingKubernetesRecord>::new();
        let mut seen_native = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut partial_reasons = Vec::<FetchPartialReason>::new();
        let mut errors = Vec::<FetchErrorCode>::new();
        let mut attempted_members = 0_u64;
        let mut completed_members = 0_u64;
        let mut provider_acquisition_ordinal = 0_u64;
        let mut total_pending_bytes = 0_u64;
        let mut outcome = AdapterOutcome::Finished;

        for member in &self.plan.members {
            if cancellation.is_cancelled() {
                partial_reasons.push(FetchPartialReason::Cancelled);
                outcome = AdapterOutcome::Cancelled;
                break;
            }
            if total_pending_bytes == caps.max_source_bytes {
                partial_reasons.push(FetchPartialReason::SourceByteCap);
                outcome = AdapterOutcome::ProviderStopped;
                break;
            }
            attempted_members += 1;
            let request = KubernetesLogRequestV1 {
                timestamps: true,
                limit_bytes: caps.max_source_bytes.saturating_sub(total_pending_bytes),
                insecure_skip_tls_verify_backend: false,
            };
            let response = match self.transport.read_logs(member, request) {
                Ok(response) => response,
                Err(error) => {
                    observe_kubernetes_transport_error(error, &mut partial_reasons, &mut errors);
                    outcome = AdapterOutcome::ProviderStopped;
                    continue;
                }
            };
            if response.limit_bytes_was_approximate {
                partial_reasons.push(FetchPartialReason::ProviderCap);
            }
            if response.incomplete_final_line {
                partial_reasons.push(FetchPartialReason::RecordTruncated);
            }
            if response.rotation_observed {
                partial_reasons.push(FetchPartialReason::SourceChanged);
            }
            if response.provider_truncated {
                partial_reasons.push(FetchPartialReason::ProviderTruncation);
            }

            for (response_ordinal, record) in response.records.into_iter().enumerate() {
                let observed_acquisition_ordinal = provider_acquisition_ordinal;
                provider_acquisition_ordinal = provider_acquisition_ordinal
                    .checked_add(1)
                    .ok_or(IngestError::ProviderInvariantViolation)?;
                if record.provider_timestamp.is_some() != record.parsed_timestamp_nanos.is_some() {
                    partial_reasons.push(FetchPartialReason::MalformedProviderFraming);
                    errors.push(FetchErrorCode::MalformedProviderFraming);
                }
                let source_len = record.payload.len().saturating_add(record.terminator.len());
                if source_len as u64 > caps.max_record_bytes {
                    partial_reasons.push(FetchPartialReason::RecordTruncated);
                    outcome = AdapterOutcome::ProviderStopped;
                    break;
                }
                if pending.len() as u64 >= caps.max_records {
                    partial_reasons.push(FetchPartialReason::RecordCountCap);
                    outcome = AdapterOutcome::ProviderStopped;
                    break;
                }
                if total_pending_bytes
                    .checked_add(source_len as u64)
                    .is_none_or(|value| value > caps.max_source_bytes)
                {
                    partial_reasons.push(FetchPartialReason::SourceByteCap);
                    outcome = AdapterOutcome::ProviderStopped;
                    break;
                }
                let response_ordinal = u64::try_from(response_ordinal)
                    .map_err(|_| IngestError::ProviderInvariantViolation)?;
                let native_identity = kubernetes_native_identity(member, &record, response_ordinal);
                let exact_bytes =
                    [record.payload.as_slice(), record.terminator.as_slice()].concat();
                match seen_native.get(&native_identity) {
                    Some(bytes) if bytes == &exact_bytes => continue,
                    Some(_) => {
                        partial_reasons.push(FetchPartialReason::OtherVersioned {
                            version: 1,
                            code: KUBERNETES_IDENTITY_CONFLICT_CODE_V1,
                        });
                        errors.push(FetchErrorCode::AdapterInvariantViolation);
                        outcome = AdapterOutcome::AdapterStopped;
                        break;
                    }
                    None => {
                        seen_native.insert(native_identity.clone(), exact_bytes);
                    }
                }
                total_pending_bytes += source_len as u64;
                pending.push(PendingKubernetesRecord {
                    member: member.clone(),
                    record,
                    response_ordinal,
                    native_identity,
                    provider_acquisition_ordinal: observed_acquisition_ordinal,
                });
            }

            match self.transport.revalidate(member) {
                Ok(observation)
                    if observation.pod_uid == member.pod_uid
                        && observation.container_id == member.container_id
                        && observation.restart_count == member.restart_count =>
                {
                    completed_members += 1;
                }
                Ok(_) => {
                    partial_reasons.push(FetchPartialReason::SourceChanged);
                    errors.push(FetchErrorCode::SourceChanged);
                    outcome = AdapterOutcome::SourceStopped;
                }
                Err(error) => {
                    observe_kubernetes_transport_error(error, &mut partial_reasons, &mut errors);
                    outcome = AdapterOutcome::ProviderStopped;
                }
            }
            if matches!(
                outcome,
                AdapterOutcome::AdapterStopped | AdapterOutcome::Cancelled
            ) {
                break;
            }
        }

        pending.sort_by(|left, right| {
            kubernetes_canonical_key(left).cmp(&kubernetes_canonical_key(right))
        });
        let mut lane_sequences = BTreeMap::<(SourceMember, SourceStream), u64>::new();
        let mut envelopes = Vec::with_capacity(pending.len());
        for (position, pending) in pending.iter().enumerate() {
            let acquisition_sequence =
                u64::try_from(position).map_err(|_| IngestError::ProviderInvariantViolation)?;
            let member = kubernetes_source_member(&pending.member)?;
            let stream = pending.record.stream.source_stream();
            let lane_sequence = lane_sequences
                .entry((member.clone(), stream.clone()))
                .or_default();
            envelopes.push(kubernetes_envelope(
                context,
                pending,
                member,
                stream,
                acquisition_sequence,
                *lane_sequence,
            )?);
            *lane_sequence = lane_sequence
                .checked_add(1)
                .ok_or(IngestError::ProviderInvariantViolation)?;
        }

        let mut batch_ordinal = 0_u64;
        for chunk in envelopes.chunks(crate::MAX_ENVELOPES_PER_BATCH_V1) {
            let batch = EnvelopeBatchV1::new(context, batch_ordinal, chunk.to_vec())
                .map_err(|_| IngestError::InvalidBatch)?;
            batch_ordinal = batch_ordinal
                .checked_add(1)
                .ok_or(IngestError::ProviderInvariantViolation)?;
            match session.accept_batch(sink, &batch) {
                AcceptStatus::Acknowledged => {}
                AcceptStatus::SinkStopped => {
                    partial_reasons.push(FetchPartialReason::SinkFailure);
                    errors.push(FetchErrorCode::SinkFailure);
                    outcome = AdapterOutcome::SinkStopped;
                    break;
                }
                AcceptStatus::AdapterStopped => {
                    partial_reasons.push(FetchPartialReason::OtherVersioned {
                        version: 1,
                        code: 202,
                    });
                    errors.push(FetchErrorCode::AdapterInvariantViolation);
                    outcome = AdapterOutcome::AdapterStopped;
                    break;
                }
            }
        }

        deduplicate_copy_values(&mut partial_reasons);
        deduplicate_copy_values(&mut errors);
        let completeness = if let Some(first) = partial_reasons.first().copied() {
            FetchCompleteness::partial(
                FetchPartialReasons::with_additional(
                    first,
                    partial_reasons.iter().skip(1).copied(),
                ),
                session.final_cursor(),
            )
        } else {
            FetchCompleteness::unknown(FetchUnknownReason::ProviderHasNoCompletenessProof)
        };
        let cap_usage = [
            CapUsage::new(
                CapKind::Records,
                session.acknowledged().records(),
                caps.max_records,
                partial_reasons.contains(&FetchPartialReason::RecordCountCap),
            ),
            CapUsage::new(
                CapKind::SourceBytes,
                session.acknowledged().source_bytes(),
                caps.max_source_bytes,
                partial_reasons.contains(&FetchPartialReason::SourceByteCap),
            ),
            CapUsage::new(
                CapKind::Members,
                attempted_members,
                caps.max_members,
                attempted_members == caps.max_members
                    && attempted_members < self.plan.members.len() as u64,
            ),
            CapUsage::new(
                CapKind::PerRecordBytes,
                0,
                caps.max_record_bytes,
                partial_reasons.contains(&FetchPartialReason::RecordTruncated),
            ),
        ];
        session.completion(
            timing,
            AttemptCounts::new(attempted_members, completed_members),
            AttemptCounts::default(),
            session.boundaries([]),
            cap_usage,
            outcome,
            errors,
            completeness,
        )
    }
}

struct PendingKubernetesRecord {
    member: KubernetesContainerInstanceV1,
    record: KubernetesLogRecordV1,
    response_ordinal: u64,
    native_identity: Vec<u8>,
    provider_acquisition_ordinal: u64,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct KubernetesCanonicalKey {
    timestamp_missing: bool,
    timestamp_nanos: i128,
    pod_uid: Vec<u8>,
    container: Vec<u8>,
    restart_count: u32,
    instance: KubernetesContainerInstanceKindV1,
    stream: KubernetesLogStreamV1,
    response_ordinal: u64,
    provider_acquisition_ordinal: u64,
}

fn kubernetes_canonical_key(pending: &PendingKubernetesRecord) -> KubernetesCanonicalKey {
    KubernetesCanonicalKey {
        timestamp_missing: pending.record.parsed_timestamp_nanos.is_none(),
        timestamp_nanos: pending.record.parsed_timestamp_nanos.unwrap_or_default(),
        pod_uid: pending.member.pod_uid.clone(),
        container: pending.member.container.clone(),
        restart_count: pending.member.restart_count,
        instance: pending.member.instance,
        stream: pending.record.stream,
        response_ordinal: pending.response_ordinal,
        provider_acquisition_ordinal: pending.provider_acquisition_ordinal,
    }
}

fn kubernetes_envelope(
    context: &ExecutionContext,
    pending: &PendingKubernetesRecord,
    member: SourceMember,
    stream: SourceStream,
    acquisition_sequence: u64,
    lane_sequence: u64,
) -> Result<RawEnvelopeV1, IngestError> {
    let timestamps = match &pending.record.provider_timestamp {
        Some(raw) => EnvelopeTimestamps::new(
            Some(SourceTimestamp::new(
                RawTimestamp::new(raw.clone())
                    .map_err(|_| IngestError::ProviderInvariantViolation)?,
                pending
                    .record
                    .parsed_timestamp_nanos
                    .map(UnixTimestampNanos::new),
            )),
            None,
            None,
            None,
        ),
        None => EnvelopeTimestamps::default(),
    };
    Ok(RawEnvelopeV1::new(
        context.envelope_identity(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(acquisition_sequence),
            LaneKey::new(member, stream),
            LaneSequence::new(lane_sequence),
        ),
        RecordBytes::framed(
            pending.record.payload.clone(),
            pending.record.terminator.clone(),
        ),
        RecordState::Complete,
    )
    .with_native_event_id(
        NativeEventId::new(pending.native_identity.clone())
            .map_err(|_| IngestError::ProviderInvariantViolation)?,
    )
    .with_cursor(digest_cursor(&pending.native_identity)?)
    .with_timestamps(timestamps)
    .with_metadata(NativeMetadata::new([
        NativeMetadataField::new(
            b"provider_acquisition_ordinal".to_vec(),
            NativeMetadataValue::Unsigned(pending.provider_acquisition_ordinal),
        ),
        NativeMetadataField::new(
            b"response_ordinal".to_vec(),
            NativeMetadataValue::Unsigned(pending.response_ordinal),
        ),
        NativeMetadataField::new(
            b"container_instance".to_vec(),
            NativeMetadataValue::Text(pending.member.instance.code().to_owned()),
        ),
    ]))
    .with_hints(RecordHints::new(
        Some(RecordFormatHint::PlainText),
        Some(EncodingHint::Utf8),
    )))
}

fn kubernetes_native_identity(
    member: &KubernetesContainerInstanceV1,
    record: &KubernetesLogRecordV1,
    response_ordinal: u64,
) -> Vec<u8> {
    let restart = member.restart_count.to_le_bytes();
    let ordinal = response_ordinal.to_le_bytes();
    encode_fields([
        member.cluster_identity.as_slice(),
        member.namespace.as_slice(),
        member.pod_uid.as_slice(),
        member.container.as_slice(),
        member.container_id.as_slice(),
        restart.as_slice(),
        member.instance.code().as_bytes(),
        record.stream.code().as_bytes(),
        record.provider_timestamp.as_deref().unwrap_or_default(),
        ordinal.as_slice(),
    ])
}

fn kubernetes_source_member(
    member: &KubernetesContainerInstanceV1,
) -> Result<SourceMember, IngestError> {
    let restart = member.restart_count.to_le_bytes();
    SourceMember::new(encode_fields([
        member.cluster_identity.as_slice(),
        member.namespace.as_slice(),
        member.pod_uid.as_slice(),
        member.container.as_slice(),
        member.container_id.as_slice(),
        restart.as_slice(),
        member.instance.code().as_bytes(),
    ]))
    .map_err(|_| IngestError::ProviderInvariantViolation)
}

fn observe_kubernetes_transport_error(
    error: KubernetesTransportErrorV1,
    partial_reasons: &mut Vec<FetchPartialReason>,
    errors: &mut Vec<FetchErrorCode>,
) {
    let (reason, code) = match error {
        KubernetesTransportErrorV1::PermissionDenied => (
            FetchPartialReason::PermissionLimited,
            FetchErrorCode::PermissionDenied,
        ),
        KubernetesTransportErrorV1::PreviousInstanceUnavailable
        | KubernetesTransportErrorV1::SourceUnavailable => (
            FetchPartialReason::SourceDisappeared,
            FetchErrorCode::SourceUnavailable,
        ),
        KubernetesTransportErrorV1::NetworkFailure => (
            FetchPartialReason::NetworkFailure,
            FetchErrorCode::NetworkFailure,
        ),
        KubernetesTransportErrorV1::ProviderFailure => (
            FetchPartialReason::SourceReadError,
            FetchErrorCode::ProviderFailure,
        ),
        KubernetesTransportErrorV1::TlsVerificationBypassed => (
            FetchPartialReason::PermissionLimited,
            FetchErrorCode::AdapterInvariantViolation,
        ),
    };
    partial_reasons.push(reason);
    errors.push(code);
}

fn deduplicate_copy_values<T: Copy + PartialEq>(values: &mut Vec<T>) {
    let mut unique = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    *values = unique;
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
    hasher.update(b"evidentrail/kubernetes/cursor/v1");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    SourceCursor::new(hasher.finalize().to_vec())
        .map_err(|_| IngestError::ProviderInvariantViolation)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KubernetesPlanErrorV1 {
    InvalidCaps,
    InvalidMember,
    InvalidMemberCount,
    DuplicateMember,
}

impl KubernetesPlanErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCaps => "EVIDENTRAIL_KUBERNETES_INVALID_CAPS",
            Self::InvalidMember => "EVIDENTRAIL_KUBERNETES_INVALID_MEMBER",
            Self::InvalidMemberCount => "EVIDENTRAIL_KUBERNETES_INVALID_MEMBER_COUNT",
            Self::DuplicateMember => "EVIDENTRAIL_KUBERNETES_DUPLICATE_MEMBER",
        }
    }
}

impl fmt::Debug for KubernetesPlanErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesPlanErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KubernetesPlanErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KubernetesPlanErrorV1 {}
