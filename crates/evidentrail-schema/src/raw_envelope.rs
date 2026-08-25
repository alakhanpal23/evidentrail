use std::error::Error as StdError;
use std::fmt;

use crate::ProviderAttestationsV1;
use crate::{
    AcquisitionOutcome, PlanDigest, PlanId, RetrievalId, SourceIdentityDigest, SourceRecordId,
};

/// Structural construction failures for pre-policy acquisition vocabulary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeConstructionError {
    EmptyAdapterKind,
    EmptyAdapterVersion,
    EmptySourceMember,
    EmptyNativeEventId,
    EmptySourceCursor,
    EmptyRawTimestamp,
}

impl EnvelopeConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyAdapterKind => "EVIDENTRAIL_SCHEMA_EMPTY_ADAPTER_KIND",
            Self::EmptyAdapterVersion => "EVIDENTRAIL_SCHEMA_EMPTY_ADAPTER_VERSION",
            Self::EmptySourceMember => "EVIDENTRAIL_SCHEMA_EMPTY_SOURCE_MEMBER",
            Self::EmptyNativeEventId => "EVIDENTRAIL_SCHEMA_EMPTY_NATIVE_EVENT_ID",
            Self::EmptySourceCursor => "EVIDENTRAIL_SCHEMA_EMPTY_SOURCE_CURSOR",
            Self::EmptyRawTimestamp => "EVIDENTRAIL_SCHEMA_EMPTY_RAW_TIMESTAMP",
        }
    }
}

impl fmt::Debug for EnvelopeConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EnvelopeConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EnvelopeConstructionError {}

/// Product-controlled adapter family and implementation version.
#[derive(Clone, PartialEq, Eq)]
pub struct AdapterIdentity {
    kind: String,
    version: String,
}

impl AdapterIdentity {
    pub fn new(
        kind: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, EnvelopeConstructionError> {
        let kind = kind.into();
        let version = version.into();
        if kind.is_empty() {
            return Err(EnvelopeConstructionError::EmptyAdapterKind);
        }
        if version.is_empty() {
            return Err(EnvelopeConstructionError::EmptyAdapterVersion);
        }
        Ok(Self { kind, version })
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Debug for AdapterIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterIdentity")
            .field("kind_present", &true)
            .field("version_present", &true)
            .finish()
    }
}

macro_rules! opaque_bytes_type {
    ($doc:literal, $name:ident, $empty_error:ident) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, EnvelopeConstructionError> {
                let bytes = bytes.into();
                if bytes.is_empty() {
                    return Err(EnvelopeConstructionError::$empty_error);
                }
                Ok(Self(bytes))
            }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("present", &true)
                    .finish()
            }
        }
    };
}

opaque_bytes_type!(
    "Exact, potentially sensitive identity of one member inside a source.",
    SourceMember,
    EmptySourceMember
);
opaque_bytes_type!(
    "Provider-native event identity. It is never conflated with a cursor.",
    NativeEventId,
    EmptyNativeEventId
);
opaque_bytes_type!(
    "Opaque adapter-defined cursor or continuation position.",
    SourceCursor,
    EmptySourceCursor
);
opaque_bytes_type!(
    "Exact provider timestamp spelling before any parsing.",
    RawTimestamp,
    EmptyRawTimestamp
);

/// Monotonic order across every acknowledged envelope in one retrieval.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AcquisitionSequence(u64);

impl AcquisitionSequence {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for AcquisitionSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AcquisitionSequence")
            .field(&self.0)
            .finish()
    }
}

/// Contiguous order within one `(source member, stream)` lane.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneSequence(u64);

impl LaneSequence {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for LaneSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LaneSequence")
            .field(&self.0)
            .finish()
    }
}

/// Typed source-native stream category used as part of the lane key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceStream {
    Stdout,
    Stderr,
    Container,
    Journal,
    LogStream,
    FileMember,
    OtherVersioned { version: u16, code: u16 },
}

impl SourceStream {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Container => "container",
            Self::Journal => "journal",
            Self::LogStream => "log_stream",
            Self::FileMember => "file_member",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for SourceStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceStream")
            .field("code", &self.code())
            .finish()
    }
}

/// Identity of a source-order lane.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneKey {
    member: SourceMember,
    stream: SourceStream,
}

impl LaneKey {
    #[must_use]
    pub const fn new(member: SourceMember, stream: SourceStream) -> Self {
        Self { member, stream }
    }

    #[must_use]
    pub const fn member(&self) -> &SourceMember {
        &self.member
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }
}

impl fmt::Debug for LaneKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaneKey")
            .field("member_present", &true)
            .field("stream_code", &self.stream.code())
            .finish()
    }
}

/// Exact bytes of one source-defined record.
///
/// `Framed` retains the source payload and source-defined terminator as
/// separate byte strings. `Whole` represents a provider-native record with no
/// independently defined terminator. Neither representation requires UTF-8.
#[derive(Clone, PartialEq, Eq)]
pub enum RecordBytes {
    Framed {
        payload: Vec<u8>,
        terminator: Vec<u8>,
    },
    Whole {
        payload: Vec<u8>,
    },
}

impl RecordBytes {
    #[must_use]
    pub fn framed(payload: impl Into<Vec<u8>>, terminator: impl Into<Vec<u8>>) -> Self {
        Self::Framed {
            payload: payload.into(),
            terminator: terminator.into(),
        }
    }

    #[must_use]
    pub fn whole(payload: impl Into<Vec<u8>>) -> Self {
        Self::Whole {
            payload: payload.into(),
        }
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Framed { payload, .. } | Self::Whole { payload } => payload,
        }
    }

    #[must_use]
    pub fn terminator(&self) -> Option<&[u8]> {
        match self {
            Self::Framed { terminator, .. } => Some(terminator),
            Self::Whole { .. } => None,
        }
    }

    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload().len()
    }

    #[must_use]
    pub fn source_len(&self) -> usize {
        self.payload_len()
            .saturating_add(self.terminator().map_or(0, <[u8]>::len))
    }

    pub fn append_exact_to(&self, destination: &mut Vec<u8>) {
        destination.extend_from_slice(self.payload());
        if let Some(terminator) = self.terminator() {
            destination.extend_from_slice(terminator);
        }
    }

    #[must_use]
    pub fn exact_bytes(&self) -> Vec<u8> {
        let mut exact = Vec::with_capacity(self.source_len());
        self.append_exact_to(&mut exact);
        exact
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Framed { .. } => "framed",
            Self::Whole { .. } => "whole",
        }
    }
}

impl fmt::Debug for RecordBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordBytes")
            .field("kind", &self.kind())
            .field("payload_bytes", &self.payload_len())
            .field(
                "terminator_bytes",
                &self.terminator().map_or(0, <[u8]>::len),
            )
            .finish()
    }
}

/// Typed reason that a received envelope is not a complete source record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordFragmentReason {
    ProviderTruncation,
    SourceByteCap,
    PerRecordByteCap,
    SourceReadError,
    MalformedProviderFraming,
    OtherVersioned { version: u16, code: u16 },
}

impl RecordFragmentReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderTruncation => "provider_truncation",
            Self::SourceByteCap => "source_byte_cap",
            Self::PerRecordByteCap => "per_record_byte_cap",
            Self::SourceReadError => "source_read_error",
            Self::MalformedProviderFraming => "malformed_provider_framing",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for RecordFragmentReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordFragmentReason")
            .field("code", &self.code())
            .finish()
    }
}

/// Whether the bytes represent a complete record or a declared fragment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Complete,
    SourceTruncated { reason: RecordFragmentReason },
    AdapterFragment { reason: RecordFragmentReason },
}

impl RecordState {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::SourceTruncated { .. } => "source_truncated",
            Self::AdapterFragment { .. } => "adapter_fragment",
        }
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

impl fmt::Debug for RecordState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("RecordState");
        summary.field("code", &self.code());
        match self {
            Self::SourceTruncated { reason } | Self::AdapterFragment { reason } => {
                summary.field("reason_code", &reason.code());
            }
            Self::Complete => {}
        }
        summary.finish()
    }
}

/// Parsed wall-clock instant as Unix-epoch nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTimestampNanos(i128);

impl UnixTimestampNanos {
    #[must_use]
    pub const fn new(value: i128) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> i128 {
        self.0
    }
}

impl fmt::Debug for UnixTimestampNanos {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnixTimestampNanos(<redacted>)")
    }
}

/// Process-local monotonic timestamp. It is meaningful only within its run.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTimestampNanos(u64);

impl MonotonicTimestampNanos {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for MonotonicTimestampNanos {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonotonicTimestampNanos(<redacted>)")
    }
}

/// Provider timestamp with the exact source spelling kept beside its parse.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceTimestamp {
    raw: RawTimestamp,
    parsed: Option<UnixTimestampNanos>,
}

impl SourceTimestamp {
    #[must_use]
    pub const fn new(raw: RawTimestamp, parsed: Option<UnixTimestampNanos>) -> Self {
        Self { raw, parsed }
    }

    #[must_use]
    pub const fn raw(&self) -> &RawTimestamp {
        &self.raw
    }

    #[must_use]
    pub const fn parsed(&self) -> Option<UnixTimestampNanos> {
        self.parsed
    }
}

impl fmt::Debug for SourceTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceTimestamp")
            .field("raw_present", &true)
            .field("parsed_present", &self.parsed.is_some())
            .finish()
    }
}

/// Optional, explicitly typed timestamp facts attached to an envelope.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EnvelopeTimestamps {
    source: Option<SourceTimestamp>,
    provider_observed_at: Option<UnixTimestampNanos>,
    adapter_emitted_at: Option<UnixTimestampNanos>,
    adapter_monotonic_time: Option<MonotonicTimestampNanos>,
}

impl EnvelopeTimestamps {
    #[must_use]
    pub const fn new(
        source: Option<SourceTimestamp>,
        provider_observed_at: Option<UnixTimestampNanos>,
        adapter_emitted_at: Option<UnixTimestampNanos>,
        adapter_monotonic_time: Option<MonotonicTimestampNanos>,
    ) -> Self {
        Self {
            source,
            provider_observed_at,
            adapter_emitted_at,
            adapter_monotonic_time,
        }
    }

    #[must_use]
    pub const fn source(&self) -> Option<&SourceTimestamp> {
        self.source.as_ref()
    }

    #[must_use]
    pub const fn provider_observed_at(&self) -> Option<UnixTimestampNanos> {
        self.provider_observed_at
    }

    #[must_use]
    pub const fn adapter_emitted_at(&self) -> Option<UnixTimestampNanos> {
        self.adapter_emitted_at
    }

    #[must_use]
    pub const fn adapter_monotonic_time(&self) -> Option<MonotonicTimestampNanos> {
        self.adapter_monotonic_time
    }
}

impl fmt::Debug for EnvelopeTimestamps {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeTimestamps")
            .field("source_present", &self.source.is_some())
            .field(
                "provider_observed_at_present",
                &self.provider_observed_at.is_some(),
            )
            .field(
                "adapter_emitted_at_present",
                &self.adapter_emitted_at.is_some(),
            )
            .field(
                "adapter_monotonic_time_present",
                &self.adapter_monotonic_time.is_some(),
            )
            .finish()
    }
}

/// Lossless typed value for provider-native metadata.
#[derive(Clone, PartialEq, Eq)]
pub enum NativeMetadataValue {
    Null,
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    FloatBits(u64),
    Text(String),
    Bytes(Vec<u8>),
    Sequence(Vec<NativeMetadataValue>),
    Map(Vec<NativeMetadataField>),
}

impl NativeMetadataValue {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean(_) => "boolean",
            Self::Signed(_) => "signed",
            Self::Unsigned(_) => "unsigned",
            Self::FloatBits(_) => "float_bits",
            Self::Text(_) => "text",
            Self::Bytes(_) => "bytes",
            Self::Sequence(_) => "sequence",
            Self::Map(_) => "map",
        }
    }
}

impl fmt::Debug for NativeMetadataValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let item_count = match self {
            Self::Sequence(values) => Some(values.len()),
            Self::Map(fields) => Some(fields.len()),
            _ => None,
        };
        formatter
            .debug_struct("NativeMetadataValue")
            .field("kind", &self.kind())
            .field("item_count", &item_count)
            .finish()
    }
}

/// One ordered native metadata field. Field names may be arbitrary bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeMetadataField {
    name: Vec<u8>,
    value: NativeMetadataValue,
}

impl NativeMetadataField {
    #[must_use]
    pub fn new(name: impl Into<Vec<u8>>, value: NativeMetadataValue) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &NativeMetadataValue {
        &self.value
    }
}

impl fmt::Debug for NativeMetadataField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeMetadataField")
            .field("name_present", &!self.name.is_empty())
            .field("value_kind", &self.value.kind())
            .finish()
    }
}

/// Ordered provider-native metadata. Ordering and duplicate field names are
/// retained because adapters must not normalize native representation.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct NativeMetadata {
    fields: Vec<NativeMetadataField>,
}

impl NativeMetadata {
    #[must_use]
    pub fn new(fields: impl IntoIterator<Item = NativeMetadataField>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn fields(&self) -> &[NativeMetadataField] {
        &self.fields
    }
}

impl fmt::Debug for NativeMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeMetadata")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

/// Non-authoritative format hint. It never changes the evidence bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordFormatHint {
    PlainText,
    Json,
    Logfmt,
    Syslog,
    StackTrace,
    OtherVersioned { version: u16, code: u16 },
}

impl RecordFormatHint {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::Json => "json",
            Self::Logfmt => "logfmt",
            Self::Syslog => "syslog",
            Self::StackTrace => "stack_trace",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for RecordFormatHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordFormatHint")
            .field("code", &self.code())
            .finish()
    }
}

/// Non-authoritative encoding hint. Evidence remains byte-oriented regardless.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EncodingHint {
    Utf8,
    Utf16LittleEndian,
    Utf16BigEndian,
    Latin1,
    Binary,
    OtherVersioned { version: u16, code: u16 },
}

impl EncodingHint {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Utf16LittleEndian => "utf16_little_endian",
            Self::Utf16BigEndian => "utf16_big_endian",
            Self::Latin1 => "latin1",
            Self::Binary => "binary",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for EncodingHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodingHint")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordHints {
    format: Option<RecordFormatHint>,
    encoding: Option<EncodingHint>,
}

impl RecordHints {
    #[must_use]
    pub const fn new(format: Option<RecordFormatHint>, encoding: Option<EncodingHint>) -> Self {
        Self { format, encoding }
    }

    #[must_use]
    pub const fn format(self) -> Option<RecordFormatHint> {
        self.format
    }

    #[must_use]
    pub const fn encoding(self) -> Option<EncodingHint> {
        self.encoding
    }
}

impl fmt::Debug for RecordHints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordHints")
            .field("format_code", &self.format.map(RecordFormatHint::code))
            .field("encoding_code", &self.encoding.map(EncodingHint::code))
            .finish()
    }
}

/// Retrieval, plan, adapter, and effective source identity for an envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct RawEnvelopeIdentityV1 {
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    adapter: AdapterIdentity,
    source_identity_digest: SourceIdentityDigest,
}

impl RawEnvelopeIdentityV1 {
    #[must_use]
    pub const fn new(
        retrieval_id: RetrievalId,
        plan_id: PlanId,
        plan_digest: PlanDigest,
        adapter: AdapterIdentity,
        source_identity_digest: SourceIdentityDigest,
    ) -> Self {
        Self {
            retrieval_id,
            plan_id,
            plan_digest,
            adapter,
            source_identity_digest,
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

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }
}

impl fmt::Debug for RawEnvelopeIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawEnvelopeIdentityV1")
            .field("retrieval_id_present", &true)
            .field("plan_id_present", &true)
            .field("plan_digest_present", &true)
            .field("adapter", &self.adapter)
            .field("source_identity_digest_present", &true)
            .finish()
    }
}

/// Global and lane-local ordering facts for an envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeOrdering {
    acquisition_sequence: AcquisitionSequence,
    lane: LaneKey,
    lane_sequence: LaneSequence,
}

impl EnvelopeOrdering {
    #[must_use]
    pub const fn new(
        acquisition_sequence: AcquisitionSequence,
        lane: LaneKey,
        lane_sequence: LaneSequence,
    ) -> Self {
        Self {
            acquisition_sequence,
            lane,
            lane_sequence,
        }
    }

    #[must_use]
    pub const fn acquisition_sequence(&self) -> AcquisitionSequence {
        self.acquisition_sequence
    }

    #[must_use]
    pub const fn lane(&self) -> &LaneKey {
        &self.lane
    }

    #[must_use]
    pub const fn lane_sequence(&self) -> LaneSequence {
        self.lane_sequence
    }
}

impl fmt::Debug for EnvelopeOrdering {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeOrdering")
            .field("acquisition_sequence", &self.acquisition_sequence)
            .field("lane", &self.lane)
            .field("lane_sequence", &self.lane_sequence)
            .finish()
    }
}

/// Version-one immutable transport object before policy authorization.
///
/// This type deliberately contains neither a snapshot locator nor a durable
/// content hash. Such commitments exist only after the policy sink authorizes
/// persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct RawEnvelopeV1 {
    identity: RawEnvelopeIdentityV1,
    ordering: EnvelopeOrdering,
    native_event_id: Option<NativeEventId>,
    cursor: Option<SourceCursor>,
    record: RecordBytes,
    state: RecordState,
    timestamps: EnvelopeTimestamps,
    metadata: Option<NativeMetadata>,
    provider_attestations: ProviderAttestationsV1,
    hints: RecordHints,
}

impl RawEnvelopeV1 {
    pub const CONTRACT_VERSION: u16 = 1;

    #[must_use]
    pub fn new(
        identity: RawEnvelopeIdentityV1,
        ordering: EnvelopeOrdering,
        record: RecordBytes,
        state: RecordState,
    ) -> Self {
        Self {
            identity,
            ordering,
            native_event_id: None,
            cursor: None,
            record,
            state,
            timestamps: EnvelopeTimestamps::default(),
            metadata: None,
            provider_attestations: ProviderAttestationsV1::default(),
            hints: RecordHints::default(),
        }
    }

    #[must_use]
    pub fn with_native_event_id(mut self, native_event_id: NativeEventId) -> Self {
        self.native_event_id = Some(native_event_id);
        self
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: SourceCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn with_timestamps(mut self, timestamps: EnvelopeTimestamps) -> Self {
        self.timestamps = timestamps;
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: NativeMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Attach only correlations that the adapter obtained from provider-native
    /// fields. Payload-parsed or inferred identities are outside this API's
    /// contract.
    #[must_use]
    pub fn with_provider_attestations(
        mut self,
        provider_attestations: ProviderAttestationsV1,
    ) -> Self {
        self.provider_attestations = provider_attestations;
        self
    }

    #[must_use]
    pub const fn with_hints(mut self, hints: RecordHints) -> Self {
        self.hints = hints;
        self
    }

    #[must_use]
    pub const fn identity(&self) -> &RawEnvelopeIdentityV1 {
        &self.identity
    }

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        Self::CONTRACT_VERSION
    }

    #[must_use]
    pub const fn ordering(&self) -> &EnvelopeOrdering {
        &self.ordering
    }

    #[must_use]
    pub const fn native_event_id(&self) -> Option<&NativeEventId> {
        self.native_event_id.as_ref()
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&SourceCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub const fn record(&self) -> &RecordBytes {
        &self.record
    }

    #[must_use]
    pub const fn state(&self) -> RecordState {
        self.state
    }

    #[must_use]
    pub const fn timestamps(&self) -> &EnvelopeTimestamps {
        &self.timestamps
    }

    #[must_use]
    pub const fn metadata(&self) -> Option<&NativeMetadata> {
        self.metadata.as_ref()
    }

    #[must_use]
    pub const fn provider_attestations(&self) -> &ProviderAttestationsV1 {
        &self.provider_attestations
    }

    #[must_use]
    pub const fn hints(&self) -> RecordHints {
        self.hints
    }
}

impl fmt::Debug for RawEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawEnvelopeV1")
            .field("identity", &self.identity)
            .field("ordering", &self.ordering)
            .field("native_event_id_present", &self.native_event_id.is_some())
            .field("cursor_present", &self.cursor.is_some())
            .field("record", &self.record)
            .field("state", &self.state)
            .field("timestamps", &self.timestamps)
            .field("metadata_present", &self.metadata.is_some())
            .field(
                "provider_attestation_count",
                &self.provider_attestations.len(),
            )
            .field("hints", &self.hints)
            .finish()
    }
}

/// Durable policy-sink acknowledgement for exactly one emitted envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct SinkAck {
    retrieval_id: RetrievalId,
    source_record_id: SourceRecordId,
    acquisition_sequence: AcquisitionSequence,
    authorized_byte_count: u64,
    outcome: AcquisitionOutcome,
}

impl SinkAck {
    #[must_use]
    pub const fn new(
        retrieval_id: RetrievalId,
        source_record_id: SourceRecordId,
        acquisition_sequence: AcquisitionSequence,
        authorized_byte_count: u64,
        outcome: AcquisitionOutcome,
    ) -> Self {
        Self {
            retrieval_id,
            source_record_id,
            acquisition_sequence,
            authorized_byte_count,
            outcome,
        }
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn source_record_id(&self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn acquisition_sequence(&self) -> AcquisitionSequence {
        self.acquisition_sequence
    }

    #[must_use]
    pub const fn authorized_byte_count(&self) -> u64 {
        self.authorized_byte_count
    }

    #[must_use]
    pub const fn outcome(&self) -> &AcquisitionOutcome {
        &self.outcome
    }
}

impl fmt::Debug for SinkAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SinkAck")
            .field("acquisition_sequence", &self.acquisition_sequence)
            .field("authorized_byte_count", &self.authorized_byte_count)
            .field("outcome_code", &self.outcome.code())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventId, ExactnessBasis, PlanDigest, PlanId, PolicyDigest};

    fn identity(adapter: AdapterIdentity) -> RawEnvelopeIdentityV1 {
        RawEnvelopeIdentityV1::new(
            RetrievalId::from_bytes([1; 32]),
            PlanId::from_bytes([2; 32]),
            PlanDigest::from_bytes([3; 32]),
            adapter,
            SourceIdentityDigest::from_bytes([4; 32]),
        )
    }

    fn ordering(member: SourceMember) -> EnvelopeOrdering {
        EnvelopeOrdering::new(
            AcquisitionSequence::new(11),
            LaneKey::new(member, SourceStream::Stderr),
            LaneSequence::new(7),
        )
    }

    #[test]
    fn record_bytes_preserve_invalid_utf8_and_terminator_exactly() {
        let payload = vec![0xff, 0x00, b'Z'];
        let terminator = b"\r\n".to_vec();
        let record = RecordBytes::framed(payload.clone(), terminator.clone());
        let envelope = RawEnvelopeV1::new(
            identity(AdapterIdentity::new("replay", "1.0.0").unwrap()),
            ordering(SourceMember::new(b"member-a".to_vec()).unwrap()),
            record,
            RecordState::Complete,
        );

        assert_eq!(envelope.contract_version(), RawEnvelopeV1::CONTRACT_VERSION);
        assert_eq!(RawEnvelopeV1::CONTRACT_VERSION, 1);
        assert_eq!(envelope.record().payload(), payload);
        assert_eq!(envelope.record().terminator(), Some(terminator.as_slice()));
        assert_eq!(envelope.record().payload_len(), 3);
        assert_eq!(envelope.record().source_len(), 5);
        assert_eq!(
            envelope.record().exact_bytes(),
            [payload, terminator].concat()
        );
    }

    #[test]
    fn global_and_lane_order_and_native_identifiers_remain_distinct() {
        let native_event_id = NativeEventId::new(b"native-event".to_vec()).unwrap();
        let cursor = SourceCursor::new(b"cursor".to_vec()).unwrap();
        let envelope = RawEnvelopeV1::new(
            identity(AdapterIdentity::new("journald", "2").unwrap()),
            EnvelopeOrdering::new(
                AcquisitionSequence::new(31),
                LaneKey::new(
                    SourceMember::new(b"boot-and-unit".to_vec()).unwrap(),
                    SourceStream::Journal,
                ),
                LaneSequence::new(9),
            ),
            RecordBytes::whole(b"duplicate payload".to_vec()),
            RecordState::AdapterFragment {
                reason: RecordFragmentReason::MalformedProviderFraming,
            },
        )
        .with_native_event_id(native_event_id.clone())
        .with_cursor(cursor.clone());

        assert_eq!(
            envelope.ordering().acquisition_sequence(),
            AcquisitionSequence::new(31)
        );
        assert_eq!(envelope.ordering().lane_sequence(), LaneSequence::new(9));
        assert_eq!(envelope.native_event_id(), Some(&native_event_id));
        assert_eq!(envelope.cursor(), Some(&cursor));
        assert_ne!(
            envelope.native_event_id().unwrap().as_bytes(),
            envelope.cursor().unwrap().as_bytes()
        );
        assert_eq!(
            SourceStream::OtherVersioned {
                version: 1,
                code: 42
            }
            .code(),
            "other_versioned"
        );
    }

    #[test]
    fn typed_optional_timestamp_metadata_and_hints_are_retained() {
        let source_timestamp = SourceTimestamp::new(
            RawTimestamp::new(b"2026-08-24T12:00:00Z".to_vec()).unwrap(),
            Some(UnixTimestampNanos::new(1_777_000_000_000_000_000)),
        );
        let timestamps = EnvelopeTimestamps::new(
            Some(source_timestamp),
            Some(UnixTimestampNanos::new(20)),
            Some(UnixTimestampNanos::new(21)),
            Some(MonotonicTimestampNanos::new(22)),
        );
        let metadata = NativeMetadata::new([
            NativeMetadataField::new(b"attempt".to_vec(), NativeMetadataValue::Unsigned(3)),
            NativeMetadataField::new(
                b"labels".to_vec(),
                NativeMetadataValue::Sequence(vec![NativeMetadataValue::Text("api".into())]),
            ),
        ]);
        let hints = RecordHints::new(Some(RecordFormatHint::Json), Some(EncodingHint::Utf8));
        let envelope = RawEnvelopeV1::new(
            identity(AdapterIdentity::new("cloud", "3").unwrap()),
            ordering(SourceMember::new(b"stream-a".to_vec()).unwrap()),
            RecordBytes::whole(b"{}".to_vec()),
            RecordState::Complete,
        )
        .with_timestamps(timestamps)
        .with_metadata(metadata)
        .with_hints(hints);

        assert_eq!(
            envelope.timestamps().source().unwrap().raw().as_bytes(),
            b"2026-08-24T12:00:00Z"
        );
        assert_eq!(
            envelope.timestamps().adapter_emitted_at().unwrap().get(),
            21
        );
        assert_eq!(
            envelope
                .timestamps()
                .adapter_monotonic_time()
                .unwrap()
                .get(),
            22
        );
        assert_eq!(envelope.metadata().unwrap().fields().len(), 2);
        assert_eq!(envelope.hints().format(), Some(RecordFormatHint::Json));
        assert_eq!(envelope.hints().encoding(), Some(EncodingHint::Utf8));
    }

    #[test]
    fn sink_ack_binds_retrieval_record_sequence_bytes_and_outcome() {
        let retrieval_id = RetrievalId::from_bytes([21; 32]);
        let source_record_id = SourceRecordId::from_bytes([22; 32]);
        let event_id = EventId::from_bytes([23; 32]);
        let ack = SinkAck::new(
            retrieval_id,
            source_record_id,
            AcquisitionSequence::new(4),
            99,
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis: ExactnessBasis::SourceExact,
            },
        );

        assert_eq!(ack.retrieval_id(), retrieval_id);
        assert_eq!(ack.source_record_id(), source_record_id);
        assert_eq!(ack.acquisition_sequence(), AcquisitionSequence::new(4));
        assert_eq!(ack.authorized_byte_count(), 99);
        assert_eq!(ack.outcome().persisted_event_id(), Some(event_id));
    }

    #[test]
    fn pre_policy_debug_and_errors_are_contentless() {
        const ADAPTER_KIND: &str = "CANARY_ADAPTER_KIND_f571";
        const ADAPTER_VERSION: &str = "CANARY_ADAPTER_VERSION_4df1";
        const MEMBER: &[u8] = b"CANARY_MEMBER_39b1";
        const NATIVE_ID: &[u8] = b"CANARY_NATIVE_ID_d03c";
        const CURSOR: &[u8] = b"CANARY_CURSOR_681c";
        const PAYLOAD: &[u8] = b"CANARY_PAYLOAD_77b8";
        const TERMINATOR: &[u8] = b"CANARY_TERMINATOR_ba2f";
        const RAW_TIMESTAMP: &[u8] = b"CANARY_RAW_TIME_c118";
        const METADATA_NAME: &[u8] = b"CANARY_METADATA_NAME_52bd";
        const METADATA_VALUE: &str = "CANARY_METADATA_VALUE_2c2d";

        let adapter = AdapterIdentity::new(ADAPTER_KIND, ADAPTER_VERSION).unwrap();
        let member = SourceMember::new(MEMBER.to_vec()).unwrap();
        let native_event_id = NativeEventId::new(NATIVE_ID.to_vec()).unwrap();
        let cursor = SourceCursor::new(CURSOR.to_vec()).unwrap();
        let raw_timestamp = RawTimestamp::new(RAW_TIMESTAMP.to_vec()).unwrap();
        let metadata_value = NativeMetadataValue::Text(METADATA_VALUE.into());
        let metadata_field = NativeMetadataField::new(METADATA_NAME.to_vec(), metadata_value);
        let metadata = NativeMetadata::new([metadata_field.clone()]);
        let envelope = RawEnvelopeV1::new(
            identity(adapter.clone()),
            ordering(member.clone()),
            RecordBytes::framed(PAYLOAD.to_vec(), TERMINATOR.to_vec()),
            RecordState::SourceTruncated {
                reason: RecordFragmentReason::ProviderTruncation,
            },
        )
        .with_native_event_id(native_event_id.clone())
        .with_cursor(cursor.clone())
        .with_timestamps(EnvelopeTimestamps::new(
            Some(SourceTimestamp::new(raw_timestamp.clone(), None)),
            None,
            None,
            None,
        ))
        .with_metadata(metadata.clone());
        let ack = SinkAck::new(
            RetrievalId::from_bytes([31; 32]),
            SourceRecordId::from_bytes([32; 32]),
            AcquisitionSequence::new(11),
            0,
            AcquisitionOutcome::OmittedByPolicy {
                policy_digest: PolicyDigest::from_bytes([33; 32]),
            },
        );

        let rendered = [
            format!("{adapter:?}"),
            format!("{member:?}"),
            format!("{native_event_id:?}"),
            format!("{cursor:?}"),
            format!("{raw_timestamp:?}"),
            format!("{metadata_field:?}"),
            format!("{metadata:?}"),
            format!("{envelope:?}"),
            format!("{ack:?}"),
        ];
        let canaries = [
            ADAPTER_KIND,
            ADAPTER_VERSION,
            std::str::from_utf8(MEMBER).unwrap(),
            std::str::from_utf8(NATIVE_ID).unwrap(),
            std::str::from_utf8(CURSOR).unwrap(),
            std::str::from_utf8(PAYLOAD).unwrap(),
            std::str::from_utf8(TERMINATOR).unwrap(),
            std::str::from_utf8(RAW_TIMESTAMP).unwrap(),
            std::str::from_utf8(METADATA_NAME).unwrap(),
            METADATA_VALUE,
        ];
        for output in rendered {
            for canary in canaries {
                assert!(!output.contains(canary));
            }
        }

        let error = AdapterIdentity::new("", ADAPTER_VERSION).unwrap_err();
        assert_eq!(error, EnvelopeConstructionError::EmptyAdapterKind);
        assert_eq!(error.to_string(), "EVIDENTRAIL_SCHEMA_EMPTY_ADAPTER_KIND");
        assert_eq!(
            format!("{error:?}"),
            "EnvelopeConstructionError { code: \"EVIDENTRAIL_SCHEMA_EMPTY_ADAPTER_KIND\" }"
        );
        assert!(!format!("{error:?}").contains(ADAPTER_VERSION));
    }
}
