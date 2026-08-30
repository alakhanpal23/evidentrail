use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EnvelopeSink, PreparedSinkAckExpectation, expected_source_record_id};
use evidentrail_schema::{NativeMetadataValue, RawEnvelopeV1, SinkAck};
use sha2::{Digest as _, Sha256};

use crate::{Cancellation, ExecutionContext, FetchCompletion, IngestError, SourceAdapter};

/// Maximum number of envelopes accepted by the V1 batch compatibility seam.
pub const MAX_ENVELOPES_PER_BATCH_V1: usize = 4_096;

/// Stable idempotency identity for one ordered adapter batch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchOperationIdV1([u8; 32]);

impl BatchOperationIdV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BatchOperationIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchOperationIdV1(<redacted>)")
    }
}

/// Immutable, canonically committed batch supplied to a durable sink.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeBatchV1 {
    operation_id: BatchOperationIdV1,
    ordinal: u64,
    canonical_digest: [u8; 32],
    envelopes: Vec<RawEnvelopeV1>,
}

impl EnvelopeBatchV1 {
    pub fn new(
        context: &ExecutionContext,
        ordinal: u64,
        envelopes: impl Into<Vec<RawEnvelopeV1>>,
    ) -> Result<Self, BatchConstructionErrorV1> {
        let envelopes = envelopes.into();
        if envelopes.is_empty() || envelopes.len() > MAX_ENVELOPES_PER_BATCH_V1 {
            return Err(BatchConstructionErrorV1::InvalidEnvelopeCount);
        }
        if envelopes
            .iter()
            .any(|envelope| !context.matches(envelope.identity()))
        {
            return Err(BatchConstructionErrorV1::CrossContextEnvelope);
        }
        for pair in envelopes.windows(2) {
            if pair[1].ordering().acquisition_sequence().get()
                != pair[0]
                    .ordering()
                    .acquisition_sequence()
                    .get()
                    .checked_add(1)
                    .ok_or(BatchConstructionErrorV1::OrderingOverflow)?
            {
                return Err(BatchConstructionErrorV1::NonContiguousOrdering);
            }
        }

        let canonical_digest = canonical_batch_digest(context, ordinal, &envelopes);
        let mut operation_hasher = domain_hasher(b"evidentrail/ingest/batch-operation/v1");
        field(
            &mut operation_hasher,
            context.fetch_identity().retrieval_id().as_bytes(),
        );
        field(&mut operation_hasher, &ordinal.to_le_bytes());
        let operation_id = BatchOperationIdV1(operation_hasher.finalize().into());
        Ok(Self {
            operation_id,
            ordinal,
            canonical_digest,
            envelopes,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> BatchOperationIdV1 {
        self.operation_id
    }

    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }

    #[must_use]
    pub fn envelopes(&self) -> &[RawEnvelopeV1] {
        &self.envelopes
    }
}

impl fmt::Debug for EnvelopeBatchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeBatchV1")
            .field("ordinal", &self.ordinal)
            .field("envelope_count", &self.envelopes.len())
            .field("operation_id_present", &true)
            .field("canonical_digest_present", &true)
            .finish()
    }
}

/// Ordered durable acknowledgements for a completely committed batch.
pub struct EnvelopeBatchAcknowledgementsV1 {
    acknowledgements: Vec<SinkAck>,
}

impl EnvelopeBatchAcknowledgementsV1 {
    pub fn verify(
        batch: &EnvelopeBatchV1,
        acknowledgements: Vec<SinkAck>,
    ) -> Result<Self, BatchSinkErrorV1> {
        if acknowledgements.len() != batch.envelopes.len()
            || !verified_prefix(batch, &acknowledgements)
        {
            return Err(BatchSinkErrorV1::invalid_acknowledgement(Vec::new()));
        }
        Ok(Self { acknowledgements })
    }

    #[must_use]
    pub fn as_slice(&self) -> &[SinkAck] {
        &self.acknowledgements
    }
}

impl fmt::Debug for EnvelopeBatchAcknowledgementsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeBatchAcknowledgementsV1")
            .field("acknowledgement_count", &self.acknowledgements.len())
            .finish()
    }
}

/// Durable batch sink. Implementations must make an exact operation identity
/// idempotent and reject changed bytes under a reused identity.
pub trait EnvelopeBatchSinkV1 {
    fn commit_batch(
        &mut self,
        batch: &EnvelopeBatchV1,
    ) -> Result<EnvelopeBatchAcknowledgementsV1, BatchSinkErrorV1>;
}

/// Batch-native source seam. The legacy single-envelope source seam remains
/// available through [`SingleEnvelopeSourceAdapterV1`].
pub trait SourceBatchAdapterV1 {
    fn execute_batches(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeBatchSinkV1,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError>;
}

/// Compatibility wrapper that drives a batch adapter through an existing
/// single-envelope sink. It preserves acknowledged-prefix accounting, but it
/// cannot add atomicity that the wrapped sink does not provide.
pub struct SingleEnvelopeBatchSinkV1<'sink> {
    sink: &'sink mut dyn EnvelopeSink,
}

impl<'sink> SingleEnvelopeBatchSinkV1<'sink> {
    #[must_use]
    pub fn new(sink: &'sink mut dyn EnvelopeSink) -> Self {
        Self { sink }
    }
}

impl EnvelopeBatchSinkV1 for SingleEnvelopeBatchSinkV1<'_> {
    fn commit_batch(
        &mut self,
        batch: &EnvelopeBatchV1,
    ) -> Result<EnvelopeBatchAcknowledgementsV1, BatchSinkErrorV1> {
        let mut acknowledgements = Vec::with_capacity(batch.envelopes.len());
        for envelope in &batch.envelopes {
            let expectation = PreparedSinkAckExpectation::from_envelope(envelope);
            let acknowledgement = self
                .sink
                .accept(envelope.clone())
                .map_err(|_| BatchSinkErrorV1::sink_stopped(acknowledgements.clone()))?;
            if expectation.verify(&acknowledgement).is_err() {
                return Err(BatchSinkErrorV1::invalid_acknowledgement(acknowledgements));
            }
            acknowledgements.push(acknowledgement);
        }
        EnvelopeBatchAcknowledgementsV1::verify(batch, acknowledgements)
    }
}

/// Legacy `SourceAdapter` wrapper for one batch-native adapter.
pub struct SingleEnvelopeSourceAdapterV1<A> {
    inner: A,
}

impl<A> SingleEnvelopeSourceAdapterV1<A> {
    #[must_use]
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }

    #[must_use]
    pub const fn inner(&self) -> &A {
        &self.inner
    }
}

impl<A> SourceAdapter for SingleEnvelopeSourceAdapterV1<A>
where
    A: SourceBatchAdapterV1,
{
    fn execute_with_cancellation(
        &self,
        context: &ExecutionContext,
        sink: &mut dyn EnvelopeSink,
        cancellation: &dyn Cancellation,
    ) -> Result<FetchCompletion, IngestError> {
        let mut compatibility = SingleEnvelopeBatchSinkV1::new(sink);
        self.inner
            .execute_batches(context, &mut compatibility, cancellation)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BatchSinkErrorCodeV1 {
    SinkStopped,
    InvalidAcknowledgement,
    OperationConflict,
}

impl BatchSinkErrorCodeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SinkStopped => "EVIDENTRAIL_BATCH_SINK_STOPPED",
            Self::InvalidAcknowledgement => "EVIDENTRAIL_BATCH_SINK_INVALID_ACKNOWLEDGEMENT",
            Self::OperationConflict => "EVIDENTRAIL_BATCH_SINK_OPERATION_CONFLICT",
        }
    }
}

/// Contentless failure carrying only already-durable acknowledgements.
pub struct BatchSinkErrorV1 {
    code: BatchSinkErrorCodeV1,
    acknowledged_prefix: Vec<SinkAck>,
}

impl BatchSinkErrorV1 {
    #[must_use]
    pub fn operation_conflict() -> Self {
        Self {
            code: BatchSinkErrorCodeV1::OperationConflict,
            acknowledged_prefix: Vec::new(),
        }
    }

    /// Construct a stopped-batch result after verifying every reported
    /// acknowledgement against the exact leading envelope prefix.
    pub fn from_acknowledged_prefix(
        batch: &EnvelopeBatchV1,
        acknowledged_prefix: Vec<SinkAck>,
        code: BatchSinkErrorCodeV1,
    ) -> Result<Self, BatchSinkErrorV1> {
        if acknowledged_prefix.len() >= batch.envelopes.len()
            || !verified_prefix(batch, &acknowledged_prefix)
        {
            return Err(Self::invalid_acknowledgement(Vec::new()));
        }
        Ok(Self {
            code,
            acknowledged_prefix,
        })
    }

    fn sink_stopped(acknowledged_prefix: Vec<SinkAck>) -> Self {
        Self {
            code: BatchSinkErrorCodeV1::SinkStopped,
            acknowledged_prefix,
        }
    }

    fn invalid_acknowledgement(acknowledged_prefix: Vec<SinkAck>) -> Self {
        Self {
            code: BatchSinkErrorCodeV1::InvalidAcknowledgement,
            acknowledged_prefix,
        }
    }

    #[must_use]
    pub const fn code(&self) -> BatchSinkErrorCodeV1 {
        self.code
    }

    #[must_use]
    pub fn acknowledged_prefix(&self) -> &[SinkAck] {
        &self.acknowledged_prefix
    }
}

impl fmt::Debug for BatchSinkErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchSinkErrorV1")
            .field("code", &self.code.code())
            .field("acknowledged_count", &self.acknowledged_prefix.len())
            .finish()
    }
}

impl fmt::Display for BatchSinkErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.code())
    }
}

impl StdError for BatchSinkErrorV1 {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BatchConstructionErrorV1 {
    InvalidEnvelopeCount,
    CrossContextEnvelope,
    NonContiguousOrdering,
    OrderingOverflow,
}

impl BatchConstructionErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEnvelopeCount => "EVIDENTRAIL_BATCH_INVALID_ENVELOPE_COUNT",
            Self::CrossContextEnvelope => "EVIDENTRAIL_BATCH_CROSS_CONTEXT_ENVELOPE",
            Self::NonContiguousOrdering => "EVIDENTRAIL_BATCH_NONCONTIGUOUS_ORDERING",
            Self::OrderingOverflow => "EVIDENTRAIL_BATCH_ORDERING_OVERFLOW",
        }
    }
}

impl fmt::Debug for BatchConstructionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchConstructionErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for BatchConstructionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for BatchConstructionErrorV1 {}

fn verified_prefix(batch: &EnvelopeBatchV1, acknowledgements: &[SinkAck]) -> bool {
    acknowledgements.len() <= batch.envelopes.len()
        && batch
            .envelopes
            .iter()
            .zip(acknowledgements)
            .all(|(envelope, acknowledgement)| {
                PreparedSinkAckExpectation::from_envelope(envelope)
                    .verify(acknowledgement)
                    .is_ok()
            })
}

fn canonical_batch_digest(
    context: &ExecutionContext,
    ordinal: u64,
    envelopes: &[RawEnvelopeV1],
) -> [u8; 32] {
    let mut hasher = domain_hasher(b"evidentrail/ingest/envelope-batch/v1");
    field(
        &mut hasher,
        context.fetch_identity().retrieval_id().as_bytes(),
    );
    field(&mut hasher, &ordinal.to_le_bytes());
    field(&mut hasher, &(envelopes.len() as u64).to_le_bytes());
    for envelope in envelopes {
        field(&mut hasher, expected_source_record_id(envelope).as_bytes());
        field(&mut hasher, envelope.record().payload());
        optional_field(&mut hasher, envelope.record().terminator());
        let timestamps = envelope.timestamps();
        optional_field(
            &mut hasher,
            timestamps.source().map(|value| value.raw().as_bytes()),
        );
        optional_i128(
            &mut hasher,
            timestamps.source().and_then(|value| value.parsed()),
        );
        optional_i128(&mut hasher, timestamps.provider_observed_at());
        optional_i128(&mut hasher, timestamps.adapter_emitted_at());
        match timestamps.adapter_monotonic_time() {
            Some(value) => {
                hasher.update([1]);
                field(&mut hasher, &value.get().to_le_bytes());
            }
            None => hasher.update([0]),
        }
        match envelope.metadata() {
            Some(metadata) => {
                hasher.update([1]);
                field(&mut hasher, &(metadata.fields().len() as u64).to_le_bytes());
                for metadata_field in metadata.fields() {
                    field(&mut hasher, metadata_field.name());
                    hash_metadata_value(&mut hasher, metadata_field.value());
                }
            }
            None => hasher.update([0]),
        }
        field(
            &mut hasher,
            &(envelope.provider_attestations().len() as u64).to_le_bytes(),
        );
        for attestation in envelope.provider_attestations().entries() {
            field(&mut hasher, attestation.scope_digest().as_bytes());
            field(&mut hasher, attestation.relation_kind().code().as_bytes());
            field(&mut hasher, attestation.origin().code().as_bytes());
            field(&mut hasher, attestation.value().as_bytes());
        }
        field(
            &mut hasher,
            envelope
                .hints()
                .format()
                .map_or(b"", |value| value.code().as_bytes()),
        );
        field(
            &mut hasher,
            envelope
                .hints()
                .encoding()
                .map_or(b"", |value| value.code().as_bytes()),
        );
    }
    hasher.finalize().into()
}

fn hash_metadata_value(hasher: &mut Sha256, value: &NativeMetadataValue) {
    field(hasher, value.kind().as_bytes());
    match value {
        NativeMetadataValue::Null => {}
        NativeMetadataValue::Boolean(value) => hasher.update([u8::from(*value)]),
        NativeMetadataValue::Signed(value) => field(hasher, &value.to_le_bytes()),
        NativeMetadataValue::Unsigned(value) | NativeMetadataValue::FloatBits(value) => {
            field(hasher, &value.to_le_bytes());
        }
        NativeMetadataValue::Text(value) => field(hasher, value.as_bytes()),
        NativeMetadataValue::Bytes(value) => field(hasher, value),
        NativeMetadataValue::Sequence(values) => {
            field(hasher, &(values.len() as u64).to_le_bytes());
            for value in values {
                hash_metadata_value(hasher, value);
            }
        }
        NativeMetadataValue::Map(fields) => {
            field(hasher, &(fields.len() as u64).to_le_bytes());
            for metadata_field in fields {
                field(hasher, metadata_field.name());
                hash_metadata_value(hasher, metadata_field.value());
            }
        }
    }
}

fn optional_i128(hasher: &mut Sha256, value: Option<evidentrail_schema::UnixTimestampNanos>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            field(hasher, &value.get().to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn optional_field(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            field(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    field(&mut hasher, domain);
    hasher
}

fn field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}
