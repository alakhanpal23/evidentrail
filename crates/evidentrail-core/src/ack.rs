use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::MAX_AUTHORIZED_RECORD_BYTES;
use evidentrail_schema::{AcquisitionOutcome, ExactnessBasis, RawEnvelopeV1, SinkAck, SourceRecordId};

use crate::hash::source_record_id;

/// Derive the exact source-record identity used by the authoritative ledger
/// path. The calculation is result-local and does not observe payload bytes.
#[must_use]
pub fn expected_source_record_id(envelope: &RawEnvelopeV1) -> SourceRecordId {
    source_record_id(envelope)
}

/// Compact payload-free facts prepared before an envelope moves into a sink.
///
/// This value owns no envelope, payload, member, cursor, or provider metadata.
/// It is therefore suitable for verifying the returned acknowledgement after
/// `EnvelopeSink::accept` has consumed the raw envelope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreparedSinkAckExpectation {
    retrieval_id: evidentrail_schema::RetrievalId,
    acquisition_sequence: evidentrail_schema::AcquisitionSequence,
    source_record_id: SourceRecordId,
    source_byte_count: usize,
}

impl PreparedSinkAckExpectation {
    /// Capture exactly the acknowledgement-binding facts for one envelope
    /// without copying its content-bearing fields.
    #[must_use]
    pub fn from_envelope(envelope: &RawEnvelopeV1) -> Self {
        Self {
            retrieval_id: envelope.identity().retrieval_id(),
            acquisition_sequence: envelope.ordering().acquisition_sequence(),
            source_record_id: expected_source_record_id(envelope),
            source_byte_count: envelope.record().source_len(),
        }
    }

    /// Verify an acknowledgement after the corresponding envelope has moved
    /// into the sink. This has the same deliberately narrow policy boundary as
    /// [`verify_sink_ack_binding`].
    pub fn verify(&self, acknowledgement: &SinkAck) -> Result<(), SinkAckVerificationError> {
        if acknowledgement.retrieval_id() != self.retrieval_id {
            return Err(SinkAckVerificationError::RetrievalMismatch);
        }
        if acknowledgement.acquisition_sequence() != self.acquisition_sequence {
            return Err(SinkAckVerificationError::AcquisitionSequenceMismatch);
        }
        if acknowledgement.source_record_id() != self.source_record_id {
            return Err(SinkAckVerificationError::SourceRecordIdMismatch);
        }

        let authorized_byte_count_is_valid = match acknowledgement.outcome() {
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::SourceExact,
                ..
            } => usize::try_from(acknowledgement.authorized_byte_count())
                .is_ok_and(|source_len| source_len == self.source_byte_count),
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::PostPolicy { .. },
                ..
            } => acknowledgement.authorized_byte_count() <= MAX_AUTHORIZED_RECORD_BYTES as u64,
            AcquisitionOutcome::OmittedByPolicy { .. } => {
                acknowledgement.authorized_byte_count() == 0
            }
        };
        if !authorized_byte_count_is_valid {
            return Err(SinkAckVerificationError::AuthorizedByteCountMismatch);
        }

        Ok(())
    }
}

impl fmt::Debug for PreparedSinkAckExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSinkAckExpectation")
            .field("source_byte_count", &self.source_byte_count)
            .finish()
    }
}

/// Verify that a sink acknowledgement is bound to one exact raw envelope.
///
/// This verifies retrieval, acquisition sequence, source-record identity, and
/// the authorized byte count that can be established from the typed outcome.
/// `SourceExact` must acknowledge the source record length and
/// `OmittedByPolicy` must acknowledge zero bytes.
///
/// A `PostPolicy` acknowledgement cannot be recomputed from the pre-policy
/// envelope: its bytes may intentionally differ and forbidden originals must
/// not be retained or hashed. For that outcome this function only enforces the
/// hard authorized-record limit. Choosing the policy outcome and proving the
/// transformed bytes remain responsibilities of the trusted policy sink; a
/// successful result here does not endorse an arbitrary sink's policy choice.
pub fn verify_sink_ack_binding(
    envelope: &RawEnvelopeV1,
    acknowledgement: &SinkAck,
) -> Result<(), SinkAckVerificationError> {
    PreparedSinkAckExpectation::from_envelope(envelope).verify(acknowledgement)
}

/// Contentless acknowledgement-binding failure classified by dimension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SinkAckVerificationError {
    RetrievalMismatch,
    AcquisitionSequenceMismatch,
    SourceRecordIdMismatch,
    AuthorizedByteCountMismatch,
}

impl SinkAckVerificationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RetrievalMismatch => "EVIDENTRAIL_SINK_ACK_RETRIEVAL_MISMATCH",
            Self::AcquisitionSequenceMismatch => "EVIDENTRAIL_SINK_ACK_ACQUISITION_SEQUENCE_MISMATCH",
            Self::SourceRecordIdMismatch => "EVIDENTRAIL_SINK_ACK_SOURCE_RECORD_ID_MISMATCH",
            Self::AuthorizedByteCountMismatch => "EVIDENTRAIL_SINK_ACK_AUTHORIZED_BYTE_COUNT_MISMATCH",
        }
    }
}

impl fmt::Debug for SinkAckVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SinkAckVerificationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SinkAckVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SinkAckVerificationError {}
