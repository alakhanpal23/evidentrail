use std::error::Error as StdError;
use std::fmt;

/// Stable, contentless failure returned by the V1 format primitive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFormatErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedOuterVersion,
    UnsupportedHeaderVersion,
    UnsupportedSuite,
    UnsupportedObjectKind,
    InvalidPayloadSchema,
    InvalidObjectSequence,
    ResultMismatch,
    NonzeroFlags,
    NonzeroReserved,
    InvalidTimeRange,
    InvalidSegmentChainStart,
    PlaintextTooLarge,
    PlaintextLengthMismatch,
    CiphertextLengthMismatch,
    FrameCountCap,
    DuplicateNonce,
    LengthOverflow,
    GlobalSequenceMismatch,
    SegmentFrameSequenceMismatch,
    PreviousCommitmentMismatch,
    CommitmentMismatch,
    AuthenticationFailed,
    EntropyUnavailable,
    AllZeroEntropyOutput,
    RepeatedEntropyOutput,
}

impl SnapshotFormatErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_MAGIC",
            Self::UnsupportedOuterVersion => "EVIDENTRAIL_SNAPSHOT_FORMAT_UNSUPPORTED_OUTER_VERSION",
            Self::UnsupportedHeaderVersion => "EVIDENTRAIL_SNAPSHOT_FORMAT_UNSUPPORTED_HEADER_VERSION",
            Self::UnsupportedSuite => "EVIDENTRAIL_SNAPSHOT_FORMAT_UNSUPPORTED_SUITE",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_SNAPSHOT_FORMAT_UNSUPPORTED_OBJECT_KIND",
            Self::InvalidPayloadSchema => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_PAYLOAD_SCHEMA",
            Self::InvalidObjectSequence => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_OBJECT_SEQUENCE",
            Self::ResultMismatch => "EVIDENTRAIL_SNAPSHOT_FORMAT_RESULT_MISMATCH",
            Self::NonzeroFlags => "EVIDENTRAIL_SNAPSHOT_FORMAT_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_SNAPSHOT_FORMAT_NONZERO_RESERVED",
            Self::InvalidTimeRange => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_TIME_RANGE",
            Self::InvalidSegmentChainStart => "EVIDENTRAIL_SNAPSHOT_FORMAT_INVALID_SEGMENT_CHAIN_START",
            Self::PlaintextTooLarge => "EVIDENTRAIL_SNAPSHOT_FORMAT_PLAINTEXT_TOO_LARGE",
            Self::PlaintextLengthMismatch => "EVIDENTRAIL_SNAPSHOT_FORMAT_PLAINTEXT_LENGTH_MISMATCH",
            Self::CiphertextLengthMismatch => "EVIDENTRAIL_SNAPSHOT_FORMAT_CIPHERTEXT_LENGTH_MISMATCH",
            Self::FrameCountCap => "EVIDENTRAIL_SNAPSHOT_FORMAT_FRAME_COUNT_CAP",
            Self::DuplicateNonce => "EVIDENTRAIL_SNAPSHOT_FORMAT_DUPLICATE_NONCE",
            Self::LengthOverflow => "EVIDENTRAIL_SNAPSHOT_FORMAT_LENGTH_OVERFLOW",
            Self::GlobalSequenceMismatch => "EVIDENTRAIL_SNAPSHOT_FORMAT_GLOBAL_SEQUENCE_MISMATCH",
            Self::SegmentFrameSequenceMismatch => {
                "EVIDENTRAIL_SNAPSHOT_FORMAT_SEGMENT_FRAME_SEQUENCE_MISMATCH"
            }
            Self::PreviousCommitmentMismatch => {
                "EVIDENTRAIL_SNAPSHOT_FORMAT_PREVIOUS_COMMITMENT_MISMATCH"
            }
            Self::CommitmentMismatch => "EVIDENTRAIL_SNAPSHOT_FORMAT_COMMITMENT_MISMATCH",
            Self::AuthenticationFailed => "EVIDENTRAIL_SNAPSHOT_FORMAT_AUTHENTICATION_FAILED",
            Self::EntropyUnavailable => "EVIDENTRAIL_SNAPSHOT_FORMAT_ENTROPY_UNAVAILABLE",
            Self::AllZeroEntropyOutput => "EVIDENTRAIL_SNAPSHOT_FORMAT_ALL_ZERO_ENTROPY_OUTPUT",
            Self::RepeatedEntropyOutput => "EVIDENTRAIL_SNAPSHOT_FORMAT_REPEATED_ENTROPY_OUTPUT",
        }
    }
}

impl fmt::Debug for SnapshotFormatErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotFormatErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SnapshotFormatErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SnapshotFormatErrorV1 {}
