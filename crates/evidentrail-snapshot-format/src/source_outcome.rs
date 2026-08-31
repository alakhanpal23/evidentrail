use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt, EventId, ExactnessBasis,
    PolicyDigest, RetrievalId, SourceRecordId, TransformationReceiptId,
};
use sha2::{Digest, Sha256};

use crate::{EventExpansionIndexV1, MAX_MANIFEST_PLAINTEXT_BYTES_V1};

pub const SOURCE_OUTCOME_TABLE_VERSION_V1: u16 = 1;
pub const SOURCE_OUTCOME_TABLE_SCHEMA_V1: u16 = 1;
pub const SOURCE_OUTCOME_TABLE_OBJECT_KIND_V1: u16 = 1;
pub const SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1: usize = 160;
pub const SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1: usize = 160;
pub const SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1: u16 = 1;
pub const SOURCE_OUTCOME_POST_POLICY_KIND_V1: u16 = 2;
pub const SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1: u16 = 3;
pub const EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1: usize = 32;
/// Component-local allocation cap derived from the outer manifest plaintext
/// bound. A future combined manifest must impose a lower shared cap.
pub const MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1: u64 =
    ((MAX_MANIFEST_PLAINTEXT_BYTES_V1 - SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1)
        / SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1) as u64;
pub const MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1: usize = SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1
    + MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1 as usize * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;

const SOURCE_OUTCOME_TABLE_MAGIC_V1: [u8; 8] = *b"EVRSOT01";

const HEADER_FLAGS_OFFSET_V1: usize = 16;
const HEADER_RESERVED_ONE_OFFSET_V1: usize = 18;
const HEADER_RETRIEVAL_ID_OFFSET_V1: usize = 24;
const HEADER_ENTRY_COUNT_OFFSET_V1: usize = 56;
const HEADER_SOURCE_EXACT_COUNT_OFFSET_V1: usize = 64;
const HEADER_POST_POLICY_COUNT_OFFSET_V1: usize = 72;
const HEADER_OMITTED_COUNT_OFFSET_V1: usize = 80;
const HEADER_INDEX_ENTRY_COUNT_OFFSET_V1: usize = 88;
const HEADER_INDEX_DIGEST_OFFSET_V1: usize = 96;
const HEADER_RESERVED_TWO_OFFSET_V1: usize = 128;

const ENTRY_ORDINAL_OFFSET_V1: usize = 0;
const ENTRY_SOURCE_RECORD_ID_OFFSET_V1: usize = 8;
const ENTRY_OUTCOME_KIND_OFFSET_V1: usize = 40;
const ENTRY_FLAGS_OFFSET_V1: usize = 42;
const ENTRY_RESERVED_ONE_OFFSET_V1: usize = 44;
const ENTRY_EVENT_ID_OFFSET_V1: usize = 48;
const ENTRY_POLICY_DIGEST_OFFSET_V1: usize = 80;
const ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1: usize = 112;
const ENTRY_RESERVED_TWO_OFFSET_V1: usize = 144;

/// Stable, contentless failure returned by the V1 source-outcome table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SourceOutcomeTableErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    UnsupportedObjectKind,
    InvalidEntryWidth,
    NonzeroFlags,
    NonzeroReserved,
    EntryCountCap,
    RetrievalMismatch,
    ReceiptEntryCountMismatch,
    ReceiptCountsMismatch,
    IndexEntryCountMismatch,
    IndexDigestMismatch,
    InvalidAcquisitionOrdinal,
    DuplicateSourceRecordId,
    DuplicatePersistedEventId,
    UnsupportedOutcomeKind,
    NoncanonicalConditionalFields,
    DeclaredCountsMismatch,
    ReceiptEntryMismatch,
    MissingIndexEvent,
    ExtraIndexEvent,
    IndexExactnessMismatch,
    ReceiptReconstructionFailed,
    ArithmeticOverflow,
}

impl SourceOutcomeTableErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_SOURCE_OUTCOME_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_SOURCE_OUTCOME_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_SOURCE_OUTCOME_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_SOURCE_OUTCOME_UNSUPPORTED_SCHEMA",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_SOURCE_OUTCOME_UNSUPPORTED_OBJECT_KIND",
            Self::InvalidEntryWidth => "EVIDENTRAIL_SOURCE_OUTCOME_INVALID_ENTRY_WIDTH",
            Self::NonzeroFlags => "EVIDENTRAIL_SOURCE_OUTCOME_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_SOURCE_OUTCOME_NONZERO_RESERVED",
            Self::EntryCountCap => "EVIDENTRAIL_SOURCE_OUTCOME_ENTRY_COUNT_CAP",
            Self::RetrievalMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_RETRIEVAL_MISMATCH",
            Self::ReceiptEntryCountMismatch => {
                "EVIDENTRAIL_SOURCE_OUTCOME_RECEIPT_ENTRY_COUNT_MISMATCH"
            }
            Self::ReceiptCountsMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_RECEIPT_COUNTS_MISMATCH",
            Self::IndexEntryCountMismatch => {
                "EVIDENTRAIL_SOURCE_OUTCOME_INDEX_ENTRY_COUNT_MISMATCH"
            }
            Self::IndexDigestMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_INDEX_DIGEST_MISMATCH",
            Self::InvalidAcquisitionOrdinal => {
                "EVIDENTRAIL_SOURCE_OUTCOME_INVALID_ACQUISITION_ORDINAL"
            }
            Self::DuplicateSourceRecordId => {
                "EVIDENTRAIL_SOURCE_OUTCOME_DUPLICATE_SOURCE_RECORD_ID"
            }
            Self::DuplicatePersistedEventId => {
                "EVIDENTRAIL_SOURCE_OUTCOME_DUPLICATE_PERSISTED_EVENT_ID"
            }
            Self::UnsupportedOutcomeKind => "EVIDENTRAIL_SOURCE_OUTCOME_UNSUPPORTED_OUTCOME_KIND",
            Self::NoncanonicalConditionalFields => {
                "EVIDENTRAIL_SOURCE_OUTCOME_NONCANONICAL_CONDITIONAL_FIELDS"
            }
            Self::DeclaredCountsMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_DECLARED_COUNTS_MISMATCH",
            Self::ReceiptEntryMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_RECEIPT_ENTRY_MISMATCH",
            Self::MissingIndexEvent => "EVIDENTRAIL_SOURCE_OUTCOME_MISSING_INDEX_EVENT",
            Self::ExtraIndexEvent => "EVIDENTRAIL_SOURCE_OUTCOME_EXTRA_INDEX_EVENT",
            Self::IndexExactnessMismatch => "EVIDENTRAIL_SOURCE_OUTCOME_INDEX_EXACTNESS_MISMATCH",
            Self::ReceiptReconstructionFailed => {
                "EVIDENTRAIL_SOURCE_OUTCOME_RECEIPT_RECONSTRUCTION_FAILED"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_SOURCE_OUTCOME_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for SourceOutcomeTableErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceOutcomeTableErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SourceOutcomeTableErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SourceOutcomeTableErrorV1 {}

/// SHA-256 binding to exact canonical `EventExpansionIndexV1::encode()` bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventExpansionIndexDigestV1([u8; EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1]);

impl EventExpansionIndexDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for EventExpansionIndexDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventExpansionIndexDigestV1(<redacted>)")
    }
}

/// Hash the exact canonical event-index artifact reconciled by this table.
#[must_use]
pub fn derive_event_expansion_index_digest_v1(
    index: &EventExpansionIndexV1,
) -> EventExpansionIndexDigestV1 {
    EventExpansionIndexDigestV1::from_bytes(Sha256::digest(index.encode()).into())
}

/// One receipt-ordered source outcome with its zero-based acquisition ordinal.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceOutcomeTableEntryV1 {
    acquisition_ordinal: u64,
    source_record_id: SourceRecordId,
    outcome: AcquisitionOutcome,
}

impl SourceOutcomeTableEntryV1 {
    #[must_use]
    pub const fn acquisition_ordinal(&self) -> u64 {
        self.acquisition_ordinal
    }

    #[must_use]
    pub const fn source_record_id(&self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &AcquisitionOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1] {
        let mut encoded = [0u8; SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1];
        encoded[ENTRY_ORDINAL_OFFSET_V1..ENTRY_SOURCE_RECORD_ID_OFFSET_V1]
            .copy_from_slice(&self.acquisition_ordinal.to_be_bytes());
        encoded[ENTRY_SOURCE_RECORD_ID_OFFSET_V1..ENTRY_OUTCOME_KIND_OFFSET_V1]
            .copy_from_slice(self.source_record_id.as_bytes());
        match &self.outcome {
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis: ExactnessBasis::SourceExact,
            } => {
                encoded[ENTRY_OUTCOME_KIND_OFFSET_V1..ENTRY_FLAGS_OFFSET_V1]
                    .copy_from_slice(&SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1.to_be_bytes());
                encoded[ENTRY_EVENT_ID_OFFSET_V1..ENTRY_POLICY_DIGEST_OFFSET_V1]
                    .copy_from_slice(event_id.as_bytes());
            }
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis:
                    ExactnessBasis::PostPolicy {
                        policy_digest,
                        transformation_receipt_id,
                    },
            } => {
                encoded[ENTRY_OUTCOME_KIND_OFFSET_V1..ENTRY_FLAGS_OFFSET_V1]
                    .copy_from_slice(&SOURCE_OUTCOME_POST_POLICY_KIND_V1.to_be_bytes());
                encoded[ENTRY_EVENT_ID_OFFSET_V1..ENTRY_POLICY_DIGEST_OFFSET_V1]
                    .copy_from_slice(event_id.as_bytes());
                encoded[ENTRY_POLICY_DIGEST_OFFSET_V1..ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1]
                    .copy_from_slice(policy_digest.as_bytes());
                encoded[ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1..ENTRY_RESERVED_TWO_OFFSET_V1]
                    .copy_from_slice(transformation_receipt_id.as_bytes());
            }
            AcquisitionOutcome::OmittedByPolicy { policy_digest } => {
                encoded[ENTRY_OUTCOME_KIND_OFFSET_V1..ENTRY_FLAGS_OFFSET_V1]
                    .copy_from_slice(&SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1.to_be_bytes());
                encoded[ENTRY_POLICY_DIGEST_OFFSET_V1..ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1]
                    .copy_from_slice(policy_digest.as_bytes());
            }
        }
        encoded
    }

    fn decode(expected_ordinal: u64, encoded: &[u8]) -> Result<Self, SourceOutcomeTableErrorV1> {
        if encoded.len() != SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1 {
            return Err(SourceOutcomeTableErrorV1::InvalidEncodedLength);
        }
        if read_u16(encoded, ENTRY_FLAGS_OFFSET_V1) != 0 {
            return Err(SourceOutcomeTableErrorV1::NonzeroFlags);
        }
        if encoded[ENTRY_RESERVED_ONE_OFFSET_V1..ENTRY_EVENT_ID_OFFSET_V1]
            .iter()
            .chain(encoded[ENTRY_RESERVED_TWO_OFFSET_V1..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(SourceOutcomeTableErrorV1::NonzeroReserved);
        }
        let acquisition_ordinal = read_u64(encoded, ENTRY_ORDINAL_OFFSET_V1);
        if acquisition_ordinal != expected_ordinal {
            return Err(SourceOutcomeTableErrorV1::InvalidAcquisitionOrdinal);
        }

        let event_bytes = read_array(encoded, ENTRY_EVENT_ID_OFFSET_V1);
        let policy_bytes = read_array(encoded, ENTRY_POLICY_DIGEST_OFFSET_V1);
        let receipt_bytes = read_array(encoded, ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1);
        let outcome = match read_u16(encoded, ENTRY_OUTCOME_KIND_OFFSET_V1) {
            SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1 => {
                if !is_all_zero(&policy_bytes) || !is_all_zero(&receipt_bytes) {
                    return Err(SourceOutcomeTableErrorV1::NoncanonicalConditionalFields);
                }
                AcquisitionOutcome::Persisted {
                    event_id: EventId::from_bytes(event_bytes),
                    exactness_basis: ExactnessBasis::SourceExact,
                }
            }
            SOURCE_OUTCOME_POST_POLICY_KIND_V1 => AcquisitionOutcome::Persisted {
                event_id: EventId::from_bytes(event_bytes),
                exactness_basis: ExactnessBasis::PostPolicy {
                    policy_digest: PolicyDigest::from_bytes(policy_bytes),
                    transformation_receipt_id: TransformationReceiptId::from_bytes(receipt_bytes),
                },
            },
            SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1 => {
                if !is_all_zero(&event_bytes) || !is_all_zero(&receipt_bytes) {
                    return Err(SourceOutcomeTableErrorV1::NoncanonicalConditionalFields);
                }
                AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes(policy_bytes),
                }
            }
            _ => return Err(SourceOutcomeTableErrorV1::UnsupportedOutcomeKind),
        };
        Ok(Self {
            acquisition_ordinal,
            source_record_id: SourceRecordId::from_bytes(read_array(
                encoded,
                ENTRY_SOURCE_RECORD_ID_OFFSET_V1,
            )),
            outcome,
        })
    }
}

impl fmt::Debug for SourceOutcomeTableEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceOutcomeTableEntryV1(<redacted>)")
    }
}

/// Canonical receipt-ordered source-outcome component of manifest plaintext.
///
/// This table plus the event index is not `FetchCompletion`, a plan/source
/// binding, frame authentication or open, outer manifest authentication,
/// recovery, filesystem durability, or proof of a sealed result.
#[derive(PartialEq, Eq)]
pub struct SourceOutcomeTableV1 {
    retrieval_id: RetrievalId,
    entries: Vec<SourceOutcomeTableEntryV1>,
    source_exact_count: u64,
    post_policy_count: u64,
    omitted_by_policy_count: u64,
    event_index_entry_count: u64,
    event_index_digest: EventExpansionIndexDigestV1,
}

impl SourceOutcomeTableV1 {
    pub fn new(
        receipt: &AcquisitionReceipt,
        event_index: &EventExpansionIndexV1,
    ) -> Result<Self, SourceOutcomeTableErrorV1> {
        validate_entry_count(receipt.acknowledged_count())?;
        let mut entries = Vec::with_capacity(receipt.acknowledged_count());
        for (ordinal, receipt_entry) in (0u64..).zip(receipt.entries()) {
            entries.push(SourceOutcomeTableEntryV1 {
                acquisition_ordinal: ordinal,
                source_record_id: receipt_entry.source_record_id(),
                outcome: receipt_entry.outcome().clone(),
            });
        }
        validate_unique_entries(&entries)?;
        validate_bijection(&entries, event_index)?;
        let (source_exact_count, post_policy_count, omitted_by_policy_count) =
            derive_counts(&entries)?;
        let receipt_counts = receipt.counts();
        if source_exact_count != usize_to_u64(receipt_counts.source_exact)?
            || post_policy_count != usize_to_u64(receipt_counts.post_policy)?
            || omitted_by_policy_count != usize_to_u64(receipt_counts.omitted_by_policy)?
        {
            return Err(SourceOutcomeTableErrorV1::ReceiptCountsMismatch);
        }
        Ok(Self {
            retrieval_id: receipt.retrieval_id(),
            entries,
            source_exact_count,
            post_policy_count,
            omitted_by_policy_count,
            event_index_entry_count: event_index.entry_count(),
            event_index_digest: derive_event_expansion_index_digest_v1(event_index),
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        SOURCE_OUTCOME_TABLE_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        SOURCE_OUTCOME_TABLE_SCHEMA_V1
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub fn entries(&self) -> &[SourceOutcomeTableEntryV1] {
        &self.entries
    }

    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entries.len() as u64
    }

    #[must_use]
    pub const fn source_exact_count(&self) -> u64 {
        self.source_exact_count
    }

    #[must_use]
    pub const fn post_policy_count(&self) -> u64 {
        self.post_policy_count
    }

    #[must_use]
    pub const fn omitted_by_policy_count(&self) -> u64 {
        self.omitted_by_policy_count
    }

    #[must_use]
    pub const fn event_index_entry_count(&self) -> u64 {
        self.event_index_entry_count
    }

    #[must_use]
    pub const fn event_index_digest(&self) -> EventExpansionIndexDigestV1 {
        self.event_index_digest
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1
            + self.entries.len() * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        let mut header = [0u8; SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1];
        header[0..8].copy_from_slice(&SOURCE_OUTCOME_TABLE_MAGIC_V1);
        header[8..10].copy_from_slice(&SOURCE_OUTCOME_TABLE_VERSION_V1.to_be_bytes());
        header[10..12].copy_from_slice(&SOURCE_OUTCOME_TABLE_SCHEMA_V1.to_be_bytes());
        header[12..14].copy_from_slice(&SOURCE_OUTCOME_TABLE_OBJECT_KIND_V1.to_be_bytes());
        header[14..16].copy_from_slice(&(SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1 as u16).to_be_bytes());
        header[HEADER_FLAGS_OFFSET_V1..HEADER_RESERVED_ONE_OFFSET_V1]
            .copy_from_slice(&0u16.to_be_bytes());
        header[HEADER_RETRIEVAL_ID_OFFSET_V1..HEADER_ENTRY_COUNT_OFFSET_V1]
            .copy_from_slice(self.retrieval_id.as_bytes());
        header[HEADER_ENTRY_COUNT_OFFSET_V1..HEADER_SOURCE_EXACT_COUNT_OFFSET_V1]
            .copy_from_slice(&self.entry_count().to_be_bytes());
        header[HEADER_SOURCE_EXACT_COUNT_OFFSET_V1..HEADER_POST_POLICY_COUNT_OFFSET_V1]
            .copy_from_slice(&self.source_exact_count.to_be_bytes());
        header[HEADER_POST_POLICY_COUNT_OFFSET_V1..HEADER_OMITTED_COUNT_OFFSET_V1]
            .copy_from_slice(&self.post_policy_count.to_be_bytes());
        header[HEADER_OMITTED_COUNT_OFFSET_V1..HEADER_INDEX_ENTRY_COUNT_OFFSET_V1]
            .copy_from_slice(&self.omitted_by_policy_count.to_be_bytes());
        header[HEADER_INDEX_ENTRY_COUNT_OFFSET_V1..HEADER_INDEX_DIGEST_OFFSET_V1]
            .copy_from_slice(&self.event_index_entry_count.to_be_bytes());
        header[HEADER_INDEX_DIGEST_OFFSET_V1..HEADER_RESERVED_TWO_OFFSET_V1]
            .copy_from_slice(self.event_index_digest.as_bytes());
        encoded.extend_from_slice(&header);
        for entry in &self.entries {
            encoded.extend_from_slice(&entry.encode());
        }
        encoded
    }

    pub fn decode(
        event_index: &EventExpansionIndexV1,
        encoded: &[u8],
    ) -> Result<Self, SourceOutcomeTableErrorV1> {
        if encoded.len() < SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1 {
            return Err(SourceOutcomeTableErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != SOURCE_OUTCOME_TABLE_MAGIC_V1 {
            return Err(SourceOutcomeTableErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != SOURCE_OUTCOME_TABLE_VERSION_V1 {
            return Err(SourceOutcomeTableErrorV1::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != SOURCE_OUTCOME_TABLE_SCHEMA_V1 {
            return Err(SourceOutcomeTableErrorV1::UnsupportedSchema);
        }
        if read_u16(encoded, 12) != SOURCE_OUTCOME_TABLE_OBJECT_KIND_V1 {
            return Err(SourceOutcomeTableErrorV1::UnsupportedObjectKind);
        }
        if usize::from(read_u16(encoded, 14)) != SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1 {
            return Err(SourceOutcomeTableErrorV1::InvalidEntryWidth);
        }
        if read_u16(encoded, HEADER_FLAGS_OFFSET_V1) != 0 {
            return Err(SourceOutcomeTableErrorV1::NonzeroFlags);
        }
        if encoded[HEADER_RESERVED_ONE_OFFSET_V1..HEADER_RETRIEVAL_ID_OFFSET_V1]
            .iter()
            .chain(
                encoded[HEADER_RESERVED_TWO_OFFSET_V1..SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1].iter(),
            )
            .any(|byte| *byte != 0)
        {
            return Err(SourceOutcomeTableErrorV1::NonzeroReserved);
        }

        let declared_entry_count = read_u64(encoded, HEADER_ENTRY_COUNT_OFFSET_V1);
        validate_declared_entry_count(declared_entry_count)?;
        let entry_count = usize::try_from(declared_entry_count)
            .map_err(|_| SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
        let entry_bytes = entry_count
            .checked_mul(SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1)
            .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
        let expected_length = SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1
            .checked_add(entry_bytes)
            .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
        if expected_length > MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1
            || encoded.len() != expected_length
        {
            return Err(SourceOutcomeTableErrorV1::InvalidEncodedLength);
        }
        let retrieval_id =
            RetrievalId::from_bytes(read_array(encoded, HEADER_RETRIEVAL_ID_OFFSET_V1));
        if read_u64(encoded, HEADER_INDEX_ENTRY_COUNT_OFFSET_V1) != event_index.entry_count() {
            return Err(SourceOutcomeTableErrorV1::IndexEntryCountMismatch);
        }
        if EventExpansionIndexDigestV1::from_bytes(read_array(
            encoded,
            HEADER_INDEX_DIGEST_OFFSET_V1,
        )) != derive_event_expansion_index_digest_v1(event_index)
        {
            return Err(SourceOutcomeTableErrorV1::IndexDigestMismatch);
        }

        let mut entries = Vec::with_capacity(entry_count);
        for index in 0..entry_count {
            let start =
                SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1 + index * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;
            let end = start + SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;
            entries.push(SourceOutcomeTableEntryV1::decode(
                u64::try_from(index).map_err(|_| SourceOutcomeTableErrorV1::ArithmeticOverflow)?,
                &encoded[start..end],
            )?);
        }
        validate_unique_entries(&entries)?;
        let (source_exact_count, post_policy_count, omitted_by_policy_count) =
            derive_counts(&entries)?;
        if read_u64(encoded, HEADER_SOURCE_EXACT_COUNT_OFFSET_V1) != source_exact_count
            || read_u64(encoded, HEADER_POST_POLICY_COUNT_OFFSET_V1) != post_policy_count
            || read_u64(encoded, HEADER_OMITTED_COUNT_OFFSET_V1) != omitted_by_policy_count
        {
            return Err(SourceOutcomeTableErrorV1::DeclaredCountsMismatch);
        }
        let derived_entry_count = source_exact_count
            .checked_add(post_policy_count)
            .and_then(|value| value.checked_add(omitted_by_policy_count))
            .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
        if derived_entry_count != declared_entry_count {
            return Err(SourceOutcomeTableErrorV1::DeclaredCountsMismatch);
        }
        let persisted_count = source_exact_count
            .checked_add(post_policy_count)
            .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
        if persisted_count != event_index.entry_count() {
            return Err(SourceOutcomeTableErrorV1::IndexEntryCountMismatch);
        }
        validate_bijection(&entries, event_index)?;
        let table = Self {
            retrieval_id,
            entries,
            source_exact_count,
            post_policy_count,
            omitted_by_policy_count,
            event_index_entry_count: event_index.entry_count(),
            event_index_digest: derive_event_expansion_index_digest_v1(event_index),
        };
        table.to_acquisition_receipt()?;
        Ok(table)
    }

    /// Reconstruct the exact canonical acquisition receipt represented by this
    /// self-contained manifest component.
    pub fn to_acquisition_receipt(&self) -> Result<AcquisitionReceipt, SourceOutcomeTableErrorV1> {
        let expected = self.entries.iter().map(|entry| entry.source_record_id);
        let assignments = self.entries.iter().map(|entry| {
            AcquisitionOutcomeAssignment::new(entry.source_record_id, entry.outcome.clone())
        });
        AcquisitionReceipt::reconcile(self.retrieval_id, expected, assignments)
            .map_err(|_| SourceOutcomeTableErrorV1::ReceiptReconstructionFailed)
    }

    /// Verify that an independently retained receipt is byte-semantically
    /// identical to this table. It is not required to open the snapshot.
    pub fn verify_against_receipt(
        &self,
        receipt: &AcquisitionReceipt,
    ) -> Result<(), SourceOutcomeTableErrorV1> {
        if self.retrieval_id != receipt.retrieval_id() {
            return Err(SourceOutcomeTableErrorV1::RetrievalMismatch);
        }
        if self.entries.len() != receipt.acknowledged_count() {
            return Err(SourceOutcomeTableErrorV1::ReceiptEntryCountMismatch);
        }
        let receipt_counts = receipt.counts();
        if self.source_exact_count != usize_to_u64(receipt_counts.source_exact)?
            || self.post_policy_count != usize_to_u64(receipt_counts.post_policy)?
            || self.omitted_by_policy_count != usize_to_u64(receipt_counts.omitted_by_policy)?
        {
            return Err(SourceOutcomeTableErrorV1::ReceiptCountsMismatch);
        }
        for (entry, receipt_entry) in self.entries.iter().zip(receipt.entries()) {
            if entry.source_record_id != receipt_entry.source_record_id()
                || &entry.outcome != receipt_entry.outcome()
            {
                return Err(SourceOutcomeTableErrorV1::ReceiptEntryMismatch);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SourceOutcomeTableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceOutcomeTableV1(<redacted>)")
    }
}

fn validate_entry_count(entry_count: usize) -> Result<(), SourceOutcomeTableErrorV1> {
    validate_declared_entry_count(usize_to_u64(entry_count)?)
}

fn validate_declared_entry_count(entry_count: u64) -> Result<(), SourceOutcomeTableErrorV1> {
    if entry_count > MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1 {
        return Err(SourceOutcomeTableErrorV1::EntryCountCap);
    }
    Ok(())
}

fn validate_unique_entries(
    entries: &[SourceOutcomeTableEntryV1],
) -> Result<(), SourceOutcomeTableErrorV1> {
    let mut source_records = BTreeSet::new();
    let mut persisted_events = BTreeSet::new();
    for entry in entries {
        if !source_records.insert(entry.source_record_id) {
            return Err(SourceOutcomeTableErrorV1::DuplicateSourceRecordId);
        }
        if let Some(event_id) = entry.outcome.persisted_event_id() {
            if !persisted_events.insert(event_id) {
                return Err(SourceOutcomeTableErrorV1::DuplicatePersistedEventId);
            }
        }
    }
    Ok(())
}

fn validate_bijection(
    entries: &[SourceOutcomeTableEntryV1],
    event_index: &EventExpansionIndexV1,
) -> Result<(), SourceOutcomeTableErrorV1> {
    let mut indexed = event_index
        .entries()
        .iter()
        .map(|entry| (entry.event_id(), entry.exactness_basis()))
        .collect::<BTreeMap<_, _>>();
    for entry in entries {
        if let AcquisitionOutcome::Persisted {
            event_id,
            exactness_basis,
        } = &entry.outcome
        {
            let indexed_exactness = indexed
                .remove(event_id)
                .ok_or(SourceOutcomeTableErrorV1::MissingIndexEvent)?;
            if indexed_exactness != *exactness_basis {
                return Err(SourceOutcomeTableErrorV1::IndexExactnessMismatch);
            }
        }
    }
    if !indexed.is_empty() {
        return Err(SourceOutcomeTableErrorV1::ExtraIndexEvent);
    }
    Ok(())
}

fn derive_counts(
    entries: &[SourceOutcomeTableEntryV1],
) -> Result<(u64, u64, u64), SourceOutcomeTableErrorV1> {
    let mut source_exact = 0u64;
    let mut post_policy = 0u64;
    let mut omitted = 0u64;
    for entry in entries {
        match &entry.outcome {
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::SourceExact,
                ..
            } => {
                source_exact = source_exact
                    .checked_add(1)
                    .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
            }
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::PostPolicy { .. },
                ..
            } => {
                post_policy = post_policy
                    .checked_add(1)
                    .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
            }
            AcquisitionOutcome::OmittedByPolicy { .. } => {
                omitted = omitted
                    .checked_add(1)
                    .ok_or(SourceOutcomeTableErrorV1::ArithmeticOverflow)?;
            }
        }
    }
    Ok((source_exact, post_policy, omitted))
}

fn usize_to_u64(value: usize) -> Result<u64, SourceOutcomeTableErrorV1> {
    u64::try_from(value).map_err(|_| SourceOutcomeTableErrorV1::ArithmeticOverflow)
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

const _: () = assert!(SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1 <= u16::MAX as usize);
const _: () = assert!(MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1 <= MAX_MANIFEST_PLAINTEXT_BYTES_V1);
