use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{EventId, ExactnessBasis, PolicyDigest, TransformationReceiptId};
use sha2::{Digest, Sha256};

use crate::{
    FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1, FrameObjectKindV1, MAX_ENCODED_FRAME_BYTES_V1,
    MAX_MANIFEST_PLAINTEXT_BYTES_V1, SEGMENT_HEADER_BYTES_V1, SegmentCatalogV1,
};

pub const EVENT_EXPANSION_INDEX_VERSION_V1: u16 = 1;
pub const EVENT_EXPANSION_INDEX_SCHEMA_V1: u16 = 1;
pub const EVENT_EXPANSION_INDEX_OBJECT_KIND_V1: u16 = 1;
pub const EVENT_EXPANSION_INDEX_HEADER_BYTES_V1: usize = 144;
pub const EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1: usize = 160;
pub const SEGMENT_CATALOG_DIGEST_BYTES_V1: usize = 32;
pub const EVENT_EXPANSION_SOURCE_EXACT_KIND_V1: u16 = 1;
pub const EVENT_EXPANSION_POST_POLICY_KIND_V1: u16 = 2;
/// Component-local allocation cap derived from the existing outer manifest
/// plaintext bound. A future combined manifest must impose a lower shared cap.
pub const MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1: u64 =
    ((MAX_MANIFEST_PLAINTEXT_BYTES_V1 - EVENT_EXPANSION_INDEX_HEADER_BYTES_V1)
        / EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1) as u64;
pub const MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1: usize = EVENT_EXPANSION_INDEX_HEADER_BYTES_V1
    + MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1 as usize * EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1;

const EVENT_EXPANSION_INDEX_MAGIC_V1: [u8; 8] = *b"EVREIX01";
const MIN_ENCODED_FRAME_BYTES_V1: u64 = (FRAME_HEADER_BYTES_V1 + FRAME_TAG_BYTES_V1) as u64;

const HEADER_FLAGS_OFFSET_V1: usize = 16;
const HEADER_RESERVED_ONE_OFFSET_V1: usize = 18;
const HEADER_ENTRY_COUNT_OFFSET_V1: usize = 24;
const HEADER_CATALOG_SEGMENT_COUNT_OFFSET_V1: usize = 32;
const HEADER_CATALOG_FRAME_COUNT_OFFSET_V1: usize = 40;
const HEADER_TOTAL_FRAME_BYTES_OFFSET_V1: usize = 48;
const HEADER_TOTAL_AUTHORIZED_BYTES_OFFSET_V1: usize = 56;
const HEADER_CATALOG_CHAIN_ROOT_OFFSET_V1: usize = 64;
const HEADER_CATALOG_DIGEST_OFFSET_V1: usize = 96;
const HEADER_RESERVED_TWO_OFFSET_V1: usize = 128;

const ENTRY_EVENT_ID_OFFSET_V1: usize = 0;
const ENTRY_SEGMENT_SEQUENCE_OFFSET_V1: usize = 32;
const ENTRY_GLOBAL_FRAME_SEQUENCE_OFFSET_V1: usize = 40;
const ENTRY_SEGMENT_FRAME_SEQUENCE_OFFSET_V1: usize = 48;
const ENTRY_FRAME_OBJECT_KIND_OFFSET_V1: usize = 52;
const ENTRY_EXACTNESS_KIND_OFFSET_V1: usize = 54;
const ENTRY_FRAME_OFFSET_OFFSET_V1: usize = 56;
const ENTRY_FRAME_ENCODED_LENGTH_OFFSET_V1: usize = 64;
const ENTRY_AUTHORIZED_OFFSET_OFFSET_V1: usize = 68;
const ENTRY_AUTHORIZED_LENGTH_OFFSET_V1: usize = 72;
const ENTRY_RESERVED_ONE_OFFSET_V1: usize = 76;
const ENTRY_POLICY_DIGEST_OFFSET_V1: usize = 80;
const ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1: usize = 112;
const ENTRY_RESERVED_TWO_OFFSET_V1: usize = 144;

/// Stable, contentless failure returned by the V1 event expansion index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventExpansionIndexErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    UnsupportedIndexObjectKind,
    InvalidEntryWidth,
    NonzeroFlags,
    NonzeroReserved,
    EntryCountCap,
    EntryCountExceedsCatalogFrames,
    DuplicateEventId,
    NoncanonicalEventOrder,
    DuplicateFrameAssignment,
    UnknownSegment,
    SegmentFrameSequenceOutOfRange,
    FrameSequenceMismatch,
    InvalidFrameEncodedLength,
    FrameEncodedLengthCap,
    FrameRangeOverflow,
    FrameOutsideSegment,
    FrameLocatorOverlap,
    AuthorizedByteRangeOverflow,
    AuthorizedBytesOutsideFrame,
    UnsupportedFrameObjectKind,
    UnsupportedExactnessKind,
    NoncanonicalSourceExactFields,
    CatalogSegmentCountMismatch,
    CatalogFrameCountMismatch,
    CatalogChainRootMismatch,
    CatalogDigestMismatch,
    TotalFrameBytesMismatch,
    TotalAuthorizedBytesMismatch,
    ArithmeticOverflow,
}

impl EventExpansionIndexErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_EVENT_INDEX_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_EVENT_INDEX_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_EVENT_INDEX_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_EVENT_INDEX_UNSUPPORTED_SCHEMA",
            Self::UnsupportedIndexObjectKind => "EVIDENTRAIL_EVENT_INDEX_UNSUPPORTED_INDEX_OBJECT_KIND",
            Self::InvalidEntryWidth => "EVIDENTRAIL_EVENT_INDEX_INVALID_ENTRY_WIDTH",
            Self::NonzeroFlags => "EVIDENTRAIL_EVENT_INDEX_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_EVENT_INDEX_NONZERO_RESERVED",
            Self::EntryCountCap => "EVIDENTRAIL_EVENT_INDEX_ENTRY_COUNT_CAP",
            Self::EntryCountExceedsCatalogFrames => {
                "EVIDENTRAIL_EVENT_INDEX_ENTRY_COUNT_EXCEEDS_CATALOG_FRAMES"
            }
            Self::DuplicateEventId => "EVIDENTRAIL_EVENT_INDEX_DUPLICATE_EVENT_ID",
            Self::NoncanonicalEventOrder => "EVIDENTRAIL_EVENT_INDEX_NONCANONICAL_EVENT_ORDER",
            Self::DuplicateFrameAssignment => "EVIDENTRAIL_EVENT_INDEX_DUPLICATE_FRAME_ASSIGNMENT",
            Self::UnknownSegment => "EVIDENTRAIL_EVENT_INDEX_UNKNOWN_SEGMENT",
            Self::SegmentFrameSequenceOutOfRange => {
                "EVIDENTRAIL_EVENT_INDEX_SEGMENT_FRAME_SEQUENCE_OUT_OF_RANGE"
            }
            Self::FrameSequenceMismatch => "EVIDENTRAIL_EVENT_INDEX_FRAME_SEQUENCE_MISMATCH",
            Self::InvalidFrameEncodedLength => "EVIDENTRAIL_EVENT_INDEX_INVALID_FRAME_ENCODED_LENGTH",
            Self::FrameEncodedLengthCap => "EVIDENTRAIL_EVENT_INDEX_FRAME_ENCODED_LENGTH_CAP",
            Self::FrameRangeOverflow => "EVIDENTRAIL_EVENT_INDEX_FRAME_RANGE_OVERFLOW",
            Self::FrameOutsideSegment => "EVIDENTRAIL_EVENT_INDEX_FRAME_OUTSIDE_SEGMENT",
            Self::FrameLocatorOverlap => "EVIDENTRAIL_EVENT_INDEX_FRAME_LOCATOR_OVERLAP",
            Self::AuthorizedByteRangeOverflow => "EVIDENTRAIL_EVENT_INDEX_AUTHORIZED_BYTE_RANGE_OVERFLOW",
            Self::AuthorizedBytesOutsideFrame => "EVIDENTRAIL_EVENT_INDEX_AUTHORIZED_BYTES_OUTSIDE_FRAME",
            Self::UnsupportedFrameObjectKind => "EVIDENTRAIL_EVENT_INDEX_UNSUPPORTED_FRAME_OBJECT_KIND",
            Self::UnsupportedExactnessKind => "EVIDENTRAIL_EVENT_INDEX_UNSUPPORTED_EXACTNESS_KIND",
            Self::NoncanonicalSourceExactFields => {
                "EVIDENTRAIL_EVENT_INDEX_NONCANONICAL_SOURCE_EXACT_FIELDS"
            }
            Self::CatalogSegmentCountMismatch => "EVIDENTRAIL_EVENT_INDEX_CATALOG_SEGMENT_COUNT_MISMATCH",
            Self::CatalogFrameCountMismatch => "EVIDENTRAIL_EVENT_INDEX_CATALOG_FRAME_COUNT_MISMATCH",
            Self::CatalogChainRootMismatch => "EVIDENTRAIL_EVENT_INDEX_CATALOG_CHAIN_ROOT_MISMATCH",
            Self::CatalogDigestMismatch => "EVIDENTRAIL_EVENT_INDEX_CATALOG_DIGEST_MISMATCH",
            Self::TotalFrameBytesMismatch => "EVIDENTRAIL_EVENT_INDEX_TOTAL_FRAME_BYTES_MISMATCH",
            Self::TotalAuthorizedBytesMismatch => {
                "EVIDENTRAIL_EVENT_INDEX_TOTAL_AUTHORIZED_BYTES_MISMATCH"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_EVENT_INDEX_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for EventExpansionIndexErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventExpansionIndexErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EventExpansionIndexErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EventExpansionIndexErrorV1 {}

/// SHA-256 binding to the exact canonical `SegmentCatalogV1::encode()` bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentCatalogDigestV1([u8; SEGMENT_CATALOG_DIGEST_BYTES_V1]);

impl SegmentCatalogDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEGMENT_CATALOG_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEGMENT_CATALOG_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for SegmentCatalogDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SegmentCatalogDigestV1(<redacted>)")
    }
}

/// Hash the exact canonical catalog artifact used to interpret index locators.
#[must_use]
pub fn derive_segment_catalog_digest_v1(catalog: &SegmentCatalogV1) -> SegmentCatalogDigestV1 {
    SegmentCatalogDigestV1::from_bytes(Sha256::digest(catalog.encode()).into())
}

/// Byte and sequence coordinates proposed for one complete encoded frame.
///
/// Catalog aggregates permit bounded range and sequence validation, but cannot
/// prove that `frame_offset` is an authenticated frame boundary. A future open
/// path must parse and authenticate the referenced frame header and AEAD object.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EventFrameLocatorV1 {
    segment_sequence: u64,
    global_frame_sequence: u64,
    segment_frame_sequence: u32,
    frame_offset: u64,
    frame_encoded_length: u32,
}

impl EventFrameLocatorV1 {
    pub fn new(
        segment_sequence: u64,
        global_frame_sequence: u64,
        segment_frame_sequence: u32,
        frame_offset: u64,
        frame_encoded_length: u32,
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        if u64::from(frame_encoded_length) < MIN_ENCODED_FRAME_BYTES_V1 {
            return Err(EventExpansionIndexErrorV1::InvalidFrameEncodedLength);
        }
        if usize::try_from(frame_encoded_length)
            .map_err(|_| EventExpansionIndexErrorV1::ArithmeticOverflow)?
            > MAX_ENCODED_FRAME_BYTES_V1
        {
            return Err(EventExpansionIndexErrorV1::FrameEncodedLengthCap);
        }
        frame_offset
            .checked_add(u64::from(frame_encoded_length))
            .ok_or(EventExpansionIndexErrorV1::FrameRangeOverflow)?;
        Ok(Self {
            segment_sequence,
            global_frame_sequence,
            segment_frame_sequence,
            frame_offset,
            frame_encoded_length,
        })
    }

    #[must_use]
    pub const fn segment_sequence(&self) -> u64 {
        self.segment_sequence
    }

    #[must_use]
    pub const fn global_frame_sequence(&self) -> u64 {
        self.global_frame_sequence
    }

    #[must_use]
    pub const fn segment_frame_sequence(&self) -> u32 {
        self.segment_frame_sequence
    }

    #[must_use]
    pub const fn frame_offset(&self) -> u64 {
        self.frame_offset
    }

    #[must_use]
    pub const fn frame_encoded_length(&self) -> u32 {
        self.frame_encoded_length
    }

    fn frame_end(&self) -> u64 {
        self.frame_offset + u64::from(self.frame_encoded_length)
    }
}

impl fmt::Debug for EventFrameLocatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventFrameLocatorV1(<redacted>)")
    }
}

/// Exact byte range of the authorized event bytes in decrypted frame plaintext.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedByteRangeV1 {
    offset: u32,
    length: u32,
}

impl AuthorizedByteRangeV1 {
    pub fn new(offset: u32, length: u32) -> Result<Self, EventExpansionIndexErrorV1> {
        offset
            .checked_add(length)
            .ok_or(EventExpansionIndexErrorV1::AuthorizedByteRangeOverflow)?;
        Ok(Self { offset, length })
    }

    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    #[must_use]
    pub const fn length(&self) -> u32 {
        self.length
    }

    fn end_exclusive(&self) -> u64 {
        u64::from(self.offset) + u64::from(self.length)
    }
}

impl fmt::Debug for AuthorizedByteRangeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedByteRangeV1(<redacted>)")
    }
}

/// One canonical EventId-to-authorized-outcome frame locator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EventExpansionIndexEntryV1 {
    event_id: EventId,
    frame_locator: EventFrameLocatorV1,
    authorized_bytes: AuthorizedByteRangeV1,
    exactness_basis: ExactnessBasis,
}

impl EventExpansionIndexEntryV1 {
    pub fn new(
        catalog: &SegmentCatalogV1,
        event_id: EventId,
        frame_locator: EventFrameLocatorV1,
        authorized_bytes: AuthorizedByteRangeV1,
        exactness_basis: ExactnessBasis,
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        let entry = Self {
            event_id,
            frame_locator,
            authorized_bytes,
            exactness_basis,
        };
        entry.validate_against(catalog)?;
        Ok(entry)
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn frame_locator(&self) -> EventFrameLocatorV1 {
        self.frame_locator
    }

    #[must_use]
    pub const fn authorized_bytes(&self) -> AuthorizedByteRangeV1 {
        self.authorized_bytes
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn frame_object_kind(&self) -> FrameObjectKindV1 {
        FrameObjectKindV1::AuthorizedOutcome
    }

    #[must_use]
    pub fn encode(&self) -> [u8; EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1] {
        let mut encoded = [0u8; EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1];
        encoded[ENTRY_EVENT_ID_OFFSET_V1..ENTRY_SEGMENT_SEQUENCE_OFFSET_V1]
            .copy_from_slice(self.event_id.as_bytes());
        encoded[ENTRY_SEGMENT_SEQUENCE_OFFSET_V1..ENTRY_GLOBAL_FRAME_SEQUENCE_OFFSET_V1]
            .copy_from_slice(&self.frame_locator.segment_sequence.to_be_bytes());
        encoded[ENTRY_GLOBAL_FRAME_SEQUENCE_OFFSET_V1..ENTRY_SEGMENT_FRAME_SEQUENCE_OFFSET_V1]
            .copy_from_slice(&self.frame_locator.global_frame_sequence.to_be_bytes());
        encoded[ENTRY_SEGMENT_FRAME_SEQUENCE_OFFSET_V1..ENTRY_FRAME_OBJECT_KIND_OFFSET_V1]
            .copy_from_slice(&self.frame_locator.segment_frame_sequence.to_be_bytes());
        encoded[ENTRY_FRAME_OBJECT_KIND_OFFSET_V1..ENTRY_EXACTNESS_KIND_OFFSET_V1]
            .copy_from_slice(&FrameObjectKindV1::AuthorizedOutcome.code().to_be_bytes());
        let exactness_code = match self.exactness_basis {
            ExactnessBasis::SourceExact => EVENT_EXPANSION_SOURCE_EXACT_KIND_V1,
            ExactnessBasis::PostPolicy { .. } => EVENT_EXPANSION_POST_POLICY_KIND_V1,
        };
        encoded[ENTRY_EXACTNESS_KIND_OFFSET_V1..ENTRY_FRAME_OFFSET_OFFSET_V1]
            .copy_from_slice(&exactness_code.to_be_bytes());
        encoded[ENTRY_FRAME_OFFSET_OFFSET_V1..ENTRY_FRAME_ENCODED_LENGTH_OFFSET_V1]
            .copy_from_slice(&self.frame_locator.frame_offset.to_be_bytes());
        encoded[ENTRY_FRAME_ENCODED_LENGTH_OFFSET_V1..ENTRY_AUTHORIZED_OFFSET_OFFSET_V1]
            .copy_from_slice(&self.frame_locator.frame_encoded_length.to_be_bytes());
        encoded[ENTRY_AUTHORIZED_OFFSET_OFFSET_V1..ENTRY_AUTHORIZED_LENGTH_OFFSET_V1]
            .copy_from_slice(&self.authorized_bytes.offset.to_be_bytes());
        encoded[ENTRY_AUTHORIZED_LENGTH_OFFSET_V1..ENTRY_RESERVED_ONE_OFFSET_V1]
            .copy_from_slice(&self.authorized_bytes.length.to_be_bytes());
        if let ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        } = self.exactness_basis
        {
            encoded[ENTRY_POLICY_DIGEST_OFFSET_V1..ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1]
                .copy_from_slice(policy_digest.as_bytes());
            encoded[ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1..ENTRY_RESERVED_TWO_OFFSET_V1]
                .copy_from_slice(transformation_receipt_id.as_bytes());
        }
        encoded
    }

    pub fn decode(
        catalog: &SegmentCatalogV1,
        encoded: &[u8],
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        if encoded.len() != EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1 {
            return Err(EventExpansionIndexErrorV1::InvalidEncodedLength);
        }
        if encoded[ENTRY_RESERVED_ONE_OFFSET_V1..ENTRY_POLICY_DIGEST_OFFSET_V1]
            .iter()
            .chain(encoded[ENTRY_RESERVED_TWO_OFFSET_V1..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(EventExpansionIndexErrorV1::NonzeroReserved);
        }
        if read_u16(encoded, ENTRY_FRAME_OBJECT_KIND_OFFSET_V1)
            != FrameObjectKindV1::AuthorizedOutcome.code()
        {
            return Err(EventExpansionIndexErrorV1::UnsupportedFrameObjectKind);
        }

        let policy_bytes = read_array(encoded, ENTRY_POLICY_DIGEST_OFFSET_V1);
        let receipt_bytes = read_array(encoded, ENTRY_TRANSFORMATION_RECEIPT_OFFSET_V1);
        let exactness_basis = match read_u16(encoded, ENTRY_EXACTNESS_KIND_OFFSET_V1) {
            EVENT_EXPANSION_SOURCE_EXACT_KIND_V1 => {
                if !is_all_zero(&policy_bytes) || !is_all_zero(&receipt_bytes) {
                    return Err(EventExpansionIndexErrorV1::NoncanonicalSourceExactFields);
                }
                ExactnessBasis::SourceExact
            }
            EVENT_EXPANSION_POST_POLICY_KIND_V1 => ExactnessBasis::PostPolicy {
                policy_digest: PolicyDigest::from_bytes(policy_bytes),
                transformation_receipt_id: TransformationReceiptId::from_bytes(receipt_bytes),
            },
            _ => return Err(EventExpansionIndexErrorV1::UnsupportedExactnessKind),
        };
        let frame_locator = EventFrameLocatorV1::new(
            read_u64(encoded, ENTRY_SEGMENT_SEQUENCE_OFFSET_V1),
            read_u64(encoded, ENTRY_GLOBAL_FRAME_SEQUENCE_OFFSET_V1),
            read_u32(encoded, ENTRY_SEGMENT_FRAME_SEQUENCE_OFFSET_V1),
            read_u64(encoded, ENTRY_FRAME_OFFSET_OFFSET_V1),
            read_u32(encoded, ENTRY_FRAME_ENCODED_LENGTH_OFFSET_V1),
        )?;
        let authorized_bytes = AuthorizedByteRangeV1::new(
            read_u32(encoded, ENTRY_AUTHORIZED_OFFSET_OFFSET_V1),
            read_u32(encoded, ENTRY_AUTHORIZED_LENGTH_OFFSET_V1),
        )?;
        Self::new(
            catalog,
            EventId::from_bytes(read_array(encoded, ENTRY_EVENT_ID_OFFSET_V1)),
            frame_locator,
            authorized_bytes,
            exactness_basis,
        )
    }

    fn validate_against(
        &self,
        catalog: &SegmentCatalogV1,
    ) -> Result<(), EventExpansionIndexErrorV1> {
        let segment_index = usize::try_from(self.frame_locator.segment_sequence)
            .map_err(|_| EventExpansionIndexErrorV1::UnknownSegment)?;
        let segment = catalog
            .entries()
            .get(segment_index)
            .ok_or(EventExpansionIndexErrorV1::UnknownSegment)?;
        if segment.segment_sequence() != self.frame_locator.segment_sequence {
            return Err(EventExpansionIndexErrorV1::UnknownSegment);
        }
        if self.frame_locator.segment_frame_sequence >= segment.frame_count() {
            return Err(EventExpansionIndexErrorV1::SegmentFrameSequenceOutOfRange);
        }
        let expected_global_sequence = segment
            .first_global_frame_sequence()
            .checked_add(u64::from(self.frame_locator.segment_frame_sequence))
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        if self.frame_locator.global_frame_sequence != expected_global_sequence {
            return Err(EventExpansionIndexErrorV1::FrameSequenceMismatch);
        }

        let preceding_minimum = u64::from(self.frame_locator.segment_frame_sequence)
            .checked_mul(MIN_ENCODED_FRAME_BYTES_V1)
            .and_then(|value| value.checked_add(SEGMENT_HEADER_BYTES_V1 as u64))
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        if self.frame_locator.frame_offset < preceding_minimum {
            return Err(EventExpansionIndexErrorV1::FrameOutsideSegment);
        }
        let frame_end = self.frame_locator.frame_end();
        let remaining_frames = segment
            .frame_count()
            .checked_sub(self.frame_locator.segment_frame_sequence)
            .and_then(|value| value.checked_sub(1))
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        let remaining_minimum = u64::from(remaining_frames)
            .checked_mul(MIN_ENCODED_FRAME_BYTES_V1)
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        let maximum_frame_end = segment
            .encoded_byte_count()
            .checked_sub(remaining_minimum)
            .ok_or(EventExpansionIndexErrorV1::FrameOutsideSegment)?;
        if frame_end > maximum_frame_end {
            return Err(EventExpansionIndexErrorV1::FrameOutsideSegment);
        }

        let frame_ciphertext_bytes = u64::from(self.frame_locator.frame_encoded_length)
            .checked_sub(FRAME_HEADER_BYTES_V1 as u64)
            .ok_or(EventExpansionIndexErrorV1::InvalidFrameEncodedLength)?;
        let other_frame_count = u64::from(segment.frame_count() - 1);
        let minimum_other_ciphertext = other_frame_count
            .checked_mul(FRAME_TAG_BYTES_V1 as u64)
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        let minimum_segment_ciphertext = frame_ciphertext_bytes
            .checked_add(minimum_other_ciphertext)
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        if minimum_segment_ciphertext > segment.ciphertext_byte_count() {
            return Err(EventExpansionIndexErrorV1::FrameOutsideSegment);
        }

        let frame_plaintext_length = frame_ciphertext_bytes
            .checked_sub(FRAME_TAG_BYTES_V1 as u64)
            .ok_or(EventExpansionIndexErrorV1::InvalidFrameEncodedLength)?;
        if self.authorized_bytes.end_exclusive() > frame_plaintext_length {
            return Err(EventExpansionIndexErrorV1::AuthorizedBytesOutsideFrame);
        }
        Ok(())
    }
}

impl fmt::Debug for EventExpansionIndexEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventExpansionIndexEntryV1(<redacted>)")
    }
}

/// Canonical EventId expansion-index component of authenticated manifest plaintext.
///
/// The codec binds typed locators to the exact canonical bytes of one supplied
/// segment catalog. Catalog aggregates still prove only range and sequence
/// consistency; an open path must authenticate the referenced frame header and
/// AEAD before treating an offset as a real frame boundary. This component does
/// not decode the authorized-outcome payload schema, provide the source-record
/// idempotency table or acquisition receipt, authenticate the outer manifest,
/// perform recovery, establish filesystem durability, or prove that a result is
/// sealed and openable.
#[derive(PartialEq, Eq)]
pub struct EventExpansionIndexV1 {
    entries: Vec<EventExpansionIndexEntryV1>,
    catalog_segment_count: u64,
    catalog_frame_count: u64,
    catalog_chain_root: crate::FrameCommitmentV1,
    catalog_digest: SegmentCatalogDigestV1,
    total_indexed_frame_bytes: u64,
    total_authorized_bytes: u64,
}

impl EventExpansionIndexV1 {
    pub fn new(
        catalog: &SegmentCatalogV1,
        mut entries: Vec<EventExpansionIndexEntryV1>,
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        validate_entry_count(catalog, entries.len())?;
        entries.sort_by_key(EventExpansionIndexEntryV1::event_id);
        validate_canonical_entries(catalog, &entries)?;
        Self::from_validated(catalog, entries)
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        EVENT_EXPANSION_INDEX_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        EVENT_EXPANSION_INDEX_SCHEMA_V1
    }

    #[must_use]
    pub fn entries(&self) -> &[EventExpansionIndexEntryV1] {
        &self.entries
    }

    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entries.len() as u64
    }

    #[must_use]
    pub const fn catalog_segment_count(&self) -> u64 {
        self.catalog_segment_count
    }

    #[must_use]
    pub const fn catalog_frame_count(&self) -> u64 {
        self.catalog_frame_count
    }

    #[must_use]
    pub const fn catalog_chain_root(&self) -> crate::FrameCommitmentV1 {
        self.catalog_chain_root
    }

    #[must_use]
    pub const fn catalog_digest(&self) -> SegmentCatalogDigestV1 {
        self.catalog_digest
    }

    #[must_use]
    pub const fn total_indexed_frame_bytes(&self) -> u64 {
        self.total_indexed_frame_bytes
    }

    #[must_use]
    pub const fn total_authorized_bytes(&self) -> u64 {
        self.total_authorized_bytes
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        EVENT_EXPANSION_INDEX_HEADER_BYTES_V1
            + self.entries.len() * EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        let mut header = [0u8; EVENT_EXPANSION_INDEX_HEADER_BYTES_V1];
        header[0..8].copy_from_slice(&EVENT_EXPANSION_INDEX_MAGIC_V1);
        header[8..10].copy_from_slice(&EVENT_EXPANSION_INDEX_VERSION_V1.to_be_bytes());
        header[10..12].copy_from_slice(&EVENT_EXPANSION_INDEX_SCHEMA_V1.to_be_bytes());
        header[12..14].copy_from_slice(&EVENT_EXPANSION_INDEX_OBJECT_KIND_V1.to_be_bytes());
        header[14..16]
            .copy_from_slice(&(EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1 as u16).to_be_bytes());
        header[HEADER_FLAGS_OFFSET_V1..HEADER_RESERVED_ONE_OFFSET_V1]
            .copy_from_slice(&0u16.to_be_bytes());
        header[HEADER_ENTRY_COUNT_OFFSET_V1..HEADER_CATALOG_SEGMENT_COUNT_OFFSET_V1]
            .copy_from_slice(&self.entry_count().to_be_bytes());
        header[HEADER_CATALOG_SEGMENT_COUNT_OFFSET_V1..HEADER_CATALOG_FRAME_COUNT_OFFSET_V1]
            .copy_from_slice(&self.catalog_segment_count.to_be_bytes());
        header[HEADER_CATALOG_FRAME_COUNT_OFFSET_V1..HEADER_TOTAL_FRAME_BYTES_OFFSET_V1]
            .copy_from_slice(&self.catalog_frame_count.to_be_bytes());
        header[HEADER_TOTAL_FRAME_BYTES_OFFSET_V1..HEADER_TOTAL_AUTHORIZED_BYTES_OFFSET_V1]
            .copy_from_slice(&self.total_indexed_frame_bytes.to_be_bytes());
        header[HEADER_TOTAL_AUTHORIZED_BYTES_OFFSET_V1..HEADER_CATALOG_CHAIN_ROOT_OFFSET_V1]
            .copy_from_slice(&self.total_authorized_bytes.to_be_bytes());
        header[HEADER_CATALOG_CHAIN_ROOT_OFFSET_V1..HEADER_CATALOG_DIGEST_OFFSET_V1]
            .copy_from_slice(self.catalog_chain_root.as_bytes());
        header[HEADER_CATALOG_DIGEST_OFFSET_V1..HEADER_RESERVED_TWO_OFFSET_V1]
            .copy_from_slice(self.catalog_digest.as_bytes());
        encoded.extend_from_slice(&header);
        for entry in &self.entries {
            encoded.extend_from_slice(&entry.encode());
        }
        encoded
    }

    pub fn decode(
        catalog: &SegmentCatalogV1,
        encoded: &[u8],
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        if encoded.len() < EVENT_EXPANSION_INDEX_HEADER_BYTES_V1 {
            return Err(EventExpansionIndexErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != EVENT_EXPANSION_INDEX_MAGIC_V1 {
            return Err(EventExpansionIndexErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != EVENT_EXPANSION_INDEX_VERSION_V1 {
            return Err(EventExpansionIndexErrorV1::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != EVENT_EXPANSION_INDEX_SCHEMA_V1 {
            return Err(EventExpansionIndexErrorV1::UnsupportedSchema);
        }
        if read_u16(encoded, 12) != EVENT_EXPANSION_INDEX_OBJECT_KIND_V1 {
            return Err(EventExpansionIndexErrorV1::UnsupportedIndexObjectKind);
        }
        if usize::from(read_u16(encoded, 14)) != EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1 {
            return Err(EventExpansionIndexErrorV1::InvalidEntryWidth);
        }
        if read_u16(encoded, HEADER_FLAGS_OFFSET_V1) != 0 {
            return Err(EventExpansionIndexErrorV1::NonzeroFlags);
        }
        if encoded[HEADER_RESERVED_ONE_OFFSET_V1..HEADER_ENTRY_COUNT_OFFSET_V1]
            .iter()
            .chain(
                encoded[HEADER_RESERVED_TWO_OFFSET_V1..EVENT_EXPANSION_INDEX_HEADER_BYTES_V1]
                    .iter(),
            )
            .any(|byte| *byte != 0)
        {
            return Err(EventExpansionIndexErrorV1::NonzeroReserved);
        }

        let declared_entry_count = read_u64(encoded, HEADER_ENTRY_COUNT_OFFSET_V1);
        validate_declared_entry_count(catalog, declared_entry_count)?;
        let entry_count = usize::try_from(declared_entry_count)
            .map_err(|_| EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        let entry_bytes = entry_count
            .checked_mul(EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1)
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        let expected_length = EVENT_EXPANSION_INDEX_HEADER_BYTES_V1
            .checked_add(entry_bytes)
            .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        if expected_length > MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1
            || encoded.len() != expected_length
        {
            return Err(EventExpansionIndexErrorV1::InvalidEncodedLength);
        }

        if read_u64(encoded, HEADER_CATALOG_SEGMENT_COUNT_OFFSET_V1) != catalog.segment_count() {
            return Err(EventExpansionIndexErrorV1::CatalogSegmentCountMismatch);
        }
        if read_u64(encoded, HEADER_CATALOG_FRAME_COUNT_OFFSET_V1) != catalog.total_frame_count() {
            return Err(EventExpansionIndexErrorV1::CatalogFrameCountMismatch);
        }
        if crate::FrameCommitmentV1::from_bytes(read_array(
            encoded,
            HEADER_CATALOG_CHAIN_ROOT_OFFSET_V1,
        )) != catalog.final_chain_root()
        {
            return Err(EventExpansionIndexErrorV1::CatalogChainRootMismatch);
        }
        if SegmentCatalogDigestV1::from_bytes(read_array(encoded, HEADER_CATALOG_DIGEST_OFFSET_V1))
            != derive_segment_catalog_digest_v1(catalog)
        {
            return Err(EventExpansionIndexErrorV1::CatalogDigestMismatch);
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut prior_event_id = None;
        for index in 0..entry_count {
            let start = EVENT_EXPANSION_INDEX_HEADER_BYTES_V1
                + index * EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1;
            let end = start + EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1;
            let entry = EventExpansionIndexEntryV1::decode(catalog, &encoded[start..end])?;
            if let Some(prior) = prior_event_id {
                if entry.event_id == prior {
                    return Err(EventExpansionIndexErrorV1::DuplicateEventId);
                }
                if entry.event_id < prior {
                    return Err(EventExpansionIndexErrorV1::NoncanonicalEventOrder);
                }
            }
            prior_event_id = Some(entry.event_id);
            entries.push(entry);
        }
        validate_canonical_entries(catalog, &entries)?;
        let index = Self::from_validated(catalog, entries)?;
        if read_u64(encoded, HEADER_TOTAL_FRAME_BYTES_OFFSET_V1) != index.total_indexed_frame_bytes
        {
            return Err(EventExpansionIndexErrorV1::TotalFrameBytesMismatch);
        }
        if read_u64(encoded, HEADER_TOTAL_AUTHORIZED_BYTES_OFFSET_V1)
            != index.total_authorized_bytes
        {
            return Err(EventExpansionIndexErrorV1::TotalAuthorizedBytesMismatch);
        }
        Ok(index)
    }

    fn from_validated(
        catalog: &SegmentCatalogV1,
        entries: Vec<EventExpansionIndexEntryV1>,
    ) -> Result<Self, EventExpansionIndexErrorV1> {
        let mut total_indexed_frame_bytes = 0u64;
        let mut total_authorized_bytes = 0u64;
        for entry in &entries {
            total_indexed_frame_bytes = total_indexed_frame_bytes
                .checked_add(u64::from(entry.frame_locator.frame_encoded_length))
                .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
            total_authorized_bytes = total_authorized_bytes
                .checked_add(u64::from(entry.authorized_bytes.length))
                .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
        }
        Ok(Self {
            entries,
            catalog_segment_count: catalog.segment_count(),
            catalog_frame_count: catalog.total_frame_count(),
            catalog_chain_root: catalog.final_chain_root(),
            catalog_digest: derive_segment_catalog_digest_v1(catalog),
            total_indexed_frame_bytes,
            total_authorized_bytes,
        })
    }
}

impl fmt::Debug for EventExpansionIndexV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventExpansionIndexV1(<redacted>)")
    }
}

fn validate_entry_count(
    catalog: &SegmentCatalogV1,
    entry_count: usize,
) -> Result<(), EventExpansionIndexErrorV1> {
    let entry_count =
        u64::try_from(entry_count).map_err(|_| EventExpansionIndexErrorV1::ArithmeticOverflow)?;
    validate_declared_entry_count(catalog, entry_count)
}

fn validate_declared_entry_count(
    catalog: &SegmentCatalogV1,
    entry_count: u64,
) -> Result<(), EventExpansionIndexErrorV1> {
    if entry_count > MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1 {
        return Err(EventExpansionIndexErrorV1::EntryCountCap);
    }
    if entry_count > catalog.total_frame_count() {
        return Err(EventExpansionIndexErrorV1::EntryCountExceedsCatalogFrames);
    }
    Ok(())
}

fn validate_canonical_entries(
    catalog: &SegmentCatalogV1,
    entries: &[EventExpansionIndexEntryV1],
) -> Result<(), EventExpansionIndexErrorV1> {
    let mut prior_event_id = None;
    let mut frames = BTreeMap::new();
    for entry in entries {
        entry.validate_against(catalog)?;
        if let Some(prior) = prior_event_id {
            if entry.event_id == prior {
                return Err(EventExpansionIndexErrorV1::DuplicateEventId);
            }
        }
        prior_event_id = Some(entry.event_id);
        let key = (
            entry.frame_locator.segment_sequence,
            entry.frame_locator.segment_frame_sequence,
        );
        if frames
            .insert(
                key,
                (
                    entry.frame_locator.frame_offset,
                    entry.frame_locator.frame_end(),
                ),
            )
            .is_some()
        {
            return Err(EventExpansionIndexErrorV1::DuplicateFrameAssignment);
        }
    }

    let mut prior: Option<(u64, u32, u64)> = None;
    for ((segment_sequence, frame_sequence), (frame_offset, frame_end)) in frames {
        if let Some((prior_segment, prior_frame_sequence, prior_end)) = prior {
            if prior_segment == segment_sequence {
                let omitted_frames = frame_sequence
                    .checked_sub(prior_frame_sequence)
                    .and_then(|difference| difference.checked_sub(1))
                    .ok_or(EventExpansionIndexErrorV1::DuplicateFrameAssignment)?;
                let minimum_gap = u64::from(omitted_frames)
                    .checked_mul(MIN_ENCODED_FRAME_BYTES_V1)
                    .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
                let minimum_offset = prior_end
                    .checked_add(minimum_gap)
                    .ok_or(EventExpansionIndexErrorV1::ArithmeticOverflow)?;
                if frame_offset < minimum_offset {
                    return Err(EventExpansionIndexErrorV1::FrameLocatorOverlap);
                }
            }
        }
        prior = Some((segment_sequence, frame_sequence, frame_end));
    }
    Ok(())
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

const _: () = assert!(EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1 <= u16::MAX as usize);
const _: () =
    assert!(MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1 <= MAX_MANIFEST_PLAINTEXT_BYTES_V1);
