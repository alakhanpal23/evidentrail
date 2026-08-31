use std::error::Error as StdError;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1, MAX_FRAME_CIPHERTEXT_BYTES_V1,
    MAX_FRAMES_PER_SEGMENT_V1, MAX_SEGMENTS_PER_RESULT_V1, MAX_TOTAL_FRAMES_PER_RESULT_V1,
    SEGMENT_HEADER_BYTES_V1,
};

pub const SEGMENT_CATALOG_VERSION_V1: u16 = 1;
pub const SEGMENT_CATALOG_SCHEMA_V1: u16 = 1;
pub const SEGMENT_CATALOG_HEADER_BYTES_V1: usize = 96;
pub const SEGMENT_CATALOG_ENTRY_BYTES_V1: usize = 112;
pub const SEGMENT_DIGEST_BYTES_V1: usize = 32;

pub const MAX_SEGMENT_CIPHERTEXT_BYTES_V1: u64 =
    MAX_FRAMES_PER_SEGMENT_V1 as u64 * MAX_FRAME_CIPHERTEXT_BYTES_V1 as u64;
pub const MAX_SEGMENT_ENCODED_BYTES_V1: u64 = SEGMENT_HEADER_BYTES_V1 as u64
    + MAX_FRAMES_PER_SEGMENT_V1 as u64 * FRAME_HEADER_BYTES_V1 as u64
    + MAX_SEGMENT_CIPHERTEXT_BYTES_V1;
pub const MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1: u64 =
    MAX_SEGMENTS_PER_RESULT_V1 * MAX_SEGMENT_CIPHERTEXT_BYTES_V1;
pub const MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1: u64 =
    MAX_SEGMENTS_PER_RESULT_V1 * MAX_SEGMENT_ENCODED_BYTES_V1;
pub const MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1: usize = SEGMENT_CATALOG_HEADER_BYTES_V1
    + MAX_SEGMENTS_PER_RESULT_V1 as usize * SEGMENT_CATALOG_ENTRY_BYTES_V1;

const SEGMENT_CATALOG_MAGIC_V1: [u8; 8] = *b"EVRSCG01";

const HEADER_SEGMENT_COUNT_OFFSET_V1: usize = 16;
const HEADER_TOTAL_FRAME_COUNT_OFFSET_V1: usize = 24;
const HEADER_TOTAL_ENCODED_BYTES_OFFSET_V1: usize = 32;
const HEADER_TOTAL_CIPHERTEXT_BYTES_OFFSET_V1: usize = 40;
const HEADER_FINAL_CHAIN_ROOT_OFFSET_V1: usize = 48;
const HEADER_RESERVED_OFFSET_V1: usize = 80;

const ENTRY_SEGMENT_SEQUENCE_OFFSET_V1: usize = 0;
const ENTRY_FIRST_GLOBAL_SEQUENCE_OFFSET_V1: usize = 8;
const ENTRY_FRAME_COUNT_OFFSET_V1: usize = 16;
const ENTRY_RESERVED_ONE_OFFSET_V1: usize = 20;
const ENTRY_ENCODED_BYTES_OFFSET_V1: usize = 24;
const ENTRY_CIPHERTEXT_BYTES_OFFSET_V1: usize = 32;
const ENTRY_SEGMENT_DIGEST_OFFSET_V1: usize = 40;
const ENTRY_FINAL_COMMITMENT_OFFSET_V1: usize = 72;
const ENTRY_RESERVED_TWO_OFFSET_V1: usize = 104;

/// Stable, contentless failure returned by the V1 segment-catalog codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SegmentCatalogErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    InvalidEntryWidth,
    NonzeroFlags,
    NonzeroReserved,
    EmptyCatalog,
    SegmentCountCap,
    SegmentSequenceMismatch,
    InvalidFrameCount,
    FrameCountCap,
    GlobalFrameRangeMismatch,
    GlobalFrameRangeOverflow,
    InvalidCiphertextByteCount,
    CiphertextByteCountCap,
    InvalidSegmentByteCount,
    SegmentByteCountCap,
    TotalFrameCountCap,
    TotalCiphertextByteCountCap,
    TotalSegmentByteCountCap,
    TotalFrameCountMismatch,
    TotalCiphertextByteCountMismatch,
    TotalSegmentByteCountMismatch,
    FinalChainRootMismatch,
    ArithmeticOverflow,
}

impl SegmentCatalogErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_SEGMENT_CATALOG_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_SEGMENT_CATALOG_UNSUPPORTED_SCHEMA",
            Self::InvalidEntryWidth => "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_ENTRY_WIDTH",
            Self::NonzeroFlags => "EVIDENTRAIL_SEGMENT_CATALOG_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_SEGMENT_CATALOG_NONZERO_RESERVED",
            Self::EmptyCatalog => "EVIDENTRAIL_SEGMENT_CATALOG_EMPTY",
            Self::SegmentCountCap => "EVIDENTRAIL_SEGMENT_CATALOG_SEGMENT_COUNT_CAP",
            Self::SegmentSequenceMismatch => {
                "EVIDENTRAIL_SEGMENT_CATALOG_SEGMENT_SEQUENCE_MISMATCH"
            }
            Self::InvalidFrameCount => "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_FRAME_COUNT",
            Self::FrameCountCap => "EVIDENTRAIL_SEGMENT_CATALOG_FRAME_COUNT_CAP",
            Self::GlobalFrameRangeMismatch => {
                "EVIDENTRAIL_SEGMENT_CATALOG_GLOBAL_FRAME_RANGE_MISMATCH"
            }
            Self::GlobalFrameRangeOverflow => {
                "EVIDENTRAIL_SEGMENT_CATALOG_GLOBAL_FRAME_RANGE_OVERFLOW"
            }
            Self::InvalidCiphertextByteCount => {
                "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_CIPHERTEXT_BYTE_COUNT"
            }
            Self::CiphertextByteCountCap => "EVIDENTRAIL_SEGMENT_CATALOG_CIPHERTEXT_BYTE_COUNT_CAP",
            Self::InvalidSegmentByteCount => {
                "EVIDENTRAIL_SEGMENT_CATALOG_INVALID_SEGMENT_BYTE_COUNT"
            }
            Self::SegmentByteCountCap => "EVIDENTRAIL_SEGMENT_CATALOG_SEGMENT_BYTE_COUNT_CAP",
            Self::TotalFrameCountCap => "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_FRAME_COUNT_CAP",
            Self::TotalCiphertextByteCountCap => {
                "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_CIPHERTEXT_BYTE_COUNT_CAP"
            }
            Self::TotalSegmentByteCountCap => {
                "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_SEGMENT_BYTE_COUNT_CAP"
            }
            Self::TotalFrameCountMismatch => {
                "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_FRAME_COUNT_MISMATCH"
            }
            Self::TotalCiphertextByteCountMismatch => {
                "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_CIPHERTEXT_BYTE_COUNT_MISMATCH"
            }
            Self::TotalSegmentByteCountMismatch => {
                "EVIDENTRAIL_SEGMENT_CATALOG_TOTAL_SEGMENT_BYTE_COUNT_MISMATCH"
            }
            Self::FinalChainRootMismatch => "EVIDENTRAIL_SEGMENT_CATALOG_FINAL_CHAIN_ROOT_MISMATCH",
            Self::ArithmeticOverflow => "EVIDENTRAIL_SEGMENT_CATALOG_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for SegmentCatalogErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentCatalogErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SegmentCatalogErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SegmentCatalogErrorV1 {}

/// Exact SHA-256 digest of one complete encoded segment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentDigestV1([u8; SEGMENT_DIGEST_BYTES_V1]);

impl SegmentDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEGMENT_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEGMENT_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for SegmentDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SegmentDigestV1(<redacted>)")
    }
}

/// Compute the ADR-required SHA-256 digest over the complete encoded segment.
#[must_use]
pub fn derive_segment_digest_v1(encoded_segment: &[u8]) -> SegmentDigestV1 {
    SegmentDigestV1::from_bytes(Sha256::digest(encoded_segment).into())
}

/// One fixed-width descriptor in the ordered V1 segment catalog.
///
/// `encoded_byte_count` covers the clear segment header plus every frame header,
/// ciphertext, and tag. `ciphertext_byte_count` is the sum of each frame
/// header's `ciphertext_length`, which includes its AEAD tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SegmentCatalogEntryV1 {
    segment_sequence: u64,
    first_global_frame_sequence: u64,
    frame_count: u32,
    encoded_byte_count: u64,
    ciphertext_byte_count: u64,
    segment_digest: SegmentDigestV1,
    final_frame_commitment: FrameCommitmentV1,
}

impl SegmentCatalogEntryV1 {
    pub fn new(
        segment_sequence: u64,
        first_global_frame_sequence: u64,
        frame_count: u32,
        encoded_byte_count: u64,
        ciphertext_byte_count: u64,
        segment_digest: SegmentDigestV1,
        final_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, SegmentCatalogErrorV1> {
        if frame_count == 0 {
            return Err(SegmentCatalogErrorV1::InvalidFrameCount);
        }
        if frame_count > MAX_FRAMES_PER_SEGMENT_V1 {
            return Err(SegmentCatalogErrorV1::FrameCountCap);
        }

        let frame_count_u64 = u64::from(frame_count);
        first_global_frame_sequence
            .checked_add(frame_count_u64)
            .ok_or(SegmentCatalogErrorV1::GlobalFrameRangeOverflow)?;

        let minimum_ciphertext_bytes = frame_count_u64
            .checked_mul(FRAME_TAG_BYTES_V1 as u64)
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        if ciphertext_byte_count < minimum_ciphertext_bytes {
            return Err(SegmentCatalogErrorV1::InvalidCiphertextByteCount);
        }
        let maximum_ciphertext_bytes = frame_count_u64
            .checked_mul(MAX_FRAME_CIPHERTEXT_BYTES_V1 as u64)
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        if ciphertext_byte_count > maximum_ciphertext_bytes {
            return Err(SegmentCatalogErrorV1::CiphertextByteCountCap);
        }

        let frame_header_bytes = frame_count_u64
            .checked_mul(FRAME_HEADER_BYTES_V1 as u64)
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        if encoded_byte_count > MAX_SEGMENT_ENCODED_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::SegmentByteCountCap);
        }
        let expected_encoded_byte_count = (SEGMENT_HEADER_BYTES_V1 as u64)
            .checked_add(frame_header_bytes)
            .and_then(|value| value.checked_add(ciphertext_byte_count))
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        if encoded_byte_count != expected_encoded_byte_count {
            return Err(SegmentCatalogErrorV1::InvalidSegmentByteCount);
        }

        Ok(Self {
            segment_sequence,
            first_global_frame_sequence,
            frame_count,
            encoded_byte_count,
            ciphertext_byte_count,
            segment_digest,
            final_frame_commitment,
        })
    }

    #[must_use]
    pub const fn segment_sequence(&self) -> u64 {
        self.segment_sequence
    }

    #[must_use]
    pub const fn first_global_frame_sequence(&self) -> u64 {
        self.first_global_frame_sequence
    }

    #[must_use]
    pub const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    #[must_use]
    pub const fn encoded_byte_count(&self) -> u64 {
        self.encoded_byte_count
    }

    #[must_use]
    pub const fn ciphertext_byte_count(&self) -> u64 {
        self.ciphertext_byte_count
    }

    #[must_use]
    pub const fn segment_digest(&self) -> SegmentDigestV1 {
        self.segment_digest
    }

    #[must_use]
    pub const fn final_frame_commitment(&self) -> FrameCommitmentV1 {
        self.final_frame_commitment
    }

    #[must_use]
    pub fn global_frame_end_exclusive(&self) -> u64 {
        self.first_global_frame_sequence + u64::from(self.frame_count)
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_CATALOG_ENTRY_BYTES_V1] {
        let mut encoded = [0u8; SEGMENT_CATALOG_ENTRY_BYTES_V1];
        encoded[ENTRY_SEGMENT_SEQUENCE_OFFSET_V1..ENTRY_FIRST_GLOBAL_SEQUENCE_OFFSET_V1]
            .copy_from_slice(&self.segment_sequence.to_be_bytes());
        encoded[ENTRY_FIRST_GLOBAL_SEQUENCE_OFFSET_V1..ENTRY_FRAME_COUNT_OFFSET_V1]
            .copy_from_slice(&self.first_global_frame_sequence.to_be_bytes());
        encoded[ENTRY_FRAME_COUNT_OFFSET_V1..ENTRY_RESERVED_ONE_OFFSET_V1]
            .copy_from_slice(&self.frame_count.to_be_bytes());
        encoded[ENTRY_ENCODED_BYTES_OFFSET_V1..ENTRY_CIPHERTEXT_BYTES_OFFSET_V1]
            .copy_from_slice(&self.encoded_byte_count.to_be_bytes());
        encoded[ENTRY_CIPHERTEXT_BYTES_OFFSET_V1..ENTRY_SEGMENT_DIGEST_OFFSET_V1]
            .copy_from_slice(&self.ciphertext_byte_count.to_be_bytes());
        encoded[ENTRY_SEGMENT_DIGEST_OFFSET_V1..ENTRY_FINAL_COMMITMENT_OFFSET_V1]
            .copy_from_slice(self.segment_digest.as_bytes());
        encoded[ENTRY_FINAL_COMMITMENT_OFFSET_V1..ENTRY_RESERVED_TWO_OFFSET_V1]
            .copy_from_slice(self.final_frame_commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SegmentCatalogErrorV1> {
        if encoded.len() != SEGMENT_CATALOG_ENTRY_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::InvalidEncodedLength);
        }
        if encoded[ENTRY_RESERVED_ONE_OFFSET_V1..ENTRY_ENCODED_BYTES_OFFSET_V1]
            .iter()
            .chain(encoded[ENTRY_RESERVED_TWO_OFFSET_V1..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(SegmentCatalogErrorV1::NonzeroReserved);
        }
        Self::new(
            read_u64(encoded, ENTRY_SEGMENT_SEQUENCE_OFFSET_V1),
            read_u64(encoded, ENTRY_FIRST_GLOBAL_SEQUENCE_OFFSET_V1),
            read_u32(encoded, ENTRY_FRAME_COUNT_OFFSET_V1),
            read_u64(encoded, ENTRY_ENCODED_BYTES_OFFSET_V1),
            read_u64(encoded, ENTRY_CIPHERTEXT_BYTES_OFFSET_V1),
            SegmentDigestV1::from_bytes(read_array(encoded, ENTRY_SEGMENT_DIGEST_OFFSET_V1)),
            FrameCommitmentV1::from_bytes(read_array(encoded, ENTRY_FINAL_COMMITMENT_OFFSET_V1)),
        )
    }
}

impl fmt::Debug for SegmentCatalogEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SegmentCatalogEntryV1(<redacted>)")
    }
}

/// Ordered segment-catalog component of a future encrypted manifest payload.
///
/// This value only reconciles segment sequences, global frame ranges, counts,
/// segment digests, and the final frame-chain root. It is not an event index or
/// acquisition receipt, and it makes no recovery, filesystem durability, or
/// sealed-result claim. A reader must still authenticate the outer manifest and
/// recompute every segment digest and frame chain before trusting this catalog.
#[derive(PartialEq, Eq)]
pub struct SegmentCatalogV1 {
    entries: Vec<SegmentCatalogEntryV1>,
    total_frame_count: u64,
    total_encoded_byte_count: u64,
    total_ciphertext_byte_count: u64,
    final_chain_root: FrameCommitmentV1,
}

impl SegmentCatalogV1 {
    pub fn new(entries: Vec<SegmentCatalogEntryV1>) -> Result<Self, SegmentCatalogErrorV1> {
        if entries.is_empty() {
            return Err(SegmentCatalogErrorV1::EmptyCatalog);
        }
        if entries.len() > MAX_SEGMENTS_PER_RESULT_V1 as usize {
            return Err(SegmentCatalogErrorV1::SegmentCountCap);
        }

        let mut expected_global_sequence = 0u64;
        let mut total_frame_count = 0u64;
        let mut total_encoded_byte_count = 0u64;
        let mut total_ciphertext_byte_count = 0u64;

        for (expected_segment_sequence, entry) in (0u64..).zip(&entries) {
            if entry.segment_sequence != expected_segment_sequence {
                return Err(SegmentCatalogErrorV1::SegmentSequenceMismatch);
            }
            if entry.first_global_frame_sequence != expected_global_sequence {
                return Err(SegmentCatalogErrorV1::GlobalFrameRangeMismatch);
            }
            expected_global_sequence = entry.global_frame_end_exclusive();
            total_frame_count = total_frame_count
                .checked_add(u64::from(entry.frame_count))
                .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
            total_encoded_byte_count = total_encoded_byte_count
                .checked_add(entry.encoded_byte_count)
                .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
            total_ciphertext_byte_count = total_ciphertext_byte_count
                .checked_add(entry.ciphertext_byte_count)
                .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        }

        if total_frame_count > MAX_TOTAL_FRAMES_PER_RESULT_V1 {
            return Err(SegmentCatalogErrorV1::TotalFrameCountCap);
        }
        if total_ciphertext_byte_count > MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::TotalCiphertextByteCountCap);
        }
        if total_encoded_byte_count > MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::TotalSegmentByteCountCap);
        }
        let final_chain_root = entries
            .last()
            .ok_or(SegmentCatalogErrorV1::EmptyCatalog)?
            .final_frame_commitment;

        Ok(Self {
            entries,
            total_frame_count,
            total_encoded_byte_count,
            total_ciphertext_byte_count,
            final_chain_root,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        SEGMENT_CATALOG_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        SEGMENT_CATALOG_SCHEMA_V1
    }

    #[must_use]
    pub fn entries(&self) -> &[SegmentCatalogEntryV1] {
        &self.entries
    }

    #[must_use]
    pub fn segment_count(&self) -> u64 {
        self.entries.len() as u64
    }

    #[must_use]
    pub const fn total_frame_count(&self) -> u64 {
        self.total_frame_count
    }

    #[must_use]
    pub const fn total_encoded_byte_count(&self) -> u64 {
        self.total_encoded_byte_count
    }

    #[must_use]
    pub const fn total_ciphertext_byte_count(&self) -> u64 {
        self.total_ciphertext_byte_count
    }

    #[must_use]
    pub const fn final_chain_root(&self) -> FrameCommitmentV1 {
        self.final_chain_root
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        SEGMENT_CATALOG_HEADER_BYTES_V1 + self.entries.len() * SEGMENT_CATALOG_ENTRY_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        let mut header = [0u8; SEGMENT_CATALOG_HEADER_BYTES_V1];
        header[0..8].copy_from_slice(&SEGMENT_CATALOG_MAGIC_V1);
        header[8..10].copy_from_slice(&SEGMENT_CATALOG_VERSION_V1.to_be_bytes());
        header[10..12].copy_from_slice(&SEGMENT_CATALOG_SCHEMA_V1.to_be_bytes());
        header[12..14].copy_from_slice(&(SEGMENT_CATALOG_ENTRY_BYTES_V1 as u16).to_be_bytes());
        header[14..16].copy_from_slice(&0u16.to_be_bytes());
        header[HEADER_SEGMENT_COUNT_OFFSET_V1..HEADER_TOTAL_FRAME_COUNT_OFFSET_V1]
            .copy_from_slice(&self.segment_count().to_be_bytes());
        header[HEADER_TOTAL_FRAME_COUNT_OFFSET_V1..HEADER_TOTAL_ENCODED_BYTES_OFFSET_V1]
            .copy_from_slice(&self.total_frame_count.to_be_bytes());
        header[HEADER_TOTAL_ENCODED_BYTES_OFFSET_V1..HEADER_TOTAL_CIPHERTEXT_BYTES_OFFSET_V1]
            .copy_from_slice(&self.total_encoded_byte_count.to_be_bytes());
        header[HEADER_TOTAL_CIPHERTEXT_BYTES_OFFSET_V1..HEADER_FINAL_CHAIN_ROOT_OFFSET_V1]
            .copy_from_slice(&self.total_ciphertext_byte_count.to_be_bytes());
        header[HEADER_FINAL_CHAIN_ROOT_OFFSET_V1..HEADER_RESERVED_OFFSET_V1]
            .copy_from_slice(self.final_chain_root.as_bytes());
        encoded.extend_from_slice(&header);
        for entry in &self.entries {
            encoded.extend_from_slice(&entry.encode());
        }
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SegmentCatalogErrorV1> {
        if encoded.len() < SEGMENT_CATALOG_HEADER_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != SEGMENT_CATALOG_MAGIC_V1 {
            return Err(SegmentCatalogErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != SEGMENT_CATALOG_VERSION_V1 {
            return Err(SegmentCatalogErrorV1::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != SEGMENT_CATALOG_SCHEMA_V1 {
            return Err(SegmentCatalogErrorV1::UnsupportedSchema);
        }
        if usize::from(read_u16(encoded, 12)) != SEGMENT_CATALOG_ENTRY_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::InvalidEntryWidth);
        }
        if read_u16(encoded, 14) != 0 {
            return Err(SegmentCatalogErrorV1::NonzeroFlags);
        }
        if encoded[HEADER_RESERVED_OFFSET_V1..SEGMENT_CATALOG_HEADER_BYTES_V1]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SegmentCatalogErrorV1::NonzeroReserved);
        }

        let declared_segment_count = read_u64(encoded, HEADER_SEGMENT_COUNT_OFFSET_V1);
        if declared_segment_count == 0 {
            return Err(SegmentCatalogErrorV1::EmptyCatalog);
        }
        if declared_segment_count > MAX_SEGMENTS_PER_RESULT_V1 {
            return Err(SegmentCatalogErrorV1::SegmentCountCap);
        }
        let entry_count = usize::try_from(declared_segment_count)
            .map_err(|_| SegmentCatalogErrorV1::ArithmeticOverflow)?;
        let entry_bytes = entry_count
            .checked_mul(SEGMENT_CATALOG_ENTRY_BYTES_V1)
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        let expected_length = SEGMENT_CATALOG_HEADER_BYTES_V1
            .checked_add(entry_bytes)
            .ok_or(SegmentCatalogErrorV1::ArithmeticOverflow)?;
        if expected_length > MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1
            || encoded.len() != expected_length
        {
            return Err(SegmentCatalogErrorV1::InvalidEncodedLength);
        }

        let declared_total_frame_count = read_u64(encoded, HEADER_TOTAL_FRAME_COUNT_OFFSET_V1);
        if declared_total_frame_count > MAX_TOTAL_FRAMES_PER_RESULT_V1 {
            return Err(SegmentCatalogErrorV1::TotalFrameCountCap);
        }
        let declared_total_encoded_bytes = read_u64(encoded, HEADER_TOTAL_ENCODED_BYTES_OFFSET_V1);
        if declared_total_encoded_bytes > MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::TotalSegmentByteCountCap);
        }
        let declared_total_ciphertext_bytes =
            read_u64(encoded, HEADER_TOTAL_CIPHERTEXT_BYTES_OFFSET_V1);
        if declared_total_ciphertext_bytes > MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1 {
            return Err(SegmentCatalogErrorV1::TotalCiphertextByteCountCap);
        }
        let declared_final_chain_root =
            FrameCommitmentV1::from_bytes(read_array(encoded, HEADER_FINAL_CHAIN_ROOT_OFFSET_V1));

        let mut entries = Vec::with_capacity(entry_count);
        for index in 0..entry_count {
            let start = SEGMENT_CATALOG_HEADER_BYTES_V1 + index * SEGMENT_CATALOG_ENTRY_BYTES_V1;
            let end = start + SEGMENT_CATALOG_ENTRY_BYTES_V1;
            entries.push(SegmentCatalogEntryV1::decode(&encoded[start..end])?);
        }
        let catalog = Self::new(entries)?;
        if declared_total_frame_count != catalog.total_frame_count {
            return Err(SegmentCatalogErrorV1::TotalFrameCountMismatch);
        }
        if declared_total_encoded_bytes != catalog.total_encoded_byte_count {
            return Err(SegmentCatalogErrorV1::TotalSegmentByteCountMismatch);
        }
        if declared_total_ciphertext_bytes != catalog.total_ciphertext_byte_count {
            return Err(SegmentCatalogErrorV1::TotalCiphertextByteCountMismatch);
        }
        if declared_final_chain_root != catalog.final_chain_root {
            return Err(SegmentCatalogErrorV1::FinalChainRootMismatch);
        }
        Ok(catalog)
    }
}

impl fmt::Debug for SegmentCatalogV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SegmentCatalogV1(<redacted>)")
    }
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

const _: () = assert!(SEGMENT_DIGEST_BYTES_V1 == 32);
const _: () = assert!(SEGMENT_CATALOG_ENTRY_BYTES_V1 <= u16::MAX as usize);
const _: () = assert!(MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1 < 1024 * 1024);
