use std::fmt;

use evidentrail_schema::ResultId;

use crate::SnapshotFormatErrorV1;

pub const OUTER_VERSION_V1: u16 = 1;
pub const FRAME_HEADER_VERSION_V1: u16 = 1;
pub const XCHACHA20_POLY1305_SUITE_ID_V1: u16 = 1;
pub const SEGMENT_HEADER_BYTES_V1: usize = 120;
pub const FRAME_HEADER_BYTES_V1: usize = 92;
pub const FRAME_NONCE_BYTES_V1: usize = 24;
pub const FRAME_TAG_BYTES_V1: usize = 16;
pub const FRAME_COMMITMENT_BYTES_V1: usize = 32;
pub const MAX_FRAME_PLAINTEXT_BYTES_V1: usize = 8 * 1024 * 1024;
pub const MAX_FRAME_CIPHERTEXT_BYTES_V1: usize = MAX_FRAME_PLAINTEXT_BYTES_V1 + FRAME_TAG_BYTES_V1;
pub const MAX_ENCODED_FRAME_BYTES_V1: usize = FRAME_HEADER_BYTES_V1 + MAX_FRAME_CIPHERTEXT_BYTES_V1;
pub const MAX_FRAMES_PER_SEGMENT_V1: u32 = 4_096;

pub(crate) const SEGMENT_MAGIC_V1: [u8; 8] = *b"EVRSNP01";
pub(crate) const FRAME_MAGIC_V1: [u8; 4] = *b"FRM1";

/// V1 frame object kinds. Authorization details remain encrypted payload data.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameObjectKindV1 {
    AuthorizedOutcome,
    AcquisitionSeal,
}

impl FrameObjectKindV1 {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::AuthorizedOutcome => 1,
            Self::AcquisitionSeal => 2,
        }
    }

    pub(crate) const fn from_code(code: u16) -> Result<Self, SnapshotFormatErrorV1> {
        match code {
            1 => Ok(Self::AuthorizedOutcome),
            2 => Ok(Self::AcquisitionSeal),
            _ => Err(SnapshotFormatErrorV1::UnsupportedObjectKind),
        }
    }
}

impl fmt::Debug for FrameObjectKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameObjectKindV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Injected 192-bit XChaCha nonce. Uniqueness is the future writer's duty.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameNonceV1([u8; FRAME_NONCE_BYTES_V1]);

impl FrameNonceV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FRAME_NONCE_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FRAME_NONCE_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for FrameNonceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrameNonceV1(<redacted>)")
    }
}

/// SHA-256 commitment used to chain frames and segments.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameCommitmentV1([u8; FRAME_COMMITMENT_BYTES_V1]);

impl FrameCommitmentV1 {
    pub const ZERO: Self = Self([0; FRAME_COMMITMENT_BYTES_V1]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; FRAME_COMMITMENT_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FRAME_COMMITMENT_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for FrameCommitmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrameCommitmentV1(<redacted>)")
    }
}

/// Constructor-validated fixed-width segment header from ADR 0004.
#[derive(Clone, PartialEq, Eq)]
pub struct SegmentHeaderV1 {
    payload_schema: u16,
    result_id: ResultId,
    segment_sequence: u64,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
    prior_segment_commitment: FrameCommitmentV1,
}

impl SegmentHeaderV1 {
    pub fn new(
        payload_schema: u16,
        result_id: ResultId,
        segment_sequence: u64,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        prior_segment_commitment: FrameCommitmentV1,
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if payload_schema == 0 {
            return Err(SnapshotFormatErrorV1::InvalidPayloadSchema);
        }
        if expires_unix_nanos <= created_unix_nanos {
            return Err(SnapshotFormatErrorV1::InvalidTimeRange);
        }
        if (segment_sequence == 0) != (prior_segment_commitment == FrameCommitmentV1::ZERO) {
            return Err(SnapshotFormatErrorV1::InvalidSegmentChainStart);
        }
        Ok(Self {
            payload_schema,
            result_id,
            segment_sequence,
            created_unix_nanos,
            expires_unix_nanos,
            prior_segment_commitment,
        })
    }

    #[must_use]
    pub const fn payload_schema(&self) -> u16 {
        self.payload_schema
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn segment_sequence(&self) -> u64 {
        self.segment_sequence
    }

    #[must_use]
    pub const fn created_unix_nanos(&self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(&self) -> i64 {
        self.expires_unix_nanos
    }

    #[must_use]
    pub const fn prior_segment_commitment(&self) -> FrameCommitmentV1 {
        self.prior_segment_commitment
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_BYTES_V1] {
        let mut encoded = [0u8; SEGMENT_HEADER_BYTES_V1];
        encoded[0..8].copy_from_slice(&SEGMENT_MAGIC_V1);
        encoded[8..10].copy_from_slice(&OUTER_VERSION_V1.to_be_bytes());
        encoded[10..12].copy_from_slice(&XCHACHA20_POLY1305_SUITE_ID_V1.to_be_bytes());
        encoded[12..14].copy_from_slice(&self.payload_schema.to_be_bytes());
        encoded[14..16].copy_from_slice(&0u16.to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..56].copy_from_slice(&self.segment_sequence.to_be_bytes());
        encoded[56..64].copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        encoded[64..72].copy_from_slice(&self.expires_unix_nanos.to_be_bytes());
        encoded[72..104].copy_from_slice(self.prior_segment_commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFormatErrorV1> {
        if encoded.len() != SEGMENT_HEADER_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != SEGMENT_MAGIC_V1 {
            return Err(SnapshotFormatErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != OUTER_VERSION_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedOuterVersion);
        }
        if read_u16(encoded, 10) != XCHACHA20_POLY1305_SUITE_ID_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedSuite);
        }
        if read_u16(encoded, 14) != 0 {
            return Err(SnapshotFormatErrorV1::NonzeroFlags);
        }
        if encoded[104..120].iter().any(|byte| *byte != 0) {
            return Err(SnapshotFormatErrorV1::NonzeroReserved);
        }
        Self::new(
            read_u16(encoded, 12),
            ResultId::from_bytes(read_array(encoded, 16)),
            read_u64(encoded, 48),
            read_i64(encoded, 56),
            read_i64(encoded, 64),
            FrameCommitmentV1::from_bytes(read_array(encoded, 72)),
        )
    }
}

impl fmt::Debug for SegmentHeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentHeaderV1")
            .field("payload_schema", &self.payload_schema)
            .field("segment_sequence", &self.segment_sequence)
            .finish()
    }
}

/// Constructor-validated fixed-width frame header from ADR 0004.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrameHeaderV1 {
    object_kind: FrameObjectKindV1,
    global_sequence: u64,
    segment_frame_sequence: u32,
    plaintext_length: u32,
    ciphertext_length: u32,
    nonce: FrameNonceV1,
    previous_frame_commitment: FrameCommitmentV1,
}

impl FrameHeaderV1 {
    pub fn new(
        object_kind: FrameObjectKindV1,
        global_sequence: u64,
        segment_frame_sequence: u32,
        plaintext_length: u32,
        nonce: FrameNonceV1,
        previous_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if segment_frame_sequence >= MAX_FRAMES_PER_SEGMENT_V1 {
            return Err(SnapshotFormatErrorV1::FrameCountCap);
        }
        let plaintext_usize =
            usize::try_from(plaintext_length).map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?;
        if plaintext_usize > MAX_FRAME_PLAINTEXT_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::PlaintextTooLarge);
        }
        let ciphertext_length = plaintext_length
            .checked_add(
                u32::try_from(FRAME_TAG_BYTES_V1)
                    .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?,
            )
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        Ok(Self {
            object_kind,
            global_sequence,
            segment_frame_sequence,
            plaintext_length,
            ciphertext_length,
            nonce,
            previous_frame_commitment,
        })
    }

    #[must_use]
    pub const fn object_kind(&self) -> FrameObjectKindV1 {
        self.object_kind
    }

    #[must_use]
    pub const fn global_sequence(&self) -> u64 {
        self.global_sequence
    }

    #[must_use]
    pub const fn segment_frame_sequence(&self) -> u32 {
        self.segment_frame_sequence
    }

    #[must_use]
    pub const fn plaintext_length(&self) -> u32 {
        self.plaintext_length
    }

    #[must_use]
    pub const fn ciphertext_length(&self) -> u32 {
        self.ciphertext_length
    }

    #[must_use]
    pub const fn nonce(&self) -> FrameNonceV1 {
        self.nonce
    }

    #[must_use]
    pub const fn previous_frame_commitment(&self) -> FrameCommitmentV1 {
        self.previous_frame_commitment
    }

    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_HEADER_BYTES_V1] {
        let mut encoded = [0u8; FRAME_HEADER_BYTES_V1];
        encoded[0..4].copy_from_slice(&FRAME_MAGIC_V1);
        encoded[4..6].copy_from_slice(&FRAME_HEADER_VERSION_V1.to_be_bytes());
        encoded[6..8].copy_from_slice(&self.object_kind.code().to_be_bytes());
        encoded[8..16].copy_from_slice(&self.global_sequence.to_be_bytes());
        encoded[16..20].copy_from_slice(&self.segment_frame_sequence.to_be_bytes());
        encoded[20..24].copy_from_slice(&self.plaintext_length.to_be_bytes());
        encoded[24..28].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        encoded[28..52].copy_from_slice(self.nonce.as_bytes());
        encoded[52..84].copy_from_slice(self.previous_frame_commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFormatErrorV1> {
        if encoded.len() != FRAME_HEADER_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        if encoded[0..4] != FRAME_MAGIC_V1 {
            return Err(SnapshotFormatErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 4) != FRAME_HEADER_VERSION_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedHeaderVersion);
        }
        if encoded[84..92].iter().any(|byte| *byte != 0) {
            return Err(SnapshotFormatErrorV1::NonzeroReserved);
        }
        let plaintext_length = read_u32(encoded, 20);
        let header = Self::new(
            FrameObjectKindV1::from_code(read_u16(encoded, 6))?,
            read_u64(encoded, 8),
            read_u32(encoded, 16),
            plaintext_length,
            FrameNonceV1::from_bytes(read_array(encoded, 28)),
            FrameCommitmentV1::from_bytes(read_array(encoded, 52)),
        )?;
        if read_u32(encoded, 24) != header.ciphertext_length {
            return Err(SnapshotFormatErrorV1::CiphertextLengthMismatch);
        }
        Ok(header)
    }
}

impl fmt::Debug for FrameHeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameHeaderV1")
            .field("object_kind", &self.object_kind)
            .field("global_sequence", &self.global_sequence)
            .field("segment_frame_sequence", &self.segment_frame_sequence)
            .field("plaintext_length", &self.plaintext_length)
            .field("ciphertext_length", &self.ciphertext_length)
            .finish()
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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}
