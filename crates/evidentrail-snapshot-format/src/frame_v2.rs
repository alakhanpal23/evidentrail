use std::error::Error as StdError;
use std::fmt;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use evidentrail_schema::ResultId;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    FRAME_COMMITMENT_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1, MAX_FRAME_PLAINTEXT_BYTES_V1,
    MAX_FRAMES_PER_SEGMENT_V1, ResultDekV1,
};

pub const SNAPSHOT_FORMAT_VERSION_V2: u16 = 2;
pub const SEGMENT_HEADER_BYTES_V2: usize = 96;
pub const FRAME_HEADER_BYTES_V2: usize = 96;
pub const MAX_ENCODED_FRAME_BYTES_V2: usize = FRAME_HEADER_BYTES_V2
    + MAX_FRAME_PLAINTEXT_BYTES_V1
    + FRAME_TAG_BYTES_V1
    + FRAME_COMMITMENT_BYTES_V1;

const SEGMENT_MAGIC_V2: [u8; 8] = *b"EVRSEG02";
const FRAME_MAGIC_V2: [u8; 8] = *b"EVRFRM02";
const FRAME_AAD_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.frame-aad.v2";
const FRAME_COMMITMENT_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.frame-commitment.v2";

/// Private encrypted object kinds. They never enter the public V1 JSON domain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SnapshotObjectKindV2 {
    Request,
    AuthorizedEvent,
    SemanticReceipt,
    OperationalReceipt,
    DataManifest,
    EventIndex,
    Product,
    FinalManifest,
    AliasManifest,
    EventIndexDirectory,
}

impl SnapshotObjectKindV2 {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::AuthorizedEvent => 2,
            Self::SemanticReceipt => 3,
            Self::OperationalReceipt => 4,
            Self::DataManifest => 5,
            Self::EventIndex => 6,
            Self::Product => 7,
            Self::FinalManifest => 8,
            Self::AliasManifest => 9,
            Self::EventIndexDirectory => 10,
        }
    }

    fn from_code(code: u16) -> Result<Self, SnapshotFrameErrorV2> {
        match code {
            1 => Ok(Self::Request),
            2 => Ok(Self::AuthorizedEvent),
            3 => Ok(Self::SemanticReceipt),
            4 => Ok(Self::OperationalReceipt),
            5 => Ok(Self::DataManifest),
            6 => Ok(Self::EventIndex),
            7 => Ok(Self::Product),
            8 => Ok(Self::FinalManifest),
            9 => Ok(Self::AliasManifest),
            10 => Ok(Self::EventIndexDirectory),
            _ => Err(SnapshotFrameErrorV2::UnsupportedObjectKind),
        }
    }
}

impl fmt::Debug for SnapshotObjectKindV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotObjectKindV2")
            .field("code", &self.code())
            .finish()
    }
}

/// Authenticated segment header. The prior segment commitment is the final
/// frame commitment of the preceding segment (zero only for segment zero).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeaderV2 {
    result_id: ResultId,
    segment_ordinal: u64,
    prior_segment_commitment: FrameCommitmentV1,
}

impl SegmentHeaderV2 {
    pub fn new(
        result_id: ResultId,
        segment_ordinal: u64,
        prior_segment_commitment: FrameCommitmentV1,
    ) -> Result<Self, SnapshotFrameErrorV2> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0)
            || (segment_ordinal == 0) != (prior_segment_commitment == FrameCommitmentV1::ZERO)
        {
            return Err(SnapshotFrameErrorV2::InvalidSegmentChain);
        }
        Ok(Self {
            result_id,
            segment_ordinal,
            prior_segment_commitment,
        })
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn segment_ordinal(self) -> u64 {
        self.segment_ordinal
    }

    #[must_use]
    pub const fn prior_segment_commitment(self) -> FrameCommitmentV1 {
        self.prior_segment_commitment
    }

    #[must_use]
    pub fn encode(self) -> [u8; SEGMENT_HEADER_BYTES_V2] {
        let mut encoded = [0u8; SEGMENT_HEADER_BYTES_V2];
        encoded[0..8].copy_from_slice(&SEGMENT_MAGIC_V2);
        encoded[8..10].copy_from_slice(&SNAPSHOT_FORMAT_VERSION_V2.to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..56].copy_from_slice(&self.segment_ordinal.to_be_bytes());
        encoded[56..88].copy_from_slice(self.prior_segment_commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFrameErrorV2> {
        if encoded.len() != SEGMENT_HEADER_BYTES_V2 {
            return Err(SnapshotFrameErrorV2::InvalidEncodedLength);
        }
        if encoded[0..8] != SEGMENT_MAGIC_V2 {
            return Err(SnapshotFrameErrorV2::InvalidMagic);
        }
        if read_u16(encoded, 8) != SNAPSHOT_FORMAT_VERSION_V2 {
            return Err(SnapshotFrameErrorV2::UnsupportedVersion);
        }
        if encoded[10..16]
            .iter()
            .chain(encoded[88..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(SnapshotFrameErrorV2::NonzeroReserved);
        }
        Self::new(
            ResultId::from_bytes(read_array(encoded, 16)),
            read_u64(encoded, 48),
            FrameCommitmentV1::from_bytes(read_array(encoded, 56)),
        )
    }
}

impl fmt::Debug for SegmentHeaderV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentHeaderV2")
            .field("segment_ordinal", &self.segment_ordinal)
            .finish_non_exhaustive()
    }
}

/// Fixed V2 frame header. The nonce is exactly `prefix || counter_be`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrameHeaderV2 {
    object_kind: SnapshotObjectKindV2,
    segment_ordinal: u64,
    frame_sequence: u32,
    global_sequence: u64,
    plaintext_length: u32,
    nonce_prefix: [u8; 16],
    nonce_counter: u64,
    previous_frame_commitment: FrameCommitmentV1,
}

impl FrameHeaderV2 {
    pub fn new(
        object_kind: SnapshotObjectKindV2,
        segment_ordinal: u64,
        frame_sequence: u32,
        global_sequence: u64,
        plaintext_length: u32,
        nonce: [u8; 24],
        previous_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, SnapshotFrameErrorV2> {
        if frame_sequence >= MAX_FRAMES_PER_SEGMENT_V1
            || usize::try_from(plaintext_length)
                .map_err(|_| SnapshotFrameErrorV2::LengthOverflow)?
                > MAX_FRAME_PLAINTEXT_BYTES_V1
        {
            return Err(SnapshotFrameErrorV2::FrameLimit);
        }
        if (frame_sequence == 0) != (previous_frame_commitment == FrameCommitmentV1::ZERO) {
            return Err(SnapshotFrameErrorV2::InvalidFrameChain);
        }
        let mut nonce_prefix = [0u8; 16];
        nonce_prefix.copy_from_slice(&nonce[..16]);
        if nonce_prefix.iter().all(|byte| *byte == 0) {
            return Err(SnapshotFrameErrorV2::InvalidNonce);
        }
        Ok(Self {
            object_kind,
            segment_ordinal,
            frame_sequence,
            global_sequence,
            plaintext_length,
            nonce_prefix,
            nonce_counter: u64::from_be_bytes(read_array(&nonce, 16)),
            previous_frame_commitment,
        })
    }

    #[must_use]
    pub const fn object_kind(self) -> SnapshotObjectKindV2 {
        self.object_kind
    }

    #[must_use]
    pub const fn segment_ordinal(self) -> u64 {
        self.segment_ordinal
    }

    #[must_use]
    pub const fn frame_sequence(self) -> u32 {
        self.frame_sequence
    }

    #[must_use]
    pub const fn global_sequence(self) -> u64 {
        self.global_sequence
    }

    #[must_use]
    pub const fn plaintext_length(self) -> u32 {
        self.plaintext_length
    }

    #[must_use]
    pub const fn nonce_counter(self) -> u64 {
        self.nonce_counter
    }

    #[must_use]
    pub const fn previous_frame_commitment(self) -> FrameCommitmentV1 {
        self.previous_frame_commitment
    }

    #[must_use]
    pub fn nonce(self) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.nonce_prefix);
        nonce[16..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        nonce
    }

    #[must_use]
    pub fn encode(self) -> [u8; FRAME_HEADER_BYTES_V2] {
        let mut encoded = [0u8; FRAME_HEADER_BYTES_V2];
        encoded[0..8].copy_from_slice(&FRAME_MAGIC_V2);
        encoded[8..10].copy_from_slice(&SNAPSHOT_FORMAT_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(&self.object_kind.code().to_be_bytes());
        encoded[16..24].copy_from_slice(&self.segment_ordinal.to_be_bytes());
        encoded[24..28].copy_from_slice(&self.frame_sequence.to_be_bytes());
        encoded[28..36].copy_from_slice(&self.global_sequence.to_be_bytes());
        encoded[36..40].copy_from_slice(&self.plaintext_length.to_be_bytes());
        encoded[40..56].copy_from_slice(&self.nonce_prefix);
        encoded[56..64].copy_from_slice(&self.nonce_counter.to_be_bytes());
        encoded[64..96].copy_from_slice(self.previous_frame_commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFrameErrorV2> {
        if encoded.len() != FRAME_HEADER_BYTES_V2 {
            return Err(SnapshotFrameErrorV2::InvalidEncodedLength);
        }
        if encoded[0..8] != FRAME_MAGIC_V2 {
            return Err(SnapshotFrameErrorV2::InvalidMagic);
        }
        if read_u16(encoded, 8) != SNAPSHOT_FORMAT_VERSION_V2 {
            return Err(SnapshotFrameErrorV2::UnsupportedVersion);
        }
        if encoded[12..16].iter().any(|byte| *byte != 0) {
            return Err(SnapshotFrameErrorV2::NonzeroReserved);
        }
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&encoded[40..56]);
        nonce[16..].copy_from_slice(&encoded[56..64]);
        Self::new(
            SnapshotObjectKindV2::from_code(read_u16(encoded, 10))?,
            read_u64(encoded, 16),
            read_u32(encoded, 24),
            read_u64(encoded, 28),
            read_u32(encoded, 36),
            nonce,
            FrameCommitmentV1::from_bytes(read_array(encoded, 64)),
        )
    }
}

impl fmt::Debug for FrameHeaderV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameHeaderV2")
            .field("object_kind", &self.object_kind)
            .field("segment_ordinal", &self.segment_ordinal)
            .field("frame_sequence", &self.frame_sequence)
            .field("plaintext_length", &self.plaintext_length)
            .finish()
    }
}

pub struct OpenedFrameV2(Zeroizing<Vec<u8>>);

impl OpenedFrameV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OpenedFrameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedFrameV2(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedFrameV2 {
    header: FrameHeaderV2,
    ciphertext: Vec<u8>,
    tag: [u8; FRAME_TAG_BYTES_V1],
    commitment: FrameCommitmentV1,
}

impl SealedFrameV2 {
    #[must_use]
    pub const fn header(&self) -> FrameHeaderV2 {
        self.header
    }

    #[must_use]
    pub const fn commitment(&self) -> FrameCommitmentV1 {
        self.commitment
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_BYTES_V2
            + self.ciphertext.len()
            + FRAME_TAG_BYTES_V1
            + FRAME_COMMITMENT_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&self.header.encode());
        encoded.extend_from_slice(&self.ciphertext);
        encoded.extend_from_slice(&self.tag);
        encoded.extend_from_slice(self.commitment.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFrameErrorV2> {
        if encoded.len() < FRAME_HEADER_BYTES_V2 + FRAME_TAG_BYTES_V1 + FRAME_COMMITMENT_BYTES_V1
            || encoded.len() > MAX_ENCODED_FRAME_BYTES_V2
        {
            return Err(SnapshotFrameErrorV2::InvalidEncodedLength);
        }
        let header = FrameHeaderV2::decode(&encoded[..FRAME_HEADER_BYTES_V2])?;
        let plaintext_length = usize::try_from(header.plaintext_length())
            .map_err(|_| SnapshotFrameErrorV2::LengthOverflow)?;
        let expected = FRAME_HEADER_BYTES_V2
            .checked_add(plaintext_length)
            .and_then(|value| value.checked_add(FRAME_TAG_BYTES_V1 + FRAME_COMMITMENT_BYTES_V1))
            .ok_or(SnapshotFrameErrorV2::LengthOverflow)?;
        if encoded.len() != expected {
            return Err(SnapshotFrameErrorV2::InvalidEncodedLength);
        }
        let ciphertext_end = FRAME_HEADER_BYTES_V2 + plaintext_length;
        Ok(Self {
            header,
            ciphertext: encoded[FRAME_HEADER_BYTES_V2..ciphertext_end].to_vec(),
            tag: read_array(encoded, ciphertext_end),
            commitment: FrameCommitmentV1::from_bytes(read_array(
                encoded,
                ciphertext_end + FRAME_TAG_BYTES_V1,
            )),
        })
    }
}

impl fmt::Debug for SealedFrameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedFrameV2")
            .field("header", &self.header)
            .field("encoded_byte_count", &self.encoded_len())
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn canonical_frame_aad_v2(segment: SegmentHeaderV2, header: FrameHeaderV2) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        FRAME_AAD_DOMAIN_V2.len() + SEGMENT_HEADER_BYTES_V2 + FRAME_HEADER_BYTES_V2,
    );
    aad.extend_from_slice(FRAME_AAD_DOMAIN_V2);
    aad.extend_from_slice(&segment.encode());
    aad.extend_from_slice(&header.encode());
    aad
}

pub fn seal_frame_v2(
    result_dek: &ResultDekV1,
    segment: SegmentHeaderV2,
    header: FrameHeaderV2,
    plaintext: &[u8],
) -> Result<SealedFrameV2, SnapshotFrameErrorV2> {
    validate_header_against_segment(segment, header, plaintext.len())?;
    let aad = canonical_frame_aad_v2(segment, header);
    let cipher = XChaCha20Poly1305::new_from_slice(result_dek.frame_key().as_bytes())
        .map_err(|_| SnapshotFrameErrorV2::AuthenticationFailed)?;
    let nonce = XNonce::from(header.nonce());
    let mut ciphertext = plaintext.to_vec();
    let tag = match cipher.encrypt_inout_detached(&nonce, &aad, ciphertext.as_mut_slice().into()) {
        Ok(tag) => tag,
        Err(_) => {
            ciphertext.zeroize();
            return Err(SnapshotFrameErrorV2::AuthenticationFailed);
        }
    };
    let tag: [u8; FRAME_TAG_BYTES_V1] = tag.into();
    let commitment = derive_frame_commitment_v2(segment, header, &ciphertext, &tag);
    Ok(SealedFrameV2 {
        header,
        ciphertext,
        tag,
        commitment,
    })
}

pub fn open_frame_v2(
    result_dek: &ResultDekV1,
    segment: SegmentHeaderV2,
    frame: &SealedFrameV2,
) -> Result<OpenedFrameV2, SnapshotFrameErrorV2> {
    validate_header_against_segment(segment, frame.header, frame.ciphertext.len())?;
    let expected = derive_frame_commitment_v2(segment, frame.header, &frame.ciphertext, &frame.tag);
    if expected != frame.commitment {
        return Err(SnapshotFrameErrorV2::CommitmentMismatch);
    }
    let aad = canonical_frame_aad_v2(segment, frame.header);
    let cipher = XChaCha20Poly1305::new_from_slice(result_dek.frame_key().as_bytes())
        .map_err(|_| SnapshotFrameErrorV2::AuthenticationFailed)?;
    let nonce = XNonce::from(frame.header.nonce());
    let tag = Tag::from(frame.tag);
    let mut plaintext = Zeroizing::new(frame.ciphertext.clone());
    cipher
        .decrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| SnapshotFrameErrorV2::AuthenticationFailed)?;
    Ok(OpenedFrameV2(plaintext))
}

fn validate_header_against_segment(
    segment: SegmentHeaderV2,
    header: FrameHeaderV2,
    plaintext_length: usize,
) -> Result<(), SnapshotFrameErrorV2> {
    if segment.segment_ordinal() != header.segment_ordinal()
        || plaintext_length
            != usize::try_from(header.plaintext_length())
                .map_err(|_| SnapshotFrameErrorV2::LengthOverflow)?
        || (header.frame_sequence() == 0
            && header.previous_frame_commitment() != FrameCommitmentV1::ZERO)
    {
        return Err(SnapshotFrameErrorV2::HeaderContextMismatch);
    }
    Ok(())
}

fn derive_frame_commitment_v2(
    segment: SegmentHeaderV2,
    header: FrameHeaderV2,
    ciphertext: &[u8],
    tag: &[u8; FRAME_TAG_BYTES_V1],
) -> FrameCommitmentV1 {
    let mut hasher = Sha256::new();
    hasher.update(FRAME_COMMITMENT_DOMAIN_V2);
    hasher.update(segment.encode());
    hasher.update(header.encode());
    hasher.update(ciphertext);
    hasher.update(tag);
    FrameCommitmentV1::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFrameErrorV2 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedObjectKind,
    NonzeroReserved,
    InvalidSegmentChain,
    InvalidFrameChain,
    InvalidNonce,
    FrameLimit,
    LengthOverflow,
    HeaderContextMismatch,
    CommitmentMismatch,
    AuthenticationFailed,
}

impl SnapshotFrameErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_SNAPSHOT_V2_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_SNAPSHOT_V2_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_SNAPSHOT_V2_UNSUPPORTED_VERSION",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_SNAPSHOT_V2_UNSUPPORTED_OBJECT_KIND",
            Self::NonzeroReserved => "EVIDENTRAIL_SNAPSHOT_V2_NONZERO_RESERVED",
            Self::InvalidSegmentChain => "EVIDENTRAIL_SNAPSHOT_V2_INVALID_SEGMENT_CHAIN",
            Self::InvalidFrameChain => "EVIDENTRAIL_SNAPSHOT_V2_INVALID_FRAME_CHAIN",
            Self::InvalidNonce => "EVIDENTRAIL_SNAPSHOT_V2_INVALID_NONCE",
            Self::FrameLimit => "EVIDENTRAIL_SNAPSHOT_V2_FRAME_LIMIT",
            Self::LengthOverflow => "EVIDENTRAIL_SNAPSHOT_V2_LENGTH_OVERFLOW",
            Self::HeaderContextMismatch => "EVIDENTRAIL_SNAPSHOT_V2_HEADER_CONTEXT_MISMATCH",
            Self::CommitmentMismatch => "EVIDENTRAIL_SNAPSHOT_V2_COMMITMENT_MISMATCH",
            Self::AuthenticationFailed => "EVIDENTRAIL_SNAPSHOT_V2_AUTHENTICATION_FAILED",
        }
    }
}

impl fmt::Debug for SnapshotFrameErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotFrameErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SnapshotFrameErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SnapshotFrameErrorV2 {}

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
    let mut result = [0u8; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
