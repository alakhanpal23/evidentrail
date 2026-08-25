use std::collections::BTreeSet;
use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    FRAME_HEADER_BYTES_V1, FRAME_NONCE_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1,
    FrameHeaderV1, FrameKeyViewV1, FrameNonceV1, FrameObjectKindV1, MAX_ENCODED_FRAME_BYTES_V1,
    MAX_FRAMES_PER_SEGMENT_V1, SEGMENT_HEADER_BYTES_V1, SegmentHeaderV1, SnapshotFormatErrorV1,
};

pub const FRAME_AAD_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.frame.v1";
pub const FRAME_AAD_BYTES_V1: usize =
    FRAME_AAD_DOMAIN_V1.len() + SEGMENT_HEADER_BYTES_V1 + FRAME_HEADER_BYTES_V1;

const SEGMENT_START_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.segment-start.v1";
const FRAME_COMMITMENT_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.frame-commit.v1";

/// One bounded encoded frame plus its derived, non-serialized chain value.
#[derive(PartialEq, Eq)]
pub struct SealedFrameV1 {
    header: FrameHeaderV1,
    ciphertext: Vec<u8>,
    tag: [u8; FRAME_TAG_BYTES_V1],
    commitment: FrameCommitmentV1,
}

impl SealedFrameV1 {
    #[must_use]
    pub const fn header(&self) -> &FrameHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn commitment(&self) -> FrameCommitmentV1 {
        self.commitment
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_BYTES_V1 + self.ciphertext.len() + FRAME_TAG_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&self.header.encode());
        encoded.extend_from_slice(&self.ciphertext);
        encoded.extend_from_slice(&self.tag);
        encoded
    }

    pub fn decode(
        segment_header: &SegmentHeaderV1,
        encoded: &[u8],
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if encoded.len() < FRAME_HEADER_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        let header = FrameHeaderV1::decode(&encoded[..FRAME_HEADER_BYTES_V1])?;
        let ciphertext_length = usize::try_from(header.ciphertext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?;
        let expected_length = FRAME_HEADER_BYTES_V1
            .checked_add(ciphertext_length)
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        if expected_length > MAX_ENCODED_FRAME_BYTES_V1 || encoded.len() != expected_length {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        let ciphertext_end = expected_length
            .checked_sub(FRAME_TAG_BYTES_V1)
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        let ciphertext = encoded[FRAME_HEADER_BYTES_V1..ciphertext_end].to_vec();
        let mut tag = [0u8; FRAME_TAG_BYTES_V1];
        tag.copy_from_slice(&encoded[ciphertext_end..expected_length]);
        let commitment = derive_frame_commitment(segment_header, &header, &ciphertext, &tag);
        Ok(Self {
            header,
            ciphertext,
            tag,
            commitment,
        })
    }
}

impl fmt::Debug for SealedFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedFrameV1")
            .field("header", &self.header)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("tag_bytes", &FRAME_TAG_BYTES_V1)
            .finish()
    }
}

/// Authenticated plaintext which clears its owned allocation on drop.
pub struct OpenedFrameV1(Zeroizing<Vec<u8>>);

impl OpenedFrameV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OpenedFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedFrameV1")
            .field("byte_count", &self.0.len())
            .finish()
    }
}

/// Exact fixed-width AAD: domain || encoded segment header || encoded frame header.
#[must_use]
pub fn canonical_frame_aad_v1(
    segment_header: &SegmentHeaderV1,
    frame_header: &FrameHeaderV1,
) -> [u8; FRAME_AAD_BYTES_V1] {
    let mut aad = [0u8; FRAME_AAD_BYTES_V1];
    let segment_offset = FRAME_AAD_DOMAIN_V1.len();
    let frame_offset = segment_offset + SEGMENT_HEADER_BYTES_V1;
    aad[..segment_offset].copy_from_slice(FRAME_AAD_DOMAIN_V1);
    aad[segment_offset..frame_offset].copy_from_slice(&segment_header.encode());
    aad[frame_offset..].copy_from_slice(&frame_header.encode());
    aad
}

/// Derive the required previous commitment for frame zero in a segment.
#[must_use]
pub fn segment_start_commitment_v1(segment_header: &SegmentHeaderV1) -> FrameCommitmentV1 {
    let mut hasher = Sha256::new();
    hasher.update(SEGMENT_START_DOMAIN_V1);
    hasher.update(segment_header.encode());
    FrameCommitmentV1::from_bytes(hasher.finalize().into())
}

/// Seal one already-validated header and exact plaintext with injected key material.
pub fn seal_frame_v1(
    key: &FrameKeyViewV1<'_>,
    segment_header: &SegmentHeaderV1,
    frame_header: FrameHeaderV1,
    plaintext: &[u8],
) -> Result<SealedFrameV1, SnapshotFormatErrorV1> {
    let aad = canonical_frame_aad_v1(segment_header, &frame_header);
    seal_frame_with_aad_v1(key, segment_header, frame_header, plaintext, &aad)
}

pub(crate) fn seal_frame_with_aad_v1(
    key: &FrameKeyViewV1<'_>,
    segment_header: &SegmentHeaderV1,
    frame_header: FrameHeaderV1,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedFrameV1, SnapshotFormatErrorV1> {
    if segment_header.segment_sequence() == 0
        && frame_header.segment_frame_sequence() == 0
        && frame_header.global_sequence() != 0
    {
        return Err(SnapshotFormatErrorV1::GlobalSequenceMismatch);
    }
    if plaintext.len()
        != usize::try_from(frame_header.plaintext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?
    {
        return Err(SnapshotFormatErrorV1::PlaintextLengthMismatch);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*frame_header.nonce().as_bytes());
    let mut ciphertext = plaintext.to_vec();
    let tag = match cipher.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into()) {
        Ok(tag) => tag,
        Err(_) => {
            ciphertext.zeroize();
            return Err(SnapshotFormatErrorV1::AuthenticationFailed);
        }
    };
    let tag: [u8; FRAME_TAG_BYTES_V1] = tag.into();
    let commitment = derive_frame_commitment(segment_header, &frame_header, &ciphertext, &tag);
    Ok(SealedFrameV1 {
        header: frame_header,
        ciphertext,
        tag,
        commitment,
    })
}

/// Authenticate and decrypt one frame. Returned plaintext is zeroized on drop.
pub fn open_frame_v1(
    key: &FrameKeyViewV1<'_>,
    segment_header: &SegmentHeaderV1,
    frame: &SealedFrameV1,
) -> Result<OpenedFrameV1, SnapshotFormatErrorV1> {
    let aad = canonical_frame_aad_v1(segment_header, &frame.header);
    open_frame_with_aad_v1(key, segment_header, frame, &aad)
}

pub(crate) fn open_frame_with_aad_v1(
    key: &FrameKeyViewV1<'_>,
    segment_header: &SegmentHeaderV1,
    frame: &SealedFrameV1,
    aad: &[u8],
) -> Result<OpenedFrameV1, SnapshotFormatErrorV1> {
    let expected_commitment =
        derive_frame_commitment(segment_header, &frame.header, &frame.ciphertext, &frame.tag);
    if expected_commitment != frame.commitment {
        return Err(SnapshotFormatErrorV1::CommitmentMismatch);
    }
    if frame.ciphertext.len()
        != usize::try_from(frame.header.plaintext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?
    {
        return Err(SnapshotFormatErrorV1::CiphertextLengthMismatch);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*frame.header.nonce().as_bytes());
    let tag = Tag::from(frame.tag);
    let mut plaintext = Zeroizing::new(frame.ciphertext.clone());
    cipher
        .decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    Ok(OpenedFrameV1(plaintext))
}

/// Bounded in-memory sequence verifier/sealer for one segment.
///
/// It provides no persistence or final-truncation guarantee. The future sealed
/// manifest must bind final counts and the returned final commitment.
pub struct FrameChainV1 {
    segment_header: SegmentHeaderV1,
    next_global_sequence: u64,
    next_segment_frame_sequence: u32,
    previous_commitment: FrameCommitmentV1,
    seen_nonces: BTreeSet<FrameNonceV1>,
}

impl FrameChainV1 {
    pub fn new(
        segment_header: SegmentHeaderV1,
        first_global_sequence: u64,
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if (segment_header.segment_sequence() == 0) != (first_global_sequence == 0) {
            return Err(SnapshotFormatErrorV1::GlobalSequenceMismatch);
        }
        let previous_commitment = segment_start_commitment_v1(&segment_header);
        Ok(Self {
            segment_header,
            next_global_sequence: first_global_sequence,
            next_segment_frame_sequence: 0,
            previous_commitment,
            seen_nonces: BTreeSet::new(),
        })
    }

    #[must_use]
    pub const fn segment_header(&self) -> &SegmentHeaderV1 {
        &self.segment_header
    }

    #[must_use]
    pub const fn next_global_sequence(&self) -> u64 {
        self.next_global_sequence
    }

    #[must_use]
    pub const fn next_segment_frame_sequence(&self) -> u32 {
        self.next_segment_frame_sequence
    }

    #[must_use]
    pub const fn final_commitment(&self) -> FrameCommitmentV1 {
        self.previous_commitment
    }

    pub fn seal_next(
        &mut self,
        key: &FrameKeyViewV1<'_>,
        object_kind: FrameObjectKindV1,
        nonce: FrameNonceV1,
        plaintext: &[u8],
    ) -> Result<SealedFrameV1, SnapshotFormatErrorV1> {
        self.validate_next_nonce(nonce)?;
        let (next_global, next_segment) = self.checked_advanced_sequences()?;
        let plaintext_length =
            u32::try_from(plaintext.len()).map_err(|_| SnapshotFormatErrorV1::PlaintextTooLarge)?;
        let header = FrameHeaderV1::new(
            object_kind,
            self.next_global_sequence,
            self.next_segment_frame_sequence,
            plaintext_length,
            nonce,
            self.previous_commitment,
        )?;
        let frame = seal_frame_v1(key, &self.segment_header, header, plaintext)?;
        self.commit_advance(nonce, frame.commitment, next_global, next_segment);
        Ok(frame)
    }

    pub fn open_next(
        &mut self,
        key: &FrameKeyViewV1<'_>,
        frame: &SealedFrameV1,
    ) -> Result<OpenedFrameV1, SnapshotFormatErrorV1> {
        if frame.header.global_sequence() != self.next_global_sequence {
            return Err(SnapshotFormatErrorV1::GlobalSequenceMismatch);
        }
        if frame.header.segment_frame_sequence() != self.next_segment_frame_sequence {
            return Err(SnapshotFormatErrorV1::SegmentFrameSequenceMismatch);
        }
        if frame.header.previous_frame_commitment() != self.previous_commitment {
            return Err(SnapshotFormatErrorV1::PreviousCommitmentMismatch);
        }
        let nonce = frame.header.nonce();
        self.validate_next_nonce(nonce)?;
        let (next_global, next_segment) = self.checked_advanced_sequences()?;
        let plaintext = open_frame_v1(key, &self.segment_header, frame)?;
        self.commit_advance(nonce, frame.commitment, next_global, next_segment);
        Ok(plaintext)
    }

    fn validate_next_nonce(&self, nonce: FrameNonceV1) -> Result<(), SnapshotFormatErrorV1> {
        if self.next_segment_frame_sequence >= MAX_FRAMES_PER_SEGMENT_V1 {
            return Err(SnapshotFormatErrorV1::FrameCountCap);
        }
        if self.seen_nonces.contains(&nonce) {
            return Err(SnapshotFormatErrorV1::DuplicateNonce);
        }
        Ok(())
    }

    fn checked_advanced_sequences(&self) -> Result<(u64, u32), SnapshotFormatErrorV1> {
        Ok((
            self.next_global_sequence
                .checked_add(1)
                .ok_or(SnapshotFormatErrorV1::LengthOverflow)?,
            self.next_segment_frame_sequence
                .checked_add(1)
                .ok_or(SnapshotFormatErrorV1::LengthOverflow)?,
        ))
    }

    fn commit_advance(
        &mut self,
        nonce: FrameNonceV1,
        commitment: FrameCommitmentV1,
        next_global: u64,
        next_segment: u32,
    ) {
        self.seen_nonces.insert(nonce);
        self.previous_commitment = commitment;
        self.next_global_sequence = next_global;
        self.next_segment_frame_sequence = next_segment;
    }
}

impl fmt::Debug for FrameChainV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameChainV1")
            .field("next_global_sequence", &self.next_global_sequence)
            .field(
                "next_segment_frame_sequence",
                &self.next_segment_frame_sequence,
            )
            .field("seen_nonce_count", &self.seen_nonces.len())
            .finish()
    }
}

fn derive_frame_commitment(
    segment_header: &SegmentHeaderV1,
    frame_header: &FrameHeaderV1,
    ciphertext: &[u8],
    tag: &[u8; FRAME_TAG_BYTES_V1],
) -> FrameCommitmentV1 {
    let mut hasher = Sha256::new();
    hasher.update(FRAME_COMMITMENT_DOMAIN_V1);
    hasher.update(segment_header.encode());
    hasher.update(frame_header.encode());
    hasher.update(ciphertext);
    hasher.update(tag);
    FrameCommitmentV1::from_bytes(hasher.finalize().into())
}

const _: () = assert!(FRAME_NONCE_BYTES_V1 == 24);
