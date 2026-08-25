use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1, FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1,
    FrameCommitmentV1, FrameNonceV1, MAX_ENCODED_MANIFEST_BYTES_V1, MAX_FRAMES_PER_SEGMENT_V1,
    SEGMENT_HEADER_BYTES_V1, SealedCoreResultManifestV1, SealedFrameV1, SegmentHeaderV1,
    XCHACHA20_POLY1305_SUITE_ID_V1, segment_start_commitment_v1,
};

use crate::encrypted_core_repository::{
    MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1, MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1,
    MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1,
};

/// Every V1 offset is an absolute byte offset from this bundle origin.
pub const SEALED_BUNDLE_ORIGIN_V1: u64 = 0;
pub const SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_VERSION_V1: u16 = 1;
pub const SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_OBJECT_KIND_V1: u16 = 1;
pub const SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1: usize = 128;
pub const SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1: usize = 48;
pub const SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1: usize = 40;

/// Maximum encoded size of the bounded in-memory ciphertext transport.
///
/// This is derived from the existing 16 MiB outer-manifest bound, the existing
/// 64 MiB aggregate segment/header/frame bound, and one fixed descriptor for
/// every admitted segment and frame. It is not a filesystem or durability
/// limit and conveys no plaintext-size authority beyond those child formats.
pub const MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1: usize =
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
        + MAX_ENCODED_MANIFEST_BYTES_V1
        + MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1
            * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1
        + MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1
            * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1
        + MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1;

const BUNDLE_MAGIC_V1: [u8; 8] = *b"EVRSEB01";

const VERSION_OFFSET: usize = 8;
const SUITE_OFFSET: usize = 10;
const OBJECT_KIND_OFFSET: usize = 12;
const HEADER_LENGTH_OFFSET: usize = 14;
const FLAGS_OFFSET: usize = 16;
const HEADER_RESERVED_START: usize = 20;
const HEADER_RESERVED_END: usize = 32;
const RESULT_ID_OFFSET: usize = 32;
const TOTAL_LENGTH_OFFSET: usize = 64;
const MANIFEST_OFFSET_OFFSET: usize = 72;
const MANIFEST_LENGTH_OFFSET: usize = 80;
const DIRECTORY_OFFSET_OFFSET: usize = 88;
const DIRECTORY_LENGTH_OFFSET: usize = 96;
const PAYLOAD_OFFSET_OFFSET: usize = 104;
const PAYLOAD_LENGTH_OFFSET: usize = 112;
const SEGMENT_COUNT_OFFSET: usize = 120;
const FRAME_COUNT_OFFSET: usize = 124;

/// Stable, contentless canonical-bundle codec failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SealedEncryptedCoreResultBundleErrorV1 {
    InvalidResultId,
    InvalidMagic,
    UnknownVersion,
    UnknownSuite,
    UnknownObjectKind,
    InvalidHeaderLength,
    NonzeroFlags,
    NonzeroReserved,
    Truncated,
    TrailingData,
    LengthOverflow,
    ManifestLengthCap,
    SegmentCountCap,
    FrameCountCap,
    FrameByteCap,
    NoncanonicalLayout,
    ManifestDecodeFailed,
    SegmentHeaderDecodeFailed,
    FrameDecodeFailed,
    ResultIdentityMismatch,
    SequenceMismatch,
    ChainMismatch,
    DuplicateNonce,
}

impl SealedEncryptedCoreResultBundleErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidResultId => "EVIDENTRAIL_SEALED_BUNDLE_INVALID_RESULT_ID",
            Self::InvalidMagic => "EVIDENTRAIL_SEALED_BUNDLE_INVALID_MAGIC",
            Self::UnknownVersion => "EVIDENTRAIL_SEALED_BUNDLE_UNKNOWN_VERSION",
            Self::UnknownSuite => "EVIDENTRAIL_SEALED_BUNDLE_UNKNOWN_SUITE",
            Self::UnknownObjectKind => "EVIDENTRAIL_SEALED_BUNDLE_UNKNOWN_OBJECT_KIND",
            Self::InvalidHeaderLength => "EVIDENTRAIL_SEALED_BUNDLE_INVALID_HEADER_LENGTH",
            Self::NonzeroFlags => "EVIDENTRAIL_SEALED_BUNDLE_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_SEALED_BUNDLE_NONZERO_RESERVED",
            Self::Truncated => "EVIDENTRAIL_SEALED_BUNDLE_TRUNCATED",
            Self::TrailingData => "EVIDENTRAIL_SEALED_BUNDLE_TRAILING_DATA",
            Self::LengthOverflow => "EVIDENTRAIL_SEALED_BUNDLE_LENGTH_OVERFLOW",
            Self::ManifestLengthCap => "EVIDENTRAIL_SEALED_BUNDLE_MANIFEST_LENGTH_CAP",
            Self::SegmentCountCap => "EVIDENTRAIL_SEALED_BUNDLE_SEGMENT_COUNT_CAP",
            Self::FrameCountCap => "EVIDENTRAIL_SEALED_BUNDLE_FRAME_COUNT_CAP",
            Self::FrameByteCap => "EVIDENTRAIL_SEALED_BUNDLE_FRAME_BYTE_CAP",
            Self::NoncanonicalLayout => "EVIDENTRAIL_SEALED_BUNDLE_NONCANONICAL_LAYOUT",
            Self::ManifestDecodeFailed => "EVIDENTRAIL_SEALED_BUNDLE_MANIFEST_DECODE_FAILED",
            Self::SegmentHeaderDecodeFailed => "EVIDENTRAIL_SEALED_BUNDLE_SEGMENT_HEADER_DECODE_FAILED",
            Self::FrameDecodeFailed => "EVIDENTRAIL_SEALED_BUNDLE_FRAME_DECODE_FAILED",
            Self::ResultIdentityMismatch => "EVIDENTRAIL_SEALED_BUNDLE_RESULT_IDENTITY_MISMATCH",
            Self::SequenceMismatch => "EVIDENTRAIL_SEALED_BUNDLE_SEQUENCE_MISMATCH",
            Self::ChainMismatch => "EVIDENTRAIL_SEALED_BUNDLE_CHAIN_MISMATCH",
            Self::DuplicateNonce => "EVIDENTRAIL_SEALED_BUNDLE_DUPLICATE_NONCE",
        }
    }
}

impl fmt::Debug for SealedEncryptedCoreResultBundleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedEncryptedCoreResultBundleErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SealedEncryptedCoreResultBundleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SealedEncryptedCoreResultBundleErrorV1 {}

pub(crate) struct SealedBundleSegmentV1 {
    pub(crate) encoded_header: [u8; SEGMENT_HEADER_BYTES_V1],
    pub(crate) encoded_frames: Vec<Vec<u8>>,
}

/// Canonical process-local transport for one already sealed result's exact
/// ciphertext objects.
///
/// The object contains no plaintext. Structural decode does not authenticate
/// the manifest or frames and does not establish key authority. Only an
/// authenticated repository import under an independently sealed key record
/// may publish it. This type makes no filesystem, write-order, durability,
/// recovery, rollback-prevention, or publication claim.
pub struct SealedEncryptedCoreResultBundleV1 {
    result_id: ResultId,
    encoded_manifest: Vec<u8>,
    segments: Vec<SealedBundleSegmentV1>,
    frame_count: usize,
    encoded_frame_bytes: usize,
    encoded_len: usize,
}

impl SealedEncryptedCoreResultBundleV1 {
    pub(crate) fn from_encrypted_parts(
        result_id: ResultId,
        encoded_manifest: Vec<u8>,
        segments: Vec<SealedBundleSegmentV1>,
    ) -> Result<Self, SealedEncryptedCoreResultBundleErrorV1> {
        let (frame_count, encoded_frame_bytes) =
            validate_encrypted_parts(result_id, &encoded_manifest, &segments)?;
        let encoded_len = canonical_encoded_len(
            encoded_manifest.len(),
            segments.len(),
            frame_count,
            encoded_frame_bytes,
        )?;
        Ok(Self {
            result_id,
            encoded_manifest,
            segments,
            frame_count,
            encoded_frame_bytes,
            encoded_len,
        })
    }

    /// Strictly decode an untrusted canonical ciphertext bundle.
    ///
    /// All attacker-controlled counts, lengths, and ends are checked against
    /// hard bounds and the input slice before ciphertext allocations occur.
    pub fn decode(encoded: &[u8]) -> Result<Self, SealedEncryptedCoreResultBundleErrorV1> {
        if encoded.len() < SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::Truncated);
        }
        if encoded.len() > MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap);
        }
        validate_fixed_header(encoded)?;

        let total_length = read_usize_u64(encoded, TOTAL_LENGTH_OFFSET)?;
        if total_length < encoded.len() {
            return Err(SealedEncryptedCoreResultBundleErrorV1::TrailingData);
        }
        if total_length > encoded.len() {
            return Err(SealedEncryptedCoreResultBundleErrorV1::Truncated);
        }
        if total_length > MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap);
        }

        let result_id = ResultId::from_bytes(read_array(encoded, RESULT_ID_OFFSET));
        if result_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(SealedEncryptedCoreResultBundleErrorV1::InvalidResultId);
        }
        let segment_count = read_usize_u32(encoded, SEGMENT_COUNT_OFFSET);
        let frame_count = read_usize_u32(encoded, FRAME_COUNT_OFFSET);
        validate_counts(segment_count, frame_count)?;

        let manifest_offset = read_usize_u64(encoded, MANIFEST_OFFSET_OFFSET)?;
        let manifest_length = read_usize_u64(encoded, MANIFEST_LENGTH_OFFSET)?;
        if manifest_length == 0 || manifest_length > MAX_ENCODED_MANIFEST_BYTES_V1 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::ManifestLengthCap);
        }
        let directory_offset = read_usize_u64(encoded, DIRECTORY_OFFSET_OFFSET)?;
        let directory_length = read_usize_u64(encoded, DIRECTORY_LENGTH_OFFSET)?;
        let payload_offset = read_usize_u64(encoded, PAYLOAD_OFFSET_OFFSET)?;
        let payload_length = read_usize_u64(encoded, PAYLOAD_LENGTH_OFFSET)?;
        if payload_length == 0 || payload_length > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap);
        }
        let expected_directory_length = canonical_directory_len(segment_count, frame_count)?;
        let expected_directory_offset = SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
            .checked_add(manifest_length)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        let expected_payload_offset = expected_directory_offset
            .checked_add(expected_directory_length)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        let expected_total = expected_payload_offset
            .checked_add(payload_length)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        if manifest_offset != SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
            || directory_offset != expected_directory_offset
            || directory_length != expected_directory_length
            || payload_offset != expected_payload_offset
            || total_length != expected_total
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
        checked_slice(encoded, manifest_offset, manifest_length)?;
        checked_slice(encoded, directory_offset, directory_length)?;
        checked_slice(encoded, payload_offset, payload_length)?;

        let segment_descriptors = decode_segment_descriptors(
            encoded,
            directory_offset,
            segment_count,
            frame_count,
            payload_offset,
            total_length,
        )?;
        let frame_directory_offset = directory_offset
            .checked_add(
                segment_count
                    .checked_mul(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1)
                    .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?,
            )
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        let frame_descriptors = decode_frame_descriptors(
            encoded,
            frame_directory_offset,
            frame_count,
            payload_offset,
            total_length,
        )?;
        validate_descriptor_contiguity(
            &segment_descriptors,
            &frame_descriptors,
            payload_offset,
            total_length,
        )?;

        let encoded_manifest = checked_slice(encoded, manifest_offset, manifest_length)?.to_vec();
        let mut segments = Vec::with_capacity(segment_count);
        for descriptor in &segment_descriptors {
            let header_bytes =
                checked_slice(encoded, descriptor.payload_offset, SEGMENT_HEADER_BYTES_V1)?;
            let mut encoded_header = [0u8; SEGMENT_HEADER_BYTES_V1];
            encoded_header.copy_from_slice(header_bytes);
            let first_frame = descriptor.first_frame_index;
            let frame_end = first_frame
                .checked_add(descriptor.frame_count)
                .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
            let mut encoded_frames = Vec::with_capacity(descriptor.frame_count);
            for frame_descriptor in &frame_descriptors[first_frame..frame_end] {
                encoded_frames.push(
                    checked_slice(
                        encoded,
                        frame_descriptor.payload_offset,
                        frame_descriptor.encoded_length,
                    )?
                    .to_vec(),
                );
            }
            segments.push(SealedBundleSegmentV1 {
                encoded_header,
                encoded_frames,
            });
        }

        let bundle = Self::from_encrypted_parts(result_id, encoded_manifest, segments)?;
        if bundle.frame_count != frame_count
            || bundle.encoded_frame_bytes != payload_length
            || bundle.encoded_len != total_length
            || bundle.encode().as_slice() != encoded
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
        Ok(bundle)
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    #[must_use]
    pub const fn encoded_frame_bytes(&self) -> usize {
        self.encoded_frame_bytes
    }

    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let segment_count = self.segments.len();
        let directory_length = canonical_directory_len(segment_count, self.frame_count)
            .expect("validated sealed bundle directory length");
        let directory_offset =
            SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 + self.encoded_manifest.len();
        let payload_offset = directory_offset + directory_length;
        let mut encoded = vec![0u8; payload_offset];
        encoded[0..8].copy_from_slice(&BUNDLE_MAGIC_V1);
        write_u16(
            &mut encoded,
            VERSION_OFFSET,
            SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_VERSION_V1,
        );
        write_u16(&mut encoded, SUITE_OFFSET, XCHACHA20_POLY1305_SUITE_ID_V1);
        write_u16(
            &mut encoded,
            OBJECT_KIND_OFFSET,
            SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_OBJECT_KIND_V1,
        );
        write_u16(
            &mut encoded,
            HEADER_LENGTH_OFFSET,
            u16::try_from(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1)
                .expect("V1 header length fits u16"),
        );
        encoded[RESULT_ID_OFFSET..RESULT_ID_OFFSET + 32].copy_from_slice(self.result_id.as_bytes());
        write_u64(
            &mut encoded,
            TOTAL_LENGTH_OFFSET,
            usize_to_u64(self.encoded_len),
        );
        write_u64(
            &mut encoded,
            MANIFEST_OFFSET_OFFSET,
            usize_to_u64(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1),
        );
        write_u64(
            &mut encoded,
            MANIFEST_LENGTH_OFFSET,
            usize_to_u64(self.encoded_manifest.len()),
        );
        write_u64(
            &mut encoded,
            DIRECTORY_OFFSET_OFFSET,
            usize_to_u64(directory_offset),
        );
        write_u64(
            &mut encoded,
            DIRECTORY_LENGTH_OFFSET,
            usize_to_u64(directory_length),
        );
        write_u64(
            &mut encoded,
            PAYLOAD_OFFSET_OFFSET,
            usize_to_u64(payload_offset),
        );
        write_u64(
            &mut encoded,
            PAYLOAD_LENGTH_OFFSET,
            usize_to_u64(self.encoded_frame_bytes),
        );
        write_u32(
            &mut encoded,
            SEGMENT_COUNT_OFFSET,
            u32::try_from(segment_count).expect("validated segment count fits u32"),
        );
        write_u32(
            &mut encoded,
            FRAME_COUNT_OFFSET,
            u32::try_from(self.frame_count).expect("validated frame count fits u32"),
        );
        encoded[SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1..directory_offset]
            .copy_from_slice(&self.encoded_manifest);

        let frame_directory_offset = directory_offset
            + segment_count * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1;
        let mut payload_cursor = payload_offset;
        let mut frame_index = 0usize;
        let mut global_sequence = 0u64;
        for (segment_index, segment) in self.segments.iter().enumerate() {
            let segment_descriptor_offset = directory_offset
                + segment_index * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1;
            let encoded_segment_length = SEGMENT_HEADER_BYTES_V1
                + segment.encoded_frames.iter().map(Vec::len).sum::<usize>();
            write_u64(
                &mut encoded,
                segment_descriptor_offset,
                usize_to_u64(segment_index),
            );
            write_u64(
                &mut encoded,
                segment_descriptor_offset + 8,
                usize_to_u64(payload_cursor),
            );
            write_u64(
                &mut encoded,
                segment_descriptor_offset + 16,
                usize_to_u64(encoded_segment_length),
            );
            write_u32(
                &mut encoded,
                segment_descriptor_offset + 24,
                u32::try_from(frame_index).expect("validated frame index fits u32"),
            );
            write_u32(
                &mut encoded,
                segment_descriptor_offset + 28,
                u32::try_from(segment.encoded_frames.len())
                    .expect("validated segment frame count fits u32"),
            );
            write_u64(
                &mut encoded,
                segment_descriptor_offset + 32,
                global_sequence,
            );

            encoded.extend_from_slice(&segment.encoded_header);
            payload_cursor += SEGMENT_HEADER_BYTES_V1;
            for (segment_frame_index, frame) in segment.encoded_frames.iter().enumerate() {
                let descriptor_offset = frame_directory_offset
                    + frame_index * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1;
                write_u64(&mut encoded, descriptor_offset, usize_to_u64(segment_index));
                write_u64(&mut encoded, descriptor_offset + 8, global_sequence);
                write_u32(
                    &mut encoded,
                    descriptor_offset + 16,
                    u32::try_from(segment_frame_index)
                        .expect("validated segment frame index fits u32"),
                );
                write_u64(
                    &mut encoded,
                    descriptor_offset + 24,
                    usize_to_u64(payload_cursor),
                );
                write_u64(
                    &mut encoded,
                    descriptor_offset + 32,
                    usize_to_u64(frame.len()),
                );
                encoded.extend_from_slice(frame);
                payload_cursor += frame.len();
                frame_index += 1;
                global_sequence += 1;
            }
        }
        debug_assert_eq!(encoded.len(), self.encoded_len);
        encoded
    }

    pub(crate) fn into_encrypted_parts(
        self,
    ) -> (ResultId, Vec<u8>, Vec<SealedBundleSegmentV1>, usize, usize) {
        (
            self.result_id,
            self.encoded_manifest,
            self.segments,
            self.frame_count,
            self.encoded_frame_bytes,
        )
    }
}

impl fmt::Debug for SealedEncryptedCoreResultBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedEncryptedCoreResultBundleV1")
            .field("segment_count", &self.segments.len())
            .field("frame_count", &self.frame_count)
            .field("encoded_bytes", &self.encoded_len)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct SegmentDescriptorV1 {
    segment_sequence: usize,
    payload_offset: usize,
    encoded_length: usize,
    first_frame_index: usize,
    frame_count: usize,
    first_global_sequence: u64,
}

#[derive(Clone, Copy)]
struct FrameDescriptorV1 {
    segment_sequence: usize,
    global_sequence: u64,
    segment_frame_sequence: usize,
    payload_offset: usize,
    encoded_length: usize,
}

fn validate_fixed_header(encoded: &[u8]) -> Result<(), SealedEncryptedCoreResultBundleErrorV1> {
    if encoded[0..8] != BUNDLE_MAGIC_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::InvalidMagic);
    }
    if read_u16(encoded, VERSION_OFFSET) != SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_VERSION_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::UnknownVersion);
    }
    if read_u16(encoded, SUITE_OFFSET) != XCHACHA20_POLY1305_SUITE_ID_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::UnknownSuite);
    }
    if read_u16(encoded, OBJECT_KIND_OFFSET) != SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_OBJECT_KIND_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::UnknownObjectKind);
    }
    if usize::from(read_u16(encoded, HEADER_LENGTH_OFFSET))
        != SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
    {
        return Err(SealedEncryptedCoreResultBundleErrorV1::InvalidHeaderLength);
    }
    if read_u32(encoded, FLAGS_OFFSET) != 0 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::NonzeroFlags);
    }
    if encoded[HEADER_RESERVED_START..HEADER_RESERVED_END]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved);
    }
    Ok(())
}

fn validate_encrypted_parts(
    result_id: ResultId,
    encoded_manifest: &[u8],
    segments: &[SealedBundleSegmentV1],
) -> Result<(usize, usize), SealedEncryptedCoreResultBundleErrorV1> {
    if result_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(SealedEncryptedCoreResultBundleErrorV1::InvalidResultId);
    }
    if encoded_manifest.is_empty() || encoded_manifest.len() > MAX_ENCODED_MANIFEST_BYTES_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::ManifestLengthCap);
    }
    let sealed_manifest = SealedCoreResultManifestV1::decode(result_id, encoded_manifest)
        .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::ManifestDecodeFailed)?;
    if segments.is_empty() || segments.len() > MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::SegmentCountCap);
    }

    let mut expected_global_sequence = 0u64;
    let mut expected_prior_segment_commitment = FrameCommitmentV1::ZERO;
    let mut seen_nonces = BTreeSet::<FrameNonceV1>::new();
    seen_nonces.insert(FrameNonceV1::from_bytes(
        *sealed_manifest.header().nonce().as_bytes(),
    ));
    let mut frame_count = 0usize;
    let mut encoded_frame_bytes = 0usize;
    let mut expected_created = None;
    let mut expected_expires = None;

    for (segment_index, segment) in segments.iter().enumerate() {
        if segment.encoded_frames.is_empty()
            || segment.encoded_frames.len() > MAX_FRAMES_PER_SEGMENT_V1 as usize
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap);
        }
        let segment_header = SegmentHeaderV1::decode(&segment.encoded_header)
            .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::SegmentHeaderDecodeFailed)?;
        if segment_header.payload_schema() != CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1
            || segment_header.result_id() != result_id
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::ResultIdentityMismatch);
        }
        if segment_header.segment_sequence()
            != u64::try_from(segment_index)
                .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::SegmentCountCap)?
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::SequenceMismatch);
        }
        if segment_header.prior_segment_commitment() != expected_prior_segment_commitment {
            return Err(SealedEncryptedCoreResultBundleErrorV1::ChainMismatch);
        }
        match (expected_created, expected_expires) {
            (None, None) => {
                expected_created = Some(segment_header.created_unix_nanos());
                expected_expires = Some(segment_header.expires_unix_nanos());
            }
            (Some(created), Some(expires))
                if created == segment_header.created_unix_nanos()
                    && expires == segment_header.expires_unix_nanos() => {}
            _ => return Err(SealedEncryptedCoreResultBundleErrorV1::ResultIdentityMismatch),
        }

        encoded_frame_bytes = encoded_frame_bytes
            .checked_add(SEGMENT_HEADER_BYTES_V1)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        let mut expected_previous_commitment = segment_start_commitment_v1(&segment_header);
        for (segment_frame_index, encoded_frame) in segment.encoded_frames.iter().enumerate() {
            if encoded_frame.len() < FRAME_HEADER_BYTES_V1 + FRAME_TAG_BYTES_V1 {
                return Err(SealedEncryptedCoreResultBundleErrorV1::FrameDecodeFailed);
            }
            let frame = SealedFrameV1::decode(&segment_header, encoded_frame)
                .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::FrameDecodeFailed)?;
            if frame.header().global_sequence() != expected_global_sequence
                || frame.header().segment_frame_sequence()
                    != u32::try_from(segment_frame_index)
                        .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?
            {
                return Err(SealedEncryptedCoreResultBundleErrorV1::SequenceMismatch);
            }
            if frame.header().previous_frame_commitment() != expected_previous_commitment {
                return Err(SealedEncryptedCoreResultBundleErrorV1::ChainMismatch);
            }
            if !seen_nonces.insert(frame.header().nonce()) {
                return Err(SealedEncryptedCoreResultBundleErrorV1::DuplicateNonce);
            }
            expected_previous_commitment = frame.commitment();
            expected_global_sequence = expected_global_sequence
                .checked_add(1)
                .ok_or(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?;
            frame_count = frame_count
                .checked_add(1)
                .ok_or(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?;
            if frame_count > MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 {
                return Err(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap);
            }
            encoded_frame_bytes = encoded_frame_bytes
                .checked_add(encoded_frame.len())
                .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
            if encoded_frame_bytes > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
                return Err(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap);
            }
        }
        expected_prior_segment_commitment = expected_previous_commitment;
    }
    validate_counts(segments.len(), frame_count)?;
    Ok((frame_count, encoded_frame_bytes))
}

fn validate_counts(
    segment_count: usize,
    frame_count: usize,
) -> Result<(), SealedEncryptedCoreResultBundleErrorV1> {
    if segment_count == 0 || segment_count > MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::SegmentCountCap);
    }
    if frame_count == 0
        || frame_count > MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1
        || frame_count < segment_count
    {
        return Err(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap);
    }
    Ok(())
}

fn canonical_directory_len(
    segment_count: usize,
    frame_count: usize,
) -> Result<usize, SealedEncryptedCoreResultBundleErrorV1> {
    let segments = segment_count
        .checked_mul(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1)
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
    let frames = frame_count
        .checked_mul(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1)
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
    segments
        .checked_add(frames)
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)
}

fn canonical_encoded_len(
    manifest_length: usize,
    segment_count: usize,
    frame_count: usize,
    payload_length: usize,
) -> Result<usize, SealedEncryptedCoreResultBundleErrorV1> {
    let directory_length = canonical_directory_len(segment_count, frame_count)?;
    let total = SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
        .checked_add(manifest_length)
        .and_then(|value| value.checked_add(directory_length))
        .and_then(|value| value.checked_add(payload_length))
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
    if total > MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1 {
        return Err(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap);
    }
    Ok(total)
}

fn decode_segment_descriptors(
    encoded: &[u8],
    directory_offset: usize,
    segment_count: usize,
    total_frame_count: usize,
    payload_offset: usize,
    total_length: usize,
) -> Result<Vec<SegmentDescriptorV1>, SealedEncryptedCoreResultBundleErrorV1> {
    let mut descriptors = Vec::with_capacity(segment_count);
    let mut expected_first_frame = 0usize;
    let mut expected_global_sequence = 0u64;
    for index in 0..segment_count {
        let offset = directory_offset
            .checked_add(
                index
                    .checked_mul(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1)
                    .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?,
            )
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        checked_slice(
            encoded,
            offset,
            SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1,
        )?;
        if read_u64(encoded, offset + 40) != 0 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved);
        }
        let descriptor = SegmentDescriptorV1 {
            segment_sequence: read_usize_u64(encoded, offset)?,
            payload_offset: read_usize_u64(encoded, offset + 8)?,
            encoded_length: read_usize_u64(encoded, offset + 16)?,
            first_frame_index: read_usize_u32(encoded, offset + 24),
            frame_count: read_usize_u32(encoded, offset + 28),
            first_global_sequence: read_u64(encoded, offset + 32),
        };
        if descriptor.segment_sequence != index
            || descriptor.first_frame_index != expected_first_frame
            || descriptor.first_global_sequence != expected_global_sequence
            || descriptor.frame_count == 0
            || descriptor.frame_count > MAX_FRAMES_PER_SEGMENT_V1 as usize
            || descriptor.payload_offset < payload_offset
            || descriptor.encoded_length < SEGMENT_HEADER_BYTES_V1
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
        let end = checked_end(descriptor.payload_offset, descriptor.encoded_length)?;
        if end > total_length {
            return Err(SealedEncryptedCoreResultBundleErrorV1::Truncated);
        }
        expected_first_frame = expected_first_frame
            .checked_add(descriptor.frame_count)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?;
        expected_global_sequence = expected_global_sequence
            .checked_add(
                u64::try_from(descriptor.frame_count)
                    .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?,
            )
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?;
        descriptors.push(descriptor);
    }
    if expected_first_frame != total_frame_count {
        return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
    }
    Ok(descriptors)
}

fn decode_frame_descriptors(
    encoded: &[u8],
    directory_offset: usize,
    frame_count: usize,
    payload_offset: usize,
    total_length: usize,
) -> Result<Vec<FrameDescriptorV1>, SealedEncryptedCoreResultBundleErrorV1> {
    let mut descriptors = Vec::with_capacity(frame_count);
    for index in 0..frame_count {
        let offset = directory_offset
            .checked_add(
                index
                    .checked_mul(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1)
                    .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?,
            )
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        checked_slice(
            encoded,
            offset,
            SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1,
        )?;
        if read_u32(encoded, offset + 20) != 0 {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved);
        }
        let descriptor = FrameDescriptorV1 {
            segment_sequence: read_usize_u64(encoded, offset)?,
            global_sequence: read_u64(encoded, offset + 8),
            segment_frame_sequence: read_usize_u32(encoded, offset + 16),
            payload_offset: read_usize_u64(encoded, offset + 24)?,
            encoded_length: read_usize_u64(encoded, offset + 32)?,
        };
        if descriptor.global_sequence
            != u64::try_from(index)
                .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)?
            || descriptor.payload_offset < payload_offset
            || descriptor.encoded_length < FRAME_HEADER_BYTES_V1 + FRAME_TAG_BYTES_V1
        {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
        let end = checked_end(descriptor.payload_offset, descriptor.encoded_length)?;
        if end > total_length {
            return Err(SealedEncryptedCoreResultBundleErrorV1::Truncated);
        }
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

fn validate_descriptor_contiguity(
    segments: &[SegmentDescriptorV1],
    frames: &[FrameDescriptorV1],
    payload_offset: usize,
    total_length: usize,
) -> Result<(), SealedEncryptedCoreResultBundleErrorV1> {
    let mut expected_payload_offset = payload_offset;
    let mut expected_frame_index = 0usize;
    for segment in segments {
        if segment.payload_offset != expected_payload_offset {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
        expected_payload_offset = expected_payload_offset
            .checked_add(SEGMENT_HEADER_BYTES_V1)
            .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)?;
        let segment_end = checked_end(segment.payload_offset, segment.encoded_length)?;
        for expected_segment_frame_sequence in 0..segment.frame_count {
            let frame = frames
                .get(expected_frame_index)
                .ok_or(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout)?;
            if frame.segment_sequence != segment.segment_sequence
                || frame.segment_frame_sequence != expected_segment_frame_sequence
                || frame.payload_offset != expected_payload_offset
            {
                return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
            }
            expected_payload_offset = checked_end(frame.payload_offset, frame.encoded_length)?;
            expected_frame_index += 1;
        }
        if expected_payload_offset != segment_end {
            return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
        }
    }
    if expected_frame_index != frames.len() || expected_payload_offset != total_length {
        return Err(SealedEncryptedCoreResultBundleErrorV1::NoncanonicalLayout);
    }
    Ok(())
}

fn checked_slice(
    bytes: &[u8],
    offset: usize,
    length: usize,
) -> Result<&[u8], SealedEncryptedCoreResultBundleErrorV1> {
    let end = checked_end(offset, length)?;
    bytes
        .get(offset..end)
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::Truncated)
}

fn checked_end(
    offset: usize,
    length: usize,
) -> Result<usize, SealedEncryptedCoreResultBundleErrorV1> {
    offset
        .checked_add(length)
        .ok_or(SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)
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

fn read_usize_u32(bytes: &[u8], offset: usize) -> usize {
    read_u32(bytes, offset) as usize
}

fn read_usize_u64(
    bytes: &[u8],
    offset: usize,
) -> Result<usize, SealedEncryptedCoreResultBundleErrorV1> {
    usize::try_from(read_u64(bytes, offset))
        .map_err(|_| SealedEncryptedCoreResultBundleErrorV1::LengthOverflow)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes[offset..offset + N]);
    array
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("validated V1 bundle length fits u64")
}

const _: () = {
    assert!(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 <= u16::MAX as usize);
    assert!(MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 <= u32::MAX as usize);
    assert!(MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 <= u32::MAX as usize);
};
