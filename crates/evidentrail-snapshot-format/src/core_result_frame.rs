use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{AcquisitionReceiptId, ResultId, SourceIdentityDigest};

use crate::crypto::{open_frame_with_aad_v1, seal_frame_with_aad_v1};
use crate::{
    FRAME_HEADER_BYTES_V1, FrameHeaderV1, FrameKeyViewV1, OpenedFrameV1, SEGMENT_HEADER_BYTES_V1,
    SealedFrameV1, SegmentHeaderV1,
};

/// Payload schema used by authority-bound core-result snapshot frames.
pub const CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1: u16 = 1;
pub const CORE_RESULT_FRAME_AAD_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.core-result-frame.v1";
pub const CORE_RESULT_FRAME_AAD_BYTES_V1: usize = CORE_RESULT_FRAME_AAD_DOMAIN_V1.len()
    + 32
    + 32
    + 32
    + SEGMENT_HEADER_BYTES_V1
    + FRAME_HEADER_BYTES_V1;

/// Stable, contentless failure for the authority-bound frame primitive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreResultFrameErrorV1 {
    InvalidResultId,
    AuthorityMismatch,
    FrameSealFailed,
    FrameOpenFailed,
}

impl CoreResultFrameErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidResultId => "EVIDENTRAIL_CORE_RESULT_FRAME_INVALID_RESULT_ID",
            Self::AuthorityMismatch => "EVIDENTRAIL_CORE_RESULT_FRAME_AUTHORITY_MISMATCH",
            Self::FrameSealFailed => "EVIDENTRAIL_CORE_RESULT_FRAME_SEAL_FAILED",
            Self::FrameOpenFailed => "EVIDENTRAIL_CORE_RESULT_FRAME_OPEN_FAILED",
        }
    }
}

impl fmt::Debug for CoreResultFrameErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreResultFrameErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CoreResultFrameErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CoreResultFrameErrorV1 {}

/// Independently retained authority included in every core-result frame AAD.
///
/// This is deliberately distinct from the frozen generic ADR frame AAD. The
/// repository admits only this stronger domain, which binds the random result
/// identity, source authority, acquisition receipt, exact segment header, and
/// exact frame header (including the previous-frame commitment).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreResultFrameAuthorityV1 {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
}

impl CoreResultFrameAuthorityV1 {
    pub fn new(
        result_id: ResultId,
        source_identity_digest: SourceIdentityDigest,
        acquisition_receipt_id: AcquisitionReceiptId,
    ) -> Result<Self, CoreResultFrameErrorV1> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CoreResultFrameErrorV1::InvalidResultId);
        }
        Ok(Self {
            result_id,
            source_identity_digest,
            acquisition_receipt_id,
        })
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn source_identity_digest(self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }
}

impl fmt::Debug for CoreResultFrameAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreResultFrameAuthorityV1(<redacted>)")
    }
}

/// Exact authority-bound frame AAD.
///
/// Layout: domain || ResultId || SourceIdentityDigest || AcquisitionReceiptId
/// || SegmentHeaderV1 || FrameHeaderV1.
pub fn canonical_core_result_frame_aad_v1(
    authority: CoreResultFrameAuthorityV1,
    segment_header: &SegmentHeaderV1,
    frame_header: &FrameHeaderV1,
) -> Result<[u8; CORE_RESULT_FRAME_AAD_BYTES_V1], CoreResultFrameErrorV1> {
    if segment_header.result_id() != authority.result_id() {
        return Err(CoreResultFrameErrorV1::AuthorityMismatch);
    }
    let mut aad = [0u8; CORE_RESULT_FRAME_AAD_BYTES_V1];
    let mut offset = 0usize;
    append(&mut aad, &mut offset, CORE_RESULT_FRAME_AAD_DOMAIN_V1);
    append(&mut aad, &mut offset, authority.result_id().as_bytes());
    append(
        &mut aad,
        &mut offset,
        authority.source_identity_digest().as_bytes(),
    );
    append(
        &mut aad,
        &mut offset,
        authority.acquisition_receipt_id().as_bytes(),
    );
    append(&mut aad, &mut offset, &segment_header.encode());
    append(&mut aad, &mut offset, &frame_header.encode());
    debug_assert_eq!(offset, CORE_RESULT_FRAME_AAD_BYTES_V1);
    Ok(aad)
}

/// Seal one frame under the authority-bound core-result AAD domain.
pub fn seal_core_result_frame_v1(
    key: &FrameKeyViewV1<'_>,
    authority: CoreResultFrameAuthorityV1,
    segment_header: &SegmentHeaderV1,
    frame_header: FrameHeaderV1,
    plaintext: &[u8],
) -> Result<SealedFrameV1, CoreResultFrameErrorV1> {
    let aad = canonical_core_result_frame_aad_v1(authority, segment_header, &frame_header)?;
    seal_frame_with_aad_v1(key, segment_header, frame_header, plaintext, &aad)
        .map_err(|_| CoreResultFrameErrorV1::FrameSealFailed)
}

/// Authenticate and open one frame under the same exact retained authority.
pub fn open_core_result_frame_v1(
    key: &FrameKeyViewV1<'_>,
    authority: CoreResultFrameAuthorityV1,
    segment_header: &SegmentHeaderV1,
    frame: &SealedFrameV1,
) -> Result<OpenedFrameV1, CoreResultFrameErrorV1> {
    let aad = canonical_core_result_frame_aad_v1(authority, segment_header, frame.header())?;
    open_frame_with_aad_v1(key, segment_header, frame, &aad)
        .map_err(|_| CoreResultFrameErrorV1::FrameOpenFailed)
}

fn append<const N: usize>(output: &mut [u8; N], offset: &mut usize, value: &[u8]) {
    let end = *offset + value.len();
    output[*offset..end].copy_from_slice(value);
    *offset = end;
}
