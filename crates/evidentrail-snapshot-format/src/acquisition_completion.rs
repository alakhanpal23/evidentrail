use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionReceipt, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CapKind, CapUsage, CompletenessProof, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchErrorCode, FetchIdentity, FetchPartialReason, FetchPartialReasons, FetchTiming,
    FetchUnknownReason, HighWaterMark, PlanDigest, PlanId, RetrievalId, SourceCursor, SourceMember,
    UnixTimestampNanos,
};

pub const ACQUISITION_COMPLETION_VERSION_V1: u16 = 1;
pub const ACQUISITION_COMPLETION_SCHEMA_V1: u16 = 1;
pub const ACQUISITION_COMPLETION_OBJECT_KIND_V1: u16 = 1;
pub const ACQUISITION_COMPLETION_HEADER_BYTES_V1: usize = 288;
pub const ACQUISITION_COMPLETION_HIGH_WATER_PREFIX_BYTES_V1: usize = 16;
pub const ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1: usize = 32;
pub const ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1: usize = 12;

/// Implementation-V1 bound for this one manifest component. It is deliberately
/// below the outer manifest limit so a future manifest can contain the other
/// required components under a shared aggregate bound.
pub const MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1: usize = 1024 * 1024;
pub const MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1: usize = 1024;
pub const MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1: usize = 64 * 1024;
pub const MAX_ACQUISITION_CURSOR_BYTES_V1: usize = 64 * 1024;
pub const MAX_ACQUISITION_HIGH_WATER_MARKS_V1: usize = 4096;
pub const MAX_ACQUISITION_CAP_USAGES_V1: usize = 256;
pub const MAX_ACQUISITION_ERROR_CODES_V1: usize = 256;
pub const MAX_ACQUISITION_PARTIAL_REASONS_V1: usize = 256;

const MAGIC_V1: [u8; 8] = *b"EVRACM01";

const FLAGS_OFFSET: usize = 16;
const RESERVED_ONE_OFFSET: usize = 18;
const RETRIEVAL_ID_OFFSET: usize = 24;
const PLAN_ID_OFFSET: usize = 56;
const PLAN_DIGEST_OFFSET: usize = 88;
const STARTED_AT_OFFSET: usize = 120;
const ENDED_AT_OFFSET: usize = 136;
const ACKNOWLEDGED_RECORDS_OFFSET: usize = 152;
const ACKNOWLEDGED_PAYLOAD_BYTES_OFFSET: usize = 160;
const ACKNOWLEDGED_SOURCE_BYTES_OFFSET: usize = 168;
const MEMBERS_ATTEMPTED_OFFSET: usize = 176;
const MEMBERS_COMPLETED_OFFSET: usize = 184;
const PAGES_ATTEMPTED_OFFSET: usize = 192;
const PAGES_COMPLETED_OFFSET: usize = 200;
const ADAPTER_OUTCOME_OFFSET: usize = 208;
const COMPLETENESS_KIND_OFFSET: usize = 210;
const COMPLETENESS_PRIMARY_TAG_OFFSET: usize = 212;
const COMPLETENESS_PRIMARY_VERSION_OFFSET: usize = 214;
const COMPLETENESS_PRIMARY_CODE_OFFSET: usize = 216;
const RESERVED_TWO_OFFSET: usize = 218;
const ADAPTER_KIND_LENGTH_OFFSET: usize = 220;
const ADAPTER_VERSION_LENGTH_OFFSET: usize = 224;
const FIRST_CURSOR_LENGTH_OFFSET: usize = 228;
const FINAL_CURSOR_LENGTH_OFFSET: usize = 232;
const CONTINUATION_LENGTH_OFFSET: usize = 236;
const HIGH_WATER_COUNT_OFFSET: usize = 240;
const CAP_USAGE_COUNT_OFFSET: usize = 244;
const ERROR_CODE_COUNT_OFFSET: usize = 248;
const PARTIAL_REASON_COUNT_OFFSET: usize = 252;
const HIGH_WATER_SECTION_LENGTH_OFFSET: usize = 256;
const TOTAL_ENCODED_LENGTH_OFFSET: usize = 260;
const RESERVED_THREE_OFFSET: usize = 264;

const FIRST_CURSOR_PRESENT: u16 = 1 << 0;
const FINAL_CURSOR_PRESENT: u16 = 1 << 1;
const CONTINUATION_PRESENT: u16 = 1 << 2;
const KNOWN_FLAGS: u16 = FIRST_CURSOR_PRESENT | FINAL_CURSOR_PRESENT | CONTINUATION_PRESENT;

const COMPLETENESS_COMPLETE: u16 = 1;
const COMPLETENESS_PARTIAL: u16 = 2;
const COMPLETENESS_UNKNOWN: u16 = 3;
const OTHER_VERSIONED_TAG: u16 = u16::MAX;

/// Stable, contentless failure returned by the completion-record boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionCompletionRecordErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    UnsupportedObjectKind,
    InvalidHeaderWidth,
    UnknownFlags,
    NonzeroReserved,
    TotalLengthCap,
    AdapterFieldTooLong,
    SourceMemberTooLong,
    CursorTooLong,
    CountCap,
    InvalidUtf8,
    InvalidField,
    NoncanonicalOptionalField,
    InvalidListOrdinal,
    HighWaterSectionLengthMismatch,
    UnsupportedAdapterOutcome,
    UnsupportedCompletenessKind,
    UnsupportedCapKind,
    UnsupportedErrorCode,
    UnsupportedCompletenessProof,
    UnsupportedPartialReason,
    UnsupportedUnknownReason,
    NoncanonicalCodeFields,
    NoncanonicalCompletenessFields,
    InvalidFetchCompletion,
    ReceiptRetrievalMismatch,
    ReceiptAcknowledgedCountMismatch,
    ArithmeticOverflow,
}

impl AcquisitionCompletionRecordErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_SCHEMA",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_OBJECT_KIND",
            Self::InvalidHeaderWidth => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_HEADER_WIDTH",
            Self::UnknownFlags => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNKNOWN_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_ACQUISITION_COMPLETION_NONZERO_RESERVED",
            Self::TotalLengthCap => "EVIDENTRAIL_ACQUISITION_COMPLETION_TOTAL_LENGTH_CAP",
            Self::AdapterFieldTooLong => "EVIDENTRAIL_ACQUISITION_COMPLETION_ADAPTER_FIELD_TOO_LONG",
            Self::SourceMemberTooLong => "EVIDENTRAIL_ACQUISITION_COMPLETION_SOURCE_MEMBER_TOO_LONG",
            Self::CursorTooLong => "EVIDENTRAIL_ACQUISITION_COMPLETION_CURSOR_TOO_LONG",
            Self::CountCap => "EVIDENTRAIL_ACQUISITION_COMPLETION_COUNT_CAP",
            Self::InvalidUtf8 => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_UTF8",
            Self::InvalidField => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_FIELD",
            Self::NoncanonicalOptionalField => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_NONCANONICAL_OPTIONAL_FIELD"
            }
            Self::InvalidListOrdinal => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_LIST_ORDINAL",
            Self::HighWaterSectionLengthMismatch => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_HIGH_WATER_SECTION_LENGTH_MISMATCH"
            }
            Self::UnsupportedAdapterOutcome => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_ADAPTER_OUTCOME"
            }
            Self::UnsupportedCompletenessKind => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_COMPLETENESS_KIND"
            }
            Self::UnsupportedCapKind => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_CAP_KIND",
            Self::UnsupportedErrorCode => "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_ERROR_CODE",
            Self::UnsupportedCompletenessProof => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_COMPLETENESS_PROOF"
            }
            Self::UnsupportedPartialReason => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_PARTIAL_REASON"
            }
            Self::UnsupportedUnknownReason => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_UNSUPPORTED_UNKNOWN_REASON"
            }
            Self::NoncanonicalCodeFields => "EVIDENTRAIL_ACQUISITION_COMPLETION_NONCANONICAL_CODE_FIELDS",
            Self::NoncanonicalCompletenessFields => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_NONCANONICAL_COMPLETENESS_FIELDS"
            }
            Self::InvalidFetchCompletion => "EVIDENTRAIL_ACQUISITION_COMPLETION_INVALID_FETCH_COMPLETION",
            Self::ReceiptRetrievalMismatch => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_RECEIPT_RETRIEVAL_MISMATCH"
            }
            Self::ReceiptAcknowledgedCountMismatch => {
                "EVIDENTRAIL_ACQUISITION_COMPLETION_RECEIPT_ACKNOWLEDGED_COUNT_MISMATCH"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_ACQUISITION_COMPLETION_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for AcquisitionCompletionRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionCompletionRecordErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for AcquisitionCompletionRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for AcquisitionCompletionRecordErrorV1 {}

/// Lossless, bounded manifest-plaintext representation of one FetchCompletion.
///
/// Ordered runtime collections retain their exact order and multiplicity. The
/// format therefore does not silently reinterpret duplicate high-water marks,
/// cap facts, errors, or partial reasons that the schema currently admits.
/// Per-entry ordinals make that order unambiguous and strictly decodable.
/// A `FetchCompletion` outside this component's explicit byte/count bounds can
/// remain a valid runtime value even though it is not encodable by this V1
/// snapshot projection; bounds errors do not reclassify it as invalid.
///
/// This record contains no raw log payload or free-form provider error text. It
/// does not create a `SourceIdentityDigest` or receipt identifier absent from
/// `FetchCompletion`; it is not an acquisition receipt, outer authentication,
/// frame authentication/open, recovery, durability, or a sealed-result proof.
#[derive(PartialEq, Eq)]
pub struct AcquisitionCompletionRecordV1 {
    completion: FetchCompletion,
}

impl AcquisitionCompletionRecordV1 {
    pub fn new(completion: &FetchCompletion) -> Result<Self, AcquisitionCompletionRecordErrorV1> {
        validate_completion_bounds(completion)?;
        Ok(Self {
            completion: completion.clone(),
        })
    }

    pub fn new_verified(
        completion: &FetchCompletion,
        receipt: &AcquisitionReceipt,
    ) -> Result<Self, AcquisitionCompletionRecordErrorV1> {
        let record = Self::new(completion)?;
        record.verify_against_receipt(receipt)?;
        Ok(record)
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        ACQUISITION_COMPLETION_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        ACQUISITION_COMPLETION_SCHEMA_V1
    }

    #[must_use]
    pub const fn completion(&self) -> &FetchCompletion {
        &self.completion
    }

    /// Restore the exact accepted runtime value, including list order and
    /// multiplicity.
    #[must_use]
    pub fn to_fetch_completion(&self) -> FetchCompletion {
        self.completion.clone()
    }

    #[must_use]
    pub fn into_fetch_completion(self) -> FetchCompletion {
        self.completion
    }

    pub fn verify_against_receipt(
        &self,
        receipt: &AcquisitionReceipt,
    ) -> Result<(), AcquisitionCompletionRecordErrorV1> {
        if self.completion.identity().retrieval_id() != receipt.retrieval_id() {
            return Err(AcquisitionCompletionRecordErrorV1::ReceiptRetrievalMismatch);
        }
        let receipt_count = u64::try_from(receipt.acknowledged_count())
            .map_err(|_| AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
        if self.completion.acknowledged().records() != receipt_count {
            return Err(AcquisitionCompletionRecordErrorV1::ReceiptAcknowledgedCountMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        encoded_len_for(&self.completion)
            .expect("validated completion length must remain representable")
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_completion(&self.completion)
            .expect("validated completion must remain canonically encodable")
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, AcquisitionCompletionRecordErrorV1> {
        decode_completion(encoded).and_then(|completion| Self::new(&completion))
    }
}

impl fmt::Debug for AcquisitionCompletionRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcquisitionCompletionRecordV1(<redacted>)")
    }
}

#[derive(Clone, Copy)]
struct EncodedCode {
    tag: u16,
    version: u16,
    code: u16,
}

fn validate_completion_bounds(
    completion: &FetchCompletion,
) -> Result<(), AcquisitionCompletionRecordErrorV1> {
    validate_nonempty_length(
        completion.identity().adapter().kind().len(),
        MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
        AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong,
    )?;
    validate_nonempty_length(
        completion.identity().adapter().version().len(),
        MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
        AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong,
    )?;
    validate_optional_cursor(completion.boundaries().first_cursor())?;
    validate_optional_cursor(completion.boundaries().final_cursor())?;
    for mark in completion.boundaries().high_water_marks() {
        validate_nonempty_length(
            mark.member().as_bytes().len(),
            MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1,
            AcquisitionCompletionRecordErrorV1::SourceMemberTooLong,
        )?;
        validate_nonempty_length(
            mark.cursor().as_bytes().len(),
            MAX_ACQUISITION_CURSOR_BYTES_V1,
            AcquisitionCompletionRecordErrorV1::CursorTooLong,
        )?;
    }
    validate_count(
        completion.boundaries().high_water_marks().len(),
        MAX_ACQUISITION_HIGH_WATER_MARKS_V1,
    )?;
    validate_count(completion.cap_usage().len(), MAX_ACQUISITION_CAP_USAGES_V1)?;
    validate_count(
        completion.error_codes().len(),
        MAX_ACQUISITION_ERROR_CODES_V1,
    )?;
    match completion.completeness() {
        FetchCompleteness::Partial {
            reasons,
            continuation,
        } => {
            validate_count(reasons.len(), MAX_ACQUISITION_PARTIAL_REASONS_V1)?;
            validate_optional_cursor(continuation.as_ref())?;
        }
        FetchCompleteness::Complete { .. } | FetchCompleteness::Unknown { .. } => {}
    }
    let encoded_len = encoded_len_for(completion)?;
    if encoded_len > MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::TotalLengthCap);
    }
    Ok(())
}

fn validate_nonempty_length(
    length: usize,
    limit: usize,
    too_long: AcquisitionCompletionRecordErrorV1,
) -> Result<(), AcquisitionCompletionRecordErrorV1> {
    if length == 0 {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidField);
    }
    if length > limit {
        return Err(too_long);
    }
    Ok(())
}

fn validate_optional_cursor(
    cursor: Option<&SourceCursor>,
) -> Result<(), AcquisitionCompletionRecordErrorV1> {
    if let Some(cursor) = cursor {
        validate_nonempty_length(
            cursor.as_bytes().len(),
            MAX_ACQUISITION_CURSOR_BYTES_V1,
            AcquisitionCompletionRecordErrorV1::CursorTooLong,
        )?;
    }
    Ok(())
}

fn validate_count(count: usize, limit: usize) -> Result<(), AcquisitionCompletionRecordErrorV1> {
    if count > limit {
        return Err(AcquisitionCompletionRecordErrorV1::CountCap);
    }
    Ok(())
}

fn encoded_len_for(
    completion: &FetchCompletion,
) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    let boundaries = completion.boundaries();
    let continuation = match completion.completeness() {
        FetchCompleteness::Partial { continuation, .. } => continuation.as_ref(),
        FetchCompleteness::Complete { .. } | FetchCompleteness::Unknown { .. } => None,
    };
    let mut length = ACQUISITION_COMPLETION_HEADER_BYTES_V1;
    for field_length in [
        completion.identity().adapter().kind().len(),
        completion.identity().adapter().version().len(),
        boundaries
            .first_cursor()
            .map_or(0, |value| value.as_bytes().len()),
        boundaries
            .final_cursor()
            .map_or(0, |value| value.as_bytes().len()),
        continuation.map_or(0, |value| value.as_bytes().len()),
    ] {
        length = length
            .checked_add(field_length)
            .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    }
    for mark in boundaries.high_water_marks() {
        length = length
            .checked_add(ACQUISITION_COMPLETION_HIGH_WATER_PREFIX_BYTES_V1)
            .and_then(|value| value.checked_add(mark.member().as_bytes().len()))
            .and_then(|value| value.checked_add(mark.cursor().as_bytes().len()))
            .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    }
    let cap_bytes = completion
        .cap_usage()
        .len()
        .checked_mul(ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let error_bytes = completion
        .error_codes()
        .len()
        .checked_mul(ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let reason_bytes = partial_reason_count(completion)
        .checked_mul(ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    length = length
        .checked_add(cap_bytes)
        .and_then(|value| value.checked_add(error_bytes))
        .and_then(|value| value.checked_add(reason_bytes))
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    Ok(length)
}

fn high_water_section_len(
    completion: &FetchCompletion,
) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    completion
        .boundaries()
        .high_water_marks()
        .iter()
        .try_fold(0usize, |length, mark| {
            length
                .checked_add(ACQUISITION_COMPLETION_HIGH_WATER_PREFIX_BYTES_V1)
                .and_then(|value| value.checked_add(mark.member().as_bytes().len()))
                .and_then(|value| value.checked_add(mark.cursor().as_bytes().len()))
                .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)
        })
}

fn partial_reason_count(completion: &FetchCompletion) -> usize {
    match completion.completeness() {
        FetchCompleteness::Partial { reasons, .. } => reasons.len(),
        FetchCompleteness::Complete { .. } | FetchCompleteness::Unknown { .. } => 0,
    }
}

fn encode_completion(
    completion: &FetchCompletion,
) -> Result<Vec<u8>, AcquisitionCompletionRecordErrorV1> {
    validate_completion_bounds(completion)?;
    let total_length = encoded_len_for(completion)?;
    let high_water_length = high_water_section_len(completion)?;
    let boundaries = completion.boundaries();
    let continuation = match completion.completeness() {
        FetchCompleteness::Partial { continuation, .. } => continuation.as_ref(),
        FetchCompleteness::Complete { .. } | FetchCompleteness::Unknown { .. } => None,
    };
    let mut flags = 0u16;
    if boundaries.first_cursor().is_some() {
        flags |= FIRST_CURSOR_PRESENT;
    }
    if boundaries.final_cursor().is_some() {
        flags |= FINAL_CURSOR_PRESENT;
    }
    if continuation.is_some() {
        flags |= CONTINUATION_PRESENT;
    }
    let (completeness_kind, primary) = encode_completeness(completion.completeness());

    let mut header = [0u8; ACQUISITION_COMPLETION_HEADER_BYTES_V1];
    header[0..8].copy_from_slice(&MAGIC_V1);
    put_u16(&mut header, 8, ACQUISITION_COMPLETION_VERSION_V1);
    put_u16(&mut header, 10, ACQUISITION_COMPLETION_SCHEMA_V1);
    put_u16(&mut header, 12, ACQUISITION_COMPLETION_OBJECT_KIND_V1);
    put_u16(
        &mut header,
        14,
        usize_to_u16(ACQUISITION_COMPLETION_HEADER_BYTES_V1)?,
    );
    put_u16(&mut header, FLAGS_OFFSET, flags);
    header[RETRIEVAL_ID_OFFSET..PLAN_ID_OFFSET]
        .copy_from_slice(completion.identity().retrieval_id().as_bytes());
    header[PLAN_ID_OFFSET..PLAN_DIGEST_OFFSET]
        .copy_from_slice(completion.identity().plan_id().as_bytes());
    header[PLAN_DIGEST_OFFSET..STARTED_AT_OFFSET]
        .copy_from_slice(completion.identity().plan_digest().as_bytes());
    put_i128(
        &mut header,
        STARTED_AT_OFFSET,
        completion.timing().started_at().get(),
    );
    put_i128(
        &mut header,
        ENDED_AT_OFFSET,
        completion.timing().ended_at().get(),
    );
    let acknowledged = completion.acknowledged();
    put_u64(
        &mut header,
        ACKNOWLEDGED_RECORDS_OFFSET,
        acknowledged.records(),
    );
    put_u64(
        &mut header,
        ACKNOWLEDGED_PAYLOAD_BYTES_OFFSET,
        acknowledged.payload_bytes(),
    );
    put_u64(
        &mut header,
        ACKNOWLEDGED_SOURCE_BYTES_OFFSET,
        acknowledged.source_bytes(),
    );
    let members = completion.member_counts();
    put_u64(&mut header, MEMBERS_ATTEMPTED_OFFSET, members.attempted());
    put_u64(&mut header, MEMBERS_COMPLETED_OFFSET, members.completed());
    let pages = completion.page_counts();
    put_u64(&mut header, PAGES_ATTEMPTED_OFFSET, pages.attempted());
    put_u64(&mut header, PAGES_COMPLETED_OFFSET, pages.completed());
    put_u16(
        &mut header,
        ADAPTER_OUTCOME_OFFSET,
        encode_adapter_outcome(completion.adapter_outcome()),
    );
    put_u16(&mut header, COMPLETENESS_KIND_OFFSET, completeness_kind);
    put_u16(&mut header, COMPLETENESS_PRIMARY_TAG_OFFSET, primary.tag);
    put_u16(
        &mut header,
        COMPLETENESS_PRIMARY_VERSION_OFFSET,
        primary.version,
    );
    put_u16(&mut header, COMPLETENESS_PRIMARY_CODE_OFFSET, primary.code);
    put_u32(
        &mut header,
        ADAPTER_KIND_LENGTH_OFFSET,
        usize_to_u32(completion.identity().adapter().kind().len())?,
    );
    put_u32(
        &mut header,
        ADAPTER_VERSION_LENGTH_OFFSET,
        usize_to_u32(completion.identity().adapter().version().len())?,
    );
    put_u32(
        &mut header,
        FIRST_CURSOR_LENGTH_OFFSET,
        optional_cursor_length(boundaries.first_cursor())?,
    );
    put_u32(
        &mut header,
        FINAL_CURSOR_LENGTH_OFFSET,
        optional_cursor_length(boundaries.final_cursor())?,
    );
    put_u32(
        &mut header,
        CONTINUATION_LENGTH_OFFSET,
        optional_cursor_length(continuation)?,
    );
    put_u32(
        &mut header,
        HIGH_WATER_COUNT_OFFSET,
        usize_to_u32(boundaries.high_water_marks().len())?,
    );
    put_u32(
        &mut header,
        CAP_USAGE_COUNT_OFFSET,
        usize_to_u32(completion.cap_usage().len())?,
    );
    put_u32(
        &mut header,
        ERROR_CODE_COUNT_OFFSET,
        usize_to_u32(completion.error_codes().len())?,
    );
    put_u32(
        &mut header,
        PARTIAL_REASON_COUNT_OFFSET,
        usize_to_u32(partial_reason_count(completion))?,
    );
    put_u32(
        &mut header,
        HIGH_WATER_SECTION_LENGTH_OFFSET,
        usize_to_u32(high_water_length)?,
    );
    put_u32(
        &mut header,
        TOTAL_ENCODED_LENGTH_OFFSET,
        usize_to_u32(total_length)?,
    );

    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(completion.identity().adapter().kind().as_bytes());
    encoded.extend_from_slice(completion.identity().adapter().version().as_bytes());
    append_optional_cursor(&mut encoded, boundaries.first_cursor());
    append_optional_cursor(&mut encoded, boundaries.final_cursor());
    append_optional_cursor(&mut encoded, continuation);

    for (ordinal, mark) in (0u32..).zip(boundaries.high_water_marks()) {
        encoded.extend_from_slice(&ordinal.to_be_bytes());
        encoded.extend_from_slice(&usize_to_u32(mark.member().as_bytes().len())?.to_be_bytes());
        encoded.extend_from_slice(&usize_to_u32(mark.cursor().as_bytes().len())?.to_be_bytes());
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(mark.member().as_bytes());
        encoded.extend_from_slice(mark.cursor().as_bytes());
    }
    for (ordinal, usage) in (0u32..).zip(completion.cap_usage()) {
        encode_cap_usage(&mut encoded, ordinal, *usage);
    }
    for (ordinal, error) in (0u32..).zip(completion.error_codes()) {
        encode_code_entry(&mut encoded, ordinal, encode_error_code(*error));
    }
    if let FetchCompleteness::Partial { reasons, .. } = completion.completeness() {
        for (ordinal, reason) in (0u32..).zip(reasons.iter()) {
            encode_code_entry(&mut encoded, ordinal, encode_partial_reason(reason));
        }
    }
    debug_assert_eq!(encoded.len(), total_length);
    Ok(encoded)
}

fn decode_completion(
    encoded: &[u8],
) -> Result<FetchCompletion, AcquisitionCompletionRecordErrorV1> {
    if encoded.len() < ACQUISITION_COMPLETION_HEADER_BYTES_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength);
    }
    if encoded[0..8] != MAGIC_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidMagic);
    }
    if read_u16(encoded, 8) != ACQUISITION_COMPLETION_VERSION_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::UnsupportedVersion);
    }
    if read_u16(encoded, 10) != ACQUISITION_COMPLETION_SCHEMA_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::UnsupportedSchema);
    }
    if read_u16(encoded, 12) != ACQUISITION_COMPLETION_OBJECT_KIND_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::UnsupportedObjectKind);
    }
    if usize::from(read_u16(encoded, 14)) != ACQUISITION_COMPLETION_HEADER_BYTES_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidHeaderWidth);
    }
    let flags = read_u16(encoded, FLAGS_OFFSET);
    if flags & !KNOWN_FLAGS != 0 {
        return Err(AcquisitionCompletionRecordErrorV1::UnknownFlags);
    }
    if encoded[RESERVED_ONE_OFFSET..RETRIEVAL_ID_OFFSET]
        .iter()
        .chain(encoded[RESERVED_TWO_OFFSET..ADAPTER_KIND_LENGTH_OFFSET].iter())
        .chain(encoded[RESERVED_THREE_OFFSET..ACQUISITION_COMPLETION_HEADER_BYTES_V1].iter())
        .any(|byte| *byte != 0)
    {
        return Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved);
    }
    let declared_total = u32_to_usize(read_u32(encoded, TOTAL_ENCODED_LENGTH_OFFSET))?;
    if declared_total > MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::TotalLengthCap);
    }
    if declared_total != encoded.len() {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength);
    }

    let adapter_kind_len = checked_nonempty_declared_length(
        read_u32(encoded, ADAPTER_KIND_LENGTH_OFFSET),
        MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
        AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong,
    )?;
    let adapter_version_len = checked_nonempty_declared_length(
        read_u32(encoded, ADAPTER_VERSION_LENGTH_OFFSET),
        MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
        AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong,
    )?;
    let first_cursor_len = checked_optional_declared_length(
        flags & FIRST_CURSOR_PRESENT != 0,
        read_u32(encoded, FIRST_CURSOR_LENGTH_OFFSET),
    )?;
    let final_cursor_len = checked_optional_declared_length(
        flags & FINAL_CURSOR_PRESENT != 0,
        read_u32(encoded, FINAL_CURSOR_LENGTH_OFFSET),
    )?;
    let continuation_len = checked_optional_declared_length(
        flags & CONTINUATION_PRESENT != 0,
        read_u32(encoded, CONTINUATION_LENGTH_OFFSET),
    )?;
    let high_water_count = checked_declared_count(
        read_u32(encoded, HIGH_WATER_COUNT_OFFSET),
        MAX_ACQUISITION_HIGH_WATER_MARKS_V1,
    )?;
    let cap_usage_count = checked_declared_count(
        read_u32(encoded, CAP_USAGE_COUNT_OFFSET),
        MAX_ACQUISITION_CAP_USAGES_V1,
    )?;
    let error_code_count = checked_declared_count(
        read_u32(encoded, ERROR_CODE_COUNT_OFFSET),
        MAX_ACQUISITION_ERROR_CODES_V1,
    )?;
    let partial_reason_count = checked_declared_count(
        read_u32(encoded, PARTIAL_REASON_COUNT_OFFSET),
        MAX_ACQUISITION_PARTIAL_REASONS_V1,
    )?;
    let high_water_section_len = u32_to_usize(read_u32(encoded, HIGH_WATER_SECTION_LENGTH_OFFSET))?;

    let cap_bytes = cap_usage_count
        .checked_mul(ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let error_bytes = error_code_count
        .checked_mul(ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let reason_bytes = partial_reason_count
        .checked_mul(ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1)
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let fixed_suffix = cap_bytes
        .checked_add(error_bytes)
        .and_then(|value| value.checked_add(reason_bytes))
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    let expected_total = ACQUISITION_COMPLETION_HEADER_BYTES_V1
        .checked_add(adapter_kind_len)
        .and_then(|value| value.checked_add(adapter_version_len))
        .and_then(|value| value.checked_add(first_cursor_len))
        .and_then(|value| value.checked_add(final_cursor_len))
        .and_then(|value| value.checked_add(continuation_len))
        .and_then(|value| value.checked_add(high_water_section_len))
        .and_then(|value| value.checked_add(fixed_suffix))
        .ok_or(AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)?;
    if expected_total != declared_total {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength);
    }

    let mut parser = Parser::new(&encoded[ACQUISITION_COMPLETION_HEADER_BYTES_V1..]);
    let adapter_kind = parse_string(parser.take(adapter_kind_len)?)?;
    let adapter_version = parse_string(parser.take(adapter_version_len)?)?;
    let first_cursor = parse_optional_cursor(&mut parser, first_cursor_len)?;
    let final_cursor = parse_optional_cursor(&mut parser, final_cursor_len)?;
    let continuation = parse_optional_cursor(&mut parser, continuation_len)?;
    let high_water_bytes = parser.take(high_water_section_len)?;
    let high_water_marks = decode_high_water_marks(high_water_bytes, high_water_count)?;
    let cap_usage = decode_cap_usages(&mut parser, cap_usage_count)?;
    let error_codes = decode_error_codes(&mut parser, error_code_count)?;
    let partial_reasons = decode_partial_reasons(&mut parser, partial_reason_count)?;
    if !parser.is_empty() {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength);
    }

    let completeness = decode_completeness(
        read_u16(encoded, COMPLETENESS_KIND_OFFSET),
        EncodedCode {
            tag: read_u16(encoded, COMPLETENESS_PRIMARY_TAG_OFFSET),
            version: read_u16(encoded, COMPLETENESS_PRIMARY_VERSION_OFFSET),
            code: read_u16(encoded, COMPLETENESS_PRIMARY_CODE_OFFSET),
        },
        partial_reasons,
        continuation,
    )?;
    let identity = FetchIdentity::new(
        RetrievalId::from_bytes(read_array(encoded, RETRIEVAL_ID_OFFSET)),
        PlanId::from_bytes(read_array(encoded, PLAN_ID_OFFSET)),
        PlanDigest::from_bytes(read_array(encoded, PLAN_DIGEST_OFFSET)),
        AdapterIdentity::new(adapter_kind, adapter_version)
            .map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidField)?,
    );
    FetchCompletion::new(
        identity,
        FetchTiming::new(
            UnixTimestampNanos::new(read_i128(encoded, STARTED_AT_OFFSET)),
            UnixTimestampNanos::new(read_i128(encoded, ENDED_AT_OFFSET)),
        ),
        AcknowledgedCounts::new(
            read_u64(encoded, ACKNOWLEDGED_RECORDS_OFFSET),
            read_u64(encoded, ACKNOWLEDGED_PAYLOAD_BYTES_OFFSET),
            read_u64(encoded, ACKNOWLEDGED_SOURCE_BYTES_OFFSET),
        ),
        AttemptCounts::new(
            read_u64(encoded, MEMBERS_ATTEMPTED_OFFSET),
            read_u64(encoded, MEMBERS_COMPLETED_OFFSET),
        ),
        AttemptCounts::new(
            read_u64(encoded, PAGES_ATTEMPTED_OFFSET),
            read_u64(encoded, PAGES_COMPLETED_OFFSET),
        ),
        FetchBoundaries::new(first_cursor, final_cursor, high_water_marks),
        cap_usage,
        decode_adapter_outcome(read_u16(encoded, ADAPTER_OUTCOME_OFFSET))?,
        error_codes,
        completeness,
    )
    .map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidFetchCompletion)
}

fn decode_high_water_marks(
    bytes: &[u8],
    count: usize,
) -> Result<Vec<HighWaterMark>, AcquisitionCompletionRecordErrorV1> {
    let mut parser = Parser::new(bytes);
    let mut marks = Vec::with_capacity(count);
    for expected_ordinal in 0..count {
        let ordinal = parser.take_u32()?;
        if ordinal != usize_to_u32(expected_ordinal)? {
            return Err(AcquisitionCompletionRecordErrorV1::InvalidListOrdinal);
        }
        let member_len = checked_nonempty_declared_length(
            parser.take_u32()?,
            MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1,
            AcquisitionCompletionRecordErrorV1::SourceMemberTooLong,
        )?;
        let cursor_len = checked_nonempty_declared_length(
            parser.take_u32()?,
            MAX_ACQUISITION_CURSOR_BYTES_V1,
            AcquisitionCompletionRecordErrorV1::CursorTooLong,
        )?;
        if parser.take_u32()? != 0 {
            return Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved);
        }
        let member = SourceMember::new(parser.take(member_len)?.to_vec())
            .map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidField)?;
        let cursor = SourceCursor::new(parser.take(cursor_len)?.to_vec())
            .map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidField)?;
        marks.push(HighWaterMark::new(member, cursor));
    }
    if !parser.is_empty() {
        return Err(AcquisitionCompletionRecordErrorV1::HighWaterSectionLengthMismatch);
    }
    Ok(marks)
}

fn decode_cap_usages(
    parser: &mut Parser<'_>,
    count: usize,
) -> Result<Vec<CapUsage>, AcquisitionCompletionRecordErrorV1> {
    let mut usages = Vec::with_capacity(count);
    for expected_ordinal in 0..count {
        if parser.take_u32()? != usize_to_u32(expected_ordinal)? {
            return Err(AcquisitionCompletionRecordErrorV1::InvalidListOrdinal);
        }
        let tag = parser.take_u16()?;
        let flags = parser.take_u16()?;
        if flags & !1 != 0 {
            return Err(AcquisitionCompletionRecordErrorV1::UnknownFlags);
        }
        let version = parser.take_u16()?;
        let code = parser.take_u16()?;
        if parser.take_u32()? != 0 {
            return Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved);
        }
        let used = parser.take_u64()?;
        let limit = parser.take_u64()?;
        usages.push(CapUsage::new(
            decode_cap_kind(EncodedCode { tag, version, code })?,
            used,
            limit,
            flags & 1 != 0,
        ));
    }
    Ok(usages)
}

fn decode_error_codes(
    parser: &mut Parser<'_>,
    count: usize,
) -> Result<Vec<FetchErrorCode>, AcquisitionCompletionRecordErrorV1> {
    let mut codes = Vec::with_capacity(count);
    for expected_ordinal in 0..count {
        codes.push(decode_error_code(decode_code_entry(
            parser,
            expected_ordinal,
        )?)?);
    }
    Ok(codes)
}

fn decode_partial_reasons(
    parser: &mut Parser<'_>,
    count: usize,
) -> Result<Vec<FetchPartialReason>, AcquisitionCompletionRecordErrorV1> {
    let mut reasons = Vec::with_capacity(count);
    for expected_ordinal in 0..count {
        reasons.push(decode_partial_reason(decode_code_entry(
            parser,
            expected_ordinal,
        )?)?);
    }
    Ok(reasons)
}

fn encode_cap_usage(encoded: &mut Vec<u8>, ordinal: u32, usage: CapUsage) {
    let code = encode_cap_kind(usage.kind());
    encoded.extend_from_slice(&ordinal.to_be_bytes());
    encoded.extend_from_slice(&code.tag.to_be_bytes());
    encoded.extend_from_slice(&u16::from(usage.reached()).to_be_bytes());
    encoded.extend_from_slice(&code.version.to_be_bytes());
    encoded.extend_from_slice(&code.code.to_be_bytes());
    encoded.extend_from_slice(&0u32.to_be_bytes());
    encoded.extend_from_slice(&usage.used().to_be_bytes());
    encoded.extend_from_slice(&usage.limit().to_be_bytes());
}

fn encode_code_entry(encoded: &mut Vec<u8>, ordinal: u32, code: EncodedCode) {
    encoded.extend_from_slice(&ordinal.to_be_bytes());
    encoded.extend_from_slice(&code.tag.to_be_bytes());
    encoded.extend_from_slice(&code.version.to_be_bytes());
    encoded.extend_from_slice(&code.code.to_be_bytes());
    encoded.extend_from_slice(&0u16.to_be_bytes());
}

fn decode_code_entry(
    parser: &mut Parser<'_>,
    expected_ordinal: usize,
) -> Result<EncodedCode, AcquisitionCompletionRecordErrorV1> {
    if parser.take_u32()? != usize_to_u32(expected_ordinal)? {
        return Err(AcquisitionCompletionRecordErrorV1::InvalidListOrdinal);
    }
    let code = EncodedCode {
        tag: parser.take_u16()?,
        version: parser.take_u16()?,
        code: parser.take_u16()?,
    };
    if parser.take_u16()? != 0 {
        return Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved);
    }
    Ok(code)
}

fn encode_completeness(completeness: &FetchCompleteness) -> (u16, EncodedCode) {
    match completeness {
        FetchCompleteness::Complete { proof } => {
            (COMPLETENESS_COMPLETE, encode_completeness_proof(*proof))
        }
        FetchCompleteness::Partial { .. } => (
            COMPLETENESS_PARTIAL,
            EncodedCode {
                tag: 0,
                version: 0,
                code: 0,
            },
        ),
        FetchCompleteness::Unknown { reason } => (
            COMPLETENESS_UNKNOWN,
            EncodedCode {
                tag: encode_unknown_reason(*reason),
                version: 0,
                code: 0,
            },
        ),
    }
}

fn decode_completeness(
    kind: u16,
    primary: EncodedCode,
    partial_reasons: Vec<FetchPartialReason>,
    continuation: Option<SourceCursor>,
) -> Result<FetchCompleteness, AcquisitionCompletionRecordErrorV1> {
    match kind {
        COMPLETENESS_COMPLETE => {
            if !partial_reasons.is_empty() || continuation.is_some() {
                return Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields);
            }
            Ok(FetchCompleteness::complete(decode_completeness_proof(
                primary,
            )?))
        }
        COMPLETENESS_PARTIAL => {
            if primary.tag != 0 || primary.version != 0 || primary.code != 0 {
                return Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields);
            }
            let mut reasons = partial_reasons.into_iter();
            let first = reasons
                .next()
                .ok_or(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields)?;
            Ok(FetchCompleteness::partial(
                FetchPartialReasons::with_additional(first, reasons),
                continuation,
            ))
        }
        COMPLETENESS_UNKNOWN => {
            if primary.version != 0
                || primary.code != 0
                || !partial_reasons.is_empty()
                || continuation.is_some()
            {
                return Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields);
            }
            Ok(FetchCompleteness::unknown(decode_unknown_reason(
                primary.tag,
            )?))
        }
        _ => Err(AcquisitionCompletionRecordErrorV1::UnsupportedCompletenessKind),
    }
}

fn encode_adapter_outcome(outcome: AdapterOutcome) -> u16 {
    match outcome {
        AdapterOutcome::Finished => 1,
        AdapterOutcome::Cancelled => 2,
        AdapterOutcome::DeadlineExceeded => 3,
        AdapterOutcome::ProviderStopped => 4,
        AdapterOutcome::SourceStopped => 5,
        AdapterOutcome::SinkStopped => 6,
        AdapterOutcome::AdapterStopped => 7,
    }
}

fn decode_adapter_outcome(tag: u16) -> Result<AdapterOutcome, AcquisitionCompletionRecordErrorV1> {
    match tag {
        1 => Ok(AdapterOutcome::Finished),
        2 => Ok(AdapterOutcome::Cancelled),
        3 => Ok(AdapterOutcome::DeadlineExceeded),
        4 => Ok(AdapterOutcome::ProviderStopped),
        5 => Ok(AdapterOutcome::SourceStopped),
        6 => Ok(AdapterOutcome::SinkStopped),
        7 => Ok(AdapterOutcome::AdapterStopped),
        _ => Err(AcquisitionCompletionRecordErrorV1::UnsupportedAdapterOutcome),
    }
}

fn encode_cap_kind(kind: CapKind) -> EncodedCode {
    match kind {
        CapKind::Records => simple_code(1),
        CapKind::SourceBytes => simple_code(2),
        CapKind::ExpandedBytes => simple_code(3),
        CapKind::Pages => simple_code(4),
        CapKind::Members => simple_code(5),
        CapKind::PerRecordBytes => simple_code(6),
        CapKind::InFlightBytes => simple_code(7),
        CapKind::EncryptedSpoolBytes => simple_code(8),
        CapKind::WallTimeMillis => simple_code(9),
        CapKind::DiagnosticBytes => simple_code(10),
        CapKind::OtherVersioned { version, code } => EncodedCode {
            tag: OTHER_VERSIONED_TAG,
            version,
            code,
        },
    }
}

fn decode_cap_kind(encoded: EncodedCode) -> Result<CapKind, AcquisitionCompletionRecordErrorV1> {
    let known = match encoded.tag {
        1 => Some(CapKind::Records),
        2 => Some(CapKind::SourceBytes),
        3 => Some(CapKind::ExpandedBytes),
        4 => Some(CapKind::Pages),
        5 => Some(CapKind::Members),
        6 => Some(CapKind::PerRecordBytes),
        7 => Some(CapKind::InFlightBytes),
        8 => Some(CapKind::EncryptedSpoolBytes),
        9 => Some(CapKind::WallTimeMillis),
        10 => Some(CapKind::DiagnosticBytes),
        OTHER_VERSIONED_TAG => {
            return Ok(CapKind::OtherVersioned {
                version: encoded.version,
                code: encoded.code,
            });
        }
        _ => return Err(AcquisitionCompletionRecordErrorV1::UnsupportedCapKind),
    };
    require_simple_code(encoded)?;
    Ok(known.expect("known cap tag assigned above"))
}

fn encode_error_code(code: FetchErrorCode) -> EncodedCode {
    match code {
        FetchErrorCode::AuthenticationChanged => simple_code(1),
        FetchErrorCode::PermissionDenied => simple_code(2),
        FetchErrorCode::SourceUnavailable => simple_code(3),
        FetchErrorCode::SourceChanged => simple_code(4),
        FetchErrorCode::ProviderFailure => simple_code(5),
        FetchErrorCode::NetworkFailure => simple_code(6),
        FetchErrorCode::ChildExitFailure => simple_code(7),
        FetchErrorCode::ChildKilled => simple_code(8),
        FetchErrorCode::MalformedProviderFraming => simple_code(9),
        FetchErrorCode::SourceReadFailure => simple_code(10),
        FetchErrorCode::SinkFailure => simple_code(11),
        FetchErrorCode::AdapterInvariantViolation => simple_code(12),
        FetchErrorCode::OtherVersioned { version, code } => EncodedCode {
            tag: OTHER_VERSIONED_TAG,
            version,
            code,
        },
    }
}

fn decode_error_code(
    encoded: EncodedCode,
) -> Result<FetchErrorCode, AcquisitionCompletionRecordErrorV1> {
    let known = match encoded.tag {
        1 => Some(FetchErrorCode::AuthenticationChanged),
        2 => Some(FetchErrorCode::PermissionDenied),
        3 => Some(FetchErrorCode::SourceUnavailable),
        4 => Some(FetchErrorCode::SourceChanged),
        5 => Some(FetchErrorCode::ProviderFailure),
        6 => Some(FetchErrorCode::NetworkFailure),
        7 => Some(FetchErrorCode::ChildExitFailure),
        8 => Some(FetchErrorCode::ChildKilled),
        9 => Some(FetchErrorCode::MalformedProviderFraming),
        10 => Some(FetchErrorCode::SourceReadFailure),
        11 => Some(FetchErrorCode::SinkFailure),
        12 => Some(FetchErrorCode::AdapterInvariantViolation),
        OTHER_VERSIONED_TAG => {
            return Ok(FetchErrorCode::OtherVersioned {
                version: encoded.version,
                code: encoded.code,
            });
        }
        _ => return Err(AcquisitionCompletionRecordErrorV1::UnsupportedErrorCode),
    };
    require_simple_code(encoded)?;
    Ok(known.expect("known error tag assigned above"))
}

fn encode_completeness_proof(proof: CompletenessProof) -> EncodedCode {
    match proof {
        CompletenessProof::FixedSnapshotVerified => simple_code(1),
        CompletenessProof::PlannedUnixFileSnapshotVerifiedV1 => simple_code(2),
        CompletenessProof::ProviderBoundaryExhausted => simple_code(3),
        CompletenessProof::FinalCursorVerified => simple_code(4),
        CompletenessProof::ReplayManifestVerified => simple_code(5),
        CompletenessProof::InMemoryFixtureExhausted => simple_code(6),
        CompletenessProof::OtherVersioned { version, code } => EncodedCode {
            tag: OTHER_VERSIONED_TAG,
            version,
            code,
        },
    }
}

fn decode_completeness_proof(
    encoded: EncodedCode,
) -> Result<CompletenessProof, AcquisitionCompletionRecordErrorV1> {
    let known = match encoded.tag {
        1 => Some(CompletenessProof::FixedSnapshotVerified),
        2 => Some(CompletenessProof::PlannedUnixFileSnapshotVerifiedV1),
        3 => Some(CompletenessProof::ProviderBoundaryExhausted),
        4 => Some(CompletenessProof::FinalCursorVerified),
        5 => Some(CompletenessProof::ReplayManifestVerified),
        6 => Some(CompletenessProof::InMemoryFixtureExhausted),
        OTHER_VERSIONED_TAG => {
            return Ok(CompletenessProof::OtherVersioned {
                version: encoded.version,
                code: encoded.code,
            });
        }
        _ => {
            return Err(AcquisitionCompletionRecordErrorV1::UnsupportedCompletenessProof);
        }
    };
    require_simple_code(encoded)?;
    Ok(known.expect("known proof tag assigned above"))
}

fn encode_partial_reason(reason: FetchPartialReason) -> EncodedCode {
    match reason {
        FetchPartialReason::RowCap => simple_code(1),
        FetchPartialReason::RecordCountCap => simple_code(2),
        FetchPartialReason::SourceByteCap => simple_code(3),
        FetchPartialReason::ExpandedByteCap => simple_code(4),
        FetchPartialReason::PageCap => simple_code(5),
        FetchPartialReason::WallTimeCap => simple_code(6),
        FetchPartialReason::Timeout => simple_code(7),
        FetchPartialReason::Cancelled => simple_code(8),
        FetchPartialReason::BackpressureLimit => simple_code(9),
        FetchPartialReason::PaginationIncomplete => simple_code(10),
        FetchPartialReason::ProviderCap => simple_code(11),
        FetchPartialReason::ProviderTruncation => simple_code(12),
        FetchPartialReason::PermissionLimited => simple_code(13),
        FetchPartialReason::AuthenticationChanged => simple_code(14),
        FetchPartialReason::RetentionBoundary => simple_code(15),
        FetchPartialReason::SourceChanged => simple_code(16),
        FetchPartialReason::SourceDisappeared => simple_code(17),
        FetchPartialReason::SourceReadError => simple_code(18),
        FetchPartialReason::ChildExitFailure => simple_code(19),
        FetchPartialReason::ChildKilled => simple_code(20),
        FetchPartialReason::NetworkFailure => simple_code(21),
        FetchPartialReason::MalformedProviderFraming => simple_code(22),
        FetchPartialReason::RecordTruncated => simple_code(23),
        FetchPartialReason::DecompressionLimit => simple_code(24),
        FetchPartialReason::SinkFailure => simple_code(25),
        FetchPartialReason::OtherVersioned { version, code } => EncodedCode {
            tag: OTHER_VERSIONED_TAG,
            version,
            code,
        },
    }
}

fn decode_partial_reason(
    encoded: EncodedCode,
) -> Result<FetchPartialReason, AcquisitionCompletionRecordErrorV1> {
    let known = match encoded.tag {
        1 => Some(FetchPartialReason::RowCap),
        2 => Some(FetchPartialReason::RecordCountCap),
        3 => Some(FetchPartialReason::SourceByteCap),
        4 => Some(FetchPartialReason::ExpandedByteCap),
        5 => Some(FetchPartialReason::PageCap),
        6 => Some(FetchPartialReason::WallTimeCap),
        7 => Some(FetchPartialReason::Timeout),
        8 => Some(FetchPartialReason::Cancelled),
        9 => Some(FetchPartialReason::BackpressureLimit),
        10 => Some(FetchPartialReason::PaginationIncomplete),
        11 => Some(FetchPartialReason::ProviderCap),
        12 => Some(FetchPartialReason::ProviderTruncation),
        13 => Some(FetchPartialReason::PermissionLimited),
        14 => Some(FetchPartialReason::AuthenticationChanged),
        15 => Some(FetchPartialReason::RetentionBoundary),
        16 => Some(FetchPartialReason::SourceChanged),
        17 => Some(FetchPartialReason::SourceDisappeared),
        18 => Some(FetchPartialReason::SourceReadError),
        19 => Some(FetchPartialReason::ChildExitFailure),
        20 => Some(FetchPartialReason::ChildKilled),
        21 => Some(FetchPartialReason::NetworkFailure),
        22 => Some(FetchPartialReason::MalformedProviderFraming),
        23 => Some(FetchPartialReason::RecordTruncated),
        24 => Some(FetchPartialReason::DecompressionLimit),
        25 => Some(FetchPartialReason::SinkFailure),
        OTHER_VERSIONED_TAG => {
            return Ok(FetchPartialReason::OtherVersioned {
                version: encoded.version,
                code: encoded.code,
            });
        }
        _ => return Err(AcquisitionCompletionRecordErrorV1::UnsupportedPartialReason),
    };
    require_simple_code(encoded)?;
    Ok(known.expect("known partial-reason tag assigned above"))
}

fn encode_unknown_reason(reason: FetchUnknownReason) -> u16 {
    match reason {
        FetchUnknownReason::ProviderHasNoCompletenessProof => 1,
        FetchUnknownReason::RetentionUnobservable => 2,
        FetchUnknownReason::HighWaterMarkUnverifiable => 3,
        FetchUnknownReason::EventuallyConsistentWindow => 4,
        FetchUnknownReason::LiveStreamOpenEnded => 5,
        FetchUnknownReason::AdapterCapabilityLimit => 6,
    }
}

fn decode_unknown_reason(
    tag: u16,
) -> Result<FetchUnknownReason, AcquisitionCompletionRecordErrorV1> {
    match tag {
        1 => Ok(FetchUnknownReason::ProviderHasNoCompletenessProof),
        2 => Ok(FetchUnknownReason::RetentionUnobservable),
        3 => Ok(FetchUnknownReason::HighWaterMarkUnverifiable),
        4 => Ok(FetchUnknownReason::EventuallyConsistentWindow),
        5 => Ok(FetchUnknownReason::LiveStreamOpenEnded),
        6 => Ok(FetchUnknownReason::AdapterCapabilityLimit),
        _ => Err(AcquisitionCompletionRecordErrorV1::UnsupportedUnknownReason),
    }
}

const fn simple_code(tag: u16) -> EncodedCode {
    EncodedCode {
        tag,
        version: 0,
        code: 0,
    }
}

fn require_simple_code(encoded: EncodedCode) -> Result<(), AcquisitionCompletionRecordErrorV1> {
    if encoded.version != 0 || encoded.code != 0 {
        return Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCodeFields);
    }
    Ok(())
}

fn optional_cursor_length(
    cursor: Option<&SourceCursor>,
) -> Result<u32, AcquisitionCompletionRecordErrorV1> {
    cursor.map_or(Ok(0), |value| usize_to_u32(value.as_bytes().len()))
}

fn append_optional_cursor(encoded: &mut Vec<u8>, cursor: Option<&SourceCursor>) {
    if let Some(cursor) = cursor {
        encoded.extend_from_slice(cursor.as_bytes());
    }
}

fn checked_nonempty_declared_length(
    length: u32,
    limit: usize,
    too_long: AcquisitionCompletionRecordErrorV1,
) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    let length = u32_to_usize(length)?;
    validate_nonempty_length(length, limit, too_long)?;
    Ok(length)
}

fn checked_optional_declared_length(
    present: bool,
    length: u32,
) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    let length = u32_to_usize(length)?;
    if present != (length != 0) {
        return Err(AcquisitionCompletionRecordErrorV1::NoncanonicalOptionalField);
    }
    if length > MAX_ACQUISITION_CURSOR_BYTES_V1 {
        return Err(AcquisitionCompletionRecordErrorV1::CursorTooLong);
    }
    Ok(length)
}

fn checked_declared_count(
    count: u32,
    limit: usize,
) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    let count = u32_to_usize(count)?;
    validate_count(count, limit)?;
    Ok(count)
}

fn parse_string(bytes: &[u8]) -> Result<String, AcquisitionCompletionRecordErrorV1> {
    String::from_utf8(bytes.to_vec()).map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidUtf8)
}

fn parse_optional_cursor(
    parser: &mut Parser<'_>,
    length: usize,
) -> Result<Option<SourceCursor>, AcquisitionCompletionRecordErrorV1> {
    if length == 0 {
        return Ok(None);
    }
    SourceCursor::new(parser.take(length)?.to_vec())
        .map(Some)
        .map_err(|_| AcquisitionCompletionRecordErrorV1::InvalidField)
}

fn usize_to_u16(value: usize) -> Result<u16, AcquisitionCompletionRecordErrorV1> {
    u16::try_from(value).map_err(|_| AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)
}

fn usize_to_u32(value: usize) -> Result<u32, AcquisitionCompletionRecordErrorV1> {
    u32::try_from(value).map_err(|_| AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)
}

fn u32_to_usize(value: u32) -> Result<usize, AcquisitionCompletionRecordErrorV1> {
    usize::try_from(value).map_err(|_| AcquisitionCompletionRecordErrorV1::ArithmeticOverflow)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_i128(bytes: &mut [u8], offset: usize, value: i128) {
    bytes[offset..offset + 16].copy_from_slice(&value.to_be_bytes());
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

fn read_i128(bytes: &[u8], offset: usize) -> i128 {
    i128::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

struct Parser<'a> {
    remaining: &'a [u8],
}

impl<'a> Parser<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AcquisitionCompletionRecordErrorV1> {
        if length > self.remaining.len() {
            return Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength);
        }
        let (taken, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(taken)
    }

    fn take_u16(&mut self) -> Result<u16, AcquisitionCompletionRecordErrorV1> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| AcquisitionCompletionRecordErrorV1::InvalidEncodedLength,
        )?))
    }

    fn take_u32(&mut self) -> Result<u32, AcquisitionCompletionRecordErrorV1> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| AcquisitionCompletionRecordErrorV1::InvalidEncodedLength,
        )?))
    }

    fn take_u64(&mut self) -> Result<u64, AcquisitionCompletionRecordErrorV1> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| AcquisitionCompletionRecordErrorV1::InvalidEncodedLength,
        )?))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

const _: () = assert!(ACQUISITION_COMPLETION_HEADER_BYTES_V1 <= u16::MAX as usize);
const _: () =
    assert!(MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1 <= crate::MAX_MANIFEST_PLAINTEXT_BYTES_V1);
