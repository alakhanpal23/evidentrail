use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{AcquisitionReceiptId, ResultId, SourceIdentityDigest};
use zeroize::Zeroizing;

use crate::{
    CORE_RESULT_MANIFEST_SCHEMA_V1, CoreResultManifestV1, MANIFEST_HEADER_BYTES_V1,
    MAX_MANIFEST_PLAINTEXT_BYTES_V1, ManifestCommitmentV1, ManifestHeaderV1, ManifestKeyViewV1,
    ManifestNonceV1, SealedManifestV1, open_manifest_v1, seal_manifest_v1,
};

/// Frozen outer `ManifestHeaderV1::payload_schema` value for an exact encoded
/// `CoreResultManifestV1` plaintext.
pub const CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1: u16 = CORE_RESULT_MANIFEST_SCHEMA_V1;

/// Stable, contentless failure at the typed core-result payload boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreResultPayloadErrorV1 {
    InvalidTimeRange,
    PlaintextLengthOverflow,
    OuterSealFailed,
    OuterDecodeFailed,
    OuterAuthenticationFailed,
    PayloadSchemaMismatch,
    AuthenticatedContextMismatch,
    InnerDecodeFailed,
    NoncanonicalInnerEncoding,
    AuthorityMismatch,
}

impl CoreResultPayloadErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTimeRange => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_INVALID_TIME_RANGE",
            Self::PlaintextLengthOverflow => {
                "EVIDENTRAIL_CORE_RESULT_PAYLOAD_PLAINTEXT_LENGTH_OVERFLOW"
            }
            Self::OuterSealFailed => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_OUTER_SEAL_FAILED",
            Self::OuterDecodeFailed => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_OUTER_DECODE_FAILED",
            Self::OuterAuthenticationFailed => {
                "EVIDENTRAIL_CORE_RESULT_PAYLOAD_OUTER_AUTHENTICATION_FAILED"
            }
            Self::PayloadSchemaMismatch => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_SCHEMA_MISMATCH",
            Self::AuthenticatedContextMismatch => {
                "EVIDENTRAIL_CORE_RESULT_PAYLOAD_AUTHENTICATED_CONTEXT_MISMATCH"
            }
            Self::InnerDecodeFailed => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_INNER_DECODE_FAILED",
            Self::NoncanonicalInnerEncoding => {
                "EVIDENTRAIL_CORE_RESULT_PAYLOAD_NONCANONICAL_INNER_ENCODING"
            }
            Self::AuthorityMismatch => "EVIDENTRAIL_CORE_RESULT_PAYLOAD_AUTHORITY_MISMATCH",
        }
    }
}

impl fmt::Debug for CoreResultPayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreResultPayloadErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CoreResultPayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CoreResultPayloadErrorV1 {}

/// Caller-controlled outer time and injected nonce used for in-memory seal.
///
/// Nonce uniqueness remains the responsibility of the result-wide nonce
/// coordinator; this value alone makes no uniqueness or publication claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreResultManifestSealContextV1 {
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
    nonce: ManifestNonceV1,
}

impl CoreResultManifestSealContextV1 {
    pub fn new(
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        nonce: ManifestNonceV1,
    ) -> Result<Self, CoreResultPayloadErrorV1> {
        validate_time_range(created_unix_nanos, expires_unix_nanos)?;
        Ok(Self {
            created_unix_nanos,
            expires_unix_nanos,
            nonce,
        })
    }

    #[must_use]
    pub const fn created_unix_nanos(self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(self) -> i64 {
        self.expires_unix_nanos
    }

    #[must_use]
    pub const fn nonce(self) -> ManifestNonceV1 {
        self.nonce
    }
}

impl fmt::Debug for CoreResultManifestSealContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreResultManifestSealContextV1(<redacted>)")
    }
}

/// Independently retained authority and time context required when opening.
///
/// `ResultId` and the times are compared with the outer header authenticated as
/// AEAD AAD. `SourceIdentityDigest` and `AcquisitionReceiptId` are compared with
/// the decoded inner record only after AEAD authentication; the receipt ID is
/// also independently recomputed from its self-restored receipt by that codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpectedCoreResultManifestContextV1 {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
}

impl ExpectedCoreResultManifestContextV1 {
    pub fn new(
        result_id: ResultId,
        source_identity_digest: SourceIdentityDigest,
        acquisition_receipt_id: AcquisitionReceiptId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
    ) -> Result<Self, CoreResultPayloadErrorV1> {
        validate_time_range(created_unix_nanos, expires_unix_nanos)?;
        Ok(Self {
            result_id,
            source_identity_digest,
            acquisition_receipt_id,
            created_unix_nanos,
            expires_unix_nanos,
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

    #[must_use]
    pub const fn created_unix_nanos(self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(self) -> i64 {
        self.expires_unix_nanos
    }
}

impl fmt::Debug for ExpectedCoreResultManifestContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedCoreResultManifestContextV1(<redacted>)")
    }
}

/// An outer AEAD object whose declared payload schema is
/// `CoreResultManifestV1`.
///
/// Decode alone is structural and does not authenticate ciphertext. Only
/// [`open_core_result_manifest_v1`] establishes authenticity.
#[derive(PartialEq, Eq)]
pub struct SealedCoreResultManifestV1 {
    outer: SealedManifestV1,
}

impl SealedCoreResultManifestV1 {
    #[must_use]
    pub const fn header(&self) -> &ManifestHeaderV1 {
        self.outer.header()
    }

    #[must_use]
    pub const fn commitment(&self) -> ManifestCommitmentV1 {
        self.outer.commitment()
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.outer.encoded_len()
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.outer.encode()
    }

    /// Parse the outer object for an expected result identity without claiming
    /// that its ciphertext or inner record has authenticated yet.
    pub fn decode(
        expected_result_id: ResultId,
        encoded: &[u8],
    ) -> Result<Self, CoreResultPayloadErrorV1> {
        let outer = SealedManifestV1::decode(expected_result_id, encoded)
            .map_err(|_| CoreResultPayloadErrorV1::OuterDecodeFailed)?;
        validate_payload_schema(outer.header())?;
        Ok(Self { outer })
    }
}

impl fmt::Debug for SealedCoreResultManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedCoreResultManifestV1(<redacted>)")
    }
}

/// Authenticated and canonically decoded core authority payload.
///
/// This object proves only the in-memory AEAD/open and exact context checks
/// performed by [`open_core_result_manifest_v1`]. It is not a result-key seal,
/// frame-chain proof, filesystem snapshot, durable write, recovery result, or
/// publication state.
#[derive(PartialEq, Eq)]
pub struct OpenedCoreResultManifestV1 {
    outer_header: ManifestHeaderV1,
    manifest: CoreResultManifestV1,
}

impl OpenedCoreResultManifestV1 {
    #[must_use]
    pub const fn outer_header(&self) -> &ManifestHeaderV1 {
        &self.outer_header
    }

    #[must_use]
    pub const fn manifest(&self) -> &CoreResultManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.manifest.result_id()
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.manifest.source_identity_digest()
    }

    #[must_use]
    pub const fn acquisition_receipt_id(&self) -> AcquisitionReceiptId {
        self.manifest.acquisition_receipt_id()
    }

    #[must_use]
    pub fn into_manifest(self) -> CoreResultManifestV1 {
        self.manifest
    }
}

impl fmt::Debug for OpenedCoreResultManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedCoreResultManifestV1(<redacted>)")
    }
}

/// Encode the exact admitted inner record into a zeroizing temporary and seal
/// it as the frozen typed outer manifest payload.
pub fn seal_core_result_manifest_v1(
    key: &ManifestKeyViewV1<'_>,
    context: CoreResultManifestSealContextV1,
    manifest: &CoreResultManifestV1,
) -> Result<SealedCoreResultManifestV1, CoreResultPayloadErrorV1> {
    if manifest.schema() != CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1 {
        return Err(CoreResultPayloadErrorV1::PayloadSchemaMismatch);
    }
    if manifest.encoded_len() > MAX_MANIFEST_PLAINTEXT_BYTES_V1 {
        return Err(CoreResultPayloadErrorV1::PlaintextLengthOverflow);
    }
    let plaintext = Zeroizing::new(manifest.encode());
    let canonical = CoreResultManifestV1::decode(&plaintext)
        .map_err(|_| CoreResultPayloadErrorV1::InnerDecodeFailed)?;
    if canonical.encode() != plaintext.as_slice() {
        return Err(CoreResultPayloadErrorV1::NoncanonicalInnerEncoding);
    }
    let plaintext_length = u32::try_from(plaintext.len())
        .map_err(|_| CoreResultPayloadErrorV1::PlaintextLengthOverflow)?;
    let header = ManifestHeaderV1::new(
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1,
        manifest.result_id(),
        0,
        context.created_unix_nanos(),
        context.expires_unix_nanos(),
        plaintext_length,
        context.nonce(),
    )
    .map_err(|_| CoreResultPayloadErrorV1::OuterSealFailed)?;
    let outer = seal_manifest_v1(key, header, &plaintext)
        .map_err(|_| CoreResultPayloadErrorV1::OuterSealFailed)?;
    Ok(SealedCoreResultManifestV1 { outer })
}

/// Authenticate the outer object, then decode and re-encode the exact inner
/// record before comparing it with independently retained authority context.
pub fn open_core_result_manifest_v1(
    key: &ManifestKeyViewV1<'_>,
    expected: ExpectedCoreResultManifestContextV1,
    sealed: &SealedCoreResultManifestV1,
) -> Result<OpenedCoreResultManifestV1, CoreResultPayloadErrorV1> {
    validate_payload_schema(sealed.outer.header())?;
    let opened = open_manifest_v1(key, expected.result_id(), &sealed.outer)
        .map_err(|_| CoreResultPayloadErrorV1::OuterAuthenticationFailed)?;
    // Only values in the successfully authenticated AAD are admitted as outer
    // context. Recheck them after open before interpreting plaintext.
    if sealed.outer.header().payload_schema() != CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1
        || sealed.outer.header().result_id() != expected.result_id()
        || sealed.outer.header().created_unix_nanos() != expected.created_unix_nanos()
        || sealed.outer.header().expires_unix_nanos() != expected.expires_unix_nanos()
    {
        return Err(CoreResultPayloadErrorV1::AuthenticatedContextMismatch);
    }
    let manifest = CoreResultManifestV1::decode(opened.as_bytes())
        .map_err(|_| CoreResultPayloadErrorV1::InnerDecodeFailed)?;
    if manifest.encode() != opened.as_bytes() {
        return Err(CoreResultPayloadErrorV1::NoncanonicalInnerEncoding);
    }
    if manifest.result_id() != sealed.outer.header().result_id()
        || manifest.source_identity_digest() != expected.source_identity_digest()
        || manifest.acquisition_receipt_id() != expected.acquisition_receipt_id()
    {
        return Err(CoreResultPayloadErrorV1::AuthorityMismatch);
    }
    Ok(OpenedCoreResultManifestV1 {
        outer_header: *sealed.outer.header(),
        manifest,
    })
}

fn validate_payload_schema(header: &ManifestHeaderV1) -> Result<(), CoreResultPayloadErrorV1> {
    if header.payload_schema() != CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1 {
        return Err(CoreResultPayloadErrorV1::PayloadSchemaMismatch);
    }
    Ok(())
}

fn validate_time_range(
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
) -> Result<(), CoreResultPayloadErrorV1> {
    if expires_unix_nanos <= created_unix_nanos {
        return Err(CoreResultPayloadErrorV1::InvalidTimeRange);
    }
    Ok(())
}

const _: () = assert!(CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1 != 0);
const _: () = assert!(MANIFEST_HEADER_BYTES_V1 < MAX_MANIFEST_PLAINTEXT_BYTES_V1);
