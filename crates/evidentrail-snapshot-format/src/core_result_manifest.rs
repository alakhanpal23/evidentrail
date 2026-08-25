use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionReceipt, AcquisitionReceiptId, ExactnessBasis, ResultId,
    SourceIdentityDigest,
};
use sha2::{Digest, Sha256};

use crate::{
    CORE_MANIFEST_COMPONENTS_SCHEMA_V1, CORE_MANIFEST_COMPONENTS_VERSION_V1,
    CoreManifestComponentsDigestV1, CoreManifestComponentsV1, MAX_MANIFEST_PLAINTEXT_BYTES_V1,
    derive_core_manifest_components_digest_v1,
};

pub const CORE_RESULT_MANIFEST_VERSION_V1: u16 = 1;
pub const CORE_RESULT_MANIFEST_SCHEMA_V1: u16 = 1;
pub const CORE_RESULT_MANIFEST_OBJECT_KIND_V1: u16 = 1;
pub const CORE_RESULT_MANIFEST_HEADER_BYTES_V1: usize = 256;
pub const CORE_RESULT_MANIFEST_DIGEST_BYTES_V1: usize = 32;
pub const CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.core-result-manifest.v1";
pub const MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1: usize = MAX_MANIFEST_PLAINTEXT_BYTES_V1;
pub const MAX_CORE_RESULT_MANIFEST_COMPONENTS_BYTES_V1: usize =
    MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 - CORE_RESULT_MANIFEST_HEADER_BYTES_V1;

const MAGIC_V1: [u8; 8] = *b"EVRCRM01";
const ACQUISITION_RECEIPT_ID_DOMAIN_V1: &[u8] = b"evidentrail/acquisition-receipt/v1";

const FLAGS_OFFSET: usize = 16;
const COMPONENTS_VERSION_OFFSET: usize = 18;
const COMPONENTS_SCHEMA_OFFSET: usize = 20;
const RESERVED_ONE_OFFSET: usize = 22;
const TOTAL_LENGTH_OFFSET: usize = 24;
const COMPONENTS_OFFSET_OFFSET: usize = 28;
const COMPONENTS_LENGTH_OFFSET: usize = 32;
const RESERVED_TWO_OFFSET: usize = 36;
const RESULT_ID_OFFSET: usize = 64;
const SOURCE_IDENTITY_DIGEST_OFFSET: usize = 96;
const ACQUISITION_RECEIPT_ID_OFFSET: usize = 128;
const COMPONENTS_DIGEST_OFFSET: usize = 160;
const MANIFEST_DIGEST_OFFSET: usize = 192;
const RESERVED_THREE_OFFSET: usize = 224;

/// Domain-separated digest of the exact canonical authority-binding record.
///
/// The digest is an integrity binding only. It is not authenticated until a
/// future outer manifest AEAD admits the record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreResultManifestDigestV1([u8; CORE_RESULT_MANIFEST_DIGEST_BYTES_V1]);

impl CoreResultManifestDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CORE_RESULT_MANIFEST_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CORE_RESULT_MANIFEST_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for CoreResultManifestDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreResultManifestDigestV1(<redacted>)")
    }
}

/// Stable, contentless construction or decode failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreResultManifestErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    UnsupportedObjectKind,
    InvalidHeaderWidth,
    NonzeroFlags,
    NonzeroReserved,
    ComponentsVersionMismatch,
    ComponentsSchemaMismatch,
    InvalidComponentsOffset,
    ComponentsLengthCap,
    ComponentsDigestMismatch,
    ManifestDigestMismatch,
    ComponentsDecodeFailed,
    NoncanonicalComponentsEncoding,
    AcquisitionReceiptReconstructionFailed,
    AcquisitionReceiptIdMismatch,
    AuthorityMismatch,
    ArithmeticOverflow,
}

impl CoreResultManifestErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_CORE_RESULT_MANIFEST_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_CORE_RESULT_MANIFEST_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_CORE_RESULT_MANIFEST_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_CORE_RESULT_MANIFEST_UNSUPPORTED_SCHEMA",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_CORE_RESULT_MANIFEST_UNSUPPORTED_OBJECT_KIND",
            Self::InvalidHeaderWidth => "EVIDENTRAIL_CORE_RESULT_MANIFEST_INVALID_HEADER_WIDTH",
            Self::NonzeroFlags => "EVIDENTRAIL_CORE_RESULT_MANIFEST_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_CORE_RESULT_MANIFEST_NONZERO_RESERVED",
            Self::ComponentsVersionMismatch => {
                "EVIDENTRAIL_CORE_RESULT_MANIFEST_COMPONENTS_VERSION_MISMATCH"
            }
            Self::ComponentsSchemaMismatch => {
                "EVIDENTRAIL_CORE_RESULT_MANIFEST_COMPONENTS_SCHEMA_MISMATCH"
            }
            Self::InvalidComponentsOffset => "EVIDENTRAIL_CORE_RESULT_MANIFEST_INVALID_COMPONENTS_OFFSET",
            Self::ComponentsLengthCap => "EVIDENTRAIL_CORE_RESULT_MANIFEST_COMPONENTS_LENGTH_CAP",
            Self::ComponentsDigestMismatch => {
                "EVIDENTRAIL_CORE_RESULT_MANIFEST_COMPONENTS_DIGEST_MISMATCH"
            }
            Self::ManifestDigestMismatch => "EVIDENTRAIL_CORE_RESULT_MANIFEST_RECORD_DIGEST_MISMATCH",
            Self::ComponentsDecodeFailed => "EVIDENTRAIL_CORE_RESULT_MANIFEST_COMPONENTS_DECODE_FAILED",
            Self::NoncanonicalComponentsEncoding => {
                "EVIDENTRAIL_CORE_RESULT_MANIFEST_NONCANONICAL_COMPONENTS_ENCODING"
            }
            Self::AcquisitionReceiptReconstructionFailed => {
                "EVIDENTRAIL_CORE_RESULT_MANIFEST_RECEIPT_RECONSTRUCTION_FAILED"
            }
            Self::AcquisitionReceiptIdMismatch => "EVIDENTRAIL_CORE_RESULT_MANIFEST_RECEIPT_ID_MISMATCH",
            Self::AuthorityMismatch => "EVIDENTRAIL_CORE_RESULT_MANIFEST_AUTHORITY_MISMATCH",
            Self::ArithmeticOverflow => "EVIDENTRAIL_CORE_RESULT_MANIFEST_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for CoreResultManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreResultManifestErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CoreResultManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CoreResultManifestErrorV1 {}

/// A canonical authority-binding record around the four proven core snapshot
/// components.
///
/// This is not the complete encrypted manifest, manifest plaintext, or a
/// sealed result. It does not contain policy-receipt contents and does not
/// claim outer AEAD/seal authentication, frame authentication/open, aliases,
/// blocks, filesystem durability, recovery, or publication. Its unkeyed
/// digests bind exact bytes but are not an authenticity boundary.
#[derive(PartialEq, Eq)]
pub struct CoreResultManifestV1 {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    components_digest: CoreManifestComponentsDigestV1,
    manifest_digest: CoreResultManifestDigestV1,
    components: CoreManifestComponentsV1,
}

impl CoreResultManifestV1 {
    pub fn new(
        result_id: ResultId,
        source_identity_digest: SourceIdentityDigest,
        acquisition_receipt_id: AcquisitionReceiptId,
        components: &CoreManifestComponentsV1,
    ) -> Result<Self, CoreResultManifestErrorV1> {
        validate_components_length(components.encoded_len())?;
        let components_encoded = components.encode();
        let canonical_components = CoreManifestComponentsV1::decode(&components_encoded)
            .map_err(|_| CoreResultManifestErrorV1::ComponentsDecodeFailed)?;
        if canonical_components.encode() != components_encoded {
            return Err(CoreResultManifestErrorV1::NoncanonicalComponentsEncoding);
        }
        validate_receipt_id(&canonical_components, acquisition_receipt_id)?;
        let components_digest = derive_core_manifest_components_digest_v1(&components_encoded);
        let manifest_digest = derive_manifest_digest(
            result_id,
            source_identity_digest,
            acquisition_receipt_id,
            components_digest,
            &components_encoded,
        )?;
        Ok(Self {
            result_id,
            source_identity_digest,
            acquisition_receipt_id,
            components_digest,
            manifest_digest,
            components: canonical_components,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        CORE_RESULT_MANIFEST_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        CORE_RESULT_MANIFEST_SCHEMA_V1
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(&self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn components_digest(&self) -> CoreManifestComponentsDigestV1 {
        self.components_digest
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> CoreResultManifestDigestV1 {
        self.manifest_digest
    }

    #[must_use]
    pub const fn components(&self) -> &CoreManifestComponentsV1 {
        &self.components
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        CORE_RESULT_MANIFEST_HEADER_BYTES_V1 + self.components.encoded_len()
    }

    pub fn to_acquisition_receipt(&self) -> Result<AcquisitionReceipt, CoreResultManifestErrorV1> {
        self.components
            .source_outcomes()
            .to_acquisition_receipt()
            .map_err(|_| CoreResultManifestErrorV1::AcquisitionReceiptReconstructionFailed)
    }

    /// Compare restored authority with independently authenticated context.
    ///
    /// The record's own unkeyed digest cannot provide this external authority.
    pub fn verify_authority(
        &self,
        expected_result_id: ResultId,
        expected_source_identity_digest: SourceIdentityDigest,
        expected_acquisition_receipt_id: AcquisitionReceiptId,
    ) -> Result<(), CoreResultManifestErrorV1> {
        if self.result_id != expected_result_id
            || self.source_identity_digest != expected_source_identity_digest
            || self.acquisition_receipt_id != expected_acquisition_receipt_id
        {
            return Err(CoreResultManifestErrorV1::AuthorityMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let components_encoded = self.components.encode();
        encode_record(
            self.result_id,
            self.source_identity_digest,
            self.acquisition_receipt_id,
            self.components_digest,
            self.manifest_digest,
            &components_encoded,
        )
        .expect("admitted core result manifests remain within frozen bounds")
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CoreResultManifestErrorV1> {
        let header = decode_header(encoded)?;
        let components_encoded = &encoded[header.components_range];
        let computed_components_digest =
            derive_core_manifest_components_digest_v1(components_encoded);
        if computed_components_digest != header.components_digest {
            return Err(CoreResultManifestErrorV1::ComponentsDigestMismatch);
        }
        let computed_manifest_digest = derive_manifest_digest(
            header.result_id,
            header.source_identity_digest,
            header.acquisition_receipt_id,
            header.components_digest,
            components_encoded,
        )?;
        if computed_manifest_digest != header.manifest_digest {
            return Err(CoreResultManifestErrorV1::ManifestDigestMismatch);
        }
        let components = CoreManifestComponentsV1::decode(components_encoded)
            .map_err(|_| CoreResultManifestErrorV1::ComponentsDecodeFailed)?;
        if components.encode() != components_encoded {
            return Err(CoreResultManifestErrorV1::NoncanonicalComponentsEncoding);
        }
        validate_receipt_id(&components, header.acquisition_receipt_id)?;
        Ok(Self {
            result_id: header.result_id,
            source_identity_digest: header.source_identity_digest,
            acquisition_receipt_id: header.acquisition_receipt_id,
            components_digest: header.components_digest,
            manifest_digest: header.manifest_digest,
            components,
        })
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ResultId,
        SourceIdentityDigest,
        AcquisitionReceiptId,
        CoreManifestComponentsV1,
    ) {
        (
            self.result_id,
            self.source_identity_digest,
            self.acquisition_receipt_id,
            self.components,
        )
    }
}

impl fmt::Debug for CoreResultManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreResultManifestV1(<redacted>)")
    }
}

struct DecodedHeader {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    components_digest: CoreManifestComponentsDigestV1,
    manifest_digest: CoreResultManifestDigestV1,
    components_range: std::ops::Range<usize>,
}

fn decode_header(encoded: &[u8]) -> Result<DecodedHeader, CoreResultManifestErrorV1> {
    if encoded.len() < CORE_RESULT_MANIFEST_HEADER_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::InvalidEncodedLength);
    }
    if encoded.len() > MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsLengthCap);
    }
    if encoded[0..8] != MAGIC_V1 {
        return Err(CoreResultManifestErrorV1::InvalidMagic);
    }
    if read_u16(encoded, 8) != CORE_RESULT_MANIFEST_VERSION_V1 {
        return Err(CoreResultManifestErrorV1::UnsupportedVersion);
    }
    if read_u16(encoded, 10) != CORE_RESULT_MANIFEST_SCHEMA_V1 {
        return Err(CoreResultManifestErrorV1::UnsupportedSchema);
    }
    if read_u16(encoded, 12) != CORE_RESULT_MANIFEST_OBJECT_KIND_V1 {
        return Err(CoreResultManifestErrorV1::UnsupportedObjectKind);
    }
    if usize::from(read_u16(encoded, 14)) != CORE_RESULT_MANIFEST_HEADER_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::InvalidHeaderWidth);
    }
    if read_u16(encoded, FLAGS_OFFSET) != 0 {
        return Err(CoreResultManifestErrorV1::NonzeroFlags);
    }
    if read_u16(encoded, COMPONENTS_VERSION_OFFSET) != CORE_MANIFEST_COMPONENTS_VERSION_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsVersionMismatch);
    }
    if read_u16(encoded, COMPONENTS_SCHEMA_OFFSET) != CORE_MANIFEST_COMPONENTS_SCHEMA_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsSchemaMismatch);
    }
    if encoded[RESERVED_ONE_OFFSET..TOTAL_LENGTH_OFFSET]
        .iter()
        .chain(encoded[RESERVED_TWO_OFFSET..RESULT_ID_OFFSET].iter())
        .chain(encoded[RESERVED_THREE_OFFSET..CORE_RESULT_MANIFEST_HEADER_BYTES_V1].iter())
        .any(|byte| *byte != 0)
    {
        return Err(CoreResultManifestErrorV1::NonzeroReserved);
    }
    let declared_total = u32_to_usize(read_u32(encoded, TOTAL_LENGTH_OFFSET))?;
    if declared_total > MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsLengthCap);
    }
    if declared_total != encoded.len() {
        return Err(CoreResultManifestErrorV1::InvalidEncodedLength);
    }
    let components_offset = u32_to_usize(read_u32(encoded, COMPONENTS_OFFSET_OFFSET))?;
    if components_offset != CORE_RESULT_MANIFEST_HEADER_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::InvalidComponentsOffset);
    }
    let components_length = u32_to_usize(read_u32(encoded, COMPONENTS_LENGTH_OFFSET))?;
    validate_components_length(components_length)?;
    let components_end = components_offset
        .checked_add(components_length)
        .ok_or(CoreResultManifestErrorV1::ArithmeticOverflow)?;
    if components_end != declared_total {
        return Err(CoreResultManifestErrorV1::InvalidEncodedLength);
    }

    Ok(DecodedHeader {
        result_id: ResultId::from_bytes(read_array(encoded, RESULT_ID_OFFSET)),
        source_identity_digest: SourceIdentityDigest::from_bytes(read_array(
            encoded,
            SOURCE_IDENTITY_DIGEST_OFFSET,
        )),
        acquisition_receipt_id: AcquisitionReceiptId::from_bytes(read_array(
            encoded,
            ACQUISITION_RECEIPT_ID_OFFSET,
        )),
        components_digest: CoreManifestComponentsDigestV1::from_bytes(read_array(
            encoded,
            COMPONENTS_DIGEST_OFFSET,
        )),
        manifest_digest: CoreResultManifestDigestV1::from_bytes(read_array(
            encoded,
            MANIFEST_DIGEST_OFFSET,
        )),
        components_range: components_offset..components_end,
    })
}

fn encode_record(
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    components_digest: CoreManifestComponentsDigestV1,
    manifest_digest: CoreResultManifestDigestV1,
    components_encoded: &[u8],
) -> Result<Vec<u8>, CoreResultManifestErrorV1> {
    validate_components_length(components_encoded.len())?;
    let total_length = CORE_RESULT_MANIFEST_HEADER_BYTES_V1
        .checked_add(components_encoded.len())
        .ok_or(CoreResultManifestErrorV1::ArithmeticOverflow)?;
    let mut header = [0u8; CORE_RESULT_MANIFEST_HEADER_BYTES_V1];
    header[0..8].copy_from_slice(&MAGIC_V1);
    put_u16(&mut header, 8, CORE_RESULT_MANIFEST_VERSION_V1);
    put_u16(&mut header, 10, CORE_RESULT_MANIFEST_SCHEMA_V1);
    put_u16(&mut header, 12, CORE_RESULT_MANIFEST_OBJECT_KIND_V1);
    put_u16(
        &mut header,
        14,
        usize_to_u16(CORE_RESULT_MANIFEST_HEADER_BYTES_V1)?,
    );
    put_u16(&mut header, FLAGS_OFFSET, 0);
    put_u16(
        &mut header,
        COMPONENTS_VERSION_OFFSET,
        CORE_MANIFEST_COMPONENTS_VERSION_V1,
    );
    put_u16(
        &mut header,
        COMPONENTS_SCHEMA_OFFSET,
        CORE_MANIFEST_COMPONENTS_SCHEMA_V1,
    );
    put_u32(
        &mut header,
        TOTAL_LENGTH_OFFSET,
        usize_to_u32(total_length)?,
    );
    put_u32(
        &mut header,
        COMPONENTS_OFFSET_OFFSET,
        usize_to_u32(CORE_RESULT_MANIFEST_HEADER_BYTES_V1)?,
    );
    put_u32(
        &mut header,
        COMPONENTS_LENGTH_OFFSET,
        usize_to_u32(components_encoded.len())?,
    );
    header[RESULT_ID_OFFSET..SOURCE_IDENTITY_DIGEST_OFFSET].copy_from_slice(result_id.as_bytes());
    header[SOURCE_IDENTITY_DIGEST_OFFSET..ACQUISITION_RECEIPT_ID_OFFSET]
        .copy_from_slice(source_identity_digest.as_bytes());
    header[ACQUISITION_RECEIPT_ID_OFFSET..COMPONENTS_DIGEST_OFFSET]
        .copy_from_slice(acquisition_receipt_id.as_bytes());
    header[COMPONENTS_DIGEST_OFFSET..MANIFEST_DIGEST_OFFSET]
        .copy_from_slice(components_digest.as_bytes());
    header[MANIFEST_DIGEST_OFFSET..RESERVED_THREE_OFFSET]
        .copy_from_slice(manifest_digest.as_bytes());

    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(components_encoded);
    Ok(encoded)
}

fn derive_manifest_digest(
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    components_digest: CoreManifestComponentsDigestV1,
    components_encoded: &[u8],
) -> Result<CoreResultManifestDigestV1, CoreResultManifestErrorV1> {
    let zero_digest = CoreResultManifestDigestV1::from_bytes([0; 32]);
    let encoded = encode_record(
        result_id,
        source_identity_digest,
        acquisition_receipt_id,
        components_digest,
        zero_digest,
        components_encoded,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1);
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| CoreResultManifestErrorV1::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(CoreResultManifestDigestV1::from_bytes(
        hasher.finalize().into(),
    ))
}

fn validate_receipt_id(
    components: &CoreManifestComponentsV1,
    expected_receipt_id: AcquisitionReceiptId,
) -> Result<(), CoreResultManifestErrorV1> {
    let receipt = components
        .source_outcomes()
        .to_acquisition_receipt()
        .map_err(|_| CoreResultManifestErrorV1::AcquisitionReceiptReconstructionFailed)?;
    if derive_acquisition_receipt_id_v1(&receipt) != expected_receipt_id {
        return Err(CoreResultManifestErrorV1::AcquisitionReceiptIdMismatch);
    }
    Ok(())
}

// Exact frozen V1 identity algorithm shared with the ledger. The domain is
// itself the first length-framed field; every field uses a u64 little-endian
// byte length; receipt entries remain in canonical acquisition order; outcome
// codes are the exact schema codes; and event/policy/transformation fields are
// included only for the matching closed outcome variant. This module owns the
// local verifier because snapshot-format must remain independent of evidentrail-core.
// It never exposes the derived value as a second authority: it only checks the
// caller-supplied AcquisitionReceiptId against the reconstructed receipt.
fn derive_acquisition_receipt_id_v1(receipt: &AcquisitionReceipt) -> AcquisitionReceiptId {
    let mut hasher = Sha256::new();
    update_receipt_field(&mut hasher, ACQUISITION_RECEIPT_ID_DOMAIN_V1);
    update_receipt_field(&mut hasher, receipt.retrieval_id().as_bytes());
    for entry in receipt.entries() {
        update_receipt_field(&mut hasher, entry.source_record_id().as_bytes());
        update_receipt_field(&mut hasher, entry.outcome().code().as_bytes());
        match entry.outcome() {
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis,
            } => {
                update_receipt_field(&mut hasher, event_id.as_bytes());
                if let ExactnessBasis::PostPolicy {
                    policy_digest,
                    transformation_receipt_id,
                } = exactness_basis
                {
                    update_receipt_field(&mut hasher, policy_digest.as_bytes());
                    update_receipt_field(&mut hasher, transformation_receipt_id.as_bytes());
                }
            }
            AcquisitionOutcome::OmittedByPolicy { policy_digest } => {
                update_receipt_field(&mut hasher, policy_digest.as_bytes());
            }
        }
    }
    AcquisitionReceiptId::from_bytes(hasher.finalize().into())
}

fn update_receipt_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("bounded receipt fields fit u64");
    hasher.update(length.to_le_bytes());
    hasher.update(value);
}

fn validate_components_length(length: usize) -> Result<(), CoreResultManifestErrorV1> {
    if length == 0 || length > MAX_CORE_RESULT_MANIFEST_COMPONENTS_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsLengthCap);
    }
    let total = CORE_RESULT_MANIFEST_HEADER_BYTES_V1
        .checked_add(length)
        .ok_or(CoreResultManifestErrorV1::ArithmeticOverflow)?;
    if total > MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 {
        return Err(CoreResultManifestErrorV1::ComponentsLengthCap);
    }
    Ok(())
}

fn usize_to_u16(value: usize) -> Result<u16, CoreResultManifestErrorV1> {
    u16::try_from(value).map_err(|_| CoreResultManifestErrorV1::ArithmeticOverflow)
}

fn usize_to_u32(value: usize) -> Result<u32, CoreResultManifestErrorV1> {
    u32::try_from(value).map_err(|_| CoreResultManifestErrorV1::ArithmeticOverflow)
}

fn u32_to_usize(value: u32) -> Result<usize, CoreResultManifestErrorV1> {
    usize::try_from(value).map_err(|_| CoreResultManifestErrorV1::ArithmeticOverflow)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

const _: () = assert!(CORE_RESULT_MANIFEST_HEADER_BYTES_V1 <= u16::MAX as usize);
const _: () = assert!(MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 <= u32::MAX as usize);
