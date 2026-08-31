use std::error::Error as StdError;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    ACQUISITION_COMPLETION_SCHEMA_V1, ACQUISITION_COMPLETION_VERSION_V1,
    AcquisitionCompletionRecordV1, EVENT_EXPANSION_INDEX_SCHEMA_V1,
    EVENT_EXPANSION_INDEX_VERSION_V1, EventExpansionIndexV1,
    MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1, MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1,
    MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1, MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1,
    MAX_MANIFEST_PLAINTEXT_BYTES_V1, SEGMENT_CATALOG_SCHEMA_V1, SEGMENT_CATALOG_VERSION_V1,
    SOURCE_OUTCOME_TABLE_SCHEMA_V1, SOURCE_OUTCOME_TABLE_VERSION_V1, SegmentCatalogV1,
    SourceOutcomeTableV1,
};

pub const CORE_MANIFEST_COMPONENTS_VERSION_V1: u16 = 1;
pub const CORE_MANIFEST_COMPONENTS_SCHEMA_V1: u16 = 1;
pub const CORE_MANIFEST_COMPONENTS_OBJECT_KIND_V1: u16 = 1;
pub const CORE_MANIFEST_COMPONENT_COUNT_V1: usize = 4;
pub const CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1: usize = 64;
pub const CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1: usize = 64;
pub const CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1: usize =
    CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1
        + CORE_MANIFEST_COMPONENT_COUNT_V1 * CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1;
pub const CORE_MANIFEST_COMPONENT_DIGEST_BYTES_V1: usize = 32;
pub const CORE_MANIFEST_COMPONENTS_DIGEST_BYTES_V1: usize = 32;
pub const MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1: usize = MAX_MANIFEST_PLAINTEXT_BYTES_V1;
pub const CORE_MANIFEST_COMPONENTS_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail.snapshot.core-manifest-components.v1";

const MAGIC_V1: [u8; 8] = *b"EVRCMC01";

const HEADER_FLAGS_OFFSET: usize = 16;
const HEADER_CHILD_COUNT_OFFSET: usize = 18;
const HEADER_TOTAL_LENGTH_OFFSET: usize = 20;
const HEADER_RESERVED_OFFSET: usize = 24;

const DESCRIPTOR_ORDINAL_OFFSET: usize = 0;
const DESCRIPTOR_KIND_OFFSET: usize = 2;
const DESCRIPTOR_VERSION_OFFSET: usize = 4;
const DESCRIPTOR_SCHEMA_OFFSET: usize = 6;
const DESCRIPTOR_BODY_OFFSET: usize = 8;
const DESCRIPTOR_LENGTH_OFFSET: usize = 12;
const DESCRIPTOR_DIGEST_OFFSET: usize = 16;
const DESCRIPTOR_RESERVED_OFFSET: usize = 48;

/// Fixed V1 child order in the core-components bundle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreManifestComponentKindV1 {
    SegmentCatalog,
    EventExpansionIndex,
    SourceOutcomeTable,
    AcquisitionCompletion,
}

impl CoreManifestComponentKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SegmentCatalog => "segment_catalog_v1",
            Self::EventExpansionIndex => "event_expansion_index_v1",
            Self::SourceOutcomeTable => "source_outcome_table_v1",
            Self::AcquisitionCompletion => "acquisition_completion_v1",
        }
    }

    const fn wire_code(self) -> u16 {
        match self {
            Self::SegmentCatalog => 1,
            Self::EventExpansionIndex => 2,
            Self::SourceOutcomeTable => 3,
            Self::AcquisitionCompletion => 4,
        }
    }

    const fn version(self) -> u16 {
        match self {
            Self::SegmentCatalog => SEGMENT_CATALOG_VERSION_V1,
            Self::EventExpansionIndex => EVENT_EXPANSION_INDEX_VERSION_V1,
            Self::SourceOutcomeTable => SOURCE_OUTCOME_TABLE_VERSION_V1,
            Self::AcquisitionCompletion => ACQUISITION_COMPLETION_VERSION_V1,
        }
    }

    const fn schema(self) -> u16 {
        match self {
            Self::SegmentCatalog => SEGMENT_CATALOG_SCHEMA_V1,
            Self::EventExpansionIndex => EVENT_EXPANSION_INDEX_SCHEMA_V1,
            Self::SourceOutcomeTable => SOURCE_OUTCOME_TABLE_SCHEMA_V1,
            Self::AcquisitionCompletion => ACQUISITION_COMPLETION_SCHEMA_V1,
        }
    }

    const fn maximum_encoded_length(self) -> usize {
        match self {
            Self::SegmentCatalog => MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1,
            Self::EventExpansionIndex => MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1,
            Self::SourceOutcomeTable => MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1,
            Self::AcquisitionCompletion => MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1,
        }
    }

    fn from_wire_code(code: u16) -> Result<Self, CoreManifestComponentsErrorV1> {
        match code {
            1 => Ok(Self::SegmentCatalog),
            2 => Ok(Self::EventExpansionIndex),
            3 => Ok(Self::SourceOutcomeTable),
            4 => Ok(Self::AcquisitionCompletion),
            _ => Err(CoreManifestComponentsErrorV1::UnsupportedChildKind),
        }
    }
}

impl fmt::Debug for CoreManifestComponentKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreManifestComponentKindV1")
            .field("code", &self.code())
            .finish()
    }
}

const CHILD_ORDER: [CoreManifestComponentKindV1; CORE_MANIFEST_COMPONENT_COUNT_V1] = [
    CoreManifestComponentKindV1::SegmentCatalog,
    CoreManifestComponentKindV1::EventExpansionIndex,
    CoreManifestComponentKindV1::SourceOutcomeTable,
    CoreManifestComponentKindV1::AcquisitionCompletion,
];

/// Raw SHA-256 of one exact canonical child encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreManifestComponentDigestV1([u8; CORE_MANIFEST_COMPONENT_DIGEST_BYTES_V1]);

impl CoreManifestComponentDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CORE_MANIFEST_COMPONENT_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CORE_MANIFEST_COMPONENT_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for CoreManifestComponentDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreManifestComponentDigestV1(<redacted>)")
    }
}

/// Domain-separated digest of the exact complete core-components encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreManifestComponentsDigestV1([u8; CORE_MANIFEST_COMPONENTS_DIGEST_BYTES_V1]);

impl CoreManifestComponentsDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CORE_MANIFEST_COMPONENTS_DIGEST_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CORE_MANIFEST_COMPONENTS_DIGEST_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for CoreManifestComponentsDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreManifestComponentsDigestV1(<redacted>)")
    }
}

/// Stable, contentless bundle construction or decode failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreManifestComponentsErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSchema,
    UnsupportedObjectKind,
    InvalidHeaderWidth,
    NonzeroFlags,
    NonzeroReserved,
    InvalidChildCount,
    InvalidDescriptorOrdinal,
    UnsupportedChildKind,
    DuplicateChildKind,
    NoncanonicalChildOrder,
    ChildVersionMismatch,
    ChildSchemaMismatch,
    ChildLengthCap,
    NoncontiguousChildRange,
    ChildDigestMismatch,
    TotalLengthCap,
    CatalogDecodeFailed,
    CatalogIndexMismatch,
    OutcomeIndexMismatch,
    CompletionDecodeFailed,
    CompletionOutcomeMismatch,
    NoncanonicalChildEncoding,
    ArithmeticOverflow,
}

impl CoreManifestComponentsErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_CORE_COMPONENTS_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_CORE_COMPONENTS_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_CORE_COMPONENTS_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_CORE_COMPONENTS_UNSUPPORTED_SCHEMA",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_CORE_COMPONENTS_UNSUPPORTED_OBJECT_KIND",
            Self::InvalidHeaderWidth => "EVIDENTRAIL_CORE_COMPONENTS_INVALID_HEADER_WIDTH",
            Self::NonzeroFlags => "EVIDENTRAIL_CORE_COMPONENTS_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_CORE_COMPONENTS_NONZERO_RESERVED",
            Self::InvalidChildCount => "EVIDENTRAIL_CORE_COMPONENTS_INVALID_CHILD_COUNT",
            Self::InvalidDescriptorOrdinal => {
                "EVIDENTRAIL_CORE_COMPONENTS_INVALID_DESCRIPTOR_ORDINAL"
            }
            Self::UnsupportedChildKind => "EVIDENTRAIL_CORE_COMPONENTS_UNSUPPORTED_CHILD_KIND",
            Self::DuplicateChildKind => "EVIDENTRAIL_CORE_COMPONENTS_DUPLICATE_CHILD_KIND",
            Self::NoncanonicalChildOrder => "EVIDENTRAIL_CORE_COMPONENTS_NONCANONICAL_CHILD_ORDER",
            Self::ChildVersionMismatch => "EVIDENTRAIL_CORE_COMPONENTS_CHILD_VERSION_MISMATCH",
            Self::ChildSchemaMismatch => "EVIDENTRAIL_CORE_COMPONENTS_CHILD_SCHEMA_MISMATCH",
            Self::ChildLengthCap => "EVIDENTRAIL_CORE_COMPONENTS_CHILD_LENGTH_CAP",
            Self::NoncontiguousChildRange => {
                "EVIDENTRAIL_CORE_COMPONENTS_NONCONTIGUOUS_CHILD_RANGE"
            }
            Self::ChildDigestMismatch => "EVIDENTRAIL_CORE_COMPONENTS_CHILD_DIGEST_MISMATCH",
            Self::TotalLengthCap => "EVIDENTRAIL_CORE_COMPONENTS_TOTAL_LENGTH_CAP",
            Self::CatalogDecodeFailed => "EVIDENTRAIL_CORE_COMPONENTS_CATALOG_DECODE_FAILED",
            Self::CatalogIndexMismatch => "EVIDENTRAIL_CORE_COMPONENTS_CATALOG_INDEX_MISMATCH",
            Self::OutcomeIndexMismatch => "EVIDENTRAIL_CORE_COMPONENTS_OUTCOME_INDEX_MISMATCH",
            Self::CompletionDecodeFailed => "EVIDENTRAIL_CORE_COMPONENTS_COMPLETION_DECODE_FAILED",
            Self::CompletionOutcomeMismatch => {
                "EVIDENTRAIL_CORE_COMPONENTS_COMPLETION_OUTCOME_MISMATCH"
            }
            Self::NoncanonicalChildEncoding => {
                "EVIDENTRAIL_CORE_COMPONENTS_NONCANONICAL_CHILD_ENCODING"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_CORE_COMPONENTS_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for CoreManifestComponentsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreManifestComponentsErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CoreManifestComponentsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CoreManifestComponentsErrorV1 {}

/// The four currently proven, cross-reconciled snapshot payload components.
///
/// This is deliberately not called a complete manifest or manifest plaintext,
/// and it does not prove a sealed result. It lacks `ResultId`, authoritative
/// `SourceIdentityDigest`/`AcquisitionReceiptId` binding, policy-receipt
/// contents, outer AEAD/seal, authenticated frame open, aliases/blocks,
/// filesystem durability, recovery, and publication state.
#[derive(PartialEq, Eq)]
pub struct CoreManifestComponentsV1 {
    catalog: SegmentCatalogV1,
    event_index: EventExpansionIndexV1,
    source_outcomes: SourceOutcomeTableV1,
    acquisition_completion: AcquisitionCompletionRecordV1,
}

impl CoreManifestComponentsV1 {
    pub fn new(
        catalog: &SegmentCatalogV1,
        event_index: &EventExpansionIndexV1,
        source_outcomes: &SourceOutcomeTableV1,
        acquisition_completion: &AcquisitionCompletionRecordV1,
    ) -> Result<Self, CoreManifestComponentsErrorV1> {
        let encoded = EncodedChildren::new(
            catalog.encode(),
            event_index.encode(),
            source_outcomes.encode(),
            acquisition_completion.encode(),
        )?;
        decode_and_reconcile_children(encoded.as_slices())
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        CORE_MANIFEST_COMPONENTS_VERSION_V1
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        CORE_MANIFEST_COMPONENTS_SCHEMA_V1
    }

    #[must_use]
    pub const fn catalog(&self) -> &SegmentCatalogV1 {
        &self.catalog
    }

    #[must_use]
    pub const fn event_index(&self) -> &EventExpansionIndexV1 {
        &self.event_index
    }

    #[must_use]
    pub const fn source_outcomes(&self) -> &SourceOutcomeTableV1 {
        &self.source_outcomes
    }

    #[must_use]
    pub const fn acquisition_completion(&self) -> &AcquisitionCompletionRecordV1 {
        &self.acquisition_completion
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1
            + self.catalog.encoded_len()
            + self.event_index.encoded_len()
            + self.source_outcomes.encoded_len()
            + self.acquisition_completion.encoded_len()
    }

    #[must_use]
    pub fn child_digest(&self, kind: CoreManifestComponentKindV1) -> CoreManifestComponentDigestV1 {
        derive_child_digest(match kind {
            CoreManifestComponentKindV1::SegmentCatalog => self.catalog.encode(),
            CoreManifestComponentKindV1::EventExpansionIndex => self.event_index.encode(),
            CoreManifestComponentKindV1::SourceOutcomeTable => self.source_outcomes.encode(),
            CoreManifestComponentKindV1::AcquisitionCompletion => {
                self.acquisition_completion.encode()
            }
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let children = EncodedChildren::new(
            self.catalog.encode(),
            self.event_index.encode(),
            self.source_outcomes.encode(),
            self.acquisition_completion.encode(),
        )
        .expect("admitted core components remain within frozen bounds");
        encode_bundle(&children).expect("admitted core components remain encodable")
    }

    #[must_use]
    pub fn bundle_digest(&self) -> CoreManifestComponentsDigestV1 {
        derive_core_manifest_components_digest_v1(&self.encode())
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CoreManifestComponentsErrorV1> {
        let children = decode_directory(encoded)?;
        decode_and_reconcile_children(children)
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SegmentCatalogV1,
        EventExpansionIndexV1,
        SourceOutcomeTableV1,
        AcquisitionCompletionRecordV1,
    ) {
        (
            self.catalog,
            self.event_index,
            self.source_outcomes,
            self.acquisition_completion,
        )
    }
}

impl fmt::Debug for CoreManifestComponentsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreManifestComponentsV1(<redacted>)")
    }
}

/// Exact digest: SHA-256(domain || encoded_length:u64-be || canonical bytes).
#[must_use]
pub fn derive_core_manifest_components_digest_v1(encoded: &[u8]) -> CoreManifestComponentsDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(CORE_MANIFEST_COMPONENTS_DIGEST_DOMAIN_V1);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    CoreManifestComponentsDigestV1::from_bytes(hasher.finalize().into())
}

struct EncodedChildren {
    catalog: Vec<u8>,
    event_index: Vec<u8>,
    source_outcomes: Vec<u8>,
    acquisition_completion: Vec<u8>,
}

impl EncodedChildren {
    fn new(
        catalog: Vec<u8>,
        event_index: Vec<u8>,
        source_outcomes: Vec<u8>,
        acquisition_completion: Vec<u8>,
    ) -> Result<Self, CoreManifestComponentsErrorV1> {
        let children = Self {
            catalog,
            event_index,
            source_outcomes,
            acquisition_completion,
        };
        validate_children_lengths(children.as_slices())?;
        Ok(children)
    }

    fn as_slices(&self) -> [&[u8]; CORE_MANIFEST_COMPONENT_COUNT_V1] {
        [
            &self.catalog,
            &self.event_index,
            &self.source_outcomes,
            &self.acquisition_completion,
        ]
    }
}

fn encode_bundle(children: &EncodedChildren) -> Result<Vec<u8>, CoreManifestComponentsErrorV1> {
    let slices = children.as_slices();
    let total_length = validate_children_lengths(slices)?;
    let mut header = [0u8; CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1];
    header[0..8].copy_from_slice(&MAGIC_V1);
    put_u16(&mut header, 8, CORE_MANIFEST_COMPONENTS_VERSION_V1);
    put_u16(&mut header, 10, CORE_MANIFEST_COMPONENTS_SCHEMA_V1);
    put_u16(&mut header, 12, CORE_MANIFEST_COMPONENTS_OBJECT_KIND_V1);
    put_u16(
        &mut header,
        14,
        usize_to_u16(CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1)?,
    );
    put_u16(&mut header, HEADER_FLAGS_OFFSET, 0);
    put_u16(
        &mut header,
        HEADER_CHILD_COUNT_OFFSET,
        usize_to_u16(CORE_MANIFEST_COMPONENT_COUNT_V1)?,
    );
    put_u32(
        &mut header,
        HEADER_TOTAL_LENGTH_OFFSET,
        usize_to_u32(total_length)?,
    );

    let mut body_offset = CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1;
    for (ordinal, (kind, child)) in CHILD_ORDER.into_iter().zip(slices).enumerate() {
        let start = CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1
            + ordinal * CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1;
        let descriptor = &mut header[start..start + CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1];
        put_u16(
            descriptor,
            DESCRIPTOR_ORDINAL_OFFSET,
            usize_to_u16(ordinal)?,
        );
        put_u16(descriptor, DESCRIPTOR_KIND_OFFSET, kind.wire_code());
        put_u16(descriptor, DESCRIPTOR_VERSION_OFFSET, kind.version());
        put_u16(descriptor, DESCRIPTOR_SCHEMA_OFFSET, kind.schema());
        put_u32(
            descriptor,
            DESCRIPTOR_BODY_OFFSET,
            usize_to_u32(body_offset)?,
        );
        put_u32(
            descriptor,
            DESCRIPTOR_LENGTH_OFFSET,
            usize_to_u32(child.len())?,
        );
        descriptor[DESCRIPTOR_DIGEST_OFFSET..DESCRIPTOR_RESERVED_OFFSET]
            .copy_from_slice(derive_child_digest(child).as_bytes());
        body_offset = body_offset
            .checked_add(child.len())
            .ok_or(CoreManifestComponentsErrorV1::ArithmeticOverflow)?;
    }

    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header);
    for child in slices {
        encoded.extend_from_slice(child);
    }
    debug_assert_eq!(encoded.len(), total_length);
    Ok(encoded)
}

fn decode_directory(
    encoded: &[u8],
) -> Result<[&[u8]; CORE_MANIFEST_COMPONENT_COUNT_V1], CoreManifestComponentsErrorV1> {
    if encoded.len() < CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1 {
        return Err(CoreManifestComponentsErrorV1::InvalidEncodedLength);
    }
    if encoded.len() > MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1 {
        return Err(CoreManifestComponentsErrorV1::TotalLengthCap);
    }
    if encoded[0..8] != MAGIC_V1 {
        return Err(CoreManifestComponentsErrorV1::InvalidMagic);
    }
    if read_u16(encoded, 8) != CORE_MANIFEST_COMPONENTS_VERSION_V1 {
        return Err(CoreManifestComponentsErrorV1::UnsupportedVersion);
    }
    if read_u16(encoded, 10) != CORE_MANIFEST_COMPONENTS_SCHEMA_V1 {
        return Err(CoreManifestComponentsErrorV1::UnsupportedSchema);
    }
    if read_u16(encoded, 12) != CORE_MANIFEST_COMPONENTS_OBJECT_KIND_V1 {
        return Err(CoreManifestComponentsErrorV1::UnsupportedObjectKind);
    }
    if usize::from(read_u16(encoded, 14)) != CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1 {
        return Err(CoreManifestComponentsErrorV1::InvalidHeaderWidth);
    }
    if read_u16(encoded, HEADER_FLAGS_OFFSET) != 0 {
        return Err(CoreManifestComponentsErrorV1::NonzeroFlags);
    }
    if usize::from(read_u16(encoded, HEADER_CHILD_COUNT_OFFSET)) != CORE_MANIFEST_COMPONENT_COUNT_V1
    {
        return Err(CoreManifestComponentsErrorV1::InvalidChildCount);
    }
    if encoded[HEADER_RESERVED_OFFSET..CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(CoreManifestComponentsErrorV1::NonzeroReserved);
    }
    let declared_total = u32_to_usize(read_u32(encoded, HEADER_TOTAL_LENGTH_OFFSET))?;
    if declared_total > MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1 {
        return Err(CoreManifestComponentsErrorV1::TotalLengthCap);
    }
    if declared_total != encoded.len() {
        return Err(CoreManifestComponentsErrorV1::InvalidEncodedLength);
    }

    let mut seen_kinds = [false; CORE_MANIFEST_COMPONENT_COUNT_V1];
    let mut expected_offset = CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1;
    let mut ranges = [(0usize, 0usize); CORE_MANIFEST_COMPONENT_COUNT_V1];
    for (ordinal, expected_kind) in CHILD_ORDER.into_iter().enumerate() {
        let start = CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1
            + ordinal * CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1;
        let descriptor = &encoded[start..start + CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1];
        if usize::from(read_u16(descriptor, DESCRIPTOR_ORDINAL_OFFSET)) != ordinal {
            return Err(CoreManifestComponentsErrorV1::InvalidDescriptorOrdinal);
        }
        let kind = CoreManifestComponentKindV1::from_wire_code(read_u16(
            descriptor,
            DESCRIPTOR_KIND_OFFSET,
        ))?;
        let kind_index = usize::from(kind.wire_code() - 1);
        if seen_kinds[kind_index] {
            return Err(CoreManifestComponentsErrorV1::DuplicateChildKind);
        }
        seen_kinds[kind_index] = true;
        if kind != expected_kind {
            return Err(CoreManifestComponentsErrorV1::NoncanonicalChildOrder);
        }
        if read_u16(descriptor, DESCRIPTOR_VERSION_OFFSET) != kind.version() {
            return Err(CoreManifestComponentsErrorV1::ChildVersionMismatch);
        }
        if read_u16(descriptor, DESCRIPTOR_SCHEMA_OFFSET) != kind.schema() {
            return Err(CoreManifestComponentsErrorV1::ChildSchemaMismatch);
        }
        if descriptor[DESCRIPTOR_RESERVED_OFFSET..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CoreManifestComponentsErrorV1::NonzeroReserved);
        }
        let child_offset = u32_to_usize(read_u32(descriptor, DESCRIPTOR_BODY_OFFSET))?;
        let child_length = u32_to_usize(read_u32(descriptor, DESCRIPTOR_LENGTH_OFFSET))?;
        if child_length == 0 || child_length > kind.maximum_encoded_length() {
            return Err(CoreManifestComponentsErrorV1::ChildLengthCap);
        }
        if child_offset != expected_offset {
            return Err(CoreManifestComponentsErrorV1::NoncontiguousChildRange);
        }
        let child_end = child_offset
            .checked_add(child_length)
            .ok_or(CoreManifestComponentsErrorV1::ArithmeticOverflow)?;
        if child_end > declared_total {
            return Err(CoreManifestComponentsErrorV1::InvalidEncodedLength);
        }
        let child = &encoded[child_offset..child_end];
        let declared_digest = CoreManifestComponentDigestV1::from_bytes(read_array(
            descriptor,
            DESCRIPTOR_DIGEST_OFFSET,
        ));
        if derive_child_digest(child) != declared_digest {
            return Err(CoreManifestComponentsErrorV1::ChildDigestMismatch);
        }
        ranges[ordinal] = (child_offset, child_end);
        expected_offset = child_end;
    }
    if expected_offset != declared_total {
        return Err(CoreManifestComponentsErrorV1::InvalidEncodedLength);
    }
    Ok(ranges.map(|(start, end)| &encoded[start..end]))
}

fn decode_and_reconcile_children(
    children: [&[u8]; CORE_MANIFEST_COMPONENT_COUNT_V1],
) -> Result<CoreManifestComponentsV1, CoreManifestComponentsErrorV1> {
    validate_children_lengths(children)?;
    let catalog = SegmentCatalogV1::decode(children[0])
        .map_err(|_| CoreManifestComponentsErrorV1::CatalogDecodeFailed)?;
    if catalog.encode() != children[0] {
        return Err(CoreManifestComponentsErrorV1::NoncanonicalChildEncoding);
    }
    let event_index = EventExpansionIndexV1::decode(&catalog, children[1])
        .map_err(|_| CoreManifestComponentsErrorV1::CatalogIndexMismatch)?;
    if event_index.encode() != children[1] {
        return Err(CoreManifestComponentsErrorV1::NoncanonicalChildEncoding);
    }
    let source_outcomes = SourceOutcomeTableV1::decode(&event_index, children[2])
        .map_err(|_| CoreManifestComponentsErrorV1::OutcomeIndexMismatch)?;
    if source_outcomes.encode() != children[2] {
        return Err(CoreManifestComponentsErrorV1::NoncanonicalChildEncoding);
    }
    let receipt = source_outcomes
        .to_acquisition_receipt()
        .map_err(|_| CoreManifestComponentsErrorV1::OutcomeIndexMismatch)?;
    let acquisition_completion = AcquisitionCompletionRecordV1::decode(children[3])
        .map_err(|_| CoreManifestComponentsErrorV1::CompletionDecodeFailed)?;
    if acquisition_completion.encode() != children[3] {
        return Err(CoreManifestComponentsErrorV1::NoncanonicalChildEncoding);
    }
    acquisition_completion
        .verify_against_receipt(&receipt)
        .map_err(|_| CoreManifestComponentsErrorV1::CompletionOutcomeMismatch)?;
    Ok(CoreManifestComponentsV1 {
        catalog,
        event_index,
        source_outcomes,
        acquisition_completion,
    })
}

fn validate_children_lengths(
    children: [&[u8]; CORE_MANIFEST_COMPONENT_COUNT_V1],
) -> Result<usize, CoreManifestComponentsErrorV1> {
    let mut total = CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1;
    for (kind, child) in CHILD_ORDER.into_iter().zip(children) {
        if child.is_empty() || child.len() > kind.maximum_encoded_length() {
            return Err(CoreManifestComponentsErrorV1::ChildLengthCap);
        }
        total = total
            .checked_add(child.len())
            .ok_or(CoreManifestComponentsErrorV1::ArithmeticOverflow)?;
    }
    if total > MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1 {
        return Err(CoreManifestComponentsErrorV1::TotalLengthCap);
    }
    Ok(total)
}

fn derive_child_digest(bytes: impl AsRef<[u8]>) -> CoreManifestComponentDigestV1 {
    CoreManifestComponentDigestV1::from_bytes(Sha256::digest(bytes.as_ref()).into())
}

fn usize_to_u16(value: usize) -> Result<u16, CoreManifestComponentsErrorV1> {
    u16::try_from(value).map_err(|_| CoreManifestComponentsErrorV1::ArithmeticOverflow)
}

fn usize_to_u32(value: usize) -> Result<u32, CoreManifestComponentsErrorV1> {
    u32::try_from(value).map_err(|_| CoreManifestComponentsErrorV1::ArithmeticOverflow)
}

fn u32_to_usize(value: u32) -> Result<usize, CoreManifestComponentsErrorV1> {
    usize::try_from(value).map_err(|_| CoreManifestComponentsErrorV1::ArithmeticOverflow)
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

const _: () = assert!(CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1 <= u16::MAX as usize);
const _: () = assert!(MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1 <= u32::MAX as usize);
