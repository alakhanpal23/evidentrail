use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1,
    MAX_EVIDENCE_REFERENCE_TARGETS, UnixTimestampNanos,
};
use evidentrail_schema::bounds::MAX_LOG_BRIEF_EVIDENCE_PACKETS;
use evidentrail_schema::{EvidenceReferenceId, ResultId};
use evidentrail_snapshot_format::MAX_FRAME_PLAINTEXT_BYTES_V1;
use sha2::{Digest, Sha256};

pub const DISPLAYED_ALIAS_MANIFEST_VERSION_V1: u16 = 1;
pub const DISPLAYED_ALIAS_MANIFEST_SCHEMA_V1: u16 = 1;
pub const DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1: usize = 112;
pub const DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1: usize = 80;

const MAGIC_V1: [u8; 8] = *b"EVRALS01";
const DIGEST_DOMAIN_V1: &[u8] = b"evidentrail/displayed-alias-manifest/v1";
const EXACT_RELATION_CODE_V1: u16 = 1;

/// Stable, contentless displayed-alias manifest failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DisplayedAliasManifestErrorV1 {
    TooManyAliases,
    InvalidOrdinal,
    InvalidResult,
    InvalidLifetime,
    InvalidRelation,
    InvalidTarget,
    InvalidEventOrder,
    DuplicateEvent,
    DuplicateReference,
    OverlappingAliasEvents,
    SizeCap,
    ArithmeticOverflow,
    WrongLength,
    UnsupportedVersion,
    UnsupportedSchema,
    NoncanonicalReserved,
    DigestMismatch,
    ReferenceMismatch,
    TrailingData,
}

impl DisplayedAliasManifestErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyAliases => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_TOO_MANY_ALIASES",
            Self::InvalidOrdinal => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_ORDINAL",
            Self::InvalidResult => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_RESULT",
            Self::InvalidLifetime => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_LIFETIME",
            Self::InvalidRelation => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_RELATION",
            Self::InvalidTarget => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_TARGET",
            Self::InvalidEventOrder => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_INVALID_EVENT_ORDER",
            Self::DuplicateEvent => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_DUPLICATE_EVENT",
            Self::DuplicateReference => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_DUPLICATE_REFERENCE",
            Self::OverlappingAliasEvents => {
                "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_OVERLAPPING_ALIAS_EVENTS"
            }
            Self::SizeCap => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_SIZE_CAP",
            Self::ArithmeticOverflow => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_ARITHMETIC_OVERFLOW",
            Self::WrongLength => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_WRONG_LENGTH",
            Self::UnsupportedVersion => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_UNSUPPORTED_VERSION",
            Self::UnsupportedSchema => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_UNSUPPORTED_SCHEMA",
            Self::NoncanonicalReserved => {
                "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_NONCANONICAL_RESERVED"
            }
            Self::DigestMismatch => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_DIGEST_MISMATCH",
            Self::ReferenceMismatch => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_REFERENCE_MISMATCH",
            Self::TrailingData => "EVIDENTRAIL_DISPLAYED_ALIAS_MANIFEST_TRAILING_DATA",
        }
    }
}

impl fmt::Debug for DisplayedAliasManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayedAliasManifestErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for DisplayedAliasManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for DisplayedAliasManifestErrorV1 {}

/// One frozen `E<n>` mapping.
///
/// The full reference material is retained so its declared ID can be
/// independently recomputed during recovery. The alias capability itself is
/// deliberately narrowed to `Exact`, even when the historical reference also
/// carried neighborhood relations in the memory-only product.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayedAliasManifestEntryV1 {
    ordinal: u16,
    reference: EvidenceReferenceV1,
    ordered_event_ids: Vec<EventId>,
}

impl DisplayedAliasManifestEntryV1 {
    pub fn new(
        result_id: ResultId,
        ordinal: u16,
        reference: EvidenceReferenceV1,
        ordered_event_ids: impl IntoIterator<Item = EventId>,
    ) -> Result<Self, DisplayedAliasManifestErrorV1> {
        if ordinal == 0 || usize::from(ordinal) > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
            return Err(DisplayedAliasManifestErrorV1::InvalidOrdinal);
        }
        if reference.result_id() != result_id {
            return Err(DisplayedAliasManifestErrorV1::InvalidResult);
        }
        if reference
            .allowed_relations()
            .binary_search(&ExpansionRelationV1::Exact)
            .is_err()
        {
            return Err(DisplayedAliasManifestErrorV1::InvalidRelation);
        }
        let target_events = reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) => Ok(*event_id),
                EvidenceTargetRef::Block(_) => Err(DisplayedAliasManifestErrorV1::InvalidTarget),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ordered_event_ids = ordered_event_ids.into_iter().collect::<Vec<_>>();
        if ordered_event_ids.is_empty()
            || ordered_event_ids.len() > MAX_EVIDENCE_REFERENCE_TARGETS
            || ordered_event_ids.len() != target_events.len()
        {
            return Err(DisplayedAliasManifestErrorV1::InvalidEventOrder);
        }
        let targets = target_events.iter().copied().collect::<BTreeSet<_>>();
        let ordered = ordered_event_ids.iter().copied().collect::<BTreeSet<_>>();
        if targets.len() != target_events.len() || ordered.len() != ordered_event_ids.len() {
            return Err(DisplayedAliasManifestErrorV1::DuplicateEvent);
        }
        if targets != ordered {
            return Err(DisplayedAliasManifestErrorV1::InvalidEventOrder);
        }
        Ok(Self {
            ordinal,
            reference,
            ordered_event_ids,
        })
    }

    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub fn ordered_event_ids(&self) -> &[EventId] {
        &self.ordered_event_ids
    }

    #[must_use]
    pub const fn allowed_relation(&self) -> ExpansionRelationV1 {
        ExpansionRelationV1::Exact
    }

    fn encoded_len(&self) -> Result<usize, DisplayedAliasManifestErrorV1> {
        DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1
            .checked_add(
                self.reference
                    .allowed_relations()
                    .len()
                    .checked_mul(2)
                    .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?,
            )
            .and_then(|value| value.checked_add(self.reference.targets().len().checked_mul(32)?))
            .and_then(|value| value.checked_add(self.ordered_event_ids.len().checked_mul(32)?))
            .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)
    }
}

impl fmt::Debug for DisplayedAliasManifestEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayedAliasManifestEntryV1")
            .field("ordinal", &self.ordinal)
            .field("event_count", &self.ordered_event_ids.len())
            .field("allowed_relation", &ExpansionRelationV1::Exact)
            .finish_non_exhaustive()
    }
}

/// Canonical plaintext carried inside one authority-bound encrypted frame.
///
/// This value alone is not authority. It becomes restart authority only after
/// the enclosing frame, result manifest, catalog, and provider seal all
/// authenticate under the same result/source/receipt context.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayedAliasManifestV1 {
    result_id: ResultId,
    expires_at: UnixTimestampNanos,
    entries: Vec<DisplayedAliasManifestEntryV1>,
}

impl DisplayedAliasManifestV1 {
    pub fn new(
        result_id: ResultId,
        expires_at: UnixTimestampNanos,
        entries: impl IntoIterator<Item = DisplayedAliasManifestEntryV1>,
    ) -> Result<Self, DisplayedAliasManifestErrorV1> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        validate_manifest(result_id, expires_at, &entries)?;
        let manifest = Self {
            result_id,
            expires_at,
            entries,
        };
        if manifest.encoded_len()? > MAX_FRAME_PLAINTEXT_BYTES_V1 {
            return Err(DisplayedAliasManifestErrorV1::SizeCap);
        }
        Ok(manifest)
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub fn entries(&self) -> &[DisplayedAliasManifestEntryV1] {
        &self.entries
    }

    pub fn encoded_len(&self) -> Result<usize, DisplayedAliasManifestErrorV1> {
        self.entries
            .iter()
            .try_fold(DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1, |total, entry| {
                total
                    .checked_add(entry.encoded_len()?)
                    .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)
            })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_manifest(self).expect("checked displayed alias manifests remain encodable")
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, DisplayedAliasManifestErrorV1> {
        decode_manifest(encoded)
    }

    #[must_use]
    pub fn has_magic(encoded: &[u8]) -> bool {
        encoded.get(..MAGIC_V1.len()) == Some(MAGIC_V1.as_slice())
    }
}

impl fmt::Debug for DisplayedAliasManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayedAliasManifestV1")
            .field("alias_count", &self.entries.len())
            .field("expiry_present", &true)
            .finish_non_exhaustive()
    }
}

fn validate_manifest(
    result_id: ResultId,
    expires_at: UnixTimestampNanos,
    entries: &[DisplayedAliasManifestEntryV1],
) -> Result<(), DisplayedAliasManifestErrorV1> {
    if entries.len() > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
        return Err(DisplayedAliasManifestErrorV1::TooManyAliases);
    }
    let mut reference_ids = BTreeSet::new();
    let mut displayed_events = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let expected_ordinal =
            u16::try_from(index + 1).map_err(|_| DisplayedAliasManifestErrorV1::TooManyAliases)?;
        if entry.ordinal != expected_ordinal {
            return Err(DisplayedAliasManifestErrorV1::InvalidOrdinal);
        }
        if entry.reference.result_id() != result_id {
            return Err(DisplayedAliasManifestErrorV1::InvalidResult);
        }
        if !reference_ids.insert(entry.reference.id()) {
            return Err(DisplayedAliasManifestErrorV1::DuplicateReference);
        }
        if entry
            .ordered_event_ids
            .iter()
            .any(|event_id| !displayed_events.insert(*event_id))
        {
            return Err(DisplayedAliasManifestErrorV1::OverlappingAliasEvents);
        }
        if entry.reference.expires_at() != expires_at || entry.reference.issued_at() >= expires_at {
            return Err(DisplayedAliasManifestErrorV1::InvalidLifetime);
        }
        DisplayedAliasManifestEntryV1::new(
            result_id,
            entry.ordinal,
            entry.reference.clone(),
            entry.ordered_event_ids.iter().copied(),
        )?;
    }
    Ok(())
}

fn encode_manifest(
    manifest: &DisplayedAliasManifestV1,
) -> Result<Vec<u8>, DisplayedAliasManifestErrorV1> {
    validate_manifest(manifest.result_id, manifest.expires_at, &manifest.entries)?;
    let total_len = manifest.encoded_len()?;
    if total_len > MAX_FRAME_PLAINTEXT_BYTES_V1 {
        return Err(DisplayedAliasManifestErrorV1::SizeCap);
    }
    let body_len = total_len
        .checked_sub(DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1)
        .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?;
    let mut body = Vec::with_capacity(body_len);
    for entry in &manifest.entries {
        encode_entry(entry, &mut body)?;
    }
    let digest = derive_digest(manifest.result_id, manifest.expires_at, &body);
    let mut encoded = vec![0u8; DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1];
    encoded[0..8].copy_from_slice(&MAGIC_V1);
    encoded[8..10].copy_from_slice(&DISPLAYED_ALIAS_MANIFEST_VERSION_V1.to_be_bytes());
    encoded[10..12].copy_from_slice(&DISPLAYED_ALIAS_MANIFEST_SCHEMA_V1.to_be_bytes());
    encoded[12..14].copy_from_slice(&EXACT_RELATION_CODE_V1.to_be_bytes());
    encoded[16..48].copy_from_slice(manifest.result_id.as_bytes());
    encoded[48..64].copy_from_slice(&manifest.expires_at.get().to_be_bytes());
    encoded[64..68].copy_from_slice(
        &u32::try_from(manifest.entries.len())
            .map_err(|_| DisplayedAliasManifestErrorV1::TooManyAliases)?
            .to_be_bytes(),
    );
    encoded[68..72].copy_from_slice(
        &u32::try_from(body_len)
            .map_err(|_| DisplayedAliasManifestErrorV1::SizeCap)?
            .to_be_bytes(),
    );
    encoded[72..104].copy_from_slice(&digest);
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

fn encode_entry(
    entry: &DisplayedAliasManifestEntryV1,
    output: &mut Vec<u8>,
) -> Result<(), DisplayedAliasManifestErrorV1> {
    let entry_len = entry.encoded_len()?;
    let start = output.len();
    output.resize(
        start
            .checked_add(entry_len)
            .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?,
        0,
    );
    let encoded = &mut output[start..];
    encoded[0..4].copy_from_slice(
        &u32::try_from(entry_len)
            .map_err(|_| DisplayedAliasManifestErrorV1::SizeCap)?
            .to_be_bytes(),
    );
    encoded[4..6].copy_from_slice(&entry.ordinal.to_be_bytes());
    encoded[6..8].copy_from_slice(&EXACT_RELATION_CODE_V1.to_be_bytes());
    encoded[8..40].copy_from_slice(entry.reference.id().as_bytes());
    encoded[40..56].copy_from_slice(&entry.reference.issued_at().get().to_be_bytes());
    encoded[56..72].copy_from_slice(&entry.reference.expires_at().get().to_be_bytes());
    encoded[72..74].copy_from_slice(
        &u16::try_from(entry.reference.targets().len())
            .map_err(|_| DisplayedAliasManifestErrorV1::InvalidTarget)?
            .to_be_bytes(),
    );
    encoded[74..76].copy_from_slice(
        &u16::try_from(entry.reference.allowed_relations().len())
            .map_err(|_| DisplayedAliasManifestErrorV1::InvalidRelation)?
            .to_be_bytes(),
    );
    encoded[76..78].copy_from_slice(
        &u16::try_from(entry.ordered_event_ids.len())
            .map_err(|_| DisplayedAliasManifestErrorV1::InvalidEventOrder)?
            .to_be_bytes(),
    );
    let mut cursor = DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1;
    for relation in entry.reference.allowed_relations() {
        encoded[cursor..cursor + 2].copy_from_slice(&relation_code(*relation).to_be_bytes());
        cursor += 2;
    }
    for target in entry.reference.targets() {
        let EvidenceTargetRef::Event(event_id) = target else {
            return Err(DisplayedAliasManifestErrorV1::InvalidTarget);
        };
        encoded[cursor..cursor + 32].copy_from_slice(event_id.as_bytes());
        cursor += 32;
    }
    for event_id in &entry.ordered_event_ids {
        encoded[cursor..cursor + 32].copy_from_slice(event_id.as_bytes());
        cursor += 32;
    }
    if cursor != entry_len {
        return Err(DisplayedAliasManifestErrorV1::ArithmeticOverflow);
    }
    Ok(())
}

fn decode_manifest(
    encoded: &[u8],
) -> Result<DisplayedAliasManifestV1, DisplayedAliasManifestErrorV1> {
    if encoded.len() < DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1
        || encoded.len() > MAX_FRAME_PLAINTEXT_BYTES_V1
    {
        return Err(DisplayedAliasManifestErrorV1::WrongLength);
    }
    if encoded[0..8] != MAGIC_V1 {
        return Err(DisplayedAliasManifestErrorV1::WrongLength);
    }
    if read_u16(encoded, 8)? != DISPLAYED_ALIAS_MANIFEST_VERSION_V1 {
        return Err(DisplayedAliasManifestErrorV1::UnsupportedVersion);
    }
    if read_u16(encoded, 10)? != DISPLAYED_ALIAS_MANIFEST_SCHEMA_V1 {
        return Err(DisplayedAliasManifestErrorV1::UnsupportedSchema);
    }
    if read_u16(encoded, 12)? != EXACT_RELATION_CODE_V1 {
        return Err(DisplayedAliasManifestErrorV1::InvalidRelation);
    }
    if encoded[14..16].iter().any(|byte| *byte != 0)
        || encoded[104..112].iter().any(|byte| *byte != 0)
    {
        return Err(DisplayedAliasManifestErrorV1::NoncanonicalReserved);
    }
    let result_id = ResultId::from_bytes(read_array::<32>(encoded, 16)?);
    let expires_at = UnixTimestampNanos::new(i128::from_be_bytes(read_array::<16>(encoded, 48)?));
    let entry_count = usize::try_from(read_u32(encoded, 64)?)
        .map_err(|_| DisplayedAliasManifestErrorV1::TooManyAliases)?;
    if entry_count > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
        return Err(DisplayedAliasManifestErrorV1::TooManyAliases);
    }
    let body_len = usize::try_from(read_u32(encoded, 68)?)
        .map_err(|_| DisplayedAliasManifestErrorV1::SizeCap)?;
    let expected_len = DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1
        .checked_add(body_len)
        .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?;
    if expected_len != encoded.len() {
        return Err(if expected_len < encoded.len() {
            DisplayedAliasManifestErrorV1::TrailingData
        } else {
            DisplayedAliasManifestErrorV1::WrongLength
        });
    }
    let body = &encoded[DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1..];
    if derive_digest(result_id, expires_at, body) != read_array::<32>(encoded, 72)? {
        return Err(DisplayedAliasManifestErrorV1::DigestMismatch);
    }
    let mut entries = Vec::with_capacity(entry_count);
    let mut cursor = 0usize;
    for index in 0..entry_count {
        let (entry, consumed) = decode_entry(result_id, &body[cursor..], index + 1)?;
        cursor = cursor
            .checked_add(consumed)
            .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?;
        entries.push(entry);
    }
    if cursor != body.len() {
        return Err(DisplayedAliasManifestErrorV1::TrailingData);
    }
    DisplayedAliasManifestV1::new(result_id, expires_at, entries)
}

fn decode_entry(
    result_id: ResultId,
    encoded: &[u8],
    expected_ordinal: usize,
) -> Result<(DisplayedAliasManifestEntryV1, usize), DisplayedAliasManifestErrorV1> {
    if encoded.len() < DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1 {
        return Err(DisplayedAliasManifestErrorV1::WrongLength);
    }
    let entry_len = usize::try_from(read_u32(encoded, 0)?)
        .map_err(|_| DisplayedAliasManifestErrorV1::SizeCap)?;
    if entry_len < DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1 || entry_len > encoded.len() {
        return Err(DisplayedAliasManifestErrorV1::WrongLength);
    }
    let encoded = &encoded[..entry_len];
    let ordinal = read_u16(encoded, 4)?;
    if usize::from(ordinal) != expected_ordinal {
        return Err(DisplayedAliasManifestErrorV1::InvalidOrdinal);
    }
    if read_u16(encoded, 6)? != EXACT_RELATION_CODE_V1 {
        return Err(DisplayedAliasManifestErrorV1::InvalidRelation);
    }
    if encoded[78..80].iter().any(|byte| *byte != 0) {
        return Err(DisplayedAliasManifestErrorV1::NoncanonicalReserved);
    }
    let declared_id = EvidenceReferenceId::from_bytes(read_array::<32>(encoded, 8)?);
    let issued_at = UnixTimestampNanos::new(i128::from_be_bytes(read_array::<16>(encoded, 40)?));
    let expires_at = UnixTimestampNanos::new(i128::from_be_bytes(read_array::<16>(encoded, 56)?));
    let target_count = usize::from(read_u16(encoded, 72)?);
    let relation_count = usize::from(read_u16(encoded, 74)?);
    let ordered_count = usize::from(read_u16(encoded, 76)?);
    if target_count == 0
        || target_count > MAX_EVIDENCE_REFERENCE_TARGETS
        || ordered_count != target_count
        || relation_count == 0
        || relation_count > 6
    {
        return Err(DisplayedAliasManifestErrorV1::InvalidTarget);
    }
    let expected_entry_len = DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1
        .checked_add(
            relation_count
                .checked_mul(2)
                .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(target_count.checked_mul(32)?))
        .and_then(|value| value.checked_add(ordered_count.checked_mul(32)?))
        .ok_or(DisplayedAliasManifestErrorV1::ArithmeticOverflow)?;
    if expected_entry_len != entry_len {
        return Err(DisplayedAliasManifestErrorV1::WrongLength);
    }
    let mut cursor = DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1;
    let mut relations = Vec::with_capacity(relation_count);
    for _ in 0..relation_count {
        relations.push(relation_from_code(read_u16(encoded, cursor)?)?);
        cursor += 2;
    }
    let mut targets = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        targets.push(EvidenceTargetRef::Event(EventId::from_bytes(read_array::<
            32,
        >(
            encoded, cursor,
        )?)));
        cursor += 32;
    }
    let mut ordered = Vec::with_capacity(ordered_count);
    for _ in 0..ordered_count {
        ordered.push(EventId::from_bytes(read_array::<32>(encoded, cursor)?));
        cursor += 32;
    }
    let reference = EvidenceReferenceV1::verify_declared(
        declared_id,
        result_id,
        targets,
        relations,
        issued_at,
        expires_at,
    )
    .map_err(|_| DisplayedAliasManifestErrorV1::ReferenceMismatch)?;
    let entry = DisplayedAliasManifestEntryV1::new(result_id, ordinal, reference, ordered)?;
    Ok((entry, entry_len))
}

fn derive_digest(result_id: ResultId, expires_at: UnixTimestampNanos, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_digest_field(&mut hasher, DIGEST_DOMAIN_V1);
    update_digest_field(
        &mut hasher,
        &DISPLAYED_ALIAS_MANIFEST_VERSION_V1.to_be_bytes(),
    );
    update_digest_field(&mut hasher, result_id.as_bytes());
    update_digest_field(&mut hasher, &expires_at.get().to_be_bytes());
    update_digest_field(&mut hasher, body);
    hasher.finalize().into()
}

fn update_digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

const fn relation_code(relation: ExpansionRelationV1) -> u16 {
    match relation {
        ExpansionRelationV1::Exact => 1,
        ExpansionRelationV1::SameLaneBeforeAfter => 2,
        ExpansionRelationV1::GlobalBeforeAfter => 3,
        ExpansionRelationV1::PatternMembers => 4,
        ExpansionRelationV1::SameAttestedTrace => 5,
        ExpansionRelationV1::AroundOnset => 6,
    }
}

fn relation_from_code(code: u16) -> Result<ExpansionRelationV1, DisplayedAliasManifestErrorV1> {
    match code {
        1 => Ok(ExpansionRelationV1::Exact),
        2 => Ok(ExpansionRelationV1::SameLaneBeforeAfter),
        3 => Ok(ExpansionRelationV1::GlobalBeforeAfter),
        4 => Ok(ExpansionRelationV1::PatternMembers),
        5 => Ok(ExpansionRelationV1::SameAttestedTrace),
        6 => Ok(ExpansionRelationV1::AroundOnset),
        _ => Err(DisplayedAliasManifestErrorV1::InvalidRelation),
    }
}

fn read_u16(encoded: &[u8], offset: usize) -> Result<u16, DisplayedAliasManifestErrorV1> {
    Ok(u16::from_be_bytes(read_array(encoded, offset)?))
}

fn read_u32(encoded: &[u8], offset: usize) -> Result<u32, DisplayedAliasManifestErrorV1> {
    Ok(u32::from_be_bytes(read_array(encoded, offset)?))
}

fn read_array<const N: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; N], DisplayedAliasManifestErrorV1> {
    encoded
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DisplayedAliasManifestErrorV1::WrongLength)
}
