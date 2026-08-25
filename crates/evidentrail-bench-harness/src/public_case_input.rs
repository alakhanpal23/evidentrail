use std::fmt;

use evidentrail_bench::{EvidentrailBenchCaseSpecV1, EvidentrailBenchRunManifestV1};
use evidentrail_core::{EventLedger, LaneKey};
use evidentrail_schema::{AcquisitionReceiptId, ArtifactDigest, EventId, SourceRecordId};
use sha2::{Digest as _, Sha256};

use crate::{
    HarnessError, MAX_HARNESS_STREAM_BYTES_V1, StdinArtifactV1, artifact_digest_for_bytes_v1,
};

const PUBLIC_CASE_ARTIFACT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/public-case-artifact/v1";
const PUBLIC_RUN_MANIFEST_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/public-run-manifest-artifact/v1";
const SOURCE_RECORD_MAP_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/public-source-record-event-map/v1";
const LEGACY_DRAIN_RETAINED_MAP_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-retained-record-map/v1";

/// Version of the canonical public-case artifact byte encoding.
pub const CANONICAL_PUBLIC_CASE_ARTIFACT_CONTRACT_VERSION_V1: u64 = 1;
/// Version of the canonical public run-manifest artifact byte encoding.
pub const CANONICAL_PUBLIC_RUN_MANIFEST_ARTIFACT_CONTRACT_VERSION_V1: u64 = 1;
/// Hard bound on exact source records admitted by one public stdin artifact.
pub const MAX_CANONICAL_PUBLIC_SOURCE_RECORDS_V1: u64 = 1_048_576;

/// Exact canonical bytes for one label-free public run manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPublicRunManifestArtifactV1 {
    bytes: Box<[u8]>,
    artifact_digest: ArtifactDigest,
}

impl CanonicalPublicRunManifestArtifactV1 {
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for CanonicalPublicRunManifestArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPublicRunManifestArtifactV1")
            .field(
                "contract_version",
                &CANONICAL_PUBLIC_RUN_MANIFEST_ARTIFACT_CONTRACT_VERSION_V1,
            )
            .field("byte_count", &self.bytes.len())
            .field("artifact_identity_present", &true)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// Deterministically encode every public run-manifest field using u64
/// little-endian length framing. Hidden annotation bindings and scores have no
/// representation in the input type or this artifact.
pub fn canonical_public_run_manifest_artifact_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
) -> Result<CanonicalPublicRunManifestArtifactV1, HarnessError> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, PUBLIC_RUN_MANIFEST_ARTIFACT_DOMAIN_V1)?;
    append_u64(
        &mut bytes,
        CANONICAL_PUBLIC_RUN_MANIFEST_ARTIFACT_CONTRACT_VERSION_V1,
    )?;
    let identity = run_manifest.identity();
    for digest in [
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        identity.dataset_artifact_digest(),
    ] {
        append_field(&mut bytes, digest.as_bytes())?;
    }
    append_u64(&mut bytes, identity.seed())?;
    let budget = identity.budget();
    for value in [
        budget.unique_candidate_event_count(),
        budget.unique_candidate_source_bytes(),
        budget.canonical_candidate_tokens(),
        budget.wall_time_nanos(),
        budget.peak_memory_bytes(),
    ] {
        append_u64(&mut bytes, value)?;
    }
    append_digest_collection(&mut bytes, run_manifest.public_case_artifact_digests())?;
    if checked_len(bytes.len())? > MAX_HARNESS_STREAM_BYTES_V1 {
        return Err(HarnessError::CanonicalPublicRunManifestArtifactTooLarge);
    }
    let artifact_digest = artifact_digest_for_bytes_v1(&bytes);
    Ok(CanonicalPublicRunManifestArtifactV1 {
        bytes: bytes.into_boxed_slice(),
        artifact_digest,
    })
}

/// Exact canonical bytes for one label-free public case specification.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPublicCaseArtifactV1 {
    bytes: Box<[u8]>,
    artifact_digest: ArtifactDigest,
}

impl CanonicalPublicCaseArtifactV1 {
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for CanonicalPublicCaseArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPublicCaseArtifactV1")
            .field(
                "contract_version",
                &CANONICAL_PUBLIC_CASE_ARTIFACT_CONTRACT_VERSION_V1,
            )
            .field("byte_count", &self.bytes.len())
            .field("artifact_identity_present", &true)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// Deterministically encode every public case field using u64 little-endian
/// length framing. The public case type has no annotation linkage or labels.
pub fn canonical_public_case_artifact_v1(
    public_case: &EvidentrailBenchCaseSpecV1,
) -> Result<CanonicalPublicCaseArtifactV1, HarnessError> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, PUBLIC_CASE_ARTIFACT_DOMAIN_V1)?;
    append_u64(
        &mut bytes,
        CANONICAL_PUBLIC_CASE_ARTIFACT_CONTRACT_VERSION_V1,
    )?;
    append_digest_collection(&mut bytes, public_case.source_artifact_digests())?;
    append_field(&mut bytes, public_case.question_digest().as_bytes())?;
    append_field(&mut bytes, public_case.plan_digest().as_bytes())?;
    append_digest_collection(&mut bytes, public_case.split_artifact_digests())?;
    append_digest_collection(&mut bytes, public_case.leakage_artifact_digests())?;
    append_u64(&mut bytes, checked_len(public_case.budget_points().len())?)?;
    for budget in public_case.budget_points() {
        for value in [
            budget.unique_candidate_event_count(),
            budget.unique_candidate_source_bytes(),
            budget.canonical_candidate_tokens(),
            budget.wall_time_nanos(),
            budget.peak_memory_bytes(),
        ] {
            append_u64(&mut bytes, value)?;
        }
    }
    append_field(
        &mut bytes,
        public_case.expected_acquisition_class().code().as_bytes(),
    )?;
    if checked_len(bytes.len())? > MAX_HARNESS_STREAM_BYTES_V1 {
        return Err(HarnessError::CanonicalPublicCaseArtifactTooLarge);
    }
    let artifact_digest = artifact_digest_for_bytes_v1(&bytes);
    Ok(CanonicalPublicCaseArtifactV1 {
        bytes: bytes.into_boxed_slice(),
        artifact_digest,
    })
}

/// One exact source occurrence joined bijectively to one source-exact event.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CanonicalPublicSourceRecordV1 {
    source_record_ordinal: u64,
    source_byte_start: u64,
    payload_byte_end: u64,
    source_byte_end: u64,
    exact_record_artifact_digest: ArtifactDigest,
    event_id: EventId,
    source_record_id: SourceRecordId,
}

impl CanonicalPublicSourceRecordV1 {
    #[must_use]
    pub const fn source_record_ordinal(self) -> u64 {
        self.source_record_ordinal
    }

    #[must_use]
    pub const fn source_byte_start(self) -> u64 {
        self.source_byte_start
    }

    #[must_use]
    pub const fn payload_byte_end(self) -> u64 {
        self.payload_byte_end
    }

    #[must_use]
    pub const fn source_byte_end(self) -> u64 {
        self.source_byte_end
    }

    #[must_use]
    pub const fn exact_record_artifact_digest(self) -> ArtifactDigest {
        self.exact_record_artifact_digest
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn source_record_id(self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn terminator_byte_count(self) -> u64 {
        self.source_byte_end - self.payload_byte_end
    }
}

impl fmt::Debug for CanonicalPublicSourceRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPublicSourceRecordV1")
            .field("source_record_ordinal", &self.source_record_ordinal)
            .field("source_byte_start", &self.source_byte_start)
            .field("payload_byte_end", &self.payload_byte_end)
            .field("source_byte_end", &self.source_byte_end)
            .field("terminator_byte_count", &self.terminator_byte_count())
            .field("record_artifact_identity_present", &true)
            .field("event_identity_present", &true)
            .field("source_record_identity_present", &true)
            .finish()
    }
}

/// Canonical LF/CRLF/final-record framing joined to a sealed public ledger.
///
/// Every stdin byte belongs to exactly one record and every record must match
/// exactly one complete, source-exact ledger event in persisted order. Blank
/// records and duplicate payload occurrences remain distinct entries.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPublicSourceRecordMapV1 {
    stdin_artifact_digest: ArtifactDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    map_artifact_digest: ArtifactDigest,
    records: Vec<CanonicalPublicSourceRecordV1>,
}

impl CanonicalPublicSourceRecordMapV1 {
    pub(crate) fn try_new(
        stdin: &StdinArtifactV1,
        ledger: &EventLedger,
    ) -> Result<Self, HarnessError> {
        let stdin_byte_count = checked_len(stdin.bytes().len())?;
        if stdin_byte_count > MAX_HARNESS_STREAM_BYTES_V1 {
            return Err(HarnessError::StdinByteCapExceeded);
        }
        let ranges = frame_source_records(stdin.bytes())?;
        if ranges.len() != ledger.events().len() {
            return Err(HarnessError::SourceRecordLedgerCountMismatch);
        }
        let receipt_entries = ledger.acquisition_receipt().entries();
        if receipt_entries.len() != ranges.len() {
            return Err(HarnessError::SourceRecordAcquisitionReceiptMismatch);
        }

        let mut records = Vec::with_capacity(ranges.len());
        let mut next_lane_sequences: Vec<(LaneKey, u64)> = Vec::new();
        for (ordinal, (((start, payload_end, end), event), receipt_entry)) in ranges
            .into_iter()
            .zip(ledger.events())
            .zip(receipt_entries)
            .enumerate()
        {
            if !event.exactness_basis().is_source_exact() {
                return Err(HarnessError::SourceRecordLedgerNotSourceExact);
            }
            if !event.record_state().is_complete() {
                return Err(HarnessError::SourceRecordLedgerFragment);
            }
            let ordinal = checked_len(ordinal)?;
            let start_u64 = checked_len(start)?;
            let payload_end_u64 = checked_len(payload_end)?;
            let end_u64 = checked_len(end)?;
            let exact = &stdin.bytes()[start..end];
            let payload = &stdin.bytes()[start..payload_end];
            let terminator = &stdin.bytes()[payload_end..end];
            if event.ordinal() != ordinal
                || event.raw() != exact
                || event.payload() != payload
                || event.terminator() != Some(terminator)
            {
                return Err(HarnessError::SourceRecordLedgerEventMismatch);
            }
            if receipt_entry.source_record_id() != event.source_record_id()
                || receipt_entry.outcome().persisted_event_id() != Some(event.id())
                || receipt_entry.outcome().exactness_basis() != Some(event.exactness_basis())
            {
                return Err(HarnessError::SourceRecordAcquisitionReceiptMismatch);
            }
            if let Some((_, next_sequence)) = next_lane_sequences
                .iter_mut()
                .find(|(lane, _)| lane == event.lane())
            {
                if event.lane_sequence().get() != *next_sequence {
                    return Err(HarnessError::SourceRecordLedgerLaneMismatch);
                }
                *next_sequence = next_sequence
                    .checked_add(1)
                    .ok_or(HarnessError::SourceRecordLedgerLaneMismatch)?;
            } else {
                if event.lane_sequence().get() != 0 {
                    return Err(HarnessError::SourceRecordLedgerLaneMismatch);
                }
                next_lane_sequences.push((event.lane().clone(), 1_u64));
            }
            records.push(CanonicalPublicSourceRecordV1 {
                source_record_ordinal: ordinal,
                source_byte_start: start_u64,
                payload_byte_end: payload_end_u64,
                source_byte_end: end_u64,
                exact_record_artifact_digest: artifact_digest_for_bytes_v1(exact),
                event_id: event.id(),
                source_record_id: event.source_record_id(),
            });
        }
        let acquisition_receipt_id = ledger.acquisition_receipt_id();
        let map_artifact_digest = derive_source_record_map_digest(
            stdin.artifact_digest(),
            acquisition_receipt_id,
            &records,
        )?;
        Ok(Self {
            stdin_artifact_digest: stdin.artifact_digest(),
            acquisition_receipt_id,
            map_artifact_digest,
            records,
        })
    }

    #[must_use]
    pub const fn stdin_artifact_digest(&self) -> ArtifactDigest {
        self.stdin_artifact_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(&self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn map_artifact_digest(&self) -> ArtifactDigest {
        self.map_artifact_digest
    }

    #[must_use]
    pub fn records(&self) -> &[CanonicalPublicSourceRecordV1] {
        &self.records
    }

    #[must_use]
    pub fn exact_record_bytes<'a>(
        &self,
        stdin: &'a StdinArtifactV1,
        source_record_ordinal: u64,
    ) -> Option<&'a [u8]> {
        if stdin.artifact_digest() != self.stdin_artifact_digest {
            return None;
        }
        let position = usize::try_from(source_record_ordinal).ok()?;
        let record = self.records.get(position)?;
        let start = usize::try_from(record.source_byte_start).ok()?;
        let end = usize::try_from(record.source_byte_end).ok()?;
        stdin.bytes().get(start..end)
    }

    #[must_use]
    pub fn payload_bytes<'a>(
        &self,
        stdin: &'a StdinArtifactV1,
        source_record_ordinal: u64,
    ) -> Option<&'a [u8]> {
        if stdin.artifact_digest() != self.stdin_artifact_digest {
            return None;
        }
        let position = usize::try_from(source_record_ordinal).ok()?;
        let record = self.records.get(position)?;
        let start = usize::try_from(record.source_byte_start).ok()?;
        let end = usize::try_from(record.payload_byte_end).ok()?;
        stdin.bytes().get(start..end)
    }

    pub fn legacy_drain_retained_records(
        &self,
        stdin: &StdinArtifactV1,
    ) -> Result<LegacyDrainRetainedRecordMapV1, HarnessError> {
        if stdin.artifact_digest() != self.stdin_artifact_digest
            || std::str::from_utf8(stdin.bytes()).is_err()
        {
            return Err(HarnessError::SourceRecordMapInputMismatch);
        }
        let mut retained = Vec::new();
        for record in &self.records {
            let start = usize::try_from(record.source_byte_start)
                .map_err(|_| HarnessError::SourceRecordMapOverflow)?;
            let payload_end = usize::try_from(record.payload_byte_end)
                .map_err(|_| HarnessError::SourceRecordMapOverflow)?;
            let payload = stdin
                .bytes()
                .get(start..payload_end)
                .ok_or(HarnessError::SourceRecordMapInputMismatch)?;
            let text = std::str::from_utf8(payload)
                .map_err(|_| HarnessError::SourceRecordMapInputMismatch)?;
            if text.trim().is_empty() {
                continue;
            }
            retained.push(LegacyDrainRetainedSourceRecordV1 {
                retained_index: checked_len(retained.len())?,
                source_record_ordinal: record.source_record_ordinal,
                event_id: record.event_id,
                exact_record_artifact_digest: record.exact_record_artifact_digest,
            });
        }
        let map_artifact_digest = derive_retained_map_digest(self.map_artifact_digest, &retained)?;
        Ok(LegacyDrainRetainedRecordMapV1 {
            source_record_map_artifact_digest: self.map_artifact_digest,
            map_artifact_digest,
            records: retained,
        })
    }
}

impl fmt::Debug for CanonicalPublicSourceRecordMapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPublicSourceRecordMapV1")
            .field("stdin_artifact_binding_present", &true)
            .field("acquisition_receipt_binding_present", &true)
            .field("map_artifact_binding_present", &true)
            .field("record_count", &self.records.len())
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// One retained nonblank CLI occurrence joined to its exact source event.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainRetainedSourceRecordV1 {
    retained_index: u64,
    source_record_ordinal: u64,
    event_id: EventId,
    exact_record_artifact_digest: ArtifactDigest,
}

impl LegacyDrainRetainedSourceRecordV1 {
    #[must_use]
    pub const fn retained_index(self) -> u64 {
        self.retained_index
    }

    #[must_use]
    pub const fn source_record_ordinal(self) -> u64 {
        self.source_record_ordinal
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exact_record_artifact_digest(self) -> ArtifactDigest {
        self.exact_record_artifact_digest
    }
}

impl fmt::Debug for LegacyDrainRetainedSourceRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainRetainedSourceRecordV1")
            .field("retained_index", &self.retained_index)
            .field("source_record_ordinal", &self.source_record_ordinal)
            .field("event_identity_present", &true)
            .field("record_artifact_identity_present", &true)
            .finish()
    }
}

/// Occurrence-aware nonblank-line mapping for the pinned raw-text CLI path.
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyDrainRetainedRecordMapV1 {
    source_record_map_artifact_digest: ArtifactDigest,
    map_artifact_digest: ArtifactDigest,
    records: Vec<LegacyDrainRetainedSourceRecordV1>,
}

impl LegacyDrainRetainedRecordMapV1 {
    #[must_use]
    pub const fn source_record_map_artifact_digest(&self) -> ArtifactDigest {
        self.source_record_map_artifact_digest
    }

    #[must_use]
    pub const fn map_artifact_digest(&self) -> ArtifactDigest {
        self.map_artifact_digest
    }

    #[must_use]
    pub fn records(&self) -> &[LegacyDrainRetainedSourceRecordV1] {
        &self.records
    }

    #[must_use]
    pub fn record_for_retained_index(
        &self,
        retained_index: u64,
    ) -> Option<LegacyDrainRetainedSourceRecordV1> {
        let position = usize::try_from(retained_index).ok()?;
        self.records
            .get(position)
            .copied()
            .filter(|record| record.retained_index == retained_index)
    }
}

impl fmt::Debug for LegacyDrainRetainedRecordMapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainRetainedRecordMapV1")
            .field("source_record_map_binding_present", &true)
            .field("map_artifact_binding_present", &true)
            .field("retained_record_count", &self.records.len())
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

fn frame_source_records(bytes: &[u8]) -> Result<Vec<(usize, usize, usize)>, HarnessError> {
    let mut records = Vec::new();
    let mut start = 0_usize;
    for (position, byte) in bytes.iter().copied().enumerate() {
        if byte != b'\n' {
            continue;
        }
        if checked_len(records.len())? >= MAX_CANONICAL_PUBLIC_SOURCE_RECORDS_V1 {
            return Err(HarnessError::SourceRecordCountExceedsHardBound);
        }
        let payload_end = if position > start && bytes[position - 1] == b'\r' {
            position - 1
        } else {
            position
        };
        records.push((start, payload_end, position + 1));
        start = position + 1;
    }
    if start < bytes.len() {
        if checked_len(records.len())? >= MAX_CANONICAL_PUBLIC_SOURCE_RECORDS_V1 {
            return Err(HarnessError::SourceRecordCountExceedsHardBound);
        }
        records.push((start, bytes.len(), bytes.len()));
    }
    Ok(records)
}

fn derive_source_record_map_digest(
    stdin_artifact_digest: ArtifactDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    records: &[CanonicalPublicSourceRecordV1],
) -> Result<ArtifactDigest, HarnessError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, SOURCE_RECORD_MAP_DOMAIN_V1)?;
    hash_field(&mut hasher, stdin_artifact_digest.as_bytes())?;
    hash_field(&mut hasher, acquisition_receipt_id.as_bytes())?;
    hash_u64(&mut hasher, checked_len(records.len())?)?;
    for record in records {
        for value in [
            record.source_record_ordinal,
            record.source_byte_start,
            record.payload_byte_end,
            record.source_byte_end,
        ] {
            hash_u64(&mut hasher, value)?;
        }
        for value in [
            record.exact_record_artifact_digest.as_bytes(),
            record.event_id.as_bytes(),
            record.source_record_id.as_bytes(),
        ] {
            hash_field(&mut hasher, value)?;
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_retained_map_digest(
    source_record_map_artifact_digest: ArtifactDigest,
    records: &[LegacyDrainRetainedSourceRecordV1],
) -> Result<ArtifactDigest, HarnessError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, LEGACY_DRAIN_RETAINED_MAP_DOMAIN_V1)?;
    hash_field(&mut hasher, source_record_map_artifact_digest.as_bytes())?;
    hash_u64(&mut hasher, checked_len(records.len())?)?;
    for record in records {
        hash_u64(&mut hasher, record.retained_index)?;
        hash_u64(&mut hasher, record.source_record_ordinal)?;
        hash_field(&mut hasher, record.event_id.as_bytes())?;
        hash_field(&mut hasher, record.exact_record_artifact_digest.as_bytes())?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn append_digest_collection(
    destination: &mut Vec<u8>,
    digests: &[ArtifactDigest],
) -> Result<(), HarnessError> {
    append_u64(destination, checked_len(digests.len())?)?;
    for digest in digests {
        append_field(destination, digest.as_bytes())?;
    }
    Ok(())
}

fn append_u64(destination: &mut Vec<u8>, value: u64) -> Result<(), HarnessError> {
    append_field(destination, &value.to_le_bytes())
}

fn append_field(destination: &mut Vec<u8>, value: &[u8]) -> Result<(), HarnessError> {
    destination.extend_from_slice(&checked_len(value.len())?.to_le_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

fn hash_u64(hasher: &mut Sha256, value: u64) -> Result<(), HarnessError> {
    hash_field(hasher, &value.to_le_bytes())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), HarnessError> {
    hasher.update(checked_len(value.len())?.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn checked_len(value: usize) -> Result<u64, HarnessError> {
    u64::try_from(value).map_err(|_| HarnessError::SourceRecordMapOverflow)
}
