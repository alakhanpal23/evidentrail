//! Native encrypted immutable-page repository for retained V3 events.
//!
//! This module deliberately does not call `DurableResultRepositoryV2`. It
//! reuses only the external key authority and audited XChaCha frame primitive.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use evidentrail_schema::{EventId, ResultId};
use evidentrail_snapshot_format::{
    FrameCommitmentV1, FrameHeaderV2, LifecycleDigestV1, OperationIdV1, SealCommitmentsV1,
    SealedFrameV2, SegmentHeaderV2, SnapshotObjectKindV2, derive_lifecycle_digest_v1,
    open_frame_v2_with_additional_aad, seal_frame_v2_with_additional_aad,
};
use rustix::fs::{self as rfs, RenameFlags};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::retained_v3::{
    RetainedAcquisitionFinishV3, RetainedEventInputV3, RetainedEventLocatorV3,
    RetainedEventStoreErrorV3, RetainedEventStoreStateV3, RetainedEventStoreV3,
    RetainedEventViewV3, RetainedPublishedAliasV3, RetainedStoreBeginV3, RetainedStoreManifestV3,
    make_manifest_v3, validate_lane_order_v3,
};
use crate::{KeyAuthorityErrorV2, KeyAuthorityV2};
use crate::{
    MAX_EVENTS_PER_PAGE_V3, MAX_STREAM_RECORDS_V3, MAX_STREAM_SOURCE_BYTES_V3,
    TARGET_PAGE_PLAINTEXT_BYTES_V3,
};

const PAGE_MAGIC_V3: [u8; 8] = *b"EVRPAG04";
const INDEX_MAGIC_V3: [u8; 8] = *b"EVRIDX04";
const CHECKPOINT_MAGIC_V3: [u8; 8] = *b"EVRCHK03";
const ALIAS_MAGIC_V3: [u8; 8] = *b"EVRALS03";
const DESCRIPTOR_MAGIC_V3: [u8; 8] = *b"EVRRPV03";
const MANIFEST_MAGIC_V3: [u8; 8] = *b"EVRMAN03";
const FORMAT_VERSION_V3: u16 = 3;
const PACK_LAYOUT_VERSION_V3: u16 = 4;
const PACK_MAGIC_V3: [u8; 8] = *b"EVRPKP04";
const PACK_DIRECTORY_MAGIC_V3: [u8; 8] = *b"EVRPKD04";
const PACK_FOOTER_MAGIC_V3: [u8; 8] = *b"EVRPKF04";
const PACK_HEADER_BYTES_V3: usize = 224;
const PACK_FOOTER_BYTES_V3: usize = 64;
const PACK_DIRECTORY_HEADER_BYTES_V3: usize = 32;
const PACK_DIRECTORY_ENTRY_BYTES_V3: usize = 88;
const MAX_PACK_FRAMES_V3: usize = 4_095;
const ACQUISITION_PACK_RECORDS_V3: usize = 65_536;
const ACQUISITION_PACK_PLAINTEXT_BYTES_V3: usize = 16 * 1024 * 1024;
const INDEX_PACK_PLAINTEXT_BYTES_V3: usize = 16 * 1024 * 1024;

pub const DURABLE_PACK_HEADER_BYTES_V3: usize = PACK_HEADER_BYTES_V3;
pub const DURABLE_PACK_FOOTER_BYTES_V3: usize = PACK_FOOTER_BYTES_V3;

const PERF_PAGE_BUILD_V3: usize = 0;
const PERF_ENCRYPT_V3: usize = 1;
const PERF_NONCE_RESERVE_V3: usize = 2;
const PERF_FILE_WRITE_V3: usize = 3;
const PERF_FILE_SYNC_V3: usize = 4;
const PERF_RENAME_V3: usize = 5;
const PERF_DIRECTORY_SYNC_V3: usize = 6;
const PERF_NONCE_ACK_V3: usize = 7;
const PERF_CHECKPOINT_BUILD_V3: usize = 8;
const PERF_INDEX_BUILD_V3: usize = 9;
const PERF_PAGE_SCAN_V3: usize = 10;
const PERF_DECRYPT_V3: usize = 11;
const PERF_PHASES_V3: usize = 12;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurablePackedPerformanceReceiptV3 {
    pub page_construction_nanos: u64,
    pub frame_encryption_nanos: u64,
    pub nonce_reservation_nanos: u64,
    pub file_write_nanos: u64,
    pub file_full_sync_nanos: u64,
    pub rename_nanos: u64,
    pub directory_sync_nanos: u64,
    pub nonce_acknowledgement_nanos: u64,
    pub checkpoint_construction_nanos: u64,
    pub index_construction_nanos: u64,
    pub page_scan_nanos: u64,
    pub frame_decryption_nanos: u64,
    pub object_count: u64,
    pub page_count: u64,
    pub index_shard_count: u64,
    pub sync_count: u64,
    pub encrypted_byte_count: u64,
    pub decrypted_byte_count: u64,
    pub written_byte_count: u64,
}

impl DurablePackedPerformanceReceiptV3 {
    #[must_use]
    pub const fn total_elapsed_nanos(self) -> u64 {
        self.page_construction_nanos
            .saturating_add(self.frame_encryption_nanos)
            .saturating_add(self.nonce_reservation_nanos)
            .saturating_add(self.file_write_nanos)
            .saturating_add(self.file_full_sync_nanos)
            .saturating_add(self.rename_nanos)
            .saturating_add(self.directory_sync_nanos)
            .saturating_add(self.nonce_acknowledgement_nanos)
            .saturating_add(self.checkpoint_construction_nanos)
            .saturating_add(self.index_construction_nanos)
            .saturating_add(self.page_scan_nanos)
            .saturating_add(self.frame_decryption_nanos)
    }
}

struct DurablePackedPerformanceStateV3 {
    enabled: AtomicBool,
    nanos: [AtomicU64; PERF_PHASES_V3],
    object_count: AtomicU64,
    page_count: AtomicU64,
    index_shard_count: AtomicU64,
    sync_count: AtomicU64,
    encrypted_byte_count: AtomicU64,
    decrypted_byte_count: AtomicU64,
    written_byte_count: AtomicU64,
}

impl DurablePackedPerformanceStateV3 {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            nanos: std::array::from_fn(|_| AtomicU64::new(0)),
            object_count: AtomicU64::new(0),
            page_count: AtomicU64::new(0),
            index_shard_count: AtomicU64::new(0),
            sync_count: AtomicU64::new(0),
            encrypted_byte_count: AtomicU64::new(0),
            decrypted_byte_count: AtomicU64::new(0),
            written_byte_count: AtomicU64::new(0),
        }
    }
}
const DESCRIPTOR_HEADER_BYTES_V3: usize = 112;
const PAGE_HEADER_BYTES_V3: usize = 160;
const PAGE_ENTRY_BYTES_V3: usize = 80;
const INDEX_SHARD_ENTRIES_V3: usize = 4_096;

/// Every externally observable V3 crash boundary. Tests can fail one point at
/// a time and reconstruct from the authority plus authenticated disk objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurablePackedFaultPointV3 {
    BeforeNonceReservation,
    AfterNonceReservation,
    BeforeFrameEncryption,
    AfterFrameEncryption,
    BeforeTemporaryCreate,
    AfterTemporaryCreate,
    BeforeTemporaryWrite,
    AfterTemporaryWrite,
    BeforeTemporarySync,
    AfterTemporarySync,
    BeforeObjectInstall,
    AfterObjectInstall,
    BeforeDirectorySync,
    AfterDirectorySync,
    BeforeNonceAcknowledgement,
    AfterNonceAcknowledgement,
    BeforeDataCommit,
    AfterDataCommit,
    BeforeSeal,
    AfterSeal,
    BeforePublicationReservation,
    AfterPublicationReservation,
    AfterPublicationRename,
    AfterPublicationSync,
    AfterAuthorityPublish,
    BeforeRecoveryObject,
    AfterRecoveryObject,
    AfterAuthorityDestroy,
    BeforeCiphertextCleanup,
    AfterCiphertextCleanup,
}

pub trait DurablePackedFaultInjectorV3: Send + Sync {
    fn fail_at(
        &self,
        point: DurablePackedFaultPointV3,
        object_kind: Option<SnapshotObjectKindV2>,
        ordinal: u64,
    ) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoDurablePackedFaultsV3;

impl DurablePackedFaultInjectorV3 for NoDurablePackedFaultsV3 {
    fn fail_at(
        &self,
        _point: DurablePackedFaultPointV3,
        _object_kind: Option<SnapshotObjectKindV2>,
        _ordinal: u64,
    ) -> bool {
        false
    }
}

#[derive(Clone)]
struct DurableObjectV3 {
    path: PathBuf,
    segment_ordinal: u64,
    kind: SnapshotObjectKindV2,
    commitment: FrameCommitmentV1,
    prior_commitment: FrameCommitmentV1,
    frame_count: usize,
    binding_digest: LifecycleDigestV1,
    operation: OperationIdV1,
}

#[derive(Clone)]
struct DurablePageV3 {
    object: DurableObjectV3,
    page_ordinal: u64,
    first_acquisition: usize,
    event_count: usize,
    frame_ordinal: usize,
}

struct PendingFrameV3 {
    kind: SnapshotObjectKindV2,
    additional_aad: Vec<u8>,
    plaintext: Zeroizing<Vec<u8>>,
}

struct PendingPageV3 {
    page_ordinal: u64,
    first_acquisition: usize,
    event_count: usize,
}

struct OpenedObjectV3 {
    additional_aad: Vec<u8>,
    frame_nonce: [u8; 24],
    plaintext: Zeroizing<Vec<u8>>,
}

struct RawObjectFileV3 {
    segment: SegmentHeaderV2,
    header: [u8; PACK_HEADER_BYTES_V3],
    kind: SnapshotObjectKindV2,
    frame_count: usize,
    directory_offset: u64,
    directory_length: u64,
    commitment: FrameCommitmentV1,
    binding_digest: LifecycleDigestV1,
    operation: OperationIdV1,
}

#[derive(Clone)]
struct PackDirectoryEntryV3 {
    offset: u64,
    length: u64,
    kind: SnapshotObjectKindV2,
    canonical_digest: [u8; 32],
    commitment: FrameCommitmentV1,
}

struct OpenedPackDirectoryV3 {
    raw: RawObjectFileV3,
    entries: Vec<PackDirectoryEntryV3>,
}

/// Independent local encrypted V3 repository.
pub struct DurablePackedRepositoryV3<A> {
    root: PathBuf,
    authority: A,
    fault_injector: Arc<dyn DurablePackedFaultInjectorV3>,
    state: RetainedEventStoreStateV3,
    begin: Option<RetainedStoreBeginV3>,
    manifest: Option<RetainedStoreManifestV3>,
    result_path: Option<PathBuf>,
    acquisition: Vec<RetainedEventLocatorV3>,
    by_event: Vec<(EventId, usize)>,
    by_lane: Vec<usize>,
    pending_arena: Zeroizing<Vec<u8>>,
    pending_first: usize,
    pending_pack_frames: Vec<PendingFrameV3>,
    pending_pack_pages: Vec<PendingPageV3>,
    pending_pack_plaintext_bytes: usize,
    pending_pack_records: usize,
    pages: Vec<DurablePageV3>,
    objects: Vec<DurableObjectV3>,
    previous_commitment: FrameCommitmentV1,
    next_checkpoint_records: u64,
    next_checkpoint_bytes: u64,
    index_commitment: LifecycleDigestV1,
    final_checkpoint_present: bool,
    published_aliases: Vec<RetainedPublishedAliasV3>,
    performance: DurablePackedPerformanceStateV3,
}

/// Compatibility name used by the CLI. Unlike the former implementation this
/// is an alias for the native packed repository, not a V2 adapter.
pub type DurableRetainedEventStoreV3<A> = DurablePackedRepositoryV3<A>;

/// Explicitly destroys an obsolete experimental V3 repository. Authority is
/// revoked before ciphertext removal; packed `.v3p` repositories are rejected.
pub fn cleanup_obsolete_v3_authority_first<A: KeyAuthorityV2>(
    root: &Path,
    authority: &A,
    result_id: ResultId,
) -> Result<(), RetainedEventStoreErrorV3> {
    let open_path = root.join(format!("{}.open", hex(result_id.as_bytes())));
    let published_path = root.join(format!("{}.published", hex(result_id.as_bytes())));
    let result_path = match (open_path.is_dir(), published_path.is_dir()) {
        (true, false) => open_path,
        (false, true) => published_path,
        _ => return Err(RetainedEventStoreErrorV3::InvalidState),
    };
    let entries = fs::read_dir(&result_path)
        .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    let obsolete_present = entries
        .iter()
        .any(|path| path.extension().is_some_and(|extension| extension == "v3"));
    let unexpected = entries.iter().any(|path| {
        !path
            .extension()
            .is_some_and(|extension| extension == "v3" || extension == "tmp")
    });
    if !obsolete_present || unexpected {
        return Err(RetainedEventStoreErrorV3::InvalidState);
    }
    match authority.destroy(result_id) {
        Ok(_) | Err(KeyAuthorityErrorV2::NotFound) => {}
        Err(error) => return Err(map_authority_error(error)),
    }
    fs::remove_dir_all(&result_path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    sync_directory(root)?;
    Ok(())
}

impl<A: KeyAuthorityV2> DurablePackedRepositoryV3<A> {
    pub fn open(root: &Path, authority: A) -> Result<Self, RetainedEventStoreErrorV3> {
        Self::open_with_fault_injector(root, authority, NoDurablePackedFaultsV3)
    }

    pub fn open_with_fault_injector<I>(
        root: &Path,
        authority: A,
        fault_injector: I,
    ) -> Result<Self, RetainedEventStoreErrorV3>
    where
        I: DurablePackedFaultInjectorV3 + 'static,
    {
        fs::create_dir_all(root).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        sync_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            authority,
            fault_injector: Arc::new(fault_injector),
            state: RetainedEventStoreStateV3::Empty,
            begin: None,
            manifest: None,
            result_path: None,
            acquisition: Vec::new(),
            by_event: Vec::new(),
            by_lane: Vec::new(),
            pending_arena: Zeroizing::new(Vec::new()),
            pending_first: 0,
            pending_pack_frames: Vec::new(),
            pending_pack_pages: Vec::new(),
            pending_pack_plaintext_bytes: 0,
            pending_pack_records: 0,
            pages: Vec::new(),
            objects: Vec::new(),
            previous_commitment: FrameCommitmentV1::ZERO,
            next_checkpoint_records: crate::CHECKPOINT_RECORD_INTERVAL_V3,
            next_checkpoint_bytes: crate::CHECKPOINT_BYTE_INTERVAL_V3,
            index_commitment: LifecycleDigestV1::from_bytes([0; 32]),
            final_checkpoint_present: false,
            published_aliases: Vec::new(),
            performance: DurablePackedPerformanceStateV3::new(),
        })
    }

    /// Reconstruct a V3 repository from authenticated disk objects and the
    /// external authority record. No in-process locator or page state is used.
    pub fn resume(
        root: &Path,
        authority: A,
        result_id: ResultId,
    ) -> Result<Self, RetainedEventStoreErrorV3> {
        Self::resume_with_fault_injector(root, authority, result_id, NoDurablePackedFaultsV3)
    }

    pub fn resume_with_fault_injector<I>(
        root: &Path,
        authority: A,
        result_id: ResultId,
        fault_injector: I,
    ) -> Result<Self, RetainedEventStoreErrorV3>
    where
        I: DurablePackedFaultInjectorV3 + 'static,
    {
        let authority_record = authority.snapshot(result_id).map_err(map_authority_error)?;
        let open_path = root.join(format!("{}.open", hex(result_id.as_bytes())));
        let published_path = root.join(format!("{}.published", hex(result_id.as_bytes())));
        let result_path = match (open_path.is_dir(), published_path.is_dir()) {
            (true, false) => open_path,
            (false, true) => published_path,
            _ => return Err(RetainedEventStoreErrorV3::CorruptIndex),
        };
        let mut paths = fs::read_dir(&result_path)
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        for temporary in paths
            .iter()
            .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
        {
            fs::remove_file(temporary).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        }
        sync_directory(&result_path)?;
        paths.retain(|path| path.extension().is_some_and(|extension| extension == "v3"));
        if !paths.is_empty() {
            return Err(RetainedEventStoreErrorV3::ObsoleteFormat);
        }
        paths = fs::read_dir(&result_path)
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        paths.retain(|path| path.extension().is_some_and(|extension| extension == "v3p"));
        paths.sort();
        let descriptor_path = paths
            .first()
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        let descriptor_raw = read_raw_object_file_v3(descriptor_path)?;
        if descriptor_raw.kind != SnapshotObjectKindV2::Request
            || descriptor_raw.frame_count != 1
            || descriptor_raw.header[16..48] != *result_id.as_bytes()
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let begin = RetainedStoreBeginV3 {
            result_id,
            namespace: read_array(&descriptor_raw.header, 48),
            created_unix_nanos: i128::from(authority_record.created_unix_nanos()),
            expires_unix_nanos: i128::from(authority_record.expires_unix_nanos()),
        };
        let mut repository = Self::open_with_fault_injector(root, authority, fault_injector)?;
        repository.begin = Some(begin);
        repository.result_path = Some(result_path);
        let mut previous = FrameCommitmentV1::ZERO;
        let mut index_hasher = Sha256::new();
        index_hasher.update(b"evidentrail/durable-packed/indexes/v3\0");
        let mut saw_index = false;
        let mut checkpoint_index = LifecycleDigestV1::from_bytes([0; 32]);
        let mut manifest = None;
        let mut alias_digest = None;
        for (expected_ordinal, path) in paths.iter().enumerate() {
            let raw = read_raw_object_file_v3(path)?;
            if raw.segment.result_id() != result_id
                || raw.segment.segment_ordinal() != expected_ordinal as u64
                || raw.segment.prior_segment_commitment() != previous
                || raw.header[48..80] != begin.namespace
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let object = DurableObjectV3 {
                path: path.clone(),
                segment_ordinal: expected_ordinal as u64,
                kind: raw.kind,
                commitment: raw.commitment,
                prior_commitment: previous,
                frame_count: raw.frame_count,
                binding_digest: raw.binding_digest,
                operation: raw.operation,
            };
            repository.inject(
                DurablePackedFaultPointV3::BeforeRecoveryObject,
                Some(object.kind),
                object.segment_ordinal,
            )?;
            repository.objects.push(object.clone());
            let directory = repository.open_pack_directory(&object)?;
            for frame_ordinal in 0..object.frame_count {
                let opened =
                    repository.open_object_from_directory(&directory, &object, frame_ordinal)?;
                match object.kind {
                    SnapshotObjectKindV2::Request => {
                        if expected_ordinal != 0
                            || object.frame_count != 1
                            || opened.additional_aad.len() != DESCRIPTOR_HEADER_BYTES_V3
                            || opened.additional_aad[0..8] != DESCRIPTOR_MAGIC_V3
                            || read_u16(&opened.additional_aad, 8) != FORMAT_VERSION_V3
                            || opened.additional_aad[16..48] != *result_id.as_bytes()
                            || read_array::<32>(&opened.additional_aad, 48) != begin.namespace
                            || read_i128(&opened.additional_aad, 80) != begin.created_unix_nanos
                            || read_i128(&opened.additional_aad, 96) != begin.expires_unix_nanos
                        {
                            return Err(RetainedEventStoreErrorV3::CorruptIndex);
                        }
                    }
                    SnapshotObjectKindV2::AuthorizedEvent => {
                        repository.reconstruct_page(&object, frame_ordinal, &opened)?;
                    }
                    SnapshotObjectKindV2::EventIndex => {
                        saw_index = true;
                        index_hasher.update(Sha256::digest(&opened.plaintext));
                    }
                    SnapshotObjectKindV2::DataManifest => {
                        if manifest.is_some() || object.frame_count != 1 {
                            return Err(RetainedEventStoreErrorV3::CorruptIndex);
                        }
                        manifest = Some(decode_manifest_v3(
                            begin,
                            &repository.acquisition,
                            &opened.plaintext,
                        )?);
                    }
                    SnapshotObjectKindV2::OperationalReceipt => {
                        if opened.plaintext.len() != 104
                            || opened.plaintext[0..8] != CHECKPOINT_MAGIC_V3
                            || read_u16(&opened.plaintext, 8) != FORMAT_VERSION_V3
                            || opened.plaintext[10..16].iter().any(|byte| *byte != 0)
                            || opened.plaintext[40..72] != *object.prior_commitment.as_bytes()
                        {
                            return Err(RetainedEventStoreErrorV3::CorruptIndex);
                        }
                        checkpoint_index =
                            LifecycleDigestV1::from_bytes(read_array(&opened.plaintext, 72));
                        if manifest.is_some() {
                            repository.final_checkpoint_present = true;
                        }
                    }
                    SnapshotObjectKindV2::AliasManifest => {
                        if opened.plaintext.len() < 18
                            || opened.plaintext[0..8] != ALIAS_MAGIC_V3
                            || read_u16(&opened.plaintext, 8) != FORMAT_VERSION_V3
                        {
                            return Err(RetainedEventStoreErrorV3::CorruptIndex);
                        }
                        alias_digest = Some(derive_lifecycle_digest_v1(&opened.plaintext));
                    }
                    _ => return Err(RetainedEventStoreErrorV3::CorruptIndex),
                }
            }
            previous = object.commitment;
            repository.inject(
                DurablePackedFaultPointV3::AfterRecoveryObject,
                Some(object.kind),
                object.segment_ordinal,
            )?;
        }
        repository.previous_commitment = previous;
        repository.pending_first = repository.acquisition.len();
        let source_bytes = repository.acquisition.last().map_or(0, |locator| {
            locator.offset.saturating_add(u64::from(locator.exact_len))
        });
        while repository.next_checkpoint_records <= repository.acquisition.len() as u64 {
            repository.next_checkpoint_records = repository
                .next_checkpoint_records
                .saturating_add(crate::CHECKPOINT_RECORD_INTERVAL_V3);
        }
        while repository.next_checkpoint_bytes <= source_bytes {
            repository.next_checkpoint_bytes = repository
                .next_checkpoint_bytes
                .saturating_add(crate::CHECKPOINT_BYTE_INTERVAL_V3);
        }
        repository.by_event = repository
            .acquisition
            .iter()
            .enumerate()
            .map(|(position, locator)| (locator.event_id, position))
            .collect();
        repository.by_event.sort_unstable_by_key(|entry| entry.0);
        if repository
            .by_event
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(RetainedEventStoreErrorV3::DuplicateEvent);
        }
        repository.by_lane = (0..repository.acquisition.len()).collect();
        repository.by_lane.sort_unstable_by_key(|position| {
            let locator = repository.acquisition[*position];
            (
                locator.lane_ordinal,
                locator.lane_sequence,
                locator.acquisition_ordinal,
            )
        });
        validate_lane_order_v3(&repository.acquisition, &repository.by_lane)
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        if saw_index {
            repository.index_commitment =
                LifecycleDigestV1::from_bytes(index_hasher.finalize().into());
            if repository.final_checkpoint_present
                && repository.index_commitment != checkpoint_index
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
        }
        repository.manifest = manifest;
        if authority_record.state() >= evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted
        {
            let manifest = repository
                .manifest
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            if !repository.final_checkpoint_present
                || authority_record.data_digest()
                    != LifecycleDigestV1::from_bytes(manifest.digest())
                || authority_record.build_context() != build_context_v3().aggregate()
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
        }
        if authority_record.state() >= evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed
            && authority_record.seal_commitments().frame_chain()
                != LifecycleDigestV1::from_bytes(*previous.as_bytes())
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        if authority_record.state() == evidentrail_snapshot_format::ResultLifecycleStateV1::Published {
            let commitment = repository_commitment_v3(result_id, &repository.objects);
            if commitment != authority_record.repository_commitment() {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
        }
        if authority_record.has_pending_nonce_reservation() {
            let installed = repository.objects.iter().any(|object| {
                object.operation == authority_record.pending_nonce_operation()
                    && object.binding_digest == authority_record.pending_nonce_digest()
            });
            if installed {
                repository
                    .authority
                    .complete_nonce_reservation(
                        result_id,
                        authority_record.pending_nonce_operation(),
                        authority_record.pending_nonce_digest(),
                    )
                    .map_err(map_authority_error)?;
            }
        }
        let mut recovered_state = authority_record.state();
        if recovered_state == evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted {
            if let Some(alias_digest) = alias_digest {
                let manifest = repository
                    .manifest
                    .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
                let manifest_digest = LifecycleDigestV1::from_bytes(manifest.digest());
                repository
                    .authority
                    .seal(
                        result_id,
                        operation_id(begin.namespace, b"seal", 0),
                        SealCommitmentsV1::new(
                            manifest_digest,
                            manifest_digest,
                            repository.index_commitment,
                            LifecycleDigestV1::from_bytes(*previous.as_bytes()),
                            alias_digest,
                        ),
                    )
                    .map_err(map_authority_error)?;
                recovered_state = evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed;
            }
        }
        if recovered_state == evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed {
            let commitment = repository_commitment_v3(result_id, &repository.objects);
            let publish_operation = operation_id(begin.namespace, b"publish", 0);
            let generation = repository
                .authority
                .reserve_publication_generation(result_id, publish_operation, commitment)
                .map_err(map_authority_error)?;
            let published = root.join(format!("{}.published", hex(result_id.as_bytes())));
            if repository.result_path()?.file_name() != published.file_name() {
                rename_create_only(repository.result_path()?, &published)?;
                sync_directory(&published)?;
                sync_directory(root)?;
                for object in &mut repository.objects {
                    if let Some(name) = object.path.file_name() {
                        object.path = published.join(name);
                    }
                }
                for page in &mut repository.pages {
                    if let Some(name) = page.object.path.file_name() {
                        page.object.path = published.join(name);
                    }
                }
                repository.result_path = Some(published);
            }
            repository
                .authority
                .publish(result_id, publish_operation, generation, commitment)
                .map_err(map_authority_error)?;
            recovered_state = evidentrail_snapshot_format::ResultLifecycleStateV1::Published;
        }
        repository.state = map_authority_state(recovered_state);
        Ok(repository)
    }

    #[must_use]
    pub const fn authority(&self) -> &A {
        &self.authority
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn published_aliases(&self) -> &[RetainedPublishedAliasV3] {
        &self.published_aliases
    }

    #[must_use]
    pub const fn manifest(&self) -> Option<RetainedStoreManifestV3> {
        self.manifest
    }

    /// Enables contentless, process-local profiling counters. It is disabled
    /// by default and is not a qualification or certification receipt.
    pub fn enable_performance_instrumentation(&self) {
        self.performance.enabled.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn performance_receipt(&self) -> DurablePackedPerformanceReceiptV3 {
        let nanos: [u64; PERF_PHASES_V3] =
            std::array::from_fn(|index| self.performance.nanos[index].load(Ordering::Relaxed));
        DurablePackedPerformanceReceiptV3 {
            page_construction_nanos: nanos[PERF_PAGE_BUILD_V3],
            frame_encryption_nanos: nanos[PERF_ENCRYPT_V3],
            nonce_reservation_nanos: nanos[PERF_NONCE_RESERVE_V3],
            file_write_nanos: nanos[PERF_FILE_WRITE_V3],
            file_full_sync_nanos: nanos[PERF_FILE_SYNC_V3],
            rename_nanos: nanos[PERF_RENAME_V3],
            directory_sync_nanos: nanos[PERF_DIRECTORY_SYNC_V3],
            nonce_acknowledgement_nanos: nanos[PERF_NONCE_ACK_V3],
            checkpoint_construction_nanos: nanos[PERF_CHECKPOINT_BUILD_V3],
            index_construction_nanos: nanos[PERF_INDEX_BUILD_V3],
            page_scan_nanos: nanos[PERF_PAGE_SCAN_V3],
            frame_decryption_nanos: nanos[PERF_DECRYPT_V3],
            object_count: self.performance.object_count.load(Ordering::Relaxed),
            page_count: self.performance.page_count.load(Ordering::Relaxed),
            index_shard_count: self.performance.index_shard_count.load(Ordering::Relaxed),
            sync_count: self.performance.sync_count.load(Ordering::Relaxed),
            encrypted_byte_count: self
                .performance
                .encrypted_byte_count
                .load(Ordering::Relaxed),
            decrypted_byte_count: self
                .performance
                .decrypted_byte_count
                .load(Ordering::Relaxed),
            written_byte_count: self.performance.written_byte_count.load(Ordering::Relaxed),
        }
    }

    fn performance_start(&self) -> Option<Instant> {
        self.performance
            .enabled
            .load(Ordering::Relaxed)
            .then(Instant::now)
    }

    fn performance_finish(&self, phase: usize, started: Option<Instant>) {
        if let Some(started) = started {
            let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.performance.nanos[phase].fetch_add(nanos, Ordering::Relaxed);
        }
    }

    fn result_path(&self) -> Result<&Path, RetainedEventStoreErrorV3> {
        self.result_path
            .as_deref()
            .ok_or(RetainedEventStoreErrorV3::InvalidState)
    }

    fn inject(
        &self,
        point: DurablePackedFaultPointV3,
        kind: Option<SnapshotObjectKindV2>,
        ordinal: u64,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.fault_injector.fail_at(point, kind, ordinal) {
            Err(RetainedEventStoreErrorV3::FaultInjected)
        } else {
            Ok(())
        }
    }

    fn reconstruct_page(
        &mut self,
        object: &DurableObjectV3,
        frame_ordinal: usize,
        opened: &OpenedObjectV3,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let header = &opened.additional_aad;
        let plaintext = &opened.plaintext;
        let page_ordinal = self
            .pages
            .len()
            .saturating_add(self.pending_pack_pages.len()) as u64;
        if header.len() != PAGE_HEADER_BYTES_V3
            || header[0..8] != PAGE_MAGIC_V3
            || read_u16(header, 8) != FORMAT_VERSION_V3
            || header[10..16].iter().any(|byte| *byte != 0)
            || header[16..48] != *begin.result_id.as_bytes()
            || header[48..80] != begin.namespace
            || read_u64(header, 80) != page_ordinal
            || header[104..136] != *object.prior_commitment.as_bytes()
            || header[136..160] != opened.frame_nonce
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let count = read_u32(header, 88) as usize;
        let entry_bytes = read_u32(header, 92) as usize;
        let data_bytes = usize::try_from(read_u64(header, 96))
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        if count == 0
            || count > MAX_EVENTS_PER_PAGE_V3
            || entry_bytes != count.saturating_mul(PAGE_ENTRY_BYTES_V3)
            || entry_bytes.checked_add(data_bytes) != Some(plaintext.len())
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let first_acquisition = self.acquisition.len();
        let global_start = self.acquisition.last().map_or(0, |locator| {
            locator.offset.saturating_add(u64::from(locator.exact_len))
        });
        let mut expected_local_offset = 0u64;
        for index in 0..count {
            let entry = index * PAGE_ENTRY_BYTES_V3;
            if plaintext[entry + 73..entry + 80]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let local_offset = read_u64(plaintext, entry + 56);
            let exact_len = read_u32(plaintext, entry + 64);
            let payload_len = read_u32(plaintext, entry + 68);
            let terminator_len = plaintext[entry + 72];
            if local_offset != expected_local_offset
                || payload_len as usize + usize::from(terminator_len) != exact_len as usize
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let data_start = entry_bytes
                .checked_add(local_offset as usize)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            if data_start
                .checked_add(exact_len as usize)
                .is_none_or(|end| end > plaintext.len())
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            self.acquisition.push(RetainedEventLocatorV3 {
                event_id: EventId::from_bytes(read_array(plaintext, entry)),
                acquisition_ordinal: read_u64(plaintext, entry + 32),
                lane_ordinal: read_u64(plaintext, entry + 40),
                lane_sequence: read_u64(plaintext, entry + 48),
                offset: global_start.saturating_add(local_offset),
                exact_len,
                payload_len,
                terminator_len,
            });
            expected_local_offset = expected_local_offset.saturating_add(u64::from(exact_len));
        }
        if expected_local_offset != data_bytes as u64 {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        self.pages.push(DurablePageV3 {
            object: object.clone(),
            page_ordinal,
            first_acquisition,
            event_count: count,
            frame_ordinal,
        });
        Ok(())
    }

    fn flush_page(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        if self.pending_first == self.acquisition.len() {
            return Ok(());
        }
        let performance_started = self.performance_start();
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let locators = &self.acquisition[self.pending_first..];
        let event_count = locators.len();
        let page_ordinal = self
            .pages
            .len()
            .saturating_add(self.pending_pack_pages.len()) as u64;
        let entry_bytes = locators
            .len()
            .checked_mul(PAGE_ENTRY_BYTES_V3)
            .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
        let mut header = vec![0; PAGE_HEADER_BYTES_V3];
        header[0..8].copy_from_slice(&PAGE_MAGIC_V3);
        header[8..10].copy_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
        header[16..48].copy_from_slice(begin.result_id.as_bytes());
        header[48..80].copy_from_slice(&begin.namespace);
        header[80..88].copy_from_slice(&page_ordinal.to_be_bytes());
        header[88..92].copy_from_slice(&(locators.len() as u32).to_be_bytes());
        header[92..96].copy_from_slice(&(entry_bytes as u32).to_be_bytes());
        header[96..104].copy_from_slice(&(self.pending_arena.len() as u64).to_be_bytes());
        header[104..136].copy_from_slice(self.previous_commitment.as_bytes());
        let mut plaintext =
            Zeroizing::new(Vec::with_capacity(entry_bytes + self.pending_arena.len()));
        let page_global_start = locators.first().map_or(0, |locator| locator.offset);
        for locator in locators {
            let local_offset = locator
                .offset
                .checked_sub(page_global_start)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            plaintext.extend_from_slice(locator.event_id.as_bytes());
            plaintext.extend_from_slice(&locator.acquisition_ordinal.to_be_bytes());
            plaintext.extend_from_slice(&locator.lane_ordinal.to_be_bytes());
            plaintext.extend_from_slice(&locator.lane_sequence.to_be_bytes());
            plaintext.extend_from_slice(&local_offset.to_be_bytes());
            plaintext.extend_from_slice(&locator.exact_len.to_be_bytes());
            plaintext.extend_from_slice(&locator.payload_len.to_be_bytes());
            plaintext.push(locator.terminator_len);
            plaintext.extend_from_slice(&[0; 7]);
        }
        plaintext.extend_from_slice(&self.pending_arena);
        let frame_bytes = header.len().saturating_add(plaintext.len());
        if !self.pending_pack_frames.is_empty()
            && (self
                .pending_pack_plaintext_bytes
                .saturating_add(frame_bytes)
                > ACQUISITION_PACK_PLAINTEXT_BYTES_V3
                || self.pending_pack_records.saturating_add(event_count)
                    > ACQUISITION_PACK_RECORDS_V3
                || self.pending_pack_frames.len() == MAX_PACK_FRAMES_V3)
        {
            self.flush_acquisition_pack()?;
            header[104..136].copy_from_slice(self.previous_commitment.as_bytes());
        }
        if frame_bytes > ACQUISITION_PACK_PLAINTEXT_BYTES_V3 {
            return Err(RetainedEventStoreErrorV3::CapacityExceeded);
        }
        self.pending_pack_frames.push(PendingFrameV3 {
            kind: SnapshotObjectKindV2::AuthorizedEvent,
            additional_aad: header,
            plaintext,
        });
        self.pending_pack_pages.push(PendingPageV3 {
            page_ordinal,
            first_acquisition: self.pending_first,
            event_count,
        });
        self.pending_pack_plaintext_bytes = self
            .pending_pack_plaintext_bytes
            .saturating_add(frame_bytes);
        self.pending_pack_records = self.pending_pack_records.saturating_add(event_count);
        self.performance.page_count.fetch_add(1, Ordering::Relaxed);
        self.pending_first = self.acquisition.len();
        self.pending_arena.clear();
        self.performance_finish(PERF_PAGE_BUILD_V3, performance_started);
        Ok(())
    }

    fn flush_acquisition_pack(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        if self.pending_pack_frames.is_empty() {
            return Ok(());
        }
        let logical_ordinal = self
            .pending_pack_pages
            .first()
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?
            .page_ordinal;
        let frames = std::mem::take(&mut self.pending_pack_frames);
        let pending_pages = std::mem::take(&mut self.pending_pack_pages);
        let object = self.write_pack(
            SnapshotObjectKindV2::AuthorizedEvent,
            "acquisition-pack",
            logical_ordinal,
            frames,
        )?;
        for (frame_ordinal, page) in pending_pages.into_iter().enumerate() {
            self.pages.push(DurablePageV3 {
                object: object.clone(),
                page_ordinal: page.page_ordinal,
                first_acquisition: page.first_acquisition,
                event_count: page.event_count,
                frame_ordinal,
            });
        }
        self.pending_pack_plaintext_bytes = 0;
        self.pending_pack_records = 0;
        Ok(())
    }

    fn write_object(
        &mut self,
        kind: SnapshotObjectKindV2,
        label: &str,
        logical_ordinal: u64,
        plaintext: &[u8],
    ) -> Result<DurableObjectV3, RetainedEventStoreErrorV3> {
        self.write_object_with_aad(kind, label, logical_ordinal, &[], plaintext)
    }

    fn write_object_with_aad(
        &mut self,
        kind: SnapshotObjectKindV2,
        label: &str,
        logical_ordinal: u64,
        additional_aad: &[u8],
        plaintext: &[u8],
    ) -> Result<DurableObjectV3, RetainedEventStoreErrorV3> {
        self.write_pack(
            kind,
            label,
            logical_ordinal,
            vec![PendingFrameV3 {
                kind,
                additional_aad: additional_aad.to_vec(),
                plaintext: Zeroizing::new(plaintext.to_vec()),
            }],
        )
    }

    fn write_pack(
        &mut self,
        kind: SnapshotObjectKindV2,
        label: &str,
        logical_ordinal: u64,
        mut frames: Vec<PendingFrameV3>,
    ) -> Result<DurableObjectV3, RetainedEventStoreErrorV3> {
        if frames.is_empty()
            || frames.len() > MAX_PACK_FRAMES_V3
            || frames.iter().any(|frame| frame.kind != kind)
        {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let segment_ordinal = self.objects.len() as u64;
        let canonical_digests = frames
            .iter()
            .enumerate()
            .map(|(frame_ordinal, frame)| {
                canonical_frame_digest_v3(
                    kind,
                    segment_ordinal,
                    frame_ordinal,
                    &frame.additional_aad,
                    &frame.plaintext,
                )
            })
            .collect::<Vec<_>>();
        let mut ordered = Sha256::new();
        ordered.update(b"evidentrail/durable-packed/ordered-frame-digests/v4\0");
        for digest in &canonical_digests {
            ordered.update(digest);
        }
        let ordered_digest: [u8; 32] = ordered.finalize().into();
        let operation = operation_id(begin.namespace, label.as_bytes(), logical_ordinal);
        let mut binding = Sha256::new();
        binding.update(b"evidentrail/durable-packed/pack-reservation/v4\0");
        binding.update(begin.result_id.as_bytes());
        binding.update(begin.namespace);
        binding.update(kind.code().to_be_bytes());
        binding.update(segment_ordinal.to_be_bytes());
        binding.update(logical_ordinal.to_be_bytes());
        binding.update((frames.len() as u64).to_be_bytes());
        binding.update(ordered_digest);
        binding.update(self.previous_commitment.as_bytes());
        let digest = LifecycleDigestV1::from_bytes(binding.finalize().into());
        let directory_plaintext_length = PACK_DIRECTORY_HEADER_BYTES_V3
            .checked_add(frames.len().saturating_mul(PACK_DIRECTORY_ENTRY_BYTES_V3))
            .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
        let mut pack_header = [0u8; PACK_HEADER_BYTES_V3];
        pack_header[0..8].copy_from_slice(&PACK_MAGIC_V3);
        pack_header[8..10].copy_from_slice(&PACK_LAYOUT_VERSION_V3.to_be_bytes());
        pack_header[10..12].copy_from_slice(&kind.code().to_be_bytes());
        pack_header[16..48].copy_from_slice(begin.result_id.as_bytes());
        pack_header[48..80].copy_from_slice(&begin.namespace);
        pack_header[80..88].copy_from_slice(&segment_ordinal.to_be_bytes());
        pack_header[88..96].copy_from_slice(&logical_ordinal.to_be_bytes());
        pack_header[96..100].copy_from_slice(&(frames.len() as u32).to_be_bytes());
        pack_header[100..104].copy_from_slice(&(directory_plaintext_length as u32).to_be_bytes());
        pack_header[104..136].copy_from_slice(self.previous_commitment.as_bytes());
        pack_header[136..168].copy_from_slice(&ordered_digest);
        pack_header[168..200].copy_from_slice(digest.as_bytes());
        pack_header[200..216].copy_from_slice(operation.as_bytes());
        self.inject(
            DurablePackedFaultPointV3::BeforeNonceReservation,
            Some(kind),
            segment_ordinal,
        )?;
        let nonce_started = self.performance_start();
        let reservation = self
            .authority
            .reserve_nonce_range(begin.result_id, operation, digest, frames.len() as u64 + 1)
            .map_err(map_authority_error)?;
        self.performance_finish(PERF_NONCE_RESERVE_V3, nonce_started);
        self.inject(
            DurablePackedFaultPointV3::AfterNonceReservation,
            Some(kind),
            segment_ordinal,
        )?;
        let segment =
            SegmentHeaderV2::new(begin.result_id, segment_ordinal, self.previous_commitment)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&segment.encode());
        encoded.extend_from_slice(&pack_header);
        let mut directory_entries = Vec::with_capacity(frames.len());
        let mut previous_frame = FrameCommitmentV1::ZERO;
        for (frame_ordinal, frame) in frames.iter_mut().enumerate() {
            let nonce = reservation
                .nonce_at(frame_ordinal as u64)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            if kind == SnapshotObjectKindV2::AuthorizedEvent {
                if frame.additional_aad.len() != PAGE_HEADER_BYTES_V3
                    || frame.additional_aad[136..160].iter().any(|byte| *byte != 0)
                {
                    return Err(RetainedEventStoreErrorV3::CorruptIndex);
                }
                frame.additional_aad[136..160].copy_from_slice(&nonce);
            }
            let global_sequence = segment_ordinal
                .checked_mul(MAX_PACK_FRAMES_V3 as u64 + 1)
                .and_then(|base| base.checked_add(frame_ordinal as u64))
                .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
            let frame_header = FrameHeaderV2::new(
                kind,
                segment_ordinal,
                frame_ordinal as u32,
                global_sequence,
                u32::try_from(frame.plaintext.len())
                    .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?,
                nonce,
                previous_frame,
            )
            .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?;
            let frame_aad = pack_frame_aad_v3(&pack_header, &frame.additional_aad);
            self.inject(
                DurablePackedFaultPointV3::BeforeFrameEncryption,
                Some(kind),
                segment_ordinal,
            )?;
            let encryption_started = self.performance_start();
            let sealed = self
                .authority
                .with_result_key(begin.result_id, |_, dek| {
                    seal_frame_v2_with_additional_aad(
                        dek,
                        segment,
                        frame_header,
                        &frame.plaintext,
                        &frame_aad,
                    )
                    .map_err(|_| KeyAuthorityErrorV2::UpdateFailed)
                })
                .map_err(map_authority_error)?;
            self.performance_finish(PERF_ENCRYPT_V3, encryption_started);
            self.performance
                .encrypted_byte_count
                .fetch_add(frame.plaintext.len() as u64, Ordering::Relaxed);
            self.inject(
                DurablePackedFaultPointV3::AfterFrameEncryption,
                Some(kind),
                segment_ordinal,
            )?;
            let sealed_bytes = sealed.encode();
            let offset = encoded.len() as u64;
            encoded.extend_from_slice(&(frame.additional_aad.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&(sealed_bytes.len() as u64).to_be_bytes());
            encoded.extend_from_slice(&frame.additional_aad);
            encoded.extend_from_slice(&sealed_bytes);
            directory_entries.push(PackDirectoryEntryV3 {
                offset,
                length: encoded.len() as u64 - offset,
                kind,
                canonical_digest: canonical_digests[frame_ordinal],
                commitment: sealed.commitment(),
            });
            previous_frame = sealed.commitment();
        }
        let directory_plaintext = encode_pack_directory_v3(&directory_entries);
        let directory_nonce = reservation
            .nonce_at(frames.len() as u64)
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let directory_header = FrameHeaderV2::new(
            SnapshotObjectKindV2::EventIndexDirectory,
            segment_ordinal,
            frames.len() as u32,
            segment_ordinal
                .checked_mul(MAX_PACK_FRAMES_V3 as u64 + 1)
                .and_then(|base| base.checked_add(frames.len() as u64))
                .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?,
            u32::try_from(directory_plaintext.len())
                .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?,
            directory_nonce,
            previous_frame,
        )
        .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?;
        let directory_aad = pack_directory_aad_v3(&pack_header);
        let encryption_started = self.performance_start();
        let sealed_directory = self
            .authority
            .with_result_key(begin.result_id, |_, dek| {
                seal_frame_v2_with_additional_aad(
                    dek,
                    segment,
                    directory_header,
                    &directory_plaintext,
                    &directory_aad,
                )
                .map_err(|_| KeyAuthorityErrorV2::UpdateFailed)
            })
            .map_err(map_authority_error)?;
        self.performance_finish(PERF_ENCRYPT_V3, encryption_started);
        self.performance
            .encrypted_byte_count
            .fetch_add(directory_plaintext.len() as u64, Ordering::Relaxed);
        let directory_offset = encoded.len() as u64;
        let sealed_directory_bytes = sealed_directory.encode();
        encoded.extend_from_slice(&sealed_directory_bytes);
        let directory_length = sealed_directory_bytes.len() as u64;
        let mut footer = [0u8; PACK_FOOTER_BYTES_V3];
        footer[0..8].copy_from_slice(&PACK_FOOTER_MAGIC_V3);
        footer[8..10].copy_from_slice(&PACK_LAYOUT_VERSION_V3.to_be_bytes());
        footer[16..24].copy_from_slice(&directory_offset.to_be_bytes());
        footer[24..32].copy_from_slice(&directory_length.to_be_bytes());
        footer[32..64].copy_from_slice(sealed_directory.commitment().as_bytes());
        encoded.extend_from_slice(&footer);
        let result_path = self.result_path()?.to_path_buf();
        let filename = format!("{segment_ordinal:020}-{label}-{logical_ordinal:020}.v3p");
        let final_path = result_path.join(filename);
        let temp_path = final_path.with_extension("v3p.tmp");
        if final_path.exists() {
            if fs::read(&final_path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)? != encoded {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            if temp_path.exists() {
                if fs::read(&temp_path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
                    != encoded
                {
                    return Err(RetainedEventStoreErrorV3::CorruptIndex);
                }
                fs::remove_file(&temp_path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
            }
        } else {
            let file = if temp_path.exists() {
                if fs::read(&temp_path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
                    != encoded
                {
                    return Err(RetainedEventStoreErrorV3::CorruptIndex);
                }
                OpenOptions::new()
                    .read(true)
                    .open(&temp_path)
                    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
            } else {
                self.inject(
                    DurablePackedFaultPointV3::BeforeTemporaryCreate,
                    Some(kind),
                    segment_ordinal,
                )?;
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&temp_path)
                    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
                self.inject(
                    DurablePackedFaultPointV3::AfterTemporaryCreate,
                    Some(kind),
                    segment_ordinal,
                )?;
                self.inject(
                    DurablePackedFaultPointV3::BeforeTemporaryWrite,
                    Some(kind),
                    segment_ordinal,
                )?;
                let write_started = self.performance_start();
                file.write_all(&encoded)
                    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
                self.performance_finish(PERF_FILE_WRITE_V3, write_started);
                self.performance
                    .written_byte_count
                    .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                self.inject(
                    DurablePackedFaultPointV3::AfterTemporaryWrite,
                    Some(kind),
                    segment_ordinal,
                )?;
                file
            };
            self.inject(
                DurablePackedFaultPointV3::BeforeTemporarySync,
                Some(kind),
                segment_ordinal,
            )?;
            let sync_started = self.performance_start();
            sync_file(&file)?;
            self.performance_finish(PERF_FILE_SYNC_V3, sync_started);
            self.performance.sync_count.fetch_add(1, Ordering::Relaxed);
            self.inject(
                DurablePackedFaultPointV3::AfterTemporarySync,
                Some(kind),
                segment_ordinal,
            )?;
            drop(file);
            self.inject(
                DurablePackedFaultPointV3::BeforeObjectInstall,
                Some(kind),
                segment_ordinal,
            )?;
            let rename_started = self.performance_start();
            rename_create_only(&temp_path, &final_path)?;
            self.performance_finish(PERF_RENAME_V3, rename_started);
            self.inject(
                DurablePackedFaultPointV3::AfterObjectInstall,
                Some(kind),
                segment_ordinal,
            )?;
        }
        self.inject(
            DurablePackedFaultPointV3::BeforeDirectorySync,
            Some(kind),
            segment_ordinal,
        )?;
        let directory_sync_started = self.performance_start();
        sync_directory(&result_path)?;
        self.performance_finish(PERF_DIRECTORY_SYNC_V3, directory_sync_started);
        self.performance.sync_count.fetch_add(1, Ordering::Relaxed);
        self.inject(
            DurablePackedFaultPointV3::AfterDirectorySync,
            Some(kind),
            segment_ordinal,
        )?;
        self.inject(
            DurablePackedFaultPointV3::BeforeNonceAcknowledgement,
            Some(kind),
            segment_ordinal,
        )?;
        let acknowledgement_started = self.performance_start();
        self.authority
            .complete_nonce_reservation(begin.result_id, operation, digest)
            .map_err(map_authority_error)?;
        self.performance_finish(PERF_NONCE_ACK_V3, acknowledgement_started);
        self.inject(
            DurablePackedFaultPointV3::AfterNonceAcknowledgement,
            Some(kind),
            segment_ordinal,
        )?;
        let object = DurableObjectV3 {
            path: final_path,
            segment_ordinal,
            kind,
            commitment: sealed_directory.commitment(),
            prior_commitment: self.previous_commitment,
            frame_count: frames.len(),
            binding_digest: digest,
            operation,
        };
        self.previous_commitment = sealed_directory.commitment();
        self.objects.push(object.clone());
        self.performance
            .object_count
            .fetch_add(1, Ordering::Relaxed);
        Ok(object)
    }

    fn open_pack_directory(
        &self,
        object: &DurableObjectV3,
    ) -> Result<OpenedPackDirectoryV3, RetainedEventStoreErrorV3> {
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let raw = read_raw_object_file_v3(&object.path)?;
        if raw.segment.result_id() != begin.result_id
            || raw.segment.segment_ordinal() != object.segment_ordinal
            || raw.segment.prior_segment_commitment() != object.prior_commitment
            || raw.kind != object.kind
            || raw.frame_count != object.frame_count
            || raw.commitment != object.commitment
            || raw.binding_digest != object.binding_digest
            || raw.operation != object.operation
            || raw.header[48..80] != begin.namespace
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let mut file =
            File::open(&object.path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        file.seek(SeekFrom::Start(raw.directory_offset))
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        let directory_len = usize::try_from(raw.directory_length)
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let mut sealed_bytes = vec![0u8; directory_len];
        file.read_exact(&mut sealed_bytes)
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        let sealed = SealedFrameV2::decode(&sealed_bytes)
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        if sealed.header().object_kind() != SnapshotObjectKindV2::EventIndexDirectory
            || sealed.header().segment_ordinal() != object.segment_ordinal
            || sealed.header().frame_sequence() != object.frame_count as u32
            || sealed.commitment() != object.commitment
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let aad = pack_directory_aad_v3(&raw.header);
        let decryption_started = self.performance_start();
        let opened = self
            .authority
            .with_result_key(begin.result_id, |_, dek| {
                Ok(open_frame_v2_with_additional_aad(
                    dek,
                    raw.segment,
                    &sealed,
                    &aad,
                ))
            })
            .map_err(map_authority_error)?
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        self.performance_finish(PERF_DECRYPT_V3, decryption_started);
        self.performance
            .decrypted_byte_count
            .fetch_add(opened.as_bytes().len() as u64, Ordering::Relaxed);
        let entries = decode_pack_directory_v3(opened.as_bytes(), object.frame_count)?;
        let first_frame_offset =
            (evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2 + PACK_HEADER_BYTES_V3) as u64;
        let mut expected_offset = first_frame_offset;
        let mut ordered = Sha256::new();
        ordered.update(b"evidentrail/durable-packed/ordered-frame-digests/v4\0");
        for entry in &entries {
            if entry.kind != object.kind
                || entry.offset != expected_offset
                || entry.length < 12
                || entry
                    .offset
                    .checked_add(entry.length)
                    .is_none_or(|end| end > raw.directory_offset)
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            expected_offset = entry.offset + entry.length;
            ordered.update(entry.canonical_digest);
        }
        let ordered_digest: [u8; 32] = ordered.finalize().into();
        if expected_offset != raw.directory_offset || raw.header[136..168] != ordered_digest {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        Ok(OpenedPackDirectoryV3 { raw, entries })
    }

    fn open_object(
        &self,
        object: &DurableObjectV3,
        frame_ordinal: usize,
    ) -> Result<OpenedObjectV3, RetainedEventStoreErrorV3> {
        let directory = self.open_pack_directory(object)?;
        self.open_object_from_directory(&directory, object, frame_ordinal)
    }

    fn open_object_from_directory(
        &self,
        directory: &OpenedPackDirectoryV3,
        object: &DurableObjectV3,
        frame_ordinal: usize,
    ) -> Result<OpenedObjectV3, RetainedEventStoreErrorV3> {
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let entry = directory
            .entries
            .get(frame_ordinal)
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        let mut file =
            File::open(&object.path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        file.seek(SeekFrom::Start(entry.offset))
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        let mut record = vec![0u8; entry.length as usize];
        file.read_exact(&mut record)
            .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
        if record.len() < 12 {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let aad_len = read_u32(&record, 0) as usize;
        let sealed_len = usize::try_from(read_u64(&record, 4))
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let frame_start = 12usize
            .checked_add(aad_len)
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        if frame_start.checked_add(sealed_len) != Some(record.len()) {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let additional_aad = record[12..frame_start].to_vec();
        let sealed = SealedFrameV2::decode(&record[frame_start..])
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        if directory.raw.segment.result_id() != begin.result_id
            || directory.raw.segment.segment_ordinal() != object.segment_ordinal
            || sealed.header().object_kind() != entry.kind
            || sealed.commitment() != entry.commitment
            || sealed.header().frame_sequence() != frame_ordinal as u32
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let frame_aad = pack_frame_aad_v3(&directory.raw.header, &additional_aad);
        let decryption_started = self.performance_start();
        let opened = self
            .authority
            .with_result_key(begin.result_id, |_, dek| {
                Ok(open_frame_v2_with_additional_aad(
                    dek,
                    directory.raw.segment,
                    &sealed,
                    &frame_aad,
                ))
            })
            .map_err(map_authority_error)?
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        self.performance_finish(PERF_DECRYPT_V3, decryption_started);
        self.performance
            .decrypted_byte_count
            .fetch_add(opened.as_bytes().len() as u64, Ordering::Relaxed);
        if canonical_frame_digest_v3(
            entry.kind,
            object.segment_ordinal,
            frame_ordinal,
            &additional_aad,
            opened.as_bytes(),
        ) != entry.canonical_digest
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        Ok(OpenedObjectV3 {
            additional_aad,
            frame_nonce: sealed.header().nonce(),
            plaintext: Zeroizing::new(opened.as_bytes().to_vec()),
        })
    }

    fn scan_page(
        &self,
        page: &DurablePageV3,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        let opened = self.open_object(&page.object, page.frame_ordinal)?;
        let scan_started = self.performance_start();
        let header = opened.additional_aad;
        let plaintext = opened.plaintext;
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        if header.len() != PAGE_HEADER_BYTES_V3
            || header[0..8] != PAGE_MAGIC_V3
            || read_u16(&header, 8) != FORMAT_VERSION_V3
            || header[16..48] != *begin.result_id.as_bytes()
            || header[48..80] != begin.namespace
            || read_u64(&header, 80) != page.page_ordinal
            || header[104..136] != *page.object.prior_commitment.as_bytes()
            || header[136..160] != opened.frame_nonce
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        let count = read_u32(&header, 88) as usize;
        let entry_bytes = read_u32(&header, 92) as usize;
        let data_bytes = usize::try_from(read_u64(&header, 96))
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let data_start = entry_bytes;
        if count != page.event_count
            || entry_bytes != count.saturating_mul(PAGE_ENTRY_BYTES_V3)
            || data_start.checked_add(data_bytes) != Some(plaintext.len())
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        for index in 0..count {
            let entry = index * PAGE_ENTRY_BYTES_V3;
            if plaintext[entry + 73..entry + 80]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let local_offset = usize::try_from(read_u64(&plaintext, entry + 56))
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            let exact_len = read_u32(&plaintext, entry + 64);
            let start = data_start
                .checked_add(local_offset)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let end = start
                .checked_add(exact_len as usize)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let exact = plaintext
                .get(start..end)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let authoritative = self
                .acquisition
                .get(page.first_acquisition + index)
                .copied()
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let decoded = RetainedEventLocatorV3 {
                event_id: EventId::from_bytes(read_array(&plaintext, entry)),
                acquisition_ordinal: read_u64(&plaintext, entry + 32),
                lane_ordinal: read_u64(&plaintext, entry + 40),
                lane_sequence: read_u64(&plaintext, entry + 48),
                offset: authoritative.offset,
                exact_len,
                payload_len: read_u32(&plaintext, entry + 68),
                terminator_len: plaintext[entry + 72],
            };
            if decoded != authoritative
                || decoded.payload_len as usize + usize::from(decoded.terminator_len) != exact.len()
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            visitor(RetainedEventViewV3::new(decoded, exact))?;
        }
        self.performance_finish(PERF_PAGE_SCAN_V3, scan_started);
        Ok(())
    }

    fn write_indexes(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        let existing_index_packs = self
            .objects
            .iter()
            .filter(|object| object.kind == SnapshotObjectKindV2::EventIndex)
            .cloned()
            .collect::<Vec<_>>();
        let mut existing_cursor = 0usize;
        let orders = [
            (
                0u8,
                self.by_event
                    .iter()
                    .map(|entry| entry.1)
                    .collect::<Vec<_>>(),
            ),
            (2u8, self.by_lane.clone()),
        ];
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail/durable-packed/indexes/v3\0");
        for (kind, positions) in orders {
            let mut pack_frames = Vec::new();
            let mut pack_bytes = 0usize;
            let mut pack_first_shard = 0u64;
            for (shard, chunk) in positions.chunks(INDEX_SHARD_ENTRIES_V3).enumerate() {
                let index_started = self.performance_start();
                let width = if kind == 0 { 40 } else { 8 };
                let mut plaintext = Vec::with_capacity(32 + chunk.len() * width);
                plaintext.extend_from_slice(&INDEX_MAGIC_V3);
                plaintext.extend_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
                plaintext.push(kind);
                plaintext.extend_from_slice(&[0; 5]);
                plaintext.extend_from_slice(&(shard as u64).to_be_bytes());
                plaintext.extend_from_slice(&(chunk.len() as u64).to_be_bytes());
                for position in chunk {
                    match kind {
                        0 => {
                            let locator = self.acquisition[*position];
                            plaintext.extend_from_slice(locator.event_id.as_bytes());
                            plaintext.extend_from_slice(&(*position as u64).to_be_bytes());
                        }
                        _ => plaintext.extend_from_slice(&(*position as u64).to_be_bytes()),
                    }
                }
                hasher.update(Sha256::digest(&plaintext));
                self.performance_finish(PERF_INDEX_BUILD_V3, index_started);
                self.performance
                    .index_shard_count
                    .fetch_add(1, Ordering::Relaxed);
                if !pack_frames.is_empty()
                    && (pack_bytes.saturating_add(plaintext.len()) > INDEX_PACK_PLAINTEXT_BYTES_V3
                        || pack_frames.len() == MAX_PACK_FRAMES_V3)
                {
                    self.write_or_verify_index_pack(
                        &existing_index_packs,
                        &mut existing_cursor,
                        if kind == 0 {
                            "event-index-pack"
                        } else {
                            "lane-index-pack"
                        },
                        pack_first_shard,
                        std::mem::take(&mut pack_frames),
                    )?;
                    pack_bytes = 0;
                    pack_first_shard = shard as u64;
                }
                if pack_frames.is_empty() {
                    pack_first_shard = shard as u64;
                }
                pack_bytes = pack_bytes.saturating_add(plaintext.len());
                pack_frames.push(PendingFrameV3 {
                    kind: SnapshotObjectKindV2::EventIndex,
                    additional_aad: Vec::new(),
                    plaintext: Zeroizing::new(plaintext),
                });
            }
            if !pack_frames.is_empty() {
                self.write_or_verify_index_pack(
                    &existing_index_packs,
                    &mut existing_cursor,
                    if kind == 0 {
                        "event-index-pack"
                    } else {
                        "lane-index-pack"
                    },
                    pack_first_shard,
                    pack_frames,
                )?;
            }
        }
        if existing_cursor != existing_index_packs.len() {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        self.index_commitment = LifecycleDigestV1::from_bytes(hasher.finalize().into());
        Ok(())
    }

    fn write_or_verify_index_pack(
        &mut self,
        existing: &[DurableObjectV3],
        existing_cursor: &mut usize,
        label: &str,
        logical_ordinal: u64,
        frames: Vec<PendingFrameV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if let Some(object) = existing.get(*existing_cursor) {
            let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
            if object.frame_count != frames.len()
                || object.operation
                    != operation_id(begin.namespace, label.as_bytes(), logical_ordinal)
            {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let directory = self.open_pack_directory(object)?;
            for (frame_ordinal, expected) in frames.iter().enumerate() {
                let opened = self.open_object_from_directory(&directory, object, frame_ordinal)?;
                if opened.additional_aad != expected.additional_aad
                    || opened.plaintext.as_slice() != expected.plaintext.as_slice()
                {
                    return Err(RetainedEventStoreErrorV3::CorruptIndex);
                }
            }
            *existing_cursor += 1;
            Ok(())
        } else {
            self.write_pack(
                SnapshotObjectKindV2::EventIndex,
                label,
                logical_ordinal,
                frames,
            )?;
            Ok(())
        }
    }

    fn write_checkpoint(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        let checkpoint_started = self.performance_start();
        let mut plaintext = Vec::with_capacity(136);
        plaintext.extend_from_slice(&CHECKPOINT_MAGIC_V3);
        plaintext.extend_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
        plaintext.extend_from_slice(&[0; 6]);
        plaintext.extend_from_slice(&(self.acquisition.len() as u64).to_be_bytes());
        let source_bytes = self.acquisition.last().map_or(0, |locator| {
            locator.offset.saturating_add(u64::from(locator.exact_len))
        });
        plaintext.extend_from_slice(&source_bytes.to_be_bytes());
        plaintext.extend_from_slice(&(self.pages.len() as u64).to_be_bytes());
        plaintext.extend_from_slice(self.previous_commitment.as_bytes());
        plaintext.extend_from_slice(self.index_commitment.as_bytes());
        self.performance_finish(PERF_CHECKPOINT_BUILD_V3, checkpoint_started);
        let ordinal = self.objects.len() as u64;
        self.write_object(
            SnapshotObjectKindV2::OperationalReceipt,
            "checkpoint",
            ordinal,
            &plaintext,
        )?;
        Ok(())
    }

    fn page_for_position(
        &self,
        position: usize,
    ) -> Result<&DurablePageV3, RetainedEventStoreErrorV3> {
        self.pages
            .iter()
            .find(|page| {
                position >= page.first_acquisition
                    && position < page.first_acquisition + page.event_count
            })
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)
    }
}

impl<A: KeyAuthorityV2> RetainedEventStoreV3 for DurablePackedRepositoryV3<A> {
    fn begin(&mut self, input: RetainedStoreBeginV3) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Empty
            || input.namespace.iter().all(|byte| *byte == 0)
            || input.expires_unix_nanos <= input.created_unix_nanos
        {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        let created = i64::try_from(input.created_unix_nanos)
            .map_err(|_| RetainedEventStoreErrorV3::InvalidInput)?;
        let expires = i64::try_from(input.expires_unix_nanos)
            .map_err(|_| RetainedEventStoreErrorV3::InvalidInput)?;
        let begin_digest = derive_lifecycle_digest_v1(
            &[
                b"EVRRPV03".as_slice(),
                input.result_id.as_bytes(),
                &input.namespace,
            ]
            .concat(),
        );
        self.authority
            .begin(
                input.result_id,
                created,
                expires,
                operation_id(input.namespace, b"begin", 0),
                begin_digest,
            )
            .map_err(map_authority_error)?;
        let name = format!("{}.open", hex(input.result_id.as_bytes()));
        let path = self.root.join(name);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
                let entries = fs::read_dir(&path)
                    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
                for entry in entries {
                    if entry
                        .extension()
                        .is_some_and(|extension| extension == "tmp")
                    {
                        fs::remove_file(entry).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
                    } else {
                        return Err(RetainedEventStoreErrorV3::InvalidState);
                    }
                }
            }
            Err(_) => return Err(RetainedEventStoreErrorV3::IoFailure),
        }
        sync_directory(&path)?;
        sync_directory(&self.root)?;
        self.begin = Some(input);
        self.result_path = Some(path);
        self.state = RetainedEventStoreStateV3::Open;
        let mut descriptor = vec![0; DESCRIPTOR_HEADER_BYTES_V3];
        descriptor[0..8].copy_from_slice(&DESCRIPTOR_MAGIC_V3);
        descriptor[8..10].copy_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
        descriptor[16..48].copy_from_slice(input.result_id.as_bytes());
        descriptor[48..80].copy_from_slice(&input.namespace);
        descriptor[80..96].copy_from_slice(&input.created_unix_nanos.to_be_bytes());
        descriptor[96..112].copy_from_slice(&input.expires_unix_nanos.to_be_bytes());
        self.write_object_with_aad(
            SnapshotObjectKindV2::Request,
            "descriptor",
            0,
            &descriptor,
            &[],
        )?;
        Ok(())
    }

    fn append(&mut self, input: RetainedEventInputV3<'_>) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Open
            || input.acquisition_ordinal != self.acquisition.len() as u64
            || input.exact_bytes.len()
                != input.payload_len as usize + usize::from(input.terminator_len)
            || self.acquisition.len() as u64 >= MAX_STREAM_RECORDS_V3
        {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
        let source_bytes = self.acquisition.last().map_or(0, |locator| {
            locator.offset.saturating_add(u64::from(locator.exact_len))
        });
        let exact_len = u32::try_from(input.exact_bytes.len())
            .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?;
        if source_bytes.saturating_add(u64::from(exact_len)) > MAX_STREAM_SOURCE_BYTES_V3 {
            return Err(RetainedEventStoreErrorV3::CapacityExceeded);
        }
        let would_exceed = self.pending_first < self.acquisition.len()
            && (self.acquisition.len() - self.pending_first == MAX_EVENTS_PER_PAGE_V3
                || self
                    .pending_arena
                    .len()
                    .saturating_add(input.exact_bytes.len())
                    > TARGET_PAGE_PLAINTEXT_BYTES_V3);
        if would_exceed {
            self.flush_page()?;
        }
        self.pending_arena.extend_from_slice(input.exact_bytes);
        self.acquisition.push(RetainedEventLocatorV3 {
            event_id: input.event_id,
            acquisition_ordinal: input.acquisition_ordinal,
            lane_ordinal: input.lane_ordinal,
            lane_sequence: input.lane_sequence,
            offset: source_bytes,
            exact_len,
            payload_len: input.payload_len,
            terminator_len: input.terminator_len,
        });
        if self.acquisition.len() - self.pending_first == MAX_EVENTS_PER_PAGE_V3
            || self.pending_arena.len() >= TARGET_PAGE_PLAINTEXT_BYTES_V3
        {
            self.flush_page()?;
        }
        let total_records = self.acquisition.len() as u64;
        let total_bytes = source_bytes.saturating_add(u64::from(exact_len));
        if total_records >= self.next_checkpoint_records
            || total_bytes >= self.next_checkpoint_bytes
        {
            self.flush_page()?;
            self.flush_acquisition_pack()?;
            self.write_checkpoint()?;
            while self.next_checkpoint_records <= total_records {
                self.next_checkpoint_records = self
                    .next_checkpoint_records
                    .saturating_add(crate::CHECKPOINT_RECORD_INTERVAL_V3);
            }
            while self.next_checkpoint_bytes <= total_bytes {
                self.next_checkpoint_bytes = self
                    .next_checkpoint_bytes
                    .saturating_add(crate::CHECKPOINT_BYTE_INTERVAL_V3);
            }
        }
        Ok(())
    }

    fn finish_acquisition(
        &mut self,
        finish: RetainedAcquisitionFinishV3,
    ) -> Result<RetainedStoreManifestV3, RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Open || finish.record_count == 0 {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        if let Some(installed_manifest) = self.manifest {
            let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
            let expected = make_manifest_v3(begin, finish, &self.acquisition)?;
            if expected != installed_manifest || self.index_commitment.as_bytes() == &[0; 32] {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            if !self.final_checkpoint_present {
                self.write_checkpoint()?;
                self.final_checkpoint_present = true;
            }
            self.inject(DurablePackedFaultPointV3::BeforeDataCommit, None, 0)?;
            self.authority
                .commit_data(
                    begin.result_id,
                    operation_id(begin.namespace, b"data", 0),
                    LifecycleDigestV1::from_bytes(installed_manifest.digest()),
                    build_context_v3(),
                )
                .map_err(map_authority_error)?;
            self.inject(DurablePackedFaultPointV3::AfterDataCommit, None, 0)?;
            self.state = RetainedEventStoreStateV3::DataCommitted;
            return Ok(installed_manifest);
        }
        self.flush_page()?;
        self.flush_acquisition_pack()?;
        self.by_event = self
            .acquisition
            .iter()
            .enumerate()
            .map(|(position, locator)| (locator.event_id, position))
            .collect();
        self.by_event.sort_unstable_by_key(|entry| entry.0);
        if self.by_event.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(RetainedEventStoreErrorV3::DuplicateEvent);
        }
        self.by_lane = (0..self.acquisition.len()).collect();
        self.by_lane.sort_unstable_by_key(|position| {
            let locator = self.acquisition[*position];
            (
                locator.lane_ordinal,
                locator.lane_sequence,
                locator.acquisition_ordinal,
            )
        });
        validate_lane_order_v3(&self.acquisition, &self.by_lane)?;
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let manifest = make_manifest_v3(begin, finish, &self.acquisition)?;
        self.write_indexes()?;
        let manifest_bytes = encode_manifest_v3(manifest);
        self.write_object(
            SnapshotObjectKindV2::DataManifest,
            "manifest",
            0,
            &manifest_bytes,
        )?;
        self.write_checkpoint()?;
        self.final_checkpoint_present = true;
        self.inject(DurablePackedFaultPointV3::BeforeDataCommit, None, 0)?;
        self.authority
            .commit_data(
                begin.result_id,
                operation_id(begin.namespace, b"data", 0),
                LifecycleDigestV1::from_bytes(manifest.digest()),
                build_context_v3(),
            )
            .map_err(map_authority_error)?;
        self.inject(DurablePackedFaultPointV3::AfterDataCommit, None, 0)?;
        self.manifest = Some(manifest);
        self.state = RetainedEventStoreStateV3::DataCommitted;
        Ok(manifest)
    }

    fn acquisition_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state < RetainedEventStoreStateV3::DataCommitted {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        for page in &self.pages {
            self.scan_page(page, visitor)?;
        }
        Ok(())
    }

    fn lane_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state < RetainedEventStoreStateV3::DataCommitted {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        let mut cursor = 0usize;
        while cursor < self.by_lane.len() {
            let position = self.by_lane[cursor];
            let page = self.page_for_position(position)?;
            let lane = self.acquisition[position].lane_ordinal;
            let mut end = cursor + 1;
            while end < self.by_lane.len() {
                let candidate = self.by_lane[end];
                if self.acquisition[candidate].lane_ordinal != lane
                    || candidate < page.first_acquisition
                    || candidate >= page.first_acquisition + page.event_count
                {
                    break;
                }
                end += 1;
            }
            let wanted = self.by_lane[cursor..end]
                .iter()
                .map(|position| self.acquisition[*position].event_id)
                .collect::<std::collections::BTreeSet<_>>();
            self.scan_page(page, &mut |view| {
                if wanted.contains(&view.locator().event_id()) {
                    visitor(view)?;
                }
                Ok(())
            })?;
            cursor = end;
        }
        Ok(())
    }

    fn read_exact(
        &self,
        event_id: EventId,
    ) -> Result<Zeroizing<Vec<u8>>, RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Published {
            return Err(RetainedEventStoreErrorV3::NotPublished);
        }
        let index = self
            .by_event
            .binary_search_by_key(&event_id, |entry| entry.0)
            .map_err(|_| RetainedEventStoreErrorV3::NotFound)?;
        let position = self.by_event[index].1;
        let page = self.page_for_position(position)?;
        let mut found = None;
        self.scan_page(page, &mut |view| {
            if view.locator().event_id() == event_id {
                found = Some(Zeroizing::new(view.exact_bytes().to_vec()));
            }
            Ok(())
        })?;
        found.ok_or(RetainedEventStoreErrorV3::CorruptIndex)
    }

    fn seal_and_publish(
        &mut self,
        manifest: RetainedStoreManifestV3,
        event_ids: &[EventId],
    ) -> Result<(), RetainedEventStoreErrorV3> {
        let aliases = event_ids.to_vec();
        self.publish(manifest, &aliases, Vec::new())
    }

    fn seal_and_publish_aliases(
        &mut self,
        manifest: RetainedStoreManifestV3,
        aliases: &[RetainedPublishedAliasV3],
    ) -> Result<(), RetainedEventStoreErrorV3> {
        let event_ids = aliases
            .iter()
            .flat_map(|alias| alias.ordered_event_ids().iter().copied())
            .collect::<Vec<_>>();
        self.publish(manifest, &event_ids, aliases.to_vec())
    }

    fn recover(&mut self) -> Result<RetainedEventStoreStateV3, RetainedEventStoreErrorV3> {
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let authority = self
            .authority
            .snapshot(begin.result_id)
            .map_err(map_authority_error)?;
        let mut previous = FrameCommitmentV1::ZERO;
        for object in &self.objects {
            let bytes = fs::read(&object.path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
            if bytes.len() < evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2 {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let segment =
                SegmentHeaderV2::decode(&bytes[..evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2])
                    .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            if segment.prior_segment_commitment() != previous {
                return Err(RetainedEventStoreErrorV3::CorruptIndex);
            }
            let directory = self.open_pack_directory(object)?;
            for frame_ordinal in 0..object.frame_count {
                self.open_object_from_directory(&directory, object, frame_ordinal)?;
            }
            previous = object.commitment;
        }
        self.state = match authority.state() {
            evidentrail_snapshot_format::ResultLifecycleStateV1::Open => RetainedEventStoreStateV3::Open,
            evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted => {
                RetainedEventStoreStateV3::DataCommitted
            }
            evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed => {
                RetainedEventStoreStateV3::Sealed
            }
            evidentrail_snapshot_format::ResultLifecycleStateV1::Published => {
                RetainedEventStoreStateV3::Published
            }
        };
        Ok(self.state)
    }

    fn destroy_authority_first(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        if let Some(begin) = self.begin {
            match self.authority.destroy(begin.result_id) {
                Ok(_) | Err(KeyAuthorityErrorV2::NotFound) => {}
                Err(error) => return Err(map_authority_error(error)),
            }
            self.inject(DurablePackedFaultPointV3::AfterAuthorityDestroy, None, 0)?;
        }
        if self.result_path.is_some() {
            self.inject(DurablePackedFaultPointV3::BeforeCiphertextCleanup, None, 0)?;
        }
        if let Some(path) = self.result_path.take() {
            if path.exists() {
                fs::remove_dir_all(path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
                sync_directory(&self.root)?;
            }
        }
        self.inject(DurablePackedFaultPointV3::AfterCiphertextCleanup, None, 0)?;
        self.pending_arena.clear();
        self.acquisition.clear();
        self.by_event.clear();
        self.by_lane.clear();
        self.pages.clear();
        self.objects.clear();
        self.published_aliases.clear();
        self.manifest = None;
        self.state = RetainedEventStoreStateV3::Destroyed;
        Ok(())
    }

    fn state(&self) -> RetainedEventStoreStateV3 {
        self.state
    }
}

impl<A: KeyAuthorityV2> DurablePackedRepositoryV3<A> {
    fn publish(
        &mut self,
        manifest: RetainedStoreManifestV3,
        event_ids: &[EventId],
        aliases: Vec<RetainedPublishedAliasV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::DataCommitted
            || self.manifest != Some(manifest)
            || event_ids.iter().any(|event_id| {
                self.by_event
                    .binary_search_by_key(event_id, |entry| entry.0)
                    .is_err()
            })
        {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let mut alias_bytes = Vec::new();
        alias_bytes.extend_from_slice(&ALIAS_MAGIC_V3);
        alias_bytes.extend_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
        alias_bytes.extend_from_slice(&(aliases.len() as u64).to_be_bytes());
        for alias in &aliases {
            alias_bytes.extend_from_slice(alias.reference().id().as_bytes());
            alias_bytes.extend_from_slice(&(alias.ordered_event_ids().len() as u64).to_be_bytes());
            for event_id in alias.ordered_event_ids() {
                alias_bytes.extend_from_slice(event_id.as_bytes());
            }
        }
        let alias_digest = derive_lifecycle_digest_v1(&alias_bytes);
        self.write_object(
            SnapshotObjectKindV2::AliasManifest,
            "aliases",
            0,
            &alias_bytes,
        )?;
        let manifest_digest = LifecycleDigestV1::from_bytes(manifest.digest());
        let chain_digest = LifecycleDigestV1::from_bytes(*self.previous_commitment.as_bytes());
        let commitments = SealCommitmentsV1::new(
            manifest_digest,
            manifest_digest,
            self.index_commitment,
            chain_digest,
            alias_digest,
        );
        self.inject(DurablePackedFaultPointV3::BeforeSeal, None, 0)?;
        self.authority
            .seal(
                begin.result_id,
                operation_id(begin.namespace, b"seal", 0),
                commitments,
            )
            .map_err(map_authority_error)?;
        self.inject(DurablePackedFaultPointV3::AfterSeal, None, 0)?;
        self.state = RetainedEventStoreStateV3::Sealed;
        let repository_commitment = repository_commitment_v3(begin.result_id, &self.objects);
        let publish_operation = operation_id(begin.namespace, b"publish", 0);
        self.inject(
            DurablePackedFaultPointV3::BeforePublicationReservation,
            None,
            0,
        )?;
        let generation = self
            .authority
            .reserve_publication_generation(
                begin.result_id,
                publish_operation,
                repository_commitment,
            )
            .map_err(map_authority_error)?;
        self.inject(
            DurablePackedFaultPointV3::AfterPublicationReservation,
            None,
            generation,
        )?;
        let staging = self.result_path()?.to_path_buf();
        let final_path = self
            .root
            .join(format!("{}.published", hex(begin.result_id.as_bytes())));
        rename_create_only(&staging, &final_path)?;
        self.inject(
            DurablePackedFaultPointV3::AfterPublicationRename,
            None,
            generation,
        )?;
        sync_directory(&final_path)?;
        sync_directory(&self.root)?;
        self.inject(
            DurablePackedFaultPointV3::AfterPublicationSync,
            None,
            generation,
        )?;
        for object in &mut self.objects {
            if let Some(name) = object.path.file_name() {
                object.path = final_path.join(name);
            }
        }
        for page in &mut self.pages {
            if let Some(name) = page.object.path.file_name() {
                page.object.path = final_path.join(name);
            }
        }
        self.result_path = Some(final_path);
        self.authority
            .publish(
                begin.result_id,
                publish_operation,
                generation,
                repository_commitment,
            )
            .map_err(map_authority_error)?;
        self.inject(
            DurablePackedFaultPointV3::AfterAuthorityPublish,
            None,
            generation,
        )?;
        self.published_aliases = aliases;
        self.state = RetainedEventStoreStateV3::Published;
        Ok(())
    }
}

fn build_context_v3() -> evidentrail_snapshot_format::BuildContextDigestsV1 {
    let digest = |value: &[u8]| derive_lifecycle_digest_v1(value);
    evidentrail_snapshot_format::BuildContextDigestsV1::new(
        digest(b"evidentrail-compile/streaming/v3"),
        digest(b"evidentrail-evidence/log-brief/v1"),
        digest(b"evidentrail-evidence/utf8-byte-tokenizer/v1"),
        digest(b"evidentrail-product/authorized-stream/v3"),
        digest(b"evidentrail-store/durable-packed/v3"),
    )
}

fn encode_manifest_v3(manifest: RetainedStoreManifestV3) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(200);
    bytes.extend_from_slice(&MANIFEST_MAGIC_V3);
    bytes.extend_from_slice(&FORMAT_VERSION_V3.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(manifest.result_id().as_bytes());
    bytes.extend_from_slice(&manifest.namespace());
    bytes.extend_from_slice(&manifest.digest());
    bytes.extend_from_slice(&manifest.record_count().to_be_bytes());
    bytes.extend_from_slice(&manifest.payload_byte_count().to_be_bytes());
    bytes.extend_from_slice(&manifest.source_byte_count().to_be_bytes());
    bytes.extend_from_slice(&manifest.input_digest());
    bytes.extend_from_slice(&manifest.completion_digest());
    bytes
}

fn decode_manifest_v3(
    begin: RetainedStoreBeginV3,
    acquisition: &[RetainedEventLocatorV3],
    bytes: &[u8],
) -> Result<RetainedStoreManifestV3, RetainedEventStoreErrorV3> {
    if bytes.len() != 200
        || bytes[0..8] != MANIFEST_MAGIC_V3
        || read_u16(bytes, 8) != FORMAT_VERSION_V3
        || bytes[10..16].iter().any(|byte| *byte != 0)
        || bytes[16..48] != *begin.result_id.as_bytes()
        || bytes[48..80] != begin.namespace
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let expected_digest: [u8; 32] = read_array(bytes, 80);
    let manifest = make_manifest_v3(
        begin,
        RetainedAcquisitionFinishV3 {
            record_count: read_u64(bytes, 112),
            payload_byte_count: read_u64(bytes, 120),
            source_byte_count: read_u64(bytes, 128),
            input_digest: read_array(bytes, 136),
            completion_digest: read_array(bytes, 168),
        },
        acquisition,
    )?;
    if manifest.digest() != expected_digest {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    Ok(manifest)
}

fn read_raw_object_file_v3(path: &Path) -> Result<RawObjectFileV3, RetainedEventStoreErrorV3> {
    let bytes = fs::read(path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    let segment_end = evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2;
    if bytes.len() < segment_end + PACK_HEADER_BYTES_V3 + PACK_FOOTER_BYTES_V3 {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let segment = SegmentHeaderV2::decode(&bytes[..segment_end])
        .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
    let header: [u8; PACK_HEADER_BYTES_V3] = bytes[segment_end..segment_end + PACK_HEADER_BYTES_V3]
        .try_into()
        .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
    if header[0..8] != PACK_MAGIC_V3
        || read_u16(&header, 8) != PACK_LAYOUT_VERSION_V3
        || header[12..16]
            .iter()
            .chain(header[216..224].iter())
            .any(|byte| *byte != 0)
        || header[16..48] != *segment.result_id().as_bytes()
        || read_u64(&header, 80) != segment.segment_ordinal()
        || header[104..136] != *segment.prior_segment_commitment().as_bytes()
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let kind = snapshot_object_kind_v3(read_u16(&header, 10))?;
    if kind == SnapshotObjectKindV2::EventIndexDirectory {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let frame_count = read_u32(&header, 96) as usize;
    let expected_directory_plaintext = PACK_DIRECTORY_HEADER_BYTES_V3
        .checked_add(frame_count.saturating_mul(PACK_DIRECTORY_ENTRY_BYTES_V3))
        .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
    if frame_count == 0
        || frame_count > MAX_PACK_FRAMES_V3
        || read_u32(&header, 100) as usize != expected_directory_plaintext
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let footer_start = bytes.len() - PACK_FOOTER_BYTES_V3;
    let footer = &bytes[footer_start..];
    if footer[0..8] != PACK_FOOTER_MAGIC_V3
        || read_u16(footer, 8) != PACK_LAYOUT_VERSION_V3
        || footer[10..16].iter().any(|byte| *byte != 0)
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let directory_offset = read_u64(footer, 16);
    let directory_length = read_u64(footer, 24);
    if directory_offset
        < (evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2 + PACK_HEADER_BYTES_V3) as u64
        || directory_offset
            .checked_add(directory_length)
            .and_then(|end| end.checked_add(PACK_FOOTER_BYTES_V3 as u64))
            != Some(bytes.len() as u64)
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let binding_digest = LifecycleDigestV1::from_bytes(read_array(&header, 168));
    let operation = OperationIdV1::from_bytes(read_array(&header, 200));
    if binding_digest.as_bytes().iter().all(|byte| *byte == 0) || operation.is_zero() {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let mut binding = Sha256::new();
    binding.update(b"evidentrail/durable-packed/pack-reservation/v4\0");
    binding.update(&header[16..48]);
    binding.update(&header[48..80]);
    binding.update(&header[10..12]);
    binding.update(&header[80..88]);
    binding.update(&header[88..96]);
    binding.update((frame_count as u64).to_be_bytes());
    binding.update(&header[136..168]);
    binding.update(&header[104..136]);
    if binding.finalize().as_slice() != binding_digest.as_bytes() {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    Ok(RawObjectFileV3 {
        segment,
        header,
        kind,
        frame_count,
        directory_offset,
        directory_length,
        commitment: FrameCommitmentV1::from_bytes(read_array(footer, 32)),
        binding_digest,
        operation,
    })
}

fn canonical_frame_digest_v3(
    kind: SnapshotObjectKindV2,
    pack_ordinal: u64,
    frame_ordinal: usize,
    additional_aad: &[u8],
    plaintext: &[u8],
) -> [u8; 32] {
    let mut normalized_aad = additional_aad.to_vec();
    if kind == SnapshotObjectKindV2::AuthorizedEvent && normalized_aad.len() == PAGE_HEADER_BYTES_V3
    {
        normalized_aad[136..160].fill(0);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/durable-packed/canonical-frame/v4\0");
    hasher.update(kind.code().to_be_bytes());
    hasher.update(pack_ordinal.to_be_bytes());
    hasher.update((frame_ordinal as u64).to_be_bytes());
    hasher.update((normalized_aad.len() as u64).to_be_bytes());
    hasher.update(Sha256::digest(&normalized_aad));
    hasher.update((plaintext.len() as u64).to_be_bytes());
    hasher.update(Sha256::digest(plaintext));
    hasher.finalize().into()
}

fn pack_frame_aad_v3(pack_header: &[u8; PACK_HEADER_BYTES_V3], additional_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PACK_HEADER_BYTES_V3 + 8 + additional_aad.len());
    aad.extend_from_slice(pack_header);
    aad.extend_from_slice(&(additional_aad.len() as u64).to_be_bytes());
    aad.extend_from_slice(additional_aad);
    aad
}

fn pack_directory_aad_v3(pack_header: &[u8; PACK_HEADER_BYTES_V3]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PACK_HEADER_BYTES_V3 + 32);
    aad.extend_from_slice(pack_header);
    aad.extend_from_slice(b"evidentrail/pack-directory/v4\0");
    aad
}

fn encode_pack_directory_v3(entries: &[PackDirectoryEntryV3]) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        PACK_DIRECTORY_HEADER_BYTES_V3 + entries.len() * PACK_DIRECTORY_ENTRY_BYTES_V3,
    ));
    encoded.extend_from_slice(&PACK_DIRECTORY_MAGIC_V3);
    encoded.extend_from_slice(&PACK_LAYOUT_VERSION_V3.to_be_bytes());
    encoded.extend_from_slice(&[0; 6]);
    encoded.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&[0; 12]);
    for entry in entries {
        encoded.extend_from_slice(&entry.offset.to_be_bytes());
        encoded.extend_from_slice(&entry.length.to_be_bytes());
        encoded.extend_from_slice(&entry.kind.code().to_be_bytes());
        encoded.extend_from_slice(&[0; 6]);
        encoded.extend_from_slice(&entry.canonical_digest);
        encoded.extend_from_slice(entry.commitment.as_bytes());
    }
    encoded
}

fn decode_pack_directory_v3(
    encoded: &[u8],
    expected_count: usize,
) -> Result<Vec<PackDirectoryEntryV3>, RetainedEventStoreErrorV3> {
    if encoded.len()
        != PACK_DIRECTORY_HEADER_BYTES_V3
            .saturating_add(expected_count.saturating_mul(PACK_DIRECTORY_ENTRY_BYTES_V3))
        || encoded[0..8] != PACK_DIRECTORY_MAGIC_V3
        || read_u16(encoded, 8) != PACK_LAYOUT_VERSION_V3
        || encoded[10..16]
            .iter()
            .chain(encoded[20..32].iter())
            .any(|byte| *byte != 0)
        || read_u32(encoded, 16) as usize != expected_count
    {
        return Err(RetainedEventStoreErrorV3::CorruptIndex);
    }
    let mut entries = Vec::with_capacity(expected_count);
    for index in 0..expected_count {
        let start = PACK_DIRECTORY_HEADER_BYTES_V3 + index * PACK_DIRECTORY_ENTRY_BYTES_V3;
        if encoded[start + 18..start + 24]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        entries.push(PackDirectoryEntryV3 {
            offset: read_u64(encoded, start),
            length: read_u64(encoded, start + 8),
            kind: snapshot_object_kind_v3(read_u16(encoded, start + 16))?,
            canonical_digest: read_array(encoded, start + 24),
            commitment: FrameCommitmentV1::from_bytes(read_array(encoded, start + 56)),
        });
    }
    Ok(entries)
}

fn snapshot_object_kind_v3(code: u16) -> Result<SnapshotObjectKindV2, RetainedEventStoreErrorV3> {
    match code {
        1 => Ok(SnapshotObjectKindV2::Request),
        2 => Ok(SnapshotObjectKindV2::AuthorizedEvent),
        3 => Ok(SnapshotObjectKindV2::SemanticReceipt),
        4 => Ok(SnapshotObjectKindV2::OperationalReceipt),
        5 => Ok(SnapshotObjectKindV2::DataManifest),
        6 => Ok(SnapshotObjectKindV2::EventIndex),
        7 => Ok(SnapshotObjectKindV2::Product),
        8 => Ok(SnapshotObjectKindV2::FinalManifest),
        9 => Ok(SnapshotObjectKindV2::AliasManifest),
        10 => Ok(SnapshotObjectKindV2::EventIndexDirectory),
        _ => Err(RetainedEventStoreErrorV3::CorruptIndex),
    }
}

fn repository_commitment_v3(result_id: ResultId, objects: &[DurableObjectV3]) -> LifecycleDigestV1 {
    let mut repository = Sha256::new();
    repository.update(b"evidentrail/durable-packed/repository/v3\0");
    repository.update(result_id.as_bytes());
    for object in objects {
        repository.update(object.commitment.as_bytes());
    }
    LifecycleDigestV1::from_bytes(repository.finalize().into())
}

fn map_authority_state(
    state: evidentrail_snapshot_format::ResultLifecycleStateV1,
) -> RetainedEventStoreStateV3 {
    match state {
        evidentrail_snapshot_format::ResultLifecycleStateV1::Open => RetainedEventStoreStateV3::Open,
        evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted => {
            RetainedEventStoreStateV3::DataCommitted
        }
        evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed => RetainedEventStoreStateV3::Sealed,
        evidentrail_snapshot_format::ResultLifecycleStateV1::Published => {
            RetainedEventStoreStateV3::Published
        }
    }
}

fn operation_id(namespace: [u8; 32], label: &[u8], ordinal: u64) -> OperationIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/durable-packed/operation/v3\0");
    hasher.update(namespace);
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(ordinal.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    OperationIdV1::from_bytes(bytes)
}

fn map_authority_error(error: KeyAuthorityErrorV2) -> RetainedEventStoreErrorV3 {
    match error {
        KeyAuthorityErrorV2::Locked => RetainedEventStoreErrorV3::AuthorityLocked,
        KeyAuthorityErrorV2::Unavailable => RetainedEventStoreErrorV3::AuthorityUnavailable,
        KeyAuthorityErrorV2::CapacityExceeded | KeyAuthorityErrorV2::NonceNamespaceExhausted => {
            RetainedEventStoreErrorV3::CapacityExceeded
        }
        KeyAuthorityErrorV2::NotFound => RetainedEventStoreErrorV3::NotFound,
        KeyAuthorityErrorV2::OperationConflict | KeyAuthorityErrorV2::InvalidTransition => {
            RetainedEventStoreErrorV3::CorruptIndex
        }
        _ => RetainedEventStoreErrorV3::IoFailure,
    }
}

fn sync_file(file: &File) -> Result<(), RetainedEventStoreErrorV3> {
    file.sync_all()
        .map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    #[cfg(target_os = "macos")]
    rfs::fcntl_fullfsync(file).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), RetainedEventStoreErrorV3> {
    let directory = File::open(path).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    sync_file(&directory)
}

fn rename_create_only(source: &Path, destination: &Path) -> Result<(), RetainedEventStoreErrorV3> {
    let source_parent = source
        .parent()
        .ok_or(RetainedEventStoreErrorV3::IoFailure)?;
    let destination_parent = destination
        .parent()
        .ok_or(RetainedEventStoreErrorV3::IoFailure)?;
    let source_directory =
        File::open(source_parent).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    let destination_directory =
        File::open(destination_parent).map_err(|_| RetainedEventStoreErrorV3::IoFailure)?;
    rfs::renameat_with(
        &source_directory,
        source
            .file_name()
            .ok_or(RetainedEventStoreErrorV3::IoFailure)?,
        &destination_directory,
        destination
            .file_name()
            .ok_or(RetainedEventStoreErrorV3::IoFailure)?,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| RetainedEventStoreErrorV3::IoFailure)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
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
    bytes[offset..offset + N]
        .try_into()
        .expect("validated fixed-width object")
}
