#![cfg(feature = "internal-test-provider")]

use std::collections::VecDeque;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use evidentrail_core::{EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1};
use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt,
    AcquisitionReceiptId, AdapterIdentity, AdapterOutcome, AttemptCounts, CompletenessProof,
    EventId, ExactnessBasis, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchTiming, PlanDigest, PlanId, PolicyDigest, ResultId, RetrievalId, SourceIdentityDigest,
    SourceRecordId, TransformationReceiptId, UnixTimestampNanos,
};
use evidentrail_snapshot_format::{
    AcquisitionCompletionRecordV1, AuthorizedByteRangeV1, CoreManifestComponentsV1,
    CoreResultManifestV1, EntropySourceFailureV1, EntropySourceV1, EventExpansionIndexEntryV1,
    EventExpansionIndexV1, EventFrameLocatorV1, ExpectedCoreResultManifestContextV1,
    FRAME_HEADER_BYTES_V1, FrameCommitmentV1, FrameObjectKindV1, MAX_FRAME_PLAINTEXT_BYTES_V1,
    RESULT_KEY_RECORD_BYTES_V1, SEGMENT_HEADER_BYTES_V1, SegmentCatalogEntryV1, SegmentCatalogV1,
    SegmentDigestV1, SourceOutcomeTableV1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, AuthenticatedFilesystemRecoveryDispositionV1,
    AuthenticatedFilesystemRestartCoordinatorV1, AuthenticatedFilesystemRestartErrorV1,
    CreatingKeyContextV1, DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1, DisplayedAliasManifestEntryV1,
    DisplayedAliasManifestErrorV1, DisplayedAliasManifestV1, EncryptedCoreResultDestroyOutcomeV1,
    EncryptedCoreResultFrameLocatorV1, EncryptedCoreResultRepositoryErrorV1,
    EphemeralKeyProviderV1, EvidenceAliasV1, ExpansionLimitV1, FilesystemBundleFaultPointV1,
    FilesystemBundleOperationV1, FilesystemBundleRecoveryClassificationV1,
    FilesystemSealedBundleErrorV1, FilesystemSealedBundleStoreV1, KeyProviderErrorV1,
    KeyProviderV1, MAX_MEMORY_ENCRYPTED_CORE_RESULTS_V1, MemoryEncryptedCoreResultRepositoryV1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1,
    SealedEncryptedCoreResultBundleErrorV1, SealedEncryptedCoreResultBundleV1,
    sealed_bundle_filename_v1, sealed_bundle_temporary_filename_v1,
};
use sha2::{Digest, Sha256};

enum EntropyStep {
    Bytes(Vec<u8>),
    Unavailable,
}

struct ScriptedEntropy {
    steps: VecDeque<EntropyStep>,
}

impl ScriptedEntropy {
    fn new(steps: impl IntoIterator<Item = EntropyStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }
}

impl EntropySourceV1 for ScriptedEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
        match self.steps.pop_front() {
            Some(EntropyStep::Bytes(bytes)) if bytes.len() == destination.len() => {
                destination.copy_from_slice(&bytes);
                Ok(())
            }
            Some(EntropyStep::Bytes(_)) | Some(EntropyStep::Unavailable) | None => {
                Err(EntropySourceFailureV1::Unavailable)
            }
        }
    }
}

fn bytes(length: usize, value: u8) -> EntropyStep {
    EntropyStep::Bytes(vec![value; length])
}

fn entropy_for_results(result_count: usize) -> Vec<EntropyStep> {
    let mut steps = vec![bytes(32, 0x11)];
    for index in 0..result_count {
        let seed = u8::try_from(index).unwrap();
        steps.extend([
            bytes(32, 0x21 + seed),
            bytes(24, 0x31 + seed),
            bytes(24, 0x41 + seed),
            bytes(24, 0x51 + seed),
        ]);
    }
    steps
}

type Repository = MemoryEncryptedCoreResultRepositoryV1<EphemeralKeyProviderV1<ScriptedEntropy>>;
type SharedProvider = Arc<EphemeralKeyProviderV1<ScriptedEntropy>>;
type SharedRepository = MemoryEncryptedCoreResultRepositoryV1<SharedProvider>;

fn repository(result_count: usize) -> Repository {
    let provider =
        EphemeralKeyProviderV1::new(ScriptedEntropy::new(entropy_for_results(result_count)), 16)
            .unwrap();
    MemoryEncryptedCoreResultRepositoryV1::new(provider, 16).unwrap()
}

fn frame_repository(frame_nonce_counts: &[usize]) -> Repository {
    let mut steps = vec![bytes(32, 0x11)];
    for (result_index, frame_nonce_count) in frame_nonce_counts.iter().copied().enumerate() {
        let result_seed = u8::try_from(result_index).unwrap();
        steps.extend([bytes(32, 0x21 + result_seed), bytes(24, 0x31 + result_seed)]);
        for frame_index in 0..frame_nonce_count {
            let frame_seed = u8::try_from(frame_index).unwrap();
            steps.push(bytes(24, 0x41 + result_seed * 8 + frame_seed));
        }
        steps.extend([bytes(24, 0x71 + result_seed), bytes(24, 0x79 + result_seed)]);
    }
    let provider = EphemeralKeyProviderV1::new(ScriptedEntropy::new(steps), 16).unwrap();
    MemoryEncryptedCoreResultRepositoryV1::new(provider, 16).unwrap()
}

fn shared_frame_repositories(frame_nonce_counts: &[usize]) -> (SharedRepository, SharedRepository) {
    let mut steps = vec![bytes(32, 0x11)];
    for (result_index, frame_nonce_count) in frame_nonce_counts.iter().copied().enumerate() {
        let result_seed = u8::try_from(result_index).unwrap();
        steps.extend([bytes(32, 0x21 + result_seed), bytes(24, 0x31 + result_seed)]);
        for frame_index in 0..frame_nonce_count {
            let frame_seed = u8::try_from(frame_index).unwrap();
            steps.push(bytes(24, 0x41 + result_seed * 8 + frame_seed));
        }
        steps.extend([bytes(24, 0x71 + result_seed), bytes(24, 0x79 + result_seed)]);
    }
    let provider = Arc::new(EphemeralKeyProviderV1::new(ScriptedEntropy::new(steps), 16).unwrap());
    (
        MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 16).unwrap(),
        MemoryEncryptedCoreResultRepositoryV1::new(provider, 16).unwrap(),
    )
}

fn repository_with_steps(steps: impl IntoIterator<Item = EntropyStep>) -> Repository {
    let provider = EphemeralKeyProviderV1::new(ScriptedEntropy::new(steps), 16).unwrap();
    MemoryEncryptedCoreResultRepositoryV1::new(provider, 16).unwrap()
}

struct Fixture {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    manifest: CoreResultManifestV1,
}

#[derive(Clone, Copy)]
struct TestPersistedEvent {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
}

struct StagingFixture {
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    retrieval_id: RetrievalId,
    receipt: AcquisitionReceipt,
}

impl StagingFixture {
    fn key_context(&self) -> CreatingKeyContextV1 {
        CreatingKeyContextV1::new(self.result_id, 1_000, 2_000).unwrap()
    }

    fn expected_context(&self) -> ExpectedCoreResultManifestContextV1 {
        ExpectedCoreResultManifestContextV1::new(
            self.result_id,
            self.source_identity_digest,
            self.acquisition_receipt_id,
            1_000,
            2_000,
        )
        .unwrap()
    }

    fn manifest(
        &self,
        catalog: &SegmentCatalogV1,
        index: &EventExpansionIndexV1,
    ) -> CoreResultManifestV1 {
        let outcomes = SourceOutcomeTableV1::new(&self.receipt, index).unwrap();
        let completion = completion_with_records(
            self.retrieval_id,
            u64::try_from(self.receipt.entries().len()).unwrap(),
        );
        let components =
            CoreManifestComponentsV1::new(catalog, index, &outcomes, &completion).unwrap();
        CoreResultManifestV1::new(
            self.result_id,
            self.source_identity_digest,
            self.acquisition_receipt_id,
            &components,
        )
        .unwrap()
    }
}

fn staging_fixture(seed: u8, events: &[TestPersistedEvent]) -> StagingFixture {
    let retrieval_id = RetrievalId::from_bytes([0x30 + seed; 32]);
    let mut source_records = Vec::with_capacity(events.len());
    let mut assignments = Vec::with_capacity(events.len());
    for (ordinal, event) in events.iter().copied().enumerate() {
        let mut source_record_bytes = [0x40 + seed; 32];
        source_record_bytes[30..32].copy_from_slice(&u16::try_from(ordinal).unwrap().to_be_bytes());
        let source_record_id = SourceRecordId::from_bytes(source_record_bytes);
        source_records.push(source_record_id);
        assignments.push(AcquisitionOutcomeAssignment::new(
            source_record_id,
            AcquisitionOutcome::Persisted {
                event_id: event.event_id,
                exactness_basis: event.exactness_basis,
            },
        ));
    }
    let receipt = AcquisitionReceipt::reconcile(retrieval_id, source_records, assignments).unwrap();
    StagingFixture {
        result_id: ResultId::from_bytes([0x80 + seed; 32]),
        source_identity_digest: SourceIdentityDigest::from_bytes([0x90 + seed; 32]),
        acquisition_receipt_id: derive_receipt_id(&receipt),
        retrieval_id,
        receipt,
    }
}

impl Fixture {
    fn key_context(&self) -> CreatingKeyContextV1 {
        CreatingKeyContextV1::new(self.result_id, 1_000, 2_000).unwrap()
    }

    fn expected_context(&self) -> ExpectedCoreResultManifestContextV1 {
        ExpectedCoreResultManifestContextV1::new(
            self.result_id,
            self.source_identity_digest,
            self.acquisition_receipt_id,
            1_000,
            2_000,
        )
        .unwrap()
    }
}

fn fixture(seed: u8) -> Fixture {
    fixture_with_catalog(seed, one_catalog(0x20 + seed), 108, 0)
}

fn fixture_with_catalog(
    seed: u8,
    catalog: SegmentCatalogV1,
    first_frame_encoded_length: u32,
    authorized_byte_length: u32,
) -> Fixture {
    let result_id = ResultId::from_bytes([0x80 + seed; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x90 + seed; 32]);
    let retrieval_id = RetrievalId::from_bytes([0x30 + seed; 32]);
    let exactness = fixture_exactness(seed);
    let event_id = fixture_event_id(seed);
    let source_record_id = SourceRecordId::from_bytes([0x40 + seed; 32]);
    let index = EventExpansionIndexV1::new(
        &catalog,
        vec![
            EventExpansionIndexEntryV1::new(
                &catalog,
                event_id,
                EventFrameLocatorV1::new(
                    0,
                    0,
                    0,
                    SEGMENT_HEADER_BYTES_V1 as u64,
                    first_frame_encoded_length,
                )
                .unwrap(),
                AuthorizedByteRangeV1::new(0, authorized_byte_length).unwrap(),
                exactness,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let receipt = AcquisitionReceipt::reconcile(
        retrieval_id,
        [source_record_id],
        [AcquisitionOutcomeAssignment::new(
            source_record_id,
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis: exactness,
            },
        )],
    )
    .unwrap();
    let acquisition_receipt_id = derive_receipt_id(&receipt);
    let outcomes = SourceOutcomeTableV1::new(&receipt, &index).unwrap();
    let completion = completion(retrieval_id);
    let components =
        CoreManifestComponentsV1::new(&catalog, &index, &outcomes, &completion).unwrap();
    let manifest = CoreResultManifestV1::new(
        result_id,
        source_identity_digest,
        acquisition_receipt_id,
        &components,
    )
    .unwrap();
    Fixture {
        result_id,
        source_identity_digest,
        acquisition_receipt_id,
        manifest,
    }
}

fn fixture_event_id(seed: u8) -> EventId {
    EventId::from_bytes([0x50 + seed; 32])
}

fn fixture_exactness(seed: u8) -> ExactnessBasis {
    ExactnessBasis::PostPolicy {
        policy_digest: PolicyDigest::from_bytes([0x60 + seed; 32]),
        transformation_receipt_id: TransformationReceiptId::from_bytes([0x70 + seed; 32]),
    }
}

fn stage_fixture_frame<P: KeyProviderV1>(
    repository: &MemoryEncryptedCoreResultRepositoryV1<P>,
    seed: u8,
    result_id: &ResultId,
    object_kind: FrameObjectKindV1,
    plaintext: &[u8],
) -> evidentrail_store::EncryptedCoreResultFramePublicationV1 {
    match object_kind {
        FrameObjectKindV1::AuthorizedOutcome => repository
            .stage_authorized_event(
                result_id,
                fixture_event_id(seed),
                fixture_exactness(seed),
                plaintext,
            )
            .unwrap()
            .frame(),
        FrameObjectKindV1::AcquisitionSeal => repository
            .stage_frame(result_id, object_kind, plaintext)
            .unwrap(),
    }
}

fn one_catalog(seed: u8) -> SegmentCatalogV1 {
    let ciphertext_bytes = 16u64;
    let encoded_bytes =
        SEGMENT_HEADER_BYTES_V1 as u64 + FRAME_HEADER_BYTES_V1 as u64 + ciphertext_bytes;
    SegmentCatalogV1::new(vec![
        SegmentCatalogEntryV1::new(
            0,
            0,
            1,
            encoded_bytes,
            ciphertext_bytes,
            SegmentDigestV1::from_bytes([seed; 32]),
            FrameCommitmentV1::from_bytes([seed.wrapping_add(1); 32]),
        )
        .unwrap(),
    ])
    .unwrap()
}

fn completion(retrieval_id: RetrievalId) -> AcquisitionCompletionRecordV1 {
    completion_with_records(retrieval_id, 1)
}

fn completion_with_records(
    retrieval_id: RetrievalId,
    acknowledged_records: u64,
) -> AcquisitionCompletionRecordV1 {
    let completion = FetchCompletion::new(
        FetchIdentity::new(
            retrieval_id,
            PlanId::from_bytes([0x11; 32]),
            PlanDigest::from_bytes([0x12; 32]),
            AdapterIdentity::new("local_file", "1").unwrap(),
        ),
        FetchTiming::new(UnixTimestampNanos::new(10), UnixTimestampNanos::new(20)),
        AcknowledgedCounts::new(acknowledged_records, 0, 0),
        AttemptCounts::default(),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::FixedSnapshotVerified),
    )
    .unwrap();
    AcquisitionCompletionRecordV1::new(&completion).unwrap()
}

fn derive_receipt_id(receipt: &AcquisitionReceipt) -> AcquisitionReceiptId {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, b"evidentrail/acquisition-receipt/v1");
    update_field(&mut hasher, receipt.retrieval_id().as_bytes());
    for entry in receipt.entries() {
        update_field(&mut hasher, entry.source_record_id().as_bytes());
        update_field(&mut hasher, entry.outcome().code().as_bytes());
        match entry.outcome() {
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis,
            } => {
                update_field(&mut hasher, event_id.as_bytes());
                if let ExactnessBasis::PostPolicy {
                    policy_digest,
                    transformation_receipt_id,
                } = exactness_basis
                {
                    update_field(&mut hasher, policy_digest.as_bytes());
                    update_field(&mut hasher, transformation_receipt_id.as_bytes());
                }
            }
            AcquisitionOutcome::OmittedByPolicy { policy_digest } => {
                update_field(&mut hasher, policy_digest.as_bytes());
            }
        }
    }
    AcquisitionReceiptId::from_bytes(hasher.finalize().into())
}

fn update_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn stage_and_seal_frames<P: KeyProviderV1>(
    repository: &MemoryEncryptedCoreResultRepositoryV1<P>,
    seed: u8,
    frames: &[(bool, FrameObjectKindV1, Vec<u8>)],
) -> (
    Fixture,
    Vec<evidentrail_store::EncryptedCoreResultFramePublicationV1>,
) {
    assert!(!frames.is_empty());
    let authority = fixture(seed);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let mut publications = Vec::with_capacity(frames.len());
    for (rotate_before, object_kind, plaintext) in frames {
        if *rotate_before {
            repository
                .rotate_staged_segment(&authority.result_id)
                .unwrap();
        }
        publications.push(stage_fixture_frame(
            repository,
            seed,
            &authority.result_id,
            *object_kind,
            plaintext,
        ));
    }
    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    let exact = fixture_with_catalog(
        seed,
        catalog,
        publications[0].encoded_byte_count(),
        u32::try_from(frames[0].2.len()).unwrap(),
    );
    assert_eq!(
        exact.acquisition_receipt_id,
        authority.acquisition_receipt_id
    );
    repository
        .seal_staged_result(&exact.result_id, &exact.manifest)
        .unwrap();
    assert_eq!(
        repository
            .provider_for_test()
            .issue_snapshot_frame_nonce(&exact.result_id),
        Err(KeyProviderErrorV1::Unavailable)
    );
    (exact, publications)
}

fn stage_and_seal_events<P: KeyProviderV1>(
    repository: &MemoryEncryptedCoreResultRepositoryV1<P>,
    seed: u8,
    events: &[(bool, TestPersistedEvent, Vec<u8>)],
) -> (
    StagingFixture,
    Vec<evidentrail_store::EncryptedCoreResultEventPublicationV1>,
) {
    let event_material = events
        .iter()
        .map(|(_, event, _)| *event)
        .collect::<Vec<_>>();
    let authority = staging_fixture(seed, &event_material);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let mut publications = Vec::with_capacity(events.len());
    for (rotate_before, event, bytes) in events {
        if *rotate_before {
            repository
                .rotate_staged_segment(&authority.result_id)
                .unwrap();
        }
        publications.push(
            repository
                .stage_authorized_event(
                    &authority.result_id,
                    event.event_id,
                    event.exactness_basis,
                    bytes,
                )
                .unwrap(),
        );
    }
    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    let index = repository
        .staged_event_expansion_index(&authority.result_id)
        .unwrap();
    let manifest = authority.manifest(&catalog, &index);
    repository
        .seal_staged_result(&authority.result_id, &manifest)
        .unwrap();
    (authority, publications)
}

fn stage_and_seal_alias_result<P: KeyProviderV1>(
    repository: &MemoryEncryptedCoreResultRepositoryV1<P>,
    seed: u8,
    events: &[(TestPersistedEvent, Vec<u8>)],
) -> (StagingFixture, EvidenceReferenceV1) {
    let event_material = events.iter().map(|(event, _)| *event).collect::<Vec<_>>();
    let authority = staging_fixture(seed, &event_material);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    for (event, bytes) in events {
        repository
            .stage_authorized_event(
                &authority.result_id,
                event.event_id,
                event.exactness_basis,
                bytes,
            )
            .unwrap();
    }
    let event_ids = event_material
        .iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    let reference = EvidenceReferenceV1::issue(
        authority.result_id,
        event_ids.iter().copied().map(EvidenceTargetRef::Event),
        [
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
        ],
        UnixTimestampNanos::new(1_100),
        UnixTimestampNanos::new(2_000),
    )
    .unwrap();
    let alias_manifest =
        DisplayedAliasManifestV1::new(
            authority.result_id,
            UnixTimestampNanos::new(2_000),
            [DisplayedAliasManifestEntryV1::new(
                authority.result_id,
                1,
                reference.clone(),
                event_ids,
            )
            .unwrap()],
        )
        .unwrap();
    repository
        .stage_displayed_alias_manifest(&authority.result_id, &alias_manifest)
        .unwrap();
    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    let index = repository
        .staged_event_expansion_index(&authority.result_id)
        .unwrap();
    let manifest = authority.manifest(&catalog, &index);
    repository
        .seal_staged_result(&authority.result_id, &manifest)
        .unwrap();
    (authority, reference)
}

#[test]
fn failed_final_publication_aborts_staging_and_leaves_no_openable_result() {
    let repository = frame_repository(&[1]);
    let authority = fixture(31);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let frame = stage_fixture_frame(
        &repository,
        31,
        &authority.result_id,
        FrameObjectKindV1::AuthorizedOutcome,
        b"verified-but-never-published",
    );
    let exact = fixture_with_catalog(
        31,
        repository
            .staged_segment_catalog(&authority.result_id)
            .unwrap(),
        frame.encoded_byte_count(),
        28,
    );
    repository.fail_next_publication_for_test().unwrap();

    assert_eq!(
        repository.seal_staged_result(&exact.result_id, &exact.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed)
    );
    assert_eq!(repository.len(), Ok(0));
    assert_eq!(
        repository
            .open_stored_frame(exact.expected_context(), frame.locator())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    assert_eq!(
        repository.begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
}

#[test]
fn destroying_private_staging_releases_it_without_ever_publishing_an_alias() {
    let repository = frame_repository(&[1]);
    let authority = fixture(32);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let frame = stage_fixture_frame(
        &repository,
        32,
        &authority.result_id,
        FrameObjectKindV1::AuthorizedOutcome,
        b"private-staging-only",
    );

    assert_eq!(
        repository.destroy(&authority.result_id),
        Ok(EncryptedCoreResultDestroyOutcomeV1::Destroyed)
    );
    assert_eq!(repository.len(), Ok(0));
    assert_eq!(
        repository
            .open_stored_frame(authority.expected_context(), frame.locator())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
}

#[test]
fn complete_transaction_publishes_only_sealed_authority_and_opens_exactly() {
    let repository = repository(1);
    let fixture = fixture(1);
    let exact_manifest = fixture.manifest.encode();
    let publication = repository
        .create_sealed_result(&fixture.key_context(), &fixture.manifest)
        .unwrap();
    assert_eq!(publication.result_id(), fixture.result_id);
    assert_eq!(repository.len().unwrap(), 1);
    let provider_record = repository
        .provider_for_test()
        .open_result_key(
            &fixture.result_id,
            &fixture.key_context().expected_context(),
        )
        .unwrap();
    assert_eq!(
        provider_record.state(),
        evidentrail_snapshot_format::ResultKeyRecordStateV1::Sealed
    );
    let binding = provider_record.seal_binding().unwrap();
    assert_eq!(
        binding.manifest_commitment(),
        publication.manifest_commitment()
    );
    assert_eq!(
        binding.final_frame_commitment(),
        fixture.manifest.components().catalog().final_chain_root()
    );
    assert_eq!(
        binding.total_frame_count(),
        fixture.manifest.components().catalog().total_frame_count()
    );
    assert_eq!(
        binding.segment_count(),
        fixture.manifest.components().catalog().segment_count()
    );
    let opened = repository
        .open_sealed_result(fixture.expected_context())
        .unwrap();
    assert_eq!(opened.manifest().encode(), exact_manifest);
    assert_eq!(
        opened.acquisition_receipt_id(),
        fixture.acquisition_receipt_id
    );
    assert_eq!(
        repository.create_sealed_result(&fixture.key_context(), &fixture.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult)
    );
    assert_eq!(
        repository.destroy(&fixture.result_id).unwrap(),
        EncryptedCoreResultDestroyOutcomeV1::Destroyed
    );
    assert!(repository.is_empty().unwrap());
    assert_eq!(
        repository.open_sealed_result(fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    assert_eq!(
        repository.destroy(&fixture.result_id).unwrap(),
        EncryptedCoreResultDestroyOutcomeV1::AlreadyAbsent
    );
}

#[test]
fn exact_provider_seal_retry_does_not_publish_an_intermediate_state() {
    let repository = repository(1);
    let fixture = fixture(2);
    repository
        .provider_for_test()
        .fail_next_seal_update_for_test()
        .unwrap();
    repository
        .create_sealed_result(&fixture.key_context(), &fixture.manifest)
        .unwrap();
    assert_eq!(repository.len().unwrap(), 1);
    assert!(
        repository
            .open_sealed_result(fixture.expected_context())
            .is_ok()
    );
}

#[test]
fn exhausted_seal_retry_rolls_back_key_authority_and_publishes_nothing() {
    let repository = repository(1);
    let fixture = fixture(11);
    repository
        .provider_for_test()
        .fail_next_two_seal_updates_for_test()
        .unwrap();
    assert_eq!(
        repository.create_sealed_result(&fixture.key_context(), &fixture.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::KeySealFailed)
    );
    assert!(repository.is_empty().unwrap());
    assert!(
        repository
            .provider_for_test()
            .list_managed_records()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repository.open_sealed_result(fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    assert_eq!(
        repository.create_sealed_result(&fixture.key_context(), &fixture.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
}

#[test]
fn nonce_failure_and_publication_failure_leave_no_openable_result() {
    let nonce_provider = EphemeralKeyProviderV1::new(
        ScriptedEntropy::new([
            bytes(32, 0x11),
            bytes(32, 0x21),
            bytes(24, 0x31),
            EntropyStep::Unavailable,
        ]),
        4,
    )
    .unwrap();
    let nonce_repository = MemoryEncryptedCoreResultRepositoryV1::new(nonce_provider, 4).unwrap();
    let nonce_fixture = fixture(3);
    assert_eq!(
        nonce_repository
            .create_sealed_result(&nonce_fixture.key_context(), &nonce_fixture.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::NonceIssuanceFailed)
    );
    assert!(nonce_repository.is_empty().unwrap());
    assert!(
        nonce_repository
            .provider_for_test()
            .list_managed_records()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nonce_repository
            .create_sealed_result(&nonce_fixture.key_context(), &nonce_fixture.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );

    let publication_repository = repository(1);
    let publication_fixture = fixture(4);
    publication_repository
        .fail_next_publication_for_test()
        .unwrap();
    assert_eq!(
        publication_repository.create_sealed_result(
            &publication_fixture.key_context(),
            &publication_fixture.manifest,
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed)
    );
    assert!(publication_repository.is_empty().unwrap());
    assert!(
        publication_repository
            .provider_for_test()
            .list_managed_records()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        publication_repository.open_sealed_result(publication_fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
}

#[test]
fn wrong_authority_tamper_and_provider_corruption_fail_closed() {
    let repository = repository(1);
    let fixture = fixture(5);
    repository
        .create_sealed_result(&fixture.key_context(), &fixture.manifest)
        .unwrap();

    let wrong_source = ExpectedCoreResultManifestContextV1::new(
        fixture.result_id,
        SourceIdentityDigest::from_bytes([0xee; 32]),
        fixture.acquisition_receipt_id,
        1_000,
        2_000,
    )
    .unwrap();
    assert_eq!(
        repository.open_sealed_result(wrong_source),
        Err(EncryptedCoreResultRepositoryErrorV1::ManifestOpenFailed)
    );
    let wrong_receipt = ExpectedCoreResultManifestContextV1::new(
        fixture.result_id,
        fixture.source_identity_digest,
        AcquisitionReceiptId::from_bytes([0xef; 32]),
        1_000,
        2_000,
    )
    .unwrap();
    assert_eq!(
        repository.open_sealed_result(wrong_receipt),
        Err(EncryptedCoreResultRepositoryErrorV1::ManifestOpenFailed)
    );
    let wrong_time = ExpectedCoreResultManifestContextV1::new(
        fixture.result_id,
        fixture.source_identity_digest,
        fixture.acquisition_receipt_id,
        1_001,
        2_000,
    )
    .unwrap();
    assert_eq!(
        repository.open_sealed_result(wrong_time),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );

    repository
        .corrupt_ciphertext_byte_for_test(fixture.result_id, 120)
        .unwrap();
    assert_eq!(
        repository.open_sealed_result(fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::SealBindingMismatch)
    );

    repository
        .provider_for_test()
        .corrupt_record_byte_for_test(&fixture.result_id, RESULT_KEY_RECORD_BYTES_V1 - 1)
        .unwrap();
    assert_eq!(
        repository.open_sealed_result(fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
}

#[test]
fn cross_result_ciphertext_swap_is_rejected_before_plaintext_release() {
    let repository = repository(2);
    let first = fixture(6);
    let second = fixture(7);
    repository
        .create_sealed_result(&first.key_context(), &first.manifest)
        .unwrap();
    repository
        .create_sealed_result(&second.key_context(), &second.manifest)
        .unwrap();
    repository
        .swap_ciphertexts_for_test(first.result_id, second.result_id)
        .unwrap();
    assert_eq!(
        repository.open_sealed_result(first.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::CiphertextDecodeFailed)
    );
    assert_eq!(
        repository.open_sealed_result(second.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::CiphertextDecodeFailed)
    );
}

#[test]
fn destroyed_key_authority_blocks_open_even_when_ciphertext_cleanup_fails() {
    let repository = repository(1);
    let fixture = fixture(8);
    repository
        .create_sealed_result(&fixture.key_context(), &fixture.manifest)
        .unwrap();
    repository.fail_next_ciphertext_cleanup_for_test().unwrap();
    assert_eq!(
        repository.destroy(&fixture.result_id),
        Err(EncryptedCoreResultRepositoryErrorV1::CiphertextCleanupFailed)
    );
    assert_eq!(repository.len().unwrap(), 1);
    assert!(
        repository
            .provider_for_test()
            .list_managed_records()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repository.open_sealed_result(fixture.expected_context()),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
    assert_eq!(
        repository.destroy(&fixture.result_id).unwrap(),
        EncryptedCoreResultDestroyOutcomeV1::Destroyed
    );
    assert!(repository.is_empty().unwrap());
}

#[test]
fn concurrent_duplicate_create_has_exactly_one_published_winner() {
    let repository = Arc::new(repository(1));
    let first = fixture(9);
    let second = fixture(9);
    let result_id = first.result_id;
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for fixture in [first, second] {
        let repository = Arc::clone(&repository);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            repository.create_sealed_result(&fixture.key_context(), &fixture.manifest)
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(
                    outcome,
                    Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult)
                )
            })
            .count(),
        1
    );
    assert_eq!(repository.len().unwrap(), 1);
    assert!(
        repository
            .open_sealed_result(fixture(9).expected_context())
            .is_ok()
    );
    assert_eq!(
        repository.destroy(&result_id).unwrap(),
        EncryptedCoreResultDestroyOutcomeV1::Destroyed
    );
}

#[test]
fn bounds_and_all_debug_output_are_contentless() {
    let provider = EphemeralKeyProviderV1::new(ScriptedEntropy::new([]), 1).unwrap();
    assert!(matches!(
        MemoryEncryptedCoreResultRepositoryV1::new(provider, 0),
        Err(EncryptedCoreResultRepositoryErrorV1::InvalidCapacity)
    ));
    let provider = EphemeralKeyProviderV1::new(ScriptedEntropy::new([]), 1).unwrap();
    assert!(matches!(
        MemoryEncryptedCoreResultRepositoryV1::new(
            provider,
            MAX_MEMORY_ENCRYPTED_CORE_RESULTS_V1 + 1,
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::InvalidCapacity)
    ));

    let repository = repository(1);
    let foreign_manifest = fixture(12).manifest;
    let fixture = fixture(10);
    assert_eq!(
        repository.create_sealed_result(&fixture.key_context(), &foreign_manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)
    );
    assert!(repository.is_empty().unwrap());
    assert!(
        repository
            .provider_for_test()
            .list_managed_records()
            .unwrap()
            .is_empty()
    );
    let publication = repository
        .create_sealed_result(&fixture.key_context(), &fixture.manifest)
        .unwrap();
    let rendered = format!(
        "{repository:?} {publication:?} {:?} {} {:?}",
        EncryptedCoreResultRepositoryErrorV1::ManifestOpenFailed,
        EncryptedCoreResultRepositoryErrorV1::SealBindingMismatch,
        EncryptedCoreResultDestroyOutcomeV1::Destroyed,
    );
    assert!(!rendered.contains(&fixture.result_id.canonical_token()));
    assert!(!rendered.contains(&fixture.source_identity_digest.to_string()));
    assert!(!rendered.contains(&fixture.acquisition_receipt_id.to_string()));
    assert_eq!(
        EncryptedCoreResultRepositoryErrorV1::ManifestOpenFailed.to_string(),
        "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_MANIFEST_OPEN_FAILED"
    );
}

#[test]
fn staged_frames_are_invisible_until_exact_manifest_and_key_seal_then_reopen_exactly() {
    let repository = frame_repository(&[3]);
    let authority = fixture(20);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let unavailable_locator = EncryptedCoreResultFrameLocatorV1::new(0, 0, 0);
    assert_eq!(
        repository
            .open_sealed_result(authority.expected_context())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    assert_eq!(
        repository
            .open_stored_frame(authority.expected_context(), unavailable_locator)
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );

    let first = b"\xff\0first\r\nheading:\x80".to_vec();
    let second = b"second".to_vec();
    let third = b"third\nline".to_vec();
    let first_publication = stage_fixture_frame(
        &repository,
        20,
        &authority.result_id,
        FrameObjectKindV1::AuthorizedOutcome,
        &first,
    );
    let second_publication = repository
        .stage_frame(
            &authority.result_id,
            FrameObjectKindV1::AcquisitionSeal,
            &second,
        )
        .unwrap();
    assert_eq!(
        repository
            .rotate_staged_segment(&authority.result_id)
            .unwrap(),
        1
    );
    let third_publication = repository
        .stage_frame(
            &authority.result_id,
            FrameObjectKindV1::AcquisitionSeal,
            &third,
        )
        .unwrap();
    assert_eq!(first_publication.locator().segment_sequence(), 0);
    assert_eq!(second_publication.locator().global_frame_sequence(), 1);
    assert_eq!(third_publication.locator().segment_sequence(), 1);
    assert_eq!(third_publication.locator().global_frame_sequence(), 2);
    assert_eq!(third_publication.locator().segment_frame_sequence(), 0);
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(3)
    );
    assert_eq!(
        repository
            .open_stored_frame(authority.expected_context(), first_publication.locator())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );

    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    assert_eq!(catalog.segment_count(), 2);
    assert_eq!(catalog.total_frame_count(), 3);
    let exact = fixture_with_catalog(
        20,
        catalog,
        first_publication.encoded_byte_count(),
        first.len() as u32,
    );
    repository
        .seal_staged_result(&exact.result_id, &exact.manifest)
        .unwrap();

    for (publication, expected) in [
        (first_publication, first.as_slice()),
        (second_publication, second.as_slice()),
        (third_publication, third.as_slice()),
    ] {
        let opened = repository
            .open_stored_frame(exact.expected_context(), publication.locator())
            .unwrap();
        assert_eq!(opened.locator(), publication.locator());
        assert_eq!(opened.object_kind(), publication.object_kind());
        assert_eq!(opened.commitment(), publication.commitment());
        assert_eq!(opened.as_bytes(), expected);
    }
}

#[test]
fn catalog_mismatch_is_retryable_without_exposing_staging() {
    let repository = frame_repository(&[1]);
    let authority = fixture(21);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    let publication = stage_fixture_frame(
        &repository,
        21,
        &authority.result_id,
        FrameObjectKindV1::AuthorizedOutcome,
        b"exact",
    );
    assert_eq!(
        repository.seal_staged_result(&authority.result_id, &authority.manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::CatalogMismatch)
    );
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(1)
    );
    assert_eq!(
        repository
            .open_stored_frame(authority.expected_context(), publication.locator())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );

    let exact = fixture_with_catalog(
        21,
        repository
            .staged_segment_catalog(&authority.result_id)
            .unwrap(),
        publication.encoded_byte_count(),
        5,
    );
    repository
        .provider_for_test()
        .fail_next_seal_update_for_test()
        .unwrap();
    repository
        .seal_staged_result(&exact.result_id, &exact.manifest)
        .unwrap();
    assert_eq!(
        repository
            .open_stored_frame(exact.expected_context(), publication.locator())
            .unwrap()
            .as_bytes(),
        b"exact"
    );
}

#[test]
fn failed_frame_publication_is_atomic_and_burns_its_provider_nonce() {
    let repository = repository_with_steps([
        bytes(32, 0x11),
        bytes(32, 0x21),
        bytes(24, 0x31),
        bytes(24, 0x44),
        bytes(24, 0x44),
        bytes(24, 0x45),
        bytes(24, 0x71),
        bytes(24, 0x79),
    ]);
    let authority = fixture(22);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    repository.fail_next_frame_publication_for_test().unwrap();
    assert_eq!(
        repository.stage_authorized_event(
            &authority.result_id,
            fixture_event_id(22),
            fixture_exactness(22),
            b"first-attempt",
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::FramePublicationFailed)
    );
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(0)
    );
    assert_eq!(
        repository.stage_authorized_event(
            &authority.result_id,
            fixture_event_id(22),
            fixture_exactness(22),
            b"reused-nonce",
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::FrameNonceIssuanceFailed)
    );
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(0)
    );

    let publication = repository
        .stage_authorized_event(
            &authority.result_id,
            fixture_event_id(22),
            fixture_exactness(22),
            b"committed",
        )
        .unwrap()
        .frame();
    assert_eq!(
        publication.locator(),
        EncryptedCoreResultFrameLocatorV1::new(0, 0, 0)
    );
    let exact = fixture_with_catalog(
        22,
        repository
            .staged_segment_catalog(&authority.result_id)
            .unwrap(),
        publication.encoded_byte_count(),
        9,
    );
    repository
        .seal_staged_result(&exact.result_id, &exact.manifest)
        .unwrap();
    assert_eq!(
        repository
            .open_stored_frame(exact.expected_context(), publication.locator())
            .unwrap()
            .as_bytes(),
        b"committed"
    );
}

#[test]
fn wrong_locator_reorder_and_cross_result_substitution_fail_closed() {
    let reordered_repository = frame_repository(&[2]);
    let (reordered_fixture, reordered_frames) = stage_and_seal_frames(
        &reordered_repository,
        23,
        &[
            (false, FrameObjectKindV1::AuthorizedOutcome, b"one".to_vec()),
            (false, FrameObjectKindV1::AcquisitionSeal, b"two".to_vec()),
        ],
    );
    let first = reordered_frames[0];
    let wrong_global = EncryptedCoreResultFrameLocatorV1::new(
        first.locator().segment_sequence(),
        first.locator().global_frame_sequence() + 1,
        first.locator().segment_frame_sequence(),
    );
    assert_eq!(
        reordered_repository
            .open_stored_frame(reordered_fixture.expected_context(), wrong_global)
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::FrameIdentityMismatch)
    );
    reordered_repository
        .swap_stored_frames_for_test(
            reordered_fixture.result_id,
            reordered_frames[0].locator(),
            reordered_fixture.result_id,
            reordered_frames[1].locator(),
        )
        .unwrap();
    assert!(matches!(
        reordered_repository
            .open_stored_frame(
                reordered_fixture.expected_context(),
                reordered_frames[0].locator(),
            )
            .err(),
        Some(
            EncryptedCoreResultRepositoryErrorV1::FrameIdentityMismatch
                | EncryptedCoreResultRepositoryErrorV1::CatalogMismatch
        )
    ));

    let cross_repository = frame_repository(&[1, 1]);
    let (first_fixture, first_frames) = stage_and_seal_frames(
        &cross_repository,
        24,
        &[(
            false,
            FrameObjectKindV1::AuthorizedOutcome,
            b"first-result".to_vec(),
        )],
    );
    let (second_fixture, second_frames) = stage_and_seal_frames(
        &cross_repository,
        25,
        &[(
            false,
            FrameObjectKindV1::AuthorizedOutcome,
            b"second-result".to_vec(),
        )],
    );
    cross_repository
        .swap_stored_frames_for_test(
            first_fixture.result_id,
            first_frames[0].locator(),
            second_fixture.result_id,
            second_frames[0].locator(),
        )
        .unwrap();
    assert!(
        cross_repository
            .open_stored_frame(first_fixture.expected_context(), first_frames[0].locator())
            .is_err()
    );
    assert!(
        cross_repository
            .open_stored_frame(
                second_fixture.expected_context(),
                second_frames[0].locator()
            )
            .is_err()
    );
}

#[test]
fn frame_tamper_truncation_and_previous_commitment_mutation_fail_closed() {
    let tamper_repository = frame_repository(&[1]);
    let (tamper_fixture, tamper_frames) = stage_and_seal_frames(
        &tamper_repository,
        26,
        &[(
            false,
            FrameObjectKindV1::AuthorizedOutcome,
            b"tamper".to_vec(),
        )],
    );
    tamper_repository
        .corrupt_stored_frame_byte_for_test(
            tamper_fixture.result_id,
            tamper_frames[0].locator(),
            FRAME_HEADER_BYTES_V1,
        )
        .unwrap();
    assert!(
        tamper_repository
            .open_stored_frame(
                tamper_fixture.expected_context(),
                tamper_frames[0].locator()
            )
            .is_err()
    );

    let truncation_repository = frame_repository(&[1]);
    let (truncation_fixture, truncation_frames) = stage_and_seal_frames(
        &truncation_repository,
        27,
        &[(
            false,
            FrameObjectKindV1::AuthorizedOutcome,
            b"truncate".to_vec(),
        )],
    );
    truncation_repository
        .truncate_stored_frame_for_test(
            truncation_fixture.result_id,
            truncation_frames[0].locator(),
            truncation_frames[0].encoded_byte_count() as usize - 1,
        )
        .unwrap();
    assert!(
        truncation_repository
            .open_stored_frame(
                truncation_fixture.expected_context(),
                truncation_frames[0].locator(),
            )
            .is_err()
    );

    let chain_repository = frame_repository(&[2]);
    let (chain_fixture, chain_frames) = stage_and_seal_frames(
        &chain_repository,
        28,
        &[
            (
                false,
                FrameObjectKindV1::AuthorizedOutcome,
                b"head".to_vec(),
            ),
            (false, FrameObjectKindV1::AcquisitionSeal, b"tail".to_vec()),
        ],
    );
    chain_repository
        .corrupt_stored_frame_byte_for_test(chain_fixture.result_id, chain_frames[1].locator(), 52)
        .unwrap();
    assert!(matches!(
        chain_repository
            .open_stored_frame(chain_fixture.expected_context(), chain_frames[1].locator())
            .err(),
        Some(
            EncryptedCoreResultRepositoryErrorV1::FrameIdentityMismatch
                | EncryptedCoreResultRepositoryErrorV1::CatalogMismatch
        )
    ));
}

#[test]
fn destroyed_frame_key_authority_denies_open_even_if_ciphertext_cleanup_fails() {
    let repository = frame_repository(&[1]);
    let (fixture, frames) = stage_and_seal_frames(
        &repository,
        29,
        &[(
            false,
            FrameObjectKindV1::AuthorizedOutcome,
            b"destroy-me".to_vec(),
        )],
    );
    repository.fail_next_ciphertext_cleanup_for_test().unwrap();
    assert_eq!(
        repository.destroy(&fixture.result_id),
        Err(EncryptedCoreResultRepositoryErrorV1::CiphertextCleanupFailed)
    );
    assert_eq!(repository.len(), Ok(1));
    assert_eq!(
        repository
            .open_stored_frame(fixture.expected_context(), frames[0].locator())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
    assert_eq!(
        repository.destroy(&fixture.result_id),
        Ok(EncryptedCoreResultDestroyOutcomeV1::Destroyed)
    );
    assert_eq!(repository.len(), Ok(0));
}

#[test]
fn frame_bounds_empty_rotation_and_debug_output_are_contentless() {
    let repository = frame_repository(&[1]);
    let authority = fixture(30);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    assert_eq!(
        repository.rotate_staged_segment(&authority.result_id),
        Err(EncryptedCoreResultRepositoryErrorV1::EmptySegment)
    );
    assert_eq!(
        repository
            .staged_segment_catalog(&authority.result_id)
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::EmptySegment)
    );
    let oversized = vec![0xa5; MAX_FRAME_PLAINTEXT_BYTES_V1 + 1];
    assert_eq!(
        repository.stage_authorized_event(
            &authority.result_id,
            fixture_event_id(30),
            fixture_exactness(30),
            &oversized,
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)
    );
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(0)
    );

    let publication = repository
        .stage_authorized_event(
            &authority.result_id,
            fixture_event_id(30),
            fixture_exactness(30),
            b"FRAME-SECRET-CANARY",
        )
        .unwrap()
        .frame();
    let rendered = format!(
        "{repository:?} {publication:?} {:?} {:?}",
        publication.locator(),
        EncryptedCoreResultRepositoryErrorV1::FrameOpenFailed,
    );
    assert!(!rendered.contains("FRAME-SECRET-CANARY"));
    assert!(!rendered.contains(&authority.result_id.canonical_token()));
    assert!(!rendered.contains(&authority.source_identity_digest.to_string()));
    assert!(!rendered.contains(&authority.acquisition_receipt_id.to_string()));
    assert_eq!(
        EncryptedCoreResultRepositoryErrorV1::FrameOpenFailed.to_string(),
        "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_OPEN_FAILED"
    );
}

#[test]
fn indexed_events_round_trip_exact_bytes_exactness_and_multisegment_locations() {
    let source_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xf1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let post_policy_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x01; 32]),
        exactness_basis: ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([0; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([0; 32]),
        },
    };
    let authority = staging_fixture(33, &[source_event, post_policy_event]);
    let repository = frame_repository(&[3]);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();

    let source_publication = repository
        .stage_authorized_event(
            &authority.result_id,
            source_event.event_id,
            source_event.exactness_basis,
            b"",
        )
        .unwrap();
    let generic_frame = repository
        .stage_frame(
            &authority.result_id,
            FrameObjectKindV1::AcquisitionSeal,
            b"\0internal-seal\r\n",
        )
        .unwrap();
    repository
        .rotate_staged_segment(&authority.result_id)
        .unwrap();
    let exact_post_policy_bytes = b"\xff\0POST\r\nmissing-terminator\x80";
    let post_policy_publication = repository
        .stage_authorized_event(
            &authority.result_id,
            post_policy_event.event_id,
            post_policy_event.exactness_basis,
            exact_post_policy_bytes,
        )
        .unwrap();

    assert_eq!(
        repository
            .open_stored_event(authority.expected_context(), source_event.event_id)
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    let index = repository
        .staged_event_expansion_index(&authority.result_id)
        .unwrap();
    assert_eq!(catalog.segment_count(), 2);
    assert_eq!(index.entry_count(), 2);
    let source_entry = index
        .entries()
        .iter()
        .find(|entry| entry.event_id() == source_event.event_id)
        .unwrap();
    let post_entry = index
        .entries()
        .iter()
        .find(|entry| entry.event_id() == post_policy_event.event_id)
        .unwrap();
    assert_eq!(source_entry.authorized_bytes().offset(), 0);
    assert_eq!(source_entry.authorized_bytes().length(), 0);
    assert_eq!(source_entry.frame_locator().segment_sequence(), 0);
    assert_eq!(post_entry.frame_locator().segment_sequence(), 1);
    assert_eq!(
        post_entry.authorized_bytes().length(),
        exact_post_policy_bytes.len() as u32
    );

    let manifest = authority.manifest(&catalog, &index);
    repository
        .seal_staged_result(&authority.result_id, &manifest)
        .unwrap();
    let opened_source = repository
        .open_stored_event(authority.expected_context(), source_event.event_id)
        .unwrap();
    assert_eq!(opened_source.event_id(), source_event.event_id);
    assert_eq!(opened_source.exactness_basis(), ExactnessBasis::SourceExact);
    assert_eq!(opened_source.as_bytes(), b"");
    let opened_post = repository
        .open_stored_event(authority.expected_context(), post_policy_event.event_id)
        .unwrap();
    assert_eq!(opened_post.event_id(), post_policy_event.event_id);
    assert_eq!(
        opened_post.exactness_basis(),
        post_policy_event.exactness_basis
    );
    assert_eq!(opened_post.as_bytes(), exact_post_policy_bytes);
    assert_eq!(
        repository
            .open_stored_frame(authority.expected_context(), generic_frame.locator())
            .unwrap()
            .as_bytes(),
        b"\0internal-seal\r\n"
    );
    assert_eq!(
        repository
            .open_stored_event(
                authority.expected_context(),
                EventId::from_bytes([0xee; 32]),
            )
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::EventNotFound)
    );
    let wrong_authority = ExpectedCoreResultManifestContextV1::new(
        authority.result_id,
        SourceIdentityDigest::from_bytes([0xee; 32]),
        authority.acquisition_receipt_id,
        1_000,
        2_000,
    )
    .unwrap();
    assert!(
        repository
            .open_stored_event(wrong_authority, source_event.event_id)
            .is_err()
    );

    let rendered = format!(
        "{source_publication:?} {post_policy_publication:?} {opened_source:?} {opened_post:?}"
    );
    assert!(!rendered.contains("POST"));
    assert!(!rendered.contains(&source_event.event_id.to_string()));
    assert!(!rendered.contains(&post_policy_event.event_id.to_string()));
    assert_eq!(
        repository.destroy(&authority.result_id),
        Ok(EncryptedCoreResultDestroyOutcomeV1::Destroyed)
    );
    assert!(
        repository
            .open_stored_event(authority.expected_context(), source_event.event_id)
            .is_err()
    );
}

#[test]
fn event_staging_rejects_untyped_and_duplicate_assignments_without_nonce_or_index_drift() {
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x31; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x32; 32]),
        exactness_basis: ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([0x41; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([0x42; 32]),
        },
    };
    let authority = staging_fixture(34, &[first_event, second_event]);
    let repository = frame_repository(&[2]);
    repository
        .begin_staged_result(
            &authority.key_context(),
            authority.source_identity_digest,
            authority.acquisition_receipt_id,
        )
        .unwrap();
    assert_eq!(
        repository.stage_frame(
            &authority.result_id,
            FrameObjectKindV1::AuthorizedOutcome,
            b"untyped",
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::AuthorizedOutcomeRequiresEvent)
    );
    let first = repository
        .stage_authorized_event(
            &authority.result_id,
            first_event.event_id,
            first_event.exactness_basis,
            b"first",
        )
        .unwrap();
    assert_eq!(
        repository.stage_authorized_event(
            &authority.result_id,
            first_event.event_id,
            first_event.exactness_basis,
            b"duplicate",
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::DuplicateEventId)
    );
    let second = repository
        .stage_authorized_event(
            &authority.result_id,
            second_event.event_id,
            second_event.exactness_basis,
            b"second",
        )
        .unwrap();
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(2)
    );

    let catalog = repository
        .staged_segment_catalog(&authority.result_id)
        .unwrap();
    let exact_index = repository
        .staged_event_expansion_index(&authority.result_id)
        .unwrap();
    let first_entry = *exact_index
        .entries()
        .iter()
        .find(|entry| entry.event_id() == first_event.event_id)
        .unwrap();
    let second_entry = *exact_index
        .entries()
        .iter()
        .find(|entry| entry.event_id() == second_event.event_id)
        .unwrap();
    assert_eq!(
        first_entry.frame_locator().frame_offset(),
        SEGMENT_HEADER_BYTES_V1 as u64
    );
    assert_eq!(
        second_entry.frame_locator().frame_offset(),
        SEGMENT_HEADER_BYTES_V1 as u64 + u64::from(first.frame().encoded_byte_count())
    );
    assert_eq!(first_entry.authorized_bytes().length(), 5);
    assert_eq!(second_entry.authorized_bytes().length(), 6);
    let duplicate_frame_index = EventExpansionIndexV1::new(
        &catalog,
        vec![
            first_entry,
            EventExpansionIndexEntryV1::new(
                &catalog,
                second_event.event_id,
                first_entry.frame_locator(),
                first_entry.authorized_bytes(),
                second_event.exactness_basis,
            )
            .unwrap(),
        ],
    );
    assert_eq!(
        duplicate_frame_index.err().unwrap().code(),
        "EVIDENTRAIL_EVENT_INDEX_DUPLICATE_FRAME_ASSIGNMENT"
    );

    let swapped_index = EventExpansionIndexV1::new(
        &catalog,
        vec![
            EventExpansionIndexEntryV1::new(
                &catalog,
                first_event.event_id,
                second_entry.frame_locator(),
                second_entry.authorized_bytes(),
                first_event.exactness_basis,
            )
            .unwrap(),
            EventExpansionIndexEntryV1::new(
                &catalog,
                second_event.event_id,
                first_entry.frame_locator(),
                first_entry.authorized_bytes(),
                second_event.exactness_basis,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let swapped_manifest = authority.manifest(&catalog, &swapped_index);
    assert_eq!(
        repository.seal_staged_result(&authority.result_id, &swapped_manifest),
        Err(EncryptedCoreResultRepositoryErrorV1::EventIndexMismatch)
    );
    assert_eq!(
        repository.staged_frame_count_for_test(&authority.result_id),
        Ok(2)
    );
    let exact_manifest = authority.manifest(&catalog, &exact_index);
    repository
        .seal_staged_result(&authority.result_id, &exact_manifest)
        .unwrap();
    assert_eq!(first.frame().locator().global_frame_sequence(), 0);
    assert_eq!(second.frame().locator().global_frame_sequence(), 1);
    assert_eq!(
        repository
            .open_stored_event(authority.expected_context(), second_event.event_id)
            .unwrap()
            .as_bytes(),
        b"second"
    );
}

#[test]
fn event_expansion_rejects_cross_event_cross_result_header_and_ciphertext_substitution() {
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x71; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x72; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let same_result_repository = frame_repository(&[2]);
    let (same_result, publications) = stage_and_seal_events(
        &same_result_repository,
        35,
        &[
            (false, first_event, b"event-one".to_vec()),
            (false, second_event, b"event-two".to_vec()),
        ],
    );
    same_result_repository
        .swap_stored_frames_for_test(
            same_result.result_id,
            publications[0].frame().locator(),
            same_result.result_id,
            publications[1].frame().locator(),
        )
        .unwrap();
    assert!(
        same_result_repository
            .open_stored_event(same_result.expected_context(), first_event.event_id)
            .is_err()
    );
    assert!(
        same_result_repository
            .open_stored_event(same_result.expected_context(), second_event.event_id)
            .is_err()
    );

    let cross_result_repository = frame_repository(&[1, 1]);
    let (left, left_publications) = stage_and_seal_events(
        &cross_result_repository,
        36,
        &[(false, first_event, b"left".to_vec())],
    );
    let (right, right_publications) = stage_and_seal_events(
        &cross_result_repository,
        37,
        &[(false, second_event, b"right".to_vec())],
    );
    cross_result_repository
        .swap_stored_frames_for_test(
            left.result_id,
            left_publications[0].frame().locator(),
            right.result_id,
            right_publications[0].frame().locator(),
        )
        .unwrap();
    assert!(
        cross_result_repository
            .open_stored_event(left.expected_context(), first_event.event_id)
            .is_err()
    );
    assert!(
        cross_result_repository
            .open_stored_event(right.expected_context(), second_event.event_id)
            .is_err()
    );

    let header_repository = frame_repository(&[1]);
    let (header_authority, header_publications) = stage_and_seal_events(
        &header_repository,
        38,
        &[(false, first_event, b"header".to_vec())],
    );
    header_repository
        .corrupt_stored_frame_byte_for_test(
            header_authority.result_id,
            header_publications[0].frame().locator(),
            20,
        )
        .unwrap();
    assert!(
        header_repository
            .open_stored_event(header_authority.expected_context(), first_event.event_id)
            .is_err()
    );

    let ciphertext_repository = frame_repository(&[1]);
    let (ciphertext_authority, ciphertext_publications) = stage_and_seal_events(
        &ciphertext_repository,
        39,
        &[(false, second_event, b"ciphertext".to_vec())],
    );
    ciphertext_repository
        .corrupt_stored_frame_byte_for_test(
            ciphertext_authority.result_id,
            ciphertext_publications[0].frame().locator(),
            FRAME_HEADER_BYTES_V1,
        )
        .unwrap();
    assert!(
        ciphertext_repository
            .open_stored_event(
                ciphertext_authority.expected_context(),
                second_event.event_id,
            )
            .is_err()
    );
}

fn bundle_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn bundle_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn bundle_usize(bytes: &[u8], offset: usize) -> usize {
    usize::try_from(bundle_u64(bytes, offset)).unwrap()
}

fn set_bundle_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn set_bundle_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn frame_descriptor_offset(bytes: &[u8], frame_index: usize) -> usize {
    let directory_offset = bundle_usize(bytes, 88);
    let segment_count = bundle_u32(bytes, 120) as usize;
    directory_offset
        + segment_count * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1
        + frame_index * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1
}

fn frame_payload_range(bytes: &[u8], frame_index: usize) -> std::ops::Range<usize> {
    let descriptor = frame_descriptor_offset(bytes, frame_index);
    let start = bundle_usize(bytes, descriptor + 24);
    let length = bundle_usize(bytes, descriptor + 32);
    start..start + length
}

fn segment_payload_range(bytes: &[u8], segment_index: usize) -> std::ops::Range<usize> {
    let descriptor = bundle_usize(bytes, 88)
        + segment_index * SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1;
    let start = bundle_usize(bytes, descriptor + 8);
    let length = bundle_usize(bytes, descriptor + 16);
    start..start + length
}

#[test]
fn sealed_bundle_round_trip_import_opens_exact_events_and_reencodes_identically() {
    let (source, destination) = shared_frame_repositories(&[2]);
    let source_exact = TestPersistedEvent {
        event_id: EventId::from_bytes([0xa1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let post_policy = TestPersistedEvent {
        event_id: EventId::from_bytes([0xa2; 32]),
        exactness_basis: ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([0xa3; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([0xa4; 32]),
        },
    };
    let first_bytes = b"\0invalid:\xff\xfe\r\n".to_vec();
    let second_bytes = b"duplicate-looking\nexact bytes\0".to_vec();
    let (authority, _) = stage_and_seal_events(
        &source,
        41,
        &[
            (false, source_exact, first_bytes.clone()),
            (true, post_policy, second_bytes.clone()),
        ],
    );

    let bundle = source
        .export_sealed_bundle(authority.expected_context())
        .unwrap();
    assert_eq!(bundle.result_id(), authority.result_id);
    assert_eq!(bundle.segment_count(), 2);
    assert_eq!(bundle.frame_count(), 2);
    let canonical = bundle.encode();
    let decoded = SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap();
    assert_eq!(decoded.encode(), canonical);

    let publication = destination
        .import_sealed_bundle(authority.expected_context(), decoded)
        .unwrap();
    assert_eq!(publication.result_id(), authority.result_id);
    let opened_first = destination
        .open_stored_event(authority.expected_context(), source_exact.event_id)
        .unwrap();
    assert_eq!(opened_first.as_bytes(), first_bytes);
    assert_eq!(opened_first.exactness_basis(), source_exact.exactness_basis);
    let opened_second = destination
        .open_stored_event(authority.expected_context(), post_policy.event_id)
        .unwrap();
    assert_eq!(opened_second.as_bytes(), second_bytes);
    assert_eq!(opened_second.exactness_basis(), post_policy.exactness_basis);

    let reexported = destination
        .export_sealed_bundle(authority.expected_context())
        .unwrap();
    assert_eq!(reexported.encode(), canonical);
}

#[test]
fn sealed_bundle_codec_rejects_header_directory_count_and_allocation_lies() {
    let (source, _) = shared_frame_repositories(&[1]);
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) = stage_and_seal_events(&source, 42, &[(false, event, b"bounded".to_vec())]);
    let canonical = source
        .export_sealed_bundle(authority.expected_context())
        .unwrap()
        .encode();

    for boundary in 0..SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 {
        assert_eq!(
            SealedEncryptedCoreResultBundleV1::decode(&canonical[..boundary]).err(),
            Some(SealedEncryptedCoreResultBundleErrorV1::Truncated)
        );
    }
    assert!(SealedEncryptedCoreResultBundleV1::decode(&canonical[..canonical.len() - 1]).is_err());
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&trailing).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::TrailingData)
    );

    let mutations: &[(usize, &[u8], SealedEncryptedCoreResultBundleErrorV1)] = &[
        (
            8,
            &2u16.to_be_bytes(),
            SealedEncryptedCoreResultBundleErrorV1::UnknownVersion,
        ),
        (
            10,
            &2u16.to_be_bytes(),
            SealedEncryptedCoreResultBundleErrorV1::UnknownSuite,
        ),
        (
            12,
            &2u16.to_be_bytes(),
            SealedEncryptedCoreResultBundleErrorV1::UnknownObjectKind,
        ),
        (
            16,
            &1u32.to_be_bytes(),
            SealedEncryptedCoreResultBundleErrorV1::NonzeroFlags,
        ),
        (
            20,
            &[1],
            SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved,
        ),
    ];
    for (offset, replacement, expected) in mutations {
        let mut mutated = canonical.clone();
        mutated[*offset..*offset + replacement.len()].copy_from_slice(replacement);
        assert_eq!(
            SealedEncryptedCoreResultBundleV1::decode(&mutated).err(),
            Some(*expected)
        );
    }

    let mut zero_segments = canonical.clone();
    set_bundle_u32(&mut zero_segments, 120, 0);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&zero_segments).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::SegmentCountCap)
    );
    let mut too_many_segments = canonical.clone();
    set_bundle_u32(&mut too_many_segments, 120, 65);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&too_many_segments).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::SegmentCountCap)
    );
    let mut zero_frames = canonical.clone();
    set_bundle_u32(&mut zero_frames, 124, 0);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&zero_frames).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::FrameCountCap)
    );
    let mut manifest_claim = canonical.clone();
    set_bundle_u64(&mut manifest_claim, 80, (16 * 1024 * 1024 + 137) as u64);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&manifest_claim).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::ManifestLengthCap)
    );
    let mut payload_claim = canonical.clone();
    set_bundle_u64(&mut payload_claim, 112, (64 * 1024 * 1024 + 1) as u64);
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&payload_claim).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::FrameByteCap)
    );
    let mut enormous_total = canonical.clone();
    set_bundle_u64(&mut enormous_total, 64, u64::MAX);
    assert!(SealedEncryptedCoreResultBundleV1::decode(&enormous_total).is_err());

    let directory_offset = bundle_usize(&canonical, 88);
    let mut segment_reserved = canonical.clone();
    segment_reserved[directory_offset + 40] = 1;
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&segment_reserved).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved)
    );
    let mut frame_reserved = canonical.clone();
    frame_reserved[frame_descriptor_offset(&canonical, 0) + 20] = 1;
    assert_eq!(
        SealedEncryptedCoreResultBundleV1::decode(&frame_reserved).err(),
        Some(SealedEncryptedCoreResultBundleErrorV1::NonzeroReserved)
    );
    let mut frame_length_lie = canonical.clone();
    let descriptor = frame_descriptor_offset(&canonical, 0);
    set_bundle_u64(
        &mut frame_length_lie,
        descriptor + 32,
        bundle_u64(&canonical, descriptor + 32) + 1,
    );
    assert!(SealedEncryptedCoreResultBundleV1::decode(&frame_length_lie).is_err());
}

#[test]
fn sealed_bundle_codec_rejects_reorder_substitution_and_cross_result_objects() {
    let (same_segment_source, _) = shared_frame_repositories(&[2]);
    let first = TestPersistedEvent {
        event_id: EventId::from_bytes([0xc1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second = TestPersistedEvent {
        event_id: EventId::from_bytes([0xc2; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (same_segment, _) = stage_and_seal_events(
        &same_segment_source,
        43,
        &[
            (false, first, b"same-size-a".to_vec()),
            (false, second, b"same-size-b".to_vec()),
        ],
    );
    let canonical = same_segment_source
        .export_sealed_bundle(same_segment.expected_context())
        .unwrap()
        .encode();
    let first_range = frame_payload_range(&canonical, 0);
    let second_range = frame_payload_range(&canonical, 1);
    assert_eq!(first_range.len(), second_range.len());
    let mut reordered = canonical.clone();
    let first_bytes = reordered[first_range.clone()].to_vec();
    let second_bytes = reordered[second_range.clone()].to_vec();
    reordered[first_range].copy_from_slice(&second_bytes);
    reordered[second_range].copy_from_slice(&first_bytes);
    assert!(SealedEncryptedCoreResultBundleV1::decode(&reordered).is_err());

    let (multi_segment_source, _) = shared_frame_repositories(&[2]);
    let (multi_segment, _) = stage_and_seal_events(
        &multi_segment_source,
        44,
        &[
            (false, first, b"equal-size".to_vec()),
            (true, second, b"equal-size".to_vec()),
        ],
    );
    let multi = multi_segment_source
        .export_sealed_bundle(multi_segment.expected_context())
        .unwrap()
        .encode();
    let segment_zero = segment_payload_range(&multi, 0);
    let segment_one = segment_payload_range(&multi, 1);
    assert_eq!(segment_zero.len(), segment_one.len());
    let mut segments_reordered = multi.clone();
    let zero_bytes = segments_reordered[segment_zero.clone()].to_vec();
    let one_bytes = segments_reordered[segment_one.clone()].to_vec();
    segments_reordered[segment_zero].copy_from_slice(&one_bytes);
    segments_reordered[segment_one].copy_from_slice(&zero_bytes);
    assert!(SealedEncryptedCoreResultBundleV1::decode(&segments_reordered).is_err());

    let (foreign_source, _) = shared_frame_repositories(&[2]);
    let foreign_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xc3; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let foreign_event_two = TestPersistedEvent {
        event_id: EventId::from_bytes([0xc4; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (foreign, _) = stage_and_seal_events(
        &foreign_source,
        45,
        &[
            (false, foreign_event, b"same-size-a".to_vec()),
            (false, foreign_event_two, b"same-size-b".to_vec()),
        ],
    );
    let foreign_encoded = foreign_source
        .export_sealed_bundle(foreign.expected_context())
        .unwrap()
        .encode();
    let mut cross_result = canonical.clone();
    let local_frame = frame_payload_range(&cross_result, 0);
    let foreign_frame = frame_payload_range(&foreign_encoded, 0);
    assert_eq!(local_frame.len(), foreign_frame.len());
    cross_result[local_frame].copy_from_slice(&foreign_encoded[foreign_frame]);
    assert!(SealedEncryptedCoreResultBundleV1::decode(&cross_result).is_err());

    let mut foreign_manifest = canonical.clone();
    let manifest_length = bundle_usize(&canonical, 80);
    assert_eq!(manifest_length, bundle_usize(&foreign_encoded, 80));
    foreign_manifest[SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
        ..SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 + manifest_length]
        .copy_from_slice(
            &foreign_encoded[SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
                ..SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 + manifest_length],
        );
    assert!(SealedEncryptedCoreResultBundleV1::decode(&foreign_manifest).is_err());
}

#[test]
fn authenticated_bundle_import_rejects_tamper_context_duplicates_and_missing_keys_atomically() {
    let (source, destination) = shared_frame_repositories(&[1]);
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xd1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) = stage_and_seal_events(
        &source,
        46,
        &[(false, event, b"final-frame-tamper".to_vec())],
    );
    let canonical = source
        .export_sealed_bundle(authority.expected_context())
        .unwrap()
        .encode();

    let mut final_ciphertext_tamper = canonical.clone();
    let frame = frame_payload_range(&canonical, 0);
    final_ciphertext_tamper[frame.end - 1] ^= 0x80;
    let structurally_valid =
        SealedEncryptedCoreResultBundleV1::decode(&final_ciphertext_tamper).unwrap();
    assert!(
        destination
            .import_sealed_bundle(authority.expected_context(), structurally_valid)
            .is_err()
    );
    assert_eq!(destination.len(), Ok(0));

    let mut manifest_tamper = canonical.clone();
    let manifest_end =
        SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 + bundle_usize(&canonical, 80);
    manifest_tamper[manifest_end - 1] ^= 0x40;
    let structurally_valid = SealedEncryptedCoreResultBundleV1::decode(&manifest_tamper).unwrap();
    assert!(
        destination
            .import_sealed_bundle(authority.expected_context(), structurally_valid)
            .is_err()
    );
    assert_eq!(destination.len(), Ok(0));

    destination.fail_next_publication_for_test().unwrap();
    assert_eq!(
        destination.import_sealed_bundle(
            authority.expected_context(),
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed)
    );
    assert_eq!(destination.len(), Ok(0));
    destination
        .import_sealed_bundle(
            authority.expected_context(),
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        )
        .unwrap();
    assert_eq!(destination.len(), Ok(1));
    assert_eq!(
        destination.import_sealed_bundle(
            authority.expected_context(),
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult)
    );

    let foreign_expected = ExpectedCoreResultManifestContextV1::new(
        ResultId::from_bytes([0xee; 32]),
        authority.source_identity_digest,
        authority.acquisition_receipt_id,
        1_000,
        2_000,
    )
    .unwrap();
    let empty_destination = repository(0);
    assert_eq!(
        empty_destination.import_sealed_bundle(
            foreign_expected,
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)
    );
    assert_eq!(
        empty_destination.import_sealed_bundle(
            authority.expected_context(),
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
    assert_eq!(empty_destination.len(), Ok(0));
}

#[test]
fn sealed_bundle_export_excludes_staging_and_destroyed_authority_blocks_import() {
    let (staging_source, _) = shared_frame_repositories(&[1]);
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xe1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let staging = staging_fixture(47, &[event]);
    staging_source
        .begin_staged_result(
            &staging.key_context(),
            staging.source_identity_digest,
            staging.acquisition_receipt_id,
        )
        .unwrap();
    staging_source
        .stage_authorized_event(
            &staging.result_id,
            event.event_id,
            event.exactness_basis,
            b"private-unsealed",
        )
        .unwrap();
    assert_eq!(
        staging_source
            .export_sealed_bundle(staging.expected_context())
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
    staging_source.destroy(&staging.result_id).unwrap();

    let (source, destination) = shared_frame_repositories(&[1]);
    let (authority, _) = stage_and_seal_events(
        &source,
        48,
        &[(false, event, b"sealed-then-destroyed".to_vec())],
    );
    let canonical = source
        .export_sealed_bundle(authority.expected_context())
        .unwrap()
        .encode();
    source.destroy(&authority.result_id).unwrap();
    assert_eq!(
        destination.import_sealed_bundle(
            authority.expected_context(),
            SealedEncryptedCoreResultBundleV1::decode(&canonical).unwrap(),
        ),
        Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)
    );
    assert_eq!(destination.len(), Ok(0));
}

#[test]
fn sealed_bundle_debug_and_errors_do_not_expose_ciphertext_canaries_or_authority() {
    let (source, _) = shared_frame_repositories(&[1]);
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xf1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let canary = b"secret-bundle-canary\0\xff";
    let (authority, _) = stage_and_seal_events(&source, 49, &[(false, event, canary.to_vec())]);
    let bundle = source
        .export_sealed_bundle(authority.expected_context())
        .unwrap();
    let encoded = bundle.encode();
    assert!(!encoded.windows(canary.len()).any(|window| window == canary));
    let debug = format!("{bundle:?}");
    assert!(!debug.contains("secret-bundle-canary"));
    assert!(!debug.contains(&authority.result_id.canonical_token()));
    let error_debug = format!(
        "{:?}",
        SealedEncryptedCoreResultBundleV1::decode(b"secret-bundle-canary").unwrap_err()
    );
    assert!(!error_debug.contains("secret-bundle-canary"));
}

#[test]
fn authenticated_bundle_import_enforces_repository_capacity_without_partial_state() {
    let (source, _) = shared_frame_repositories(&[1, 1]);
    let destination =
        MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(source.provider_for_test()), 1)
            .unwrap();
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xf2; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xf3; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (first, _) = stage_and_seal_events(
        &source,
        50,
        &[(false, first_event, b"capacity-one".to_vec())],
    );
    let first_bundle = source
        .export_sealed_bundle(first.expected_context())
        .unwrap();
    let (second, _) = stage_and_seal_events(
        &source,
        51,
        &[(false, second_event, b"capacity-two".to_vec())],
    );
    let second_bundle = source
        .export_sealed_bundle(second.expected_context())
        .unwrap();

    destination
        .import_sealed_bundle(first.expected_context(), first_bundle)
        .unwrap();
    assert_eq!(
        destination.import_sealed_bundle(second.expected_context(), second_bundle),
        Err(EncryptedCoreResultRepositoryErrorV1::CapacityExceeded)
    );
    assert_eq!(destination.len(), Ok(1));
    assert_eq!(
        destination
            .open_stored_event(first.expected_context(), first_event.event_id)
            .unwrap()
            .as_bytes(),
        b"capacity-one"
    );
    assert_eq!(
        destination
            .open_stored_event(second.expected_context(), second_event.event_id)
            .err(),
        Some(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)
    );
}

static SYNTHETIC_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

struct SyntheticBundleRoot {
    path: PathBuf,
}

impl SyntheticBundleRoot {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let ordinal = SYNTHETIC_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "evidentrail-synthetic-bundle-{}-{ordinal}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn store(&self) -> FilesystemSealedBundleStoreV1 {
        FilesystemSealedBundleStoreV1::open_existing_root(&self.path).unwrap()
    }
}

impl Drop for SyntheticBundleRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn filesystem_bundle_fixture(
    seed: u8,
    payload: &[u8],
) -> (SealedEncryptedCoreResultBundleV1, ResultId) {
    let (source, _) = shared_frame_repositories(&[1]);
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([seed; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) = stage_and_seal_events(&source, seed, &[(false, event, payload.to_vec())]);
    (
        source
            .export_sealed_bundle(authority.expected_context())
            .unwrap(),
        authority.result_id,
    )
}

#[test]
fn filesystem_publication_orders_barriers_uses_strict_modes_and_reads_back_exactly() {
    let root = SyntheticBundleRoot::new();
    let store = root.store();
    let payload = b"synthetic-only\0\xff\r\n";
    let (bundle, result_id) = filesystem_bundle_fixture(52, payload);
    let encoded = bundle.encode();

    assert_eq!(
        store.publish(&bundle),
        Ok(evidentrail_store::FilesystemBundlePublicationV1::BarrierIssuedAndReadBack)
    );
    assert_eq!(
        store.operations_for_test().unwrap(),
        vec![
            FilesystemBundleOperationV1::TemporaryCreated,
            FilesystemBundleOperationV1::BytesWritten,
            FilesystemBundleOperationV1::FileSynced,
            FilesystemBundleOperationV1::PublishedNoReplace,
            FilesystemBundleOperationV1::DirectorySynced,
            FilesystemBundleOperationV1::ReadBackVerified,
        ]
    );
    let final_name = sealed_bundle_filename_v1(result_id);
    let temporary_name = sealed_bundle_temporary_filename_v1(result_id);
    assert_eq!(
        final_name,
        format!("r_{}.sealed-bundle.v1", "b4".repeat(32))
    );
    assert!(root.path().join(&final_name).is_file());
    assert!(!root.path().join(temporary_name).exists());
    let metadata = fs::symlink_metadata(root.path().join(&final_name)).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(store.read(result_id).unwrap().encode(), encoded);
    assert!(
        !fs::read(root.path().join(&final_name))
            .unwrap()
            .windows(payload.len())
            .any(|window| window == payload)
    );

    assert_eq!(
        store.publish(&bundle),
        Err(FilesystemSealedBundleErrorV1::DuplicateResult)
    );
    assert_eq!(fs::read(root.path().join(final_name)).unwrap(), encoded);
}

#[test]
fn filesystem_root_rejects_relative_symlinked_and_permissive_paths() {
    assert_eq!(
        FilesystemSealedBundleStoreV1::open_existing_root(Path::new("relative-root")).err(),
        Some(FilesystemSealedBundleErrorV1::InvalidRootPath)
    );

    let root = SyntheticBundleRoot::new();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        FilesystemSealedBundleStoreV1::open_existing_root(root.path()).err(),
        Some(FilesystemSealedBundleErrorV1::RootPermissionMismatch)
    );
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let alias = root.path().with_extension("symlink-alias");
    symlink(root.path(), &alias).unwrap();
    assert_eq!(
        FilesystemSealedBundleStoreV1::open_existing_root(&alias).err(),
        Some(FilesystemSealedBundleErrorV1::InvalidRootPath)
    );
    fs::remove_file(alias).unwrap();
}

fn report_has(
    report: &evidentrail_store::FilesystemBundleRecoveryReportV1,
    classification: FilesystemBundleRecoveryClassificationV1,
) -> bool {
    report
        .entries()
        .iter()
        .any(|entry| entry.classification() == classification)
}

#[test]
fn filesystem_fault_boundaries_preserve_only_classified_ciphertext_states() {
    let partial_root = SyntheticBundleRoot::new();
    let partial_store = partial_root.store();
    let (partial_bundle, partial_result) = filesystem_bundle_fixture(53, b"partial-write");
    partial_store
        .fail_next_for_test(FilesystemBundleFaultPointV1::PartialWrite { byte_count: 64 })
        .unwrap();
    assert_eq!(
        partial_store.publish(&partial_bundle),
        Err(FilesystemSealedBundleErrorV1::WriteFailed)
    );
    assert!(
        partial_root
            .path()
            .join(sealed_bundle_temporary_filename_v1(partial_result))
            .exists()
    );
    assert!(
        !partial_root
            .path()
            .join(sealed_bundle_filename_v1(partial_result))
            .exists()
    );
    let report = partial_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::InvalidCiphertextQuarantined
    ));
    assert_eq!(
        partial_store.read(partial_result).err(),
        Some(FilesystemSealedBundleErrorV1::ResultUnavailable)
    );

    let unsynced_root = SyntheticBundleRoot::new();
    let unsynced_store = unsynced_root.store();
    let (unsynced_bundle, unsynced_result) = filesystem_bundle_fixture(54, b"full-but-unsynced");
    unsynced_store
        .fail_next_for_test(FilesystemBundleFaultPointV1::BeforeFileSync)
        .unwrap();
    assert_eq!(
        unsynced_store.publish(&unsynced_bundle),
        Err(FilesystemSealedBundleErrorV1::FileSyncFailed)
    );
    let report = unsynced_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::InterruptedTemporaryQuarantined
    ));
    assert_eq!(
        unsynced_store.read(unsynced_result).err(),
        Some(FilesystemSealedBundleErrorV1::ResultUnavailable)
    );

    let ambiguous_root = SyntheticBundleRoot::new();
    let ambiguous_store = ambiguous_root.store();
    let (ambiguous_bundle, ambiguous_result) =
        filesystem_bundle_fixture(55, b"renamed-before-root-sync");
    ambiguous_store
        .fail_next_for_test(FilesystemBundleFaultPointV1::BeforeDirectorySync)
        .unwrap();
    assert_eq!(
        ambiguous_store.publish(&ambiguous_bundle),
        Err(FilesystemSealedBundleErrorV1::DirectorySyncFailed)
    );
    assert_eq!(
        ambiguous_store.operations_for_test().unwrap(),
        vec![
            FilesystemBundleOperationV1::TemporaryCreated,
            FilesystemBundleOperationV1::BytesWritten,
            FilesystemBundleOperationV1::FileSynced,
            FilesystemBundleOperationV1::PublishedNoReplace,
        ]
    );
    let report = ambiguous_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::StructurallyValidFinal
    ));
    assert_eq!(
        ambiguous_store.read(ambiguous_result).unwrap().encode(),
        ambiguous_bundle.encode()
    );
}

#[test]
fn filesystem_recovery_quarantines_truncation_trailing_bytes_and_result_swap() {
    let truncated_root = SyntheticBundleRoot::new();
    let truncated_store = truncated_root.store();
    let (truncated_bundle, truncated_result) = filesystem_bundle_fixture(56, b"truncate-me");
    truncated_store.publish(&truncated_bundle).unwrap();
    OpenOptions::new()
        .write(true)
        .open(
            truncated_root
                .path()
                .join(sealed_bundle_filename_v1(truncated_result)),
        )
        .unwrap()
        .set_len(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1 as u64 - 1)
        .unwrap();
    let report = truncated_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::InvalidCiphertextQuarantined
    ));

    let trailing_root = SyntheticBundleRoot::new();
    let trailing_store = trailing_root.store();
    let (trailing_bundle, trailing_result) = filesystem_bundle_fixture(57, b"append-me");
    trailing_store.publish(&trailing_bundle).unwrap();
    OpenOptions::new()
        .append(true)
        .open(
            trailing_root
                .path()
                .join(sealed_bundle_filename_v1(trailing_result)),
        )
        .unwrap()
        .write_all(b"trailing")
        .unwrap();
    let report = trailing_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::InvalidCiphertextQuarantined
    ));

    let swap_root = SyntheticBundleRoot::new();
    let swap_store = swap_root.store();
    let (first_bundle, first_result) = filesystem_bundle_fixture(58, b"first-result");
    let (second_bundle, _) = filesystem_bundle_fixture(59, b"second-result");
    swap_store.publish(&first_bundle).unwrap();
    fs::write(
        swap_root
            .path()
            .join(sealed_bundle_filename_v1(first_result)),
        second_bundle.encode(),
    )
    .unwrap();
    assert_eq!(
        swap_store.read(first_result).err(),
        Some(FilesystemSealedBundleErrorV1::AuthorityMismatch)
    );
    let report = swap_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::AuthorityMismatchQuarantined
    ));
}

#[test]
fn filesystem_rejects_and_quarantines_permissions_symlinks_hardlinks_and_aliases() {
    let permission_root = SyntheticBundleRoot::new();
    let permission_store = permission_root.store();
    let (permission_bundle, permission_result) = filesystem_bundle_fixture(60, b"permissions");
    permission_store.publish(&permission_bundle).unwrap();
    fs::set_permissions(
        permission_root
            .path()
            .join(sealed_bundle_filename_v1(permission_result)),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(
        permission_store.read(permission_result).err(),
        Some(FilesystemSealedBundleErrorV1::PermissionMismatch)
    );
    let report = permission_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::UnsafeMetadataQuarantined
    ));

    let symlink_root = SyntheticBundleRoot::new();
    let symlink_store = symlink_root.store();
    let (_, symlink_result) = filesystem_bundle_fixture(61, b"symlink");
    let sentinel = symlink_root.path().join("foreign-sentinel");
    fs::write(&sentinel, b"sentinel-unchanged").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(
        &sentinel,
        symlink_root
            .path()
            .join(sealed_bundle_filename_v1(symlink_result)),
    )
    .unwrap();
    assert_eq!(
        symlink_store.read(symlink_result).err(),
        Some(FilesystemSealedBundleErrorV1::UnsafeObject)
    );
    let report = symlink_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::UnsafeMetadataQuarantined
    ));
    assert_eq!(fs::read(sentinel).unwrap(), b"sentinel-unchanged");

    let hardlink_root = SyntheticBundleRoot::new();
    let hardlink_store = hardlink_root.store();
    let (hardlink_bundle, hardlink_result) = filesystem_bundle_fixture(62, b"hard-link");
    hardlink_store.publish(&hardlink_bundle).unwrap();
    let final_path = hardlink_root
        .path()
        .join(sealed_bundle_filename_v1(hardlink_result));
    fs::hard_link(&final_path, hardlink_root.path().join("foreign-hard-link")).unwrap();
    assert_eq!(
        hardlink_store.read(hardlink_result).err(),
        Some(FilesystemSealedBundleErrorV1::HardLinkRejected)
    );
    let report = hardlink_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::UnsafeMetadataQuarantined
    ));

    let alias_root = SyntheticBundleRoot::new();
    let alias_store = alias_root.store();
    let (alias_bundle, alias_result) = filesystem_bundle_fixture(63, b"case-alias");
    let alias_name = sealed_bundle_filename_v1(alias_result).to_ascii_uppercase();
    fs::write(alias_root.path().join(&alias_name), alias_bundle.encode()).unwrap();
    fs::set_permissions(
        alias_root.path().join(&alias_name),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        alias_store.read(alias_result).err(),
        Some(FilesystemSealedBundleErrorV1::ResultUnavailable)
    );
    let report = alias_store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::NoncanonicalAliasQuarantined
    ));
}

#[test]
fn filesystem_concurrent_publish_is_create_only_and_never_replaces_a_winner() {
    let root = SyntheticBundleRoot::new();
    let first_store = Arc::new(root.store());
    let second_store = Arc::new(root.store());
    let (bundle, result_id) = filesystem_bundle_fixture(64, b"concurrent-winner");
    let canonical = bundle.encode();
    let bundle = Arc::new(bundle);
    let barrier = Arc::new(Barrier::new(2));

    let first = {
        let store = Arc::clone(&first_store);
        let bundle = Arc::clone(&bundle);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            store.publish(&bundle)
        })
    };
    let second = {
        let store = Arc::clone(&second_store);
        let bundle = Arc::clone(&bundle);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            store.publish(&bundle)
        })
    };
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| matches!(
                error,
                FilesystemSealedBundleErrorV1::TemporaryExists
                    | FilesystemSealedBundleErrorV1::DuplicateResult
            ))
    );
    assert_eq!(first_store.read(result_id).unwrap().encode(), canonical);
    assert!(
        !root
            .path()
            .join(sealed_bundle_temporary_filename_v1(result_id))
            .exists()
    );

    let sentinel_root = SyntheticBundleRoot::new();
    let sentinel_store = sentinel_root.store();
    let (sentinel_bundle, sentinel_result) = filesystem_bundle_fixture(65, b"must-not-overwrite");
    let final_path = sentinel_root
        .path()
        .join(sealed_bundle_filename_v1(sentinel_result));
    fs::write(&final_path, b"preexisting-sentinel").unwrap();
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        sentinel_store.publish(&sentinel_bundle),
        Err(FilesystemSealedBundleErrorV1::DuplicateResult)
    );
    assert_eq!(fs::read(final_path).unwrap(), b"preexisting-sentinel");
}

#[test]
fn filesystem_recovery_preserves_identical_final_and_quarantines_only_retry_temp() {
    let root = SyntheticBundleRoot::new();
    let store = root.store();
    let (bundle, result_id) = filesystem_bundle_fixture(66, b"same-final-and-temp");
    store.publish(&bundle).unwrap();
    let final_path = root.path().join(sealed_bundle_filename_v1(result_id));
    let temporary_path = root
        .path()
        .join(sealed_bundle_temporary_filename_v1(result_id));
    fs::copy(&final_path, &temporary_path).unwrap();
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)).unwrap();

    let report = store.recover_and_quarantine().unwrap();
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::StructurallyValidFinal
    ));
    assert!(report_has(
        &report,
        FilesystemBundleRecoveryClassificationV1::InterruptedTemporaryQuarantined
    ));
    assert_eq!(store.read(result_id).unwrap().encode(), bundle.encode());
    assert!(!temporary_path.exists());
    assert!(
        root.path()
            .join(format!(
                ".quarantine-{}",
                sealed_bundle_temporary_filename_v1(result_id)
            ))
            .exists()
    );
}

#[test]
fn filesystem_recovery_fails_closed_on_conflict_and_quarantine_collision() {
    let conflict_root = SyntheticBundleRoot::new();
    let conflict_store = conflict_root.store();
    let (first_bundle, first_result) = filesystem_bundle_fixture(67, b"conflict-first");
    let (foreign_bundle, _) = filesystem_bundle_fixture(68, b"conflict-foreign");
    conflict_store.publish(&first_bundle).unwrap();
    let temporary_path = conflict_root
        .path()
        .join(sealed_bundle_temporary_filename_v1(first_result));
    fs::write(&temporary_path, foreign_bundle.encode()).unwrap();
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)).unwrap();
    let report = conflict_store.recover_and_quarantine().unwrap();
    assert_eq!(
        report
            .entries()
            .iter()
            .filter(|entry| {
                entry.classification()
                    == FilesystemBundleRecoveryClassificationV1::ConflictingStateQuarantined
            })
            .count(),
        2
    );
    assert_eq!(
        conflict_store.read(first_result).err(),
        Some(FilesystemSealedBundleErrorV1::ResultUnavailable)
    );

    let collision_root = SyntheticBundleRoot::new();
    let collision_store = collision_root.store();
    let (collision_bundle, collision_result) = filesystem_bundle_fixture(69, b"collision");
    collision_store
        .fail_next_for_test(FilesystemBundleFaultPointV1::PartialWrite { byte_count: 16 })
        .unwrap();
    assert_eq!(
        collision_store.publish(&collision_bundle),
        Err(FilesystemSealedBundleErrorV1::WriteFailed)
    );
    let temporary_name = sealed_bundle_temporary_filename_v1(collision_result);
    let quarantine_path = collision_root
        .path()
        .join(format!(".quarantine-{temporary_name}"));
    fs::write(&quarantine_path, b"occupied").unwrap();
    fs::set_permissions(&quarantine_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        collision_store.recover_and_quarantine().err(),
        Some(FilesystemSealedBundleErrorV1::QuarantineCollision)
    );
    assert!(collision_root.path().join(temporary_name).exists());
}

#[test]
fn filesystem_public_types_and_recovery_debug_are_contentless() {
    let root = SyntheticBundleRoot::new();
    let store = root.store();
    let canary = b"filesystem-debug-secret\0\xff";
    let (bundle, result_id) = filesystem_bundle_fixture(70, canary);
    store.publish(&bundle).unwrap();
    let report = store.recover_and_quarantine().unwrap();
    let rendered = format!(
        "{store:?} {report:?} {:?} {:?} {:?}",
        report.entries()[0],
        FilesystemSealedBundleErrorV1::BundleDecodeFailed,
        FilesystemBundleFaultPointV1::PartialWrite { byte_count: 7 }
    );
    assert!(!rendered.contains("filesystem-debug-secret"));
    assert!(!rendered.contains(&result_id.canonical_token()));
    assert!(!rendered.contains(root.path().to_string_lossy().as_ref()));
}

#[test]
fn authenticated_restart_imports_only_after_full_authentication_and_opens_exact_event() {
    let root = SyntheticBundleRoot::new();
    let (source, unused_destination) = shared_frame_repositories(&[1]);
    let provider = Arc::clone(source.provider_for_test());
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x81; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let plaintext = b"restart-exact\0\xff\r\n".to_vec();
    let (authority, _) = stage_and_seal_events(&source, 71, &[(false, event, plaintext.clone())]);
    let unrelated_provider =
        Arc::new(EphemeralKeyProviderV1::new(ScriptedEntropy::new([]), 2).unwrap());
    let unrelated =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), unrelated_provider, 2)
            .unwrap();
    assert_eq!(
        unrelated.publish_from_repository(
            &source,
            authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        ),
        Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable)
    );
    assert!(root.store().read(authority.result_id).is_err());
    drop(unrelated);
    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 2)
            .unwrap();
    publisher
        .publish_from_repository(
            &source,
            authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();

    drop(publisher);
    drop(source);
    drop(unused_destination);
    let expected_plaintext = plaintext.clone();
    drop(plaintext);

    let recovered =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 2).unwrap();
    let publication = recovered
        .recover(authority.expected_context(), UnixTimestampNanos::new(1_501))
        .unwrap();
    assert_eq!(
        publication.disposition(),
        AuthenticatedFilesystemRecoveryDispositionV1::Imported
    );
    assert_eq!(recovered.visible_result_count(), Ok(1));
    let opened = recovered
        .open_event(
            authority.expected_context(),
            event.event_id,
            UnixTimestampNanos::new(1_502),
        )
        .unwrap();
    assert_eq!(opened.event_id(), event.event_id);
    assert_eq!(opened.exactness_basis(), event.exactness_basis);
    assert_eq!(opened.as_bytes(), expected_plaintext);
    assert_eq!(
        recovered
            .recover(authority.expected_context(), UnixTimestampNanos::new(1_503),)
            .unwrap()
            .disposition(),
        AuthenticatedFilesystemRecoveryDispositionV1::AlreadyVisible
    );

    let rendered = format!(
        "{recovered:?} {publication:?} {:?}",
        AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined
    );
    assert!(!rendered.contains("restart-exact"));
    assert!(!rendered.contains(&authority.result_id.canonical_token()));
    assert!(!rendered.contains(root.path().to_string_lossy().as_ref()));
}

#[test]
fn authenticated_restart_quarantines_a_structural_bundle_that_fails_aead() {
    let root = SyntheticBundleRoot::new();
    let (source, unused_destination) = shared_frame_repositories(&[1]);
    let provider = Arc::clone(source.provider_for_test());
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x82; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) = stage_and_seal_events(
        &source,
        72,
        &[(false, event, b"authenticated-tamper".to_vec())],
    );
    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 2)
            .unwrap();
    publisher
        .publish_from_repository(
            &source,
            authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(publisher);
    drop(source);
    drop(unused_destination);

    let final_path = root
        .path()
        .join(sealed_bundle_filename_v1(authority.result_id));
    let mut encoded = fs::read(&final_path).unwrap();
    let frame = frame_payload_range(&encoded, 0);
    encoded[frame.end - 1] ^= 0x40;
    fs::write(&final_path, encoded).unwrap();
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();

    let recovered =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 2).unwrap();
    assert_eq!(
        recovered.recover(authority.expected_context(), UnixTimestampNanos::new(1_501),),
        Err(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    );
    assert_eq!(recovered.visible_result_count(), Ok(0));
    assert!(!final_path.exists());
    assert!(
        root.path()
            .join(format!(
                ".quarantine-{}",
                sealed_bundle_filename_v1(authority.result_id)
            ))
            .exists()
    );
}

#[test]
fn authenticated_restart_enforces_expiry_without_quarantining_valid_ciphertext() {
    let root = SyntheticBundleRoot::new();
    let (source, unused_destination) = shared_frame_repositories(&[1]);
    let provider = Arc::clone(source.provider_for_test());
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x83; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) =
        stage_and_seal_events(&source, 73, &[(false, event, b"expiry-boundary".to_vec())]);
    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 2)
            .unwrap();
    publisher
        .publish_from_repository(
            &source,
            authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(source);
    drop(unused_destination);
    drop(publisher);

    let recovered =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 2).unwrap();
    assert_eq!(
        recovered.recover(authority.expected_context(), UnixTimestampNanos::new(2_000),),
        Err(AuthenticatedFilesystemRestartErrorV1::OutsideValidity)
    );
    assert_eq!(recovered.visible_result_count(), Ok(0));
    assert!(
        root.path()
            .join(sealed_bundle_filename_v1(authority.result_id))
            .exists()
    );
    assert_eq!(
        recovered
            .open_event(
                authority.expected_context(),
                event.event_id,
                UnixTimestampNanos::new(2_000),
            )
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::OutsideValidity)
    );
}

#[test]
fn authenticated_restart_quarantines_ciphertext_after_key_authority_is_destroyed() {
    let root = SyntheticBundleRoot::new();
    let (source, unused_destination) = shared_frame_repositories(&[1]);
    let provider = Arc::clone(source.provider_for_test());
    let event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x84; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (authority, _) =
        stage_and_seal_events(&source, 74, &[(false, event, b"destroyed-key".to_vec())]);
    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 2)
            .unwrap();
    publisher
        .publish_from_repository(
            &source,
            authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(publisher);
    drop(source);
    drop(unused_destination);
    provider.set_locked_for_test(true).unwrap();
    let unavailable =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 2)
            .unwrap();
    assert_eq!(
        unavailable.recover(authority.expected_context(), UnixTimestampNanos::new(1_501),),
        Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable)
    );
    assert!(
        root.path()
            .join(sealed_bundle_filename_v1(authority.result_id))
            .exists()
    );
    drop(unavailable);
    provider.set_locked_for_test(false).unwrap();
    assert_eq!(
        provider.destroy_result_key(&authority.result_id),
        Ok(evidentrail_store::KeyDestroyOutcomeV1::Destroyed)
    );

    let recovered =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 2).unwrap();
    assert_eq!(
        recovered.recover(authority.expected_context(), UnixTimestampNanos::new(1_501),),
        Err(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    );
    assert_eq!(recovered.visible_result_count(), Ok(0));
    assert!(
        root.path()
            .join(format!(
                ".quarantine-{}",
                sealed_bundle_filename_v1(authority.result_id)
            ))
            .exists()
    );
}

#[test]
fn authenticated_restart_capacity_failure_leaves_the_second_candidate_retryable() {
    let root = SyntheticBundleRoot::new();
    let (source, unused_destination) = shared_frame_repositories(&[1, 1]);
    let provider = Arc::clone(source.provider_for_test());
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x85; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0x86; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (first, _) = stage_and_seal_events(
        &source,
        75,
        &[(false, first_event, b"capacity-first".to_vec())],
    );
    let (second, _) = stage_and_seal_events(
        &source,
        76,
        &[(false, second_event, b"capacity-second".to_vec())],
    );
    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 1)
            .unwrap();
    publisher
        .publish_from_repository(
            &source,
            first.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    publisher
        .publish_from_repository(
            &source,
            second.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(publisher);
    drop(source);
    drop(unused_destination);

    let recovered =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 1).unwrap();
    recovered
        .recover(first.expected_context(), UnixTimestampNanos::new(1_501))
        .unwrap();
    assert_eq!(
        recovered.recover(second.expected_context(), UnixTimestampNanos::new(1_501),),
        Err(AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable)
    );
    assert_eq!(recovered.visible_result_count(), Ok(1));
    assert_eq!(
        recovered
            .open_event(
                first.expected_context(),
                first_event.event_id,
                UnixTimestampNanos::new(1_502),
            )
            .unwrap()
            .as_bytes(),
        b"capacity-first"
    );
    assert_eq!(
        root.store().read(second.result_id).unwrap().result_id(),
        second.result_id
    );
}

#[test]
fn displayed_alias_manifest_recomputes_reference_identity_and_rejects_noncanonical_material() {
    let result_id = ResultId::from_bytes([0xa0; 32]);
    let first = EventId::from_bytes([0xa1; 32]);
    let second = EventId::from_bytes([0xa2; 32]);
    let reference = EvidenceReferenceV1::issue(
        result_id,
        [
            EvidenceTargetRef::Event(second),
            EvidenceTargetRef::Event(first),
        ],
        [
            ExpansionRelationV1::GlobalBeforeAfter,
            ExpansionRelationV1::Exact,
        ],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    let entry =
        DisplayedAliasManifestEntryV1::new(result_id, 1, reference.clone(), [first, second])
            .unwrap();
    let manifest =
        DisplayedAliasManifestV1::new(result_id, UnixTimestampNanos::new(200), [entry.clone()])
            .unwrap();
    let encoded = manifest.encode();
    let decoded = DisplayedAliasManifestV1::decode(&encoded).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.entries()[0].reference().id(), reference.id());
    assert_eq!(
        decoded.entries()[0].allowed_relation(),
        ExpansionRelationV1::Exact
    );
    assert_eq!(decoded.entries()[0].ordered_event_ids(), &[first, second]);

    let duplicate_reference = DisplayedAliasManifestV1::new(
        result_id,
        UnixTimestampNanos::new(200),
        [
            entry.clone(),
            DisplayedAliasManifestEntryV1::new(result_id, 2, reference, [second, first]).unwrap(),
        ],
    );
    assert_eq!(
        duplicate_reference,
        Err(DisplayedAliasManifestErrorV1::DuplicateReference)
    );
    let overlapping_reference = EvidenceReferenceV1::issue(
        result_id,
        [EvidenceTargetRef::Event(first)],
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(101),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    assert_eq!(
        DisplayedAliasManifestV1::new(
            result_id,
            UnixTimestampNanos::new(200),
            [
                entry,
                DisplayedAliasManifestEntryV1::new(result_id, 2, overlapping_reference, [first],)
                    .unwrap(),
            ],
        ),
        Err(DisplayedAliasManifestErrorV1::OverlappingAliasEvents)
    );

    let mut reserved = encoded.clone();
    reserved[14] = 1;
    assert_eq!(
        DisplayedAliasManifestV1::decode(&reserved),
        Err(DisplayedAliasManifestErrorV1::NoncanonicalReserved)
    );
    let mut mutated_body = encoded.clone();
    *mutated_body.last_mut().unwrap() ^= 0x40;
    assert_eq!(
        DisplayedAliasManifestV1::decode(&mutated_body),
        Err(DisplayedAliasManifestErrorV1::DigestMismatch)
    );
    let mut forged_reference = encoded.clone();
    forged_reference[DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1 + 8] ^= 0x01;
    let body = &forged_reference[DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1..];
    let mut digest = Sha256::new();
    for field in [
        b"evidentrail/displayed-alias-manifest/v1".as_slice(),
        &1u16.to_be_bytes(),
        result_id.as_bytes(),
        &UnixTimestampNanos::new(200).get().to_be_bytes(),
        body,
    ] {
        digest.update(u64::try_from(field.len()).unwrap().to_be_bytes());
        digest.update(field);
    }
    let rebound_digest: [u8; 32] = digest.finalize().into();
    forged_reference[72..104].copy_from_slice(&rebound_digest);
    assert_eq!(
        DisplayedAliasManifestV1::decode(&forged_reference),
        Err(DisplayedAliasManifestErrorV1::ReferenceMismatch)
    );
    let mut excessive_count = encoded;
    excessive_count[64..68].copy_from_slice(&513u32.to_be_bytes());
    assert_eq!(
        DisplayedAliasManifestV1::decode(&excessive_count),
        Err(DisplayedAliasManifestErrorV1::TooManyAliases)
    );

    let rendered = format!(
        "{manifest:?} {:?} {:?}",
        manifest.entries()[0],
        DisplayedAliasManifestErrorV1::ReferenceMismatch
    );
    assert!(!rendered.contains(&result_id.canonical_token()));
    assert!(!rendered.contains(&decoded.entries()[0].reference().id().to_string()));
    assert!(!rendered.contains("a1a1a1"));
}

#[test]
fn recovered_alias_manifest_tamper_and_cross_result_substitution_are_quarantined() {
    let tamper_root = SyntheticBundleRoot::new();
    let (tamper_source, tamper_unused) = shared_frame_repositories(&[2]);
    let tamper_provider = Arc::clone(tamper_source.provider_for_test());
    let tamper_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb1; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (tamper_authority, _) = stage_and_seal_alias_result(
        &tamper_source,
        77,
        &[(tamper_event, b"alias-tamper-canary".to_vec())],
    );
    let tamper_publisher = AuthenticatedFilesystemRestartCoordinatorV1::new(
        tamper_root.store(),
        Arc::clone(&tamper_provider),
        2,
    )
    .unwrap();
    tamper_publisher
        .publish_from_repository(
            &tamper_source,
            tamper_authority.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(tamper_publisher);
    drop(tamper_source);
    drop(tamper_unused);
    let tamper_path = tamper_root
        .path()
        .join(sealed_bundle_filename_v1(tamper_authority.result_id));
    let mut tampered = fs::read(&tamper_path).unwrap();
    let alias_frame = frame_payload_range(&tampered, 1);
    tampered[alias_frame.end - 1] ^= 0x20;
    fs::write(&tamper_path, tampered).unwrap();
    fs::set_permissions(&tamper_path, fs::Permissions::from_mode(0o600)).unwrap();
    let tamper_recovery =
        AuthenticatedFilesystemRestartCoordinatorV1::new(tamper_root.store(), tamper_provider, 2)
            .unwrap();
    assert_eq!(
        tamper_recovery
            .recover_exact_alias_result(
                tamper_authority.expected_context(),
                UnixTimestampNanos::new(1_501),
            )
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    );
    assert_eq!(tamper_recovery.visible_result_count(), Ok(0));

    let swap_root = SyntheticBundleRoot::new();
    let (swap_source, swap_unused) = shared_frame_repositories(&[2, 2]);
    let swap_provider = Arc::clone(swap_source.provider_for_test());
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb2; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb3; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (first, _) = stage_and_seal_alias_result(
        &swap_source,
        78,
        &[(first_event, b"same-sized-first".to_vec())],
    );
    let (second, _) = stage_and_seal_alias_result(
        &swap_source,
        79,
        &[(second_event, b"same-sized-other".to_vec())],
    );
    let swap_publisher = AuthenticatedFilesystemRestartCoordinatorV1::new(
        swap_root.store(),
        Arc::clone(&swap_provider),
        2,
    )
    .unwrap();
    for authority in [&first, &second] {
        swap_publisher
            .publish_from_repository(
                &swap_source,
                authority.expected_context(),
                UnixTimestampNanos::new(1_500),
            )
            .unwrap();
    }
    drop(swap_publisher);
    drop(swap_source);
    drop(swap_unused);
    let first_path = swap_root
        .path()
        .join(sealed_bundle_filename_v1(first.result_id));
    let second_path = swap_root
        .path()
        .join(sealed_bundle_filename_v1(second.result_id));
    let mut first_bytes = fs::read(&first_path).unwrap();
    let mut second_bytes = fs::read(&second_path).unwrap();
    let first_alias = frame_payload_range(&first_bytes, 1);
    let second_alias = frame_payload_range(&second_bytes, 1);
    assert_eq!(first_alias.len(), second_alias.len());
    let original_first_alias = first_bytes[first_alias.clone()].to_vec();
    first_bytes[first_alias].copy_from_slice(&second_bytes[second_alias.clone()]);
    second_bytes[second_alias].copy_from_slice(&original_first_alias);
    fs::write(&first_path, first_bytes).unwrap();
    fs::write(&second_path, second_bytes).unwrap();
    fs::set_permissions(&first_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&second_path, fs::Permissions::from_mode(0o600)).unwrap();
    let swap_recovery =
        AuthenticatedFilesystemRestartCoordinatorV1::new(swap_root.store(), swap_provider, 2)
            .unwrap();
    assert_eq!(
        swap_recovery
            .recover_exact_alias_result(first.expected_context(), UnixTimestampNanos::new(1_501),)
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    );
    assert_eq!(swap_recovery.visible_result_count(), Ok(0));
}

#[test]
fn recovered_alias_destroyed_key_capacity_and_expansion_caps_fail_closed() {
    let destroyed_root = SyntheticBundleRoot::new();
    let (destroyed_source, destroyed_unused) = shared_frame_repositories(&[2]);
    let destroyed_provider = Arc::clone(destroyed_source.provider_for_test());
    let destroyed_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb4; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (destroyed, _) = stage_and_seal_alias_result(
        &destroyed_source,
        80,
        &[(destroyed_event, b"destroyed-alias-key".to_vec())],
    );
    let destroyed_publisher = AuthenticatedFilesystemRestartCoordinatorV1::new(
        destroyed_root.store(),
        Arc::clone(&destroyed_provider),
        2,
    )
    .unwrap();
    destroyed_publisher
        .publish_from_repository(
            &destroyed_source,
            destroyed.expected_context(),
            UnixTimestampNanos::new(1_500),
        )
        .unwrap();
    drop(destroyed_publisher);
    drop(destroyed_source);
    drop(destroyed_unused);
    assert_eq!(
        destroyed_provider.destroy_result_key(&destroyed.result_id),
        Ok(evidentrail_store::KeyDestroyOutcomeV1::Destroyed)
    );
    let destroyed_recovery = AuthenticatedFilesystemRestartCoordinatorV1::new(
        destroyed_root.store(),
        destroyed_provider,
        2,
    )
    .unwrap();
    assert_eq!(
        destroyed_recovery
            .recover_exact_alias_result(
                destroyed.expected_context(),
                UnixTimestampNanos::new(1_501),
            )
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    );

    let capacity_root = SyntheticBundleRoot::new();
    let (capacity_source, capacity_unused) = shared_frame_repositories(&[2, 2]);
    let capacity_provider = Arc::clone(capacity_source.provider_for_test());
    let first_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb5; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let second_event = TestPersistedEvent {
        event_id: EventId::from_bytes([0xb6; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    };
    let (first, first_reference) = stage_and_seal_alias_result(
        &capacity_source,
        81,
        &[(first_event, b"atomic-whole-event".to_vec())],
    );
    let (second, _) = stage_and_seal_alias_result(
        &capacity_source,
        82,
        &[(second_event, b"capacity-second-alias".to_vec())],
    );
    let capacity_publisher = AuthenticatedFilesystemRestartCoordinatorV1::new(
        capacity_root.store(),
        Arc::clone(&capacity_provider),
        1,
    )
    .unwrap();
    for authority in [&first, &second] {
        capacity_publisher
            .publish_from_repository(
                &capacity_source,
                authority.expected_context(),
                UnixTimestampNanos::new(1_500),
            )
            .unwrap();
    }
    drop(capacity_publisher);
    drop(capacity_source);
    drop(capacity_unused);
    let capacity_recovery = AuthenticatedFilesystemRestartCoordinatorV1::new(
        capacity_root.store(),
        capacity_provider,
        1,
    )
    .unwrap();
    let handle = capacity_recovery
        .recover_exact_alias_result(first.expected_context(), UnixTimestampNanos::new(1_501))
        .unwrap();
    assert_eq!(
        capacity_recovery
            .recover_exact_alias_result(second.expected_context(), UnixTimestampNanos::new(1_501),)
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable)
    );
    assert!(
        capacity_root.store().read(second.result_id).is_ok(),
        "capacity failure must leave the canonical ciphertext retryable"
    );
    let alias = EvidenceAliasV1::new(first.result_id, 1).unwrap();
    let low_bytes = AliasExpansionRequestV1::new(
        first.result_id,
        alias,
        ExpansionRelationV1::Exact,
        ExpansionLimitV1::new(1, 1, 0, 0).unwrap(),
    );
    assert_eq!(
        handle
            .expand_alias(low_bytes, UnixTimestampNanos::new(1_502))
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::InsufficientExpansionBudget)
    );
    let exact = handle
        .expand_alias(
            AliasExpansionRequestV1::new(
                first.result_id,
                alias,
                ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
            ),
            UnixTimestampNanos::new(1_502),
        )
        .unwrap();
    assert_eq!(exact.reference_id(), first_reference.id());
    assert_eq!(exact.events().len(), 1);
    assert_eq!(exact.events()[0].as_bytes(), b"atomic-whole-event");
    assert!(!exact.truncated());
}
