#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use evidentrail_schema::{EventId, ExactnessBasis, ResultId};
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, LifecycleDigestV1, LifecycleTransitionV1, OperationIdV1,
};
use evidentrail_store::{
    AuthorityDestroyOutcomeV2, BatchCommitInputV2, DataCommitInputV2, DurableEventInputV2,
    DurableRepositoryFaultInjectorV2, DurableRepositoryFaultPointV2, DurableResultRepositoryV2,
    KeyAuthorityErrorV2, KeyAuthorityV2, ProcessKeyAuthorityV2, RecoveryDispositionV2, SealInputV2,
};

#[derive(Clone, Default)]
struct FailOnce(Arc<Mutex<Option<DurableRepositoryFaultPointV2>>>);

impl FailOnce {
    fn arm(&self, point: DurableRepositoryFaultPointV2) {
        *self.0.lock().unwrap() = Some(point);
    }
}

impl DurableRepositoryFaultInjectorV2 for FailOnce {
    fn fail_at(&self, point: DurableRepositoryFaultPointV2) -> bool {
        let mut armed = self.0.lock().unwrap();
        if *armed == Some(point) {
            *armed = None;
            true
        } else {
            false
        }
    }
}

fn digest(byte: u8) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationIdV1 {
    OperationIdV1::from_bytes([byte; 16])
}

fn build() -> BuildContextDigestsV1 {
    BuildContextDigestsV1::new(digest(1), digest(2), digest(3), digest(4), digest(5))
}

fn unique_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "evidentrail-durable-v2-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ))
}

fn commit_one_batch(
    repository: &DurableResultRepositoryV2<Arc<ProcessKeyAuthorityV2>>,
    result_id: ResultId,
    event_id: EventId,
    operation_byte: u8,
) {
    let batch = BatchCommitInputV2::new(
        0,
        operation(operation_byte),
        vec![
            DurableEventInputV2::new(
                event_id,
                ExactnessBasis::SourceExact,
                b"authorized-basis".to_vec(),
            )
            .unwrap(),
        ],
        vec![b"semantic".to_vec()],
        vec![b"operational".to_vec()],
    )
    .unwrap();
    repository.commit_batch(result_id, &batch).unwrap();
}

fn commit_data(
    repository: &DurableResultRepositoryV2<Arc<ProcessKeyAuthorityV2>>,
    result_id: ResultId,
    operation_byte: u8,
) {
    repository
        .commit_data(
            result_id,
            DataCommitInputV2 {
                operation: operation(operation_byte),
                question_configuration: digest(10),
                acquisition_receipt: digest(11),
                transformation_receipts: digest(12),
                fetch_completion: digest(13),
                source_identity: digest(14),
                build_context: build(),
            },
        )
        .unwrap();
}

fn seal_result(
    repository: &DurableResultRepositoryV2<Arc<ProcessKeyAuthorityV2>>,
    result_id: ResultId,
    operation_byte: u8,
) {
    repository
        .seal(
            result_id,
            &SealInputV2 {
                operation: operation(operation_byte),
                log_brief: b"brief".to_vec(),
                references: b"references".to_vec(),
                presentation_receipt: b"presentation".to_vec(),
                status: b"status".to_vec(),
                alias_manifest: b"aliases".to_vec(),
            },
        )
        .unwrap();
}

#[test]
fn data_commit_globally_orders_entries_before_multi_shard_indexing() {
    const EVENT_COUNT: usize =
        evidentrail_snapshot_format::MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2 + 1;
    let root = unique_root().with_extension("multi-shard-order");
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let repository =
        DurableResultRepositoryV2::open(&root, Arc::new(ProcessKeyAuthorityV2::new(1).unwrap()))
            .unwrap();
    let result_id = ResultId::from_bytes([0x21; 32]);
    repository
        .begin(result_id, 100, 10_000, operation(1), b"request")
        .unwrap();

    let mut target = None;
    for (batch_ordinal, first) in (0..EVENT_COUNT)
        .step_by(evidentrail_store::MAX_DURABLE_BATCH_EVENTS_V2)
        .enumerate()
    {
        let end = EVENT_COUNT.min(first + evidentrail_store::MAX_DURABLE_BATCH_EVENTS_V2);
        let events = (first..end)
            .map(|ordinal| {
                let mut id = [0_u8; 32];
                id[24..]
                    .copy_from_slice(&u64::try_from(EVENT_COUNT - ordinal).unwrap().to_be_bytes());
                let event_id = EventId::from_bytes(id);
                if ordinal == EVENT_COUNT / 2 {
                    target = Some(event_id);
                }
                DurableEventInputV2::new(
                    event_id,
                    ExactnessBasis::SourceExact,
                    ordinal.to_be_bytes().to_vec(),
                )
                .unwrap()
            })
            .collect();
        let mut operation_bytes = [0_u8; 16];
        operation_bytes[0] = 2;
        operation_bytes[8..].copy_from_slice(&u64::try_from(batch_ordinal).unwrap().to_be_bytes());
        let batch = BatchCommitInputV2::new(
            u64::try_from(batch_ordinal).unwrap(),
            OperationIdV1::from_bytes(operation_bytes),
            events,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        repository.commit_batch(result_id, &batch).unwrap();
    }

    commit_data(&repository, result_id, 3);
    seal_result(&repository, result_id, 4);
    repository.publish(result_id, operation(5)).unwrap();
    let target = target.unwrap();
    let expanded = repository
        .expand(result_id, &[target], 1, 1024, 200)
        .unwrap();
    assert_eq!(expanded.events().len(), 1);
    assert_eq!(expanded.events()[0].event_id(), target);
    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn durable_lifecycle_is_invisible_until_publication_and_expands_by_index() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = ProcessKeyAuthorityV2::new(8).unwrap();
    let repository = Arc::new(DurableResultRepositoryV2::open(&root, authority).unwrap());
    let result_id = ResultId::from_bytes([0x31; 32]);
    let event_id = EventId::from_bytes([0x41; 32]);
    let exact = b"invalid-utf8:\xff\0blank:\r\n\r\n".to_vec();

    assert_eq!(
        repository.begin(result_id, 100, 10_000, operation(1), b"question\0request"),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert_eq!(
        repository.begin(result_id, 100, 10_000, operation(1), b"question\0request"),
        Ok(LifecycleTransitionV1::AlreadyApplied)
    );

    let batch = BatchCommitInputV2::new(
        0,
        operation(2),
        vec![
            DurableEventInputV2::new(event_id, ExactnessBasis::SourceExact, exact.clone()).unwrap(),
        ],
        vec![b"semantic receipt".to_vec()],
        vec![b"operational receipt".to_vec()],
    )
    .unwrap();
    let first = repository.commit_batch(result_id, &batch).unwrap();
    assert_eq!(first.acknowledgements().len(), 1);
    let retry = repository.commit_batch(result_id, &batch).unwrap();
    assert_eq!(retry.transition(), LifecycleTransitionV1::AlreadyApplied);
    assert_eq!(retry.acknowledgements(), first.acknowledgements());

    assert_eq!(
        repository.commit_data(
            result_id,
            DataCommitInputV2 {
                operation: operation(3),
                question_configuration: digest(10),
                acquisition_receipt: digest(11),
                transformation_receipts: digest(12),
                fetch_completion: digest(13),
                source_identity: digest(14),
                build_context: build(),
            },
        ),
        Ok(LifecycleTransitionV1::Applied)
    );
    let seal = SealInputV2 {
        operation: operation(4),
        log_brief: b"brief".to_vec(),
        references: b"references".to_vec(),
        presentation_receipt: b"presentation".to_vec(),
        status: b"status".to_vec(),
        alias_manifest: b"aliases".to_vec(),
    };
    assert_eq!(
        repository.seal(result_id, &seal),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert!(
        repository
            .expand(result_id, &[event_id], 1, 1024, 200)
            .is_err()
    );
    assert_eq!(
        repository.publish(result_id, operation(5)),
        Ok(LifecycleTransitionV1::Applied)
    );

    let expanded = repository
        .expand(result_id, &[event_id], 1, 1024, 200)
        .unwrap();
    assert_eq!(expanded.events().len(), 1);
    assert_eq!(expanded.events()[0].event_id(), event_id);
    assert_eq!(expanded.events()[0].authorized_bytes(), exact);
    assert_eq!(
        repository.recover(result_id, 200, Some(build())),
        Ok(RecoveryDispositionV2::AlreadyVisible)
    );

    let final_lock = root
        .join(format!("r-{}", "31".repeat(32)))
        .join(".result.lock");
    let reader_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(final_lock)
        .unwrap();
    rustix::fs::flock(&reader_file, rustix::fs::FlockOperation::LockShared).unwrap();
    let (sender, receiver) = mpsc::channel();
    let cleanup_repository = Arc::clone(&repository);
    let cleanup = std::thread::spawn(move || {
        let outcome = cleanup_repository.destroy(result_id);
        sender.send(outcome).unwrap();
    });
    assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
    rustix::fs::flock(&reader_file, rustix::fs::FlockOperation::Unlock).unwrap();
    receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    cleanup.join().unwrap();
    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn selected_frame_mutation_and_repository_commitment_replay_fail_closed() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(4).unwrap()).unwrap();
    let result_id = ResultId::from_bytes([0x51; 32]);
    let event_id = EventId::from_bytes([0x61; 32]);
    repository
        .begin(result_id, 100, 10_000, operation(11), b"request")
        .unwrap();
    let batch = BatchCommitInputV2::new(
        0,
        operation(12),
        vec![
            DurableEventInputV2::new(
                event_id,
                ExactnessBasis::SourceExact,
                b"authorized".to_vec(),
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let committed = repository.commit_batch(result_id, &batch).unwrap();
    let locator = committed.acknowledgements()[0].locator();
    repository
        .commit_data(
            result_id,
            DataCommitInputV2 {
                operation: operation(13),
                question_configuration: digest(20),
                acquisition_receipt: digest(21),
                transformation_receipts: digest(22),
                fetch_completion: digest(23),
                source_identity: digest(24),
                build_context: build(),
            },
        )
        .unwrap();
    repository
        .seal(
            result_id,
            &SealInputV2 {
                operation: operation(14),
                log_brief: b"brief".to_vec(),
                references: b"references".to_vec(),
                presentation_receipt: b"presentation".to_vec(),
                status: b"status".to_vec(),
                alias_manifest: b"aliases".to_vec(),
            },
        )
        .unwrap();
    repository.publish(result_id, operation(15)).unwrap();

    let final_path = root.join(format!("r-{}", "51".repeat(32)));
    let commitment_path = final_path.join("repository.commitment");
    let mut commitment_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&commitment_path)
        .unwrap();
    let mut original_commitment = [0u8; 32];
    commitment_file
        .read_exact(&mut original_commitment)
        .unwrap();
    commitment_file.seek(SeekFrom::Start(0)).unwrap();
    commitment_file
        .write_all(&[original_commitment[0] ^ 1])
        .unwrap();
    commitment_file.sync_all().unwrap();
    assert!(
        repository
            .expand(result_id, &[event_id], 1, 1024, 200)
            .is_err()
    );
    commitment_file.seek(SeekFrom::Start(0)).unwrap();
    commitment_file.write_all(&original_commitment).unwrap();
    commitment_file.sync_all().unwrap();

    let segment = final_path.join(format!("segment-{:020}.seg", locator.segment_ordinal()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(segment)
        .unwrap();
    file.seek(SeekFrom::Start(
        locator.byte_offset() + evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2 as u64,
    ))
    .unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    assert!(
        repository
            .expand(result_id, &[event_id], 1, 1024, 200)
            .is_err()
    );

    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn publication_retry_survives_commitment_write_before_create_only_rename() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = Arc::new(ProcessKeyAuthorityV2::new(4).unwrap());
    let repository = DurableResultRepositoryV2::open(&root, Arc::clone(&authority)).unwrap();
    let result_id = ResultId::from_bytes([0x71; 32]);
    let event_id = EventId::from_bytes([0x72; 32]);
    repository
        .begin(result_id, 100, 10_000, operation(21), b"request")
        .unwrap();
    commit_one_batch(&repository, result_id, event_id, 22);
    commit_data(&repository, result_id, 23);
    seal_result(&repository, result_id, 24);
    assert!(
        repository
            .publish(result_id, OperationIdV1::from_bytes([0; 16]))
            .is_err()
    );
    assert!(
        !root
            .join(format!(".open-{}", "71".repeat(32)))
            .join("repository.commitment")
            .exists()
    );

    let final_path = root.join(format!("r-{}", "71".repeat(32)));
    fs::create_dir(&final_path).unwrap();
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(repository.publish(result_id, operation(25)).is_err());
    let staging = root.join(format!(".open-{}", "71".repeat(32)));
    assert!(staging.join("repository.commitment").is_file());

    fs::remove_dir(&final_path).unwrap();
    assert_eq!(
        repository.publish(result_id, operation(25)),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert_eq!(
        repository.publish(result_id, operation(25)),
        Ok(LifecycleTransitionV1::AlreadyApplied)
    );
    assert_eq!(
        repository
            .expand(result_id, &[event_id], 1, 1024, 200)
            .unwrap()
            .events()[0]
            .authorized_bytes(),
        b"authorized-basis"
    );
    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_reconciles_open_data_sealed_expired_orphan_and_conflict_states() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = Arc::new(ProcessKeyAuthorityV2::new(16).unwrap());
    let repository = DurableResultRepositoryV2::open(&root, Arc::clone(&authority)).unwrap();

    let open_id = ResultId::from_bytes([0x81; 32]);
    repository
        .begin(open_id, 100, 10_000, operation(31), b"open")
        .unwrap();
    assert_eq!(
        repository.recover(open_id, 200, None),
        Ok(RecoveryDispositionV2::ResumeOpen)
    );

    let data_id = ResultId::from_bytes([0x82; 32]);
    repository
        .begin(data_id, 100, 10_000, operation(32), b"data")
        .unwrap();
    commit_one_batch(&repository, data_id, EventId::from_bytes([0x92; 32]), 33);
    commit_data(&repository, data_id, 34);
    assert_eq!(
        repository.recover(
            data_id,
            200,
            Some(BuildContextDigestsV1::new(
                digest(9),
                digest(2),
                digest(3),
                digest(4),
                digest(5),
            )),
        ),
        Ok(RecoveryDispositionV2::ReissueRequired)
    );
    assert_eq!(
        repository.recover(data_id, 200, Some(build())),
        Ok(RecoveryDispositionV2::ResumeCompilation)
    );

    let sealed_id = ResultId::from_bytes([0x83; 32]);
    repository
        .begin(sealed_id, 100, 10_000, operation(35), b"sealed")
        .unwrap();
    commit_one_batch(&repository, sealed_id, EventId::from_bytes([0x93; 32]), 36);
    commit_data(&repository, sealed_id, 37);
    seal_result(&repository, sealed_id, 38);
    assert_eq!(
        repository.recover(sealed_id, 200, Some(build())),
        Ok(RecoveryDispositionV2::CompletedPublication)
    );
    assert_eq!(
        repository.recover(sealed_id, 200, Some(build())),
        Ok(RecoveryDispositionV2::AlreadyVisible)
    );

    let expired_id = ResultId::from_bytes([0x84; 32]);
    repository
        .begin(expired_id, 100, 150, operation(39), b"expired")
        .unwrap();
    assert_eq!(
        repository.recover(expired_id, 200, None),
        Ok(RecoveryDispositionV2::Expired)
    );
    assert_eq!(
        authority.snapshot(expired_id),
        Err(KeyAuthorityErrorV2::NotFound)
    );

    let missing_id = ResultId::from_bytes([0x87; 32]);
    repository
        .begin(
            missing_id,
            100,
            1_000_000_000_000,
            operation(42),
            b"missing",
        )
        .unwrap();
    fs::remove_dir_all(root.join(format!(".open-{}", "87".repeat(32)))).unwrap();
    assert_eq!(
        repository.recover(missing_id, 300_000_000_101, None),
        Ok(RecoveryDispositionV2::Absent)
    );
    assert_eq!(
        authority.snapshot(missing_id),
        Err(KeyAuthorityErrorV2::NotFound)
    );

    let orphan_id = ResultId::from_bytes([0x85; 32]);
    repository
        .begin(orphan_id, 100, 10_000, operation(40), b"orphan")
        .unwrap();
    authority.destroy(orphan_id).unwrap();
    assert_eq!(
        repository.recover(orphan_id, 200, None),
        Ok(RecoveryDispositionV2::Quarantined)
    );

    let conflict_id = ResultId::from_bytes([0x86; 32]);
    repository
        .begin(conflict_id, 100, 10_000, operation(41), b"conflict")
        .unwrap();
    let conflicting_final = root.join(format!("r-{}", "86".repeat(32)));
    fs::create_dir(&conflicting_final).unwrap();
    fs::set_permissions(&conflicting_final, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        repository.recover(conflict_id, 200, None),
        Ok(RecoveryDispositionV2::Quarantined)
    );

    for result_id in [open_id, data_id, sealed_id, conflict_id] {
        repository.destroy(result_id).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bulk_recovery_discovers_authority_and_orphan_objects_without_debug_identifiers() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = Arc::new(ProcessKeyAuthorityV2::new(4).unwrap());
    let repository = DurableResultRepositoryV2::open(&root, Arc::clone(&authority)).unwrap();
    let live_id = ResultId::from_bytes([0x91; 32]);
    let orphan_id = ResultId::from_bytes([0x92; 32]);
    repository
        .begin(live_id, 100, 10_000, operation(51), b"live")
        .unwrap();
    repository
        .begin(orphan_id, 100, 10_000, operation(52), b"orphan")
        .unwrap();
    authority.destroy(orphan_id).unwrap();

    let report = repository.recover_all(200, |_| None).unwrap();
    assert_eq!(report.entries().len(), 2);
    assert!(report.entries().iter().any(|entry| {
        entry.result_id() == live_id && entry.disposition() == RecoveryDispositionV2::ResumeOpen
    }));
    assert!(report.entries().iter().any(|entry| {
        entry.result_id() == orphan_id && entry.disposition() == RecoveryDispositionV2::Quarantined
    }));
    let debug = format!("{report:?}");
    assert!(!debug.contains(&"91".repeat(32)));
    assert!(!debug.contains(&"92".repeat(32)));

    repository.destroy(live_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn deterministic_crash_hooks_prove_exact_retry_and_key_first_cleanup() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = Arc::new(ProcessKeyAuthorityV2::new(4).unwrap());
    let faults = FailOnce::default();
    let repository = DurableResultRepositoryV2::open_with_fault_injector(
        &root,
        Arc::clone(&authority),
        faults.clone(),
    )
    .unwrap();
    let result_id = ResultId::from_bytes([0xa1; 32]);
    let event_id = EventId::from_bytes([0xa2; 32]);
    repository
        .begin(result_id, 100, 10_000, operation(61), b"request")
        .unwrap();

    let batch = BatchCommitInputV2::new(
        0,
        operation(62),
        vec![
            DurableEventInputV2::new(
                event_id,
                ExactnessBasis::SourceExact,
                b"authorized-basis".to_vec(),
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    faults.arm(DurableRepositoryFaultPointV2::AfterBatchDurabilityBeforeAcknowledgement);
    assert!(repository.commit_batch(result_id, &batch).is_err());
    let retry = repository.commit_batch(result_id, &batch).unwrap();
    assert_eq!(retry.transition(), LifecycleTransitionV1::AlreadyApplied);
    let changed = BatchCommitInputV2::new(
        0,
        operation(62),
        vec![
            DurableEventInputV2::new(event_id, ExactnessBasis::SourceExact, b"changed".to_vec())
                .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(repository.commit_batch(result_id, &changed).is_err());

    faults.arm(DurableRepositoryFaultPointV2::AfterDataDurabilityBeforeAuthority);
    let data = DataCommitInputV2 {
        operation: operation(63),
        question_configuration: digest(10),
        acquisition_receipt: digest(11),
        transformation_receipts: digest(12),
        fetch_completion: digest(13),
        source_identity: digest(14),
        build_context: build(),
    };
    assert!(repository.commit_data(result_id, data).is_err());
    assert_eq!(
        repository.commit_data(result_id, data),
        Ok(LifecycleTransitionV1::Applied)
    );

    faults.arm(DurableRepositoryFaultPointV2::AfterSealDurabilityBeforeAuthority);
    let seal = SealInputV2 {
        operation: operation(64),
        log_brief: b"brief".to_vec(),
        references: b"references".to_vec(),
        presentation_receipt: b"presentation".to_vec(),
        status: b"status".to_vec(),
        alias_manifest: b"aliases".to_vec(),
    };
    assert!(repository.seal(result_id, &seal).is_err());
    assert_eq!(
        repository.seal(result_id, &seal),
        Ok(LifecycleTransitionV1::Applied)
    );

    faults.arm(DurableRepositoryFaultPointV2::AfterPublishRenameBeforeAuthority);
    assert!(repository.publish(result_id, operation(65)).is_err());
    assert_eq!(
        repository.publish(result_id, operation(65)),
        Ok(LifecycleTransitionV1::Applied)
    );

    faults.arm(DurableRepositoryFaultPointV2::AfterAuthorityDestroyBeforeCleanup);
    assert!(repository.destroy(result_id).is_err());
    assert_eq!(
        authority.snapshot(result_id),
        Err(KeyAuthorityErrorV2::NotFound)
    );
    assert_eq!(
        repository.destroy(result_id),
        Ok(AuthorityDestroyOutcomeV2::AlreadyAbsent)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsafe_root_permissions_symlinks_and_hardlinked_ciphertext_are_rejected() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(1).unwrap()).is_err()
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let linked_root = root.with_extension("link");
    if linked_root.exists() {
        fs::remove_file(&linked_root).unwrap();
    }
    symlink(&root, &linked_root).unwrap();
    assert!(
        DurableResultRepositoryV2::open(&linked_root, ProcessKeyAuthorityV2::new(1).unwrap())
            .is_err()
    );
    fs::remove_file(linked_root).unwrap();
    fs::remove_dir_all(&root).unwrap();

    let authority = Arc::new(ProcessKeyAuthorityV2::new(2).unwrap());
    let repository = DurableResultRepositoryV2::open(&root, Arc::clone(&authority)).unwrap();
    let result_id = ResultId::from_bytes([0xb1; 32]);
    let event_id = EventId::from_bytes([0xb2; 32]);
    repository
        .begin(result_id, 100, 10_000, operation(71), b"request")
        .unwrap();
    let batch = BatchCommitInputV2::new(
        0,
        operation(72),
        vec![
            DurableEventInputV2::new(
                event_id,
                ExactnessBasis::SourceExact,
                b"authorized".to_vec(),
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let committed = repository.commit_batch(result_id, &batch).unwrap();
    commit_data(&repository, result_id, 73);
    seal_result(&repository, result_id, 74);
    repository.publish(result_id, operation(75)).unwrap();

    let final_path = root.join(format!("r-{}", "b1".repeat(32)));
    let segment = final_path.join(format!(
        "segment-{:020}.seg",
        committed.acknowledgements()[0].locator().segment_ordinal()
    ));
    let extra_link = final_path.join("attacker-hardlink");
    fs::hard_link(&segment, &extra_link).unwrap();
    assert!(
        repository
            .expand(result_id, &[event_id], 1, 1024, 200)
            .is_err()
    );
    fs::remove_file(extra_link).unwrap();
    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn publication_generations_are_authority_allocated_and_repository_global() {
    let root = unique_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let authority = Arc::new(ProcessKeyAuthorityV2::new(4).unwrap());
    let repository = DurableResultRepositoryV2::open(&root, Arc::clone(&authority)).unwrap();
    let first = ResultId::from_bytes([0xc1; 32]);
    let second = ResultId::from_bytes([0xc2; 32]);

    for (result_id, base) in [(first, 80), (second, 90)] {
        repository
            .begin(result_id, 100, 10_000, operation(base), b"request")
            .unwrap();
        commit_data(&repository, result_id, base + 1);
        seal_result(&repository, result_id, base + 2);
        repository.publish(result_id, operation(base + 3)).unwrap();
    }

    assert_eq!(
        authority.snapshot(first).unwrap().publication_generation(),
        1
    );
    assert_eq!(
        authority.snapshot(second).unwrap().publication_generation(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}
