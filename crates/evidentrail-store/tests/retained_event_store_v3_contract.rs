use evidentrail_core::{
    EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1, UnixTimestampNanos,
};
use evidentrail_schema::{EventId, ResultId};
#[cfg(unix)]
use evidentrail_snapshot_format::SnapshotObjectKindV2;
use evidentrail_store::{
    KeyAuthorityV2, PackedMemoryEventStoreV3, RetainedAcquisitionFinishV3, RetainedEventInputV3,
    RetainedEventStoreStateV3, RetainedEventStoreV3, RetainedStoreBeginV3,
};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(unix)]
struct FailOnceV3 {
    point: evidentrail_store::DurablePackedFaultPointV3,
    kind: Option<SnapshotObjectKindV2>,
    fired: AtomicBool,
}

#[cfg(unix)]
impl evidentrail_store::DurablePackedFaultInjectorV3 for FailOnceV3 {
    fn fail_at(
        &self,
        point: evidentrail_store::DurablePackedFaultPointV3,
        kind: Option<SnapshotObjectKindV2>,
        _ordinal: u64,
    ) -> bool {
        point == self.point
            && self.kind.is_none_or(|expected| kind == Some(expected))
            && !self.fired.swap(true, Ordering::SeqCst)
    }
}

#[cfg(unix)]
fn fail_once(
    point: evidentrail_store::DurablePackedFaultPointV3,
    kind: Option<SnapshotObjectKindV2>,
) -> FailOnceV3 {
    FailOnceV3 {
        point,
        kind,
        fired: AtomicBool::new(false),
    }
}

#[cfg(unix)]
fn acquire_one_v3<B: RetainedEventStoreV3>(
    store: &mut B,
    result_id: ResultId,
    namespace: [u8; 32],
    event_id: EventId,
) -> evidentrail_store::RetainedStoreManifestV3 {
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace,
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 1,
            terminator_len: 1,
            exact_bytes: b"x\n",
        })
        .unwrap();
    store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 1,
            source_byte_count: 2,
            input_digest: [3; 32],
            completion_digest: [4; 32],
        })
        .unwrap()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn packed_memory_store_has_deterministic_scans_exact_reads_and_authority_first_destroy() {
    let result_id = ResultId::from_bytes([7; 32]);
    let first_id = EventId::from_bytes([2; 32]);
    let second_id = EventId::from_bytes([1; 32]);
    let first = b"ready\r\n";
    let second = b"\xffERR\0";
    let mut store = PackedMemoryEventStoreV3::new();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [9; 32],
            created_unix_nanos: 10,
            expires_unix_nanos: 20,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id: first_id,
            acquisition_ordinal: 0,
            lane_ordinal: 4,
            lane_sequence: 0,
            payload_len: 5,
            terminator_len: 2,
            exact_bytes: first,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id: second_id,
            acquisition_ordinal: 1,
            lane_ordinal: 3,
            lane_sequence: 0,
            payload_len: 5,
            terminator_len: 0,
            exact_bytes: second,
        })
        .unwrap();
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 2,
            payload_byte_count: 10,
            source_byte_count: 12,
            input_digest: digest(b"input"),
            completion_digest: digest(b"completion"),
        })
        .unwrap();
    assert_eq!(store.state(), RetainedEventStoreStateV3::DataCommitted);
    let mut acquisition_ids = Vec::new();
    store
        .acquisition_scan(&mut |view| {
            acquisition_ids.push(view.locator().event_id());
            Ok(())
        })
        .unwrap();
    let mut lane_ids = Vec::new();
    store
        .lane_scan(&mut |view| {
            lane_ids.push(view.locator().event_id());
            Ok(())
        })
        .unwrap();
    assert_eq!(acquisition_ids[0], first_id);
    assert_eq!(lane_ids[0], second_id);
    assert!(store.read_exact(first_id).is_err());

    store
        .seal_and_publish(manifest, &[first_id, second_id])
        .unwrap();
    assert_eq!(store.state(), RetainedEventStoreStateV3::Published);
    assert_eq!(store.read_exact(first_id).unwrap().as_slice(), first);
    assert_eq!(store.read_exact(second_id).unwrap().as_slice(), second);

    store.destroy_authority_first().unwrap();
    assert_eq!(store.state(), RetainedEventStoreStateV3::Destroyed);
    assert_eq!(store.retained_plaintext_bytes(), 0);
    assert!(store.read_exact(first_id).is_err());
}

#[test]
fn manifest_is_stable_for_identical_packed_input() {
    fn build() -> [u8; 32] {
        let mut store = PackedMemoryEventStoreV3::new();
        store
            .begin(RetainedStoreBeginV3 {
                result_id: ResultId::from_bytes([3; 32]),
                namespace: [4; 32],
                created_unix_nanos: 1,
                expires_unix_nanos: 2,
            })
            .unwrap();
        store
            .append(RetainedEventInputV3 {
                event_id: EventId::from_bytes([5; 32]),
                acquisition_ordinal: 0,
                lane_ordinal: 0,
                lane_sequence: 0,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            })
            .unwrap();
        store
            .finish_acquisition(RetainedAcquisitionFinishV3 {
                record_count: 1,
                payload_byte_count: 1,
                source_byte_count: 2,
                input_digest: [6; 32],
                completion_digest: [7; 32],
            })
            .unwrap()
            .digest()
    }
    assert_eq!(build(), build());
}

#[test]
fn packed_memory_store_rejects_duplicate_ids_when_building_the_sorted_index() {
    let mut store = PackedMemoryEventStoreV3::new();
    store
        .begin(RetainedStoreBeginV3 {
            result_id: ResultId::from_bytes([0x13; 32]),
            namespace: [0x14; 32],
            created_unix_nanos: 1,
            expires_unix_nanos: 2,
        })
        .unwrap();
    let event_id = EventId::from_bytes([0x15; 32]);
    for ordinal in 0..2 {
        store
            .append(RetainedEventInputV3 {
                event_id,
                acquisition_ordinal: ordinal,
                lane_ordinal: ordinal,
                lane_sequence: 0,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            })
            .unwrap();
    }
    assert_eq!(
        store
            .finish_acquisition(RetainedAcquisitionFinishV3 {
                record_count: 2,
                payload_byte_count: 2,
                source_byte_count: 4,
                input_digest: [0x16; 32],
                completion_digest: [0x17; 32],
            })
            .unwrap_err(),
        evidentrail_store::RetainedEventStoreErrorV3::DuplicateEvent
    );
}

#[cfg(unix)]
#[test]
fn durable_v3_uses_authority_gated_publication_and_exact_encrypted_reads() {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = evidentrail_store::ProcessKeyAuthorityV2::new(4).unwrap();
    let mut store = evidentrail_store::DurableRetainedEventStoreV3::open(&root, authority).unwrap();
    let result_id = ResultId::from_bytes([0x31; 32]);
    let event_id = EventId::from_bytes([0x41; 32]);
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0x51; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 5,
            terminator_len: 1,
            exact_bytes: b"fatal\n",
        })
        .unwrap();
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 5,
            source_byte_count: 6,
            input_digest: [0x61; 32],
            completion_digest: [0x71; 32],
        })
        .unwrap();
    assert!(store.read_exact(event_id).is_err());
    let reference = EvidenceReferenceV1::issue(
        result_id,
        [EvidenceTargetRef::Event(event_id)],
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(1_000),
    )
    .unwrap();
    store
        .seal_and_publish_aliases(
            manifest,
            &[evidentrail_store::RetainedPublishedAliasV3::new(
                reference,
                vec![event_id],
            )],
        )
        .unwrap();
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        for object in std::fs::read_dir(path).unwrap() {
            let bytes = std::fs::read(object.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(b"fatal\n".len())
                    .any(|window| window == b"fatal\n"),
                "durable objects must not contain plaintext records"
            );
        }
    }
    assert_eq!(store.read_exact(event_id).unwrap().as_slice(), b"fatal\n");
    assert_eq!(store.published_aliases().len(), 1);
    assert_eq!(
        store.published_aliases()[0].ordered_event_ids(),
        &[event_id]
    );
    store.destroy_authority_first().unwrap();
    assert_eq!(store.state(), RetainedEventStoreStateV3::Destroyed);
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_detects_authenticated_page_corruption_during_recovery() {
    static NEXT: AtomicU64 = AtomicU64::new(10_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-corrupt-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut store = evidentrail_store::DurablePackedRepositoryV3::open(
        &root,
        evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap(),
    )
    .unwrap();
    store
        .begin(RetainedStoreBeginV3 {
            result_id: ResultId::from_bytes([0x81; 32]),
            namespace: [0x82; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id: EventId::from_bytes([0x83; 32]),
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 7,
            terminator_len: 1,
            exact_bytes: b"private\n",
        })
        .unwrap();
    store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 7,
            source_byte_count: 8,
            input_digest: [0x84; 32],
            completion_digest: [0x85; 32],
        })
        .unwrap();
    let result_dir = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let page = std::fs::read_dir(result_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("-acquisition-pack-")
        })
        .unwrap();
    let mut bytes = std::fs::read(&page).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(page, bytes).unwrap();
    assert_eq!(
        store.recover().unwrap_err(),
        evidentrail_store::RetainedEventStoreErrorV3::CorruptIndex
    );
    store.destroy_authority_first().unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_rejects_a_page_header_changed_without_touching_ciphertext() {
    static NEXT: AtomicU64 = AtomicU64::new(15_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-aad-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
    let result_id = ResultId::from_bytes([0x86; 32]);
    let mut store =
        evidentrail_store::DurablePackedRepositoryV3::open(&root, Arc::clone(&authority)).unwrap();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0x87; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id: EventId::from_bytes([0x88; 32]),
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 3,
            terminator_len: 1,
            exact_bytes: b"bad\n",
        })
        .unwrap();
    store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 3,
            source_byte_count: 4,
            input_digest: [0x89; 32],
            completion_digest: [0x8a; 32],
        })
        .unwrap();
    let result_dir = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let page = std::fs::read_dir(result_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("-acquisition-pack-")
        })
        .unwrap();
    let mut bytes = std::fs::read(&page).unwrap();
    let aad_length_offset = evidentrail_snapshot_format::SEGMENT_HEADER_BYTES_V2
        + evidentrail_store::DURABLE_PACK_HEADER_BYTES_V3;
    let aad_length = u32::from_be_bytes(
        bytes[aad_length_offset..aad_length_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let sealed_length = u64::from_be_bytes(
        bytes[aad_length_offset + 4..aad_length_offset + 12]
            .try_into()
            .unwrap(),
    ) as usize;
    let aad_start = aad_length_offset + 12;
    let sealed_start = aad_start + aad_length;
    let sealed = evidentrail_snapshot_format::SealedFrameV2::decode(
        &bytes[sealed_start..sealed_start + sealed_length],
    )
    .unwrap();
    assert_eq!(
        &bytes[aad_start + 136..aad_start + 160],
        &sealed.header().nonce()
    );
    bytes[aad_start + 80] ^= 1;
    std::fs::write(page, bytes).unwrap();
    assert!(matches!(
        evidentrail_store::DurablePackedRepositoryV3::resume(&root, authority, result_id),
        Err(evidentrail_store::RetainedEventStoreErrorV3::CorruptIndex)
    ));
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_fault_matrix_covers_every_object_durability_boundary() {
    use evidentrail_store::DurablePackedFaultPointV3 as P;
    static NEXT: AtomicU64 = AtomicU64::new(30_000);
    let points = [
        P::BeforeNonceReservation,
        P::AfterNonceReservation,
        P::BeforeFrameEncryption,
        P::AfterFrameEncryption,
        P::BeforeTemporaryCreate,
        P::AfterTemporaryCreate,
        P::BeforeTemporaryWrite,
        P::AfterTemporaryWrite,
        P::BeforeTemporarySync,
        P::AfterTemporarySync,
        P::BeforeObjectInstall,
        P::AfterObjectInstall,
        P::BeforeDirectorySync,
        P::AfterDirectorySync,
        P::BeforeNonceAcknowledgement,
        P::AfterNonceAcknowledgement,
    ];
    let kinds = [
        SnapshotObjectKindV2::Request,
        SnapshotObjectKindV2::AuthorizedEvent,
        SnapshotObjectKindV2::EventIndex,
        SnapshotObjectKindV2::DataManifest,
        SnapshotObjectKindV2::OperationalReceipt,
        SnapshotObjectKindV2::AliasManifest,
    ];
    for (case, (point, kind)) in points
        .into_iter()
        .flat_map(|point| kinds.into_iter().map(move |kind| (point, kind)))
        .enumerate()
    {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-object-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&case.to_be_bytes()));
        let event_id = EventId::from_bytes(digest(&[case as u8, 1]));
        let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
            &root,
            Arc::clone(&authority),
            fail_once(point, Some(kind)),
        )
        .unwrap();
        let begin = store.begin(RetainedStoreBeginV3 {
            result_id,
            namespace: digest(&[case as u8, 2]),
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        });
        let outcome = if begin.is_err() {
            begin.map(|_| ())
        } else {
            let append = store.append(RetainedEventInputV3 {
                event_id,
                acquisition_ordinal: 0,
                lane_ordinal: 0,
                lane_sequence: 0,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            });
            if append.is_err() {
                append
            } else {
                let finish = store.finish_acquisition(RetainedAcquisitionFinishV3 {
                    record_count: 1,
                    payload_byte_count: 1,
                    source_byte_count: 2,
                    input_digest: [3; 32],
                    completion_digest: [4; 32],
                });
                match finish {
                    Err(error) => Err(error),
                    Ok(manifest) => store.seal_and_publish(manifest, &[event_id]),
                }
            }
        };
        assert_eq!(
            outcome.unwrap_err(),
            evidentrail_store::RetainedEventStoreErrorV3::FaultInjected,
            "unreached fault point {point:?} for {kind:?}"
        );
        let _ = store.destroy_authority_first();
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn durable_v3_checkpoint_packs_bound_sync_objects_and_lookup_across_packs() {
    static NEXT: AtomicU64 = AtomicU64::new(80_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-cross-pack-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
    let result_id = ResultId::from_bytes([0xd1; 32]);
    let mut store =
        evidentrail_store::DurablePackedRepositoryV3::open(&root, Arc::clone(&authority)).unwrap();
    store.enable_performance_instrumentation();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0xd2; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    let record_count = 65_537u64;
    let mut first_event = None;
    let mut last_event = None;
    for ordinal in 0..record_count {
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(&ordinal.to_be_bytes());
        id[8] = 0xa5;
        let event_id = EventId::from_bytes(id);
        first_event.get_or_insert(event_id);
        last_event = Some(event_id);
        store
            .append(RetainedEventInputV3 {
                event_id,
                acquisition_ordinal: ordinal,
                lane_ordinal: ordinal % 3,
                lane_sequence: ordinal / 3,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            })
            .unwrap();
    }
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count,
            payload_byte_count: record_count,
            source_byte_count: record_count * 2,
            input_digest: [0xd3; 32],
            completion_digest: [0xd4; 32],
        })
        .unwrap();
    store
        .seal_and_publish(manifest, &[first_event.unwrap(), last_event.unwrap()])
        .unwrap();
    let result_dir = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let names = std::fs::read_dir(&result_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names
            .iter()
            .filter(|name| name.contains("-acquisition-pack-"))
            .count(),
        2
    );
    assert!(
        names.len() < 20,
        "checkpoint packing must keep sync objects bounded"
    );
    assert_eq!(
        store.read_exact(first_event.unwrap()).unwrap().as_slice(),
        b"x\n"
    );
    assert_eq!(
        store.read_exact(last_event.unwrap()).unwrap().as_slice(),
        b"x\n"
    );
    let receipt = store.performance_receipt();
    assert!(receipt.total_elapsed_nanos() > 0);
    assert_eq!(receipt.page_count, 17);
    assert!(receipt.object_count < 20);
    assert_eq!(receipt.sync_count, receipt.object_count * 2);
    assert!(receipt.encrypted_byte_count > record_count * 2);
    assert!(receipt.decrypted_byte_count > 0);
    drop(store);
    let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
        &root,
        Arc::clone(&authority),
        result_id,
    )
    .unwrap();
    assert_eq!(
        resumed.read_exact(last_event.unwrap()).unwrap().as_slice(),
        b"x\n"
    );
    resumed.destroy_authority_first().unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_supports_an_oversized_singleton_page_without_plaintext_publication() {
    static NEXT: AtomicU64 = AtomicU64::new(90_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-oversized-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap();
    let mut store = evidentrail_store::DurablePackedRepositoryV3::open(&root, authority).unwrap();
    let result_id = ResultId::from_bytes([0xe1; 32]);
    let event_id = EventId::from_bytes([0xe2; 32]);
    let exact = vec![0x5a; 2 * 1024 * 1024];
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0xe3; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: exact.len() as u32,
            terminator_len: 0,
            exact_bytes: &exact,
        })
        .unwrap();
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: exact.len() as u64,
            source_byte_count: exact.len() as u64,
            input_digest: [0xe4; 32],
            completion_digest: [0xe5; 32],
        })
        .unwrap();
    store.seal_and_publish(manifest, &[event_id]).unwrap();
    assert_eq!(store.read_exact(event_id).unwrap().as_slice(), exact);
    store.destroy_authority_first().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_rejects_experimental_one_object_layout_with_typed_result() {
    static NEXT: AtomicU64 = AtomicU64::new(100_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-obsolete-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
    let result_id = ResultId::from_bytes([0xf1; 32]);
    let mut store =
        evidentrail_store::DurablePackedRepositoryV3::open(&root, Arc::clone(&authority)).unwrap();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0xf2; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    let result_dir = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let descriptor = std::fs::read_dir(&result_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::rename(&descriptor, descriptor.with_extension("v3")).unwrap();
    drop(store);
    assert!(matches!(
        evidentrail_store::DurablePackedRepositoryV3::resume(
            &root,
            Arc::clone(&authority),
            result_id
        ),
        Err(evidentrail_store::RetainedEventStoreErrorV3::ObsoleteFormat)
    ));
    evidentrail_store::cleanup_obsolete_v3_authority_first(&root, authority.as_ref(), result_id)
        .unwrap();
    assert!(matches!(
        authority.snapshot(result_id),
        Err(evidentrail_store::KeyAuthorityErrorV2::NotFound)
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_replays_before_install_and_authenticates_after_install() {
    use evidentrail_store::DurablePackedFaultPointV3 as P;
    static NEXT: AtomicU64 = AtomicU64::new(110_000);
    for (case, point) in [P::BeforeObjectInstall, P::AfterObjectInstall]
        .into_iter()
        .enumerate()
    {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-install-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&[0xf3, case as u8]));
        let event_id = EventId::from_bytes(digest(&[0xf4, case as u8]));
        let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
            &root,
            Arc::clone(&authority),
            fail_once(point, Some(SnapshotObjectKindV2::AuthorizedEvent)),
        )
        .unwrap();
        store
            .begin(RetainedStoreBeginV3 {
                result_id,
                namespace: digest(&[0xf5, case as u8]),
                created_unix_nanos: 100,
                expires_unix_nanos: 1_000,
            })
            .unwrap();
        store
            .append(RetainedEventInputV3 {
                event_id,
                acquisition_ordinal: 0,
                lane_ordinal: 0,
                lane_sequence: 0,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            })
            .unwrap();
        let finish = RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 1,
            source_byte_count: 2,
            input_digest: [3; 32],
            completion_digest: [4; 32],
        };
        assert_eq!(
            store.finish_acquisition(finish).unwrap_err(),
            evidentrail_store::RetainedEventStoreErrorV3::FaultInjected
        );
        drop(store);
        let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
            &root,
            Arc::clone(&authority),
            result_id,
        )
        .unwrap();
        if point == P::BeforeObjectInstall {
            resumed
                .append(RetainedEventInputV3 {
                    event_id,
                    acquisition_ordinal: 0,
                    lane_ordinal: 0,
                    lane_sequence: 0,
                    payload_len: 1,
                    terminator_len: 1,
                    exact_bytes: b"x\n",
                })
                .unwrap();
        }
        resumed.finish_acquisition(finish).unwrap();
        assert_eq!(resumed.state(), RetainedEventStoreStateV3::DataCommitted);
        resumed.destroy_authority_first().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn durable_v3_reuses_an_authenticated_partial_index_pack() {
    use evidentrail_store::DurablePackedFaultPointV3 as P;
    static NEXT: AtomicU64 = AtomicU64::new(120_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-index-recovery-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
    let result_id = ResultId::from_bytes([0xf6; 32]);
    let event_id = EventId::from_bytes([0xf7; 32]);
    let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
        &root,
        Arc::clone(&authority),
        fail_once(
            P::AfterObjectInstall,
            Some(SnapshotObjectKindV2::EventIndex),
        ),
    )
    .unwrap();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0xf8; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 1,
            terminator_len: 1,
            exact_bytes: b"x\n",
        })
        .unwrap();
    let finish = RetainedAcquisitionFinishV3 {
        record_count: 1,
        payload_byte_count: 1,
        source_byte_count: 2,
        input_digest: [3; 32],
        completion_digest: [4; 32],
    };
    assert_eq!(
        store.finish_acquisition(finish).unwrap_err(),
        evidentrail_store::RetainedEventStoreErrorV3::FaultInjected
    );
    drop(store);
    let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
        &root,
        Arc::clone(&authority),
        result_id,
    )
    .unwrap();
    resumed.finish_acquisition(finish).unwrap();
    assert_eq!(resumed.state(), RetainedEventStoreStateV3::DataCommitted);
    resumed.destroy_authority_first().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn durable_v3_fault_matrix_recovers_lifecycle_recovery_and_destruction_boundaries() {
    use evidentrail_store::DurablePackedFaultPointV3 as P;
    static NEXT: AtomicU64 = AtomicU64::new(50_000);

    for (case, point) in [P::BeforeDataCommit, P::AfterDataCommit]
        .into_iter()
        .enumerate()
    {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-data-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&[0xa0, case as u8]));
        let event_id = EventId::from_bytes(digest(&[0xa1, case as u8]));
        let namespace = digest(&[0xa2, case as u8]);
        let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
            &root,
            Arc::clone(&authority),
            fail_once(point, None),
        )
        .unwrap();
        store
            .begin(RetainedStoreBeginV3 {
                result_id,
                namespace,
                created_unix_nanos: 100,
                expires_unix_nanos: 1_000,
            })
            .unwrap();
        store
            .append(RetainedEventInputV3 {
                event_id,
                acquisition_ordinal: 0,
                lane_ordinal: 0,
                lane_sequence: 0,
                payload_len: 1,
                terminator_len: 1,
                exact_bytes: b"x\n",
            })
            .unwrap();
        let finish = RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 1,
            source_byte_count: 2,
            input_digest: [3; 32],
            completion_digest: [4; 32],
        };
        assert_eq!(
            store.finish_acquisition(finish).unwrap_err(),
            evidentrail_store::RetainedEventStoreErrorV3::FaultInjected
        );
        drop(store);
        let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
            &root,
            Arc::clone(&authority),
            result_id,
        )
        .unwrap();
        if point == P::BeforeDataCommit {
            resumed.finish_acquisition(finish).unwrap();
        }
        assert_eq!(resumed.state(), RetainedEventStoreStateV3::DataCommitted);
        resumed.destroy_authority_first().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    let publication_points = [
        P::BeforeSeal,
        P::AfterSeal,
        P::BeforePublicationReservation,
        P::AfterPublicationReservation,
        P::AfterPublicationRename,
        P::AfterPublicationSync,
        P::AfterAuthorityPublish,
    ];
    for (case, point) in publication_points.into_iter().enumerate() {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-publish-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&[0xb0, case as u8]));
        let event_id = EventId::from_bytes(digest(&[0xb1, case as u8]));
        let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
            &root,
            Arc::clone(&authority),
            fail_once(point, None),
        )
        .unwrap();
        let manifest = acquire_one_v3(&mut store, result_id, digest(&[0xb2, case as u8]), event_id);
        assert_eq!(
            store.seal_and_publish(manifest, &[event_id]).unwrap_err(),
            evidentrail_store::RetainedEventStoreErrorV3::FaultInjected
        );
        drop(store);
        let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
            &root,
            Arc::clone(&authority),
            result_id,
        )
        .unwrap();
        assert_eq!(resumed.state(), RetainedEventStoreStateV3::Published);
        assert_eq!(resumed.read_exact(event_id).unwrap().as_slice(), b"x\n");
        resumed.destroy_authority_first().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    for point in [P::BeforeRecoveryObject, P::AfterRecoveryObject] {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-recovery-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&[0xc0, point as u8]));
        let event_id = EventId::from_bytes(digest(&[0xc1, point as u8]));
        let mut store =
            evidentrail_store::DurablePackedRepositoryV3::open(&root, Arc::clone(&authority))
                .unwrap();
        acquire_one_v3(
            &mut store,
            result_id,
            digest(&[0xc2, point as u8]),
            event_id,
        );
        drop(store);
        assert!(matches!(
            evidentrail_store::DurablePackedRepositoryV3::resume_with_fault_injector(
                &root,
                Arc::clone(&authority),
                result_id,
                fail_once(point, None),
            ),
            Err(evidentrail_store::RetainedEventStoreErrorV3::FaultInjected)
        ));
        let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
            &root,
            Arc::clone(&authority),
            result_id,
        )
        .unwrap();
        resumed.destroy_authority_first().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    for point in [
        P::AfterAuthorityDestroy,
        P::BeforeCiphertextCleanup,
        P::AfterCiphertextCleanup,
    ] {
        let root = std::env::temp_dir().join(format!(
            "evidentrail-retained-v3-destroy-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
        let result_id = ResultId::from_bytes(digest(&[0xd0, point as u8]));
        let event_id = EventId::from_bytes(digest(&[0xd1, point as u8]));
        let mut store = evidentrail_store::DurablePackedRepositoryV3::open_with_fault_injector(
            &root,
            Arc::clone(&authority),
            fail_once(point, None),
        )
        .unwrap();
        acquire_one_v3(
            &mut store,
            result_id,
            digest(&[0xd2, point as u8]),
            event_id,
        );
        assert_eq!(
            store.destroy_authority_first().unwrap_err(),
            evidentrail_store::RetainedEventStoreErrorV3::FaultInjected
        );
        assert!(
            authority.snapshot(result_id).is_err(),
            "key must be gone first"
        );
        store.destroy_authority_first().unwrap();
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn durable_v3_reconstructs_data_committed_and_published_results_only_from_disk() {
    static NEXT: AtomicU64 = AtomicU64::new(20_000);
    let root = std::env::temp_dir().join(format!(
        "evidentrail-retained-v3-restart-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = Arc::new(evidentrail_store::ProcessKeyAuthorityV2::new(1).unwrap());
    let result_id = ResultId::from_bytes([0x91; 32]);
    let event_id = EventId::from_bytes([0x92; 32]);
    let mut store =
        evidentrail_store::DurablePackedRepositoryV3::open(&root, Arc::clone(&authority)).unwrap();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [0x93; 32],
            created_unix_nanos: 100,
            expires_unix_nanos: 1_000,
        })
        .unwrap();
    store
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: 0,
            lane_ordinal: 0,
            lane_sequence: 0,
            payload_len: 7,
            terminator_len: 1,
            exact_bytes: b"restart\n",
        })
        .unwrap();
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: 1,
            payload_byte_count: 7,
            source_byte_count: 8,
            input_digest: [0x94; 32],
            completion_digest: [0x95; 32],
        })
        .unwrap();
    drop(store);

    let mut resumed = evidentrail_store::DurablePackedRepositoryV3::resume(
        &root,
        Arc::clone(&authority),
        result_id,
    )
    .unwrap();
    assert_eq!(resumed.state(), RetainedEventStoreStateV3::DataCommitted);
    assert_eq!(resumed.manifest(), Some(manifest));
    let mut scanned = Vec::new();
    resumed
        .acquisition_scan(&mut |view| {
            scanned.extend_from_slice(view.exact_bytes());
            Ok(())
        })
        .unwrap();
    assert_eq!(scanned, b"restart\n");
    resumed.seal_and_publish(manifest, &[event_id]).unwrap();
    drop(resumed);

    let mut published = evidentrail_store::DurablePackedRepositoryV3::resume(
        &root,
        Arc::clone(&authority),
        result_id,
    )
    .unwrap();
    assert_eq!(published.state(), RetainedEventStoreStateV3::Published);
    assert_eq!(
        published.read_exact(event_id).unwrap().as_slice(),
        b"restart\n"
    );
    published.destroy_authority_first().unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}
