use evidentrail_schema::{EventId, ExactnessBasis, ResultId};
use evidentrail_snapshot_format::{
    AuthenticatedEventIndexDirectoryV2, AuthenticatedEventIndexEntryV2, AuthenticatedEventIndexV2,
    DurableAcknowledgementV2, DurableBatchJournalV2, EventFrameLocatorV2, FrameCommitmentV1,
    LifecycleDigestV1, LifecycleTransitionV1, MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2,
    MAX_FRAME_PLAINTEXT_BYTES_V1, NonceReservationV1, OperationIdV1, ResultAuthorityRecordV2,
    ResultNoncePrefixV1,
};

fn event_id(value: u64) -> EventId {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    EventId::from_bytes(bytes)
}

fn digest(byte: u8) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationIdV1 {
    OperationIdV1::from_bytes([byte; 16])
}

fn locator(value: u64) -> EventFrameLocatorV2 {
    let mut commitment = [0u8; 32];
    commitment[0] = 1;
    commitment[24..].copy_from_slice(&value.to_be_bytes());
    EventFrameLocatorV2::new(
        value / 4_094 + 1,
        (value % 4_094) as u32,
        value,
        96 + value * 256,
        256,
        64,
        FrameCommitmentV1::from_bytes(commitment),
    )
    .unwrap()
}

#[test]
fn million_scale_index_uses_bounded_authenticated_shards() {
    let count = MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2 + 1;
    let entries = (0..count)
        .map(|index| {
            AuthenticatedEventIndexEntryV2::new(
                event_id(index as u64 + 1),
                ExactnessBasis::SourceExact,
                locator(index as u64),
            )
        })
        .collect::<Vec<_>>();
    let chain = FrameCommitmentV1::from_bytes([0x55; 32]);
    let shards = entries
        .chunks(MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2)
        .map(|chunk| AuthenticatedEventIndexV2::new(chunk.to_vec(), chain).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(shards.len(), 2);
    assert!(
        shards
            .iter()
            .all(|shard| shard.encoded_len() <= MAX_FRAME_PLAINTEXT_BYTES_V1)
    );

    let directory = AuthenticatedEventIndexDirectoryV2::from_shards(&shards, chain).unwrap();
    assert_eq!(directory.event_count(), count as u64);
    let decoded = AuthenticatedEventIndexDirectoryV2::decode(&directory.encode()).unwrap();
    assert_eq!(decoded, directory);
    let descriptor = *decoded
        .shard_for(event_id(count as u64))
        .expect("last event routes to second shard");
    assert_eq!(descriptor.ordinal(), 1);
    decoded.verify_shard(descriptor, &shards[1]).unwrap();

    let mut tampered = directory.encode();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(AuthenticatedEventIndexDirectoryV2::decode(&tampered).is_err());
}

#[test]
fn journal_freezes_exact_acknowledgements_and_pending_reservations_survive_codec() {
    let reservation =
        NonceReservationV1::new(ResultNoncePrefixV1::from_bytes([7; 16]), 11, 4).unwrap();
    let acknowledgements = vec![
        DurableAcknowledgementV2::new(event_id(1), locator(1)),
        DurableAcknowledgementV2::new(event_id(2), locator(2)),
    ];
    let journal =
        DurableBatchJournalV2::new(9, operation(3), digest(4), reservation, acknowledgements)
            .unwrap();
    let decoded = DurableBatchJournalV2::decode(&journal.encode()).unwrap();
    assert_eq!(decoded, journal);

    let mut record = ResultAuthorityRecordV2::new_open(
        ResultId::from_bytes([9; 32]),
        10,
        20,
        ResultNoncePrefixV1::from_bytes([8; 16]),
        operation(1),
        digest(1),
    )
    .unwrap();
    let first = record
        .reserve_pending_nonce_range(operation(2), digest(2), 3)
        .unwrap();
    let restored = ResultAuthorityRecordV2::decode(&record.encode()).unwrap();
    assert!(restored.has_pending_nonce_reservation());
    assert_eq!(
        record
            .reserve_pending_nonce_range(operation(2), digest(2), 3)
            .unwrap(),
        first
    );
    assert!(
        record
            .reserve_pending_nonce_range(operation(3), digest(2), 3)
            .is_err()
    );
    assert_eq!(
        record
            .complete_pending_nonce_range(operation(2), digest(2))
            .unwrap(),
        LifecycleTransitionV1::Applied
    );
    assert!(!record.has_pending_nonce_reservation());
}
