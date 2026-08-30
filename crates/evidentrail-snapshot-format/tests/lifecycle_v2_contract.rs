use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, FrameCommitmentV1, FrameHeaderV2, LifecycleDigestV1,
    LifecycleTransitionV1, OperationIdV1, ResultAuthorityRecordV2, ResultDekV1,
    ResultLifecycleStateV1, ResultNoncePrefixV1, SealCommitmentsV1, SegmentHeaderV2,
    SnapshotObjectKindV2, derive_lifecycle_digest_v1, open_frame_v2, seal_frame_v2,
};

fn digest(byte: u8) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationIdV1 {
    OperationIdV1::from_bytes([byte; 16])
}

fn build() -> BuildContextDigestsV1 {
    BuildContextDigestsV1::new(digest(1), digest(2), digest(3), digest(4), digest(5))
}

#[test]
fn authority_record_enforces_four_monotonic_states_and_exact_retries() {
    let result_id = ResultId::from_bytes([9; 32]);
    let mut record = ResultAuthorityRecordV2::new_open(
        result_id,
        100,
        200,
        ResultNoncePrefixV1::from_bytes([7; 16]),
        operation(1),
        digest(10),
    )
    .unwrap();

    let first = record.reserve_nonce_range(3).unwrap();
    let second = record.reserve_nonce_range(2).unwrap();
    assert_eq!(&first.nonce_at(0).unwrap()[..16], &[7; 16]);
    assert_eq!(
        u64::from_be_bytes(first.nonce_at(2).unwrap()[16..].try_into().unwrap()),
        2
    );
    assert_eq!(
        u64::from_be_bytes(second.nonce_at(0).unwrap()[16..].try_into().unwrap()),
        3
    );

    assert_eq!(
        record.commit_data(operation(2), digest(11), build()),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert_eq!(
        record.commit_data(operation(2), digest(11), build()),
        Ok(LifecycleTransitionV1::AlreadyApplied)
    );
    let commitments =
        SealCommitmentsV1::new(digest(20), digest(21), digest(22), digest(23), digest(24));
    assert_eq!(
        record.seal(operation(3), commitments),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert_eq!(
        record.publish(operation(4), 1, digest(30)),
        Ok(LifecycleTransitionV1::Applied)
    );
    assert_eq!(record.state(), ResultLifecycleStateV1::Published);
    assert_eq!(
        record.seal(operation(3), commitments),
        Ok(LifecycleTransitionV1::AlreadyApplied)
    );
    assert!(
        record
            .commit_data(operation(2), digest(99), build())
            .is_err()
    );

    let encoded = record.encode();
    let decoded = ResultAuthorityRecordV2::decode(&encoded).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(
        format!("{record:?}"),
        "ResultAuthorityRecordV2 { state: ResultLifecycleStateV1 { code: 4 }, .. }"
    );
}

#[test]
fn v2_frames_bind_result_segment_kind_sequence_length_chain_and_counter() {
    let result_id = ResultId::from_bytes([8; 32]);
    let dek = ResultDekV1::from_test_bytes([6; 32]).unwrap();
    let segment = SegmentHeaderV2::new(result_id, 0, FrameCommitmentV1::ZERO).unwrap();
    let mut nonce = [5; 24];
    nonce[16..].copy_from_slice(&42u64.to_be_bytes());
    let plaintext = b"exact\0bytes\r\n";
    let header = FrameHeaderV2::new(
        SnapshotObjectKindV2::AuthorizedEvent,
        0,
        0,
        0,
        plaintext.len() as u32,
        nonce,
        FrameCommitmentV1::ZERO,
    )
    .unwrap();
    let sealed = seal_frame_v2(&dek, segment, header, plaintext).unwrap();
    assert_eq!(
        open_frame_v2(&dek, segment, &sealed).unwrap().as_bytes(),
        plaintext
    );

    let mut tampered = sealed.encode();
    tampered[evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2] ^= 1;
    let tampered = evidentrail_snapshot_format::SealedFrameV2::decode(&tampered).unwrap();
    assert!(open_frame_v2(&dek, segment, &tampered).is_err());

    let digest = derive_lifecycle_digest_v1(plaintext);
    assert_ne!(
        digest,
        derive_lifecycle_digest_v1(b"exact\0bytes\r\nchanged")
    );
}
