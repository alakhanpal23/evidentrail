use evidentrail_schema::{AcquisitionReceiptId, ResultId, SourceIdentityDigest};
use evidentrail_snapshot_format::{
    CORE_RESULT_FRAME_AAD_BYTES_V1, CORE_RESULT_FRAME_AAD_DOMAIN_V1,
    CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1, CoreResultFrameAuthorityV1, CoreResultFrameErrorV1,
    FRAME_HEADER_BYTES_V1, FrameCommitmentV1, FrameHeaderV1, FrameNonceV1, FrameObjectKindV1,
    ResultDekV1, SealedFrameV1, SegmentHeaderV1, canonical_core_result_frame_aad_v1,
    open_core_result_frame_v1, open_frame_v1, seal_core_result_frame_v1,
    segment_start_commitment_v1,
};

fn result_id(value: u8) -> ResultId {
    ResultId::from_bytes([value; 32])
}

fn authority(
    result: u8,
    source: u8,
    receipt: u8,
) -> Result<CoreResultFrameAuthorityV1, CoreResultFrameErrorV1> {
    CoreResultFrameAuthorityV1::new(
        result_id(result),
        SourceIdentityDigest::from_bytes([source; 32]),
        AcquisitionReceiptId::from_bytes([receipt; 32]),
    )
}

fn segment(result: u8) -> SegmentHeaderV1 {
    SegmentHeaderV1::new(
        CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1,
        result_id(result),
        0,
        1_000,
        2_000,
        FrameCommitmentV1::ZERO,
    )
    .unwrap()
}

fn header(segment: &SegmentHeaderV1, plaintext_length: u32) -> FrameHeaderV1 {
    FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        plaintext_length,
        FrameNonceV1::from_bytes([0x44; 24]),
        segment_start_commitment_v1(segment),
    )
    .unwrap()
}

#[test]
fn authority_aad_layout_is_exact_and_binds_every_identity_and_chain_field() {
    let authority = authority(0x11, 0x22, 0x33).unwrap();
    let exact_segment = segment(0x11);
    let header = header(&exact_segment, 7);
    let aad = canonical_core_result_frame_aad_v1(authority, &exact_segment, &header).unwrap();
    assert_eq!(aad.len(), CORE_RESULT_FRAME_AAD_BYTES_V1);

    let mut expected = Vec::new();
    expected.extend_from_slice(CORE_RESULT_FRAME_AAD_DOMAIN_V1);
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&[0x33; 32]);
    expected.extend_from_slice(&exact_segment.encode());
    expected.extend_from_slice(&header.encode());
    assert_eq!(aad.as_slice(), expected);
    let frame_offset = aad.len() - FRAME_HEADER_BYTES_V1;
    assert_eq!(
        &aad[frame_offset + 52..frame_offset + 84],
        header.previous_frame_commitment().as_bytes()
    );

    let foreign_segment = segment(0x12);
    assert_eq!(
        canonical_core_result_frame_aad_v1(authority, &foreign_segment, &header),
        Err(CoreResultFrameErrorV1::AuthorityMismatch)
    );
}

#[test]
fn exact_binary_round_trip_requires_the_authority_bound_path() {
    let key = ResultDekV1::from_test_bytes([0x55; 32]).unwrap();
    let authority = authority(0x11, 0x22, 0x33).unwrap();
    let segment = segment(0x11);
    let plaintext = b"\xff\0line\r\nnot utf8\x80";
    let frame = seal_core_result_frame_v1(
        &key.frame_key(),
        authority,
        &segment,
        header(&segment, plaintext.len() as u32),
        plaintext,
    )
    .unwrap();
    let opened = open_core_result_frame_v1(&key.frame_key(), authority, &segment, &frame).unwrap();
    assert_eq!(opened.as_bytes(), plaintext);
    assert!(open_frame_v1(&key.frame_key(), &segment, &frame).is_err());
}

#[test]
fn wrong_source_receipt_result_segment_and_key_never_release_plaintext() {
    let key = ResultDekV1::from_test_bytes([0x55; 32]).unwrap();
    let wrong_key = ResultDekV1::from_test_bytes([0x56; 32]).unwrap();
    let exact_authority = authority(0x11, 0x22, 0x33).unwrap();
    let segment = segment(0x11);
    let frame = seal_core_result_frame_v1(
        &key.frame_key(),
        exact_authority,
        &segment,
        header(&segment, 6),
        b"secret",
    )
    .unwrap();

    for wrong_authority in [
        authority(0x11, 0x23, 0x33).unwrap(),
        authority(0x11, 0x22, 0x34).unwrap(),
    ] {
        assert_eq!(
            open_core_result_frame_v1(&key.frame_key(), wrong_authority, &segment, &frame).err(),
            Some(CoreResultFrameErrorV1::FrameOpenFailed)
        );
    }
    assert_eq!(
        open_core_result_frame_v1(&wrong_key.frame_key(), exact_authority, &segment, &frame,).err(),
        Some(CoreResultFrameErrorV1::FrameOpenFailed)
    );
    assert_eq!(
        open_core_result_frame_v1(
            &key.frame_key(),
            authority(0x12, 0x22, 0x33).unwrap(),
            &segment,
            &frame,
        )
        .err(),
        Some(CoreResultFrameErrorV1::AuthorityMismatch)
    );

    let different_segment = SegmentHeaderV1::new(
        CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1,
        result_id(0x11),
        1,
        1_000,
        2_000,
        FrameCommitmentV1::from_bytes([0x99; 32]),
    )
    .unwrap();
    assert_eq!(
        open_core_result_frame_v1(
            &key.frame_key(),
            exact_authority,
            &different_segment,
            &frame,
        )
        .err(),
        Some(CoreResultFrameErrorV1::FrameOpenFailed)
    );
}

#[test]
fn mutation_truncation_and_previous_commitment_substitution_fail_closed() {
    let key = ResultDekV1::from_test_bytes([0x55; 32]).unwrap();
    let authority = authority(0x11, 0x22, 0x33).unwrap();
    let segment = segment(0x11);
    let frame = seal_core_result_frame_v1(
        &key.frame_key(),
        authority,
        &segment,
        header(&segment, 7),
        b"payload",
    )
    .unwrap();
    let encoded = frame.encode();
    for boundary in 0..encoded.len() {
        assert!(SealedFrameV1::decode(&segment, &encoded[..boundary]).is_err());
    }

    for offset in [52usize, FRAME_HEADER_BYTES_V1, encoded.len() - 1] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0x80;
        if let Ok(mutated_frame) = SealedFrameV1::decode(&segment, &mutated) {
            assert!(
                open_core_result_frame_v1(&key.frame_key(), authority, &segment, &mutated_frame,)
                    .is_err()
            );
        }
    }
}

#[test]
fn authority_and_failures_have_contentless_debug_output() {
    assert_eq!(
        authority(0, 1, 2),
        Err(CoreResultFrameErrorV1::InvalidResultId)
    );
    let rendered = format!(
        "{:?} {:?}",
        authority(0x71, 0x72, 0x73).unwrap(),
        CoreResultFrameErrorV1::FrameOpenFailed
    );
    for canary in ["71717171", "72727272", "73737373"] {
        assert!(!rendered.contains(canary));
    }
    assert_eq!(
        CoreResultFrameErrorV1::FrameOpenFailed.to_string(),
        "EVIDENTRAIL_CORE_RESULT_FRAME_OPEN_FAILED"
    );
}
