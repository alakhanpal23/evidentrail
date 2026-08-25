use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    FRAME_AAD_BYTES_V1, FRAME_AAD_DOMAIN_V1, FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1,
    FrameChainV1, FrameCommitmentV1, FrameHeaderV1, FrameNonceV1, FrameObjectKindV1,
    MAX_FRAME_PLAINTEXT_BYTES_V1, MAX_FRAMES_PER_SEGMENT_V1, RESULT_DEK_BYTES_V1, ResultDekV1,
    SEGMENT_HEADER_BYTES_V1, SealedFrameV1, SegmentHeaderV1, SnapshotFormatErrorV1,
    canonical_frame_aad_v1, open_frame_v1, seal_frame_v1, segment_start_commitment_v1,
};

fn segment(result_seed: u8) -> SegmentHeaderV1 {
    SegmentHeaderV1::new(
        7,
        ResultId::from_bytes([result_seed; 32]),
        0,
        1_000,
        2_000,
        FrameCommitmentV1::ZERO,
    )
    .unwrap()
}

fn key(seed: u8) -> ResultDekV1 {
    ResultDekV1::from_test_bytes([seed; RESULT_DEK_BYTES_V1]).unwrap()
}

fn nonce(seed: u8) -> FrameNonceV1 {
    FrameNonceV1::from_bytes([seed; 24])
}

fn sealed_fixture() -> (SegmentHeaderV1, ResultDekV1, SealedFrameV1) {
    let segment = segment(11);
    let key = key(12);
    let header = FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        20,
        nonce(13),
        segment_start_commitment_v1(&segment),
    )
    .unwrap();
    let frame =
        seal_frame_v1(&key.frame_key(), &segment, header, b"authenticated bytes\0").unwrap();
    (segment, key, frame)
}

#[test]
fn fixed_width_headers_are_exact_big_endian_and_constructor_validated() {
    let result = ResultId::from_bytes([0x44; 32]);
    let segment = SegmentHeaderV1::new(
        0x1234,
        result,
        0,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        FrameCommitmentV1::ZERO,
    )
    .unwrap();
    let encoded = segment.encode();
    assert_eq!(encoded.len(), SEGMENT_HEADER_BYTES_V1);
    assert_eq!(&encoded[0..8], b"EVRSNP01");
    assert_eq!(&encoded[8..10], &[0, 1]);
    assert_eq!(&encoded[10..12], &[0, 1]);
    assert_eq!(&encoded[12..14], &[0x12, 0x34]);
    assert_eq!(&encoded[14..16], &[0, 0]);
    assert_eq!(&encoded[16..48], &[0x44; 32]);
    assert_eq!(&encoded[48..56], &[0; 8]);
    assert_eq!(&encoded[56..64], &0x0102_0304_0506_0708i64.to_be_bytes());
    assert_eq!(&encoded[64..72], &0x1112_1314_1516_1718i64.to_be_bytes());
    assert!(encoded[72..].iter().all(|byte| *byte == 0));
    assert_eq!(SegmentHeaderV1::decode(&encoded).unwrap(), segment);

    let previous = segment_start_commitment_v1(&segment);
    let frame = FrameHeaderV1::new(
        FrameObjectKindV1::AcquisitionSeal,
        0x0102_0304_0506_0708,
        0x0102,
        0x2122,
        FrameNonceV1::from_bytes([0x55; 24]),
        previous,
    )
    .unwrap();
    let frame_bytes = frame.encode();
    assert_eq!(frame_bytes.len(), FRAME_HEADER_BYTES_V1);
    assert_eq!(&frame_bytes[0..4], b"FRM1");
    assert_eq!(&frame_bytes[4..8], &[0, 1, 0, 2]);
    assert_eq!(&frame_bytes[8..16], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&frame_bytes[16..20], &0x0102u32.to_be_bytes());
    assert_eq!(&frame_bytes[20..24], &0x2122u32.to_be_bytes());
    assert_eq!(
        &frame_bytes[24..28],
        &(0x2122u32 + u32::try_from(FRAME_TAG_BYTES_V1).unwrap()).to_be_bytes()
    );
    assert_eq!(&frame_bytes[28..52], &[0x55; 24]);
    assert_eq!(&frame_bytes[52..84], previous.as_bytes());
    assert!(frame_bytes[84..92].iter().all(|byte| *byte == 0));
    assert_eq!(FrameHeaderV1::decode(&frame_bytes).unwrap(), frame);

    let aad = canonical_frame_aad_v1(&segment, &frame);
    assert_eq!(aad.len(), FRAME_AAD_BYTES_V1);
    assert_eq!(&aad[..FRAME_AAD_DOMAIN_V1.len()], FRAME_AAD_DOMAIN_V1);
    assert_eq!(
        &aad[FRAME_AAD_DOMAIN_V1.len()..FRAME_AAD_DOMAIN_V1.len() + SEGMENT_HEADER_BYTES_V1],
        &encoded
    );
    assert_eq!(
        &aad[FRAME_AAD_DOMAIN_V1.len() + SEGMENT_HEADER_BYTES_V1..],
        &frame_bytes
    );

    assert_eq!(
        SegmentHeaderV1::new(0, result, 0, 1, 2, FrameCommitmentV1::ZERO),
        Err(SnapshotFormatErrorV1::InvalidPayloadSchema)
    );
    assert_eq!(
        SegmentHeaderV1::new(1, result, 0, 2, 2, FrameCommitmentV1::ZERO),
        Err(SnapshotFormatErrorV1::InvalidTimeRange)
    );
    assert_eq!(
        SegmentHeaderV1::new(1, result, 1, 1, 2, FrameCommitmentV1::ZERO),
        Err(SnapshotFormatErrorV1::InvalidSegmentChainStart)
    );
    assert_eq!(
        SegmentHeaderV1::new(1, result, 0, 1, 2, FrameCommitmentV1::from_bytes([1; 32])),
        Err(SnapshotFormatErrorV1::InvalidSegmentChainStart)
    );
    assert_eq!(
        FrameChainV1::new(segment.clone(), 1).unwrap_err(),
        SnapshotFormatErrorV1::GlobalSequenceMismatch
    );
    let later_segment =
        SegmentHeaderV1::new(1, result, 1, 1, 2, FrameCommitmentV1::from_bytes([1; 32])).unwrap();
    assert_eq!(
        FrameChainV1::new(later_segment.clone(), 0).unwrap_err(),
        SnapshotFormatErrorV1::GlobalSequenceMismatch
    );
    assert!(FrameChainV1::new(later_segment, 1).is_ok());
}

#[test]
fn decoder_rejects_unknown_fixed_fields_and_lengths_before_allocation() {
    let segment = segment(20);
    let canonical_segment = segment.encode();
    for boundary in 0..SEGMENT_HEADER_BYTES_V1 {
        assert_eq!(
            SegmentHeaderV1::decode(&canonical_segment[..boundary]),
            Err(SnapshotFormatErrorV1::InvalidEncodedLength)
        );
    }
    let mut bytes = segment.encode();
    bytes[0] ^= 1;
    assert_eq!(
        SegmentHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::InvalidMagic)
    );
    let mut bytes = segment.encode();
    bytes[9] = 2;
    assert_eq!(
        SegmentHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedOuterVersion)
    );
    let mut bytes = segment.encode();
    bytes[11] = 2;
    assert_eq!(
        SegmentHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedSuite)
    );
    let mut bytes = segment.encode();
    bytes[15] = 1;
    assert_eq!(
        SegmentHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::NonzeroFlags)
    );
    let mut bytes = segment.encode();
    bytes[119] = 1;
    assert_eq!(
        SegmentHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::NonzeroReserved)
    );
    assert_eq!(
        SegmentHeaderV1::decode(&segment.encode()[..119]),
        Err(SnapshotFormatErrorV1::InvalidEncodedLength)
    );

    let header = FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        0,
        nonce(1),
        segment_start_commitment_v1(&segment),
    )
    .unwrap();
    let canonical_frame_header = header.encode();
    for boundary in 0..FRAME_HEADER_BYTES_V1 {
        assert_eq!(
            FrameHeaderV1::decode(&canonical_frame_header[..boundary]),
            Err(SnapshotFormatErrorV1::InvalidEncodedLength)
        );
    }
    let mut bytes = header.encode();
    bytes[7] = 99;
    assert_eq!(
        FrameHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedObjectKind)
    );
    let mut bytes = header.encode();
    bytes[27] ^= 1;
    assert_eq!(
        FrameHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::CiphertextLengthMismatch)
    );
    let mut bytes = header.encode();
    let over_cap = u32::try_from(MAX_FRAME_PLAINTEXT_BYTES_V1 + 1).unwrap();
    bytes[20..24].copy_from_slice(&over_cap.to_be_bytes());
    bytes[24..28].copy_from_slice(&(over_cap + 16).to_be_bytes());
    assert_eq!(
        FrameHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::PlaintextTooLarge)
    );
    let mut bytes = header.encode();
    bytes[91] = 1;
    assert_eq!(
        FrameHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::NonzeroReserved)
    );
}

#[test]
fn injected_key_nonce_round_trip_is_deterministic_and_frozen() {
    let segment = segment(11);
    let key =
        ResultDekV1::from_test_bytes(std::array::from_fn(|index| u8::try_from(index).unwrap()))
            .unwrap();
    let nonce = FrameNonceV1::from_bytes(std::array::from_fn(|index| {
        0x20 + u8::try_from(index).unwrap()
    }));
    let header = FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        7,
        nonce,
        segment_start_commitment_v1(&segment),
    )
    .unwrap();
    let frame = seal_frame_v1(&key.frame_key(), &segment, header, b"abc\0\xff\nZ").unwrap();
    let encoded = frame.encode();
    assert_eq!(
        hex(&encoded),
        "46524d31000100010000000000000000000000000000000700000017202122232425262728292a2b2c2d2e2f30313233343536377504c1071c6ec967cb5f4c20634d3951219e3dccd91f2967744ff11e7d9d785800000000000000007c3b2ecb843d4e28693b91ad96bf7abbf50340fa744ec3"
    );
    assert_eq!(
        open_frame_v1(&key.frame_key(), &segment, &frame)
            .unwrap()
            .as_bytes(),
        b"abc\0\xff\nZ"
    );
    assert_eq!(SealedFrameV1::decode(&segment, &encoded).unwrap(), frame);
}

#[test]
fn every_frame_truncation_and_single_byte_mutation_fails_closed() {
    let (segment, key, frame) = sealed_fixture();
    let encoded = frame.encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            SealedFrameV1::decode(&segment, &encoded[..boundary]),
            Err(SnapshotFormatErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        SealedFrameV1::decode(&segment, &extended),
        Err(SnapshotFormatErrorV1::InvalidEncodedLength)
    );
    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 1;
        if let Ok(mutated_frame) = SealedFrameV1::decode(&segment, &mutated) {
            assert!(
                open_frame_v1(&key.frame_key(), &segment, &mutated_frame).is_err(),
                "mutation {index} authenticated"
            );
        }
    }
}

#[test]
fn cross_result_and_segment_header_mutation_fail_authentication() {
    let (original_segment, frame_key, frame) = sealed_fixture();
    let foreign = segment(99);
    assert!(open_frame_v1(&frame_key.frame_key(), &foreign, &frame).is_err());
    let wrong_key = key(0xfe);
    assert!(open_frame_v1(&wrong_key.frame_key(), &original_segment, &frame).is_err());

    let encoded_header = original_segment.encode();
    for index in 0..encoded_header.len() {
        let mut mutated = encoded_header;
        mutated[index] ^= 1;
        if let Ok(mutated_header) = SegmentHeaderV1::decode(&mutated) {
            assert!(
                open_frame_v1(&frame_key.frame_key(), &mutated_header, &frame).is_err(),
                "segment-header mutation {index} authenticated"
            );
        }
    }
}

#[test]
fn frame_chain_rejects_reorder_duplicate_and_reused_nonce_without_advancing() {
    let segment = segment(30);
    let key = key(31);
    let frame_key = key.frame_key();
    let mut writer = FrameChainV1::new(segment.clone(), 0).unwrap();
    let first = writer
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            nonce(1),
            b"first",
        )
        .unwrap();
    assert_eq!(
        writer.seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            nonce(1),
            b"reuse"
        ),
        Err(SnapshotFormatErrorV1::DuplicateNonce)
    );
    assert_eq!(writer.next_global_sequence(), 1);
    let second = writer
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AcquisitionSeal,
            nonce(2),
            b"second",
        )
        .unwrap();

    let mut reader = FrameChainV1::new(segment, 0).unwrap();
    assert_eq!(
        reader.open_next(&frame_key, &second).unwrap_err(),
        SnapshotFormatErrorV1::GlobalSequenceMismatch
    );
    assert_eq!(reader.next_global_sequence(), 0);
    assert_eq!(
        reader.open_next(&frame_key, &first).unwrap().as_bytes(),
        b"first"
    );
    assert_eq!(
        reader.open_next(&frame_key, &first).unwrap_err(),
        SnapshotFormatErrorV1::GlobalSequenceMismatch
    );
    assert_eq!(
        reader.open_next(&frame_key, &second).unwrap().as_bytes(),
        b"second"
    );
    assert_eq!(reader.final_commitment(), writer.final_commitment());
}

#[test]
fn invalid_utf8_nul_empty_and_duplicate_records_remain_exact_occurrences() {
    let segment = segment(40);
    let key = key(41);
    let frame_key = key.frame_key();
    let mut writer = FrameChainV1::new(segment.clone(), 0).unwrap();
    let hostile = [0xff, 0, b'\r', b'\n', 0x80];
    let first = writer
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            nonce(1),
            &hostile,
        )
        .unwrap();
    let duplicate = writer
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            nonce(2),
            &hostile,
        )
        .unwrap();
    let empty = writer
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AcquisitionSeal,
            nonce(3),
            b"",
        )
        .unwrap();
    assert_ne!(first.encode(), duplicate.encode());
    assert_ne!(first.commitment(), duplicate.commitment());

    let mut reader = FrameChainV1::new(segment, 0).unwrap();
    assert_eq!(
        reader.open_next(&frame_key, &first).unwrap().as_bytes(),
        hostile
    );
    assert_eq!(
        reader.open_next(&frame_key, &duplicate).unwrap().as_bytes(),
        hostile
    );
    assert!(
        reader
            .open_next(&frame_key, &empty)
            .unwrap()
            .as_bytes()
            .is_empty()
    );
}

#[test]
fn frame_and_allocation_caps_are_inclusive_and_fail_before_state_change() {
    let segment = segment(50);
    let maximum_header = FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        u32::try_from(MAX_FRAME_PLAINTEXT_BYTES_V1).unwrap(),
        nonce(1),
        segment_start_commitment_v1(&segment),
    )
    .unwrap();
    assert_eq!(
        FrameHeaderV1::new(
            FrameObjectKindV1::AuthorizedOutcome,
            0,
            0,
            u32::try_from(MAX_FRAME_PLAINTEXT_BYTES_V1 + 1).unwrap(),
            nonce(1),
            segment_start_commitment_v1(&segment),
        ),
        Err(SnapshotFormatErrorV1::PlaintextTooLarge)
    );

    let key = key(51);
    let frame_key = key.frame_key();
    let maximum_plaintext = vec![0xa5; MAX_FRAME_PLAINTEXT_BYTES_V1];
    let maximum_frame =
        seal_frame_v1(&frame_key, &segment, maximum_header, &maximum_plaintext).unwrap();
    let opened = open_frame_v1(&frame_key, &segment, &maximum_frame).unwrap();
    assert_eq!(opened.as_bytes(), maximum_plaintext);

    let mut chain = FrameChainV1::new(segment, 0).unwrap();
    for sequence in 0..MAX_FRAMES_PER_SEGMENT_V1 {
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[..4].copy_from_slice(&sequence.to_be_bytes());
        chain
            .seal_next(
                &frame_key,
                FrameObjectKindV1::AuthorizedOutcome,
                FrameNonceV1::from_bytes(nonce_bytes),
                b"",
            )
            .unwrap();
    }
    assert_eq!(
        chain.seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            nonce(0xff),
            b""
        ),
        Err(SnapshotFormatErrorV1::FrameCountCap)
    );
    assert_eq!(
        chain.next_segment_frame_sequence(),
        MAX_FRAMES_PER_SEGMENT_V1
    );
}

#[test]
fn all_public_debug_and_errors_are_contentless() {
    const CANARY: &str = "SECRET_KEY_RESULT_NONCE_PAYLOAD_71f9";
    let segment = SegmentHeaderV1::new(
        1,
        ResultId::from_bytes([b'S'; 32]),
        0,
        1,
        2,
        FrameCommitmentV1::ZERO,
    )
    .unwrap();
    let key = ResultDekV1::from_test_bytes([b'K'; RESULT_DEK_BYTES_V1]).unwrap();
    let frame_key = key.frame_key();
    let mut chain = FrameChainV1::new(segment.clone(), 0).unwrap();
    let frame = chain
        .seal_next(
            &frame_key,
            FrameObjectKindV1::AuthorizedOutcome,
            FrameNonceV1::from_bytes([b'N'; 24]),
            CANARY.as_bytes(),
        )
        .unwrap();
    let opened = open_frame_v1(&frame_key, &segment, &frame).unwrap();
    let rendered = format!(
        "{segment:?} {:?} {:?} {key:?} {frame_key:?} {frame:?} {opened:?} {chain:?} {:?}",
        frame.header(),
        frame.commitment(),
        SnapshotFormatErrorV1::AuthenticationFailed
    );
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains("KKKK"));
    assert!(!rendered.contains("NNNN"));
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
