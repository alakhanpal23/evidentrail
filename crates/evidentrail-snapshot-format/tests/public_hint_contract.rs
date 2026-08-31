use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    PUBLIC_CLEANUP_HINT_BYTES_V1, PUBLIC_CLEANUP_HINT_VERSION_V1, PublicCleanupHintErrorV1,
    PublicCleanupHintV1, RootKeyVersionV1, XCHACHA20_POLY1305_SUITE_ID_V1,
};
use sha2::{Digest, Sha256};

fn result_id() -> ResultId {
    let mut bytes = [0u8; 32];
    for (byte, value) in bytes.iter_mut().zip(0x20u8..0x40) {
        *byte = value;
    }
    ResultId::from_bytes(bytes)
}

fn hint() -> PublicCleanupHintV1 {
    PublicCleanupHintV1::new(
        0x1234,
        result_id(),
        RootKeyVersionV1::new(0x0102_0304).unwrap(),
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
    )
    .unwrap()
}

#[test]
fn exact_layout_and_independently_reconstructed_golden_hash_are_frozen() {
    let encoded = hint().encode();
    let mut expected = [0u8; PUBLIC_CLEANUP_HINT_BYTES_V1];
    expected[0..8].copy_from_slice(b"EVRPUB01");
    expected[8..10].copy_from_slice(&1u16.to_be_bytes());
    expected[10..12].copy_from_slice(&1u16.to_be_bytes());
    expected[12..14].copy_from_slice(&0x1234u16.to_be_bytes());
    expected[14..46].copy_from_slice(result_id().as_bytes());
    expected[46..50].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    expected[50..58].copy_from_slice(&0x0102_0304_0506_0708i64.to_be_bytes());
    expected[58..66].copy_from_slice(&0x1112_1314_1516_1718i64.to_be_bytes());
    assert!(expected[66..82].iter().all(|byte| *byte == 0));

    assert_eq!(encoded, expected);
    // Independently frozen with Python 3 `bytearray`, `int.to_bytes('big')`,
    // and `hashlib.sha256`, rather than this Rust encoder.
    assert_eq!(
        Sha256::digest(expected).as_slice(),
        &[
            0xc5, 0x8c, 0x39, 0x38, 0xca, 0x9a, 0x6b, 0xb3, 0x4a, 0x79, 0x32, 0x01, 0xb3, 0x96,
            0xbf, 0x9f, 0x3f, 0x69, 0xb9, 0x22, 0x5f, 0xbb, 0xde, 0x53, 0x53, 0x02, 0x46, 0x90,
            0x05, 0xda, 0x72, 0xb3,
        ]
    );

    let decoded = PublicCleanupHintV1::decode(&expected).unwrap();
    assert_eq!(decoded, hint());
    assert_eq!(decoded.encode(), expected);
    assert_eq!(decoded.version(), PUBLIC_CLEANUP_HINT_VERSION_V1);
    assert_eq!(decoded.suite_id(), XCHACHA20_POLY1305_SUITE_ID_V1);
    assert_eq!(decoded.manifest_payload_schema_version(), 0x1234);
    assert_eq!(decoded.result_id(), result_id());
    assert_eq!(decoded.root_key_version().get(), 0x0102_0304);
    assert_eq!(decoded.created_unix_nanos(), 0x0102_0304_0506_0708);
    assert_eq!(decoded.expires_unix_nanos(), 0x1112_1314_1516_1718);
}

#[test]
fn constructor_checks_nonzero_id_versions_and_full_i64_time_domain() {
    assert_eq!(
        PublicCleanupHintV1::new(
            1,
            ResultId::from_bytes([0; 32]),
            RootKeyVersionV1::new(1).unwrap(),
            0,
            1,
        ),
        Err(PublicCleanupHintErrorV1::InvalidResultId)
    );
    assert_eq!(
        PublicCleanupHintV1::new(0, result_id(), RootKeyVersionV1::new(1).unwrap(), 0, 1,),
        Err(PublicCleanupHintErrorV1::InvalidManifestPayloadSchemaVersion)
    );
    assert!(RootKeyVersionV1::new(0).is_err());
    assert_eq!(
        PublicCleanupHintV1::new(1, result_id(), RootKeyVersionV1::new(1).unwrap(), 7, 7,),
        Err(PublicCleanupHintErrorV1::InvalidTimeRange)
    );
    assert_eq!(
        PublicCleanupHintV1::new(
            u16::MAX,
            result_id(),
            RootKeyVersionV1::new(u32::MAX).unwrap(),
            i64::MIN,
            i64::MAX,
        )
        .unwrap()
        .expires_unix_nanos(),
        i64::MAX
    );
}

#[test]
fn decoder_rejects_every_truncation_and_all_trailing_data() {
    let encoded = hint().encode();
    for length in 0..PUBLIC_CLEANUP_HINT_BYTES_V1 {
        assert_eq!(
            PublicCleanupHintV1::decode(&encoded[..length]),
            Err(PublicCleanupHintErrorV1::InvalidEncodedLength),
            "accepted truncation at {length}"
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        PublicCleanupHintV1::decode(&trailing),
        Err(PublicCleanupHintErrorV1::InvalidEncodedLength)
    );
}

#[test]
fn decoder_rejects_unknown_fixed_fields_and_every_noncanonical_zero_region() {
    let encoded = hint().encode();

    let mut wrong_magic = encoded;
    wrong_magic[0] ^= 1;
    assert_eq!(
        PublicCleanupHintV1::decode(&wrong_magic),
        Err(PublicCleanupHintErrorV1::InvalidMagic)
    );

    let mut wrong_version = encoded;
    wrong_version[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        PublicCleanupHintV1::decode(&wrong_version),
        Err(PublicCleanupHintErrorV1::UnsupportedVersion)
    );

    let mut wrong_suite = encoded;
    wrong_suite[10..12].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        PublicCleanupHintV1::decode(&wrong_suite),
        Err(PublicCleanupHintErrorV1::UnsupportedSuite)
    );

    let mut zero_schema = encoded;
    zero_schema[12..14].fill(0);
    assert_eq!(
        PublicCleanupHintV1::decode(&zero_schema),
        Err(PublicCleanupHintErrorV1::InvalidManifestPayloadSchemaVersion)
    );

    let mut zero_result = encoded;
    zero_result[14..46].fill(0);
    assert_eq!(
        PublicCleanupHintV1::decode(&zero_result),
        Err(PublicCleanupHintErrorV1::InvalidResultId)
    );

    let mut zero_root_version = encoded;
    zero_root_version[46..50].fill(0);
    assert_eq!(
        PublicCleanupHintV1::decode(&zero_root_version),
        Err(PublicCleanupHintErrorV1::InvalidRootKeyVersion)
    );

    let mut invalid_time = encoded;
    invalid_time[58..66].copy_from_slice(&0x0102_0304_0506_0708i64.to_be_bytes());
    assert_eq!(
        PublicCleanupHintV1::decode(&invalid_time),
        Err(PublicCleanupHintErrorV1::InvalidTimeRange)
    );

    for offset in 66..PUBLIC_CLEANUP_HINT_BYTES_V1 {
        let mut nonzero_reserved = encoded;
        nonzero_reserved[offset] = 1;
        assert_eq!(
            PublicCleanupHintV1::decode(&nonzero_reserved),
            Err(PublicCleanupHintErrorV1::NonzeroReserved),
            "accepted nonzero reserved byte at {offset}"
        );
    }
}

#[test]
fn debug_and_errors_expose_no_result_time_or_content_canaries() {
    let canary_result = ResultId::from_bytes(*b"CANARY_RESULT_IDENTIFIER_BYTES!!");
    let hint = PublicCleanupHintV1::new(
        0x4341,
        canary_result,
        RootKeyVersionV1::new(0x4e41_5259).unwrap(),
        1_234_567_890,
        1_234_567_999,
    )
    .unwrap();
    let result_token = canary_result.canonical_token();
    let outputs = [
        format!("{hint:?}"),
        format!("{:?}", PublicCleanupHintErrorV1::InvalidResultId),
        PublicCleanupHintErrorV1::InvalidTimeRange.to_string(),
    ];
    for output in outputs {
        assert!(!output.contains("CANARY"));
        assert!(!output.contains(&result_token));
        assert!(!output.contains("1234567"));
        assert!(!output.contains("4341"));
        assert!(!output.contains("4e415259"));
    }
    assert_eq!(format!("{hint:?}"), "PublicCleanupHintV1(<redacted>)");
}
