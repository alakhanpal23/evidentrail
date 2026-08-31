use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    MANIFEST_AAD_BYTES_V1, MANIFEST_AAD_DOMAIN_V1, MANIFEST_HEADER_BYTES_V1,
    MANIFEST_OBJECT_KIND_V1, MANIFEST_TAG_BYTES_V1, MAX_MANIFEST_PLAINTEXT_BYTES_V1,
    ManifestHeaderV1, ManifestNonceV1, RESULT_DEK_BYTES_V1, ResultDekV1, SealedManifestV1,
    SnapshotFormatErrorV1, canonical_manifest_aad_v1, open_manifest_v1, seal_manifest_v1,
};

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn key(seed: u8) -> ResultDekV1 {
    ResultDekV1::from_test_bytes([seed; RESULT_DEK_BYTES_V1]).unwrap()
}

fn nonce(seed: u8) -> ManifestNonceV1 {
    ManifestNonceV1::from_bytes([seed; 24])
}

fn header(result_seed: u8, nonce_seed: u8, plaintext_length: usize) -> ManifestHeaderV1 {
    ManifestHeaderV1::new(
        7,
        result(result_seed),
        0,
        1_000,
        2_000,
        u32::try_from(plaintext_length).unwrap(),
        nonce(nonce_seed),
    )
    .unwrap()
}

fn sealed_fixture() -> (ResultId, ResultDekV1, SealedManifestV1) {
    let result_id = result(11);
    let key = key(12);
    let plaintext = b"manifest bytes\0\xff";
    let manifest = seal_manifest_v1(
        &key.manifest_key(),
        header(11, 13, plaintext.len()),
        plaintext,
    )
    .unwrap();
    (result_id, key, manifest)
}

#[test]
fn fixed_header_is_exact_big_endian_and_constructor_validated() {
    let result_id = result(0x44);
    let manifest_header = ManifestHeaderV1::new(
        0x1234,
        result_id,
        0,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        0x2122,
        ManifestNonceV1::from_bytes([0x55; 24]),
    )
    .unwrap();
    let encoded = manifest_header.encode();
    assert_eq!(encoded.len(), MANIFEST_HEADER_BYTES_V1);
    assert_eq!(&encoded[0..8], b"EVRMNF01");
    assert_eq!(&encoded[8..10], &[0, 1]);
    assert_eq!(&encoded[10..12], &[0, 1]);
    assert_eq!(&encoded[12..14], &[0x12, 0x34]);
    assert_eq!(&encoded[14..16], &MANIFEST_OBJECT_KIND_V1.to_be_bytes());
    assert_eq!(&encoded[16..48], &[0x44; 32]);
    assert_eq!(&encoded[48..56], &[0; 8]);
    assert_eq!(&encoded[56..64], &0x0102_0304_0506_0708i64.to_be_bytes());
    assert_eq!(&encoded[64..72], &0x1112_1314_1516_1718i64.to_be_bytes());
    assert_eq!(&encoded[72..76], &0x2122u32.to_be_bytes());
    assert_eq!(
        &encoded[76..80],
        &(0x2122u32 + u32::try_from(MANIFEST_TAG_BYTES_V1).unwrap()).to_be_bytes()
    );
    assert_eq!(&encoded[80..104], &[0x55; 24]);
    assert!(encoded[104..120].iter().all(|byte| *byte == 0));
    assert_eq!(ManifestHeaderV1::decode(&encoded).unwrap(), manifest_header);

    let aad = canonical_manifest_aad_v1(&manifest_header);
    assert_eq!(aad.len(), MANIFEST_AAD_BYTES_V1);
    assert_eq!(&aad[..MANIFEST_AAD_DOMAIN_V1.len()], MANIFEST_AAD_DOMAIN_V1);
    assert_eq!(&aad[MANIFEST_AAD_DOMAIN_V1.len()..], &encoded);

    assert_eq!(
        ManifestHeaderV1::new(0, result_id, 0, 1, 2, 0, nonce(1)),
        Err(SnapshotFormatErrorV1::InvalidPayloadSchema)
    );
    assert_eq!(
        ManifestHeaderV1::new(1, result_id, 1, 1, 2, 0, nonce(1)),
        Err(SnapshotFormatErrorV1::InvalidObjectSequence)
    );
    assert_eq!(
        ManifestHeaderV1::new(1, result_id, 0, 2, 2, 0, nonce(1)),
        Err(SnapshotFormatErrorV1::InvalidTimeRange)
    );
    assert_eq!(
        ManifestHeaderV1::new(
            1,
            result_id,
            0,
            1,
            2,
            u32::try_from(MAX_MANIFEST_PLAINTEXT_BYTES_V1 + 1).unwrap(),
            nonce(1),
        ),
        Err(SnapshotFormatErrorV1::PlaintextTooLarge)
    );
    assert_eq!(
        seal_manifest_v1(&key(1).manifest_key(), header(0x44, 1, 1), b""),
        Err(SnapshotFormatErrorV1::PlaintextLengthMismatch)
    );
}

#[test]
fn decoder_rejects_every_header_truncation_and_invalid_fixed_field() {
    let header = header(20, 21, 0);
    let canonical = header.encode();
    for boundary in 0..MANIFEST_HEADER_BYTES_V1 {
        assert_eq!(
            ManifestHeaderV1::decode(&canonical[..boundary]),
            Err(SnapshotFormatErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut extended = canonical.to_vec();
    extended.push(0);
    assert_eq!(
        ManifestHeaderV1::decode(&extended),
        Err(SnapshotFormatErrorV1::InvalidEncodedLength)
    );

    let mut bytes = canonical;
    bytes[0] ^= 1;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::InvalidMagic)
    );
    let mut bytes = canonical;
    bytes[9] = 2;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedOuterVersion)
    );
    let mut bytes = canonical;
    bytes[11] = 2;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedSuite)
    );
    let mut bytes = canonical;
    bytes[13] = 0;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::InvalidPayloadSchema)
    );
    let mut bytes = canonical;
    bytes[15] = 2;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::UnsupportedObjectKind)
    );
    let mut bytes = canonical;
    bytes[55] = 1;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::InvalidObjectSequence)
    );
    let mut bytes = canonical;
    bytes[76..80].copy_from_slice(&17u32.to_be_bytes());
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::CiphertextLengthMismatch)
    );
    let mut bytes = canonical;
    let over_cap = u32::try_from(MAX_MANIFEST_PLAINTEXT_BYTES_V1 + 1).unwrap();
    bytes[72..76].copy_from_slice(&over_cap.to_be_bytes());
    bytes[76..80].copy_from_slice(&(over_cap + 16).to_be_bytes());
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::PlaintextTooLarge)
    );
    let mut bytes = canonical;
    bytes[119] = 1;
    assert_eq!(
        ManifestHeaderV1::decode(&bytes),
        Err(SnapshotFormatErrorV1::NonzeroReserved)
    );
}

#[test]
fn injected_key_nonce_vector_is_deterministic_and_frozen() {
    let result_id = result(11);
    let key =
        ResultDekV1::from_test_bytes(std::array::from_fn(|index| u8::try_from(index).unwrap()))
            .unwrap();
    let nonce = ManifestNonceV1::from_bytes(std::array::from_fn(|index| {
        0x20 + u8::try_from(index).unwrap()
    }));
    let plaintext = b"abc\0\xff\nZ";
    let header = ManifestHeaderV1::new(
        7,
        result_id,
        0,
        1_000,
        2_000,
        u32::try_from(plaintext.len()).unwrap(),
        nonce,
    )
    .unwrap();
    let manifest = seal_manifest_v1(&key.manifest_key(), header, plaintext).unwrap();
    // Cross-checked independently with a standalone HChaCha20 derivation and
    // the Python cryptography ChaCha20-Poly1305 implementation.
    assert_eq!(
        hex(&manifest.encode()),
        "4556524d4e46303100010001000700010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000000003e800000000000007d00000000700000017202122232425262728292a2b2c2d2e2f3031323334353637000000000000000000000000000000007c3b2ecb843d4e0c727baaa68e9bdcf3af39a4a0288e33"
    );
    assert_eq!(
        hex(manifest.commitment().as_bytes()),
        "e8892af18f54e6a9284a697380381355ccc28f90130438ff4f6aae80d0f42816"
    );
    assert_eq!(
        open_manifest_v1(&key.manifest_key(), result_id, &manifest)
            .unwrap()
            .as_bytes(),
        plaintext
    );
}

#[test]
fn empty_binary_and_maximum_plaintexts_round_trip_exactly() {
    let result_id = result(30);
    let key = key(31);
    let manifest_key = key.manifest_key();
    let empty = seal_manifest_v1(&manifest_key, header(30, 1, 0), b"").unwrap();
    assert!(
        open_manifest_v1(&manifest_key, result_id, &empty)
            .unwrap()
            .as_bytes()
            .is_empty()
    );

    let binary = [0xff, 0, b'\r', b'\n', 0x80, b'\\'];
    let binary_manifest =
        seal_manifest_v1(&manifest_key, header(30, 2, binary.len()), &binary).unwrap();
    assert_eq!(
        open_manifest_v1(&manifest_key, result_id, &binary_manifest)
            .unwrap()
            .as_bytes(),
        binary
    );

    let maximum = vec![0xa5; MAX_MANIFEST_PLAINTEXT_BYTES_V1];
    let maximum_manifest =
        seal_manifest_v1(&manifest_key, header(30, 3, maximum.len()), &maximum).unwrap();
    assert_eq!(
        open_manifest_v1(&manifest_key, result_id, &maximum_manifest)
            .unwrap()
            .as_bytes(),
        maximum
    );
}

#[test]
fn every_object_truncation_and_header_ciphertext_tag_mutation_fails_closed() {
    let (result_id, key, manifest) = sealed_fixture();
    let encoded = manifest.encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            SealedManifestV1::decode(result_id, &encoded[..boundary]),
            Err(SnapshotFormatErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        SealedManifestV1::decode(result_id, &extended),
        Err(SnapshotFormatErrorV1::InvalidEncodedLength)
    );
    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 1;
        if let Ok(mutated_manifest) = SealedManifestV1::decode(result_id, &mutated) {
            assert!(
                open_manifest_v1(&key.manifest_key(), result_id, &mutated_manifest).is_err(),
                "mutation {index} authenticated"
            );
        }
    }
}

#[test]
fn wrong_key_and_result_fail_without_releasing_plaintext() {
    let (result_id, manifest_key, manifest) = sealed_fixture();
    assert_eq!(
        open_manifest_v1(&manifest_key.manifest_key(), result(99), &manifest).unwrap_err(),
        SnapshotFormatErrorV1::ResultMismatch
    );
    assert_eq!(
        SealedManifestV1::decode(result(99), &manifest.encode()),
        Err(SnapshotFormatErrorV1::ResultMismatch)
    );
    let wrong_key = key(0xfe);
    assert_eq!(
        open_manifest_v1(&wrong_key.manifest_key(), result_id, &manifest).unwrap_err(),
        SnapshotFormatErrorV1::AuthenticationFailed
    );
}

#[test]
fn public_debug_and_errors_are_contentless() {
    const CANARY: &str = "SECRET_MANIFEST_PAYLOAD_9d3f";
    let result_id = ResultId::from_bytes([b'S'; 32]);
    let key = ResultDekV1::from_test_bytes([b'K'; RESULT_DEK_BYTES_V1]).unwrap();
    let manifest_key = key.manifest_key();
    let nonce = ManifestNonceV1::from_bytes([b'N'; 24]);
    let header = ManifestHeaderV1::new(
        1,
        result_id,
        0,
        1,
        2,
        u32::try_from(CANARY.len()).unwrap(),
        nonce,
    )
    .unwrap();
    let manifest = seal_manifest_v1(&manifest_key, header, CANARY.as_bytes()).unwrap();
    let opened = open_manifest_v1(&manifest_key, result_id, &manifest).unwrap();
    let error = SnapshotFormatErrorV1::AuthenticationFailed;
    let rendered = format!(
        "{header:?} {key:?} {manifest_key:?} {nonce:?} {manifest:?} {opened:?} {:?} {error:?} {error}",
        manifest.commitment()
    );
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains("KKKK"));
    assert!(!rendered.contains("NNNN"));
    assert!(!rendered.contains("SSSS"));
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
