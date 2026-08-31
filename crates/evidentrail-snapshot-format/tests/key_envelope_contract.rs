use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    DEK_WRAP_AAD_BYTES_V1, DEK_WRAP_AAD_DOMAIN_V1, DekWrapNonceV1, DerivedResultKeysV1,
    FrameCommitmentV1, KEY_ENVELOPE_CONTEXT_BYTES_V1, KEY_RECORD_VERSION_V1, KeyEnvelopeContextV1,
    KeyEnvelopeErrorV1, MANIFEST_COMMITMENT_BYTES_V1, MAX_SEGMENTS_PER_RESULT_V1,
    MAX_TOTAL_FRAMES_PER_RESULT_V1, ManifestCommitmentV1, ManifestHeaderV1, ManifestNonceV1,
    RESULT_DEK_BYTES_V1, RootKekV1, RootKeyVersionV1, SEAL_BINDING_AAD_BYTES_V1,
    SEAL_BINDING_AAD_DOMAIN_V1, SEAL_BINDING_BYTES_V1, SEALED_SEAL_BINDING_BYTES_V1,
    SealBindingNonceV1, SealBindingV1, SealedSealBindingV1, WRAPPED_RESULT_DEK_BYTES_V1,
    WrappedResultDekV1, canonical_dek_wrap_aad_v1, canonical_seal_binding_aad_v1,
    open_seal_binding_v1, open_wrapped_result_dek_v1, seal_binding_v1, seal_manifest_v1,
    wrap_result_dek_v1,
};
use zeroize::Zeroizing;

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn version(value: u32) -> RootKeyVersionV1 {
    RootKeyVersionV1::new(value).unwrap()
}

fn context() -> KeyEnvelopeContextV1 {
    KeyEnvelopeContextV1::new(
        version(0x0102_0304),
        result(0x11),
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
    )
    .unwrap()
}

fn derived_keys(root_offset: u8) -> DerivedResultKeysV1 {
    derived_keys_for(root_offset, result(0x11), version(0x0102_0304))
}

fn derived_keys_for(
    root_offset: u8,
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
) -> DerivedResultKeysV1 {
    let mut root = [0u8; 32];
    for (byte, value) in root.iter_mut().zip(0u8..) {
        *byte = value.wrapping_add(root_offset);
    }
    RootKekV1::from_zeroizing(Zeroizing::new(root))
        .unwrap()
        .derive_result_keys(result_id, root_key_version)
        .unwrap()
}

fn binding() -> SealBindingV1 {
    SealBindingV1::new(
        ManifestCommitmentV1::from_bytes([0x44; MANIFEST_COMMITMENT_BYTES_V1]),
        FrameCommitmentV1::from_bytes([0x55; 32]),
        5_000,
        2,
    )
    .unwrap()
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap();
    }
    output
}

#[test]
fn context_codec_and_both_aad_domains_are_exact_big_endian() {
    let context = context();
    let encoded = context.encode();
    assert_eq!(encoded.len(), KEY_ENVELOPE_CONTEXT_BYTES_V1);
    assert_eq!(&encoded[0..2], &KEY_RECORD_VERSION_V1.to_be_bytes());
    assert_eq!(&encoded[2..6], &[1, 2, 3, 4]);
    assert_eq!(&encoded[6..38], &[0x11; 32]);
    assert_eq!(&encoded[38..46], &0x0102_0304_0506_0708i64.to_be_bytes());
    assert_eq!(&encoded[46..54], &0x1112_1314_1516_1718i64.to_be_bytes());
    assert_eq!(KeyEnvelopeContextV1::decode(&encoded).unwrap(), context);

    let wrap_aad = canonical_dek_wrap_aad_v1(&context);
    assert_eq!(wrap_aad.len(), DEK_WRAP_AAD_BYTES_V1);
    assert_eq!(
        &wrap_aad[..DEK_WRAP_AAD_DOMAIN_V1.len()],
        DEK_WRAP_AAD_DOMAIN_V1
    );
    assert_eq!(&wrap_aad[DEK_WRAP_AAD_DOMAIN_V1.len()..], &encoded);

    let seal_aad = canonical_seal_binding_aad_v1(&context);
    assert_eq!(seal_aad.len(), SEAL_BINDING_AAD_BYTES_V1);
    assert_eq!(
        &seal_aad[..SEAL_BINDING_AAD_DOMAIN_V1.len()],
        SEAL_BINDING_AAD_DOMAIN_V1
    );
    assert_eq!(&seal_aad[SEAL_BINDING_AAD_DOMAIN_V1.len()..], &encoded);
    assert_ne!(wrap_aad.as_slice(), seal_aad.as_slice());
}

#[test]
fn context_rejects_every_length_and_invalid_version_or_time() {
    let canonical = context().encode();
    for boundary in 0..KEY_ENVELOPE_CONTEXT_BYTES_V1 {
        assert_eq!(
            KeyEnvelopeContextV1::decode(&canonical[..boundary]),
            Err(KeyEnvelopeErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert_eq!(
        KeyEnvelopeContextV1::decode(&trailing),
        Err(KeyEnvelopeErrorV1::InvalidEncodedLength)
    );

    let mut wrong_record_version = canonical;
    wrong_record_version[0..2].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        KeyEnvelopeContextV1::decode(&wrong_record_version),
        Err(KeyEnvelopeErrorV1::UnsupportedRecordVersion)
    );
    let mut zero_root_version = canonical;
    zero_root_version[2..6].fill(0);
    assert_eq!(
        KeyEnvelopeContextV1::decode(&zero_root_version),
        Err(KeyEnvelopeErrorV1::InvalidRootKeyVersion)
    );
    assert_eq!(
        KeyEnvelopeContextV1::new(version(1), result(1), 10, 10),
        Err(KeyEnvelopeErrorV1::InvalidTimeRange)
    );
    assert_eq!(
        KeyEnvelopeContextV1::new(version(1), result(1), 11, 10),
        Err(KeyEnvelopeErrorV1::InvalidTimeRange)
    );
}

#[test]
fn seal_binding_codec_and_count_bounds_are_exact() {
    let binding = binding();
    let encoded = binding.encode();
    assert_eq!(encoded.len(), SEAL_BINDING_BYTES_V1);
    assert_eq!(&encoded[0..32], &[0x44; 32]);
    assert_eq!(&encoded[32..64], &[0x55; 32]);
    assert_eq!(&encoded[64..72], &5_000u64.to_be_bytes());
    assert_eq!(&encoded[72..80], &2u64.to_be_bytes());
    assert_eq!(SealBindingV1::decode(&encoded).unwrap(), binding);

    for boundary in 0..SEAL_BINDING_BYTES_V1 {
        assert_eq!(
            SealBindingV1::decode(&encoded[..boundary]),
            Err(KeyEnvelopeErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        SealBindingV1::decode(&trailing),
        Err(KeyEnvelopeErrorV1::InvalidEncodedLength)
    );

    let manifest = ManifestCommitmentV1::from_bytes([1; 32]);
    let frame = FrameCommitmentV1::from_bytes([2; 32]);
    assert_eq!(
        SealBindingV1::new(manifest, frame, 0, 1),
        Err(KeyEnvelopeErrorV1::InvalidTotalFrameCount)
    );
    assert_eq!(
        SealBindingV1::new(manifest, frame, MAX_TOTAL_FRAMES_PER_RESULT_V1 + 1, 1),
        Err(KeyEnvelopeErrorV1::InvalidTotalFrameCount)
    );
    assert_eq!(
        SealBindingV1::new(manifest, frame, 1, 0),
        Err(KeyEnvelopeErrorV1::InvalidSegmentCount)
    );
    assert_eq!(
        SealBindingV1::new(manifest, frame, 1, MAX_SEGMENTS_PER_RESULT_V1 + 1),
        Err(KeyEnvelopeErrorV1::InvalidSegmentCount)
    );
    assert_eq!(
        SealBindingV1::new(manifest, frame, 1, 2),
        Err(KeyEnvelopeErrorV1::InvalidCountRelation)
    );
    assert_eq!(
        SealBindingV1::new(manifest, frame, 4_097, 1),
        Err(KeyEnvelopeErrorV1::InvalidCountRelation)
    );
    SealBindingV1::new(
        manifest,
        frame,
        MAX_TOTAL_FRAMES_PER_RESULT_V1,
        MAX_SEGMENTS_PER_RESULT_V1,
    )
    .unwrap();
}

#[test]
fn independent_libsodium_vectors_freeze_wrap_and_seal_objects() {
    // Independently frozen with PyNaCl 1.6.2/libsodium using the exact HKDF
    // vectors and canonical context/AAD asserted in this test module.
    let keys = derived_keys(0);
    let dek =
        evidentrail_snapshot_format::ResultDekV1::from_test_bytes([0x33; RESULT_DEK_BYTES_V1])
            .unwrap();
    let wrapped = wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &context(),
        DekWrapNonceV1::from_bytes([0x22; 24]),
        &dek,
    )
    .unwrap();
    assert_eq!(
        wrapped.encode(),
        hex_array::<WRAPPED_RESULT_DEK_BYTES_V1>(
            "222222222222222222222222222222222222222222222222\
             2f3c784e714bf72a4b7fe66615ddcacd241f8034cc6cb03447f0907923e8de25\
             2ddf1cdf3b7e4c2df7164b4d7fbb1111"
                .replace(char::is_whitespace, "")
                .as_str()
        )
    );

    let sealed = seal_binding_v1(
        &keys.seal_key(),
        &context(),
        SealBindingNonceV1::from_bytes([0x66; 24]),
        &binding(),
    )
    .unwrap();
    assert_eq!(
        sealed.encode(),
        hex_array::<SEALED_SEAL_BINDING_BYTES_V1>(
            "666666666666666666666666666666666666666666666666\
             372ddb2b0a1b78d634fb8b96b785b82da50c0117b47dd948876fb876f4bfa7b4\
             f191e8fe20bdd56c8d4af623151be63b55b875e6afe8972c6e11d54306ce033d\
             9ce10d03c7308491e23db9644e9b2ab3d05beabe79de88272750922c741129e7"
                .replace(char::is_whitespace, "")
                .as_str()
        )
    );
}

#[test]
fn wrapped_dek_round_trip_is_exact_and_context_bound() {
    let keys = derived_keys(0);
    let dek =
        evidentrail_snapshot_format::ResultDekV1::from_test_bytes([0xa5; RESULT_DEK_BYTES_V1])
            .unwrap();
    let wrapped = wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &context(),
        DekWrapNonceV1::from_bytes([0x31; 24]),
        &dek,
    )
    .unwrap();
    let opened = open_wrapped_result_dek_v1(&keys.dek_wrap_key(), &context(), &wrapped).unwrap();

    let manifest_header = ManifestHeaderV1::new(
        1,
        result(0x11),
        0,
        100,
        200,
        5,
        ManifestNonceV1::from_bytes([0x71; 24]),
    )
    .unwrap();
    let original_ciphertext =
        seal_manifest_v1(&dek.manifest_key(), manifest_header, b"\0\xffabc").unwrap();
    let opened_ciphertext =
        seal_manifest_v1(&opened.manifest_key(), manifest_header, b"\0\xffabc").unwrap();
    assert_eq!(original_ciphertext.encode(), opened_ciphertext.encode());

    let wrong_key = derived_keys(1);
    assert_eq!(
        open_wrapped_result_dek_v1(&wrong_key.dek_wrap_key(), &context(), &wrapped).unwrap_err(),
        KeyEnvelopeErrorV1::AuthenticationFailed
    );
    for wrong_context in [
        KeyEnvelopeContextV1::new(version(0x0102_0305), result(0x11), 1, 2).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x12), 1, 2).unwrap(),
    ] {
        assert_eq!(
            open_wrapped_result_dek_v1(&keys.dek_wrap_key(), &wrong_context, &wrapped).unwrap_err(),
            KeyEnvelopeErrorV1::KeyContextMismatch
        );
        assert_eq!(
            wrap_result_dek_v1(
                &keys.dek_wrap_key(),
                &wrong_context,
                DekWrapNonceV1::from_bytes([0x31; 24]),
                &dek,
            )
            .unwrap_err(),
            KeyEnvelopeErrorV1::KeyContextMismatch
        );
    }
    for wrong_time in [
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 2, 3).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 1, 3).unwrap(),
    ] {
        assert_eq!(
            open_wrapped_result_dek_v1(&keys.dek_wrap_key(), &wrong_time, &wrapped).unwrap_err(),
            KeyEnvelopeErrorV1::AuthenticationFailed
        );
    }
}

#[test]
fn wrapped_dek_rejects_every_truncation_trailing_byte_and_mutation() {
    let keys = derived_keys(0);
    let dek =
        evidentrail_snapshot_format::ResultDekV1::from_test_bytes([0x99; RESULT_DEK_BYTES_V1])
            .unwrap();
    let wrapped = wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &context(),
        DekWrapNonceV1::from_bytes([0x41; 24]),
        &dek,
    )
    .unwrap();
    let canonical = wrapped.encode();
    for boundary in 0..WRAPPED_RESULT_DEK_BYTES_V1 {
        assert_eq!(
            WrappedResultDekV1::decode(&canonical[..boundary]),
            Err(KeyEnvelopeErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert_eq!(
        WrappedResultDekV1::decode(&trailing),
        Err(KeyEnvelopeErrorV1::InvalidEncodedLength)
    );
    for index in 0..WRAPPED_RESULT_DEK_BYTES_V1 {
        let mut mutated = canonical;
        mutated[index] ^= 1;
        let mutated = WrappedResultDekV1::decode(&mutated).unwrap();
        assert_eq!(
            open_wrapped_result_dek_v1(&keys.dek_wrap_key(), &context(), &mutated).unwrap_err(),
            KeyEnvelopeErrorV1::AuthenticationFailed,
            "index {index}"
        );
    }
}

#[test]
fn seal_binding_round_trip_is_typed_exact_and_context_bound() {
    let keys = derived_keys(0);
    let sealed = seal_binding_v1(
        &keys.seal_key(),
        &context(),
        SealBindingNonceV1::from_bytes([0x51; 24]),
        &binding(),
    )
    .unwrap();
    let opened = open_seal_binding_v1(&keys.seal_key(), &context(), &sealed).unwrap();
    assert_eq!(
        opened.manifest_commitment(),
        binding().manifest_commitment()
    );
    assert_eq!(
        opened.final_frame_commitment(),
        binding().final_frame_commitment()
    );
    assert_eq!(opened.total_frame_count(), 5_000);
    assert_eq!(opened.segment_count(), 2);

    let wrong_key = derived_keys(1);
    assert_eq!(
        open_seal_binding_v1(&wrong_key.seal_key(), &context(), &sealed).unwrap_err(),
        KeyEnvelopeErrorV1::AuthenticationFailed
    );
    for wrong_context in [
        KeyEnvelopeContextV1::new(version(0x0102_0305), result(0x11), 1, 2).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x12), 1, 2).unwrap(),
    ] {
        assert_eq!(
            open_seal_binding_v1(&keys.seal_key(), &wrong_context, &sealed).unwrap_err(),
            KeyEnvelopeErrorV1::KeyContextMismatch
        );
        assert_eq!(
            seal_binding_v1(
                &keys.seal_key(),
                &wrong_context,
                SealBindingNonceV1::from_bytes([0x51; 24]),
                &binding(),
            )
            .unwrap_err(),
            KeyEnvelopeErrorV1::KeyContextMismatch
        );
    }
    for wrong_time in [
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 2, 3).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 1, 3).unwrap(),
    ] {
        assert_eq!(
            open_seal_binding_v1(&keys.seal_key(), &wrong_time, &sealed).unwrap_err(),
            KeyEnvelopeErrorV1::AuthenticationFailed
        );
    }
}

#[test]
fn sealed_binding_rejects_every_truncation_trailing_byte_and_mutation() {
    let keys = derived_keys(0);
    let sealed = seal_binding_v1(
        &keys.seal_key(),
        &context(),
        SealBindingNonceV1::from_bytes([0x61; 24]),
        &binding(),
    )
    .unwrap();
    let canonical = sealed.encode();
    for boundary in 0..SEALED_SEAL_BINDING_BYTES_V1 {
        assert_eq!(
            SealedSealBindingV1::decode(&canonical[..boundary]),
            Err(KeyEnvelopeErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert_eq!(
        SealedSealBindingV1::decode(&trailing),
        Err(KeyEnvelopeErrorV1::InvalidEncodedLength)
    );
    for index in 0..SEALED_SEAL_BINDING_BYTES_V1 {
        let mut mutated = canonical;
        mutated[index] ^= 1;
        let mutated = SealedSealBindingV1::decode(&mutated).unwrap();
        assert_eq!(
            open_seal_binding_v1(&keys.seal_key(), &context(), &mutated).unwrap_err(),
            KeyEnvelopeErrorV1::AuthenticationFailed,
            "index {index}"
        );
    }
}

#[test]
fn envelope_debug_and_errors_expose_no_context_key_dek_nonce_or_binding_canaries() {
    let secret_context = KeyEnvelopeContextV1::new(version(1), result(b'R'), 1, 2).unwrap();
    let keys = derived_keys_for(0, result(b'R'), version(1));
    let dek =
        evidentrail_snapshot_format::ResultDekV1::from_test_bytes([b'D'; RESULT_DEK_BYTES_V1])
            .unwrap();
    let wrapped = wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &secret_context,
        DekWrapNonceV1::from_bytes([b'N'; 24]),
        &dek,
    )
    .unwrap();
    let secret_binding = SealBindingV1::new(
        ManifestCommitmentV1::from_bytes([b'M'; 32]),
        FrameCommitmentV1::from_bytes([b'F'; 32]),
        1,
        1,
    )
    .unwrap();
    let sealed = seal_binding_v1(
        &keys.seal_key(),
        &secret_context,
        SealBindingNonceV1::from_bytes([b'S'; 24]),
        &secret_binding,
    )
    .unwrap();
    let opened = open_seal_binding_v1(&keys.seal_key(), &secret_context, &sealed).unwrap();
    let rendered = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        secret_context,
        wrapped.nonce(),
        wrapped,
        secret_binding,
        sealed.nonce(),
        sealed,
        opened,
        KeyEnvelopeErrorV1::AuthenticationFailed,
    );
    for canary in ["RRRR", "NNNN", "DDDD", "MMMM", "FFFF", "SSSS"] {
        assert!(!rendered.contains(canary));
    }
}
