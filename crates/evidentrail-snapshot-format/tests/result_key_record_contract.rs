use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    DEK_WRAP_AAD_DOMAIN_V1, DekWrapNonceV1, DerivedResultKeysV1, FrameCommitmentV1,
    KEY_RECORD_VERSION_V1, KeyEnvelopeContextV1, MAX_SEGMENTS_PER_RESULT_V1, ManifestCommitmentV1,
    RESULT_DEK_BYTES_V1, RESULT_KEY_RECORD_BYTES_V1, RESULT_KEY_RECORD_CREATING_STATE_V1,
    RESULT_KEY_RECORD_SEALED_STATE_V1, ResultDekV1, ResultKeyRecordErrorV1, ResultKeyRecordStateV1,
    ResultKeyRecordV1, ResultKeySealTransitionV1, RootKekV1, RootKeyVersionV1,
    SEALED_SEAL_BINDING_BYTES_V1, SealBindingNonceV1, SealBindingV1, SealedSealBindingV1,
    WRAPPED_RESULT_DEK_BYTES_V1, WrappedResultDekV1, XCHACHA20_POLY1305_SUITE_ID_V1,
    seal_binding_v1, wrap_result_dek_v1,
};
use sha2::{Digest, Sha256};
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

fn keys() -> DerivedResultKeysV1 {
    derived_keys_for(0, result(0x11), version(0x0102_0304))
}

fn binding(frame_count: u64, segment_count: u64) -> SealBindingV1 {
    SealBindingV1::new(
        ManifestCommitmentV1::from_bytes([0x44; 32]),
        FrameCommitmentV1::from_bytes([0x55; 32]),
        frame_count,
        segment_count,
    )
    .unwrap()
}

fn wrapped(keys: &DerivedResultKeysV1, nonce: u8) -> WrappedResultDekV1 {
    let dek = ResultDekV1::from_test_bytes([0x33; RESULT_DEK_BYTES_V1]).unwrap();
    wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &context(),
        DekWrapNonceV1::from_bytes([nonce; 24]),
        &dek,
    )
    .unwrap()
}

fn sealed(keys: &DerivedResultKeysV1, nonce: u8) -> SealedSealBindingV1 {
    seal_binding_v1(
        &keys.seal_key(),
        &context(),
        SealBindingNonceV1::from_bytes([nonce; 24]),
        &binding(5_000, 2),
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

fn golden_wrapped() -> WrappedResultDekV1 {
    WrappedResultDekV1::decode(&hex_array::<WRAPPED_RESULT_DEK_BYTES_V1>(
        &"222222222222222222222222222222222222222222222222\
         bddcfea292e96eb326dda3441b4d792729ccf6af82c8a6ba348e38a1bb924419\
         c65843727d5c9b805202a65962a0a82a"
            .replace(char::is_whitespace, ""),
    ))
    .unwrap()
}

fn golden_sealed() -> SealedSealBindingV1 {
    SealedSealBindingV1::decode(&hex_array::<SEALED_SEAL_BINDING_BYTES_V1>(
        &"666666666666666666666666666666666666666666666666\
         c8c99e9053675b60f6158676b1dd3a355eafe44938226c06c0e5ac8445fd3e16\
         a8398c54793cf54319865278bf165b7840e3bd2858ad640061ea05b94b16cb6b\
         87038724ca57112c42ee1fc58d7f2a0e5574adf8a5d4755f78d5aa517688cb03"
            .replace(char::is_whitespace, ""),
    ))
    .unwrap()
}

#[test]
fn creating_record_layout_is_exact_and_seal_padding_is_canonical_zero() {
    let keys = keys();
    let record =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), golden_wrapped()).unwrap();
    assert_eq!(record.state(), ResultKeyRecordStateV1::Creating);
    assert!(record.sealed_binding().is_none());

    let encoded = record.encode();
    assert_eq!(encoded.len(), RESULT_KEY_RECORD_BYTES_V1);
    assert_eq!(&encoded[0..8], b"EVRKEY01");
    assert_eq!(&encoded[8..10], &KEY_RECORD_VERSION_V1.to_be_bytes());
    assert_eq!(
        &encoded[10..12],
        &XCHACHA20_POLY1305_SUITE_ID_V1.to_be_bytes()
    );
    assert_eq!(&encoded[12..16], &[1, 2, 3, 4]);
    assert_eq!(&encoded[16..48], &[0x11; 32]);
    assert_eq!(&encoded[48..56], &0x0102_0304_0506_0708i64.to_be_bytes());
    assert_eq!(&encoded[56..64], &0x1112_1314_1516_1718i64.to_be_bytes());
    assert_eq!(&encoded[64..66], &72u16.to_be_bytes());
    assert_eq!(
        &encoded[66..68],
        &RESULT_KEY_RECORD_CREATING_STATE_V1.to_be_bytes()
    );
    assert_eq!(&encoded[68..70], &[0; 2]);
    assert_eq!(&encoded[70..72], &[0; 2]);
    assert_eq!(&encoded[72..144], &golden_wrapped().encode());
    assert!(encoded[144..].iter().all(|byte| *byte == 0));

    let decoded = ResultKeyRecordV1::decode(&context(), &encoded).unwrap();
    assert_eq!(decoded.state(), ResultKeyRecordStateV1::Creating);
    assert_eq!(decoded.encode(), encoded);
    decoded.open_result_dek(&keys.dek_wrap_key()).unwrap();
    assert!(
        decoded
            .open_sealed_binding(&keys.seal_key())
            .unwrap()
            .is_none()
    );
}

#[test]
fn sealed_record_has_an_independently_reconstructed_golden_encoding_and_digest() {
    let keys = keys();
    let mut record =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), golden_wrapped()).unwrap();
    assert_eq!(
        record
            .transition_to_sealed(&keys.dek_wrap_key(), &keys.seal_key(), golden_sealed())
            .unwrap(),
        ResultKeySealTransitionV1::Applied
    );

    let mut expected = [0u8; RESULT_KEY_RECORD_BYTES_V1];
    expected[0..8].copy_from_slice(b"EVRKEY01");
    expected[8..10].copy_from_slice(&1u16.to_be_bytes());
    expected[10..12].copy_from_slice(&1u16.to_be_bytes());
    expected[12..16].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    expected[16..48].copy_from_slice(&[0x11; 32]);
    expected[48..56].copy_from_slice(&0x0102_0304_0506_0708i64.to_be_bytes());
    expected[56..64].copy_from_slice(&0x1112_1314_1516_1718i64.to_be_bytes());
    expected[64..66].copy_from_slice(&72u16.to_be_bytes());
    expected[66..68].copy_from_slice(&2u16.to_be_bytes());
    expected[68..70].copy_from_slice(&120u16.to_be_bytes());
    expected[72..144].copy_from_slice(&golden_wrapped().encode());
    expected[144..264].copy_from_slice(&golden_sealed().encode());
    assert_eq!(record.encode(), expected);

    // Independently reconstructed with Python bytearray + hashlib.sha256 from
    // the two previously independent libsodium envelope vectors.
    let digest: [u8; 32] = Sha256::digest(expected).into();
    assert_eq!(
        digest,
        hex_array("7ac080a20f6930562bcb0afb60bdf29b547ae936f1f70467dc6c722a1bb76a36")
    );

    let decoded = ResultKeyRecordV1::decode(&context(), &expected).unwrap();
    assert_eq!(decoded.state(), ResultKeyRecordStateV1::Sealed);
    let opened = decoded
        .open_sealed_binding(&keys.seal_key())
        .unwrap()
        .unwrap();
    assert_eq!(opened.total_frame_count(), 5_000);
    assert_eq!(opened.segment_count(), 2);
}

#[test]
fn decoder_rejects_every_truncation_and_trailing_data() {
    let keys = keys();
    let canonical =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), wrapped(&keys, 0x31))
            .unwrap()
            .encode();
    for boundary in 0..RESULT_KEY_RECORD_BYTES_V1 {
        assert!(matches!(
            ResultKeyRecordV1::decode(&context(), &canonical[..boundary]),
            Err(ResultKeyRecordErrorV1::InvalidEncodedLength)
        ));
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert!(matches!(
        ResultKeyRecordV1::decode(&context(), &trailing),
        Err(ResultKeyRecordErrorV1::InvalidEncodedLength)
    ));
}

#[test]
fn every_fixed_header_and_context_class_fails_closed() {
    let keys = keys();
    let canonical =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), wrapped(&keys, 0x32))
            .unwrap()
            .encode();

    let mut mutation = canonical;
    mutation[0] ^= 1;
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::InvalidMagic);
    let mut mutation = canonical;
    mutation[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::UnsupportedRecordVersion);
    let mut mutation = canonical;
    mutation[10..12].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::UnsupportedSuite);
    let mut mutation = canonical;
    mutation[12..16].fill(0);
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::InvalidRootKeyVersion);
    let mut mutation = canonical;
    mutation[16] ^= 1;
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::ContextMismatch);
    let mut mutation = canonical;
    mutation[56..64].copy_from_slice(&0x0102_0304_0506_0708i64.to_be_bytes());
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::InvalidTimeRange);
    let mut mutation = canonical;
    mutation[64..66].copy_from_slice(&71u16.to_be_bytes());
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::InvalidWrappedDekLength);
    let mut mutation = canonical;
    mutation[66..68].copy_from_slice(&3u16.to_be_bytes());
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::UnknownState);
    let mut mutation = canonical;
    mutation[70] = 1;
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::NonzeroReserved);
    let mut mutation = canonical;
    mutation[279] = 1;
    assert_decode_error(&mutation, ResultKeyRecordErrorV1::NonzeroReserved);

    for wrong_context in [
        KeyEnvelopeContextV1::new(version(0x0102_0305), result(0x11), 1, 2).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x12), 1, 2).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 2, 3).unwrap(),
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x11), 1, 3).unwrap(),
    ] {
        assert!(matches!(
            ResultKeyRecordV1::decode(&wrong_context, &canonical),
            Err(ResultKeyRecordErrorV1::ContextMismatch)
        ));
    }
}

#[test]
fn creating_and_sealed_state_layouts_are_mutually_exclusive_and_canonical() {
    let keys = keys();
    let creating =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), wrapped(&keys, 0x33))
            .unwrap()
            .encode();

    let mut creating_with_length = creating;
    creating_with_length[68..70].copy_from_slice(&120u16.to_be_bytes());
    assert_decode_error(
        &creating_with_length,
        ResultKeyRecordErrorV1::NoncanonicalCreatingLayout,
    );
    let mut creating_with_seal_bytes = creating;
    creating_with_seal_bytes[144] = 1;
    assert_decode_error(
        &creating_with_seal_bytes,
        ResultKeyRecordErrorV1::NoncanonicalCreatingLayout,
    );

    let mut sealed_without_length = creating;
    sealed_without_length[66..68].copy_from_slice(&RESULT_KEY_RECORD_SEALED_STATE_V1.to_be_bytes());
    assert_decode_error(
        &sealed_without_length,
        ResultKeyRecordErrorV1::InvalidSealedBindingLength,
    );
    let mut sealed_zero_binding = sealed_without_length;
    sealed_zero_binding[68..70].copy_from_slice(&120u16.to_be_bytes());
    assert_decode_error(
        &sealed_zero_binding,
        ResultKeyRecordErrorV1::NoncanonicalSealedLayout,
    );
    let mut sealed_wrong_length = sealed_zero_binding;
    sealed_wrong_length[68..70].copy_from_slice(&119u16.to_be_bytes());
    assert_decode_error(
        &sealed_wrong_length,
        ResultKeyRecordErrorV1::InvalidSealedBindingLength,
    );
}

#[test]
fn ciphertext_mutation_is_structural_but_never_authenticates() {
    let keys = keys();
    let mut record =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), wrapped(&keys, 0x34))
            .unwrap();
    record
        .transition_to_sealed(&keys.dek_wrap_key(), &keys.seal_key(), sealed(&keys, 0x35))
        .unwrap();
    let canonical = record.encode();

    let mut wrapped_mutation = canonical;
    wrapped_mutation[72 + 31] ^= 1;
    let decoded = ResultKeyRecordV1::decode(&context(), &wrapped_mutation).unwrap();
    assert!(matches!(
        decoded.open_result_dek(&keys.dek_wrap_key()),
        Err(ResultKeyRecordErrorV1::WrappedDekAuthenticationFailed)
    ));
    let mut decoded = decoded;
    let before = decoded.encode();
    assert_eq!(
        decoded
            .transition_to_sealed(&keys.dek_wrap_key(), &keys.seal_key(), sealed(&keys, 0x36),)
            .unwrap_err(),
        ResultKeyRecordErrorV1::WrappedDekAuthenticationFailed
    );
    assert_eq!(decoded.encode(), before);

    let mut sealed_mutation = canonical;
    sealed_mutation[144 + 47] ^= 1;
    let decoded = ResultKeyRecordV1::decode(&context(), &sealed_mutation).unwrap();
    assert!(matches!(
        decoded.open_sealed_binding(&keys.seal_key()),
        Err(ResultKeyRecordErrorV1::SealedBindingAuthenticationFailed)
    ));
}

#[test]
fn creating_constructor_authenticates_wrapped_dek_and_context() {
    let keys = keys();
    let canonical = wrapped(&keys, 0x36).encode();
    let mut corrupted = canonical;
    corrupted[30] ^= 1;
    assert!(matches!(
        ResultKeyRecordV1::new_creating(
            context(),
            &keys.dek_wrap_key(),
            WrappedResultDekV1::decode(&corrupted).unwrap(),
        ),
        Err(ResultKeyRecordErrorV1::WrappedDekAuthenticationFailed)
    ));

    let wrong_root = derived_keys_for(1, result(0x11), version(0x0102_0304));
    assert!(matches!(
        ResultKeyRecordV1::new_creating(
            context(),
            &wrong_root.dek_wrap_key(),
            WrappedResultDekV1::decode(&canonical).unwrap(),
        ),
        Err(ResultKeyRecordErrorV1::WrappedDekAuthenticationFailed)
    ));

    let wrong_context =
        KeyEnvelopeContextV1::new(version(0x0102_0304), result(0x12), 1, 2).unwrap();
    assert!(matches!(
        ResultKeyRecordV1::new_creating(
            wrong_context,
            &keys.dek_wrap_key(),
            WrappedResultDekV1::decode(&canonical).unwrap(),
        ),
        Err(ResultKeyRecordErrorV1::ContextMismatch)
    ));
}

#[test]
fn seal_transition_is_atomic_exactly_once_and_explicitly_idempotent() {
    let keys = keys();
    let mut record =
        ResultKeyRecordV1::new_creating(context(), &keys.dek_wrap_key(), wrapped(&keys, 0x37))
            .unwrap();
    let creating_bytes = record.encode();

    let mut corrupt = sealed(&keys, 0x38).encode();
    corrupt[41] ^= 1;
    assert_eq!(
        record
            .transition_to_sealed(
                &keys.dek_wrap_key(),
                &keys.seal_key(),
                SealedSealBindingV1::decode(&corrupt).unwrap(),
            )
            .unwrap_err(),
        ResultKeyRecordErrorV1::SealedBindingAuthenticationFailed
    );
    assert_eq!(record.encode(), creating_bytes);

    let first = sealed(&keys, 0x38);
    let first_bytes = first.encode();
    assert_eq!(
        record
            .transition_to_sealed(&keys.dek_wrap_key(), &keys.seal_key(), first)
            .unwrap(),
        ResultKeySealTransitionV1::Applied
    );
    let sealed_record_bytes = record.encode();
    assert_eq!(&sealed_record_bytes[72..144], &creating_bytes[72..144]);

    assert_eq!(
        record
            .transition_to_sealed(
                &keys.dek_wrap_key(),
                &keys.seal_key(),
                SealedSealBindingV1::decode(&first_bytes).unwrap(),
            )
            .unwrap(),
        ResultKeySealTransitionV1::AlreadySealedSame
    );
    assert_eq!(record.encode(), sealed_record_bytes);

    // The same semantic binding under a fresh nonce is a different immutable
    // seal object and cannot replace the first one.
    assert_eq!(
        record
            .transition_to_sealed(&keys.dek_wrap_key(), &keys.seal_key(), sealed(&keys, 0x39),)
            .unwrap_err(),
        ResultKeyRecordErrorV1::DifferentSecondSeal
    );
    assert_eq!(record.encode(), sealed_record_bytes);
}

#[test]
fn record_state_debug_and_errors_are_contentless() {
    let secret_context = KeyEnvelopeContextV1::new(version(7), result(b'R'), 1, 2).unwrap();
    let keys = derived_keys_for(0, result(b'R'), version(7));
    let dek = ResultDekV1::from_test_bytes([b'D'; RESULT_DEK_BYTES_V1]).unwrap();
    let wrapped = wrap_result_dek_v1(
        &keys.dek_wrap_key(),
        &secret_context,
        DekWrapNonceV1::from_bytes([b'N'; 24]),
        &dek,
    )
    .unwrap();
    let record =
        ResultKeyRecordV1::new_creating(secret_context, &keys.dek_wrap_key(), wrapped).unwrap();
    let rendered = format!(
        "{record:?} {:?} {:?} {:?} {}",
        record.state(),
        ResultKeySealTransitionV1::AlreadySealedSame,
        ResultKeyRecordErrorV1::DifferentSecondSeal,
        DEK_WRAP_AAD_DOMAIN_V1.len(),
    );
    for canary in ["RRRR", "DDDD", "NNNN"] {
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn storage_count_bounds_remain_linked_to_the_envelope_contract() {
    assert_eq!(MAX_SEGMENTS_PER_RESULT_V1, 4_096);
    assert_eq!(
        evidentrail_snapshot_format::MAX_TOTAL_FRAMES_PER_RESULT_V1,
        MAX_SEGMENTS_PER_RESULT_V1 * 4_096
    );
}

fn assert_decode_error(encoded: &[u8], expected: ResultKeyRecordErrorV1) {
    assert!(matches!(
        ResultKeyRecordV1::decode(&context(), encoded),
        Err(actual) if actual == expected
    ));
}
