use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt,
    AcquisitionReceiptId, AdapterIdentity, AdapterOutcome, AttemptCounts, CompletenessProof,
    EventId, ExactnessBasis, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchTiming, PlanDigest, PlanId, PolicyDigest, ResultId, RetrievalId, SourceIdentityDigest,
    SourceRecordId, TransformationReceiptId, UnixTimestampNanos,
};
use evidentrail_snapshot_format::{
    AcquisitionCompletionRecordV1, AuthorizedByteRangeV1, CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1,
    CORE_RESULT_MANIFEST_HEADER_BYTES_V1, CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1,
    CORE_RESULT_MANIFEST_SCHEMA_V1, CORE_RESULT_MANIFEST_VERSION_V1, CoreManifestComponentsV1,
    CoreResultManifestErrorV1, CoreResultManifestSealContextV1, CoreResultManifestV1,
    CoreResultPayloadErrorV1, EventExpansionIndexEntryV1, EventExpansionIndexV1,
    EventFrameLocatorV1, ExpectedCoreResultManifestContextV1, FRAME_HEADER_BYTES_V1,
    FrameCommitmentV1, MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1, MAX_MANIFEST_PLAINTEXT_BYTES_V1,
    ManifestHeaderV1, ManifestNonceV1, RESULT_DEK_BYTES_V1, ResultDekV1, SEGMENT_HEADER_BYTES_V1,
    SealedCoreResultManifestV1, SegmentCatalogEntryV1, SegmentCatalogV1, SegmentDigestV1,
    SourceOutcomeTableV1, derive_core_manifest_components_digest_v1, open_core_result_manifest_v1,
    seal_core_result_manifest_v1, seal_manifest_v1,
};
use sha2::{Digest, Sha256};

const COMPONENTS_DIGEST_OFFSET: usize = 160;
const MANIFEST_DIGEST_OFFSET: usize = 192;
const MANIFEST_DIGEST_END: usize = 224;

fn hex_vec(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex_vec(encoded).try_into().unwrap()
}

fn receipt_id() -> AcquisitionReceiptId {
    // Independently reconstructed with Python hashlib using the ledger V1
    // domain-as-field, u64 little-endian field lengths, ordered entries, and
    // exact conditional post-policy/omission fields.
    AcquisitionReceiptId::from_bytes(hex_array(
        "bfb662cc7bf266518524aeaa6bce9d919eb1b75cc7de78eea3688124d8e01dce",
    ))
}

fn foreign_receipt_id() -> AcquisitionReceiptId {
    AcquisitionReceiptId::from_bytes(hex_array(
        "55dcb7afd8bf844f4e3001bef857c3fa3ac3ddf97f36f7b32f31555c5caf002f",
    ))
}

fn catalog(seed: u8) -> SegmentCatalogV1 {
    let ciphertext_bytes = 16u64;
    let encoded_bytes =
        SEGMENT_HEADER_BYTES_V1 as u64 + FRAME_HEADER_BYTES_V1 as u64 + ciphertext_bytes;
    SegmentCatalogV1::new(vec![
        SegmentCatalogEntryV1::new(
            0,
            0,
            1,
            encoded_bytes,
            ciphertext_bytes,
            SegmentDigestV1::from_bytes([seed; 32]),
            FrameCommitmentV1::from_bytes([seed.wrapping_add(1); 32]),
        )
        .unwrap(),
    ])
    .unwrap()
}

fn receipt(retrieval_id: RetrievalId) -> AcquisitionReceipt {
    let post_policy = ExactnessBasis::PostPolicy {
        policy_digest: PolicyDigest::from_bytes([0x61; 32]),
        transformation_receipt_id: TransformationReceiptId::from_bytes([0x71; 32]),
    };
    AcquisitionReceipt::reconcile(
        retrieval_id,
        [
            SourceRecordId::from_bytes([0x41; 32]),
            SourceRecordId::from_bytes([0x42; 32]),
        ],
        [
            AcquisitionOutcomeAssignment::new(
                SourceRecordId::from_bytes([0x41; 32]),
                AcquisitionOutcome::Persisted {
                    event_id: EventId::from_bytes([0x51; 32]),
                    exactness_basis: post_policy,
                },
            ),
            AcquisitionOutcomeAssignment::new(
                SourceRecordId::from_bytes([0x42; 32]),
                AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes([0x62; 32]),
                },
            ),
        ],
    )
    .unwrap()
}

fn completion(retrieval_id: RetrievalId) -> AcquisitionCompletionRecordV1 {
    let completion = FetchCompletion::new(
        FetchIdentity::new(
            retrieval_id,
            PlanId::from_bytes([0x11; 32]),
            PlanDigest::from_bytes([0x12; 32]),
            AdapterIdentity::new("local_file", "1").unwrap(),
        ),
        FetchTiming::new(UnixTimestampNanos::new(10), UnixTimestampNanos::new(20)),
        AcknowledgedCounts::new(2, 0, 0),
        AttemptCounts::default(),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::FixedSnapshotVerified),
    )
    .unwrap();
    AcquisitionCompletionRecordV1::new(&completion).unwrap()
}

fn bundle_for(retrieval_seed: u8, catalog_seed: u8) -> CoreManifestComponentsV1 {
    let retrieval_id = RetrievalId::from_bytes([retrieval_seed; 32]);
    let catalog = catalog(catalog_seed);
    let post_policy = ExactnessBasis::PostPolicy {
        policy_digest: PolicyDigest::from_bytes([0x61; 32]),
        transformation_receipt_id: TransformationReceiptId::from_bytes([0x71; 32]),
    };
    let index = EventExpansionIndexV1::new(
        &catalog,
        vec![
            EventExpansionIndexEntryV1::new(
                &catalog,
                EventId::from_bytes([0x51; 32]),
                EventFrameLocatorV1::new(0, 0, 0, 120, 108).unwrap(),
                AuthorizedByteRangeV1::new(0, 0).unwrap(),
                post_policy,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let receipt = receipt(retrieval_id);
    let outcomes = SourceOutcomeTableV1::new(&receipt, &index).unwrap();
    let completion = completion(retrieval_id);
    CoreManifestComponentsV1::new(&catalog, &index, &outcomes, &completion).unwrap()
}

fn bundle() -> CoreManifestComponentsV1 {
    bundle_for(0x31, 0x21)
}

fn manifest_for(
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    bundle: &CoreManifestComponentsV1,
) -> CoreResultManifestV1 {
    manifest_for_receipt(result_id, source_identity_digest, receipt_id(), bundle)
}

fn manifest_for_receipt(
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    bundle: &CoreManifestComponentsV1,
) -> CoreResultManifestV1 {
    CoreResultManifestV1::new(
        result_id,
        source_identity_digest,
        acquisition_receipt_id,
        bundle,
    )
    .unwrap()
}

fn manifest() -> CoreResultManifestV1 {
    manifest_for(
        ResultId::from_bytes([0x81; 32]),
        SourceIdentityDigest::from_bytes([0x91; 32]),
        &bundle(),
    )
}

fn key(seed: u8) -> ResultDekV1 {
    ResultDekV1::from_test_bytes([seed; RESULT_DEK_BYTES_V1]).unwrap()
}

fn seal_context(nonce_seed: u8) -> CoreResultManifestSealContextV1 {
    CoreResultManifestSealContextV1::new(
        1_000,
        2_000,
        ManifestNonceV1::from_bytes([nonce_seed; 24]),
    )
    .unwrap()
}

fn expected_context(
    result_id: ResultId,
    source_identity_digest: SourceIdentityDigest,
) -> ExpectedCoreResultManifestContextV1 {
    ExpectedCoreResultManifestContextV1::new(
        result_id,
        source_identity_digest,
        receipt_id(),
        1_000,
        2_000,
    )
    .unwrap()
}

fn sealed_payload() -> (ResultDekV1, SealedCoreResultManifestV1) {
    let key = key(0xa1);
    let manifest = manifest();
    let sealed =
        seal_core_result_manifest_v1(&key.manifest_key(), seal_context(0xb1), &manifest).unwrap();
    (key, sealed)
}

fn recompute_manifest_digest(encoded: &mut [u8]) {
    encoded[MANIFEST_DIGEST_OFFSET..MANIFEST_DIGEST_END].fill(0);
    let mut hasher = Sha256::new();
    hasher.update(CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&*encoded);
    let digest: [u8; 32] = hasher.finalize().into();
    encoded[MANIFEST_DIGEST_OFFSET..MANIFEST_DIGEST_END].copy_from_slice(&digest);
}

#[test]
fn frozen_nontrivial_receipt_and_manifest_golden_are_exact() {
    let manifest = manifest();
    let encoded = manifest.encode();
    let expected_header = hex_vec(concat!(
        "45565243524d3031000100010001010000000001000100000000074b00000100",
        "0000064b00000000000000000000000000000000000000000000000000000000",
        "8181818181818181818181818181818181818181818181818181818181818181",
        "9191919191919191919191919191919191919191919191919191919191919191",
        "bfb662cc7bf266518524aeaa6bce9d919eb1b75cc7de78eea3688124d8e01dce",
        "10c61150c3bb3c0524140ed1280f4e3b3f94de199e66f724d93a4f2ff16c028f",
        "585fb7c5d0d28b6e5cafb3eea9c109594bafb1499c0b3fd7dabe8bb5b3397285",
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));
    assert_eq!(expected_header.len(), CORE_RESULT_MANIFEST_HEADER_BYTES_V1);
    assert_eq!(
        &encoded[..CORE_RESULT_MANIFEST_HEADER_BYTES_V1],
        expected_header
    );
    assert_eq!(encoded.len(), 1_867);
    assert_eq!(manifest.encoded_len(), encoded.len());
    assert_eq!(
        manifest.components_digest().as_bytes(),
        &hex_array::<32>("10c61150c3bb3c0524140ed1280f4e3b3f94de199e66f724d93a4f2ff16c028f")
    );
    assert_eq!(
        manifest.manifest_digest().as_bytes(),
        &hex_array::<32>("585fb7c5d0d28b6e5cafb3eea9c109594bafb1499c0b3fd7dabe8bb5b3397285")
    );
    assert_eq!(manifest.acquisition_receipt_id(), receipt_id());
    assert_eq!(manifest.version(), CORE_RESULT_MANIFEST_VERSION_V1);
    assert_eq!(manifest.schema(), CORE_RESULT_MANIFEST_SCHEMA_V1);
    assert_eq!(
        manifest.components_digest(),
        derive_core_manifest_components_digest_v1(&encoded[CORE_RESULT_MANIFEST_HEADER_BYTES_V1..])
    );
    assert_eq!(
        CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1,
        b"evidentrail.snapshot.core-result-manifest.v1"
    );
}

#[test]
fn decode_is_self_restoring_and_exact() {
    let encoded = manifest().encode();
    let restored = CoreResultManifestV1::decode(&encoded).unwrap();
    assert_eq!(restored.encode(), encoded);
    assert_eq!(restored.encoded_len(), encoded.len());
    assert_eq!(restored.result_id(), ResultId::from_bytes([0x81; 32]));
    assert_eq!(
        restored.source_identity_digest(),
        SourceIdentityDigest::from_bytes([0x91; 32])
    );
    assert_eq!(restored.acquisition_receipt_id(), receipt_id());
    let reconstructed = restored.to_acquisition_receipt().unwrap();
    assert_eq!(
        reconstructed.retrieval_id(),
        RetrievalId::from_bytes([0x31; 32])
    );
    assert_eq!(reconstructed.acknowledged_count(), 2);
    assert_eq!(reconstructed.entries()[0].outcome().code(), "post_policy");
    assert_eq!(
        reconstructed.entries()[1].outcome().code(),
        "omitted_by_policy"
    );
}

#[test]
fn construction_rejects_receipt_identity_drift_and_preserves_zero_authority_domains() {
    let bundle = bundle();
    assert_eq!(
        CoreResultManifestV1::new(
            ResultId::from_bytes([0; 32]),
            SourceIdentityDigest::from_bytes([0; 32]),
            AcquisitionReceiptId::from_bytes([0; 32]),
            &bundle,
        ),
        Err(CoreResultManifestErrorV1::AcquisitionReceiptIdMismatch)
    );
    let admitted = CoreResultManifestV1::new(
        ResultId::from_bytes([0; 32]),
        SourceIdentityDigest::from_bytes([0; 32]),
        receipt_id(),
        &bundle,
    )
    .unwrap();
    let restored = CoreResultManifestV1::decode(&admitted.encode()).unwrap();
    assert_eq!(restored.result_id().as_bytes(), &[0; 32]);
    assert_eq!(restored.source_identity_digest().as_bytes(), &[0; 32]);
}

#[test]
fn every_truncation_boundary_and_trailing_data_fail() {
    let encoded = manifest().encode();
    for boundary in 0..encoded.len() {
        assert!(CoreResultManifestV1::decode(&encoded[..boundary]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        CoreResultManifestV1::decode(&trailing),
        Err(CoreResultManifestErrorV1::InvalidEncodedLength)
    );
}

#[test]
fn fixed_header_fields_and_every_reserved_byte_are_strict() {
    let encoded = manifest().encode();
    for (offset, expected) in [
        (0, CoreResultManifestErrorV1::InvalidMagic),
        (9, CoreResultManifestErrorV1::UnsupportedVersion),
        (11, CoreResultManifestErrorV1::UnsupportedSchema),
        (13, CoreResultManifestErrorV1::UnsupportedObjectKind),
        (15, CoreResultManifestErrorV1::InvalidHeaderWidth),
        (17, CoreResultManifestErrorV1::NonzeroFlags),
        (19, CoreResultManifestErrorV1::ComponentsVersionMismatch),
        (21, CoreResultManifestErrorV1::ComponentsSchemaMismatch),
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert_eq!(CoreResultManifestV1::decode(&mutated), Err(expected));
    }
    for offset in (22..24).chain(36..64).chain(224..256) {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            CoreResultManifestV1::decode(&mutated),
            Err(CoreResultManifestErrorV1::NonzeroReserved)
        );
    }
}

#[test]
fn length_offset_and_outer_cap_fail_before_child_allocation() {
    let encoded = manifest().encode();

    let mut bad_total = encoded.clone();
    bad_total[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        CoreResultManifestV1::decode(&bad_total),
        Err(CoreResultManifestErrorV1::ComponentsLengthCap)
    );

    let mut bad_offset = encoded.clone();
    bad_offset[28..32].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        CoreResultManifestV1::decode(&bad_offset),
        Err(CoreResultManifestErrorV1::InvalidComponentsOffset)
    );

    let mut bad_length = encoded.clone();
    bad_length[32..36].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        CoreResultManifestV1::decode(&bad_length),
        Err(CoreResultManifestErrorV1::ComponentsLengthCap)
    );

    let oversized = vec![0u8; MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1 + 1];
    assert_eq!(
        CoreResultManifestV1::decode(&oversized),
        Err(CoreResultManifestErrorV1::ComponentsLengthCap)
    );
}

#[test]
fn child_and_record_digest_mutations_fail_closed() {
    let encoded = manifest().encode();

    let mut body_mutation = encoded.clone();
    body_mutation[CORE_RESULT_MANIFEST_HEADER_BYTES_V1] ^= 1;
    assert_eq!(
        CoreResultManifestV1::decode(&body_mutation),
        Err(CoreResultManifestErrorV1::ComponentsDigestMismatch)
    );

    let mut components_digest_mutation = encoded.clone();
    components_digest_mutation[COMPONENTS_DIGEST_OFFSET] ^= 1;
    assert_eq!(
        CoreResultManifestV1::decode(&components_digest_mutation),
        Err(CoreResultManifestErrorV1::ComponentsDigestMismatch)
    );

    let mut record_digest_mutation = encoded;
    record_digest_mutation[MANIFEST_DIGEST_OFFSET] ^= 1;
    assert_eq!(
        CoreResultManifestV1::decode(&record_digest_mutation),
        Err(CoreResultManifestErrorV1::ManifestDigestMismatch)
    );
}

#[test]
fn authority_and_bundle_cross_swaps_are_detected_at_each_binding() {
    let manifest = manifest();
    let encoded = manifest.encode();

    let mut authority_swap = encoded.clone();
    authority_swap[64] ^= 1;
    assert_eq!(
        CoreResultManifestV1::decode(&authority_swap),
        Err(CoreResultManifestErrorV1::ManifestDigestMismatch)
    );

    let foreign = bundle_for(0x32, 0x22).encode();
    assert_eq!(
        foreign.len(),
        encoded.len() - CORE_RESULT_MANIFEST_HEADER_BYTES_V1
    );
    let mut bundle_swap = encoded.clone();
    bundle_swap[CORE_RESULT_MANIFEST_HEADER_BYTES_V1..].copy_from_slice(&foreign);
    assert_eq!(
        CoreResultManifestV1::decode(&bundle_swap),
        Err(CoreResultManifestErrorV1::ComponentsDigestMismatch)
    );

    let foreign_digest = derive_core_manifest_components_digest_v1(&foreign);
    bundle_swap[COMPONENTS_DIGEST_OFFSET..MANIFEST_DIGEST_OFFSET]
        .copy_from_slice(foreign_digest.as_bytes());
    assert_eq!(
        CoreResultManifestV1::decode(&bundle_swap),
        Err(CoreResultManifestErrorV1::ManifestDigestMismatch)
    );

    recompute_manifest_digest(&mut bundle_swap);
    assert_eq!(
        CoreResultManifestV1::decode(&bundle_swap),
        Err(CoreResultManifestErrorV1::AcquisitionReceiptIdMismatch)
    );

    let foreign_authority = manifest_for(
        ResultId::from_bytes([0x82; 32]),
        SourceIdentityDigest::from_bytes([0x92; 32]),
        &bundle(),
    );
    let restored = CoreResultManifestV1::decode(&foreign_authority.encode()).unwrap();
    assert_eq!(
        restored.verify_authority(
            ResultId::from_bytes([0x81; 32]),
            SourceIdentityDigest::from_bytes([0x91; 32]),
            receipt_id(),
        ),
        Err(CoreResultManifestErrorV1::AuthorityMismatch)
    );
}

#[test]
fn receipt_header_mutation_reaches_semantic_check_after_digest_rebinding() {
    let mut encoded = manifest().encode();
    encoded[128] ^= 1;
    recompute_manifest_digest(&mut encoded);
    assert_eq!(
        CoreResultManifestV1::decode(&encoded),
        Err(CoreResultManifestErrorV1::AcquisitionReceiptIdMismatch)
    );
}

#[test]
fn debug_and_errors_are_contentless() {
    let canaries = [
        "CANARY_RESULT_AUTHORITY_12345678",
        "CANARY_SOURCE_AUTHORITY_12345678",
    ];
    let bundle = bundle();
    let manifest = CoreResultManifestV1::new(
        ResultId::from_bytes(*b"CANARY_RESULT_AUTHORITY_12345678"),
        SourceIdentityDigest::from_bytes(*b"CANARY_SOURCE_AUTHORITY_12345678"),
        receipt_id(),
        &bundle,
    )
    .unwrap();
    let output = format!(
        "{manifest:?} {:?} {:?}",
        manifest.manifest_digest(),
        CoreResultManifestErrorV1::AcquisitionReceiptIdMismatch
    );
    for canary in canaries {
        assert!(!output.contains(canary));
    }
    assert_eq!(
        format!("{}", CoreResultManifestErrorV1::ManifestDigestMismatch),
        "EVIDENTRAIL_CORE_RESULT_MANIFEST_RECORD_DIGEST_MISMATCH"
    );
}

#[test]
fn typed_outer_aead_round_trip_authenticates_context_and_exact_inner_bytes() {
    let (key, sealed) = sealed_payload();
    assert_eq!(
        sealed.header().payload_schema(),
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1
    );
    assert_eq!(
        sealed.header().result_id(),
        ResultId::from_bytes([0x81; 32])
    );
    assert_eq!(sealed.header().created_unix_nanos(), 1_000);
    assert_eq!(sealed.header().expires_unix_nanos(), 2_000);
    assert_eq!(
        usize::try_from(sealed.header().plaintext_length()).unwrap(),
        manifest().encoded_len()
    );
    assert!(
        usize::try_from(sealed.header().plaintext_length()).unwrap()
            <= MAX_MANIFEST_PLAINTEXT_BYTES_V1
    );

    let encoded = sealed.encode();
    let decoded =
        SealedCoreResultManifestV1::decode(ResultId::from_bytes([0x81; 32]), &encoded).unwrap();
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.encoded_len(), encoded.len());
    let opened = open_core_result_manifest_v1(
        &key.manifest_key(),
        expected_context(
            ResultId::from_bytes([0x81; 32]),
            SourceIdentityDigest::from_bytes([0x91; 32]),
        ),
        &decoded,
    )
    .unwrap();
    assert_eq!(opened.manifest().encode(), manifest().encode());
    assert_eq!(opened.result_id(), ResultId::from_bytes([0x81; 32]));
    assert_eq!(
        opened.source_identity_digest(),
        SourceIdentityDigest::from_bytes([0x91; 32])
    );
    assert_eq!(opened.acquisition_receipt_id(), receipt_id());
    assert_eq!(opened.outer_header(), decoded.header());
    assert_eq!(opened.into_manifest().encode(), manifest().encode());
}

#[test]
fn typed_contexts_reject_invalid_times() {
    assert_eq!(
        CoreResultManifestSealContextV1::new(2, 2, ManifestNonceV1::from_bytes([1; 24]),),
        Err(CoreResultPayloadErrorV1::InvalidTimeRange)
    );
    assert_eq!(
        ExpectedCoreResultManifestContextV1::new(
            ResultId::from_bytes([1; 32]),
            SourceIdentityDigest::from_bytes([2; 32]),
            AcquisitionReceiptId::from_bytes([3; 32]),
            3,
            2,
        ),
        Err(CoreResultPayloadErrorV1::InvalidTimeRange)
    );
}

#[test]
fn wrong_key_result_source_and_time_context_fail_closed() {
    let (result_key, sealed) = sealed_payload();
    let expected = expected_context(
        ResultId::from_bytes([0x81; 32]),
        SourceIdentityDigest::from_bytes([0x91; 32]),
    );
    assert_eq!(
        open_core_result_manifest_v1(&key(0xa2).manifest_key(), expected, &sealed),
        Err(CoreResultPayloadErrorV1::OuterAuthenticationFailed)
    );
    assert_eq!(
        open_core_result_manifest_v1(
            &result_key.manifest_key(),
            expected_context(
                ResultId::from_bytes([0x82; 32]),
                SourceIdentityDigest::from_bytes([0x91; 32]),
            ),
            &sealed,
        ),
        Err(CoreResultPayloadErrorV1::OuterAuthenticationFailed)
    );
    assert_eq!(
        open_core_result_manifest_v1(
            &result_key.manifest_key(),
            expected_context(
                ResultId::from_bytes([0x81; 32]),
                SourceIdentityDigest::from_bytes([0x92; 32]),
            ),
            &sealed,
        ),
        Err(CoreResultPayloadErrorV1::AuthorityMismatch)
    );
    let wrong_receipt = ExpectedCoreResultManifestContextV1::new(
        ResultId::from_bytes([0x81; 32]),
        SourceIdentityDigest::from_bytes([0x91; 32]),
        AcquisitionReceiptId::from_bytes([0xfe; 32]),
        1_000,
        2_000,
    )
    .unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&result_key.manifest_key(), wrong_receipt, &sealed),
        Err(CoreResultPayloadErrorV1::AuthorityMismatch)
    );
    let wrong_time = ExpectedCoreResultManifestContextV1::new(
        ResultId::from_bytes([0x81; 32]),
        SourceIdentityDigest::from_bytes([0x91; 32]),
        receipt_id(),
        1_001,
        2_000,
    )
    .unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&result_key.manifest_key(), wrong_time, &sealed),
        Err(CoreResultPayloadErrorV1::AuthenticatedContextMismatch)
    );
}

#[test]
fn typed_decode_rejects_wrong_result_and_payload_schema_without_auth_claim() {
    let (key, sealed) = sealed_payload();
    assert_eq!(
        SealedCoreResultManifestV1::decode(ResultId::from_bytes([0x82; 32]), &sealed.encode(),),
        Err(CoreResultPayloadErrorV1::OuterDecodeFailed)
    );

    let inner = manifest().encode();
    let header = ManifestHeaderV1::new(
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1 + 1,
        ResultId::from_bytes([0x81; 32]),
        0,
        1_000,
        2_000,
        u32::try_from(inner.len()).unwrap(),
        ManifestNonceV1::from_bytes([0xb2; 24]),
    )
    .unwrap();
    let generic = seal_manifest_v1(&key.manifest_key(), header, &inner).unwrap();
    assert_eq!(
        SealedCoreResultManifestV1::decode(ResultId::from_bytes([0x81; 32]), &generic.encode(),),
        Err(CoreResultPayloadErrorV1::PayloadSchemaMismatch)
    );
}

#[test]
fn every_outer_truncation_and_single_byte_mutation_fails_before_admission() {
    let (key, sealed) = sealed_payload();
    let encoded = sealed.encode();
    let result_id = ResultId::from_bytes([0x81; 32]);
    let expected = expected_context(result_id, SourceIdentityDigest::from_bytes([0x91; 32]));
    for boundary in 0..encoded.len() {
        assert_eq!(
            SealedCoreResultManifestV1::decode(result_id, &encoded[..boundary]),
            Err(CoreResultPayloadErrorV1::OuterDecodeFailed),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SealedCoreResultManifestV1::decode(result_id, &trailing),
        Err(CoreResultPayloadErrorV1::OuterDecodeFailed)
    );
    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 1;
        if let Ok(parsed) = SealedCoreResultManifestV1::decode(result_id, &mutated) {
            assert!(
                open_core_result_manifest_v1(&key.manifest_key(), expected, &parsed).is_err(),
                "mutation {index} authenticated and admitted"
            );
        }
    }
}

#[test]
fn authenticated_inner_result_source_and_canonical_bytes_cannot_be_cross_swapped() {
    let key = key(0xa3);
    let outer_result_id = ResultId::from_bytes([0x81; 32]);
    let expected = expected_context(
        outer_result_id,
        SourceIdentityDigest::from_bytes([0x91; 32]),
    );

    let foreign_result = manifest_for(
        ResultId::from_bytes([0x82; 32]),
        SourceIdentityDigest::from_bytes([0x91; 32]),
        &bundle(),
    );
    let foreign_bytes = foreign_result.encode();
    let header = ManifestHeaderV1::new(
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1,
        outer_result_id,
        0,
        1_000,
        2_000,
        u32::try_from(foreign_bytes.len()).unwrap(),
        ManifestNonceV1::from_bytes([0xb3; 24]),
    )
    .unwrap();
    let generic = seal_manifest_v1(&key.manifest_key(), header, &foreign_bytes).unwrap();
    let typed = SealedCoreResultManifestV1::decode(outer_result_id, &generic.encode()).unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&key.manifest_key(), expected, &typed),
        Err(CoreResultPayloadErrorV1::AuthorityMismatch)
    );

    let foreign_source = manifest_for(
        outer_result_id,
        SourceIdentityDigest::from_bytes([0x92; 32]),
        &bundle(),
    );
    let typed =
        seal_core_result_manifest_v1(&key.manifest_key(), seal_context(0xb4), &foreign_source)
            .unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&key.manifest_key(), expected, &typed),
        Err(CoreResultPayloadErrorV1::AuthorityMismatch)
    );

    let foreign_bundle = bundle_for(0x32, 0x22);
    let foreign_receipt = manifest_for_receipt(
        outer_result_id,
        SourceIdentityDigest::from_bytes([0x91; 32]),
        foreign_receipt_id(),
        &foreign_bundle,
    );
    let typed =
        seal_core_result_manifest_v1(&key.manifest_key(), seal_context(0xb7), &foreign_receipt)
            .unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&key.manifest_key(), expected, &typed),
        Err(CoreResultPayloadErrorV1::AuthorityMismatch)
    );

    let mut noncanonical = manifest().encode();
    noncanonical[CORE_RESULT_MANIFEST_HEADER_BYTES_V1] ^= 1;
    let header = ManifestHeaderV1::new(
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1,
        outer_result_id,
        0,
        1_000,
        2_000,
        u32::try_from(noncanonical.len()).unwrap(),
        ManifestNonceV1::from_bytes([0xb5; 24]),
    )
    .unwrap();
    let generic = seal_manifest_v1(&key.manifest_key(), header, &noncanonical).unwrap();
    let typed = SealedCoreResultManifestV1::decode(outer_result_id, &generic.encode()).unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&key.manifest_key(), expected, &typed),
        Err(CoreResultPayloadErrorV1::InnerDecodeFailed)
    );

    let mut trailing_inner = manifest().encode();
    trailing_inner.push(0);
    let header = ManifestHeaderV1::new(
        CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1,
        outer_result_id,
        0,
        1_000,
        2_000,
        u32::try_from(trailing_inner.len()).unwrap(),
        ManifestNonceV1::from_bytes([0xb6; 24]),
    )
    .unwrap();
    let generic = seal_manifest_v1(&key.manifest_key(), header, &trailing_inner).unwrap();
    let typed = SealedCoreResultManifestV1::decode(outer_result_id, &generic.encode()).unwrap();
    assert_eq!(
        open_core_result_manifest_v1(&key.manifest_key(), expected, &typed),
        Err(CoreResultPayloadErrorV1::InnerDecodeFailed)
    );
}

#[test]
fn typed_payload_debug_and_errors_never_expose_authority_or_plaintext_canaries() {
    let result_id = ResultId::from_bytes(*b"CANARY_RESULT_AUTHORITY_12345678");
    let source_identity = SourceIdentityDigest::from_bytes(*b"CANARY_SOURCE_AUTHORITY_12345678");
    let manifest = manifest_for(result_id, source_identity, &bundle());
    let key = key(b'K');
    let seal_context =
        CoreResultManifestSealContextV1::new(1_000, 2_000, ManifestNonceV1::from_bytes([b'N'; 24]))
            .unwrap();
    let expected = ExpectedCoreResultManifestContextV1::new(
        result_id,
        source_identity,
        receipt_id(),
        1_000,
        2_000,
    )
    .unwrap();
    let redacted_expected = ExpectedCoreResultManifestContextV1::new(
        result_id,
        source_identity,
        AcquisitionReceiptId::from_bytes(*b"CANARY_RECEIPT_AUTHORITY_1234567"),
        1_000,
        2_000,
    )
    .unwrap();
    let sealed =
        seal_core_result_manifest_v1(&key.manifest_key(), seal_context, &manifest).unwrap();
    let opened = open_core_result_manifest_v1(&key.manifest_key(), expected, &sealed).unwrap();
    let rendered = format!(
        "{seal_context:?} {expected:?} {redacted_expected:?} {sealed:?} {opened:?} {:?} {}",
        CoreResultPayloadErrorV1::AuthorityMismatch,
        CoreResultPayloadErrorV1::OuterAuthenticationFailed,
    );
    assert!(!rendered.contains("CANARY_RESULT_AUTHORITY_12345678"));
    assert!(!rendered.contains("CANARY_SOURCE_AUTHORITY_12345678"));
    assert!(!rendered.contains("CANARY_RECEIPT_AUTHORITY_1234567"));
    assert!(!rendered.contains("KKKK"));
    assert!(!rendered.contains("NNNN"));
}
