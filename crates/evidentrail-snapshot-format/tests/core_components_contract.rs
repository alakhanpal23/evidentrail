use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt,
    AdapterIdentity, AdapterOutcome, AttemptCounts, CompletenessProof, EventId, ExactnessBasis,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, PlanDigest,
    PlanId, PolicyDigest, RetrievalId, SourceRecordId, UnixTimestampNanos,
};
use evidentrail_snapshot_format::{
    ACQUISITION_COMPLETION_HEADER_BYTES_V1, AcquisitionCompletionRecordV1, AuthorizedByteRangeV1,
    CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1, CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1,
    CORE_MANIFEST_COMPONENTS_DIGEST_DOMAIN_V1, CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1,
    CORE_MANIFEST_COMPONENTS_SCHEMA_V1, CORE_MANIFEST_COMPONENTS_VERSION_V1,
    CoreManifestComponentKindV1, CoreManifestComponentsErrorV1, CoreManifestComponentsV1,
    EventExpansionIndexEntryV1, EventExpansionIndexV1, EventFrameLocatorV1, FRAME_HEADER_BYTES_V1,
    FrameCommitmentV1, MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1,
    MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1, SEGMENT_HEADER_BYTES_V1, SegmentCatalogEntryV1,
    SegmentCatalogV1, SegmentDigestV1, SourceOutcomeTableV1,
    derive_core_manifest_components_digest_v1,
};
use sha2::{Digest, Sha256};

struct Fixture {
    catalog: SegmentCatalogV1,
    index: EventExpansionIndexV1,
    outcomes: SourceOutcomeTableV1,
    completion: AcquisitionCompletionRecordV1,
}

fn one_segment(digest: [u8; 32], commitment: [u8; 32]) -> SegmentCatalogV1 {
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
            SegmentDigestV1::from_bytes(digest),
            FrameCommitmentV1::from_bytes(commitment),
        )
        .unwrap(),
    ])
    .unwrap()
}

fn one_index(catalog: &SegmentCatalogV1, exactness_basis: ExactnessBasis) -> EventExpansionIndexV1 {
    EventExpansionIndexV1::new(
        catalog,
        vec![
            EventExpansionIndexEntryV1::new(
                catalog,
                EventId::from_bytes([0; 32]),
                EventFrameLocatorV1::new(0, 0, 0, 120, 108).unwrap(),
                AuthorizedByteRangeV1::new(0, 0).unwrap(),
                exactness_basis,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn one_receipt(retrieval_id: RetrievalId, exactness_basis: ExactnessBasis) -> AcquisitionReceipt {
    AcquisitionReceipt::reconcile(
        retrieval_id,
        [SourceRecordId::from_bytes([0; 32])],
        [AcquisitionOutcomeAssignment::new(
            SourceRecordId::from_bytes([0; 32]),
            AcquisitionOutcome::Persisted {
                event_id: EventId::from_bytes([0; 32]),
                exactness_basis,
            },
        )],
    )
    .unwrap()
}

fn one_completion(retrieval_id: RetrievalId, records: u64) -> AcquisitionCompletionRecordV1 {
    let completion = FetchCompletion::new(
        FetchIdentity::new(
            retrieval_id,
            PlanId::from_bytes([0; 32]),
            PlanDigest::from_bytes([0; 32]),
            AdapterIdentity::new("a", "1").unwrap(),
        ),
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(0)),
        AcknowledgedCounts::new(records, 0, 0),
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

fn fixture_with(
    retrieval_id: RetrievalId,
    catalog_digest: [u8; 32],
    exactness_basis: ExactnessBasis,
) -> Fixture {
    let catalog = one_segment(catalog_digest, [0; 32]);
    let index = one_index(&catalog, exactness_basis);
    let receipt = one_receipt(retrieval_id, exactness_basis);
    let outcomes = SourceOutcomeTableV1::new(&receipt, &index).unwrap();
    let completion = one_completion(retrieval_id, 1);
    Fixture {
        catalog,
        index,
        outcomes,
        completion,
    }
}

fn fixture() -> Fixture {
    fixture_with(
        RetrievalId::from_bytes([0; 32]),
        [0; 32],
        ExactnessBasis::SourceExact,
    )
}

fn bundle(fixture: &Fixture) -> CoreManifestComponentsV1 {
    CoreManifestComponentsV1::new(
        &fixture.catalog,
        &fixture.index,
        &fixture.outcomes,
        &fixture.completion,
    )
    .unwrap()
}

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

fn descriptor_start(ordinal: usize) -> usize {
    CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1
        + ordinal * CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn child_range(encoded: &[u8], ordinal: usize) -> std::ops::Range<usize> {
    let descriptor = descriptor_start(ordinal);
    let start = usize::try_from(read_u32(encoded, descriptor + 8)).unwrap();
    let length = usize::try_from(read_u32(encoded, descriptor + 12)).unwrap();
    start..start + length
}

fn replace_child_and_digest(encoded: &mut [u8], ordinal: usize, replacement: &[u8]) {
    let range = child_range(encoded, ordinal);
    assert_eq!(range.len(), replacement.len());
    encoded[range].copy_from_slice(replacement);
    let descriptor = descriptor_start(ordinal);
    encoded[descriptor + 16..descriptor + 48]
        .copy_from_slice(&<[u8; 32]>::from(Sha256::digest(replacement)));
}

#[test]
fn fixed_directory_and_independently_reconstructed_golden_digests_are_frozen() {
    let fixture = fixture();
    let bundle = bundle(&fixture);
    let encoded = bundle.encode();
    let expected_header = hex_vec(concat!(
        "455652434d433031000100010001014000000004000005a20000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000010001000100000140000000d004c92c48edba57ec291fbae41b1c47f7",
        "8be8c46d272e210af8b341656915102c00000000000000000000000000000000",
        "00010002000100010000021000000130486ad26075a171840309ed3d1e543ee4",
        "38bd944c42df6b4dc58528366d0b28e200000000000000000000000000000000",
        "000200030001000100000340000001400f2d15fc3cbca78eae64126ddfd376bb",
        "beb1978b2294c03b29765080c8fef5b300000000000000000000000000000000",
        "000300040001000100000480000001227b9e9765cd65b48c9a13d28bea70fec1",
        "d6a2cfce46faa10059dcad3075377e6800000000000000000000000000000000"
    ));
    assert_eq!(
        expected_header.len(),
        CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1
    );
    assert_eq!(
        &encoded[..CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1],
        expected_header
    );
    assert_eq!(encoded.len(), 1_442);
    assert_eq!(bundle.encoded_len(), encoded.len());

    // Independently reconstructed using Python bytearray/int.to_bytes and
    // hashlib.sha256 from the frozen child and directory layouts.
    assert_eq!(
        bundle.bundle_digest().as_bytes(),
        &hex_array::<32>("8f99ecd22337e8ee1a31c4c335ccfcecd432d8b26e389b9ec60d16276f371a2e")
    );
    assert_eq!(
        bundle
            .child_digest(CoreManifestComponentKindV1::SegmentCatalog)
            .as_bytes(),
        &hex_array::<32>("04c92c48edba57ec291fbae41b1c47f78be8c46d272e210af8b341656915102c")
    );
    assert_eq!(
        bundle
            .child_digest(CoreManifestComponentKindV1::EventExpansionIndex)
            .as_bytes(),
        &hex_array::<32>("486ad26075a171840309ed3d1e543ee438bd944c42df6b4dc58528366d0b28e2")
    );
    assert_eq!(
        bundle
            .child_digest(CoreManifestComponentKindV1::SourceOutcomeTable)
            .as_bytes(),
        &hex_array::<32>("0f2d15fc3cbca78eae64126ddfd376bbbeb1978b2294c03b29765080c8fef5b3")
    );
    assert_eq!(
        bundle
            .child_digest(CoreManifestComponentKindV1::AcquisitionCompletion)
            .as_bytes(),
        &hex_array::<32>("7b9e9765cd65b48c9a13d28bea70fec1d6a2cfce46faa10059dcad3075377e68")
    );
    assert_eq!(
        bundle.bundle_digest(),
        derive_core_manifest_components_digest_v1(&encoded)
    );
    let raw_sha: [u8; 32] = Sha256::digest(&encoded).into();
    assert_ne!(raw_sha, *bundle.bundle_digest().as_bytes());
    assert_eq!(
        CORE_MANIFEST_COMPONENTS_DIGEST_DOMAIN_V1,
        b"evidentrail.snapshot.core-manifest-components.v1"
    );
}

#[test]
fn decode_is_self_restoring_and_preserves_zero_valued_typed_domains() {
    let fixture = fixture();
    let encoded = bundle(&fixture).encode();
    drop(fixture);
    let restored = CoreManifestComponentsV1::decode(&encoded).unwrap();
    assert_eq!(restored.version(), CORE_MANIFEST_COMPONENTS_VERSION_V1);
    assert_eq!(restored.schema(), CORE_MANIFEST_COMPONENTS_SCHEMA_V1);
    assert_eq!(
        restored.catalog().entries()[0].segment_digest().as_bytes(),
        &[0; 32]
    );
    assert_eq!(
        restored.event_index().entries()[0].event_id().as_bytes(),
        &[0; 32]
    );
    assert_eq!(
        restored.source_outcomes().retrieval_id().as_bytes(),
        &[0; 32]
    );
    assert_eq!(
        restored
            .acquisition_completion()
            .completion()
            .identity()
            .plan_digest()
            .as_bytes(),
        &[0; 32]
    );
    let receipt = restored.source_outcomes().to_acquisition_receipt().unwrap();
    restored
        .acquisition_completion()
        .verify_against_receipt(&receipt)
        .unwrap();
    let (catalog, index, outcomes, completion) = restored.into_parts();
    assert_eq!(catalog.segment_count(), 1);
    assert_eq!(index.entry_count(), 1);
    assert_eq!(outcomes.entry_count(), 1);
    assert_eq!(completion.completion().acknowledged().records(), 1);
}

#[test]
fn constructor_replays_every_cross_join() {
    let base = fixture();
    let foreign_catalog = one_segment([1; 32], [0; 32]);
    assert_eq!(
        CoreManifestComponentsV1::new(
            &foreign_catalog,
            &base.index,
            &base.outcomes,
            &base.completion,
        ),
        Err(CoreManifestComponentsErrorV1::CatalogIndexMismatch)
    );

    let post_policy = ExactnessBasis::PostPolicy {
        policy_digest: PolicyDigest::from_bytes([0; 32]),
        transformation_receipt_id: evidentrail_schema::TransformationReceiptId::from_bytes([0; 32]),
    };
    let foreign_index = one_index(&base.catalog, post_policy);
    assert_eq!(
        CoreManifestComponentsV1::new(
            &base.catalog,
            &foreign_index,
            &base.outcomes,
            &base.completion,
        ),
        Err(CoreManifestComponentsErrorV1::OutcomeIndexMismatch)
    );

    let wrong_retrieval_completion = one_completion(RetrievalId::from_bytes([2; 32]), 1);
    assert_eq!(
        CoreManifestComponentsV1::new(
            &base.catalog,
            &base.index,
            &base.outcomes,
            &wrong_retrieval_completion,
        ),
        Err(CoreManifestComponentsErrorV1::CompletionOutcomeMismatch)
    );
    let wrong_count_completion = one_completion(RetrievalId::from_bytes([0; 32]), 0);
    assert_eq!(
        CoreManifestComponentsV1::new(
            &base.catalog,
            &base.index,
            &base.outcomes,
            &wrong_count_completion,
        ),
        Err(CoreManifestComponentsErrorV1::CompletionOutcomeMismatch)
    );
}

#[test]
fn decoder_cross_swaps_fail_even_after_attacker_recomputes_child_digest() {
    let base = fixture();
    let encoded = bundle(&base).encode();

    let foreign_catalog = one_segment([1; 32], [0; 32]);
    let mut catalog_swap = encoded.clone();
    replace_child_and_digest(&mut catalog_swap, 0, &foreign_catalog.encode());
    assert_eq!(
        CoreManifestComponentsV1::decode(&catalog_swap),
        Err(CoreManifestComponentsErrorV1::CatalogIndexMismatch)
    );

    let post_policy = ExactnessBasis::PostPolicy {
        policy_digest: PolicyDigest::from_bytes([0; 32]),
        transformation_receipt_id: evidentrail_schema::TransformationReceiptId::from_bytes([0; 32]),
    };
    let foreign_index = one_index(&base.catalog, post_policy);
    let mut index_swap = encoded.clone();
    replace_child_and_digest(&mut index_swap, 1, &foreign_index.encode());
    assert_eq!(
        CoreManifestComponentsV1::decode(&index_swap),
        Err(CoreManifestComponentsErrorV1::OutcomeIndexMismatch)
    );

    let foreign_receipt = one_receipt(
        RetrievalId::from_bytes([2; 32]),
        ExactnessBasis::SourceExact,
    );
    let foreign_outcome = SourceOutcomeTableV1::new(&foreign_receipt, &base.index).unwrap();
    let mut outcome_swap = encoded.clone();
    replace_child_and_digest(&mut outcome_swap, 2, &foreign_outcome.encode());
    assert_eq!(
        CoreManifestComponentsV1::decode(&outcome_swap),
        Err(CoreManifestComponentsErrorV1::CompletionOutcomeMismatch)
    );

    let foreign_completion = one_completion(RetrievalId::from_bytes([2; 32]), 1);
    assert_eq!(
        foreign_completion.encoded_len(),
        ACQUISITION_COMPLETION_HEADER_BYTES_V1 + 2
    );
    let mut completion_swap = encoded;
    replace_child_and_digest(&mut completion_swap, 3, &foreign_completion.encode());
    assert_eq!(
        CoreManifestComponentsV1::decode(&completion_swap),
        Err(CoreManifestComponentsErrorV1::CompletionOutcomeMismatch)
    );
}

#[test]
fn directory_rejects_reorder_duplicate_unknown_ranges_and_digest_mutation() {
    let encoded = bundle(&fixture()).encode();
    let first = descriptor_start(0);
    let second = descriptor_start(1);

    let mut duplicate = encoded.clone();
    duplicate[second + 2..second + 4].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        CoreManifestComponentsV1::decode(&duplicate),
        Err(CoreManifestComponentsErrorV1::DuplicateChildKind)
    );
    let mut reordered = encoded.clone();
    reordered[first + 2..first + 4].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        CoreManifestComponentsV1::decode(&reordered),
        Err(CoreManifestComponentsErrorV1::NoncanonicalChildOrder)
    );
    let mut unknown = encoded.clone();
    unknown[first + 2..first + 4].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        CoreManifestComponentsV1::decode(&unknown),
        Err(CoreManifestComponentsErrorV1::UnsupportedChildKind)
    );
    let mut ordinal = encoded.clone();
    ordinal[first + 1] = 1;
    assert_eq!(
        CoreManifestComponentsV1::decode(&ordinal),
        Err(CoreManifestComponentsErrorV1::InvalidDescriptorOrdinal)
    );
    let mut range = encoded.clone();
    range[first + 8..first + 12].copy_from_slice(&321u32.to_be_bytes());
    assert_eq!(
        CoreManifestComponentsV1::decode(&range),
        Err(CoreManifestComponentsErrorV1::NoncontiguousChildRange)
    );
    let mut digest = encoded.clone();
    let catalog_range = child_range(&digest, 0);
    digest[catalog_range.start] ^= 1;
    assert_eq!(
        CoreManifestComponentsV1::decode(&digest),
        Err(CoreManifestComponentsErrorV1::ChildDigestMismatch)
    );
}

#[test]
fn decoder_reinvokes_each_canonical_child_decoder_after_digest_validation() {
    let encoded = bundle(&fixture()).encode();
    for (ordinal, expected) in [
        (0, CoreManifestComponentsErrorV1::CatalogDecodeFailed),
        (1, CoreManifestComponentsErrorV1::CatalogIndexMismatch),
        (2, CoreManifestComponentsErrorV1::OutcomeIndexMismatch),
        (3, CoreManifestComponentsErrorV1::CompletionDecodeFailed),
    ] {
        let mut mutated = encoded.clone();
        let range = child_range(&mutated, ordinal);
        let mut child = mutated[range.clone()].to_vec();
        child[0] ^= 1;
        replace_child_and_digest(&mut mutated, ordinal, &child);
        assert_eq!(
            CoreManifestComponentsV1::decode(&mutated),
            Err(expected),
            "ordinal {ordinal}"
        );
    }
}

#[test]
fn strict_header_rejects_every_truncation_trailing_fixed_field_and_reserved_byte() {
    let encoded = bundle(&fixture()).encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            CoreManifestComponentsV1::decode(&encoded[..boundary]),
            Err(CoreManifestComponentsErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        CoreManifestComponentsV1::decode(&trailing),
        Err(CoreManifestComponentsErrorV1::InvalidEncodedLength)
    );
    for (offset, expected) in [
        (0, CoreManifestComponentsErrorV1::InvalidMagic),
        (8, CoreManifestComponentsErrorV1::UnsupportedVersion),
        (10, CoreManifestComponentsErrorV1::UnsupportedSchema),
        (12, CoreManifestComponentsErrorV1::UnsupportedObjectKind),
        (14, CoreManifestComponentsErrorV1::InvalidHeaderWidth),
        (16, CoreManifestComponentsErrorV1::NonzeroFlags),
        (18, CoreManifestComponentsErrorV1::InvalidChildCount),
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert_eq!(CoreManifestComponentsV1::decode(&mutated), Err(expected));
    }
    for offset in 24..64 {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            CoreManifestComponentsV1::decode(&mutated),
            Err(CoreManifestComponentsErrorV1::NonzeroReserved),
            "header offset {offset}"
        );
    }
    for ordinal in 0..4 {
        let start = descriptor_start(ordinal);
        for offset in start + 48..start + 64 {
            let mut mutated = encoded.clone();
            mutated[offset] = 1;
            assert_eq!(
                CoreManifestComponentsV1::decode(&mutated),
                Err(CoreManifestComponentsErrorV1::NonzeroReserved),
                "descriptor offset {offset}"
            );
        }
    }
}

#[test]
fn version_schema_length_and_total_caps_fail_before_child_allocation() {
    let encoded = bundle(&fixture()).encode();
    let first = descriptor_start(0);
    for (offset, expected) in [
        (
            first + 4,
            CoreManifestComponentsErrorV1::ChildVersionMismatch,
        ),
        (
            first + 6,
            CoreManifestComponentsErrorV1::ChildSchemaMismatch,
        ),
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert_eq!(CoreManifestComponentsV1::decode(&mutated), Err(expected));
    }
    let mut child_cap = encoded.clone();
    let completion = descriptor_start(3);
    child_cap[completion + 12..completion + 16].copy_from_slice(
        &u32::try_from(MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1 + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert_eq!(
        CoreManifestComponentsV1::decode(&child_cap),
        Err(CoreManifestComponentsErrorV1::ChildLengthCap)
    );
    let mut total_cap = encoded;
    total_cap[20..24].copy_from_slice(
        &u32::try_from(MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1 + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert_eq!(
        CoreManifestComponentsV1::decode(&total_cap),
        Err(CoreManifestComponentsErrorV1::TotalLengthCap)
    );
}

#[test]
fn debug_and_errors_never_expose_child_identity_or_digest_canaries() {
    const CANARY: &str = "CORE-COMPONENTS-CANARY-SECRET";
    let mut canary = [0u8; 32];
    for (target, source) in canary.iter_mut().zip(CANARY.bytes().cycle()) {
        *target = source;
    }
    let fixture = fixture_with(
        RetrievalId::from_bytes(canary),
        canary,
        ExactnessBasis::SourceExact,
    );
    let bundle = bundle(&fixture);
    let output = format!(
        "{bundle:?} {:?} {:?} {:?} {}",
        bundle.bundle_digest(),
        bundle.child_digest(CoreManifestComponentKindV1::SegmentCatalog),
        CoreManifestComponentKindV1::SegmentCatalog,
        CoreManifestComponentsErrorV1::CompletionOutcomeMismatch
    );
    assert!(!output.contains(CANARY));
    assert!(!output.contains("434f52452d434f4d504f4e454e5453"));
    assert_eq!(
        format!("{bundle:?}"),
        "CoreManifestComponentsV1(<redacted>)"
    );
}
