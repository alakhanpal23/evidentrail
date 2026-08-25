use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt, EventId, ExactnessBasis,
    PolicyDigest, RetrievalId, SourceRecordId, TransformationReceiptId,
};
use evidentrail_snapshot_format::{
    AuthorizedByteRangeV1, EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1, EventExpansionIndexEntryV1,
    EventExpansionIndexV1, EventFrameLocatorV1, FRAME_HEADER_BYTES_V1, FrameCommitmentV1,
    MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1, SEGMENT_HEADER_BYTES_V1,
    SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1, SOURCE_OUTCOME_POST_POLICY_KIND_V1,
    SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1, SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1,
    SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1, SOURCE_OUTCOME_TABLE_SCHEMA_V1,
    SOURCE_OUTCOME_TABLE_VERSION_V1, SegmentCatalogEntryV1, SegmentCatalogV1, SegmentDigestV1,
    SourceOutcomeTableErrorV1, SourceOutcomeTableV1, derive_event_expansion_index_digest_v1,
};
use sha2::{Digest, Sha256};

fn sequential_bytes(start: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(u8::try_from(offset).unwrap());
    }
    bytes
}

fn event(seed: u8) -> EventId {
    EventId::from_bytes(sequential_bytes(seed))
}

fn source(seed: u8) -> SourceRecordId {
    SourceRecordId::from_bytes(sequential_bytes(seed))
}

fn retrieval(seed: u8) -> RetrievalId {
    RetrievalId::from_bytes(sequential_bytes(seed))
}

fn policy(seed: u8) -> PolicyDigest {
    PolicyDigest::from_bytes(sequential_bytes(seed))
}

fn transformation(seed: u8) -> TransformationReceiptId {
    TransformationReceiptId::from_bytes(sequential_bytes(seed))
}

fn segment(
    segment_sequence: u64,
    first_global_sequence: u64,
    frame_count: u32,
    ciphertext_byte_count: u64,
    digest_seed: u8,
    commitment_seed: u8,
) -> SegmentCatalogEntryV1 {
    let encoded_byte_count = SEGMENT_HEADER_BYTES_V1 as u64
        + u64::from(frame_count) * FRAME_HEADER_BYTES_V1 as u64
        + ciphertext_byte_count;
    SegmentCatalogEntryV1::new(
        segment_sequence,
        first_global_sequence,
        frame_count,
        encoded_byte_count,
        ciphertext_byte_count,
        SegmentDigestV1::from_bytes(sequential_bytes(digest_seed)),
        FrameCommitmentV1::from_bytes(sequential_bytes(commitment_seed)),
    )
    .unwrap()
}

fn catalog() -> SegmentCatalogV1 {
    SegmentCatalogV1::new(vec![
        segment(0, 0, 2, 40, 0x10, 0x40),
        segment(1, 2, 3, 64, 0x60, 0x80),
    ])
    .unwrap()
}

fn source_index_entry(catalog: &SegmentCatalogV1, event_id: EventId) -> EventExpansionIndexEntryV1 {
    EventExpansionIndexEntryV1::new(
        catalog,
        event_id,
        EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap(),
        AuthorizedByteRangeV1::new(0, 8).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap()
}

fn post_policy_index_entry(
    catalog: &SegmentCatalogV1,
    event_id: EventId,
    policy_digest: PolicyDigest,
    transformation_receipt_id: TransformationReceiptId,
) -> EventExpansionIndexEntryV1 {
    EventExpansionIndexEntryV1::new(
        catalog,
        event_id,
        EventFrameLocatorV1::new(1, 3, 1, 228, 124).unwrap(),
        AuthorizedByteRangeV1::new(0, 16).unwrap(),
        ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        },
    )
    .unwrap()
}

fn event_index(catalog: &SegmentCatalogV1) -> EventExpansionIndexV1 {
    EventExpansionIndexV1::new(
        catalog,
        vec![
            source_index_entry(catalog, event(0x10)),
            post_policy_index_entry(catalog, event(0x30), policy(0xa0), transformation(0xc0)),
        ],
    )
    .unwrap()
}

fn source_exact_outcome(event_id: EventId) -> AcquisitionOutcome {
    AcquisitionOutcome::Persisted {
        event_id,
        exactness_basis: ExactnessBasis::SourceExact,
    }
}

fn post_policy_outcome(
    event_id: EventId,
    policy_digest: PolicyDigest,
    transformation_receipt_id: TransformationReceiptId,
) -> AcquisitionOutcome {
    AcquisitionOutcome::Persisted {
        event_id,
        exactness_basis: ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        },
    }
}

fn receipt() -> AcquisitionReceipt {
    let expected = [source(0x50), source(0x70), source(0x90)];
    // Assignment order is deliberately different from acquisition order.
    let assignments = [
        AcquisitionOutcomeAssignment::new(
            source(0x90),
            post_policy_outcome(event(0x30), policy(0xa0), transformation(0xc0)),
        ),
        AcquisitionOutcomeAssignment::new(source(0x50), source_exact_outcome(event(0x10))),
        AcquisitionOutcomeAssignment::new(
            source(0x70),
            AcquisitionOutcome::OmittedByPolicy {
                policy_digest: policy(0xe0),
            },
        ),
    ];
    AcquisitionReceipt::reconcile(retrieval(0xd0), expected, assignments).unwrap()
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

#[test]
fn exact_codec_and_independently_reconstructed_golden_hash_are_frozen() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let receipt = receipt();
    let table = SourceOutcomeTableV1::new(&receipt, &index).unwrap();
    let expected = hex_vec(concat!(
        "455652534f54303100010001000100a00000000000000000d0d1d2d3d4d5d6d7",
        "d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef0000000000000003",
        "0000000000000001000000000000000100000000000000010000000000000002",
        "5235bc2cfeaff89accd46c6ea3565ee64f0dea1ab11612bf1e65fc3d9bf583d3",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000505152535455565758595a5b5c5d5e5f6061626364656667",
        "68696a6b6c6d6e6f0001000000000000101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f00000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000001707172737475767778797a7b7c7d7e7f8081828384858687",
        "88898a8b8c8d8e8f000300000000000000000000000000000000000000000000",
        "00000000000000000000000000000000e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000002909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7",
        "a8a9aaabacadaeaf0002000000000000303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf00000000000000000000000000000000"
    ));
    assert_eq!(
        expected.len(),
        SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1 + 3 * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1
    );
    assert_eq!(table.encode(), expected);
    assert_eq!(table.encoded_len(), expected.len());

    // Independently reconstructed with Python 3 bytearray/int.to_bytes and
    // hashlib.sha256 from the frozen field offsets.
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(
        digest,
        hex_array("dde4f16383db0483fa8b9cfd03967c294d64310e751e9f58e1a3e7225118ec9d")
    );
    assert_eq!(
        table.event_index_digest().as_bytes(),
        &hex_array::<EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1>(
            "5235bc2cfeaff89accd46c6ea3565ee64f0dea1ab11612bf1e65fc3d9bf583d3"
        )
    );

    let decoded = SourceOutcomeTableV1::decode(&index, &expected).unwrap();
    assert_eq!(decoded, table);
    assert_eq!(decoded.version(), SOURCE_OUTCOME_TABLE_VERSION_V1);
    assert_eq!(decoded.schema(), SOURCE_OUTCOME_TABLE_SCHEMA_V1);
    assert_eq!(decoded.retrieval_id(), retrieval(0xd0));
    assert_eq!(decoded.entry_count(), 3);
    assert_eq!(decoded.source_exact_count(), 1);
    assert_eq!(decoded.post_policy_count(), 1);
    assert_eq!(decoded.omitted_by_policy_count(), 1);
    assert_eq!(decoded.event_index_entry_count(), 2);
    assert_eq!(decoded.entries()[0].acquisition_ordinal(), 0);
    assert_eq!(decoded.entries()[0].source_record_id(), source(0x50));
    assert_eq!(decoded.entries()[1].source_record_id(), source(0x70));
    assert_eq!(decoded.entries()[2].source_record_id(), source(0x90));
}

#[test]
fn decode_is_self_restoring_and_reconstructs_the_exact_receipt() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let original_receipt = receipt();
    let encoded = SourceOutcomeTableV1::new(&original_receipt, &index)
        .unwrap()
        .encode();
    drop(original_receipt);

    let decoded = SourceOutcomeTableV1::decode(&index, &encoded).unwrap();
    let reconstructed = decoded.to_acquisition_receipt().unwrap();
    assert_eq!(reconstructed, receipt());
    assert_eq!(reconstructed.retrieval_id(), retrieval(0xd0));
    assert_eq!(reconstructed.counts().source_exact, 1);
    assert_eq!(reconstructed.counts().post_policy, 1);
    assert_eq!(reconstructed.counts().omitted_by_policy, 1);
    assert_eq!(reconstructed.entries()[0].source_record_id(), source(0x50));
    assert_eq!(reconstructed.entries()[1].source_record_id(), source(0x70));
    assert_eq!(reconstructed.entries()[2].source_record_id(), source(0x90));
    decoded.verify_against_receipt(&reconstructed).unwrap();

    let foreign = AcquisitionReceipt::reconcile(
        retrieval(0xd1),
        receipt()
            .entries()
            .iter()
            .map(|entry| entry.source_record_id()),
        receipt().entries().iter().map(|entry| {
            AcquisitionOutcomeAssignment::new(entry.source_record_id(), entry.outcome().clone())
        }),
    )
    .unwrap();
    assert_eq!(
        decoded.verify_against_receipt(&foreign),
        Err(SourceOutcomeTableErrorV1::RetrievalMismatch)
    );
}

#[test]
fn construction_uses_receipt_order_and_supports_an_empty_receipt() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let table = SourceOutcomeTableV1::new(&receipt(), &index).unwrap();
    assert_eq!(table.entries()[0].source_record_id(), source(0x50));
    assert_eq!(table.entries()[1].source_record_id(), source(0x70));
    assert_eq!(table.entries()[2].source_record_id(), source(0x90));

    let empty_index = EventExpansionIndexV1::new(&catalog, Vec::new()).unwrap();
    let empty_receipt =
        AcquisitionReceipt::reconcile(retrieval(1), std::iter::empty(), std::iter::empty())
            .unwrap();
    let empty = SourceOutcomeTableV1::new(&empty_receipt, &empty_index).unwrap();
    assert_eq!(empty.entry_count(), 0);
    assert_eq!(empty.encoded_len(), SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1);
    let decoded = SourceOutcomeTableV1::decode(&empty_index, &empty.encode()).unwrap();
    assert_eq!(decoded.to_acquisition_receipt().unwrap(), empty_receipt);
}

#[test]
fn construction_requires_an_exact_receipt_index_bijection() {
    let catalog = catalog();
    let full_index = event_index(&catalog);
    let source_only_index =
        EventExpansionIndexV1::new(&catalog, vec![source_index_entry(&catalog, event(0x10))])
            .unwrap();
    assert_eq!(
        SourceOutcomeTableV1::new(&receipt(), &source_only_index),
        Err(SourceOutcomeTableErrorV1::MissingIndexEvent)
    );

    let source_only_receipt = AcquisitionReceipt::reconcile(
        retrieval(0xd0),
        [source(0x50)],
        [AcquisitionOutcomeAssignment::new(
            source(0x50),
            source_exact_outcome(event(0x10)),
        )],
    )
    .unwrap();
    assert_eq!(
        SourceOutcomeTableV1::new(&source_only_receipt, &full_index),
        Err(SourceOutcomeTableErrorV1::ExtraIndexEvent)
    );

    let wrong_exactness = AcquisitionReceipt::reconcile(
        retrieval(0xd0),
        [source(0x50), source(0x90)],
        [
            AcquisitionOutcomeAssignment::new(source(0x50), source_exact_outcome(event(0x10))),
            AcquisitionOutcomeAssignment::new(source(0x90), source_exact_outcome(event(0x30))),
        ],
    )
    .unwrap();
    assert_eq!(
        SourceOutcomeTableV1::new(&wrong_exactness, &full_index),
        Err(SourceOutcomeTableErrorV1::IndexExactnessMismatch)
    );
}

#[test]
fn used_hash_identifiers_accept_the_full_zero_value_domain() {
    let catalog = catalog();
    let zero_event = EventId::from_bytes([0; 32]);
    let zero_source_index =
        EventExpansionIndexV1::new(&catalog, vec![source_index_entry(&catalog, zero_event)])
            .unwrap();
    let source_receipt = AcquisitionReceipt::reconcile(
        retrieval(2),
        [source(1), source(2)],
        [
            AcquisitionOutcomeAssignment::new(source(1), source_exact_outcome(zero_event)),
            AcquisitionOutcomeAssignment::new(
                source(2),
                AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes([0; 32]),
                },
            ),
        ],
    )
    .unwrap();
    let source_table = SourceOutcomeTableV1::new(&source_receipt, &zero_source_index).unwrap();
    let decoded = SourceOutcomeTableV1::decode(&zero_source_index, &source_table.encode()).unwrap();
    assert_eq!(decoded.to_acquisition_receipt().unwrap(), source_receipt);

    let zero_post_index = EventExpansionIndexV1::new(
        &catalog,
        vec![post_policy_index_entry(
            &catalog,
            zero_event,
            PolicyDigest::from_bytes([0; 32]),
            TransformationReceiptId::from_bytes([0; 32]),
        )],
    )
    .unwrap();
    let post_receipt = AcquisitionReceipt::reconcile(
        retrieval(3),
        [source(3)],
        [AcquisitionOutcomeAssignment::new(
            source(3),
            post_policy_outcome(
                zero_event,
                PolicyDigest::from_bytes([0; 32]),
                TransformationReceiptId::from_bytes([0; 32]),
            ),
        )],
    )
    .unwrap();
    let post_table = SourceOutcomeTableV1::new(&post_receipt, &zero_post_index).unwrap();
    let decoded = SourceOutcomeTableV1::decode(&zero_post_index, &post_table.encode()).unwrap();
    assert_eq!(decoded.to_acquisition_receipt().unwrap(), post_receipt);
}

#[test]
fn conditional_unused_fields_are_canonical_zero() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let encoded = SourceOutcomeTableV1::new(&receipt(), &index)
        .unwrap()
        .encode();
    let source_start = SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1;
    let omitted_start = source_start + SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;
    let post_start = omitted_start + SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;
    assert_eq!(
        u16::from_be_bytes(
            encoded[source_start + 40..source_start + 42]
                .try_into()
                .unwrap()
        ),
        SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1
    );
    assert!(
        encoded[source_start + 80..source_start + 144]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        u16::from_be_bytes(
            encoded[omitted_start + 40..omitted_start + 42]
                .try_into()
                .unwrap()
        ),
        SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1
    );
    assert!(
        encoded[omitted_start + 48..omitted_start + 80]
            .iter()
            .chain(encoded[omitted_start + 112..omitted_start + 144].iter())
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        u16::from_be_bytes(
            encoded[post_start + 40..post_start + 42]
                .try_into()
                .unwrap()
        ),
        SOURCE_OUTCOME_POST_POLICY_KIND_V1
    );

    for offset in [
        source_start + 80,
        source_start + 112,
        omitted_start + 48,
        omitted_start + 112,
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            SourceOutcomeTableV1::decode(&index, &mutated),
            Err(SourceOutcomeTableErrorV1::NoncanonicalConditionalFields),
            "offset {offset}"
        );
    }
}

#[test]
fn decode_rejects_truncation_trailing_and_allocation_count_attacks() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let encoded = SourceOutcomeTableV1::new(&receipt(), &index)
        .unwrap()
        .encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            SourceOutcomeTableV1::decode(&index, &encoded[..boundary]),
            Err(SourceOutcomeTableErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &trailing),
        Err(SourceOutcomeTableErrorV1::InvalidEncodedLength)
    );
    let mut allocation_attack = encoded;
    allocation_attack[56..64]
        .copy_from_slice(&(MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1 + 1).to_be_bytes());
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &allocation_attack),
        Err(SourceOutcomeTableErrorV1::EntryCountCap)
    );
}

#[test]
fn decode_rejects_header_version_counts_flags_and_every_reserved_byte() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let encoded = SourceOutcomeTableV1::new(&receipt(), &index)
        .unwrap()
        .encode();
    for (range, error) in [
        (0..8, SourceOutcomeTableErrorV1::InvalidMagic),
        (8..10, SourceOutcomeTableErrorV1::UnsupportedVersion),
        (10..12, SourceOutcomeTableErrorV1::UnsupportedSchema),
        (12..14, SourceOutcomeTableErrorV1::UnsupportedObjectKind),
        (14..16, SourceOutcomeTableErrorV1::InvalidEntryWidth),
        (16..18, SourceOutcomeTableErrorV1::NonzeroFlags),
    ] {
        let mut mutated = encoded.clone();
        mutated[range.start] ^= 1;
        assert_eq!(SourceOutcomeTableV1::decode(&index, &mutated), Err(error));
    }
    for offset in (18..24).chain(128..160) {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            SourceOutcomeTableV1::decode(&index, &mutated),
            Err(SourceOutcomeTableErrorV1::NonzeroReserved),
            "header offset {offset}"
        );
    }
    for entry_start in (0..3).map(|index| {
        SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1 + index * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1
    }) {
        let mut flags = encoded.clone();
        flags[entry_start + 42] = 1;
        assert_eq!(
            SourceOutcomeTableV1::decode(&index, &flags),
            Err(SourceOutcomeTableErrorV1::NonzeroFlags)
        );
        for offset in
            (entry_start + 44..entry_start + 48).chain(entry_start + 144..entry_start + 160)
        {
            let mut mutated = encoded.clone();
            mutated[offset] = 1;
            assert_eq!(
                SourceOutcomeTableV1::decode(&index, &mutated),
                Err(SourceOutcomeTableErrorV1::NonzeroReserved),
                "entry offset {offset}"
            );
        }
    }

    for count_offset in [64, 72, 80] {
        let mut mutated = encoded.clone();
        mutated[count_offset + 7] ^= 1;
        assert_eq!(
            SourceOutcomeTableV1::decode(&index, &mutated),
            Err(SourceOutcomeTableErrorV1::DeclaredCountsMismatch)
        );
    }
    let mut index_count = encoded;
    index_count[95] ^= 1;
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &index_count),
        Err(SourceOutcomeTableErrorV1::IndexEntryCountMismatch)
    );
}

#[test]
fn decode_rejects_unknown_outcomes_bad_ordinals_and_duplicate_identities() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let encoded = SourceOutcomeTableV1::new(&receipt(), &index)
        .unwrap()
        .encode();
    let first = SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1;
    let second = first + SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;
    let third = second + SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;

    let mut kind = encoded.clone();
    kind[first + 40..first + 42].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &kind),
        Err(SourceOutcomeTableErrorV1::UnsupportedOutcomeKind)
    );
    let mut ordinal = encoded.clone();
    ordinal[first + 7] = 1;
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &ordinal),
        Err(SourceOutcomeTableErrorV1::InvalidAcquisitionOrdinal)
    );
    let mut duplicate_source = encoded.clone();
    duplicate_source.copy_within(first + 8..first + 40, second + 8);
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &duplicate_source),
        Err(SourceOutcomeTableErrorV1::DuplicateSourceRecordId)
    );
    let mut duplicate_event = encoded.clone();
    duplicate_event.copy_within(first + 48..first + 80, third + 48);
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &duplicate_event),
        Err(SourceOutcomeTableErrorV1::DuplicatePersistedEventId)
    );
    let mut reversed = encoded;
    let first_entry = reversed[first..second].to_vec();
    let second_entry = reversed[second..third].to_vec();
    reversed[first..second].copy_from_slice(&second_entry);
    reversed[second..third].copy_from_slice(&first_entry);
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &reversed),
        Err(SourceOutcomeTableErrorV1::InvalidAcquisitionOrdinal)
    );
}

#[test]
fn index_digest_binds_the_exact_canonical_index_artifact() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let table = SourceOutcomeTableV1::new(&receipt(), &index).unwrap();
    assert_eq!(
        table.event_index_digest(),
        derive_event_expansion_index_digest_v1(&index)
    );

    let altered_source = EventExpansionIndexEntryV1::new(
        &catalog,
        event(0x10),
        EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap(),
        AuthorizedByteRangeV1::new(0, 7).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap();
    let altered_index = EventExpansionIndexV1::new(
        &catalog,
        vec![
            altered_source,
            post_policy_index_entry(&catalog, event(0x30), policy(0xa0), transformation(0xc0)),
        ],
    )
    .unwrap();
    assert_ne!(index.encode(), altered_index.encode());
    assert_eq!(
        SourceOutcomeTableV1::decode(&altered_index, &table.encode()),
        Err(SourceOutcomeTableErrorV1::IndexDigestMismatch)
    );

    let mut mutated = table.encode();
    mutated[96] ^= 1;
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &mutated),
        Err(SourceOutcomeTableErrorV1::IndexDigestMismatch)
    );
}

#[test]
fn decode_rejects_receipt_index_exactness_and_membership_mutations() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let encoded = SourceOutcomeTableV1::new(&receipt(), &index)
        .unwrap()
        .encode();
    let first = SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1;
    let third = first + 2 * SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1;

    let mut missing = encoded.clone();
    missing[third + 48..third + 80].fill(0x55);
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &missing),
        Err(SourceOutcomeTableErrorV1::MissingIndexEvent)
    );

    let mut exactness = encoded;
    exactness[third + 40..third + 42]
        .copy_from_slice(&SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1.to_be_bytes());
    exactness[third + 80..third + 144].fill(0);
    exactness[64..72].copy_from_slice(&2u64.to_be_bytes());
    exactness[72..80].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        SourceOutcomeTableV1::decode(&index, &exactness),
        Err(SourceOutcomeTableErrorV1::IndexExactnessMismatch)
    );
}

#[test]
fn foreign_receipt_order_is_rejected_without_being_required_for_decode() {
    let catalog = catalog();
    let index = event_index(&catalog);
    let table = SourceOutcomeTableV1::new(&receipt(), &index).unwrap();
    let foreign = AcquisitionReceipt::reconcile(
        retrieval(0xd0),
        [source(0x70), source(0x50), source(0x90)],
        [
            AcquisitionOutcomeAssignment::new(
                source(0x90),
                post_policy_outcome(event(0x30), policy(0xa0), transformation(0xc0)),
            ),
            AcquisitionOutcomeAssignment::new(source(0x50), source_exact_outcome(event(0x10))),
            AcquisitionOutcomeAssignment::new(
                source(0x70),
                AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: policy(0xe0),
                },
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        table.verify_against_receipt(&foreign),
        Err(SourceOutcomeTableErrorV1::ReceiptEntryMismatch)
    );
}

#[test]
fn debug_and_errors_never_expose_identity_or_policy_canaries() {
    const CANARY: &str = "SOURCE-OUTCOME-CANARY-SECRET";
    let mut canary = [0u8; 32];
    for (target, source) in canary.iter_mut().zip(CANARY.bytes().cycle()) {
        *target = source;
    }
    let catalog = catalog();
    let index = EventExpansionIndexV1::new(
        &catalog,
        vec![source_index_entry(&catalog, EventId::from_bytes(canary))],
    )
    .unwrap();
    let receipt = AcquisitionReceipt::reconcile(
        RetrievalId::from_bytes(canary),
        [SourceRecordId::from_bytes(canary)],
        [AcquisitionOutcomeAssignment::new(
            SourceRecordId::from_bytes(canary),
            source_exact_outcome(EventId::from_bytes(canary)),
        )],
    )
    .unwrap();
    let table = SourceOutcomeTableV1::new(&receipt, &index).unwrap();
    let output = format!(
        "{:?} {:?} {:?} {}",
        table,
        table.entries()[0],
        table.event_index_digest(),
        SourceOutcomeTableErrorV1::ReceiptEntryMismatch
    );
    assert!(!output.contains(CANARY));
    assert!(!output.contains("534f55524345"));
    assert_eq!(format!("{table:?}"), "SourceOutcomeTableV1(<redacted>)");
    assert_eq!(
        format!("{:?}", table.entries()[0]),
        "SourceOutcomeTableEntryV1(<redacted>)"
    );
}
