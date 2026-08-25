use evidentrail_schema::{EventId, ExactnessBasis, PolicyDigest, TransformationReceiptId};
use evidentrail_snapshot_format::{
    AuthorizedByteRangeV1, EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1,
    EVENT_EXPANSION_INDEX_HEADER_BYTES_V1, EVENT_EXPANSION_INDEX_OBJECT_KIND_V1,
    EVENT_EXPANSION_INDEX_SCHEMA_V1, EVENT_EXPANSION_INDEX_VERSION_V1,
    EVENT_EXPANSION_POST_POLICY_KIND_V1, EVENT_EXPANSION_SOURCE_EXACT_KIND_V1,
    EventExpansionIndexEntryV1, EventExpansionIndexErrorV1, EventExpansionIndexV1,
    EventFrameLocatorV1, FRAME_HEADER_BYTES_V1, FrameCommitmentV1, MAX_ENCODED_FRAME_BYTES_V1,
    MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1, SEGMENT_HEADER_BYTES_V1, SegmentCatalogEntryV1,
    SegmentCatalogV1, SegmentDigestV1, derive_segment_catalog_digest_v1,
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

fn source_entry(catalog: &SegmentCatalogV1, event_seed: u8) -> EventExpansionIndexEntryV1 {
    EventExpansionIndexEntryV1::new(
        catalog,
        event(event_seed),
        EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap(),
        AuthorizedByteRangeV1::new(0, 8).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap()
}

fn post_policy_entry(catalog: &SegmentCatalogV1, event_seed: u8) -> EventExpansionIndexEntryV1 {
    EventExpansionIndexEntryV1::new(
        catalog,
        event(event_seed),
        EventFrameLocatorV1::new(1, 3, 1, 228, 124).unwrap(),
        AuthorizedByteRangeV1::new(0, 16).unwrap(),
        ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes(sequential_bytes(0xa0)),
            transformation_receipt_id: TransformationReceiptId::from_bytes(sequential_bytes(0xc0)),
        },
    )
    .unwrap()
}

fn fixture(catalog: &SegmentCatalogV1) -> EventExpansionIndexV1 {
    EventExpansionIndexV1::new(
        catalog,
        vec![
            source_entry(catalog, 0x10),
            post_policy_entry(catalog, 0x30),
        ],
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
    let bytes = hex_vec(encoded);
    bytes.try_into().unwrap()
}

#[test]
fn exact_codec_and_independently_reconstructed_golden_hash_are_frozen() {
    let catalog = catalog();
    let index = fixture(&catalog);
    let expected = hex_vec(concat!(
        "455652454958303100010001000100a000000000000000000000000000000002",
        "0000000000000002000000000000000500000000000000f00000000000000018",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "74fe5ceaf3d33b501106c0636f575a34708e50b3aaf99816e0c48bce0b18340c",
        "00000000000000000000000000000000101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f00000000000000000000000000000000",
        "0000000000010001000000000000007800000074000000000000000800000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f00000000000000010000000000000003",
        "000000010001000200000000000000e40000007c000000000000001000000000",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "00000000000000000000000000000000"
    ));
    assert_eq!(
        expected.len(),
        EVENT_EXPANSION_INDEX_HEADER_BYTES_V1 + 2 * EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1
    );
    assert_eq!(index.encode(), expected);
    assert_eq!(index.encoded_len(), expected.len());

    // Independently reconstructed with Python 3 bytearray/int.to_bytes and
    // hashlib.sha256 from the frozen field offsets.
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(
        digest,
        hex_array("5235bc2cfeaff89accd46c6ea3565ee64f0dea1ab11612bf1e65fc3d9bf583d3")
    );

    let decoded = EventExpansionIndexV1::decode(&catalog, &expected).unwrap();
    assert_eq!(decoded, index);
    assert_eq!(decoded.version(), EVENT_EXPANSION_INDEX_VERSION_V1);
    assert_eq!(decoded.schema(), EVENT_EXPANSION_INDEX_SCHEMA_V1);
    assert_eq!(decoded.entry_count(), 2);
    assert_eq!(decoded.catalog_segment_count(), 2);
    assert_eq!(decoded.catalog_frame_count(), 5);
    assert_eq!(decoded.catalog_chain_root(), catalog.final_chain_root());
    assert_eq!(
        decoded.catalog_digest(),
        derive_segment_catalog_digest_v1(&catalog)
    );
    assert_eq!(decoded.total_indexed_frame_bytes(), 240);
    assert_eq!(decoded.total_authorized_bytes(), 24);
    assert_eq!(
        decoded.entries()[0].frame_object_kind(),
        evidentrail_snapshot_format::FrameObjectKindV1::AuthorizedOutcome
    );
    assert_eq!(
        decoded.entries()[0].exactness_basis(),
        ExactnessBasis::SourceExact
    );
    assert!(matches!(
        decoded.entries()[1].exactness_basis(),
        ExactnessBasis::PostPolicy { .. }
    ));
}

#[test]
fn construction_canonicalizes_event_order_and_rejects_duplicate_events_or_frames() {
    let catalog = catalog();
    let high = post_policy_entry(&catalog, 0x30);
    let low = source_entry(&catalog, 0x10);
    let canonical = EventExpansionIndexV1::new(&catalog, vec![high, low]).unwrap();
    assert_eq!(canonical.entries()[0].event_id(), event(0x10));
    assert_eq!(canonical.entries()[1].event_id(), event(0x30));

    let second_frame = EventExpansionIndexEntryV1::new(
        &catalog,
        event(0x10),
        EventFrameLocatorV1::new(0, 1, 1, 236, 108).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap();
    assert_eq!(
        EventExpansionIndexV1::new(&catalog, vec![low, second_frame]),
        Err(EventExpansionIndexErrorV1::DuplicateEventId)
    );

    let same_frame = EventExpansionIndexEntryV1::new(
        &catalog,
        event(0x20),
        low.frame_locator(),
        AuthorizedByteRangeV1::new(1, 2).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap();
    assert_eq!(
        EventExpansionIndexV1::new(&catalog, vec![low, same_frame]),
        Err(EventExpansionIndexErrorV1::DuplicateFrameAssignment)
    );
}

#[test]
fn locator_validation_rejects_unknown_sequences_overflow_and_out_of_frame_bytes() {
    let catalog = catalog();
    assert_eq!(
        EventFrameLocatorV1::new(0, 0, 0, 120, 107),
        Err(EventExpansionIndexErrorV1::InvalidFrameEncodedLength)
    );
    assert_eq!(
        EventFrameLocatorV1::new(
            0,
            0,
            0,
            120,
            u32::try_from(MAX_ENCODED_FRAME_BYTES_V1 + 1).unwrap(),
        ),
        Err(EventExpansionIndexErrorV1::FrameEncodedLengthCap)
    );
    assert_eq!(
        EventFrameLocatorV1::new(0, 0, 0, u64::MAX, 108),
        Err(EventExpansionIndexErrorV1::FrameRangeOverflow)
    );
    assert_eq!(
        AuthorizedByteRangeV1::new(u32::MAX, 1),
        Err(EventExpansionIndexErrorV1::AuthorizedByteRangeOverflow)
    );

    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(2, 5, 0, 120, 108).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        EventExpansionIndexErrorV1::UnknownSegment,
    );
    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(0, 2, 2, 336, 108).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        EventExpansionIndexErrorV1::SegmentFrameSequenceOutOfRange,
    );
    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(0, 1, 0, 120, 116).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        EventExpansionIndexErrorV1::FrameSequenceMismatch,
    );
    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(0, 0, 0, 119, 116).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        EventExpansionIndexErrorV1::FrameOutsideSegment,
    );
    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(0, 0, 0, 120, 117).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        EventExpansionIndexErrorV1::FrameOutsideSegment,
    );
    assert_entry_error(
        &catalog,
        EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap(),
        AuthorizedByteRangeV1::new(1, 8).unwrap(),
        EventExpansionIndexErrorV1::AuthorizedBytesOutsideFrame,
    );
}

#[test]
fn index_rejects_overlapping_frame_locations_and_more_entries_than_catalog_frames() {
    let catalog = catalog();
    let first = source_entry(&catalog, 0x10);
    let overlapping = EventExpansionIndexEntryV1::new(
        &catalog,
        event(0x20),
        EventFrameLocatorV1::new(0, 1, 1, 228, 108).unwrap(),
        AuthorizedByteRangeV1::new(0, 0).unwrap(),
        ExactnessBasis::SourceExact,
    )
    .unwrap();
    assert_eq!(
        EventExpansionIndexV1::new(&catalog, vec![first, overlapping]),
        Err(EventExpansionIndexErrorV1::FrameLocatorOverlap)
    );

    let excess = (0u8..6)
        .map(|seed| {
            EventExpansionIndexEntryV1::new(
                &catalog,
                EventId::from_bytes([seed + 1; 32]),
                first.frame_locator(),
                AuthorizedByteRangeV1::new(0, 0).unwrap(),
                ExactnessBasis::SourceExact,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        EventExpansionIndexV1::new(&catalog, excess),
        Err(EventExpansionIndexErrorV1::EntryCountExceedsCatalogFrames)
    );

    let empty = EventExpansionIndexV1::new(&catalog, Vec::new()).unwrap();
    assert_eq!(empty.entry_count(), 0);
    assert_eq!(empty.total_indexed_frame_bytes(), 0);
    assert_eq!(empty.total_authorized_bytes(), 0);
    assert_eq!(
        EventExpansionIndexV1::decode(&catalog, &empty.encode()).unwrap(),
        empty
    );
}

#[test]
fn exactness_fields_use_the_full_typed_id_domain_and_remain_canonical() {
    let catalog = catalog();
    let locator = EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap();
    let range = AuthorizedByteRangeV1::new(0, 8).unwrap();
    let all_zero_post_policy = EventExpansionIndexEntryV1::new(
        &catalog,
        EventId::from_bytes([0; 32]),
        locator,
        range,
        ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([0; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([0; 32]),
        },
    )
    .unwrap();
    assert_eq!(
        EventExpansionIndexEntryV1::decode(&catalog, &all_zero_post_policy.encode()).unwrap(),
        all_zero_post_policy
    );

    let source = source_entry(&catalog, 0x10).encode();
    for boundary in 0..EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1 {
        assert_eq!(
            EventExpansionIndexEntryV1::decode(&catalog, &source[..boundary]),
            Err(EventExpansionIndexErrorV1::InvalidEncodedLength)
        );
    }
    let mut trailing = source.to_vec();
    trailing.push(0);
    assert_eq!(
        EventExpansionIndexEntryV1::decode(&catalog, &trailing),
        Err(EventExpansionIndexErrorV1::InvalidEncodedLength)
    );
    assert_eq!(
        u16::from_be_bytes(source[54..56].try_into().unwrap()),
        EVENT_EXPANSION_SOURCE_EXACT_KIND_V1
    );
    assert!(source[80..144].iter().all(|byte| *byte == 0));
    let mut mutated = source;
    mutated[80] = 1;
    assert_eq!(
        EventExpansionIndexEntryV1::decode(&catalog, &mutated),
        Err(EventExpansionIndexErrorV1::NoncanonicalSourceExactFields)
    );

    let post_policy = post_policy_entry(&catalog, 0x30).encode();
    assert_eq!(
        u16::from_be_bytes(post_policy[54..56].try_into().unwrap()),
        EVENT_EXPANSION_POST_POLICY_KIND_V1
    );
    let mut mutated = post_policy;
    mutated[54..56].copy_from_slice(&3u16.to_be_bytes());
    assert_eq!(
        EventExpansionIndexEntryV1::decode(&catalog, &mutated),
        Err(EventExpansionIndexErrorV1::UnsupportedExactnessKind)
    );
}

#[test]
fn decode_rejects_every_truncation_trailing_data_and_count_allocation_attack() {
    let catalog = catalog();
    let encoded = fixture(&catalog).encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            EventExpansionIndexV1::decode(&catalog, &encoded[..boundary]),
            Err(EventExpansionIndexErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        EventExpansionIndexV1::decode(&catalog, &trailing),
        Err(EventExpansionIndexErrorV1::InvalidEncodedLength)
    );

    let mut excessive = encoded;
    excessive[24..32].copy_from_slice(&(MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1 + 1).to_be_bytes());
    assert_eq!(
        EventExpansionIndexV1::decode(&catalog, &excessive),
        Err(EventExpansionIndexErrorV1::EntryCountCap)
    );

    let mut more_than_catalog = fixture(&catalog).encode();
    more_than_catalog[24..32].copy_from_slice(&6u64.to_be_bytes());
    assert_eq!(
        EventExpansionIndexV1::decode(&catalog, &more_than_catalog),
        Err(EventExpansionIndexErrorV1::EntryCountExceedsCatalogFrames)
    );
}

#[test]
fn decode_rejects_unknown_kinds_versions_widths_and_every_reserved_byte() {
    let catalog = catalog();
    let encoded = fixture(&catalog).encode();

    let mut mutated = encoded.clone();
    mutated[0] ^= 1;
    assert_decode_error(&catalog, &mutated, EventExpansionIndexErrorV1::InvalidMagic);
    let mut mutated = encoded.clone();
    mutated[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::UnsupportedVersion,
    );
    let mut mutated = encoded.clone();
    mutated[10..12].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::UnsupportedSchema,
    );
    let mut mutated = encoded.clone();
    mutated[12..14].copy_from_slice(&(EVENT_EXPANSION_INDEX_OBJECT_KIND_V1 + 1).to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::UnsupportedIndexObjectKind,
    );
    let mut mutated = encoded.clone();
    mutated[14..16].copy_from_slice(&159u16.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::InvalidEntryWidth,
    );
    let mut mutated = encoded.clone();
    mutated[16] = 1;
    assert_decode_error(&catalog, &mutated, EventExpansionIndexErrorV1::NonzeroFlags);

    for offset in (18..24).chain(128..144) {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_decode_error(
            &catalog,
            &mutated,
            EventExpansionIndexErrorV1::NonzeroReserved,
        );
    }
    for entry_start in [144usize, 304] {
        for relative in (76..80).chain(144..160) {
            let mut mutated = encoded.clone();
            mutated[entry_start + relative] = 1;
            assert_decode_error(
                &catalog,
                &mutated,
                EventExpansionIndexErrorV1::NonzeroReserved,
            );
        }
    }
    let mut mutated = encoded;
    mutated[144 + 52..144 + 54].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::UnsupportedFrameObjectKind,
    );
}

#[test]
fn decode_reconciles_catalog_binding_totals_and_canonical_event_order() {
    let catalog = catalog();
    let encoded = fixture(&catalog).encode();

    let mut mutated = encoded.clone();
    mutated[32..40].copy_from_slice(&3u64.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::CatalogSegmentCountMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[40..48].copy_from_slice(&6u64.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::CatalogFrameCountMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[64] ^= 1;
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::CatalogChainRootMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[96] ^= 1;
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::CatalogDigestMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[48..56].copy_from_slice(&241u64.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::TotalFrameBytesMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[56..64].copy_from_slice(&25u64.to_be_bytes());
    assert_decode_error(
        &catalog,
        &mutated,
        EventExpansionIndexErrorV1::TotalAuthorizedBytesMismatch,
    );

    let mut reversed = encoded.clone();
    let first = reversed[144..304].to_vec();
    let second = reversed[304..464].to_vec();
    reversed[144..304].copy_from_slice(&second);
    reversed[304..464].copy_from_slice(&first);
    assert_decode_error(
        &catalog,
        &reversed,
        EventExpansionIndexErrorV1::NoncanonicalEventOrder,
    );

    let mut duplicate = encoded;
    let first_event = duplicate[144..176].to_vec();
    duplicate[304..336].copy_from_slice(&first_event);
    assert_decode_error(
        &catalog,
        &duplicate,
        EventExpansionIndexErrorV1::DuplicateEventId,
    );
}

#[test]
fn decoding_against_a_different_catalog_fails_before_locator_use() {
    let catalog = catalog();
    let encoded = fixture(&catalog).encode();

    let fewer_segments = SegmentCatalogV1::new(vec![segment(0, 0, 2, 40, 1, 2)]).unwrap();
    assert_decode_error(
        &fewer_segments,
        &encoded,
        EventExpansionIndexErrorV1::CatalogSegmentCountMismatch,
    );

    let fewer_frames = SegmentCatalogV1::new(vec![
        segment(0, 0, 1, 16, 1, 2),
        segment(1, 1, 3, 48, 3, 0x80),
    ])
    .unwrap();
    assert_decode_error(
        &fewer_frames,
        &encoded,
        EventExpansionIndexErrorV1::CatalogFrameCountMismatch,
    );

    let different_root = SegmentCatalogV1::new(vec![
        segment(0, 0, 2, 40, 1, 2),
        segment(1, 2, 3, 64, 3, 0x81),
    ])
    .unwrap();
    assert_decode_error(
        &different_root,
        &encoded,
        EventExpansionIndexErrorV1::CatalogChainRootMismatch,
    );

    let different_exact_catalog = SegmentCatalogV1::new(vec![
        segment(0, 0, 2, 40, 0x11, 0x40),
        segment(1, 2, 3, 64, 0x61, 0x80),
    ])
    .unwrap();
    assert_eq!(
        different_exact_catalog.segment_count(),
        catalog.segment_count()
    );
    assert_eq!(
        different_exact_catalog.total_frame_count(),
        catalog.total_frame_count()
    );
    assert_eq!(
        different_exact_catalog.final_chain_root(),
        catalog.final_chain_root()
    );
    assert_decode_error(
        &different_exact_catalog,
        &encoded,
        EventExpansionIndexErrorV1::CatalogDigestMismatch,
    );
}

#[test]
fn debug_and_errors_never_expose_event_policy_receipt_or_location_canaries() {
    const CANARY: &str = "EVENT-INDEX-CANARY-SECRET";
    let catalog = catalog();
    let mut canary_bytes = [0u8; 32];
    for (target, source) in canary_bytes.iter_mut().zip(CANARY.bytes().cycle()) {
        *target = source;
    }
    let locator = EventFrameLocatorV1::new(0, 0, 0, 120, 116).unwrap();
    let range = AuthorizedByteRangeV1::new(0, 8).unwrap();
    let entry = EventExpansionIndexEntryV1::new(
        &catalog,
        EventId::from_bytes(canary_bytes),
        locator,
        range,
        ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes(canary_bytes),
            transformation_receipt_id: TransformationReceiptId::from_bytes(canary_bytes),
        },
    )
    .unwrap();
    let index = EventExpansionIndexV1::new(&catalog, vec![entry]).unwrap();
    let output = format!(
        "{locator:?} {range:?} {entry:?} {index:?} {:?} {:?} {}",
        index.catalog_digest(),
        EventExpansionIndexErrorV1::NoncanonicalSourceExactFields,
        EventExpansionIndexErrorV1::FrameOutsideSegment
    );
    assert!(!output.contains(CANARY));
    assert!(!output.contains("4556454e54"));
    assert_eq!(
        format!("{entry:?}"),
        "EventExpansionIndexEntryV1(<redacted>)"
    );
    assert_eq!(format!("{index:?}"), "EventExpansionIndexV1(<redacted>)");
}

fn assert_entry_error(
    catalog: &SegmentCatalogV1,
    locator: EventFrameLocatorV1,
    range: AuthorizedByteRangeV1,
    expected: EventExpansionIndexErrorV1,
) {
    assert_eq!(
        EventExpansionIndexEntryV1::new(
            catalog,
            event(1),
            locator,
            range,
            ExactnessBasis::SourceExact,
        ),
        Err(expected)
    );
}

fn assert_decode_error(
    catalog: &SegmentCatalogV1,
    encoded: &[u8],
    expected: EventExpansionIndexErrorV1,
) {
    assert_eq!(
        EventExpansionIndexV1::decode(catalog, encoded),
        Err(expected)
    );
}
