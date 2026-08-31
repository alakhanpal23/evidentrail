use evidentrail_snapshot_format::{
    FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1, MAX_FRAME_CIPHERTEXT_BYTES_V1,
    MAX_FRAMES_PER_SEGMENT_V1, MAX_SEGMENT_CIPHERTEXT_BYTES_V1, MAX_SEGMENT_ENCODED_BYTES_V1,
    MAX_SEGMENTS_PER_RESULT_V1, MAX_TOTAL_FRAMES_PER_RESULT_V1,
    MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1, MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1,
    SEGMENT_CATALOG_ENTRY_BYTES_V1, SEGMENT_CATALOG_HEADER_BYTES_V1, SEGMENT_CATALOG_SCHEMA_V1,
    SEGMENT_CATALOG_VERSION_V1, SEGMENT_HEADER_BYTES_V1, SegmentCatalogEntryV1,
    SegmentCatalogErrorV1, SegmentCatalogV1, SegmentDigestV1, derive_segment_digest_v1,
};
use sha2::{Digest, Sha256};

fn sequential_bytes(start: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(u8::try_from(offset).unwrap());
    }
    bytes
}

fn entry(
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

fn fixture() -> SegmentCatalogV1 {
    SegmentCatalogV1::new(vec![
        entry(0, 0, 2, 40, 0x10, 0x40),
        entry(1, 2, 3, 64, 0x60, 0x80),
    ])
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

#[test]
fn exact_codec_and_independently_reconstructed_golden_hash_are_frozen() {
    let catalog = fixture();
    let expected = hex_vec(concat!(
        "4556525343473031000100010070000000000000000000020000000000000005",
        "00000000000003240000000000000068808182838485868788898a8b8c8d8e8f",
        "909192939495969798999a9b9c9d9e9f00000000000000000000000000000000",
        "0000000000000000000000000000000000000002000000000000000000000158",
        "0000000000000028101112131415161718191a1b1c1d1e1f2021222324252627",
        "28292a2b2c2d2e2f404142434445464748494a4b4c4d4e4f5051525354555657",
        "58595a5b5c5d5e5f000000000000000000000000000000010000000000000002",
        "000000030000000000000000000001cc00000000000000406061626364656667",
        "68696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
        "88898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000000"
    ));
    assert_eq!(
        expected.len(),
        SEGMENT_CATALOG_HEADER_BYTES_V1 + 2 * SEGMENT_CATALOG_ENTRY_BYTES_V1
    );
    assert_eq!(catalog.encoded_len(), expected.len());
    assert_eq!(catalog.encode(), expected);

    // Independently reconstructed with Python 3 bytearray/int.to_bytes and
    // hashlib.sha256 from the documented offsets, not from this Rust codec.
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(
        digest,
        sequential_hex("c5d7a448b5fdb9f788524674457062b92c3d28152ceb8bc1eb359f5d91d16307")
    );

    let decoded = SegmentCatalogV1::decode(&expected).unwrap();
    assert_eq!(decoded, catalog);
    assert_eq!(decoded.version(), SEGMENT_CATALOG_VERSION_V1);
    assert_eq!(decoded.schema(), SEGMENT_CATALOG_SCHEMA_V1);
    assert_eq!(decoded.segment_count(), 2);
    assert_eq!(decoded.total_frame_count(), 5);
    assert_eq!(decoded.total_encoded_byte_count(), 804);
    assert_eq!(decoded.total_ciphertext_byte_count(), 104);
    assert_eq!(
        decoded.final_chain_root(),
        FrameCommitmentV1::from_bytes(sequential_bytes(0x80))
    );
    assert_eq!(decoded.entries()[0].global_frame_end_exclusive(), 2);
    assert_eq!(decoded.entries()[1].global_frame_end_exclusive(), 5);
}

#[test]
fn entry_construction_checks_positive_frames_ranges_and_exact_byte_accounting() {
    let digest = SegmentDigestV1::from_bytes([1; 32]);
    let commitment = FrameCommitmentV1::from_bytes([2; 32]);
    assert_eq!(
        SegmentCatalogEntryV1::new(0, 0, 0, 120, 0, digest, commitment),
        Err(SegmentCatalogErrorV1::InvalidFrameCount)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(
            0,
            0,
            MAX_FRAMES_PER_SEGMENT_V1 + 1,
            120,
            16,
            digest,
            commitment,
        ),
        Err(SegmentCatalogErrorV1::FrameCountCap)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(0, u64::MAX, 1, 228, 16, digest, commitment),
        Err(SegmentCatalogErrorV1::GlobalFrameRangeOverflow)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(0, 0, 2, 335, 31, digest, commitment),
        Err(SegmentCatalogErrorV1::InvalidCiphertextByteCount)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(
            0,
            0,
            1,
            120 + 92 + MAX_FRAME_CIPHERTEXT_BYTES_V1 as u64 + 1,
            MAX_FRAME_CIPHERTEXT_BYTES_V1 as u64 + 1,
            digest,
            commitment,
        ),
        Err(SegmentCatalogErrorV1::CiphertextByteCountCap)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(0, 0, 1, 227, 16, digest, commitment),
        Err(SegmentCatalogErrorV1::InvalidSegmentByteCount)
    );
    assert_eq!(
        SegmentCatalogEntryV1::new(
            0,
            0,
            1,
            MAX_SEGMENT_ENCODED_BYTES_V1 + 1,
            16,
            digest,
            commitment,
        ),
        Err(SegmentCatalogErrorV1::SegmentByteCountCap)
    );

    let maximum = SegmentCatalogEntryV1::new(
        0,
        0,
        MAX_FRAMES_PER_SEGMENT_V1,
        MAX_SEGMENT_ENCODED_BYTES_V1,
        MAX_SEGMENT_CIPHERTEXT_BYTES_V1,
        digest,
        commitment,
    )
    .unwrap();
    assert_eq!(maximum.frame_count(), MAX_FRAMES_PER_SEGMENT_V1);
    assert_eq!(maximum.encoded_byte_count(), MAX_SEGMENT_ENCODED_BYTES_V1);
    assert_eq!(
        maximum.ciphertext_byte_count(),
        MAX_SEGMENT_CIPHERTEXT_BYTES_V1
    );

    let minimum = entry(0, 0, 1, FRAME_TAG_BYTES_V1 as u64, 3, 4);
    assert_eq!(minimum.encoded_byte_count(), 228);
}

#[test]
fn catalog_rejects_empty_excess_gapped_overlapping_and_reordered_inputs() {
    assert_eq!(
        SegmentCatalogV1::new(Vec::new()),
        Err(SegmentCatalogErrorV1::EmptyCatalog)
    );

    let excess: Vec<_> = (0..=MAX_SEGMENTS_PER_RESULT_V1)
        .map(|index| entry(index, index, 1, 16, 1, 2))
        .collect();
    assert_eq!(
        SegmentCatalogV1::new(excess),
        Err(SegmentCatalogErrorV1::SegmentCountCap)
    );

    assert_eq!(
        SegmentCatalogV1::new(vec![entry(1, 0, 1, 16, 1, 2)]),
        Err(SegmentCatalogErrorV1::SegmentSequenceMismatch)
    );
    assert_eq!(
        SegmentCatalogV1::new(vec![entry(0, 0, 2, 32, 1, 2), entry(2, 2, 1, 16, 3, 4),]),
        Err(SegmentCatalogErrorV1::SegmentSequenceMismatch)
    );
    assert_eq!(
        SegmentCatalogV1::new(vec![entry(0, 0, 2, 32, 1, 2), entry(1, 3, 1, 16, 3, 4),]),
        Err(SegmentCatalogErrorV1::GlobalFrameRangeMismatch)
    );
    assert_eq!(
        SegmentCatalogV1::new(vec![entry(0, 0, 2, 32, 1, 2), entry(1, 1, 1, 16, 3, 4),]),
        Err(SegmentCatalogErrorV1::GlobalFrameRangeMismatch)
    );
}

#[test]
fn decode_rejects_every_truncation_trailing_data_and_count_allocation_attack() {
    let encoded = fixture().encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            SegmentCatalogV1::decode(&encoded[..boundary]),
            Err(SegmentCatalogErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SegmentCatalogV1::decode(&trailing),
        Err(SegmentCatalogErrorV1::InvalidEncodedLength)
    );

    let mut excess_count = encoded;
    excess_count[16..24].copy_from_slice(&(MAX_SEGMENTS_PER_RESULT_V1 + 1).to_be_bytes());
    assert_eq!(
        SegmentCatalogV1::decode(&excess_count),
        Err(SegmentCatalogErrorV1::SegmentCountCap)
    );
}

#[test]
fn decode_rejects_unknown_fixed_fields_and_every_reserved_byte() {
    let encoded = fixture().encode();

    let mut mutated = encoded.clone();
    mutated[0] ^= 1;
    assert_decode_error(&mutated, SegmentCatalogErrorV1::InvalidMagic);
    let mut mutated = encoded.clone();
    mutated[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::UnsupportedVersion);
    let mut mutated = encoded.clone();
    mutated[10..12].copy_from_slice(&2u16.to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::UnsupportedSchema);
    let mut mutated = encoded.clone();
    mutated[12..14].copy_from_slice(&111u16.to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::InvalidEntryWidth);
    let mut mutated = encoded.clone();
    mutated[14] = 1;
    assert_decode_error(&mutated, SegmentCatalogErrorV1::NonzeroFlags);

    for offset in 80..96 {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_decode_error(&mutated, SegmentCatalogErrorV1::NonzeroReserved);
    }
    for entry_start in [96usize, 208] {
        for relative in (20..24).chain(104..112) {
            let mut mutated = encoded.clone();
            mutated[entry_start + relative] = 1;
            assert_decode_error(&mutated, SegmentCatalogErrorV1::NonzeroReserved);
        }
    }
}

#[test]
fn decode_reconciles_declared_totals_caps_and_final_chain_root() {
    let encoded = fixture().encode();

    let mut mutated = encoded.clone();
    mutated[24..32].copy_from_slice(&6u64.to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::TotalFrameCountMismatch);
    let mut mutated = encoded.clone();
    mutated[32..40].copy_from_slice(&805u64.to_be_bytes());
    assert_decode_error(
        &mutated,
        SegmentCatalogErrorV1::TotalSegmentByteCountMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[40..48].copy_from_slice(&105u64.to_be_bytes());
    assert_decode_error(
        &mutated,
        SegmentCatalogErrorV1::TotalCiphertextByteCountMismatch,
    );
    let mut mutated = encoded.clone();
    mutated[48] ^= 1;
    assert_decode_error(&mutated, SegmentCatalogErrorV1::FinalChainRootMismatch);

    let mut mutated = encoded.clone();
    mutated[24..32].copy_from_slice(&(MAX_TOTAL_FRAMES_PER_RESULT_V1 + 1).to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::TotalFrameCountCap);
    let mut mutated = encoded.clone();
    mutated[32..40].copy_from_slice(&(MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1 + 1).to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::TotalSegmentByteCountCap);
    let mut mutated = encoded;
    mutated[40..48].copy_from_slice(&(MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1 + 1).to_be_bytes());
    assert_decode_error(&mutated, SegmentCatalogErrorV1::TotalCiphertextByteCountCap);
}

#[test]
fn entry_decode_rejects_invalid_counts_ranges_bytes_and_reserved_regions() {
    let canonical = entry(0, 0, 2, 40, 1, 2).encode();
    for boundary in 0..SEGMENT_CATALOG_ENTRY_BYTES_V1 {
        assert_eq!(
            SegmentCatalogEntryV1::decode(&canonical[..boundary]),
            Err(SegmentCatalogErrorV1::InvalidEncodedLength)
        );
    }
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert_eq!(
        SegmentCatalogEntryV1::decode(&trailing),
        Err(SegmentCatalogErrorV1::InvalidEncodedLength)
    );

    let mut mutated = canonical;
    mutated[16..20].fill(0);
    assert_eq!(
        SegmentCatalogEntryV1::decode(&mutated),
        Err(SegmentCatalogErrorV1::InvalidFrameCount)
    );
    let mut mutated = canonical;
    mutated[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        SegmentCatalogEntryV1::decode(&mutated),
        Err(SegmentCatalogErrorV1::GlobalFrameRangeOverflow)
    );
    let mut mutated = canonical;
    mutated[32..40].copy_from_slice(&31u64.to_be_bytes());
    assert_eq!(
        SegmentCatalogEntryV1::decode(&mutated),
        Err(SegmentCatalogErrorV1::InvalidCiphertextByteCount)
    );
    let mut mutated = canonical;
    mutated[24..32].copy_from_slice(&343u64.to_be_bytes());
    assert_eq!(
        SegmentCatalogEntryV1::decode(&mutated),
        Err(SegmentCatalogErrorV1::InvalidSegmentByteCount)
    );
}

#[test]
fn segment_digest_is_exact_sha256_of_the_complete_segment_bytes() {
    let digest = derive_segment_digest_v1(b"abc");
    assert_eq!(
        *digest.as_bytes(),
        sequential_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_ne!(derive_segment_digest_v1(b"abc\0"), digest);
}

#[test]
fn public_debug_and_errors_never_expose_catalog_material() {
    const CANARY: &str = "SEGMENT-CATALOG-CANARY-SECRET";
    let mut canary_bytes = [0u8; 32];
    for (target, source) in canary_bytes.iter_mut().zip(CANARY.bytes().cycle()) {
        *target = source;
    }
    let entry = SegmentCatalogEntryV1::new(
        0,
        0,
        1,
        228,
        16,
        SegmentDigestV1::from_bytes(canary_bytes),
        FrameCommitmentV1::from_bytes(canary_bytes),
    )
    .unwrap();
    let catalog = SegmentCatalogV1::new(vec![entry]).unwrap();
    let output = format!(
        "{entry:?} {:?} {catalog:?} {:?} {}",
        entry.segment_digest(),
        SegmentCatalogErrorV1::FinalChainRootMismatch,
        SegmentCatalogErrorV1::InvalidSegmentByteCount
    );
    assert!(!output.contains(CANARY));
    assert!(!output.contains("5345474d454e54"));
    assert_eq!(format!("{entry:?}"), "SegmentCatalogEntryV1(<redacted>)");
    assert_eq!(format!("{catalog:?}"), "SegmentCatalogV1(<redacted>)");
}

fn assert_decode_error(encoded: &[u8], expected: SegmentCatalogErrorV1) {
    assert_eq!(SegmentCatalogV1::decode(encoded), Err(expected));
}

fn sequential_hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap();
    }
    output
}
