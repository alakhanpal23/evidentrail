use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt,
    AdapterIdentity, AdapterOutcome, AttemptCounts, CapKind, CapUsage, CompletenessProof,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchErrorCode, FetchIdentity,
    FetchPartialReason, FetchPartialReasons, FetchTiming, FetchUnknownReason, HighWaterMark,
    PlanDigest, PlanId, PolicyDigest, RetrievalId, SourceCursor, SourceMember, SourceRecordId,
    UnixTimestampNanos,
};
use evidentrail_snapshot_format::{
    ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1, ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1,
    ACQUISITION_COMPLETION_HEADER_BYTES_V1, ACQUISITION_COMPLETION_SCHEMA_V1,
    ACQUISITION_COMPLETION_VERSION_V1, AcquisitionCompletionRecordErrorV1,
    AcquisitionCompletionRecordV1, MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
    MAX_ACQUISITION_CAP_USAGES_V1, MAX_ACQUISITION_CURSOR_BYTES_V1, MAX_ACQUISITION_ERROR_CODES_V1,
    MAX_ACQUISITION_HIGH_WATER_MARKS_V1, MAX_ACQUISITION_PARTIAL_REASONS_V1,
    MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1,
};
use sha2::{Digest, Sha256};

fn sequential_bytes(start: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(u8::try_from(offset).unwrap());
    }
    bytes
}

fn cursor(bytes: impl Into<Vec<u8>>) -> SourceCursor {
    SourceCursor::new(bytes).unwrap()
}

fn member(bytes: impl Into<Vec<u8>>) -> SourceMember {
    SourceMember::new(bytes).unwrap()
}

fn identity(adapter_kind: String, adapter_version: String) -> FetchIdentity {
    FetchIdentity::new(
        RetrievalId::from_bytes(sequential_bytes(0x10)),
        PlanId::from_bytes(sequential_bytes(0x30)),
        PlanDigest::from_bytes([0; 32]),
        AdapterIdentity::new(adapter_kind, adapter_version).unwrap(),
    )
}

fn build_partial(
    identity: FetchIdentity,
    boundaries: FetchBoundaries,
    cap_usage: Vec<CapUsage>,
    error_codes: Vec<FetchErrorCode>,
    reasons: FetchPartialReasons,
    continuation: Option<SourceCursor>,
) -> FetchCompletion {
    FetchCompletion::new(
        identity,
        FetchTiming::new(
            UnixTimestampNanos::new(-5),
            UnixTimestampNanos::new(123_456_789),
        ),
        AcknowledgedCounts::new(3, 20, 24),
        AttemptCounts::new(2, 1),
        AttemptCounts::new(4, 2),
        boundaries,
        cap_usage,
        AdapterOutcome::ProviderStopped,
        error_codes,
        FetchCompleteness::partial(reasons, continuation),
    )
    .unwrap()
}

fn partial_fixture() -> FetchCompletion {
    build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(
            Some(cursor(vec![0, b'f', 0xff])),
            Some(cursor(b"final".to_vec())),
            [
                HighWaterMark::new(member(b"member-b".to_vec()), cursor(vec![0x80, 0])),
                HighWaterMark::new(member(b"member-a".to_vec()), cursor(b"cursor".to_vec())),
            ],
        ),
        vec![
            CapUsage::new(CapKind::Records, 3, 10, false),
            CapUsage::new(
                CapKind::OtherVersioned {
                    version: 0,
                    code: 0,
                },
                4,
                4,
                true,
            ),
        ],
        vec![
            FetchErrorCode::ProviderFailure,
            FetchErrorCode::OtherVersioned {
                version: 0,
                code: 0,
            },
        ],
        FetchPartialReasons::with_additional(
            FetchPartialReason::PageCap,
            [
                FetchPartialReason::PageCap,
                FetchPartialReason::OtherVersioned {
                    version: 0,
                    code: 0,
                },
            ],
        ),
        Some(cursor(b"next\0".to_vec())),
    )
}

fn receipt(retrieval_id: RetrievalId, count: u8) -> AcquisitionReceipt {
    let expected = (0..count)
        .map(|value| SourceRecordId::from_bytes([value.wrapping_add(1); 32]))
        .collect::<Vec<_>>();
    let assignments = expected
        .iter()
        .enumerate()
        .map(|(index, source_record_id)| {
            AcquisitionOutcomeAssignment::new(
                *source_record_id,
                AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes([u8::try_from(index).unwrap(); 32]),
                },
            )
        })
        .collect::<Vec<_>>();
    AcquisitionReceipt::reconcile(retrieval_id, expected, assignments).unwrap()
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

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn section_offsets(encoded: &[u8]) -> (usize, usize, usize, usize) {
    let variable_prefix = [220, 224, 228, 232, 236]
        .into_iter()
        .map(|offset| usize::try_from(read_u32(encoded, offset)).unwrap())
        .sum::<usize>();
    let high_water_start = ACQUISITION_COMPLETION_HEADER_BYTES_V1 + variable_prefix;
    let cap_start = high_water_start + usize::try_from(read_u32(encoded, 256)).unwrap();
    let error_start = cap_start
        + usize::try_from(read_u32(encoded, 244)).unwrap()
            * ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1;
    let reason_start = error_start
        + usize::try_from(read_u32(encoded, 248)).unwrap()
            * ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1;
    (high_water_start, cap_start, error_start, reason_start)
}

#[test]
fn exact_codec_and_independently_reconstructed_golden_hash_are_frozen() {
    let completion = partial_fixture();
    let record = AcquisitionCompletionRecordV1::new_verified(
        &completion,
        &receipt(completion.identity().retrieval_id(), 3),
    )
    .unwrap();
    let expected = hex_vec(concat!(
        "45565241434d3031000100010001012000070000000000001011121314151617",
        "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        "38393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f0000000000000000",
        "000000000000000000000000000000000000000000000000ffffffffffffffff",
        "fffffffffffffffb000000000000000000000000075bcd150000000000000003",
        "0000000000000014000000000000001800000000000000020000000000000001",
        "0000000000000004000000000000000200040002000000000000000000000007",
        "0000000200000003000000050000000500000002000000020000000200000003",
        "00000038000001ea000000000000000000000000000000000000000000000000",
        "6669787475726576310066ff66696e616c6e6578740000000000000000080000",
        "0002000000006d656d6265722d62800000000001000000080000000600000000",
        "6d656d6265722d61637572736f72000000000001000000000000000000000000",
        "000000000003000000000000000a00000001ffff000100000000000000000000",
        "000000000004000000000000000400000000000500000000000000000001ffff",
        "0000000000000000000000050000000000000000000100050000000000000000",
        "0002ffff000000000000"
    ));
    assert_eq!(expected.len(), 490);
    assert_eq!(record.encoded_len(), expected.len());
    assert_eq!(record.encode(), expected);
    // Independently reconstructed with Python bytearray/int.to_bytes and
    // hashlib.sha256 from the frozen offsets and code table.
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&expected)),
        hex_array("1ce0c151a11f47cb041da7ffc6e164a076f7acf12732ad8363791575b51f91be")
    );

    let restored = AcquisitionCompletionRecordV1::decode(&expected).unwrap();
    assert_eq!(restored, record);
    assert_eq!(restored.version(), ACQUISITION_COMPLETION_VERSION_V1);
    assert_eq!(restored.schema(), ACQUISITION_COMPLETION_SCHEMA_V1);
    assert_eq!(restored.to_fetch_completion(), completion);
}

#[test]
fn decode_is_self_restoring_for_binary_boundaries_and_zero_typed_digests() {
    let completion = partial_fixture();
    let encoded = AcquisitionCompletionRecordV1::new(&completion)
        .unwrap()
        .encode();
    drop(completion);
    let restored = AcquisitionCompletionRecordV1::decode(&encoded)
        .unwrap()
        .into_fetch_completion();
    assert_eq!(restored, partial_fixture());
    assert_eq!(restored.identity().plan_digest().as_bytes(), &[0; 32]);
    assert_eq!(
        restored.boundaries().first_cursor().unwrap().as_bytes(),
        &[0, b'f', 0xff]
    );
    assert_eq!(
        restored.boundaries().high_water_marks()[0]
            .cursor()
            .as_bytes(),
        &[0x80, 0]
    );
}

#[test]
fn ordered_multiplicity_is_preserved_and_ordinals_are_checked() {
    let duplicate_mark = HighWaterMark::new(member(b"same".to_vec()), cursor(b"same".to_vec()));
    let completion = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(None, None, [duplicate_mark.clone(), duplicate_mark]),
        vec![
            CapUsage::new(CapKind::Pages, 1, 2, false),
            CapUsage::new(CapKind::Pages, 1, 2, false),
        ],
        vec![
            FetchErrorCode::NetworkFailure,
            FetchErrorCode::NetworkFailure,
        ],
        FetchPartialReasons::with_additional(
            FetchPartialReason::Timeout,
            [FetchPartialReason::Timeout],
        ),
        None,
    );
    let record = AcquisitionCompletionRecordV1::new(&completion).unwrap();
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&record.encode())
            .unwrap()
            .to_fetch_completion(),
        completion
    );

    let encoded = record.encode();
    let (high_water, cap, error, reason) = section_offsets(&encoded);
    for ordinal_offset in [high_water, cap, error, reason] {
        let mut mutated = encoded.clone();
        mutated[ordinal_offset + 3] = 1;
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(&mutated),
            Err(AcquisitionCompletionRecordErrorV1::InvalidListOrdinal),
            "offset {ordinal_offset}"
        );
    }
}

#[test]
fn complete_unknown_and_every_closed_code_variant_round_trip() {
    let cap_kinds = [
        CapKind::Records,
        CapKind::SourceBytes,
        CapKind::ExpandedBytes,
        CapKind::Pages,
        CapKind::Members,
        CapKind::PerRecordBytes,
        CapKind::InFlightBytes,
        CapKind::EncryptedSpoolBytes,
        CapKind::WallTimeMillis,
        CapKind::DiagnosticBytes,
        CapKind::OtherVersioned {
            version: u16::MAX,
            code: u16::MAX,
        },
    ];
    let error_codes = vec![
        FetchErrorCode::AuthenticationChanged,
        FetchErrorCode::PermissionDenied,
        FetchErrorCode::SourceUnavailable,
        FetchErrorCode::SourceChanged,
        FetchErrorCode::ProviderFailure,
        FetchErrorCode::NetworkFailure,
        FetchErrorCode::ChildExitFailure,
        FetchErrorCode::ChildKilled,
        FetchErrorCode::MalformedProviderFraming,
        FetchErrorCode::SourceReadFailure,
        FetchErrorCode::SinkFailure,
        FetchErrorCode::AdapterInvariantViolation,
        FetchErrorCode::OtherVersioned {
            version: u16::MAX,
            code: u16::MAX,
        },
    ];
    let reasons = [
        FetchPartialReason::RowCap,
        FetchPartialReason::RecordCountCap,
        FetchPartialReason::SourceByteCap,
        FetchPartialReason::ExpandedByteCap,
        FetchPartialReason::PageCap,
        FetchPartialReason::WallTimeCap,
        FetchPartialReason::Timeout,
        FetchPartialReason::Cancelled,
        FetchPartialReason::BackpressureLimit,
        FetchPartialReason::PaginationIncomplete,
        FetchPartialReason::ProviderCap,
        FetchPartialReason::ProviderTruncation,
        FetchPartialReason::PermissionLimited,
        FetchPartialReason::AuthenticationChanged,
        FetchPartialReason::RetentionBoundary,
        FetchPartialReason::SourceChanged,
        FetchPartialReason::SourceDisappeared,
        FetchPartialReason::SourceReadError,
        FetchPartialReason::ChildExitFailure,
        FetchPartialReason::ChildKilled,
        FetchPartialReason::NetworkFailure,
        FetchPartialReason::MalformedProviderFraming,
        FetchPartialReason::RecordTruncated,
        FetchPartialReason::DecompressionLimit,
        FetchPartialReason::SinkFailure,
        FetchPartialReason::OtherVersioned {
            version: u16::MAX,
            code: u16::MAX,
        },
    ];
    let partial = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::default(),
        cap_kinds
            .into_iter()
            .map(|kind| CapUsage::new(kind, 0, 0, false))
            .collect(),
        error_codes,
        FetchPartialReasons::with_additional(reasons[0], reasons[1..].iter().copied()),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(
            &AcquisitionCompletionRecordV1::new(&partial)
                .unwrap()
                .encode()
        )
        .unwrap()
        .to_fetch_completion(),
        partial
    );

    let proofs = [
        CompletenessProof::FixedSnapshotVerified,
        CompletenessProof::PlannedUnixFileSnapshotVerifiedV1,
        CompletenessProof::ProviderBoundaryExhausted,
        CompletenessProof::FinalCursorVerified,
        CompletenessProof::ReplayManifestVerified,
        CompletenessProof::InMemoryFixtureExhausted,
        CompletenessProof::OtherVersioned {
            version: 0,
            code: 0,
        },
    ];
    for proof in proofs {
        let complete = FetchCompletion::new(
            identity("fixture".to_owned(), "v1".to_owned()),
            FetchTiming::new(
                UnixTimestampNanos::new(i128::MIN),
                UnixTimestampNanos::new(i128::MAX),
            ),
            AcknowledgedCounts::new(0, 0, 0),
            AttemptCounts::new(2, 2),
            AttemptCounts::new(3, 3),
            FetchBoundaries::default(),
            [],
            AdapterOutcome::Finished,
            [],
            FetchCompleteness::complete(proof),
        )
        .unwrap();
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(
                &AcquisitionCompletionRecordV1::new(&complete)
                    .unwrap()
                    .encode()
            )
            .unwrap()
            .to_fetch_completion(),
            complete
        );
    }

    for reason in [
        FetchUnknownReason::ProviderHasNoCompletenessProof,
        FetchUnknownReason::RetentionUnobservable,
        FetchUnknownReason::HighWaterMarkUnverifiable,
        FetchUnknownReason::EventuallyConsistentWindow,
        FetchUnknownReason::LiveStreamOpenEnded,
        FetchUnknownReason::AdapterCapabilityLimit,
    ] {
        let unknown = FetchCompletion::new(
            identity("fixture".to_owned(), "v1".to_owned()),
            FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(0)),
            AcknowledgedCounts::default(),
            AttemptCounts::default(),
            AttemptCounts::default(),
            FetchBoundaries::default(),
            [],
            AdapterOutcome::Cancelled,
            [],
            FetchCompleteness::unknown(reason),
        )
        .unwrap();
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(
                &AcquisitionCompletionRecordV1::new(&unknown)
                    .unwrap()
                    .encode()
            )
            .unwrap()
            .to_fetch_completion(),
            unknown
        );
    }

    for outcome in [
        AdapterOutcome::Finished,
        AdapterOutcome::Cancelled,
        AdapterOutcome::DeadlineExceeded,
        AdapterOutcome::ProviderStopped,
        AdapterOutcome::SourceStopped,
        AdapterOutcome::SinkStopped,
        AdapterOutcome::AdapterStopped,
    ] {
        let completion = FetchCompletion::new(
            identity("fixture".to_owned(), "v1".to_owned()),
            FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
            AcknowledgedCounts::default(),
            AttemptCounts::default(),
            AttemptCounts::default(),
            FetchBoundaries::default(),
            [],
            outcome,
            [],
            FetchCompleteness::unknown(FetchUnknownReason::AdapterCapabilityLimit),
        )
        .unwrap();
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(
                &AcquisitionCompletionRecordV1::new(&completion)
                    .unwrap()
                    .encode()
            )
            .unwrap()
            .to_fetch_completion(),
            completion
        );
    }
}

#[test]
fn receipt_verification_uses_only_shared_retrieval_and_record_count_facts() {
    let completion = partial_fixture();
    let record = AcquisitionCompletionRecordV1::new(&completion).unwrap();
    record
        .verify_against_receipt(&receipt(completion.identity().retrieval_id(), 3))
        .unwrap();
    assert_eq!(
        record.verify_against_receipt(&receipt(RetrievalId::from_bytes([9; 32]), 3)),
        Err(AcquisitionCompletionRecordErrorV1::ReceiptRetrievalMismatch)
    );
    assert_eq!(
        record.verify_against_receipt(&receipt(completion.identity().retrieval_id(), 2)),
        Err(AcquisitionCompletionRecordErrorV1::ReceiptAcknowledgedCountMismatch)
    );
}

#[test]
fn projection_rejects_every_field_count_and_total_bound() {
    let oversized_adapter = build_partial(
        identity(
            "a".repeat(MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1 + 1),
            "v1".to_owned(),
        ),
        FetchBoundaries::default(),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::new(&oversized_adapter),
        Err(AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong)
    );

    let oversized_cursor = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(
            Some(cursor(vec![0; MAX_ACQUISITION_CURSOR_BYTES_V1 + 1])),
            None,
            [],
        ),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::new(&oversized_cursor),
        Err(AcquisitionCompletionRecordErrorV1::CursorTooLong)
    );

    let oversized_member = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(
            None,
            None,
            [HighWaterMark::new(
                member(vec![0; MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1 + 1]),
                cursor(vec![1]),
            )],
        ),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::new(&oversized_member),
        Err(AcquisitionCompletionRecordErrorV1::SourceMemberTooLong)
    );

    let marks = (0..=MAX_ACQUISITION_HIGH_WATER_MARKS_V1)
        .map(|_| HighWaterMark::new(member(vec![1]), cursor(vec![2])))
        .collect::<Vec<_>>();
    let too_many_marks = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(None, None, marks),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::new(&too_many_marks),
        Err(AcquisitionCompletionRecordErrorV1::CountCap)
    );

    for (caps, errors, reasons) in [
        (
            vec![CapUsage::new(CapKind::Records, 0, 0, false); MAX_ACQUISITION_CAP_USAGES_V1 + 1],
            Vec::new(),
            vec![FetchPartialReason::Timeout],
        ),
        (
            Vec::new(),
            vec![FetchErrorCode::NetworkFailure; MAX_ACQUISITION_ERROR_CODES_V1 + 1],
            vec![FetchPartialReason::Timeout],
        ),
        (
            Vec::new(),
            Vec::new(),
            vec![FetchPartialReason::Timeout; MAX_ACQUISITION_PARTIAL_REASONS_V1 + 1],
        ),
    ] {
        let mut reasons = reasons.into_iter();
        let completion = build_partial(
            identity("fixture".to_owned(), "v1".to_owned()),
            FetchBoundaries::default(),
            caps,
            errors,
            FetchPartialReasons::with_additional(reasons.next().unwrap(), reasons),
            None,
        );
        assert_eq!(
            AcquisitionCompletionRecordV1::new(&completion),
            Err(AcquisitionCompletionRecordErrorV1::CountCap)
        );
    }

    let large_marks = (0..9)
        .map(|_| {
            HighWaterMark::new(
                member(vec![1; MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1]),
                cursor(vec![2; MAX_ACQUISITION_CURSOR_BYTES_V1]),
            )
        })
        .collect::<Vec<_>>();
    let over_total = build_partial(
        identity("fixture".to_owned(), "v1".to_owned()),
        FetchBoundaries::new(None, None, large_marks),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        None,
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::new(&over_total),
        Err(AcquisitionCompletionRecordErrorV1::TotalLengthCap)
    );
}

#[test]
fn decode_rejects_every_truncation_trailing_and_count_allocation_attack() {
    let encoded = AcquisitionCompletionRecordV1::new(&partial_fixture())
        .unwrap()
        .encode();
    for boundary in 0..encoded.len() {
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(&encoded[..boundary]),
            Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength),
            "boundary {boundary}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&trailing),
        Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength)
    );
    let mut allocation_attack = encoded;
    allocation_attack[240..244].copy_from_slice(
        &u32::try_from(MAX_ACQUISITION_HIGH_WATER_MARKS_V1 + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&allocation_attack),
        Err(AcquisitionCompletionRecordErrorV1::CountCap)
    );
}

#[test]
fn decode_rejects_fixed_fields_flags_lengths_and_every_reserved_header_byte() {
    let encoded = AcquisitionCompletionRecordV1::new(&partial_fixture())
        .unwrap()
        .encode();
    for (offset, error) in [
        (0, AcquisitionCompletionRecordErrorV1::InvalidMagic),
        (8, AcquisitionCompletionRecordErrorV1::UnsupportedVersion),
        (10, AcquisitionCompletionRecordErrorV1::UnsupportedSchema),
        (
            12,
            AcquisitionCompletionRecordErrorV1::UnsupportedObjectKind,
        ),
        (14, AcquisitionCompletionRecordErrorV1::InvalidHeaderWidth),
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert_eq!(AcquisitionCompletionRecordV1::decode(&mutated), Err(error));
    }
    let mut flags = encoded.clone();
    flags[17] |= 0x80;
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&flags),
        Err(AcquisitionCompletionRecordErrorV1::UnknownFlags)
    );
    for offset in (18..24).chain(218..220).chain(264..288) {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(&mutated),
            Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved),
            "offset {offset}"
        );
    }
    let mut total = encoded.clone();
    total[260..264].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&total),
        Err(AcquisitionCompletionRecordErrorV1::TotalLengthCap)
    );
    let mut adapter_length = encoded.clone();
    adapter_length[220..224].copy_from_slice(
        &u32::try_from(MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1 + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&adapter_length),
        Err(AcquisitionCompletionRecordErrorV1::AdapterFieldTooLong)
    );
}

#[test]
fn optional_fields_utf8_and_variable_section_structure_are_strict() {
    let encoded = AcquisitionCompletionRecordV1::new(&partial_fixture())
        .unwrap()
        .encode();
    let mut absent_with_length = encoded.clone();
    absent_with_length[16..18].copy_from_slice(&6u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&absent_with_length),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalOptionalField)
    );
    let mut present_without_length = encoded.clone();
    present_without_length[228..232].fill(0);
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&present_without_length),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalOptionalField)
    );
    let mut invalid_utf8 = encoded.clone();
    invalid_utf8[ACQUISITION_COMPLETION_HEADER_BYTES_V1] = 0xff;
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&invalid_utf8),
        Err(AcquisitionCompletionRecordErrorV1::InvalidUtf8)
    );
    let mut wrong_high_water_length = encoded.clone();
    wrong_high_water_length[256..260].copy_from_slice(&55u32.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&wrong_high_water_length),
        Err(AcquisitionCompletionRecordErrorV1::InvalidEncodedLength)
    );
}

#[test]
fn nested_entry_flags_reserved_codes_and_kinds_fail_closed() {
    let encoded = AcquisitionCompletionRecordV1::new(&partial_fixture())
        .unwrap()
        .encode();
    let (high_water, cap, error, reason) = section_offsets(&encoded);
    for offset in [high_water + 12, cap + 12, error + 10, reason + 10] {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert_eq!(
            AcquisitionCompletionRecordV1::decode(&mutated),
            Err(AcquisitionCompletionRecordErrorV1::NonzeroReserved),
            "offset {offset}"
        );
    }
    let mut cap_flags = encoded.clone();
    cap_flags[cap + 6..cap + 8].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&cap_flags),
        Err(AcquisitionCompletionRecordErrorV1::UnknownFlags)
    );
    let mut cap_kind = encoded.clone();
    cap_kind[cap + 4..cap + 6].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&cap_kind),
        Err(AcquisitionCompletionRecordErrorV1::UnsupportedCapKind)
    );
    let mut error_kind = encoded.clone();
    error_kind[error + 4..error + 6].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&error_kind),
        Err(AcquisitionCompletionRecordErrorV1::UnsupportedErrorCode)
    );
    let mut reason_kind = encoded.clone();
    reason_kind[reason + 4..reason + 6].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&reason_kind),
        Err(AcquisitionCompletionRecordErrorV1::UnsupportedPartialReason)
    );
    let mut extension_on_known = encoded;
    extension_on_known[error + 6..error + 8].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&extension_on_known),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCodeFields)
    );
}

#[test]
fn completeness_conditionals_and_runtime_cross_field_invariants_are_rechecked() {
    let encoded = AcquisitionCompletionRecordV1::new(&partial_fixture())
        .unwrap()
        .encode();
    let mut no_reasons = encoded.clone();
    no_reasons[252..256].fill(0);
    no_reasons[260..264].copy_from_slice(&u32::try_from(encoded.len() - 36).unwrap().to_be_bytes());
    no_reasons.truncate(encoded.len() - 36);
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&no_reasons),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields)
    );
    let mut partial_with_primary = encoded.clone();
    partial_with_primary[213] = 1;
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&partial_with_primary),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields)
    );
    let mut unknown_with_continuation = encoded.clone();
    unknown_with_continuation[210..212].copy_from_slice(&3u16.to_be_bytes());
    unknown_with_continuation[212..214].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&unknown_with_continuation),
        Err(AcquisitionCompletionRecordErrorV1::NoncanonicalCompletenessFields)
    );
    let mut unknown_outcome = encoded.clone();
    unknown_outcome[208..210].copy_from_slice(&99u16.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&unknown_outcome),
        Err(AcquisitionCompletionRecordErrorV1::UnsupportedAdapterOutcome)
    );

    let mut ended_before_started = encoded.clone();
    ended_before_started[120..136].copy_from_slice(&10i128.to_be_bytes());
    ended_before_started[136..152].copy_from_slice(&9i128.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&ended_before_started),
        Err(AcquisitionCompletionRecordErrorV1::InvalidFetchCompletion)
    );
    let mut payload_exceeds_source = encoded;
    payload_exceeds_source[160..168].copy_from_slice(&25u64.to_be_bytes());
    assert_eq!(
        AcquisitionCompletionRecordV1::decode(&payload_exceeds_source),
        Err(AcquisitionCompletionRecordErrorV1::InvalidFetchCompletion)
    );
}

#[test]
fn debug_and_errors_never_expose_adapter_member_cursor_or_identity_canaries() {
    const CANARY: &str = "ACQUISITION-COMPLETION-CANARY-SECRET";
    let completion = build_partial(
        identity(CANARY.to_owned(), CANARY.to_owned()),
        FetchBoundaries::new(
            Some(cursor(CANARY.as_bytes().to_vec())),
            None,
            [HighWaterMark::new(
                member(CANARY.as_bytes().to_vec()),
                cursor(CANARY.as_bytes().to_vec()),
            )],
        ),
        Vec::new(),
        Vec::new(),
        FetchPartialReasons::new(FetchPartialReason::Timeout),
        Some(cursor(CANARY.as_bytes().to_vec())),
    );
    let record = AcquisitionCompletionRecordV1::new(&completion).unwrap();
    let output = format!(
        "{record:?} {:?} {}",
        AcquisitionCompletionRecordErrorV1::InvalidUtf8,
        AcquisitionCompletionRecordErrorV1::ReceiptRetrievalMismatch
    );
    assert!(!output.contains(CANARY));
    assert!(!output.contains("4143515549534954494f4e"));
    assert_eq!(
        format!("{record:?}"),
        "AcquisitionCompletionRecordV1(<redacted>)"
    );
}
