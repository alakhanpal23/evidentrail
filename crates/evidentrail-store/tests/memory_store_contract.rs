use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey, LaneSequence,
    LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1,
    RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos,
};
use evidentrail_core::{EvidenceReferenceId, ExpansionRelationV1, ResultId};
use evidentrail_schema::bounds::MAX_EXPANSION_BEFORE_AFTER;
use evidentrail_store::{
    AliasExpansionRequestV1, DEFAULT_RESULT_TTL_NANOS, EvidenceAliasV1, ExpansionLimitV1,
    ExpansionRequestV1, MAX_EXPANSION_BYTES, MAX_EXPANSION_EVENTS, MemoryResultStore,
    ResultStoreError,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn fixture_ledger() -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([1; 32]);
    let plan_id = PlanId::from_bytes([2; 32]);
    let plan_digest = PlanDigest::from_bytes([3; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([4; 32]);
    let adapter = AdapterIdentity::new("fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let member = SourceMember::new(b"approved".to_vec()).unwrap();
    let records = [
        (SourceStream::Stderr, 0, vec![0xff, 0x00]),
        (SourceStream::Stdout, 0, b"out0".to_vec()),
        (SourceStream::Stderr, 1, b"err1".to_vec()),
        (SourceStream::Stdout, 1, b"out1".to_vec()),
        (SourceStream::Stderr, 2, b"err2\r\n".to_vec()),
    ];
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut total_bytes = 0_u64;
    for (position, (stream, lane_sequence, bytes)) in records.into_iter().enumerate() {
        total_bytes += u64::try_from(bytes.len()).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(u64::try_from(position).unwrap()),
                    LaneKey::new(member.clone(), stream),
                    LaneSequence::new(lane_sequence),
                ),
                RecordBytes::whole(bytes),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(5, total_bytes, total_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn broad_limit() -> ExpansionLimitV1 {
    ExpansionLimitV1::new(MAX_EXPANSION_EVENTS, MAX_EXPANSION_BYTES, 1, 1).unwrap()
}

#[test]
fn exact_expansion_survives_as_authorized_bytes_with_basis_and_order() {
    let ledger = fixture_ledger();
    let targets = [ledger.events()[0].id(), ledger.events()[2].id()];
    let mut store = MemoryResultStore::new();
    store
        .insert(result(1), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let reference = store
        .issue_event_reference(
            result(1),
            targets,
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    let response = store
        .expand(
            ExpansionRequestV1::new(
                result(1),
                reference.id(),
                ExpansionRelationV1::Exact,
                broad_limit(),
            ),
            UnixTimestampNanos::new(102),
        )
        .unwrap();

    assert_eq!(
        response
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>(),
        targets
    );
    assert_eq!(response.events()[0].exact_bytes(), &[0xff, 0x00]);
    assert_eq!(response.events()[1].exact_bytes(), b"err1");
    assert!(
        response
            .events()
            .iter()
            .all(|event| event.exactness_basis().is_source_exact())
    );
    assert_eq!(response.returned_bytes(), 6);
    assert!(!response.truncated());
}

#[test]
fn global_and_same_lane_relations_are_distinct_under_interleaving() {
    let ledger = fixture_ledger();
    let anchor = ledger.events()[2].id();
    let mut store = MemoryResultStore::new();
    store
        .insert(result(2), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let reference = store
        .issue_event_reference(
            result(2),
            [anchor],
            [
                ExpansionRelationV1::Exact,
                ExpansionRelationV1::GlobalBeforeAfter,
                ExpansionRelationV1::SameLaneBeforeAfter,
            ],
            UnixTimestampNanos::new(101),
        )
        .unwrap();

    let expand = |relation| {
        store
            .expand(
                ExpansionRequestV1::new(result(2), reference.id(), relation, broad_limit()),
                UnixTimestampNanos::new(102),
            )
            .unwrap()
            .events()
            .iter()
            .map(|event| event.exact_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        expand(ExpansionRelationV1::GlobalBeforeAfter),
        [b"out0".as_slice(), b"err1", b"out1"]
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        expand(ExpansionRelationV1::SameLaneBeforeAfter),
        [vec![0xff, 0x00], b"err1".to_vec(), b"err2\r\n".to_vec()]
    );
}

#[test]
fn expansion_caps_never_slice_an_event() {
    let ledger = fixture_ledger();
    let anchor = ledger.events()[2].id();
    let mut store = MemoryResultStore::new();
    store
        .insert(result(3), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let reference = store
        .issue_event_reference(
            result(3),
            [anchor],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    let response = store
        .expand(
            ExpansionRequestV1::new(
                result(3),
                reference.id(),
                ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(1, 3, 0, 0).unwrap(),
            ),
            UnixTimestampNanos::new(102),
        )
        .unwrap();

    assert!(response.events().is_empty());
    assert_eq!(response.returned_bytes(), 0);
    assert!(response.truncated());
}

#[test]
fn expiry_is_fixed_exclusive_and_cleanup_and_delete_are_idempotent() {
    let ledger = fixture_ledger();
    let anchor = ledger.events()[0].id();
    let created = UnixTimestampNanos::new(100);
    let expires = UnixTimestampNanos::new(100 + DEFAULT_RESULT_TTL_NANOS);
    let mut store = MemoryResultStore::new();
    assert_eq!(store.insert(result(4), ledger, created).unwrap(), expires);
    let reference = store
        .issue_event_reference(result(4), [anchor], [ExpansionRelationV1::Exact], created)
        .unwrap();
    let request = ExpansionRequestV1::new(
        result(4),
        reference.id(),
        ExpansionRelationV1::Exact,
        broad_limit(),
    );

    assert!(
        store
            .expand(request, UnixTimestampNanos::new(expires.get() - 1))
            .is_ok()
    );
    assert_eq!(
        store.expand(request, expires),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    assert_eq!(store.cleanup_expired(expires), 1);
    assert_eq!(store.cleanup_expired(expires), 0);
    store.delete(result(4));
    store.delete(result(4));
    assert_eq!(store.result_count(), 0);
}

#[test]
fn forged_cross_result_expired_and_disallowed_requests_collapse() {
    let first_ledger = fixture_ledger();
    let anchor = first_ledger.events()[0].id();
    let second_ledger = first_ledger.clone();
    let mut store = MemoryResultStore::new();
    store
        .insert(result(5), first_ledger, UnixTimestampNanos::new(100))
        .unwrap();
    store
        .insert(result(6), second_ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let reference = store
        .issue_event_reference(
            result(5),
            [anchor],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(101),
        )
        .unwrap();

    let denied = [
        ExpansionRequestV1::new(
            result(6),
            reference.id(),
            ExpansionRelationV1::Exact,
            broad_limit(),
        ),
        ExpansionRequestV1::new(
            result(5),
            EvidenceReferenceId::from_bytes([0xee; 32]),
            ExpansionRelationV1::Exact,
            broad_limit(),
        ),
        ExpansionRequestV1::new(
            result(5),
            reference.id(),
            ExpansionRelationV1::SameLaneBeforeAfter,
            broad_limit(),
        ),
    ];
    for request in denied {
        assert_eq!(
            store.expand(request, UnixTimestampNanos::new(102)),
            Err(ResultStoreError::ReferenceUnavailable)
        );
    }
}

#[test]
fn invalid_limits_references_ids_and_timestamps_fail_contentlessly() {
    assert_eq!(
        ExpansionLimitV1::new(0, 1, 0, 0),
        Err(ResultStoreError::InvalidExpansionLimit)
    );
    assert_eq!(
        ExpansionLimitV1::new(MAX_EXPANSION_EVENTS + 1, 1, 0, 0),
        Err(ResultStoreError::InvalidExpansionLimit)
    );
    assert_eq!(
        ExpansionLimitV1::new(1, MAX_EXPANSION_BYTES + 1, 0, 0),
        Err(ResultStoreError::InvalidExpansionLimit)
    );
    assert_eq!(
        ExpansionLimitV1::new(1, 1, MAX_EXPANSION_BEFORE_AFTER + 1, 0),
        Err(ResultStoreError::InvalidExpansionLimit)
    );

    let ledger = fixture_ledger();
    let anchor = ledger.events()[0].id();
    let mut store = MemoryResultStore::new();
    store
        .insert(result(7), ledger.clone(), UnixTimestampNanos::new(100))
        .unwrap();
    assert_eq!(
        store.insert(result(7), ledger.clone(), UnixTimestampNanos::new(100)),
        Err(ResultStoreError::DuplicateResultId)
    );
    assert_eq!(
        store.insert(result(8), ledger, UnixTimestampNanos::new(i128::MAX)),
        Err(ResultStoreError::TimestampOverflow)
    );
    assert_eq!(
        store.issue_event_reference(
            result(7),
            [anchor, anchor],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(101),
        ),
        Err(ResultStoreError::InvalidReferenceMaterial)
    );
    assert_eq!(
        store.issue_event_reference(
            result(7),
            [anchor],
            [
                ExpansionRelationV1::Exact,
                ExpansionRelationV1::SameAttestedTrace,
            ],
            UnixTimestampNanos::new(101),
        ),
        Err(ResultStoreError::InvalidReferenceMaterial)
    );
    assert_eq!(
        ResultStoreError::ReferenceUnavailable.to_string(),
        "EVIDENTRAIL_STORE_REFERENCE_UNAVAILABLE"
    );
}

#[test]
fn debug_views_never_expose_result_reference_or_payload_bytes() {
    let ledger = fixture_ledger();
    let anchor = ledger.events()[0].id();
    let mut store = MemoryResultStore::new();
    store
        .insert(result(0xab), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let reference = store
        .issue_event_reference(
            result(0xab),
            [anchor],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    let request = ExpansionRequestV1::new(
        result(0xab),
        reference.id(),
        ExpansionRelationV1::Exact,
        broad_limit(),
    );
    let response = store.expand(request, UnixTimestampNanos::new(102)).unwrap();
    let rendered = format!("{store:?} {request:?} {response:?}");

    assert!(!rendered.contains(&result(0xab).canonical_token()));
    assert!(!rendered.contains(&reference.id().to_string()));
    for forbidden in ["out0", "err1", "err2"] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn short_aliases_are_result_scoped_and_resolve_only_the_frozen_manifest() {
    let ledger = fixture_ledger();
    let second_ledger = ledger.clone();
    let expected_first = ledger.events()[0].id();
    let extra_target = ledger.events()[1].id();
    let mut store = MemoryResultStore::new();
    let registered = store
        .insert_with_event_references(result(0xc1), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    store
        .insert_with_event_references(result(0xc2), second_ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let unpublished_request = AliasExpansionRequestV1::new(
        result(0xc1),
        EvidenceAliasV1::new(result(0xc1), 1).unwrap(),
        ExpansionRelationV1::Exact,
        broad_limit(),
    );
    assert_eq!(
        store.expand_alias(unpublished_request, UnixTimestampNanos::new(100)),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    store
        .publish_event_aliases(result(0xc1), UnixTimestampNanos::new(100))
        .unwrap();
    store
        .publish_event_aliases(result(0xc2), UnixTimestampNanos::new(100))
        .unwrap();
    assert_eq!(
        store.publish_event_aliases(result(0xc1), UnixTimestampNanos::new(100)),
        Err(ResultStoreError::AliasManifestAlreadyPublished)
    );
    let first_reference = registered.references()[0].id();
    let alias = EvidenceAliasV1::new(result(0xc1), 1).unwrap();
    assert_eq!(alias.canonical_token(), "E1");

    let request = AliasExpansionRequestV1::new(
        result(0xc1),
        alias,
        ExpansionRelationV1::Exact,
        broad_limit(),
    );
    let response = store
        .expand_alias(request, UnixTimestampNanos::new(101))
        .unwrap();
    assert_eq!(response.reference_id(), first_reference);
    assert_eq!(response.events()[0].event_id(), expected_first);

    store
        .issue_event_reference(
            result(0xc1),
            [extra_target],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(102),
        )
        .unwrap();
    assert_eq!(
        store
            .expand_alias(request, UnixTimestampNanos::new(103))
            .unwrap()
            .reference_id(),
        first_reference
    );

    let cross_result = AliasExpansionRequestV1::new(
        result(0xc2),
        alias,
        ExpansionRelationV1::Exact,
        broad_limit(),
    );
    assert_eq!(
        store.expand_alias(cross_result, UnixTimestampNanos::new(103)),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    let forged_ordinal = AliasExpansionRequestV1::new(
        result(0xc1),
        EvidenceAliasV1::new(result(0xc1), 6).unwrap(),
        ExpansionRelationV1::Exact,
        broad_limit(),
    );
    assert_eq!(
        store.expand_alias(forged_ordinal, UnixTimestampNanos::new(103)),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    assert_eq!(
        EvidenceAliasV1::new(result(0xc1), 0),
        Err(ResultStoreError::InvalidEvidenceAlias)
    );
    assert!(!format!("{alias:?} {request:?}").contains(&result(0xc1).canonical_token()));
}

#[test]
fn packet_aliases_are_atomic_source_ordered_and_never_split_by_expansion_caps() {
    let ledger = fixture_ledger();
    let first = ledger.events()[0].id();
    let third = ledger.events()[2].id();
    let mut store = MemoryResultStore::new();
    store
        .insert_with_event_references(result(0xd1), ledger, UnixTimestampNanos::new(100))
        .unwrap();
    let prepared = store
        .prepare_packet_references(
            result(0xd1),
            [vec![third, first]],
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    let registered = store
        .commit_packet_references(prepared, UnixTimestampNanos::new(101))
        .unwrap();
    assert_eq!(registered.references().len(), 1);
    assert_eq!(
        registered.references()[0].targets(),
        [
            evidentrail_core::EvidenceTargetRef::Event(first),
            evidentrail_core::EvidenceTargetRef::Event(third),
        ]
    );

    let exact = |limit| {
        store.expand_alias(
            AliasExpansionRequestV1::new(
                result(0xd1),
                EvidenceAliasV1::new(result(0xd1), 1).unwrap(),
                ExpansionRelationV1::Exact,
                limit,
            ),
            UnixTimestampNanos::new(101),
        )
    };
    let expanded = exact(ExpansionLimitV1::new(2, 1024, 0, 0).unwrap()).unwrap();
    assert_eq!(
        expanded
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>(),
        [first, third]
    );
    assert!(!expanded.truncated());
    assert_eq!(
        exact(ExpansionLimitV1::new(1, 1024, 0, 0).unwrap()),
        Err(ResultStoreError::InsufficientExpansionBudget)
    );
    assert_eq!(
        exact(ExpansionLimitV1::new(2, 3, 0, 0).unwrap()),
        Err(ResultStoreError::InsufficientExpansionBudget)
    );

    let prepared = store
        .prepare_packet_references(result(0xd1), [vec![third]], UnixTimestampNanos::new(102))
        .unwrap();
    assert_eq!(
        store.commit_packet_references(prepared, UnixTimestampNanos::new(102)),
        Err(ResultStoreError::AliasManifestAlreadyPublished)
    );
    let unchanged = store
        .expand_alias(
            AliasExpansionRequestV1::new(
                result(0xd1),
                EvidenceAliasV1::new(result(0xd1), 1).unwrap(),
                ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(2, 1024, 0, 0).unwrap(),
            ),
            UnixTimestampNanos::new(103),
        )
        .unwrap();
    assert_eq!(unchanged.events().len(), 2);
}

#[test]
fn invalid_packet_manifests_leave_the_retained_result_unpublished_and_unchanged() {
    let ledger = fixture_ledger();
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let unknown = evidentrail_core::EventId::from_bytes([0xee; 32]);
    let invalid = [
        vec![vec![first, first]],
        vec![vec![first, second], vec![second]],
        vec![vec![unknown]],
        vec![Vec::new()],
    ];
    for (offset, packets) in invalid.into_iter().enumerate() {
        let mut store = MemoryResultStore::new();
        let result_id = result(0xe0 + u8::try_from(offset).unwrap());
        let registered = store
            .insert_with_event_references(result_id, ledger.clone(), UnixTimestampNanos::new(100))
            .unwrap();
        assert_eq!(
            store.prepare_packet_references(result_id, packets, UnixTimestampNanos::new(101)),
            Err(ResultStoreError::InvalidReferenceMaterial)
        );
        assert_eq!(store.result_count(), 1);
        assert!(
            store
                .expand(
                    ExpansionRequestV1::new(
                        result_id,
                        registered.references()[0].id(),
                        ExpansionRelationV1::Exact,
                        broad_limit(),
                    ),
                    UnixTimestampNanos::new(102),
                )
                .is_ok()
        );
        assert_eq!(
            store.expand_alias(
                AliasExpansionRequestV1::new(
                    result_id,
                    EvidenceAliasV1::new(result_id, 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    broad_limit(),
                ),
                UnixTimestampNanos::new(102),
            ),
            Err(ResultStoreError::ReferenceUnavailable)
        );
    }
}
