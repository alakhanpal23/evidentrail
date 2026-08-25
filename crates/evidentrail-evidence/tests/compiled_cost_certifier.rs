use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventId,
    EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_evidence::{
    CompiledBriefError, CompiledCostCertificationError, CompiledPacketMembershipV1,
    Utf8ByteTokenizerV1, certify_compiled_costs_v1, compiled_cost_model_v1,
    render_cost_certified_compiled_log_brief_v1, utf8_byte_tokenizer_digest_v1,
};
use evidentrail_schema::{PlanDigest, PlanId, ResultId, RetrievalId, bounds::JSON_SAFE_INTEGER_MAX};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1,
    ComposablePacketCostV1, FacetAffinityV1, FacetWeightV1, IntactPacketV1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, SelectionDecisionV1, SelectionProblemV1, SelectionV1,
    TotalTokenBudgetV1,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn opaque(seed: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(seed).unwrap().to_be_bytes());
    bytes
}

fn result_id(seed: usize) -> ResultId {
    ResultId::from_bytes(opaque(seed))
}

fn ledger(
    seed: u8,
    records: Vec<RecordBytes>,
    completeness: FetchCompleteness,
) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("COST_CERT_TEST", "V1").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"opaque-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder =
        LedgerBuilder::new(identity.clone(), source_identity_digest, SourceExactPolicy);
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    for (position, record) in records.iter().cloned().enumerate() {
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(record.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(record.source_len()).unwrap())
            .unwrap();
        let sequence = u64::try_from(position).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                record,
                RecordState::Complete,
            ))
            .unwrap();
    }
    let record_count = u64::try_from(records.len()).unwrap();
    let completion = FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        completeness,
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn complete_ledger(seed: u8, records: Vec<RecordBytes>) -> evidentrail_core::EventLedger {
    ledger(
        seed,
        records,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    )
}

fn memberships(
    ledger: &evidentrail_core::EventLedger,
    groups: &[Vec<usize>],
) -> Vec<CompiledPacketMembershipV1> {
    groups
        .iter()
        .enumerate()
        .map(|(packet_index, members)| {
            CompiledPacketMembershipV1::new(
                PacketIdV1::from_bytes(opaque(packet_index + 100)),
                members.iter().map(|index| ledger.events()[*index].id()),
            )
            .unwrap()
        })
        .collect()
}

fn select_all(certificate: &evidentrail_evidence::CompiledCostCertificationV1) -> SelectionV1 {
    let mut facets = Vec::new();
    let mut packets = Vec::new();
    for (index, bound) in certificate.packet_bounds().iter().enumerate() {
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::FailureRole,
            &opaque(index + 1),
            FacetWeightV1::new(AFFINITY_SCALE_V1).unwrap(),
        )
        .unwrap();
        packets.push(
            IntactPacketV1::new(
                bound.packet_id(),
                bound.event_ids().iter().copied(),
                certificate
                    .packet_cost(bound.packet_id(), bound.event_ids())
                    .unwrap(),
                [FacetAffinityV1::new(
                    facet.id(),
                    AffinityV1::new(AFFINITY_SCALE_V1).unwrap(),
                )],
            )
            .unwrap(),
        );
        facets.push(facet);
    }
    let problem = SelectionProblemV1::new(
        facets,
        packets,
        [],
        TotalTokenBudgetV1::new(certificate.universe_upper_bound()).unwrap(),
        certificate.fixed_overhead(),
    )
    .unwrap();
    let SelectionDecisionV1::Selected(selection) = problem.select().unwrap() else {
        panic!("certified universe must fit its generated bound");
    };
    assert_eq!(selection.packets().len(), certificate.packet_bounds().len());
    selection
}

fn references(
    result_id: ResultId,
    selection: &SelectionV1,
    now: UnixTimestampNanos,
) -> Vec<EvidenceReferenceV1> {
    selection
        .packets()
        .iter()
        .map(|selected| {
            EvidenceReferenceV1::issue(
                result_id,
                selected
                    .packet()
                    .event_ids()
                    .iter()
                    .copied()
                    .map(EvidenceTargetRef::Event),
                [ExpansionRelationV1::Exact],
                now,
                UnixTimestampNanos::new(now.get().checked_add(100).unwrap()),
            )
            .unwrap()
        })
        .collect()
}

fn certify_select_render(
    ledger: &evidentrail_core::EventLedger,
    result_id: ResultId,
    groups: &[Vec<usize>],
) -> (String, evidentrail_evidence::CompiledCostAccountingV1) {
    let tokenizer = Utf8ByteTokenizerV1::new();
    let certificate =
        certify_compiled_costs_v1(ledger, result_id, memberships(ledger, groups), &tokenizer)
            .unwrap();
    let selection = select_all(&certificate);
    certificate
        .verify_selection(ledger, result_id, &selection, &tokenizer)
        .unwrap();
    let now = UnixTimestampNanos::new(10);
    let references = references(result_id, &selection, now);
    let rendered = render_cost_certified_compiled_log_brief_v1(
        ledger,
        result_id,
        derive_question_digest_v1(b"why"),
        ledger.plan_digest(),
        selection,
        references,
        now,
        &tokenizer,
        &certificate,
    )
    .unwrap();
    let accounting = rendered.brief().cost();
    assert!(accounting.is_additive_bound_certified());
    assert_eq!(accounting.coverage_only_token_cost(), 0);
    assert_eq!(
        accounting.coverage_only_token_limit(),
        (accounting.total_token_budget()
            - accounting.reserved_fixed_overhead()
            - accounting.mandatory_token_cost())
            / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1
    );
    assert_eq!(
        accounting.total_rendered_tokens(),
        accounting.total_rendered_bytes()
    );
    assert!(accounting.total_rendered_tokens() <= accounting.accounted_token_upper_bound());
    assert!(rendered.text().is_ascii());
    (rendered.text().to_owned(), accounting)
}

fn certify_builtin(
    ledger: &evidentrail_core::EventLedger,
    result_id: ResultId,
    memberships: impl IntoIterator<Item = CompiledPacketMembershipV1>,
) -> evidentrail_evidence::CompiledCostCertificationV1 {
    certify_compiled_costs_v1(ledger, result_id, memberships, &Utf8ByteTokenizerV1::new()).unwrap()
}

#[test]
fn compiled_certificate_closes_membership_selection_and_whole_render_loop() {
    let ledger = complete_ledger(
        1,
        vec![
            RecordBytes::framed(b"plain".to_vec(), b"\n".to_vec()),
            RecordBytes::whole(vec![0, b'\n', b'\\', b'\r', 0xff]),
            RecordBytes::framed(b"tail".to_vec(), b"\r\n".to_vec()),
            RecordBytes::whole(b"retained".to_vec()),
        ],
    );
    let result_id = result_id(1);
    let (_text, accounting) = certify_select_render(&ledger, result_id, &[vec![0, 2], vec![1]]);
    assert_ne!(
        accounting.cost_model(),
        compiled_cost_model_v1(utf8_byte_tokenizer_digest_v1()),
        "certified identity must also commit the bound contract",
    );
}

#[test]
fn generated_bounds_cover_partial_acquisition_and_escape_expansion() {
    let partial = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
        None,
    );
    let ledger = ledger(
        2,
        vec![
            RecordBytes::whole((0_u8..=255).collect::<Vec<_>>()),
            RecordBytes::whole(b"STATUS\nCOVERAGE\r\\".to_vec()),
            RecordBytes::whole(b"retained".to_vec()),
        ],
        partial,
    );
    let (text, _) = certify_select_render(&ledger, result_id(2), &[vec![1], vec![0]]);
    assert!(text.contains("acquisition: PARTIAL"));
    assert!(text.contains("\\x00"));
    assert!(text.contains("\\xff"));
}

#[test]
fn deterministic_adversarial_bytes_never_exceed_generated_bound() {
    for seed in 0_u8..32 {
        let mut first = Vec::new();
        let mut state = seed.wrapping_add(1);
        for _ in 0..usize::from(seed) + 1 {
            state = state.wrapping_mul(73).wrapping_add(41);
            first.push(state);
        }
        first.extend_from_slice(&[0, b'\n', b'\r', b'\\', 0x7f, 0x80, 0xff]);
        let ledger = complete_ledger(
            seed.wrapping_add(20),
            vec![
                RecordBytes::whole(first),
                RecordBytes::framed(vec![seed; usize::from(seed % 7)], b"\r\n".to_vec()),
                RecordBytes::whole(Vec::new()),
                RecordBytes::whole(b"retained".to_vec()),
            ],
        );
        let _ = certify_select_render(
            &ledger,
            result_id(1000 + usize::from(seed)),
            &[vec![2, 0], vec![1]],
        );
    }
}

#[test]
fn maximum_width_objective_values_remain_below_packet_bound() {
    let ledger = complete_ledger(
        90,
        vec![
            RecordBytes::whole(b"one".to_vec()),
            RecordBytes::whole(b"retained".to_vec()),
        ],
    );
    let membership = memberships(&ledger, &[vec![0]]).remove(0);
    let certificate = certify_builtin(&ledger, result_id(90), [membership]);
    let bound = &certificate.packet_bounds()[0];
    let mut facets = Vec::new();
    let mut affinities = Vec::new();
    for index in 0..4_096_usize {
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::FailureRole,
            &opaque(index + 10_000),
            FacetWeightV1::new(AFFINITY_SCALE_V1).unwrap(),
        )
        .unwrap();
        affinities.push(FacetAffinityV1::new(
            facet.id(),
            AffinityV1::new(AFFINITY_SCALE_V1).unwrap(),
        ));
        facets.push(facet);
    }
    let packet = IntactPacketV1::new(
        bound.packet_id(),
        bound.event_ids().iter().copied(),
        bound.cost(),
        affinities,
    )
    .unwrap();
    let problem = SelectionProblemV1::new(
        facets,
        [packet],
        [],
        TotalTokenBudgetV1::new(certificate.universe_upper_bound()).unwrap(),
        certificate.fixed_overhead(),
    )
    .unwrap();
    let SelectionDecisionV1::Selected(selection) = problem.select().unwrap() else {
        panic!("maximum-width fixture must fit");
    };
    let tokenizer = Utf8ByteTokenizerV1::new();
    let now = UnixTimestampNanos::new(10);
    let refs = references(result_id(90), &selection, now);
    let rendered = render_cost_certified_compiled_log_brief_v1(
        &ledger,
        result_id(90),
        derive_question_digest_v1(b"wide"),
        ledger.plan_digest(),
        selection,
        refs,
        now,
        &tokenizer,
        &certificate,
    )
    .unwrap();
    assert!(rendered.text().contains("roles: failure_role"));
    assert_eq!(rendered.brief().evidence()[0].affinities().len(), 4_096);
    assert_eq!(
        rendered.brief().evidence()[0].facet_kinds(),
        [ProductionFacetKindV1::FailureRole]
    );
    assert!(
        rendered.brief().cost().total_rendered_tokens()
            <= rendered.brief().cost().accounted_token_upper_bound()
    );
}

#[test]
fn membership_and_universe_reject_duplicate_unknown_and_overlap() {
    let ledger = complete_ledger(
        3,
        vec![
            RecordBytes::whole(b"a".to_vec()),
            RecordBytes::whole(b"b".to_vec()),
        ],
    );
    let first = ledger.events()[0].id();
    let packet = PacketIdV1::from_bytes(opaque(1));
    assert_eq!(
        CompiledPacketMembershipV1::new(packet, []).unwrap_err(),
        CompiledCostCertificationError::EmptyPacketMembership,
    );
    assert_eq!(
        CompiledPacketMembershipV1::new(packet, [first, first]).unwrap_err(),
        CompiledCostCertificationError::DuplicateEventInPacket,
    );
    let duplicate_packet = [
        CompiledPacketMembershipV1::new(packet, [first]).unwrap(),
        CompiledPacketMembershipV1::new(packet, [ledger.events()[1].id()]).unwrap(),
    ];
    assert_eq!(
        certify_compiled_costs_v1(
            &ledger,
            result_id(3),
            duplicate_packet,
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap_err(),
        CompiledCostCertificationError::DuplicatePacketId,
    );
    let overlap = [
        CompiledPacketMembershipV1::new(PacketIdV1::from_bytes(opaque(2)), [first]).unwrap(),
        CompiledPacketMembershipV1::new(PacketIdV1::from_bytes(opaque(3)), [first]).unwrap(),
    ];
    assert_eq!(
        certify_compiled_costs_v1(&ledger, result_id(3), overlap, &Utf8ByteTokenizerV1::new(),)
            .unwrap_err(),
        CompiledCostCertificationError::OverlappingEvent,
    );
    let unknown = EventId::from_bytes([0xf0; 32]);
    let unknown_membership =
        CompiledPacketMembershipV1::new(PacketIdV1::from_bytes(opaque(4)), [unknown]).unwrap();
    assert_eq!(
        certify_compiled_costs_v1(
            &ledger,
            result_id(3),
            [unknown_membership],
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap_err(),
        CompiledCostCertificationError::UnknownEvent,
    );
}

#[test]
fn keyed_costs_reject_unknown_or_changed_membership() {
    let ledger = complete_ledger(
        4,
        vec![
            RecordBytes::whole(b"a".to_vec()),
            RecordBytes::whole(b"b".to_vec()),
        ],
    );
    let certificate = certify_builtin(&ledger, result_id(4), memberships(&ledger, &[vec![0]]));
    let bound = &certificate.packet_bounds()[0];
    assert_eq!(
        certificate
            .packet_cost(bound.packet_id(), &[ledger.events()[1].id()])
            .unwrap_err(),
        CompiledCostCertificationError::PacketMembershipMismatch,
    );
    assert_eq!(
        certificate
            .packet_cost(PacketIdV1::from_bytes(opaque(999)), bound.event_ids())
            .unwrap_err(),
        CompiledCostCertificationError::UnknownPacketId,
    );
}

#[test]
fn forged_manual_packet_cost_cannot_pass_certificate_verification() {
    let ledger = complete_ledger(6, vec![RecordBytes::whole(b"a".to_vec())]);
    let certificate = certify_builtin(&ledger, result_id(6), memberships(&ledger, &[vec![0]]));
    let bound = &certificate.packet_bounds()[0];
    let facet = ProductionFacetV1::new(
        ProductionFacetKindV1::FailureRole,
        b"facet",
        FacetWeightV1::new(1).unwrap(),
    )
    .unwrap();
    let forged = ComposablePacketCostV1::new(
        certificate.cost_model(),
        bound.cost().upper_bound_tokens().checked_sub(1).unwrap(),
    )
    .unwrap();
    let packet = IntactPacketV1::new(
        bound.packet_id(),
        bound.event_ids().iter().copied(),
        forged,
        [FacetAffinityV1::new(
            facet.id(),
            AffinityV1::new(1).unwrap(),
        )],
    )
    .unwrap();
    let problem = SelectionProblemV1::new(
        [facet],
        [packet],
        [],
        TotalTokenBudgetV1::new(JSON_SAFE_INTEGER_MAX).unwrap(),
        certificate.fixed_overhead(),
    )
    .unwrap();
    let SelectionDecisionV1::Selected(selection) = problem.select().unwrap() else {
        panic!("forged selection fixture must be selected");
    };
    let tokenizer = Utf8ByteTokenizerV1::new();
    assert_eq!(
        certificate
            .verify_selection(&ledger, result_id(6), &selection, &tokenizer)
            .unwrap_err(),
        CompiledCostCertificationError::PacketCostMismatch,
    );
    let error = render_cost_certified_compiled_log_brief_v1(
        &ledger,
        result_id(6),
        derive_question_digest_v1(b"forged"),
        ledger.plan_digest(),
        selection,
        [],
        UnixTimestampNanos::new(10),
        &tokenizer,
        &certificate,
    )
    .unwrap_err();
    assert_eq!(error, CompiledBriefError::CostCertificationMismatch);
}

#[test]
fn public_debug_surfaces_are_contentless() {
    let ledger = complete_ledger(7, vec![RecordBytes::whole(b"secret".to_vec())]);
    let certificate = certify_builtin(&ledger, result_id(7), memberships(&ledger, &[vec![0]]));
    let debug = format!("{certificate:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("opaque-member"));
    let error_debug = format!("{:?}", CompiledCostCertificationError::UnknownEvent);
    assert_eq!(
        error_debug,
        "CompiledCostCertificationError { code: \"EVIDENTRAIL_COMPILED_COST_UNKNOWN_EVENT\" }",
    );
}
