use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateResourceCap,
    CanonicalProducerProposalArtifactV1, EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, ExpectedAcquisitionClassV1,
    FrozenProducerProposalFrontierPlanV1, FrozenProducerProposalUniverseV1,
    GovernedCaseArtifactBindingV1, GovernedCaseArtifactJoinV1,
    GovernedProducerProposalComparisonV1, GovernedProducerProposalEvaluationV1,
    MAX_PRODUCER_PROPOSAL_FRONTIER_POINTS_V1, MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1,
    MeasuredProducerProposalResourcesV1, MeasurementTrustBoundaryV1,
    ProducerProposalComparisonErrorV1, ProducerProposalErrorV1, ProducerProposalFrontierErrorV1,
    ProducerProposalIdV1, ProducerProposalIdentityV1, ProducerProposalMeasurementEnvironmentV1,
    ProducerProposalMeasurementReceiptV1, ProducerProposalPacketV1,
    ProducerProposalParetoRelationV1, ProducerProposalRenderErrorV1, ProducerProposalRenderLimitV1,
    ProducerProposalResourceCapV1, ProducerProposalResourceDimensionV1,
    WeightedDiagnosticRequirementV1, canonical_producer_proposal_renderer_v1_identity,
    evaluate_governed_producer_proposal_frontier_v1, evaluate_governed_producer_proposals_v1,
    render_canonical_producer_proposals_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, FramingPolicy, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_schema::{ArtifactDigest, BlockId, EventId, QuestionDigest};
use sha2::{Digest as _, Sha256};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn proposal_id(seed: u8) -> ProducerProposalIdV1 {
    ProducerProposalIdV1::from_bytes([seed; 32])
}

fn ledger(seed: u8, raw_events: &[&[u8]]) -> EventLedger {
    ledger_with_source_identity(seed, seed.wrapping_add(3), raw_events)
}

fn ledger_with_source_identity(
    seed: u8,
    source_identity_seed: u8,
    raw_events: &[&[u8]],
) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([source_identity_seed; 32]);
    let adapter = AdapterIdentity::new("producer-proposal-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"CANARY_PRODUCER_MEMBER".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0u64;
    for (position, raw) in raw_events.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(raw.len()).unwrap())
            .unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    u64::try_from(raw_events.len()).unwrap(),
                    source_bytes,
                    source_bytes,
                ),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::complete(CompletenessProof::OtherVersioned {
                    version: 1,
                    code: 91,
                }),
            )
            .unwrap(),
        )
        .unwrap()
}

fn public_case(ledger: &EventLedger) -> EvidentrailBenchCaseSpecV1 {
    EvidentrailBenchCaseSpecV1::new(
        [artifact(1)],
        QuestionDigest::from_bytes([2; 32]),
        ledger.plan_digest(),
        [artifact(3)],
        [artifact(4)],
        [
            CandidateResourceCap::try_new(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
                .unwrap(),
        ],
        ExpectedAcquisitionClassV1::Complete,
    )
    .unwrap()
}

fn producer(seed: u8) -> ProducerProposalIdentityV1 {
    ProducerProposalIdentityV1::new(
        artifact(seed),
        artifact(seed.wrapping_add(1)),
        artifact(seed.wrapping_add(2)),
    )
}

fn configured_producer(method_seed: u8, config_seed: u8) -> ProducerProposalIdentityV1 {
    ProducerProposalIdentityV1::new(
        artifact(method_seed),
        artifact(config_seed),
        artifact(config_seed.wrapping_add(1)),
    )
}

fn measurement_environment(seed: u8) -> ProducerProposalMeasurementEnvironmentV1 {
    measurement_environment_parts(seed, seed.wrapping_add(1))
}

fn measurement_environment_parts(
    tokenizer_seed: u8,
    harness_seed: u8,
) -> ProducerProposalMeasurementEnvironmentV1 {
    let renderer = canonical_producer_proposal_renderer_v1_identity();
    ProducerProposalMeasurementEnvironmentV1::try_new(
        renderer.artifact_digest(),
        renderer.contract_version(),
        artifact(tokenizer_seed),
        1,
        artifact(harness_seed),
        1,
    )
    .unwrap()
}

fn measured() -> MeasuredProducerProposalResourcesV1 {
    MeasuredProducerProposalResourcesV1::try_new(17, Some(23), Some(29)).unwrap()
}

fn packet(seed: u8, members: impl IntoIterator<Item = EventId>) -> ProducerProposalPacketV1 {
    ProducerProposalPacketV1::try_new(proposal_id(seed), members).unwrap()
}

fn block_index(ledger: &EventLedger) -> BlockIndex<'_> {
    let grouped = BlockAssignment::new_same_lane_v1(
        ledger.events()[0].lane().clone(),
        ledger.events()[0..2]
            .iter()
            .map(|event| (event.id(), event.lane_sequence())),
        FramingPolicy::new(b"producer-proposal-blocks".to_vec(), b"1".to_vec()),
        BlockState::Reconstructed,
        BlockConfidence::High,
    );
    let tail = BlockAssignment::new_same_lane_v1(
        ledger.events()[2].lane().clone(),
        [(ledger.events()[2].id(), ledger.events()[2].lane_sequence())],
        FramingPolicy::new(b"producer-proposal-blocks".to_vec(), b"1".to_vec()),
        BlockState::FallbackSingleton,
        BlockConfidence::Certain,
    );
    BlockIndex::reconcile(ledger, [grouped, tail]).unwrap()
}

fn requirement(
    weight_micros: u64,
    alternatives: impl IntoIterator<Item = Vec<EvidenceTargetV1>>,
) -> WeightedDiagnosticRequirementV1 {
    WeightedDiagnosticRequirementV1::new(weight_micros, alternatives).unwrap()
}

fn annotation(
    public_case_artifact: ArtifactDigest,
    requirements: impl IntoIterator<Item = WeightedDiagnosticRequirementV1>,
) -> EvidentrailBenchAnnotationSpecV1 {
    EvidentrailBenchAnnotationSpecV1::new(
        public_case_artifact,
        requirements,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap()
}

fn artifact_join(
    public_case_artifact: ArtifactDigest,
    annotation_artifact: ArtifactDigest,
) -> GovernedCaseArtifactJoinV1 {
    let run_budget = BenchmarkBudgetV1::try_new(
        Some(1_000_000),
        Some(1_000_000),
        Some(1_000_000),
        Some(1_000_000),
        Some(1_000_000),
    )
    .unwrap();
    let run_identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(240)),
        Some(artifact(241)),
        Some(artifact(242)),
        Some(17),
        Some(run_budget),
    )
    .unwrap();
    let public = EvidentrailBenchRunManifestV1::new(run_identity, [public_case_artifact]).unwrap();
    let binding = GovernedCaseArtifactBindingV1::new(public_case_artifact, annotation_artifact);
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        artifact(243),
        &public,
        artifact(244),
        artifact(245),
        [binding],
    )
    .unwrap();
    hidden.resolve_case_binding(binding).unwrap()
}

fn generous_cap() -> ProducerProposalResourceCapV1 {
    ProducerProposalResourceCapV1::try_new(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
        .unwrap()
}

fn measurement(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
) -> ProducerProposalMeasurementReceiptV1 {
    ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        universe,
        render(ledger, universe),
        measurement_environment(60),
        measured(),
    )
    .unwrap()
}

fn measurement_with(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
    seed: u8,
    tokens: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
) -> ProducerProposalMeasurementReceiptV1 {
    ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        universe,
        render(ledger, universe),
        measurement_environment(seed),
        MeasuredProducerProposalResourcesV1::try_new(
            tokens,
            Some(wall_time_nanos),
            Some(peak_rss_bytes),
        )
        .unwrap(),
    )
    .unwrap()
}

fn measurement_with_environment(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    tokens: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
) -> ProducerProposalMeasurementReceiptV1 {
    ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        universe,
        render(ledger, universe),
        environment,
        MeasuredProducerProposalResourcesV1::try_new(
            tokens,
            Some(wall_time_nanos),
            Some(peak_rss_bytes),
        )
        .unwrap(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn governed_evaluation(
    case_artifact: ArtifactDigest,
    annotation_artifact: ArtifactDigest,
    case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    universe: &FrozenProducerProposalUniverseV1,
    measured: ProducerProposalMeasurementReceiptV1,
    cap: ProducerProposalResourceCapV1,
) -> GovernedProducerProposalEvaluationV1 {
    evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, annotation_artifact),
        case,
        annotation,
        ledger,
        blocks,
        universe,
        measured,
        cap,
    )
    .unwrap()
}

fn byte_occurrence_count(haystack: &[u8], needle: &[u8]) -> usize {
    assert!(!needle.is_empty());
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug, PartialEq, Eq)]
struct IndependentlyDecodedProposalMember {
    proposal_id_hex: String,
    event_id_hex: String,
    raw: Vec<u8>,
}

fn independently_decode_escape_v1(encoded: &str) -> Vec<u8> {
    let encoded = encoded.as_bytes();
    let mut decoded = Vec::new();
    let mut cursor = 0;
    while cursor < encoded.len() {
        if encoded[cursor] != b'\\' {
            decoded.push(encoded[cursor]);
            cursor += 1;
            continue;
        }
        cursor += 1;
        assert!(
            cursor < encoded.len(),
            "escape cannot end after a backslash"
        );
        match encoded[cursor] {
            b'\\' => {
                decoded.push(b'\\');
                cursor += 1;
            }
            b'n' => {
                decoded.push(b'\n');
                cursor += 1;
            }
            b'r' => {
                decoded.push(b'\r');
                cursor += 1;
            }
            b't' => {
                decoded.push(b'\t');
                cursor += 1;
            }
            b'x' => {
                assert!(
                    cursor + 2 < encoded.len(),
                    "hex escape must have two digits"
                );
                let high = independent_hex_nibble(encoded[cursor + 1]);
                let low = independent_hex_nibble(encoded[cursor + 2]);
                decoded.push((high << 4) | low);
                cursor += 3;
            }
            _ => panic!("unknown escape in independently decoded fixture"),
        }
    }
    decoded
}

fn independent_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("renderer emitted a non-canonical hex nibble"),
    }
}

fn independently_decode_proposal_members_v1(
    artifact: &CanonicalProducerProposalArtifactV1,
) -> Vec<IndependentlyDecodedProposalMember> {
    let text = std::str::from_utf8(artifact.bytes()).expect("canonical artifact must be ASCII");
    let text = text
        .strip_suffix('\n')
        .expect("canonical artifact must end in exactly framed LF lines");
    let lines = text.split('\n').collect::<Vec<_>>();
    let mut cursor = lines
        .iter()
        .position(|line| {
            *line == "BEGIN_PROPOSAL" || *line == "END_EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1"
        })
        .expect("canonical proposal body sentinel must be present");
    let mut decoded = Vec::new();
    while lines[cursor] == "BEGIN_PROPOSAL" {
        cursor += 1;
        let proposal_id_hex = lines[cursor]
            .strip_prefix("proposal_id: ")
            .expect("proposal identity field must follow its boundary")
            .to_owned();
        cursor += 1;
        let member_count = lines[cursor]
            .strip_prefix("member_count: ")
            .expect("member count must follow proposal identity")
            .parse::<usize>()
            .expect("canonical member count must be decimal");
        cursor += 1;
        for _ in 0..member_count {
            assert_eq!(lines[cursor], "BEGIN_MEMBER");
            cursor += 1;
            let event_id_hex = lines[cursor]
                .strip_prefix("event_id: ")
                .expect("event identity must follow its boundary")
                .to_owned();
            cursor += 1;
            let source_byte_count = lines[cursor]
                .strip_prefix("source_byte_count: ")
                .expect("source byte count must follow event identity")
                .parse::<usize>()
                .expect("canonical source byte count must be decimal");
            cursor += 1;
            let raw = independently_decode_escape_v1(
                lines[cursor]
                    .strip_prefix("data: ")
                    .expect("encoded data must follow source byte count"),
            );
            assert_eq!(raw.len(), source_byte_count);
            cursor += 1;
            assert_eq!(lines[cursor], "END_MEMBER");
            cursor += 1;
            decoded.push(IndependentlyDecodedProposalMember {
                proposal_id_hex: proposal_id_hex.clone(),
                event_id_hex,
                raw,
            });
        }
        assert_eq!(lines[cursor], "END_PROPOSAL");
        cursor += 1;
    }
    assert_eq!(
        lines[cursor],
        "END_EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1"
    );
    assert_eq!(cursor + 1, lines.len());
    decoded
}

fn render(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
) -> CanonicalProducerProposalArtifactV1 {
    render_canonical_producer_proposals_v1(
        ledger,
        universe,
        ProducerProposalRenderLimitV1::hard_maximum(),
    )
    .unwrap()
}

#[test]
fn overlapping_packets_charge_packets_and_unique_member_bytes_separately() {
    let ledger = ledger(10, &[b"alpha", b"CANARY_EVENT_PAYLOAD", b"omega-tail"]);
    let case_artifact = artifact(20);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let first_block = blocks.blocks()[0].id();
    let events = ledger.events();

    // This is frozen before any annotation is constructed.
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(40),
        [
            packet(2, [events[1].id(), events[2].id()]),
            packet(1, [events[0].id(), events[1].id()]),
        ],
    )
    .unwrap();
    let annotation = annotation(
        case_artifact,
        [
            requirement(7, [vec![EvidenceTargetV1::Block(first_block)]]),
            requirement(3, [vec![EvidenceTargetV1::Event(events[2].id())]]),
        ],
    );
    let evaluation = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(21)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &universe,
        measurement(&ledger, &universe),
        generous_cap(),
    )
    .unwrap();

    let expected_bytes = ledger
        .events()
        .iter()
        .map(|event| u64::try_from(event.raw().len()).unwrap())
        .sum::<u64>();
    assert_eq!(evaluation.resources().proposal_packet_count(), 2);
    assert_eq!(evaluation.resources().unique_member_event_count(), 3);
    assert_eq!(
        evaluation.resources().unique_member_source_bytes(),
        expected_bytes
    );
    assert_eq!(
        evaluation.resources().canonical_proposal_render_tokens(),
        17
    );
    assert_eq!(evaluation.resources().wall_time_nanos(), 23);
    assert_eq!(evaluation.resources().peak_rss_bytes(), 29);
    assert_eq!(evaluation.recall().exact_weight_ratio(), (10, 10));
    let acquisition_binding = evaluation.acquisition_binding();
    assert_eq!(acquisition_binding.retrieval_id(), ledger.retrieval_id());
    assert_eq!(acquisition_binding.plan_id(), ledger.plan_id());
    assert_eq!(acquisition_binding.plan_digest(), ledger.plan_digest());
    assert_eq!(
        acquisition_binding.acquisition_receipt_id(),
        ledger.acquisition_receipt_id()
    );
    assert_eq!(
        acquisition_binding.source_identity_digest(),
        ledger.source_identity_digest()
    );
    assert_eq!(
        acquisition_binding.acquisition_class(),
        ExpectedAcquisitionClassV1::Complete
    );
    assert_eq!(
        evaluation.measurement_trust_boundary(),
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    );
    assert!(evaluation.cap_violations().is_none());
}

#[test]
fn one_all_input_packet_is_charged_all_unique_source_bytes_once() {
    let ledger = ledger(11, &[b"one", b"two-two", b"three-three-three"]);
    let case_artifact = artifact(22);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let all_events = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(41),
        [packet(1, all_events)],
    )
    .unwrap();
    let annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Block(blocks.blocks()[0].id())]],
        )],
    );
    let evaluated = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(23)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &universe,
        measurement(&ledger, &universe),
        generous_cap(),
    )
    .unwrap();
    assert_eq!(evaluated.resources().proposal_packet_count(), 1);
    assert_eq!(
        evaluated.resources().unique_member_event_count(),
        u64::try_from(ledger.len()).unwrap()
    );
    assert_eq!(
        evaluated.resources().unique_member_source_bytes(),
        ledger
            .events()
            .iter()
            .map(|event| u64::try_from(event.raw().len()).unwrap())
            .sum::<u64>()
    );
}

#[test]
fn alternative_requirement_works_but_partial_block_never_gets_block_credit() {
    let ledger = ledger(12, &[b"block-a", b"block-b", b"alternative"]);
    let case_artifact = artifact(24);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let block = blocks.blocks()[0].id();
    let partial = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(42),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let annotation = annotation(
        case_artifact,
        [
            requirement(
                7,
                [
                    vec![EvidenceTargetV1::Block(block)],
                    vec![EvidenceTargetV1::Event(ledger.events()[2].id())],
                ],
            ),
            requirement(3, [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]]),
        ],
    );
    let partial_result = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(25)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &partial,
        measurement(&ledger, &partial),
        generous_cap(),
    )
    .unwrap();
    assert_eq!(partial_result.recall().exact_weight_ratio(), (3, 10));

    let alternative = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(42),
        [packet(1, [ledger.events()[2].id()])],
    )
    .unwrap();
    let alternative_result = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(25)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &alternative,
        measurement(&ledger, &alternative),
        generous_cap(),
    )
    .unwrap();
    assert_eq!(alternative_result.recall().exact_weight_ratio(), (7, 10));
}

#[test]
fn proposal_construction_rejects_empty_duplicates_unknowns_and_duplicate_ids() {
    let ledger = ledger(13, &[b"a", b"b", b"c"]);
    let case = public_case(&ledger);
    assert_eq!(
        ProducerProposalPacketV1::try_new(proposal_id(1), []),
        Err(ProducerProposalErrorV1::EmptyProposalMembership)
    );
    assert_eq!(
        ProducerProposalPacketV1::try_new(
            proposal_id(1),
            [ledger.events()[0].id(), ledger.events()[0].id()],
        ),
        Err(ProducerProposalErrorV1::DuplicateProposalMember)
    );
    let duplicate = packet(1, [ledger.events()[0].id()]);
    assert_eq!(
        FrozenProducerProposalUniverseV1::try_new(
            artifact(26),
            &case,
            &ledger,
            producer(43),
            [duplicate.clone(), duplicate],
        ),
        Err(ProducerProposalErrorV1::DuplicateProposalId)
    );
    let unknown = packet(2, [EventId::from_bytes([0xee; 32])]);
    assert_eq!(
        FrozenProducerProposalUniverseV1::try_new(
            artifact(26),
            &case,
            &ledger,
            producer(43),
            [unknown],
        ),
        Err(ProducerProposalErrorV1::UnknownProposalMember { count: 1 })
    );
}

#[test]
fn canonical_freeze_is_order_independent_and_every_material_mutation_rebinds() {
    let ledger = ledger(14, &[b"a", b"b", b"c"]);
    let case = public_case(&ledger);
    let first = FrozenProducerProposalUniverseV1::try_new(
        artifact(27),
        &case,
        &ledger,
        producer(44),
        [
            packet(2, [ledger.events()[2].id(), ledger.events()[1].id()]),
            packet(1, [ledger.events()[0].id()]),
        ],
    )
    .unwrap();
    let reordered = FrozenProducerProposalUniverseV1::try_new(
        artifact(27),
        &case,
        &ledger,
        producer(44),
        [
            packet(1, [ledger.events()[0].id()]),
            packet(2, [ledger.events()[1].id(), ledger.events()[2].id()]),
        ],
    )
    .unwrap();
    assert_eq!(first, reordered);
    assert_eq!(first.digest(), reordered.digest());

    let changed_membership = FrozenProducerProposalUniverseV1::try_new(
        artifact(27),
        &case,
        &ledger,
        producer(44),
        [
            packet(1, [ledger.events()[0].id()]),
            packet(2, [ledger.events()[2].id()]),
        ],
    )
    .unwrap();
    let changed_producer = FrozenProducerProposalUniverseV1::try_new(
        artifact(27),
        &case,
        &ledger,
        producer(45),
        reordered.proposals().iter().cloned(),
    )
    .unwrap();
    assert_ne!(first.digest(), changed_membership.digest());
    assert_ne!(first.digest(), changed_producer.digest());

    let changed_receipt_artifact = FrozenProducerProposalUniverseV1::try_new(
        artifact(27),
        &case,
        &ledger,
        ProducerProposalIdentityV1::new(
            first.producer().method_artifact_digest(),
            first.producer().config_artifact_digest(),
            artifact(0xd1),
        ),
        first.proposals().iter().cloned(),
    )
    .unwrap();
    let changed_case_artifact = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xd2),
        &case,
        &ledger,
        first.producer(),
        first.proposals().iter().cloned(),
    )
    .unwrap();
    assert_ne!(first.digest(), changed_receipt_artifact.digest());
    assert_ne!(first.digest(), changed_case_artifact.digest());
}

#[test]
fn zero_proposal_universe_is_explicit_stable_and_has_zero_recall() {
    let ledger = ledger(0xa0, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(0xa1);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xa2),
        std::iter::empty::<ProducerProposalPacketV1>(),
    )
    .unwrap();
    assert!(universe.proposals().is_empty());
    assert_eq!(universe.accounting().proposal_packet_count(), 0);
    assert_eq!(universe.accounting().unique_member_event_count(), 0);
    assert_eq!(universe.accounting().unique_member_source_bytes(), 0);
    assert_eq!(
        universe.construction_trust_boundary_code(),
        "label_free_data_boundary_process_order_not_attested"
    );

    let annotation = annotation(
        case_artifact,
        [requirement(
            7,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let measurement = ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        &universe,
        render(&ledger, &universe),
        measurement_environment(0xa3),
        MeasuredProducerProposalResourcesV1::try_new(0, Some(1), Some(1)).unwrap(),
    )
    .unwrap();
    let evaluated = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(0xa5)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &universe,
        measurement,
        ProducerProposalResourceCapV1::try_new(0, 0, 0, 1, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(evaluated.recall().exact_weight_ratio(), (0, 7));
    assert_eq!(evaluated.resources().proposal_packet_count(), 0);
    assert_eq!(evaluated.resources().unique_member_event_count(), 0);
    assert_eq!(evaluated.resources().unique_member_source_bytes(), 0);
    assert!(evaluated.cap_violations().is_none());
}

#[test]
fn measurement_is_nonzero_self_asserted_and_bound_to_exact_frozen_universe() {
    assert_eq!(
        MeasuredProducerProposalResourcesV1::try_new(1, None, Some(1)),
        Err(ProducerProposalErrorV1::MissingWallTimeMeasurement)
    );
    assert_eq!(
        MeasuredProducerProposalResourcesV1::try_new(1, Some(0), Some(1)),
        Err(ProducerProposalErrorV1::ZeroWallTimeMeasurement)
    );
    assert_eq!(
        MeasuredProducerProposalResourcesV1::try_new(1, Some(1), None),
        Err(ProducerProposalErrorV1::MissingPeakRssMeasurement)
    );
    assert_eq!(
        MeasuredProducerProposalResourcesV1::try_new(1, Some(1), Some(0)),
        Err(ProducerProposalErrorV1::ZeroPeakRssMeasurement)
    );
    let renderer = canonical_producer_proposal_renderer_v1_identity();
    assert_eq!(
        ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            0,
            artifact(1),
            1,
            artifact(2),
            1,
        ),
        Err(ProducerProposalErrorV1::ZeroRendererContractVersion)
    );
    assert_eq!(
        ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            renderer.contract_version(),
            artifact(1),
            0,
            artifact(2),
            1,
        ),
        Err(ProducerProposalErrorV1::ZeroTokenizerContractVersion)
    );
    assert_eq!(
        ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            renderer.contract_version(),
            artifact(1),
            1,
            artifact(2),
            0,
        ),
        Err(ProducerProposalErrorV1::ZeroMeasurementHarnessContractVersion)
    );
    assert_eq!(
        ProducerProposalMeasurementEnvironmentV1::try_new(
            artifact(0xff),
            renderer.contract_version(),
            artifact(1),
            1,
            artifact(2),
            1,
        ),
        Err(ProducerProposalErrorV1::UnsupportedCanonicalRenderer)
    );
    assert_eq!(
        ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            renderer.contract_version() + 1,
            artifact(1),
            1,
            artifact(2),
            1,
        ),
        Err(ProducerProposalErrorV1::UnsupportedCanonicalRenderer)
    );

    let ledger = ledger(15, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(28);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let first = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(46),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let mutated = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(46),
        [packet(1, [ledger.events()[1].id()])],
    )
    .unwrap();
    let receipt = measurement(&ledger, &first);
    assert_eq!(
        receipt.trust_boundary_code(),
        "self_asserted_reproducibility_input_not_attested"
    );
    let annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(29)),
            &case,
            &annotation,
            &ledger,
            &blocks,
            &mutated,
            receipt,
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::MeasurementBindingMismatch)
    );
}

#[test]
fn measurement_receipt_derives_the_exact_render_and_rejects_foreign_authority() {
    let ledger =
        ledger_with_source_identity(0xbc, 0xbd, &[b"CANARY_MEASUREMENT_CONTENT\n", b"peer\r\n"]);
    let case_artifact = artifact(0xbe);
    let case = public_case(&ledger);
    let first = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xbf),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let same_acquisition_different_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xbf),
        [packet(1, [ledger.events()[1].id()])],
    )
    .unwrap();
    assert_eq!(
        ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
            &same_acquisition_different_universe,
            render(&ledger, &first),
            measurement_environment(0xc0),
            measured(),
        ),
        Err(ProducerProposalErrorV1::CanonicalRenderUniverseMismatch)
    );

    let foreign_ledger = ledger_with_source_identity(0xc1, 0xc2, &[b"foreign\n", b"peer\n"]);
    let foreign_case = public_case(&foreign_ledger);
    let foreign_universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xc3),
        &foreign_case,
        &foreign_ledger,
        producer(0xc4),
        [packet(1, [foreign_ledger.events()[0].id()])],
    )
    .unwrap();
    assert_eq!(
        ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
            &foreign_universe,
            render(&ledger, &first),
            measurement_environment(0xc0),
            measured(),
        ),
        Err(ProducerProposalErrorV1::CanonicalRenderAcquisitionMismatch)
    );

    let exact_artifact = render(&ledger, &first);
    let exact_digest = exact_artifact.artifact_digest();
    let exact_byte_count = exact_artifact.byte_count();
    let environment = measurement_environment(0xc5);
    let receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        &first,
        exact_artifact,
        environment,
        measured(),
    )
    .unwrap();
    assert_eq!(receipt.rendered_artifact().artifact_digest(), exact_digest);
    assert_eq!(receipt.rendered_artifact().byte_count(), exact_byte_count);
    assert_eq!(receipt.environment(), environment);
    assert_eq!(
        receipt.environment().renderer(),
        canonical_producer_proposal_renderer_v1_identity()
    );
    assert_eq!(receipt.environment().contract_version(), 1);

    let changed_environment_receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        &first,
        render(&ledger, &first),
        measurement_environment(0xc6),
        measured(),
    )
    .unwrap();
    let changed_measurement_receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        &first,
        render(&ledger, &first),
        environment,
        MeasuredProducerProposalResourcesV1::try_new(18, Some(23), Some(29)).unwrap(),
    )
    .unwrap();
    assert_ne!(receipt.digest(), changed_environment_receipt.digest());
    assert_ne!(receipt.digest(), changed_measurement_receipt.digest());
    let debug = format!("{receipt:?} {environment:?}");
    assert!(!debug.contains("CANARY_MEASUREMENT_CONTENT"));
    assert!(!debug.contains(&lowercase_hex(exact_digest.as_bytes())));
}

#[test]
fn governed_join_rejects_artifact_source_and_measurement_universe_tampering() {
    let sealed_ledger = ledger_with_source_identity(0xb0, 0xb1, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(0xb2);
    let case = public_case(&sealed_ledger);
    let blocks = block_index(&sealed_ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &sealed_ledger,
        producer(0xb3),
        [packet(1, [sealed_ledger.events()[0].id()])],
    )
    .unwrap();
    let annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                sealed_ledger.events()[0].id(),
            )]],
        )],
    );

    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(artifact(0xb4), artifact(0xb5)),
            &case,
            &annotation,
            &sealed_ledger,
            &blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::PublicCaseArtifactBindingMismatch)
    );

    let changed_source = ledger_with_source_identity(0xb0, 0xb6, &[b"a", b"b", b"c"]);
    let changed_source_blocks = block_index(&changed_source);
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(0xb5)),
            &case,
            &annotation,
            &changed_source,
            &changed_source_blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::SourceIdentityMismatch)
    );

    let changed_receipt = ledger_with_source_identity(0xb0, 0xb1, &[b"a", b"b", b"changed-record"]);
    let changed_receipt_blocks = block_index(&changed_receipt);
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(0xb5)),
            &case,
            &annotation,
            &changed_receipt,
            &changed_receipt_blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::AcquisitionReceiptMismatch)
    );

    let changed_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &sealed_ledger,
        universe.producer(),
        [packet(1, [sealed_ledger.events()[1].id()])],
    )
    .unwrap();
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(0xb5)),
            &case,
            &annotation,
            &sealed_ledger,
            &blocks,
            &changed_universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::MeasurementBindingMismatch)
    );
}

#[test]
fn every_resource_cap_violation_is_retained_without_scalarization() {
    let ledger = ledger(16, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(30);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(47),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let zero_cap = ProducerProposalResourceCapV1::try_new(0, 0, 0, 0, 0).unwrap();
    let evaluated = evaluate_governed_producer_proposals_v1(
        artifact_join(case_artifact, artifact(31)),
        &case,
        &annotation,
        &ledger,
        &blocks,
        &universe,
        measurement(&ledger, &universe),
        zero_cap,
    )
    .unwrap();
    assert_eq!(evaluated.resource_cap(), zero_cap);
    assert!(format!("{evaluated:?}").contains("resource_cap"));
    let violations = evaluated
        .cap_violations()
        .expect("all positive dimensions must violate zero caps");
    assert_eq!(evaluated.resources().unique_member_event_count(), 1);
    assert_eq!(violations.len(), 5);
    assert_eq!(
        violations.dimensions(),
        &[
            ProducerProposalResourceDimensionV1::ProposalPacketCount,
            ProducerProposalResourceDimensionV1::UniqueMemberSourceBytes,
            ProducerProposalResourceDimensionV1::CanonicalProposalRenderTokens,
            ProducerProposalResourceDimensionV1::WallTimeNanos,
            ProducerProposalResourceDimensionV1::PeakRssBytes,
        ]
    );
}

#[test]
fn governed_join_rejects_unknown_targets_and_mismatched_block_universe() {
    let sealed_ledger = ledger(17, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(32);
    let case = public_case(&sealed_ledger);
    let blocks = block_index(&sealed_ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &sealed_ledger,
        producer(48),
        [packet(1, [sealed_ledger.events()[0].id()])],
    )
    .unwrap();
    let unknown_event_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(EventId::from_bytes(
                [0xed; 32],
            ))]],
        )],
    );
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(33)),
            &case,
            &unknown_event_annotation,
            &sealed_ledger,
            &blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::UnknownAnnotationEvent { count: 1 })
    );
    let unknown_block_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Block(BlockId::from_bytes(
                [0xec; 32],
            ))]],
        )],
    );
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(33)),
            &case,
            &unknown_block_annotation,
            &sealed_ledger,
            &blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::UnknownAnnotationBlock { count: 1 })
    );

    let foreign_same_retrieval = ledger(17, &[b"different-a", b"different-b", b"different-c"]);
    let foreign_blocks = block_index(&foreign_same_retrieval);
    let known_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                sealed_ledger.events()[0].id(),
            )]],
        )],
    );
    assert_eq!(
        evaluate_governed_producer_proposals_v1(
            artifact_join(case_artifact, artifact(33)),
            &case,
            &known_annotation,
            &sealed_ledger,
            &foreign_blocks,
            &universe,
            measurement(&sealed_ledger, &universe),
            generous_cap(),
        ),
        Err(ProducerProposalErrorV1::BlockIndexUniverseMismatch)
    );
}

#[test]
fn public_freeze_and_measurement_debug_are_label_blind_and_contentless() {
    let ledger = ledger(18, &[b"CANARY_PRODUCER_PAYLOAD", b"second", b"third"]);
    let case = public_case(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(34),
        &case,
        &ledger,
        producer(49),
        [packet(0xab, [ledger.events()[0].id()])],
    )
    .unwrap();
    let receipt = measurement(&ledger, &universe);
    let debug = format!(
        "{:?} {:?} {:?} {:?}",
        universe,
        universe.proposals()[0],
        universe.digest(),
        receipt
    );
    for forbidden in [
        "CANARY_PRODUCER_PAYLOAD",
        "CANARY_PRODUCER_MEMBER",
        "abababababababab",
        "annotation",
        "requirement",
        "recall",
        "target",
    ] {
        assert!(
            !debug
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase())
        );
    }
    assert!(debug.contains("self_asserted_reproducibility_input_not_attested"));
}

#[test]
fn paired_comparison_is_symmetric_non_scalar_and_refuses_unverified_winner() {
    let ledger = ledger(0xc0, &[b"x", b"block-peer", b"irrelevant-and-expensive"]);
    let case_artifact = artifact(0xc1);
    let annotation_artifact = artifact(0xc2);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let cap = generous_cap();
    let left_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xc3),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let right_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xc4),
        [packet(2, [ledger.events()[2].id()])],
    )
    .unwrap();
    let left = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &annotation,
        &ledger,
        &blocks,
        &left_universe,
        measurement_with(&ledger, &left_universe, 0xc5, 1, 2, 3),
        cap,
    );
    let right = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &annotation,
        &ledger,
        &blocks,
        &right_universe,
        measurement_with(&ledger, &right_universe, 0xc5, 10, 20, 30),
        cap,
    );

    let comparison =
        GovernedProducerProposalComparisonV1::try_new(left.clone(), right.clone()).unwrap();
    assert_eq!(comparison.resource_cap(), cap);
    assert_eq!(comparison.left_resources(), left.resources());
    assert_eq!(comparison.right_resources(), right.resources());
    assert_eq!(comparison.left_recall().exact_weight_ratio(), (1, 1));
    assert_eq!(comparison.right_recall().exact_weight_ratio(), (0, 1));
    assert_eq!(comparison.left_producer(), left.producer());
    assert_eq!(comparison.right_producer(), right.producer());
    assert_eq!(
        comparison.left_measurement_trust_boundary(),
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    );
    assert_eq!(
        comparison.right_measurement_trust_boundary(),
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    );
    assert_eq!(
        comparison.quality_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert_eq!(
        comparison.cost_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert_eq!(
        comparison.joint_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert!(comparison.both_k_eligible());
    assert_eq!(
        comparison.verified_joint_pareto_winner(),
        Err(ProducerProposalComparisonErrorV1::MeasurementTrustNotVerified)
    );

    let equal = GovernedProducerProposalComparisonV1::try_new(left.clone(), left.clone()).unwrap();
    assert_eq!(
        equal.quality_relation(),
        ProducerProposalParetoRelationV1::Equal
    );
    assert_eq!(
        equal.cost_relation(),
        ProducerProposalParetoRelationV1::Equal
    );
    assert_eq!(
        equal.joint_relation(),
        ProducerProposalParetoRelationV1::Equal
    );

    let reversed = GovernedProducerProposalComparisonV1::try_new(right, left).unwrap();
    assert_eq!(
        reversed.quality_relation(),
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    );
    assert_eq!(
        reversed.cost_relation(),
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    );
    assert_eq!(
        reversed.joint_relation(),
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    );
    assert_eq!(reversed.left_resources(), comparison.right_resources());
    assert_eq!(reversed.right_resources(), comparison.left_resources());
    let debug = format!("{comparison:?}");
    assert!(debug.contains("contains_cross_dimension_scalar_score: false"));
}

#[test]
fn paired_comparison_rejects_tokenizer_and_harness_environment_mismatch() {
    let ledger = ledger(0xcc, &[b"CANARY_PAIR_ENV", b"peer", b"tail"]);
    let case_artifact = artifact(0xcd);
    let annotation_artifact = artifact(0xce);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let case_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xcf),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let cap = generous_cap();
    let base_environment = measurement_environment_parts(0xd0, 0xd1);
    let tokenizer_changed_environment = measurement_environment_parts(0xd2, 0xd1);
    let harness_changed_environment = measurement_environment_parts(0xd0, 0xd3);
    let base = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with_environment(&ledger, &universe, base_environment, 1, 1, 1),
        cap,
    );
    let tokenizer_changed = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with_environment(&ledger, &universe, tokenizer_changed_environment, 1, 1, 1),
        cap,
    );
    let harness_changed = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with_environment(&ledger, &universe, harness_changed_environment, 1, 1, 1),
        cap,
    );
    assert_eq!(
        GovernedProducerProposalComparisonV1::try_new(base.clone(), tokenizer_changed),
        Err(ProducerProposalComparisonErrorV1::MeasurementEnvironmentMismatch)
    );
    let harness_error =
        GovernedProducerProposalComparisonV1::try_new(base, harness_changed).unwrap_err();
    assert_eq!(
        harness_error,
        ProducerProposalComparisonErrorV1::MeasurementEnvironmentMismatch
    );
    let debug = format!("{harness_error:?}");
    assert!(!debug.contains("CANARY_PAIR_ENV"));
    assert!(!debug.contains("d0d0d0d0"));
}

#[test]
fn paired_comparison_preserves_exact_incomparable_quality_cost_and_violations() {
    let ledger = ledger(0xd0, &[b"high-weight-but-long", b"b", b"c"]);
    let case_artifact = artifact(0xd1);
    let annotation_artifact = artifact(0xd2);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let annotation = annotation(
        case_artifact,
        [
            requirement(10, [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]]),
            requirement(3, [vec![EvidenceTargetV1::Event(ledger.events()[1].id())]]),
            requirement(3, [vec![EvidenceTargetV1::Event(ledger.events()[2].id())]]),
        ],
    );
    let cap = ProducerProposalResourceCapV1::try_new(1, 5, 5, 5, 5).unwrap();
    let left_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xd3),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let right_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xd4),
        [packet(
            2,
            [ledger.events()[1].id(), ledger.events()[2].id()],
        )],
    )
    .unwrap();
    let left = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &annotation,
        &ledger,
        &blocks,
        &left_universe,
        measurement_with(&ledger, &left_universe, 0xd5, 1, 1, 1),
        cap,
    );
    let right = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &annotation,
        &ledger,
        &blocks,
        &right_universe,
        measurement_with(&ledger, &right_universe, 0xd5, 10, 10, 10),
        cap,
    );
    let comparison =
        GovernedProducerProposalComparisonV1::try_new(left.clone(), right.clone()).unwrap();

    assert_eq!(comparison.left_recall().exact_weight_ratio(), (10, 16));
    assert_eq!(comparison.left_recall().satisfied_requirement_count(), 1);
    assert_eq!(comparison.right_recall().exact_weight_ratio(), (6, 16));
    assert_eq!(comparison.right_recall().satisfied_requirement_count(), 2);
    assert_eq!(
        comparison.quality_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert_eq!(
        comparison.cost_relation(),
        ProducerProposalParetoRelationV1::Incomparable
    );
    assert_eq!(
        comparison.joint_relation(),
        ProducerProposalParetoRelationV1::Incomparable
    );
    assert_eq!(comparison.left_cap_violations(), left.cap_violations());
    assert_eq!(comparison.right_cap_violations(), right.cap_violations());
    assert!(
        comparison
            .left_cap_violations()
            .unwrap()
            .contains(ProducerProposalResourceDimensionV1::UniqueMemberSourceBytes)
    );
    assert!(
        comparison
            .right_cap_violations()
            .unwrap()
            .contains(ProducerProposalResourceDimensionV1::CanonicalProposalRenderTokens)
    );
    assert!(!comparison.both_k_eligible());
}

#[test]
fn joint_pareto_allows_quality_equal_or_cost_equal_when_the_other_strictly_improves() {
    let equal_quality_ledger = ledger(0xd7, &[b"a", b"peer", b"extra-cost"]);
    let equal_quality_case_artifact = artifact(0xd8);
    let equal_quality_annotation_artifact = artifact(0xd9);
    let equal_quality_case = public_case(&equal_quality_ledger);
    let equal_quality_blocks = block_index(&equal_quality_ledger);
    let equal_quality_annotation = annotation(
        equal_quality_case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                equal_quality_ledger.events()[0].id(),
            )]],
        )],
    );
    let cheaper_universe = FrozenProducerProposalUniverseV1::try_new(
        equal_quality_case_artifact,
        &equal_quality_case,
        &equal_quality_ledger,
        producer(0xda),
        [packet(1, [equal_quality_ledger.events()[0].id()])],
    )
    .unwrap();
    let costlier_universe = FrozenProducerProposalUniverseV1::try_new(
        equal_quality_case_artifact,
        &equal_quality_case,
        &equal_quality_ledger,
        producer(0xdb),
        [packet(
            2,
            [
                equal_quality_ledger.events()[0].id(),
                equal_quality_ledger.events()[2].id(),
            ],
        )],
    )
    .unwrap();
    let cap = generous_cap();
    let cheaper = governed_evaluation(
        equal_quality_case_artifact,
        equal_quality_annotation_artifact,
        &equal_quality_case,
        &equal_quality_annotation,
        &equal_quality_ledger,
        &equal_quality_blocks,
        &cheaper_universe,
        measurement_with(&equal_quality_ledger, &cheaper_universe, 0xdc, 1, 1, 1),
        cap,
    );
    let costlier = governed_evaluation(
        equal_quality_case_artifact,
        equal_quality_annotation_artifact,
        &equal_quality_case,
        &equal_quality_annotation,
        &equal_quality_ledger,
        &equal_quality_blocks,
        &costlier_universe,
        measurement_with(&equal_quality_ledger, &costlier_universe, 0xdc, 2, 2, 2),
        cap,
    );
    let equal_quality = GovernedProducerProposalComparisonV1::try_new(cheaper, costlier).unwrap();
    assert_eq!(
        equal_quality.quality_relation(),
        ProducerProposalParetoRelationV1::Equal
    );
    assert_eq!(
        equal_quality.cost_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert_eq!(
        equal_quality.joint_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );

    let equal_cost_ledger = ledger(0xde, &[b"a", b"b", b"c"]);
    let equal_cost_case_artifact = artifact(0xdf);
    let equal_cost_annotation_artifact = artifact(0xe0);
    let equal_cost_case = public_case(&equal_cost_ledger);
    let equal_cost_blocks = block_index(&equal_cost_ledger);
    let equal_cost_annotation = annotation(
        equal_cost_case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                equal_cost_ledger.events()[0].id(),
            )]],
        )],
    );
    let higher_quality_universe = FrozenProducerProposalUniverseV1::try_new(
        equal_cost_case_artifact,
        &equal_cost_case,
        &equal_cost_ledger,
        producer(0xe1),
        [packet(1, [equal_cost_ledger.events()[0].id()])],
    )
    .unwrap();
    let lower_quality_universe = FrozenProducerProposalUniverseV1::try_new(
        equal_cost_case_artifact,
        &equal_cost_case,
        &equal_cost_ledger,
        producer(0xe2),
        [packet(2, [equal_cost_ledger.events()[2].id()])],
    )
    .unwrap();
    let higher_quality = governed_evaluation(
        equal_cost_case_artifact,
        equal_cost_annotation_artifact,
        &equal_cost_case,
        &equal_cost_annotation,
        &equal_cost_ledger,
        &equal_cost_blocks,
        &higher_quality_universe,
        measurement_with(&equal_cost_ledger, &higher_quality_universe, 0xe3, 1, 1, 1),
        cap,
    );
    let lower_quality = governed_evaluation(
        equal_cost_case_artifact,
        equal_cost_annotation_artifact,
        &equal_cost_case,
        &equal_cost_annotation,
        &equal_cost_ledger,
        &equal_cost_blocks,
        &lower_quality_universe,
        measurement_with(&equal_cost_ledger, &lower_quality_universe, 0xe3, 1, 1, 1),
        cap,
    );
    let equal_cost =
        GovernedProducerProposalComparisonV1::try_new(higher_quality, lower_quality).unwrap();
    assert_eq!(
        equal_cost.quality_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    assert_eq!(
        equal_cost.cost_relation(),
        ProducerProposalParetoRelationV1::Equal
    );
    assert_eq!(
        equal_cost.joint_relation(),
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
}

#[test]
fn paired_comparison_rejects_different_caps_and_governed_case_bindings() {
    let ledger = ledger(0xe0, &[b"a", b"b", b"c"]);
    let case_artifact = artifact(0xe1);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let case_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        producer(0xe2),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let first_cap = generous_cap();
    let second_cap = ProducerProposalResourceCapV1::try_new(9, 9, 9, 9, 9).unwrap();
    let left = governed_evaluation(
        case_artifact,
        artifact(0xe3),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with(&ledger, &universe, 0xe4, 1, 1, 1),
        first_cap,
    );
    let different_cap = governed_evaluation(
        case_artifact,
        artifact(0xe3),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with(&ledger, &universe, 0xe4, 1, 1, 1),
        second_cap,
    );
    assert_eq!(
        GovernedProducerProposalComparisonV1::try_new(left.clone(), different_cap),
        Err(ProducerProposalComparisonErrorV1::ResourceCapMismatch)
    );

    let different_binding = governed_evaluation(
        case_artifact,
        artifact(0xe5),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with(&ledger, &universe, 0xe4, 1, 1, 1),
        first_cap,
    );
    assert_eq!(
        GovernedProducerProposalComparisonV1::try_new(left, different_binding),
        Err(ProducerProposalComparisonErrorV1::CaseArtifactBindingMismatch)
    );

    let other_case_artifact = artifact(0xe6);
    let other_annotation = annotation(
        other_case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )],
    );
    let other_universe = FrozenProducerProposalUniverseV1::try_new(
        other_case_artifact,
        &case,
        &ledger,
        producer(0xe2),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let other_case = governed_evaluation(
        other_case_artifact,
        artifact(0xe7),
        &case,
        &other_annotation,
        &ledger,
        &blocks,
        &other_universe,
        measurement_with(&ledger, &other_universe, 0xe8, 1, 1, 1),
        first_cap,
    );
    let left_again = governed_evaluation(
        case_artifact,
        artifact(0xe3),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with(&ledger, &universe, 0xe4, 1, 1, 1),
        first_cap,
    );
    assert_eq!(
        GovernedProducerProposalComparisonV1::try_new(left_again, other_case),
        Err(ProducerProposalComparisonErrorV1::CaseArtifactBindingMismatch)
    );

    let foreign_ledger = ledger_with_source_identity(0xe9, 0xec, &[b"a", b"b", b"c"]);
    let foreign_case = public_case(&foreign_ledger);
    let foreign_blocks = block_index(&foreign_ledger);
    let foreign_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                foreign_ledger.events()[0].id(),
            )]],
        )],
    );
    let foreign_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &foreign_case,
        &foreign_ledger,
        producer(0xea),
        [packet(1, [foreign_ledger.events()[0].id()])],
    )
    .unwrap();
    let foreign_evaluation = governed_evaluation(
        case_artifact,
        artifact(0xe3),
        &foreign_case,
        &foreign_annotation,
        &foreign_ledger,
        &foreign_blocks,
        &foreign_universe,
        measurement_with(&foreign_ledger, &foreign_universe, 0xeb, 1, 1, 1),
        first_cap,
    );
    let primary_again = governed_evaluation(
        case_artifact,
        artifact(0xe3),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &universe,
        measurement_with(&ledger, &universe, 0xe4, 1, 1, 1),
        first_cap,
    );
    assert_eq!(
        GovernedProducerProposalComparisonV1::try_new(primary_again, foreign_evaluation),
        Err(ProducerProposalComparisonErrorV1::AcquisitionBindingMismatch)
    );
}

#[test]
fn frontier_plan_canonically_freezes_label_free_configured_points_and_bounds() {
    let ledger = ledger(0x31, &[b"CANARY_FRONTIER_A\n", b"b\n", b"c\n"]);
    let case = public_case(&ledger);
    let first = FrozenProducerProposalUniverseV1::try_new(
        artifact(0x32),
        &case,
        &ledger,
        configured_producer(0x40, 0x41),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let second = FrozenProducerProposalUniverseV1::try_new(
        artifact(0x32),
        &case,
        &ledger,
        configured_producer(0x40, 0x43),
        [packet(2, [ledger.events()[1].id()])],
    )
    .unwrap();
    let first_cap = ProducerProposalResourceCapV1::try_new(1, 10, 20, 30, 40).unwrap();
    let second_cap = ProducerProposalResourceCapV1::try_new(2, 11, 21, 31, 41).unwrap();
    let environment = measurement_environment(0x45);
    let first_order = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        [(&second, second_cap), (&first, first_cap)],
    )
    .unwrap();
    let second_order = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        [(&first, first_cap), (&second, second_cap)],
    )
    .unwrap();
    assert_eq!(first_order, second_order);
    assert_eq!(first_order.digest(), second_order.digest());
    assert_eq!(first_order.points().len(), 2);
    assert_eq!(first_order.points()[0].cap(), first_cap);
    assert_eq!(first_order.points()[1].cap(), second_cap);
    assert_eq!(
        first_order.method_artifact_digest(),
        first.producer().method_artifact_digest()
    );
    assert_eq!(first_order.measurement_environment(), environment);
    assert_eq!(
        first_order.freeze_boundary_code(),
        "public_universes_and_caps_frozen_before_hidden_annotations"
    );
    let debug = format!("{first_order:?}");
    assert!(!debug.contains("CANARY_FRONTIER_A"));
    assert!(!debug.contains("annotation_artifact"));
    let changed_cap = ProducerProposalResourceCapV1::try_new(2, 11, 21, 31, 42).unwrap();
    let changed_plan = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        [(&first, first_cap), (&second, changed_cap)],
    )
    .unwrap();
    assert_ne!(first_order.digest(), changed_plan.digest());

    assert_eq!(
        FrozenProducerProposalFrontierPlanV1::try_new(
            environment,
            std::iter::empty::<(
                &FrozenProducerProposalUniverseV1,
                ProducerProposalResourceCapV1,
            )>(),
        ),
        Err(ProducerProposalFrontierErrorV1::EmptyRequestedPoints)
    );
    assert_eq!(
        FrozenProducerProposalFrontierPlanV1::try_new(
            environment,
            [(&first, first_cap), (&first, first_cap)],
        ),
        Err(ProducerProposalFrontierErrorV1::DuplicateUniverseCapPoint)
    );
    let apples_to_apples = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        [(&first, first_cap), (&second, first_cap)],
    )
    .unwrap();
    assert_eq!(apples_to_apples.points().len(), 2);

    let different_method = FrozenProducerProposalUniverseV1::try_new(
        artifact(0x32),
        &case,
        &ledger,
        configured_producer(0x46, 0x47),
        [packet(3, [ledger.events()[2].id()])],
    )
    .unwrap();
    assert_eq!(
        FrozenProducerProposalFrontierPlanV1::try_new(
            environment,
            [(&first, first_cap), (&different_method, second_cap)],
        ),
        Err(ProducerProposalFrontierErrorV1::MethodArtifactMismatch)
    );
    let different_public_artifact = FrozenProducerProposalUniverseV1::try_new(
        artifact(0x48),
        &case,
        &ledger,
        configured_producer(0x40, 0x49),
        [packet(4, [ledger.events()[2].id()])],
    )
    .unwrap();
    assert_eq!(
        FrozenProducerProposalFrontierPlanV1::try_new(
            environment,
            [
                (&first, first_cap),
                (&different_public_artifact, second_cap),
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::PublicCaseBindingMismatch)
    );

    let too_many = (0..=MAX_PRODUCER_PROPOSAL_FRONTIER_POINTS_V1)
        .map(|index| {
            (
                &first,
                ProducerProposalResourceCapV1::try_new(u64::try_from(index).unwrap(), 1, 1, 1, 1)
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        FrozenProducerProposalFrontierPlanV1::try_new(environment, too_many),
        Err(ProducerProposalFrontierErrorV1::TooManyRequestedPoints)
    );
    let boundary_cap = ProducerProposalResourceCapV1::try_new(
        evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX,
        evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX,
        evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX,
        evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX,
        evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX,
    )
    .unwrap();
    assert!(
        FrozenProducerProposalFrontierPlanV1::try_new(environment, [(&first, boundary_cap)])
            .is_ok()
    );
    assert_eq!(
        ProducerProposalResourceCapV1::try_new(
            evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX + 1,
            0,
            0,
            0,
            0,
        ),
        Err(ProducerProposalErrorV1::ResourceCapExceedsJsonSafeInteger)
    );
}

#[test]
fn governed_frontier_retains_all_points_and_exact_non_scalar_dominance() {
    let ledger = ledger(0x50, &[b"high-quality-long\n", b"b", b"unused\n"]);
    let case_artifact = artifact(0x51);
    let annotation_artifact = artifact(0x52);
    let case = public_case(&ledger);
    let blocks = block_index(&ledger);
    let environment = measurement_environment(0x53);
    let costly = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        configured_producer(0x54, 0x55),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let cheap_lower_quality = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        configured_producer(0x54, 0x57),
        [packet(2, [ledger.events()[1].id()])],
    )
    .unwrap();
    let cheaper_equal_quality = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        configured_producer(0x54, 0x59),
        [packet(3, [ledger.events()[0].id()])],
    )
    .unwrap();
    let infeasible = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &case,
        &ledger,
        configured_producer(0x54, 0x5b),
        [packet(4, [ledger.events()[2].id()])],
    )
    .unwrap();
    let shared_eligible_cap =
        ProducerProposalResourceCapV1::try_new(10, 1_000, 100, 100, 100).unwrap();
    let costly_cap = shared_eligible_cap;
    let cheap_cap = shared_eligible_cap;
    let equal_quality_cap = shared_eligible_cap;
    let infeasible_cap = ProducerProposalResourceCapV1::try_new(0, 0, 0, 0, 0).unwrap();

    // The complete configured point set is frozen before hidden annotation.
    let plan = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        [
            (&cheaper_equal_quality, equal_quality_cap),
            (&costly, costly_cap),
            (&cheap_lower_quality, cheap_cap),
            (&infeasible, infeasible_cap),
        ],
    )
    .unwrap();
    let case_annotation = annotation(
        case_artifact,
        [
            requirement(10, [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]]),
            requirement(5, [vec![EvidenceTargetV1::Event(ledger.events()[1].id())]]),
        ],
    );
    let costly_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &costly,
        measurement_with_environment(&ledger, &costly, environment, 10, 10, 10),
        costly_cap,
    );
    let cheap_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &cheap_lower_quality,
        measurement_with_environment(&ledger, &cheap_lower_quality, environment, 1, 1, 1),
        cheap_cap,
    );
    let equal_quality_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &cheaper_equal_quality,
        measurement_with_environment(&ledger, &cheaper_equal_quality, environment, 5, 5, 5),
        equal_quality_cap,
    );
    let infeasible_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &infeasible,
        measurement_with_environment(&ledger, &infeasible, environment, 2, 2, 2),
        infeasible_cap,
    );
    let frontier = evaluate_governed_producer_proposal_frontier_v1(
        &plan,
        [
            cheap_evaluation.clone(),
            equal_quality_evaluation.clone(),
            costly_evaluation.clone(),
            infeasible_evaluation.clone(),
        ],
    )
    .unwrap();
    let replay = evaluate_governed_producer_proposal_frontier_v1(
        &plan,
        [
            costly_evaluation.clone(),
            infeasible_evaluation.clone(),
            cheap_evaluation.clone(),
            equal_quality_evaluation.clone(),
        ],
    )
    .unwrap();
    assert_eq!(frontier, replay);
    assert_eq!(frontier.digest(), replay.digest());
    assert_eq!(frontier.plan_digest(), plan.digest());
    assert_eq!(frontier.points().len(), 4);
    assert_eq!(frontier.eligible_points().count(), 3);
    assert_eq!(frontier.ineligible_points().count(), 1);
    assert_eq!(frontier.measurement_environment(), environment);
    assert_eq!(
        frontier.method_artifact_digest(),
        costly.producer().method_artifact_digest()
    );

    let costly_point = frontier
        .points()
        .iter()
        .find(|point| point.planned().universe_digest() == costly.digest())
        .unwrap();
    assert_eq!(costly_point.recall().exact_weight_ratio(), (10, 15));
    assert!(costly_point.cap_violations().is_none());
    let equal_quality_point = frontier
        .points()
        .iter()
        .find(|point| point.planned().universe_digest() == cheaper_equal_quality.digest())
        .unwrap();
    assert_eq!(equal_quality_point.recall().exact_weight_ratio(), (10, 15));
    assert!(equal_quality_point.cap_violations().is_none());
    let cheap_point = frontier
        .points()
        .iter()
        .find(|point| point.planned().universe_digest() == cheap_lower_quality.digest())
        .unwrap();
    assert_eq!(cheap_point.recall().exact_weight_ratio(), (5, 15));
    assert!(cheap_point.cap_violations().is_none());
    let infeasible_point = frontier
        .points()
        .iter()
        .find(|point| point.planned().universe_digest() == infeasible.digest())
        .unwrap();
    assert_eq!(infeasible_point.cap_violations().unwrap().len(), 5);

    let frontier_universes = frontier
        .frontier_points()
        .map(|point| point.planned().universe_digest())
        .collect::<Vec<_>>();
    assert_eq!(frontier_universes.len(), 2);
    assert!(frontier_universes.contains(&cheap_lower_quality.digest()));
    assert!(frontier_universes.contains(&cheaper_equal_quality.digest()));
    assert!(!frontier_universes.contains(&costly.digest()));
    assert!(!frontier_universes.contains(&infeasible.digest()));
    assert!(!frontier.contains_scalar_score());
    assert!(!frontier.contains_auc());
    assert!(!frontier.contains_verified_winner());
    let debug = format!("{frontier:?}");
    assert!(debug.contains("contains_scalar_score: false"));
    assert!(debug.contains("contains_auc: false"));
    assert!(debug.contains("contains_verified_winner: false"));
    assert!(debug.contains("eligible_point_count: 3"));
    assert!(debug.contains("ineligible_point_count: 1"));
    assert!(!debug.contains("high-quality-long"));

    let all_infeasible_plan =
        FrozenProducerProposalFrontierPlanV1::try_new(environment, [(&infeasible, infeasible_cap)])
            .unwrap();
    let all_infeasible = evaluate_governed_producer_proposal_frontier_v1(
        &all_infeasible_plan,
        [infeasible_evaluation.clone()],
    )
    .unwrap();
    assert_eq!(all_infeasible.points().len(), 1);
    assert_eq!(all_infeasible.eligible_points().count(), 0);
    assert_eq!(all_infeasible.ineligible_points().count(), 1);
    assert_eq!(all_infeasible.frontier_points().count(), 0);

    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                costly_evaluation.clone(),
                cheap_evaluation.clone(),
                equal_quality_evaluation.clone(),
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::MissingOutcomePoints { count: 1 })
    );
    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                costly_evaluation.clone(),
                costly_evaluation.clone(),
                cheap_evaluation.clone(),
                equal_quality_evaluation.clone(),
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::DuplicateOutcomePoint)
    );

    let post_hoc_cap = ProducerProposalResourceCapV1::try_new(9, 9, 9, 9, 9).unwrap();
    let post_hoc_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &costly,
        measurement_with_environment(&ledger, &costly, environment, 10, 10, 10),
        post_hoc_cap,
    );
    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                post_hoc_evaluation,
                cheap_evaluation.clone(),
                equal_quality_evaluation.clone()
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::UnplannedOutcomePoint)
    );

    let foreign_environment = measurement_environment(0x5b);
    let foreign_environment_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &costly,
        measurement_with_environment(&ledger, &costly, foreign_environment, 10, 10, 10),
        costly_cap,
    );
    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                foreign_environment_evaluation,
                cheap_evaluation.clone(),
                equal_quality_evaluation.clone(),
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::MeasurementEnvironmentMismatch)
    );
    let foreign_ledger = ledger_with_source_identity(0x5d, 0x5e, &[b"a", b"b", b"c"]);
    let foreign_case = public_case(&foreign_ledger);
    let foreign_blocks = block_index(&foreign_ledger);
    let foreign_universe = FrozenProducerProposalUniverseV1::try_new(
        case_artifact,
        &foreign_case,
        &foreign_ledger,
        configured_producer(0x54, 0x55),
        [packet(1, [foreign_ledger.events()[0].id()])],
    )
    .unwrap();
    let foreign_annotation = annotation(
        case_artifact,
        [requirement(
            1,
            [vec![EvidenceTargetV1::Event(
                foreign_ledger.events()[0].id(),
            )]],
        )],
    );
    let foreign_acquisition_evaluation = governed_evaluation(
        case_artifact,
        annotation_artifact,
        &foreign_case,
        &foreign_annotation,
        &foreign_ledger,
        &foreign_blocks,
        &foreign_universe,
        measurement_with_environment(&foreign_ledger, &foreign_universe, environment, 10, 10, 10),
        costly_cap,
    );
    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                foreign_acquisition_evaluation,
                cheap_evaluation.clone(),
                equal_quality_evaluation.clone(),
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::AcquisitionBindingMismatch)
    );
    let foreign_annotation_evaluation = governed_evaluation(
        case_artifact,
        artifact(0x5c),
        &case,
        &case_annotation,
        &ledger,
        &blocks,
        &costly,
        measurement_with_environment(&ledger, &costly, environment, 10, 10, 10),
        costly_cap,
    );
    assert_eq!(
        evaluate_governed_producer_proposal_frontier_v1(
            &plan,
            [
                cheap_evaluation,
                foreign_annotation_evaluation,
                equal_quality_evaluation,
            ],
        ),
        Err(ProducerProposalFrontierErrorV1::AnnotationBindingMismatch)
    );
}

#[test]
fn canonical_renderer_reversibly_escapes_arbitrary_authorized_bytes() {
    let raw = b"CANARY_RENDER\x00\xff\n\r\t\\Z\n";
    let ledger = ledger(0xf0, &[raw.as_slice(), b"peer\n"]);
    let case = public_case(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xf1),
        &case,
        &ledger,
        producer(0xf2),
        [packet(1, [ledger.events()[0].id()])],
    )
    .unwrap();
    let rendered = render(&ledger, &universe);

    assert!(rendered.bytes().is_ascii());
    assert!(!rendered.bytes().contains(&0));
    assert!(!rendered.bytes().contains(&0xff));
    assert!(!rendered.bytes().contains(&b'\r'));
    assert_eq!(
        byte_occurrence_count(
            rendered.bytes(),
            b"data: CANARY_RENDER\\x00\\xff\\n\\r\\t\\\\Z\\n\nEND_MEMBER\n",
        ),
        1
    );
    let event_field = format!(
        "event_id: {}\n",
        lowercase_hex(ledger.events()[0].id().as_bytes())
    );
    assert_eq!(
        byte_occurrence_count(rendered.bytes(), event_field.as_bytes()),
        1
    );
    assert_eq!(
        rendered.byte_count(),
        u64::try_from(rendered.bytes().len()).unwrap()
    );
    assert_eq!(
        rendered.artifact_digest().as_bytes(),
        &<[u8; 32]>::from(Sha256::digest(rendered.bytes()))
    );
    assert_eq!(rendered.member_occurrence_count(), 1);
    assert_eq!(
        rendered.occurrence_source_bytes(),
        u64::try_from(raw.len()).unwrap()
    );
    assert_eq!(rendered.unique_member_event_count(), 1);
    assert_eq!(
        rendered.unique_member_source_bytes(),
        u64::try_from(raw.len()).unwrap()
    );
    let identity = canonical_producer_proposal_renderer_v1_identity();
    assert_eq!(rendered.renderer(), identity);
    assert_eq!(identity.contract_version(), 1);
    assert_eq!(identity.code(), "canonical_producer_proposal_renderer_v1");
    assert!(!format!("{rendered:?}").contains("CANARY_RENDER"));
}

#[test]
fn independent_decoder_recovers_every_escape_and_exact_member_boundary() {
    let first_raw = b"literal !~\\\n\r\t\x00\x01\x1f\x7f\x80\xff\r\n";
    let second_raw = b"second-without-terminator";
    let ledger = ledger(0xfd, &[first_raw.as_slice(), second_raw.as_slice()]);
    let case = public_case(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xfe),
        &case,
        &ledger,
        producer(0xff),
        [
            packet(2, [ledger.events()[1].id(), ledger.events()[0].id()]),
            packet(1, [ledger.events()[0].id()]),
        ],
    )
    .unwrap();
    let rendered = render(&ledger, &universe);
    let decoded = independently_decode_proposal_members_v1(&rendered);
    let expected = universe
        .proposals()
        .iter()
        .flat_map(|proposal| {
            proposal
                .member_event_ids()
                .iter()
                .map(|event_id| IndependentlyDecodedProposalMember {
                    proposal_id_hex: lowercase_hex(proposal.id().as_bytes()),
                    event_id_hex: lowercase_hex(event_id.as_bytes()),
                    raw: ledger.event(*event_id).unwrap().raw().to_vec(),
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(decoded, expected);
    assert_eq!(
        decoded
            .iter()
            .filter(|member| member.raw == first_raw)
            .count(),
        2,
        "an overlapping member must retain two exact proposal occurrences"
    );
    assert!(decoded.iter().any(|member| member.raw.ends_with(b"\r\n")));
    assert!(
        decoded
            .iter()
            .any(|member| member.raw == second_raw.as_slice())
    );
}

#[test]
fn canonical_renderer_is_deterministic_and_canonicalizes_proposal_and_member_order() {
    let ledger = ledger(0xf3, &[b"first\n", b"second\r\n", b"third"]);
    let case = public_case(&ledger);
    let first = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xf4),
        &case,
        &ledger,
        producer(0xf5),
        [
            packet(2, [ledger.events()[2].id(), ledger.events()[1].id()]),
            packet(1, [ledger.events()[0].id()]),
        ],
    )
    .unwrap();
    let reordered = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xf4),
        &case,
        &ledger,
        producer(0xf5),
        [
            packet(1, [ledger.events()[0].id()]),
            packet(2, [ledger.events()[1].id(), ledger.events()[2].id()]),
        ],
    )
    .unwrap();
    let first_render = render(&ledger, &first);
    assert_eq!(first, reordered);
    assert_eq!(first_render, render(&ledger, &first));
    assert_eq!(first_render, render(&ledger, &reordered));
    assert_eq!(
        byte_occurrence_count(first_render.bytes(), b"BEGIN_PROPOSAL\n"),
        2
    );
    assert_eq!(
        byte_occurrence_count(first_render.bytes(), b"END_PROPOSAL\n"),
        2
    );

    let mutated_ledger =
        ledger_with_source_identity(0xf3, 0xf6, &[b"first\n", b"changed\r\n", b"third"]);
    let mutated_case = public_case(&mutated_ledger);
    let mutated_universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xf4),
        &mutated_case,
        &mutated_ledger,
        producer(0xf5),
        [packet(1, [mutated_ledger.events()[0].id()])],
    )
    .unwrap();
    assert_ne!(
        first_render.artifact_digest(),
        render(&mutated_ledger, &mutated_universe).artifact_digest()
    );
    let mismatch = render_canonical_producer_proposals_v1(
        &mutated_ledger,
        &first,
        ProducerProposalRenderLimitV1::hard_maximum(),
    );
    assert_eq!(
        mismatch,
        Err(ProducerProposalRenderErrorV1::AcquisitionBindingMismatch)
    );
    assert!(!format!("{:?}", mismatch.unwrap_err()).contains("changed"));
}

#[test]
fn canonical_renderer_charges_overlapping_members_per_proposal_occurrence() {
    let ledger = ledger(0xf7, &[b"first\n", b"OVERLAP\n", b"unused\n"]);
    let case = public_case(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xf8),
        &case,
        &ledger,
        producer(0xf9),
        [
            packet(1, [ledger.events()[0].id(), ledger.events()[1].id()]),
            packet(2, [ledger.events()[1].id()]),
        ],
    )
    .unwrap();
    let rendered = render(&ledger, &universe);
    let first_bytes = u64::try_from(ledger.events()[0].raw().len()).unwrap();
    let overlap_bytes = u64::try_from(ledger.events()[1].raw().len()).unwrap();
    assert_eq!(rendered.proposal_packet_count(), 2);
    assert_eq!(rendered.member_occurrence_count(), 3);
    assert_eq!(
        rendered.occurrence_source_bytes(),
        first_bytes + overlap_bytes * 2
    );
    assert_eq!(rendered.unique_member_event_count(), 2);
    assert_eq!(
        rendered.unique_member_source_bytes(),
        first_bytes + overlap_bytes
    );
    assert_eq!(
        byte_occurrence_count(rendered.bytes(), b"data: OVERLAP\\n\n"),
        2
    );

    let exact_limit =
        ProducerProposalRenderLimitV1::try_new(usize::try_from(rendered.byte_count()).unwrap())
            .unwrap();
    assert_eq!(
        render_canonical_producer_proposals_v1(&ledger, &universe, exact_limit).unwrap(),
        rendered
    );
    let one_below =
        ProducerProposalRenderLimitV1::try_new(usize::try_from(rendered.byte_count() - 1).unwrap())
            .unwrap();
    assert_eq!(
        render_canonical_producer_proposals_v1(&ledger, &universe, one_below),
        Err(ProducerProposalRenderErrorV1::OutputLimitExceeded)
    );
}

#[test]
fn canonical_renderer_has_one_empty_artifact_and_rejects_invalid_bounds() {
    assert_eq!(
        ProducerProposalRenderLimitV1::try_new(0),
        Err(ProducerProposalRenderErrorV1::ZeroOutputLimit)
    );
    assert_eq!(
        ProducerProposalRenderLimitV1::try_new(MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1 + 1),
        Err(ProducerProposalRenderErrorV1::OutputLimitExceedsHardMaximum)
    );

    let ledger = ledger(0xfa, &[b"retained-but-not-proposed\n"]);
    let case = public_case(&ledger);
    let universe = FrozenProducerProposalUniverseV1::try_new(
        artifact(0xfb),
        &case,
        &ledger,
        producer(0xfc),
        std::iter::empty::<ProducerProposalPacketV1>(),
    )
    .unwrap();
    let first = render(&ledger, &universe);
    let second = render(&ledger, &universe);
    assert_eq!(first, second);
    assert_eq!(first.proposal_packet_count(), 0);
    assert_eq!(first.member_occurrence_count(), 0);
    assert_eq!(first.occurrence_source_bytes(), 0);
    assert_eq!(first.unique_member_event_count(), 0);
    assert_eq!(first.unique_member_source_bytes(), 0);
    assert_eq!(byte_occurrence_count(first.bytes(), b"BEGIN_PROPOSAL\n"), 0);
    assert!(
        first
            .bytes()
            .ends_with(b"END_EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n")
    );
    assert_eq!(
        render_canonical_producer_proposals_v1(
            &ledger,
            &universe,
            ProducerProposalRenderLimitV1::try_new(32).unwrap(),
        ),
        Err(ProducerProposalRenderErrorV1::OutputLimitExceeded)
    );
}
