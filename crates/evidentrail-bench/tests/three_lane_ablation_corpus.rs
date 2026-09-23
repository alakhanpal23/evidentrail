use std::collections::BTreeSet;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateResourceCap, EvidenceTargetV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1,
    EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1,
    ExpectedAcquisitionClassV1, FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    FrozenPublicSyntheticThreeLaneSelectionCorpusV1, GovernedCaseArtifactBindingV1,
    GovernedSyntheticThreeLaneAblationCaseInputV1, GovernedSyntheticThreeLaneSelectionCaseInputV1,
    MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, MatchedBaselineArmV1,
    MeasuredProducerProposalResourcesV1, ProducerProposalMeasurementEnvironmentV1,
    ProducerProposalMeasurementReceiptV1, ProducerProposalRenderLimitV1,
    ProducerProposalResourceCapV1, RequiredEventSelectionDispositionV1,
    RequiredEventSelectionResidualV1, RequirementSelectionAttributionClassV1,
    SelectorChallengerAdmissionBlockerV1, SelectorChallengerComparisonCaseV1,
    SelectorChallengerRecallRelationV1, SelectorPerturbationCaseV1,
    SelectorPerturbationExpectedOutcomeV1, SelectorPerturbationGovernedAnnotationV1,
    SyntheticThreeLaneAblationCaseV1, SyntheticThreeLaneAblationFamilyV1,
    SyntheticThreeLaneAblationPublicCaseInputV1, SyntheticThreeLaneCorpusErrorV1,
    SyntheticThreeLaneCorpusScopeV1, SyntheticThreeLaneNeedsMoreClassV1,
    SyntheticThreeLaneSelectionBudgetScheduleV1, SyntheticThreeLaneSelectionPublicCaseInputV1,
    ThreeLaneAblationMaskV1, ThreeLaneAblationMeasurementAllocationV1,
    ThreeLaneAblationPreparationDecisionV1, ThreeLaneAblationPublicPointInputV1,
    ThreeLaneSelectionCorpusErrorV1, WeightedDiagnosticRequirementV1,
    canonical_producer_proposal_renderer_v1_identity,
    evaluate_governed_selector_challenger_comparison_v1,
    evaluate_governed_selector_perturbation_corpus_v1,
    evaluate_governed_synthetic_three_lane_ablation_corpus_v1,
    evaluate_governed_synthetic_three_lane_selection_corpus_v1,
    freeze_prepared_three_lane_ablations_v1, freeze_public_synthetic_three_lane_ablation_corpus_v1,
    freeze_public_synthetic_three_lane_selection_corpus_v1,
    freeze_public_three_lane_ablation_batch_v1, freeze_selector_challenger_comparison_v1,
    freeze_selector_perturbation_corpus_v1, prepare_three_lane_ablations_v1,
    render_canonical_producer_proposals_v1, synthetic_three_lane_ablation_corpus_identity_v1,
    synthetic_three_lane_selection_budget_schedule_v1, three_lane_ablation_config_digest_v1,
    three_lane_ablation_method_family_digest_v1,
};
use evidentrail_compile::{
    ThreeLaneNeedsMoreV1, proposal_candidate_config_digest_v1, proposal_compiler_config_digest_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FetchUnknownReason, FramingPolicy, LaneKey, LaneSequence, LedgerBuilder,
    PlanDigest, PlanId, PolicyAuthorization, ProviderAttestationScopeDigestV1,
    ProviderAttestationValueV1, ProviderAttestationsV1, ProviderAttestedCorrelationV1,
    ProviderAttestedRelationKindV1, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState,
    ResultId, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_evidence::{PinnedTokenizer, Utf8ByteTokenizerV1, utf8_byte_tokenizer_digest_v1};
use evidentrail_schema::ArtifactDigest;
use evidentrail_select::{NeedsMoreReasonV1, ProductionFacetKindV1, SelectionConstraintV1};

const RECORD_COUNT: usize = 12;
const STRUCTURAL_CANARY: &str = "CANARY_STRUCTURAL_INJECTION_72f1";
const QUESTION_CANARY: &str = "CANARY_QUESTION_SHOULD_NOT_LEAK_920d";

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone)]
struct SyntheticRecord {
    raw: Vec<u8>,
    terminator: Vec<u8>,
    stream: SourceStream,
    attestations: ProviderAttestationsV1,
}

impl SyntheticRecord {
    fn ordinary(position: usize) -> Self {
        Self {
            raw: format!("ordinary heartbeat {position:02}").into_bytes(),
            terminator: if position + 1 == RECORD_COUNT {
                Vec::new()
            } else if position % 3 == 0 {
                b"\r\n".to_vec()
            } else {
                b"\n".to_vec()
            },
            stream: SourceStream::Stderr,
            attestations: ProviderAttestationsV1::default(),
        }
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn case_position(case: SyntheticThreeLaneAblationCaseV1) -> usize {
    SyntheticThreeLaneAblationCaseV1::ALL
        .iter()
        .position(|candidate| *candidate == case)
        .unwrap()
}

fn question(case: SyntheticThreeLaneAblationCaseV1) -> &'static [u8] {
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => {
            b"diagnose 123e4567-e89b-12d3-a456-426614174000 CANARY_QUESTION_SHOULD_NOT_LEAK_920d"
        }
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle
        | SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail
        | SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors
        | SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => b"",
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => {
            b"diagnose 123e4567-e89b-12d3-a456-426614174999"
        }
    }
}

fn acquisition_class(case: SyntheticThreeLaneAblationCaseV1) -> ExpectedAcquisitionClassV1 {
    match case {
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => {
            ExpectedAcquisitionClassV1::Partial
        }
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
            ExpectedAcquisitionClassV1::Unknown
        }
        _ => ExpectedAcquisitionClassV1::Complete,
    }
}

fn completeness(case: SyntheticThreeLaneAblationCaseV1) -> FetchCompleteness {
    match case {
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            None,
        ),
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
            FetchCompleteness::unknown(FetchUnknownReason::RetentionUnobservable)
        }
        _ => FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    }
}

fn trace_attestations(value: &[u8]) -> ProviderAttestationsV1 {
    ProviderAttestationsV1::new([ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([0xa7; 32]),
        ProviderAttestedRelationKindV1::TraceIdentity,
        ProviderAttestationValueV1::new(value.to_vec()).unwrap(),
    )])
    .unwrap()
}

fn records(case: SyntheticThreeLaneAblationCaseV1) -> Vec<SyntheticRecord> {
    let mut records = (0..RECORD_COUNT)
        .map(SyntheticRecord::ordinary)
        .collect::<Vec<_>>();
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => {
            records[2].raw =
                b"request 123e4567-e89b-12d3-a456-426614174000 cannot be found".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => {
            records[2].raw = b"deployment started".to_vec();
            records[5].raw = b"fatal crash after rollout".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => {
            records[2].raw = b"request entered worker".to_vec();
            records[8].raw = b"request left worker near tail".to_vec();
            records[2].attestations = trace_attestations(b"trace-provider-only");
            records[8].attestations = trace_attestations(b"trace-provider-only");
        }
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => {
            for (position, record) in records.iter_mut().enumerate() {
                record.stream = if position % 2 == 0 {
                    SourceStream::Stdout
                } else {
                    SourceStream::Stderr
                };
            }
            records[2].raw = b"provider-linked precursor".to_vec();
            records[3].raw = b"provider-linked sibling".to_vec();
            records[2].attestations = trace_attestations(b"trace-mixed");
            records[3].attestations = trace_attestations(b"trace-mixed");
            records[5].raw = b"request 123e4567-e89b-12d3-a456-426614174999 selected".to_vec();
            records[8].raw = b"panic at mixed-lane tail context".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => {
            for record in &mut records {
                record.raw = b"retry heartbeat repeated distractor".to_vec();
            }
            records[5].raw = b"panic worker unavailable".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
            records[0].raw = [
                b"\0\xff\nEVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n".as_slice(),
                STRUCTURAL_CANARY.as_bytes(),
                b"\r\\tail".as_slice(),
            ]
            .concat();
        }
    }
    records
}

fn ledger(case: SyntheticThreeLaneAblationCaseV1) -> EventLedger {
    let seed = u8::try_from(case_position(case) + 20).unwrap();
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("synthetic-three-lane-corpus", "v1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let member = SourceMember::new(b"synthetic-conformance-member".to_vec()).unwrap();
    let records = records(case);
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut stdout_sequence = 0_u64;
    let mut stderr_sequence = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    for (position, record) in records.into_iter().enumerate() {
        let lane_sequence = match record.stream {
            SourceStream::Stdout => {
                let current = stdout_sequence;
                stdout_sequence += 1;
                current
            }
            SourceStream::Stderr => {
                let current = stderr_sequence;
                stderr_sequence += 1;
                current
            }
            _ => panic!("fixture uses only stdout/stderr"),
        };
        payload_bytes += u64::try_from(record.raw.len()).unwrap();
        source_bytes += u64::try_from(record.raw.len() + record.terminator.len()).unwrap();
        builder
            .accept(
                RawEnvelopeV1::new(
                    envelope_identity.clone(),
                    EnvelopeOrdering::new(
                        AcquisitionSequence::new(u64::try_from(position).unwrap()),
                        LaneKey::new(member.clone(), record.stream),
                        LaneSequence::new(lane_sequence),
                    ),
                    RecordBytes::framed(record.raw, record.terminator),
                    RecordState::Complete,
                )
                .with_provider_attestations(record.attestations),
            )
            .unwrap();
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    u64::try_from(RECORD_COUNT).unwrap(),
                    payload_bytes,
                    source_bytes,
                ),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                completeness(case),
            )
            .unwrap(),
        )
        .unwrap()
}

fn blocks(ledger: &EventLedger) -> BlockIndex<'_> {
    BlockIndex::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"synthetic-singleton".to_vec(), b"v1".to_vec()),
                BlockState::Reconstructed,
                BlockConfidence::Certain,
            )
        }),
    )
    .unwrap()
}

fn measurement_environment() -> ProducerProposalMeasurementEnvironmentV1 {
    let renderer = canonical_producer_proposal_renderer_v1_identity();
    ProducerProposalMeasurementEnvironmentV1::try_new(
        renderer.artifact_digest(),
        renderer.contract_version(),
        utf8_byte_tokenizer_digest_v1(),
        1,
        artifact(231),
        1,
    )
    .unwrap()
}

fn public_case(
    case: SyntheticThreeLaneAblationCaseV1,
    ledger: &EventLedger,
) -> EvidentrailBenchCaseSpecV1 {
    let position = u8::try_from(case_position(case)).unwrap();
    EvidentrailBenchCaseSpecV1::new(
        [artifact(100 + position)],
        derive_question_digest_v1(question(case)),
        ledger.plan_digest(),
        [artifact(120 + position)],
        [artifact(140 + position)],
        [
            CandidateResourceCap::try_new(1_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
                .unwrap(),
        ],
        acquisition_class(case),
    )
    .unwrap()
}

fn generous_cap() -> ProducerProposalResourceCapV1 {
    ProducerProposalResourceCapV1::try_new(1_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
        .unwrap()
}

fn point_inputs(
    case: SyntheticThreeLaneAblationCaseV1,
    ledger: &EventLedger,
    frozen: &evidentrail_bench::FrozenThreeLaneAblationSetV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cost_offset: u64,
) -> Vec<ThreeLaneAblationPublicPointInputV1> {
    let case_offset = u64::try_from(case_position(case)).unwrap();
    let wall = 101 + cost_offset + case_offset;
    let rss = 201 + cost_offset + case_offset;
    let cap = if case == SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes {
        ProducerProposalResourceCapV1::try_new(0, 0, 0, 0, 0).unwrap()
    } else {
        generous_cap()
    };
    ThreeLaneAblationMaskV1::ALL
        .into_iter()
        .map(|mask| {
            let universe = frozen.configuration(mask).universe();
            let rendered = render_canonical_producer_proposals_v1(
                ledger,
                universe,
                ProducerProposalRenderLimitV1::hard_maximum(),
            )
            .unwrap();
            let render_tokens = Utf8ByteTokenizerV1::new()
                .count_tokens(std::str::from_utf8(rendered.bytes()).unwrap())
                .unwrap();
            let measured =
                MeasuredProducerProposalResourcesV1::try_new(render_tokens, Some(wall), Some(rss))
                    .unwrap();
            let receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted_borrowed(
                universe,
                &rendered,
                environment,
                measured,
            )
            .unwrap();
            ThreeLaneAblationPublicPointInputV1::new(mask, cap, rendered, receipt)
        })
        .collect()
}

fn public_batch(
    case: SyntheticThreeLaneAblationCaseV1,
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cost_offset: u64,
) -> evidentrail_bench::FrozenPublicThreeLaneAblationBatchV1 {
    let position = u8::try_from(case_position(case)).unwrap();
    let prepared = match prepare_three_lane_ablations_v1(
        question(case),
        ledger,
        blocks,
        ResultId::from_bytes([170 + position; 32]),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
    {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(residual) => {
            panic!("synthetic conformance preparation residual: {residual:?}")
        }
    };
    let public_case = public_case(case, ledger);
    let frozen = freeze_prepared_three_lane_ablations_v1(
        case.identity_digest(),
        &public_case,
        ledger,
        &prepared,
    )
    .unwrap();
    let points = point_inputs(case, ledger, &frozen, environment, cost_offset);
    freeze_public_three_lane_ablation_batch_v1(
        case.identity_digest(),
        public_case,
        frozen,
        environment,
        ThreeLaneAblationMeasurementAllocationV1::ConservativeSharedBatchFullChargeEachConfiguration,
        points,
    )
    .unwrap()
}

fn public_case_inputs(
    ledgers: &[EventLedger],
    blocks: &[BlockIndex<'_>],
    cost_offset: u64,
) -> Vec<SyntheticThreeLaneAblationPublicCaseInputV1> {
    let environment = measurement_environment();
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            SyntheticThreeLaneAblationPublicCaseInputV1::new(
                case,
                public_batch(
                    case,
                    &ledgers[position],
                    &blocks[position],
                    environment,
                    cost_offset,
                ),
            )
        })
        .collect()
}

fn public_corpus(
    ledgers: &[EventLedger],
    blocks: &[BlockIndex<'_>],
    cost_offset: u64,
    reverse_inputs: bool,
) -> FrozenPublicSyntheticThreeLaneAblationCorpusV1 {
    let mut inputs = public_case_inputs(ledgers, blocks, cost_offset);
    if reverse_inputs {
        inputs.reverse();
    }
    freeze_public_synthetic_three_lane_ablation_corpus_v1(inputs).unwrap()
}

fn prepared_ablation_set(
    case: SyntheticThreeLaneAblationCaseV1,
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
) -> evidentrail_bench::PreparedThreeLaneAblationSetV1 {
    let position = u8::try_from(case_position(case)).unwrap();
    match prepare_three_lane_ablations_v1(
        question(case),
        ledger,
        blocks,
        ResultId::from_bytes([170 + position; 32]),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
    {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(residual) => {
            panic!("synthetic conformance preparation residual: {residual:?}")
        }
    }
}

fn prepared_ablation_sets(
    ledgers: &[EventLedger],
    blocks: &[BlockIndex<'_>],
) -> Vec<evidentrail_bench::PreparedThreeLaneAblationSetV1> {
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| prepared_ablation_set(case, &ledgers[position], &blocks[position]))
        .collect()
}

fn selection_public_corpus(
    source: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    ledgers: &[EventLedger],
    prepared: &[evidentrail_bench::PreparedThreeLaneAblationSetV1],
    schedule: SyntheticThreeLaneSelectionBudgetScheduleV1,
    reverse_inputs: bool,
) -> FrozenPublicSyntheticThreeLaneSelectionCorpusV1 {
    let mut inputs = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            SyntheticThreeLaneSelectionPublicCaseInputV1::new(
                case,
                &prepared[position],
                &ledgers[position],
                question(case),
                UnixTimestampNanos::new(50_000),
                UnixTimestampNanos::new(60_000),
            )
        })
        .collect::<Vec<_>>();
    if reverse_inputs {
        inputs.reverse();
    }
    freeze_public_synthetic_three_lane_selection_corpus_v1(source, schedule, inputs).unwrap()
}

fn target_indices(case: SyntheticThreeLaneAblationCaseV1) -> &'static [usize] {
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => &[2],
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => &[2, 5],
        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => &[2, 8],
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => &[2, 5, 8],
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => &[5],
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => &[0],
    }
}

fn annotations(ledgers: &[EventLedger]) -> Vec<EvidentrailBenchAnnotationSpecV1> {
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            let targets = target_indices(case)
                .iter()
                .map(|target| EvidenceTargetV1::Event(ledgers[position].events()[*target].id()))
                .collect::<Vec<_>>();
            let weight = 3 + u64::try_from(position).unwrap() * 2;
            EvidentrailBenchAnnotationSpecV1::new(
                case.identity_digest(),
                [WeightedDiagnosticRequirementV1::new(weight, [targets]).unwrap()],
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        })
        .collect()
}

fn hidden_manifest(
    public_run_manifest_artifact: ArtifactDigest,
) -> EvidentrailBenchHiddenEvaluationManifestV1 {
    let budget = BenchmarkBudgetV1::try_new(
        Some(1_000),
        Some(1_000),
        Some(1_000),
        Some(1_000),
        Some(1_000),
    )
    .unwrap();
    let run_identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(200)),
        Some(artifact(201)),
        Some(synthetic_three_lane_ablation_corpus_identity_v1()),
        Some(1),
        Some(budget),
    )
    .unwrap();
    let public = EvidentrailBenchRunManifestV1::new(
        run_identity,
        SyntheticThreeLaneAblationCaseV1::ALL.map(|case| case.identity_digest()),
    )
    .unwrap();
    let bindings = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            GovernedCaseArtifactBindingV1::new(
                case.identity_digest(),
                artifact(210 + u8::try_from(position).unwrap()),
            )
        });
    EvidentrailBenchHiddenEvaluationManifestV1::new(
        public_run_manifest_artifact,
        &public,
        artifact(220),
        artifact(221),
        bindings,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn governed_input<'input, 'ledger>(
    _public: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    annotations: &'input [EvidentrailBenchAnnotationSpecV1],
    ledgers: &'ledger [EventLedger],
    blocks: &'input [BlockIndex<'ledger>],
    hidden: &EvidentrailBenchHiddenEvaluationManifestV1,
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    public_corpus_digest: evidentrail_bench::FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    public_batch_digest: evidentrail_bench::FrozenPublicThreeLaneAblationBatchDigestV1,
    join_case: SyntheticThreeLaneAblationCaseV1,
) -> GovernedSyntheticThreeLaneAblationCaseInputV1<'input, 'ledger> {
    let position = case_position(case);
    let join_position = case_position(join_case);
    let binding = GovernedCaseArtifactBindingV1::new(
        join_case.identity_digest(),
        artifact(210 + u8::try_from(join_position).unwrap()),
    );
    GovernedSyntheticThreeLaneAblationCaseInputV1::new(
        case,
        family,
        public_corpus_digest,
        public_batch_digest,
        hidden.resolve_case_binding(binding).unwrap(),
        &annotations[position],
        &ledgers[position],
        &blocks[position],
    )
}

fn governed_inputs<'input, 'ledger>(
    public: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    annotations: &'input [EvidentrailBenchAnnotationSpecV1],
    ledgers: &'ledger [EventLedger],
    blocks: &'input [BlockIndex<'ledger>],
    hidden: &EvidentrailBenchHiddenEvaluationManifestV1,
) -> Vec<GovernedSyntheticThreeLaneAblationCaseInputV1<'input, 'ledger>> {
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                public,
                annotations,
                ledgers,
                blocks,
                hidden,
                case,
                case.family(),
                public.digest(),
                public.case(case).batch().digest(),
                case,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn governed_selection_input<'input, 'ledger>(
    public: &FrozenPublicSyntheticThreeLaneSelectionCorpusV1,
    source: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    annotations: &'input [EvidentrailBenchAnnotationSpecV1],
    ledgers: &'ledger [EventLedger],
    blocks: &'input [BlockIndex<'ledger>],
    hidden: &EvidentrailBenchHiddenEvaluationManifestV1,
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    selection_corpus_digest: evidentrail_bench::FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    selection_case: SyntheticThreeLaneAblationCaseV1,
    source_batch_case: SyntheticThreeLaneAblationCaseV1,
    annotation_case: SyntheticThreeLaneAblationCaseV1,
    join_case: SyntheticThreeLaneAblationCaseV1,
) -> GovernedSyntheticThreeLaneSelectionCaseInputV1<'input, 'ledger> {
    let position = case_position(case);
    let join_position = case_position(join_case);
    let binding = GovernedCaseArtifactBindingV1::new(
        join_case.identity_digest(),
        artifact(210 + u8::try_from(join_position).unwrap()),
    );
    GovernedSyntheticThreeLaneSelectionCaseInputV1::new(
        case,
        family,
        selection_corpus_digest,
        public.case(selection_case).digest(),
        source.case(source_batch_case).batch().digest(),
        hidden.resolve_case_binding(binding).unwrap(),
        &annotations[case_position(annotation_case)],
        &ledgers[position],
        &blocks[position],
    )
}

fn governed_selection_inputs<'input, 'ledger>(
    public: &FrozenPublicSyntheticThreeLaneSelectionCorpusV1,
    source: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    annotations: &'input [EvidentrailBenchAnnotationSpecV1],
    ledgers: &'ledger [EventLedger],
    blocks: &'input [BlockIndex<'ledger>],
    hidden: &EvidentrailBenchHiddenEvaluationManifestV1,
) -> Vec<GovernedSyntheticThreeLaneSelectionCaseInputV1<'input, 'ledger>> {
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_selection_input(
                public,
                source,
                annotations,
                ledgers,
                blocks,
                hidden,
                case,
                case.family(),
                public.digest(),
                case,
                case,
                case,
                case,
            )
        })
        .collect()
}

fn contains_event(
    public: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    case: SyntheticThreeLaneAblationCaseV1,
    mask: ThreeLaneAblationMaskV1,
    event_id: evidentrail_core::EventId,
) -> bool {
    public
        .case(case)
        .batch()
        .ablations()
        .configuration(mask)
        .universe()
        .proposals()
        .iter()
        .any(|proposal| proposal.member_event_ids().contains(&event_id))
}

fn setup_ledgers() -> Vec<EventLedger> {
    SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(ledger)
        .collect()
}

#[test]
fn six_case_public_then_governed_corpus_is_exact_deterministic_and_non_claiming() {
    let ledgers = setup_ledgers();
    let blocks = ledgers.iter().map(blocks).collect::<Vec<_>>();

    // No annotation type is constructed before the complete public corpus.
    let public = public_corpus(&ledgers, &blocks, 0, false);
    let public_replay = public_corpus(&ledgers, &blocks, 0, true);
    assert_eq!(public.digest(), public_replay.digest());
    assert_eq!(
        public.corpus_identity(),
        synthetic_three_lane_ablation_corpus_identity_v1()
    );
    assert_eq!(public.cases().len(), 6);
    assert_eq!(
        public.method_family_digest(),
        three_lane_ablation_method_family_digest_v1()
    );
    assert_eq!(public.environment(), measurement_environment());
    assert_eq!(
        public.scope(),
        SyntheticThreeLaneCorpusScopeV1::SyntheticConformanceOnlyGeneratorFamiliesNotIndependent
    );
    assert!(!public.contains_annotations());
    assert_eq!(
        public.staging_trust_boundary_code(),
        "label_free_data_boundary_not_external_temporal_attestation"
    );
    assert_eq!(
        SyntheticThreeLaneAblationCaseV1::ALL
            .into_iter()
            .map(SyntheticThreeLaneAblationCaseV1::identity_digest)
            .collect::<BTreeSet<_>>()
            .len(),
        6
    );
    assert_eq!(
        SyntheticThreeLaneAblationFamilyV1::ALL
            .into_iter()
            .map(SyntheticThreeLaneAblationFamilyV1::identity_digest)
            .collect::<BTreeSet<_>>()
            .len(),
        5
    );
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let frozen = public.case(case);
        assert_eq!(frozen.family(), case.family());
        assert_eq!(frozen.batch().points().len(), 4);
        assert_eq!(
            frozen.batch().allocation(),
            ThreeLaneAblationMeasurementAllocationV1::ConservativeSharedBatchFullChargeEachConfiguration
        );
        for mask in ThreeLaneAblationMaskV1::ALL {
            let point = frozen.batch().point(mask);
            assert_eq!(point.mask(), mask);
            assert_eq!(
                point.measurement().measured().wall_time_nanos(),
                frozen.batch().shared_wall_time_nanos()
            );
            assert_eq!(
                point.measurement().measured().peak_rss_bytes(),
                frozen.batch().shared_peak_rss_bytes()
            );
        }
    }

    // The synthetic fixtures exercise one lane-exclusive target per relevant
    // family without hand-authoring producer packets.
    let lexical_case = SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead;
    let lexical_event = ledgers[case_position(lexical_case)].events()[2].id();
    assert!(contains_event(
        &public,
        lexical_case,
        ThreeLaneAblationMaskV1::Full,
        lexical_event
    ));
    assert!(!contains_event(
        &public,
        lexical_case,
        ThreeLaneAblationMaskV1::WithoutLexical,
        lexical_event
    ));

    let coverage_case = SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle;
    for target in [2, 5] {
        let event = ledgers[case_position(coverage_case)].events()[target].id();
        assert!(contains_event(
            &public,
            coverage_case,
            ThreeLaneAblationMaskV1::Full,
            event
        ));
        assert!(!contains_event(
            &public,
            coverage_case,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            event
        ));
    }

    let provider_case = SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail;
    for target in [2, 8] {
        let event = ledgers[case_position(provider_case)].events()[target].id();
        assert!(contains_event(
            &public,
            provider_case,
            ThreeLaneAblationMaskV1::Full,
            event
        ));
        assert!(!contains_event(
            &public,
            provider_case,
            ThreeLaneAblationMaskV1::WithoutProvider,
            event
        ));
    }

    let mixed_case = SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved;
    let mixed_ledger = &ledgers[case_position(mixed_case)];
    assert!(
        mixed_ledger
            .events()
            .windows(2)
            .all(|pair| pair[0].lane().stream() != pair[1].lane().stream())
    );
    for (mask, target) in [
        (ThreeLaneAblationMaskV1::WithoutProvider, 2),
        (ThreeLaneAblationMaskV1::WithoutLexical, 5),
        (ThreeLaneAblationMaskV1::WithoutCoverage, 8),
    ] {
        let event = mixed_ledger.events()[target].id();
        assert!(contains_event(
            &public,
            mixed_case,
            ThreeLaneAblationMaskV1::Full,
            event
        ));
        assert!(!contains_event(&public, mixed_case, mask, event));
    }

    let partial_case = SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors;
    assert_eq!(
        public
            .case(partial_case)
            .batch()
            .public_case()
            .expected_acquisition_class(),
        ExpectedAcquisitionClassV1::Partial
    );
    let unknown_case = SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes;
    assert_eq!(
        public
            .case(unknown_case)
            .batch()
            .public_case()
            .expected_acquisition_class(),
        ExpectedAcquisitionClassV1::Unknown
    );
    assert!(
        public
            .case(unknown_case)
            .batch()
            .ablations()
            .configuration(ThreeLaneAblationMaskV1::WithoutCoverage)
            .universe()
            .proposals()
            .is_empty()
    );
    let arbitrary_render = public
        .case(unknown_case)
        .batch()
        .point(ThreeLaneAblationMaskV1::Full)
        .canonical_artifact()
        .bytes();
    assert!(arbitrary_render.is_ascii());
    assert!(arbitrary_render.windows(4).any(|window| window == b"\\x00"));
    assert!(arbitrary_render.windows(4).any(|window| window == b"\\xff"));
    assert!(arbitrary_render.windows(2).any(|window| window == b"\\n"));
    assert!(!arbitrary_render.windows(2).any(|window| window == b"\n\0"));
    assert!(
        !arbitrary_render
            .windows(b"\nEVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1".len())
            .any(|window| window == b"\nEVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1")
    );

    let public_debug = format!("{public:?}");
    for canary in [
        STRUCTURAL_CANARY,
        "123e4567-e89b-12d3-a456-426614174000",
        "fatal crash",
        QUESTION_CANARY,
    ] {
        assert!(!public_debug.contains(canary));
    }

    // Governed material enters only after the complete public package exists.
    let annotations = annotations(&ledgers);
    let hidden = hidden_manifest(artifact(225));
    let governed = evaluate_governed_synthetic_three_lane_ablation_corpus_v1(
        &public,
        governed_inputs(&public, &annotations, &ledgers, &blocks, &hidden),
    )
    .unwrap();
    assert_eq!(governed.public_corpus_digest(), public.digest());
    assert_eq!(governed.cases().len(), 6);
    assert_eq!(governed.family_macro_recalls().len(), 20);
    assert_eq!(governed.family_lane_removal_deltas().len(), 15);
    assert!(!governed.contains_scalar_composite());
    assert!(!governed.contains_auc());
    assert!(!governed.contains_winner());
    assert!(!governed.contains_vds_claim());
    assert!(!governed.contains_statistical_claim());
    assert!(!governed.contains_general_quality_claim());
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let governed_case = governed.case(case);
        assert_eq!(governed_case.family(), case.family());
        assert_eq!(governed_case.batch().evaluations().len(), 4);
    }
    assert_eq!(
        governed
            .case(lexical_case)
            .batch()
            .evaluation(ThreeLaneAblationMaskV1::Full)
            .evaluation()
            .recall()
            .exact_weight_ratio(),
        (3, 3)
    );
    assert_eq!(
        governed
            .case(lexical_case)
            .batch()
            .evaluation(ThreeLaneAblationMaskV1::WithoutLexical)
            .evaluation()
            .recall()
            .exact_weight_ratio(),
        (0, 3)
    );
    for (case, removed, weight) in [
        (coverage_case, ThreeLaneAblationMaskV1::WithoutCoverage, 5),
        (provider_case, ThreeLaneAblationMaskV1::WithoutProvider, 7),
        (mixed_case, ThreeLaneAblationMaskV1::WithoutLexical, 9),
        (mixed_case, ThreeLaneAblationMaskV1::WithoutCoverage, 9),
        (mixed_case, ThreeLaneAblationMaskV1::WithoutProvider, 9),
        (partial_case, ThreeLaneAblationMaskV1::WithoutCoverage, 11),
        (unknown_case, ThreeLaneAblationMaskV1::WithoutCoverage, 13),
    ] {
        assert_eq!(
            governed
                .case(case)
                .batch()
                .evaluation(ThreeLaneAblationMaskV1::Full)
                .evaluation()
                .recall()
                .exact_weight_ratio(),
            (weight, weight)
        );
        assert_eq!(
            governed
                .case(case)
                .batch()
                .evaluation(removed)
                .evaluation()
                .recall()
                .exact_weight_ratio(),
            (0, weight)
        );
    }
    let unknown = governed.case(unknown_case).batch();
    assert_eq!(unknown.frontier().frontier_points().count(), 0);
    assert_eq!(unknown.frontier().ineligible_points().count(), 4);
    assert!(
        unknown
            .evaluations()
            .iter()
            .all(|point| point.evaluation().cap_violations().is_some())
    );

    let lexical_full = governed
        .family_macro_recalls()
        .iter()
        .find(|summary| {
            summary.family() == SyntheticThreeLaneAblationFamilyV1::Lexical
                && summary.mask() == ThreeLaneAblationMaskV1::Full
        })
        .unwrap();
    assert_eq!(lexical_full.components().len(), 1);
    assert_eq!(
        lexical_full.formula_code(),
        "unweighted_mean_of_exact_case_weighted_requirement_recall_components"
    );
    let lexical_delta = governed
        .family_lane_removal_deltas()
        .iter()
        .find(|summary| {
            summary.family() == SyntheticThreeLaneAblationFamilyV1::Lexical
                && summary.ablated_mask() == ThreeLaneAblationMaskV1::WithoutLexical
        })
        .unwrap();
    assert_eq!(lexical_delta.components().len(), 1);
    assert!(lexical_delta.components().iter().any(|component| {
        component.case() == lexical_case && component.exact_delta_magnitude_ratio() == (3, 3)
    }));
    let coverage_full = governed
        .family_macro_recalls()
        .iter()
        .find(|summary| {
            summary.family() == SyntheticThreeLaneAblationFamilyV1::Coverage
                && summary.mask() == ThreeLaneAblationMaskV1::Full
        })
        .unwrap();
    assert_eq!(coverage_full.components().len(), 2);

    let governed_debug = format!("{governed:?}");
    for canary in [
        STRUCTURAL_CANARY,
        "123e4567-e89b-12d3-a456-426614174999",
        "trace-provider-only",
        QUESTION_CANARY,
    ] {
        assert!(!governed_debug.contains(canary));
    }
}

#[test]
fn governed_corpus_rejects_missing_duplicate_foreign_family_and_join_mutations() {
    let ledgers = setup_ledgers();
    let blocks = ledgers.iter().map(blocks).collect::<Vec<_>>();
    let public = public_corpus(&ledgers, &blocks, 0, false);
    let foreign_public = public_corpus(&ledgers, &blocks, 1, false);
    let annotations = annotations(&ledgers);
    let hidden = hidden_manifest(artifact(225));
    let first = SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead;

    let mut missing_public = public_case_inputs(&ledgers, &blocks, 2);
    missing_public.pop();
    assert_eq!(
        freeze_public_synthetic_three_lane_ablation_corpus_v1(missing_public).unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 }
    );
    let mut duplicate_public = public_case_inputs(&ledgers, &blocks, 3);
    duplicate_public.push(SyntheticThreeLaneAblationPublicCaseInputV1::new(
        first,
        public_batch(
            first,
            &ledgers[case_position(first)],
            &blocks[case_position(first)],
            measurement_environment(),
            3,
        ),
    ));
    assert_eq!(
        freeze_public_synthetic_three_lane_ablation_corpus_v1(duplicate_public).unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::DuplicateCase
    );

    let mut missing = governed_inputs(&public, &annotations, &ledgers, &blocks, &hidden);
    missing.pop();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, missing).unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 }
    );

    let mut duplicate = governed_inputs(&public, &annotations, &ledgers, &blocks, &hidden);
    duplicate.push(governed_input(
        &public,
        &annotations,
        &ledgers,
        &blocks,
        &hidden,
        first,
        first.family(),
        public.digest(),
        public.case(first).batch().digest(),
        first,
    ));
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, duplicate).unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::DuplicateCase
    );

    let family_mismatch = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                &public,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                if case == first {
                    SyntheticThreeLaneAblationFamilyV1::Coverage
                } else {
                    case.family()
                },
                public.digest(),
                public.case(case).batch().digest(),
                case,
            )
        })
        .collect::<Vec<_>>();
    let family_error =
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, family_mismatch)
            .unwrap_err();
    assert_eq!(
        family_error,
        SyntheticThreeLaneCorpusErrorV1::FamilyMismatch
    );

    let foreign_corpus = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                &public,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                if case == first {
                    foreign_public.digest()
                } else {
                    public.digest()
                },
                public.case(case).batch().digest(),
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, foreign_corpus)
            .unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::ForeignCorpus
    );

    let second = SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle;
    let foreign_batch = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                &public,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                public.digest(),
                if case == first {
                    public.case(second).batch().digest()
                } else {
                    public.case(case).batch().digest()
                },
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, foreign_batch)
            .unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::ForeignPublicBatch
    );

    let swapped_join = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                &public,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                public.digest(),
                public.case(case).batch().digest(),
                if case == first { second } else { case },
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, swapped_join)
            .unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::ForeignCaseJoin
    );

    let foreign_hidden = hidden_manifest(artifact(226));
    let mixed_runs = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_input(
                &public,
                &annotations,
                &ledgers,
                &blocks,
                if case == first {
                    &foreign_hidden
                } else {
                    &hidden
                },
                case,
                case.family(),
                public.digest(),
                public.case(case).batch().digest(),
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(&public, mixed_runs).unwrap_err(),
        SyntheticThreeLaneCorpusErrorV1::ForeignRunManifest
    );

    let error_debug = format!("{family_error:?}");
    assert!(error_debug.contains("EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FAMILY_MISMATCH"));
    for canary in [
        STRUCTURAL_CANARY,
        "123e4567-e89b-12d3-a456-426614174000",
        "fatal crash",
        QUESTION_CANARY,
    ] {
        assert!(!error_debug.contains(canary));
    }
}

#[test]
fn budgeted_selector_and_canonical_renderer_freeze_before_required_event_scoring() {
    assert_eq!(
        three_lane_ablation_method_family_digest_v1().as_bytes(),
        &[
            0xc9, 0xac, 0x07, 0x8e, 0x47, 0xb2, 0xf3, 0x70, 0xe5, 0xaa, 0x39, 0xb2, 0x56, 0x67,
            0x88, 0x0a, 0x46, 0x6b, 0x92, 0xfd, 0xf7, 0xb3, 0x2f, 0xc9, 0xe0, 0x77, 0x44, 0x15,
            0x46, 0xa5, 0xba, 0xd3,
        ]
    );
    let ledgers = setup_ledgers();
    let blocks = ledgers.iter().map(blocks).collect::<Vec<_>>();
    let source = public_corpus(&ledgers, &blocks, 0, false);
    let prepared = prepared_ablation_sets(&ledgers, &blocks);
    let schedule = synthetic_three_lane_selection_budget_schedule_v1();

    // The complete 24-outcome selection/render package exists before the
    // first governed annotation value is constructed.
    let public = selection_public_corpus(&source, &ledgers, &prepared, schedule, false);
    let replay = selection_public_corpus(&source, &ledgers, &prepared, schedule, true);
    assert_eq!(public.digest(), replay.digest());
    assert_eq!(public.source_public_corpus_digest(), source.digest());
    assert_eq!(
        public.scope(),
        SyntheticThreeLaneCorpusScopeV1::SyntheticConformanceOnlyGeneratorFamiliesNotIndependent
    );
    assert_eq!(public.budget_schedule(), schedule);
    assert_eq!(public.cases().len(), 6);
    assert!(!public.contains_annotations());

    let mut selected_count = 0usize;
    let mut empty_count = 0usize;
    let mut budget_infeasible_count = 0usize;
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let public_case = public.case(case);
        let position = case_position(case);
        let configured = prepared[position].configuration(ThreeLaneAblationMaskV1::Full);
        let prepared_full = configured.prepared();
        let oracle = public_case.full_selection_oracle();
        assert_eq!(oracle.case(), case);
        assert_eq!(
            oracle.source_public_batch_digest(),
            source.case(case).batch().digest()
        );
        assert_eq!(
            oracle.production_outcome_digest(),
            public_case.outcome(ThreeLaneAblationMaskV1::Full).digest()
        );
        assert_eq!(
            oracle.proposal_receipt_digest(),
            prepared_full.receipt().digest()
        );
        assert_eq!(
            oracle.full_configuration_digest(),
            three_lane_ablation_config_digest_v1(ThreeLaneAblationMaskV1::Full)
        );
        assert_eq!(
            oracle.candidate_config_digest(),
            proposal_candidate_config_digest_v1()
        );
        assert_eq!(
            oracle.compiler_config_digest(),
            proposal_compiler_config_digest_v1()
        );
        assert_eq!(oracle.total_token_budget(), schedule.budget(case).tokens());
        assert_eq!(oracle.oracle_policy_version(), b"2");
        assert_eq!(oracle.oracle_optional_packet_cap(), 12);
        assert_eq!(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, 12);
        assert!(!oracle.contains_annotations());
        assert!(!oracle.claims_approximation_factor());
        assert!(!oracle.claims_population_quality());

        let expected_exact = match case {
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => {
                Some((1_500_000_000_000, 2_323, 4, 130))
            }
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => {
                Some((9_000_000_000_000, 3_998, 7, 1_024))
            }
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => {
                Some((2_500_000_000_000, 2_864, 5, 520))
            }
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => {
                Some((6_250_000_000_000, 4_621, 8, 1_024))
            }
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => None,
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
                Some((1_500_000_000_000, 1_785, 3, 130))
            }
        };
        match (oracle.decision().exact_evaluated(), expected_exact) {
            (Some(exact), Some((gain, selected_cost, packet_count, reachable_count))) => {
                let optional_count = prepared_full
                    .proposal_packets()
                    .len()
                    .checked_sub(prepared_full.mandatory().len())
                    .unwrap();
                assert_eq!(
                    exact.proposal_packet_count(),
                    u64::try_from(prepared_full.proposal_packets().len()).unwrap()
                );
                assert_eq!(
                    exact.optional_packet_count(),
                    u64::try_from(optional_count).unwrap()
                );
                assert!(optional_count <= MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1);
                assert_eq!(exact.production_gain().numerator(), gain);
                assert_eq!(exact.optimum_gain().numerator(), gain);
                assert_eq!(exact.production_selected_packet_cost(), selected_cost);
                assert_eq!(exact.optimum_selected_packet_cost(), selected_cost);
                assert_eq!(exact.production_packet_ids().len(), packet_count);
                assert_eq!(exact.optimum_packet_ids().len(), packet_count);
                assert_eq!(exact.reachable_subset_count(), reachable_count);
                assert_eq!(exact.regret_numerator(), 0);
                assert_eq!(
                    exact.optimum_gain().numerator() - exact.production_gain().numerator(),
                    exact.regret_numerator()
                );
                assert_eq!(
                    exact.production_packet_ids(),
                    public_case
                        .outcome(ThreeLaneAblationMaskV1::Full)
                        .decision()
                        .selected()
                        .unwrap()
                        .selected_packet_ids()
                );
                let fixed = public_case
                    .outcome(ThreeLaneAblationMaskV1::Full)
                    .fixed_overhead_tokens()
                    .unwrap();
                assert_eq!(
                    fixed,
                    if case == SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes {
                        432
                    } else {
                        438
                    }
                );
                assert_eq!(
                    exact.production_accounted_token_upper_bound(),
                    fixed + exact.production_selected_packet_cost()
                );
                assert_eq!(
                    exact.optimum_accounted_token_upper_bound(),
                    fixed + exact.optimum_selected_packet_cost()
                );
                assert!(
                    exact.production_accounted_token_upper_bound() <= oracle.total_token_budget()
                );
                assert!(exact.optimum_accounted_token_upper_bound() <= oracle.total_token_budget());
                assert!(!exact.claims_approximation_factor());
            }
            (None, None) => {
                let needs_more = oracle.decision().production_needs_more().unwrap();
                assert_eq!(
                    needs_more.compiler_reason(),
                    ThreeLaneNeedsMoreV1::FixedOverheadExceedsTotalBudget
                );
                assert_eq!(
                    needs_more.selection_reason(),
                    Some(NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget)
                );
                assert_eq!(needs_more.fixed_overhead_tokens(), Some(425));
                assert_eq!(needs_more.optional_packet_count(), 10);
                assert_eq!(needs_more.proposal_packet_count(), 10);
                assert_eq!(needs_more.mandatory_packet_cost(), 0);
                assert_eq!(needs_more.mandatory_packet_count(), 0);
            }
            _ => panic!("frozen six-case exact-oracle outcome changed"),
        }
        assert!(oracle.decision().optional_packet_cap_ineligible().is_none());
        assert_eq!(public_case.outcomes().len(), 4);
        assert_eq!(public_case.acquisition_class(), acquisition_class(case));
        assert_eq!(
            public_case.shared_producer_wall_time_nanos(),
            101 + u64::try_from(case_position(case)).unwrap()
        );
        assert_eq!(
            public_case.shared_producer_peak_rss_bytes(),
            201 + u64::try_from(case_position(case)).unwrap()
        );
        let full_selected_source_bytes = public_case
            .outcome(ThreeLaneAblationMaskV1::Full)
            .decision()
            .selected()
            .map_or(0, |selected| selected.selected_unique_source_bytes());
        let baselines = public_case.matched_baselines();
        assert_eq!(
            u64::try_from(baselines.matched_source_byte_budget().bytes()).unwrap(),
            full_selected_source_bytes
        );
        assert_eq!(baselines.outcomes().len(), 3);
        assert_eq!(
            baselines.budget_basis_code(),
            "full_selected_unique_source_bytes_only"
        );
        assert!(!baselines.contains_total_output_envelope_parity());
        assert_eq!(
            baselines.limitation_code(),
            "raw_method_result_bytes_not_equivalent_to_compiled_renderer_overhead"
        );
        for arm in MatchedBaselineArmV1::ALL {
            let baseline = baselines.outcome(arm);
            assert_eq!(baseline.arm(), arm);
            assert_eq!(
                baseline.result().accounting().budget(),
                baselines.matched_source_byte_budget()
            );
            assert!(
                baseline.result().accounting().selected_source_bytes()
                    <= baselines.matched_source_byte_budget().bytes()
            );
        }
        for mask in ThreeLaneAblationMaskV1::ALL {
            let outcome = public_case.outcome(mask);
            assert_eq!(outcome.budget(), schedule.budget(case));
            match outcome.decision() {
                evidentrail_bench::FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(
                    selected,
                ) => {
                    selected_count += 1;
                    assert!(!selected.selected_packet_ids().is_empty());
                    assert!(!selected.selected_event_ids().is_empty());
                    assert_eq!(
                        selected.selected_packet_count(),
                        u64::try_from(selected.selected_packet_ids().len()).unwrap()
                    );
                    assert!(selected.render().token_count() <= outcome.budget().tokens());
                    assert!(
                        selected.coverage_only_token_charge()
                            <= selected.coverage_only_token_limit()
                    );
                    let exact_source_bytes = selected
                        .selected_event_ids()
                        .iter()
                        .map(|event_id| {
                            ledgers[case_position(case)]
                                .event(*event_id)
                                .unwrap()
                                .raw()
                                .len()
                        })
                        .sum::<usize>();
                    assert_eq!(
                        selected.selected_unique_source_bytes(),
                        u64::try_from(exact_source_bytes).unwrap()
                    );
                    let rendered_events = selected
                        .render()
                        .artifact()
                        .brief()
                        .evidence()
                        .iter()
                        .flat_map(|packet| packet.canonical_event_ids().iter().copied())
                        .collect::<BTreeSet<_>>();
                    assert_eq!(
                        rendered_events,
                        selected.selected_event_ids().iter().copied().collect()
                    );
                    assert!(!selected.render().text().contains(QUESTION_CANARY));
                    assert!(
                        !selected
                            .render()
                            .text()
                            .contains("\nEVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n")
                    );
                    assert!(!selected.render().text().contains('\0'));
                }
                evidentrail_bench::FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(
                    needs_more,
                ) => match needs_more.class() {
                    SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse => empty_count += 1,
                    SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible => {
                        budget_infeasible_count += 1;
                    }
                },
            }
        }
    }
    assert!(selected_count > 0);
    assert!(empty_count > 0);
    assert!(budget_infeasible_count > 0);
    assert_eq!(selected_count + empty_count + budget_infeasible_count, 24);
    assert_eq!(
        SyntheticThreeLaneAblationCaseV1::ALL
            .into_iter()
            .map(|case| public.case(case).full_selection_oracle().digest())
            .collect::<BTreeSet<_>>()
            .len(),
        6,
        "case-bound oracle artifacts must not be substitutable",
    );
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        assert_eq!(
            public.case(case).full_selection_oracle().digest(),
            replay.case(case).full_selection_oracle().digest(),
            "permuting public input order must preserve the canonical case oracle",
        );
    }
    let public_debug = format!("{public:?}");
    for canary in [STRUCTURAL_CANARY, QUESTION_CANARY, "fatal crash"] {
        assert!(!public_debug.contains(canary));
    }

    let annotations = annotations(&ledgers);
    let hidden = hidden_manifest(artifact(225));
    let governed = evaluate_governed_synthetic_three_lane_selection_corpus_v1(
        &public,
        &source,
        governed_selection_inputs(&public, &source, &annotations, &ledgers, &blocks, &hidden),
    )
    .unwrap();
    let mut governed_replay_inputs =
        governed_selection_inputs(&public, &source, &annotations, &ledgers, &blocks, &hidden);
    governed_replay_inputs.reverse();
    let governed_replay = evaluate_governed_synthetic_three_lane_selection_corpus_v1(
        &public,
        &source,
        governed_replay_inputs,
    )
    .unwrap();
    assert_eq!(governed.digest(), governed_replay.digest());
    assert_eq!(
        governed.full_selection_oracle_report().digest(),
        governed_replay.full_selection_oracle_report().digest()
    );
    assert_eq!(governed.public_selection_corpus_digest(), public.digest());
    assert_eq!(governed.cases().len(), 6);
    assert_eq!(governed.family_mask_components().len(), 20);
    assert_eq!(governed.family_lane_removal_deltas().len(), 15);
    assert!(!governed.contains_scalar_composite());
    assert!(!governed.contains_auc());
    assert!(!governed.contains_winner());
    assert!(!governed.contains_statistical_claim());
    assert!(!governed.contains_general_quality_claim());
    let oracle_report = governed.full_selection_oracle_report();
    assert_eq!(
        oracle_report.public_selection_corpus_digest(),
        public.digest()
    );
    assert_eq!(oracle_report.cases().len(), 6);
    assert_eq!(oracle_report.exact_evaluated_count(), 5);
    assert_eq!(oracle_report.zero_regret_count(), 5);
    assert_eq!(oracle_report.nonzero_regret_count(), 0);
    assert_eq!(oracle_report.production_needs_more_count(), 1);
    assert_eq!(oracle_report.optional_packet_cap_ineligible_count(), 0);
    assert_eq!(oracle_report.oracle_policy_version(), b"2");
    assert_eq!(oracle_report.oracle_optional_packet_cap(), 12);
    assert!(!oracle_report.claims_population_quality());
    assert!(!oracle_report.claims_approximation_factor());
    assert!(!oracle_report.contains_scalar_composite());
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let report_case = oracle_report.case(case);
        assert_eq!(report_case.case(), case);
        assert_eq!(
            report_case.frozen_oracle().digest(),
            public.case(case).full_selection_oracle().digest()
        );
        assert_eq!(
            report_case.production_required_event_recall(),
            governed
                .case(case)
                .point(ThreeLaneAblationMaskV1::Full)
                .required_event_recall()
        );
        match report_case.frozen_oracle().decision().exact_evaluated() {
            Some(exact) => {
                assert_eq!(
                    exact.optimum_gain().numerator() - exact.production_gain().numerator(),
                    exact.regret_numerator()
                );
                let production_recall = report_case.production_required_event_recall();
                let optimum_recall = report_case.optimum_required_event_recall().unwrap();
                assert_eq!(
                    optimum_recall, production_recall,
                    "this frozen corpus has equal governed hidden-label recall for the exact optimum and production Full selection",
                );
                assert_eq!(
                    optimum_recall.exact_weight_ratio(),
                    match case {
                        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => (3, 3),
                        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => (5, 5),
                        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => (7, 7),
                        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => (9, 9),
                        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
                            (13, 13)
                        }
                        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => {
                            unreachable!("the fixed-overhead terminal has no exact optimum")
                        }
                    }
                );
            }
            None => {
                assert_eq!(
                    case,
                    SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors
                );
                assert!(report_case.optimum_required_event_recall().is_none());
            }
        }
    }
    for summary in governed.family_mask_components() {
        for component in summary.components() {
            assert_eq!(component.case().family(), summary.family());
            assert_eq!(component.point().mask(), summary.mask());
        }
    }

    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        for mask in ThreeLaneAblationMaskV1::ALL {
            let public_outcome = public.case(case).outcome(mask);
            let point = governed.case(case).point(mask);
            let attribution = governed.case(case).attribution(mask);
            assert_eq!(point.public_outcome_digest(), public_outcome.digest());
            assert_eq!(attribution.mask(), mask);
            assert!(attribution.render_reference_mapping_exact());
            assert_eq!(attribution.requirements().len(), 1);
            assert_eq!(point.acquisition_class(), acquisition_class(case));
            let recall = point.required_event_recall();
            assert_eq!(recall.requirement_count(), 1);
            assert!(recall.satisfied_requirement_count() <= 1);
            match public_outcome.decision() {
                evidentrail_bench::FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(
                    selected,
                ) => {
                    assert_eq!(
                        point.selected_packet_count(),
                        selected.selected_packet_count()
                    );
                    assert_eq!(
                        point.selected_event_count(),
                        u64::try_from(selected.selected_event_ids().len()).unwrap()
                    );
                    assert_eq!(
                        point.selected_unique_source_bytes(),
                        selected.selected_unique_source_bytes()
                    );
                    assert_eq!(
                        point.selected_render_tokens(),
                        selected.render().token_count()
                    );
                    assert_eq!(
                        point.coverage_only_token_charge(),
                        Some(selected.coverage_only_token_charge())
                    );
                    assert_eq!(
                        point.coverage_only_token_limit(),
                        Some(selected.coverage_only_token_limit())
                    );
                    assert_eq!(point.needs_more_class(), None);
                    assert_eq!(
                        point.residual(),
                        if recall.is_perfect() {
                            RequiredEventSelectionResidualV1::None
                        } else {
                            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss
                        }
                    );
                }
                evidentrail_bench::FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(
                    needs_more,
                ) => {
                    assert_eq!(point.selected_packet_count(), 0);
                    assert_eq!(point.selected_event_count(), 0);
                    assert_eq!(point.selected_unique_source_bytes(), 0);
                    assert_eq!(point.selected_render_tokens(), 0);
                    assert_eq!(point.coverage_only_token_charge(), None);
                    assert_eq!(point.coverage_only_token_limit(), None);
                    assert_eq!(point.needs_more_class(), Some(needs_more.class()));
                    assert_eq!(recall.satisfied_requirement_count(), 0);
                    assert_eq!(
                        point.residual(),
                        match needs_more.class() {
                            SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse => {
                                RequiredEventSelectionResidualV1::EmptyProposalUniverse
                            }
                            SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible => {
                                RequiredEventSelectionResidualV1::BudgetInfeasible
                            }
                        }
                    );
                }
            }
        }
        for arm in MatchedBaselineArmV1::ALL {
            let baseline = governed.case(case).matched_baseline(arm);
            assert_eq!(baseline.arm(), arm);
            assert_eq!(
                baseline.public_outcome_digest(),
                public.case(case).matched_baselines().outcome(arm).digest()
            );
            let accounting = baseline.evaluation().public_result().accounting();
            assert_eq!(
                accounting.source_byte_budget(),
                u64::try_from(
                    public
                        .case(case)
                        .matched_baselines()
                        .matched_source_byte_budget()
                        .bytes()
                )
                .unwrap()
            );
            assert!(accounting.selected_source_bytes() <= accounting.source_byte_budget());
        }
    }

    // Freeze the complete unchanged-fixture outcome/resource surface. This is
    // a conformance table, not a scalar comparison or general-quality claim.
    for (case, mask, recall, packets, events, bytes, tokens, residual, needs_more) in [
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            ThreeLaneAblationMaskV1::Full,
            (3, 3),
            4,
            4,
            127,
            1_831,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (0, 3),
            3,
            3,
            66,
            1_452,
            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (3, 3),
            1,
            1,
            61,
            816,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (3, 3),
            4,
            4,
            127,
            1_831,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            ThreeLaneAblationMaskV1::Full,
            (5, 5),
            7,
            7,
            155,
            2_790,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (5, 5),
            7,
            7,
            155,
            2_790,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (0, 5),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::EmptyProposalUniverse,
            Some(SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (5, 5),
            7,
            7,
            155,
            2_790,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            ThreeLaneAblationMaskV1::Full,
            (7, 7),
            5,
            5,
            119,
            2_143,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (7, 7),
            5,
            5,
            119,
            2_143,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (7, 7),
            2,
            2,
            53,
            1_128,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (0, 7),
            3,
            3,
            66,
            1_452,
            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::Full,
            (9, 9),
            8,
            8,
            227,
            3_248,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (0, 9),
            7,
            7,
            173,
            2_876,
            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (0, 9),
            3,
            3,
            105,
            1_498,
            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (0, 9),
            6,
            6,
            176,
            2_536,
            RequiredEventSelectionResidualV1::SelectedRequiredEventMiss,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::Full,
            (0, 11),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::BudgetInfeasible,
            Some(SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (0, 11),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::BudgetInfeasible,
            Some(SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (0, 11),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::EmptyProposalUniverse,
            Some(SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (0, 11),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::BudgetInfeasible,
            Some(SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            ThreeLaneAblationMaskV1::Full,
            (13, 13),
            3,
            3,
            128,
            1_518,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            ThreeLaneAblationMaskV1::WithoutLexical,
            (13, 13),
            3,
            3,
            128,
            1_518,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            (0, 13),
            0,
            0,
            0,
            0,
            RequiredEventSelectionResidualV1::EmptyProposalUniverse,
            Some(SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse),
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            ThreeLaneAblationMaskV1::WithoutProvider,
            (13, 13),
            3,
            3,
            128,
            1_518,
            RequiredEventSelectionResidualV1::None,
            None,
        ),
    ] {
        let point = governed.case(case).point(mask);
        assert_eq!(point.required_event_recall().exact_weight_ratio(), recall);
        assert_eq!(point.selected_packet_count(), packets);
        assert_eq!(point.selected_event_count(), events);
        assert_eq!(point.selected_unique_source_bytes(), bytes);
        assert_eq!(point.selected_render_tokens(), tokens);
        assert_eq!(point.residual(), residual);
        assert_eq!(point.needs_more_class(), needs_more);
    }

    // The two previously frozen top-one misses must be repaired by selecting
    // the exact unchanged endpoint packet with a newly positive half-weight
    // provider marginal. This is not satisfied by a fixture or budget change.
    for (case, formerly_saturated_target, expected_minimum_bound, expected_packet_cost) in [
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            8,
            1_589,
            579,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            2,
            2_198,
            575,
        ),
    ] {
        assert_eq!(
            governed
                .case(case)
                .point(ThreeLaneAblationMaskV1::Full)
                .residual(),
            RequiredEventSelectionResidualV1::None,
            "the unchanged formerly saturated endpoint must now be selected",
        );
        let public_full = public.case(case).outcome(ThreeLaneAblationMaskV1::Full);
        let attribution = governed
            .case(case)
            .attribution(ThreeLaneAblationMaskV1::Full);
        assert!(attribution.render_reference_mapping_exact());
        assert_eq!(attribution.requirements().len(), 1);
        let requirement = &attribution.requirements()[0];
        assert_eq!(
            requirement.class(),
            RequirementSelectionAttributionClassV1::Satisfied
        );
        for alternative in requirement.alternatives() {
            assert!(alternative.all_members_in_proposal_universe());
            assert_eq!(
                alternative.oracle_budget_feasibility(),
                evidentrail_bench::AlternativeOracleBudgetFeasibilityV1::Feasible
            );
            assert!(
                alternative.minimum_compiled_token_bound().unwrap()
                    <= public_full.budget().tokens()
            );
            assert_eq!(
                alternative.minimum_compiled_token_bound(),
                Some(expected_minimum_bound)
            );
            assert!(alternative.events().iter().all(|event| {
                event.disposition() == RequiredEventSelectionDispositionV1::SelectedAndRendered
            }));
        }

        let formerly_saturated_event =
            ledgers[case_position(case)].events()[formerly_saturated_target].id();
        let repaired_event = requirement
            .alternatives()
            .iter()
            .flat_map(|alternative| alternative.events())
            .find(|event| event.event_id() == formerly_saturated_event)
            .unwrap();
        assert_eq!(
            repaired_event.disposition(),
            RequiredEventSelectionDispositionV1::SelectedAndRendered
        );
        let repaired_packets = repaired_event
            .containing_packets()
            .iter()
            .filter(|packet| {
                packet.affinities().iter().any(|affinity| {
                    affinity.kind() == ProductionFacetKindV1::ProviderAttestedGraphRelation
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(repaired_packets.len(), 1);
        for packet in repaired_packets {
            assert!(packet.is_selected());
            assert_eq!(packet.token_cost_upper_bound(), expected_packet_cost);
            assert!(!packet.is_mandatory());
            assert_eq!(packet.affinities().len(), 1);
            assert_eq!(
                packet.affinities()[0].kind(),
                ProductionFacetKindV1::ProviderAttestedGraphRelation
            );
            assert_eq!(packet.affinities()[0].weight_micros(), 500_000);
            assert_eq!(packet.affinities()[0].affinity_micros(), 1_000_000);
            assert_eq!(
                packet.selected_marginal_gain_numerator(),
                Some(500_000_000_000)
            );
            assert_eq!(
                packet.selected_constraint(),
                Some(SelectionConstraintV1::DensityGreedy)
            );
            assert_eq!(packet.post_selection_marginal_gain_numerator(), None);
            assert!(packet.saturations().is_empty());

            let relation_facet = packet.affinities()[0].facet_id();
            let selected_relation_packets = public_full
                .proposal_audits()
                .iter()
                .filter(|candidate| {
                    candidate.is_selected()
                        && candidate.affinities().iter().any(|affinity| {
                            affinity.facet_id() == relation_facet
                                && affinity.kind()
                                    == ProductionFacetKindV1::ProviderAttestedGraphRelation
                        })
                })
                .collect::<Vec<_>>();
            assert_eq!(selected_relation_packets.len(), 2);
            assert!(selected_relation_packets.iter().all(|selected| {
                selected
                    .selected_marginal_gain_numerator()
                    .is_some_and(|gain| gain > 0)
            }));
        }
    }
    for summary in governed.family_lane_removal_deltas() {
        for component in summary.components() {
            let (numerator, denominator) = component.exact_rational_delta();
            assert!(denominator > 0);
            assert!(numerator.abs() <= i128::from(denominator));
        }
    }

    // Cheap baselines are matched only to Full's selected unique authorized
    // source bytes. Their raw MethodResult bytes are not equivalent to the
    // compiled renderer envelope, so this table makes no output-parity claim.
    for (case, arm, budget, recall, selected_events, selected_bytes) in [
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            MatchedBaselineArmV1::RawChronological,
            127,
            (3, 3),
            3,
            106,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            MatchedBaselineArmV1::GrepHeadTail,
            127,
            (3, 3),
            4,
            127,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            MatchedBaselineArmV1::QuotaHybrid,
            127,
            (0, 3),
            5,
            111,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            MatchedBaselineArmV1::RawChronological,
            155,
            (5, 5),
            6,
            135,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            MatchedBaselineArmV1::GrepHeadTail,
            155,
            (5, 5),
            6,
            135,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            MatchedBaselineArmV1::QuotaHybrid,
            155,
            (0, 5),
            6,
            130,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            MatchedBaselineArmV1::RawChronological,
            119,
            (0, 7),
            5,
            113,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            MatchedBaselineArmV1::GrepHeadTail,
            119,
            (0, 7),
            5,
            113,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            MatchedBaselineArmV1::QuotaHybrid,
            119,
            (0, 7),
            5,
            111,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            MatchedBaselineArmV1::RawChronological,
            227,
            (0, 9),
            8,
            217,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            MatchedBaselineArmV1::GrepHeadTail,
            227,
            (0, 9),
            8,
            217,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            MatchedBaselineArmV1::QuotaHybrid,
            227,
            (0, 9),
            7,
            191,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            MatchedBaselineArmV1::RawChronological,
            0,
            (0, 11),
            0,
            0,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            MatchedBaselineArmV1::GrepHeadTail,
            0,
            (0, 11),
            0,
            0,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            MatchedBaselineArmV1::QuotaHybrid,
            0,
            (0, 11),
            0,
            0,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            MatchedBaselineArmV1::RawChronological,
            128,
            (13, 13),
            2,
            107,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            MatchedBaselineArmV1::GrepHeadTail,
            128,
            (13, 13),
            3,
            128,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            MatchedBaselineArmV1::QuotaHybrid,
            128,
            (0, 13),
            5,
            110,
        ),
    ] {
        let baseline = governed.case(case).matched_baseline(arm);
        let accounting = baseline.evaluation().public_result().accounting();
        assert_eq!(accounting.source_byte_budget(), budget);
        assert_eq!(
            baseline
                .evaluation()
                .diagnostic_recall()
                .exact_weight_ratio(),
            recall
        );
        assert_eq!(accounting.selected_event_count(), selected_events);
        assert_eq!(accounting.selected_source_bytes(), selected_bytes);
    }

    // Every non-perfect mask has one explicit governed failure class. No
    // objective-saturation residual remains after the V2 provider repair.
    for (case, mask, expected_class) in [
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            ThreeLaneAblationMaskV1::WithoutLexical,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            ThreeLaneAblationMaskV1::WithoutProvider,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutLexical,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            ThreeLaneAblationMaskV1::WithoutProvider,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::Full,
            RequirementSelectionAttributionClassV1::BudgetInfeasible,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutLexical,
            RequirementSelectionAttributionClassV1::BudgetInfeasible,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            ThreeLaneAblationMaskV1::WithoutProvider,
            RequirementSelectionAttributionClassV1::BudgetInfeasible,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            ThreeLaneAblationMaskV1::WithoutCoverage,
            RequirementSelectionAttributionClassV1::CandidateRecallMiss,
        ),
    ] {
        let point = governed.case(case).point(mask);
        assert!(!point.required_event_recall().is_perfect());
        assert_eq!(
            governed.case(case).attribution(mask).requirements()[0].class(),
            expected_class
        );
    }

    // The earlier governed producer-universe artifact remains attached, so
    // all five-axis violations and conservative shared-batch charges survive.
    assert_eq!(
        governed.producer_proposal_corpus().public_corpus_digest(),
        source.digest()
    );
    let debug = format!("{governed:?}");
    for canary in [STRUCTURAL_CANARY, QUESTION_CANARY, "fatal crash"] {
        assert!(!debug.contains(canary));
    }
}

#[test]
fn selection_corpus_rejects_cross_budget_receipt_run_and_annotation_joins() {
    let ledgers = setup_ledgers();
    let blocks = ledgers.iter().map(blocks).collect::<Vec<_>>();
    let source = public_corpus(&ledgers, &blocks, 0, false);
    let prepared = prepared_ablation_sets(&ledgers, &blocks);
    let schedule = synthetic_three_lane_selection_budget_schedule_v1();
    let public = selection_public_corpus(&source, &ledgers, &prepared, schedule, false);

    let changed_schedule = SyntheticThreeLaneSelectionBudgetScheduleV1::try_new(
        SyntheticThreeLaneAblationCaseV1::ALL
            .into_iter()
            .map(|case| {
                let base = schedule.budget(case).tokens();
                (
                    case,
                    if case == SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead {
                        base + 1
                    } else {
                        base
                    },
                )
            }),
    )
    .unwrap();
    let changed_budget_public =
        selection_public_corpus(&source, &ledgers, &prepared, changed_schedule, false);
    assert_ne!(public.digest(), changed_budget_public.digest());

    assert_eq!(
        SyntheticThreeLaneSelectionBudgetScheduleV1::try_new([(
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            1,
        )])
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::MissingBudgetCases { count: 5 }
    );
    assert_eq!(
        SyntheticThreeLaneSelectionBudgetScheduleV1::try_new([
            (
                SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
                1,
            ),
            (
                SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
                2,
            ),
        ])
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::DuplicateBudgetCase
    );

    let annotations = annotations(&ledgers);
    let hidden = hidden_manifest(artifact(225));
    let first = SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead;
    let second = SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle;

    let missing =
        governed_selection_inputs(&public, &source, &annotations, &ledgers, &blocks, &hidden)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(&public, &source, missing)
            .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 }
    );

    let cross_budget = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_selection_input(
                &public,
                &source,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                public.digest(),
                if case == first { second } else { case },
                case,
                case,
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(&public, &source, cross_budget,)
            .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::CaseBindingMismatch
    );

    let foreign_selection = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_selection_input(
                &public,
                &source,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                if case == first {
                    changed_budget_public.digest()
                } else {
                    public.digest()
                },
                case,
                case,
                case,
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(
            &public,
            &source,
            foreign_selection,
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::ForeignSelectionCorpus
    );

    let swapped_annotation = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_selection_input(
                &public,
                &source,
                &annotations,
                &ledgers,
                &blocks,
                &hidden,
                case,
                case.family(),
                public.digest(),
                case,
                case,
                if case == first { second } else { case },
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(
            &public,
            &source,
            swapped_annotation,
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::SourceCorpusEvaluation(
            SyntheticThreeLaneCorpusErrorV1::ForeignCaseJoin,
        )
    );

    let foreign_hidden = hidden_manifest(artifact(226));
    let mixed_runs = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .map(|case| {
            governed_selection_input(
                &public,
                &source,
                &annotations,
                &ledgers,
                &blocks,
                if case == first {
                    &foreign_hidden
                } else {
                    &hidden
                },
                case,
                case.family(),
                public.digest(),
                case,
                case,
                case,
                case,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(&public, &source, mixed_runs)
            .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::SourceCorpusEvaluation(
            SyntheticThreeLaneCorpusErrorV1::ForeignRunManifest,
        )
    );

    let foreign_source = public_corpus(&ledgers, &blocks, 1, false);
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(
            &public,
            &foreign_source,
            governed_selection_inputs(&public, &source, &annotations, &ledgers, &blocks, &hidden,),
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::ForeignSourceCorpus
    );

    let mut block_annotations = annotations.clone();
    block_annotations[0] = EvidentrailBenchAnnotationSpecV1::new(
        first.identity_digest(),
        [WeightedDiagnosticRequirementV1::new(
            3,
            [[EvidenceTargetV1::Block(blocks[0].blocks()[0].id())]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        evaluate_governed_synthetic_three_lane_selection_corpus_v1(
            &public,
            &source,
            governed_selection_inputs(
                &public,
                &source,
                &block_annotations,
                &ledgers,
                &blocks,
                &hidden,
            ),
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::NonEventRequirementTarget
    );

    let mismatched_prepared_inputs = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            SyntheticThreeLaneSelectionPublicCaseInputV1::new(
                case,
                if case == first {
                    &prepared[case_position(second)]
                } else {
                    &prepared[position]
                },
                &ledgers[position],
                question(case),
                UnixTimestampNanos::new(50_000),
                UnixTimestampNanos::new(60_000),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        freeze_public_synthetic_three_lane_selection_corpus_v1(
            &source,
            schedule,
            mismatched_prepared_inputs,
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch
    );

    let mismatched_question_inputs = SyntheticThreeLaneAblationCaseV1::ALL
        .into_iter()
        .enumerate()
        .map(|(position, case)| {
            SyntheticThreeLaneSelectionPublicCaseInputV1::new(
                case,
                &prepared[position],
                &ledgers[position],
                if case == first {
                    b"foreign-question".as_slice()
                } else {
                    question(case)
                },
                UnixTimestampNanos::new(50_000),
                UnixTimestampNanos::new(60_000),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        freeze_public_synthetic_three_lane_selection_corpus_v1(
            &source,
            schedule,
            mismatched_question_inputs,
        )
        .unwrap_err(),
        ThreeLaneSelectionCorpusErrorV1::CaseBindingMismatch
    );

    let debug = format!(
        "{:?}",
        ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch
    );
    for canary in [STRUCTURAL_CANARY, QUESTION_CANARY, "fatal crash"] {
        assert!(!debug.contains(canary));
    }
}

#[test]
fn bounded_selector_challenger_is_frozen_paired_and_remains_evaluation_only() {
    let ledgers = setup_ledgers();
    let blocks = ledgers.iter().map(blocks).collect::<Vec<_>>();
    let source = public_corpus(&ledgers, &blocks, 0, false);
    let prepared = prepared_ablation_sets(&ledgers, &blocks);
    let schedule = synthetic_three_lane_selection_budget_schedule_v1();
    let selection = selection_public_corpus(&source, &ledgers, &prepared, schedule, false);
    let perturbations = freeze_selector_perturbation_corpus_v1().unwrap();

    // Both source corpora and every challenger decision are frozen before any
    // governed annotation type is constructed.
    let public = freeze_selector_challenger_comparison_v1(&perturbations, &selection).unwrap();
    let replay = freeze_selector_challenger_comparison_v1(&perturbations, &selection).unwrap();
    assert_eq!(public, replay);
    assert_eq!(public.digest(), replay.digest());
    assert_eq!(public.cases().len(), 19);
    assert_eq!(public.objective_better_count(), 2);
    assert_eq!(public.objective_equal_count(), 14);
    assert_eq!(public.matched_terminal_count(), 3);
    assert_eq!(public.objective_regression_count(), 0);
    assert_eq!(public.selected_cost_increase_count(), 2);
    assert_eq!(public.positive_regret_fix_count(), 2);
    assert_eq!(public.exact_mode_count(), 18);
    assert_eq!(public.beam_mode_count(), 1);
    assert_eq!(public.transition_cap_reached_count(), 0);
    assert!(!public.contains_annotations());
    assert!(!public.claims_wall_time_or_peak_rss());
    assert!(!public.changes_production_selector());
    assert_eq!(
        public
            .cases()
            .iter()
            .map(|case| case.case())
            .collect::<BTreeSet<_>>()
            .len(),
        19
    );
    assert_eq!(
        public
            .cases()
            .iter()
            .map(|case| case.pair().digest())
            .collect::<BTreeSet<_>>()
            .len(),
        19
    );
    assert!(public.cases().iter().all(|case| {
        case.pair().challenger_identity()
            == evidentrail_bench::bounded_selector_challenger_identity_v1()
    }));

    let density = public.case(SelectorChallengerComparisonCaseV1::Perturbation(
        SelectorPerturbationCaseV1::DensityTrap,
    ));
    assert!(density.fixes_positive_production_regret());
    assert_eq!(
        density
            .pair()
            .production()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        600_000
    );
    assert_eq!(
        density
            .pair()
            .challenger()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        1_000_000
    );
    assert_eq!(
        density
            .pair()
            .production()
            .selected()
            .unwrap()
            .selected_packet_cost(),
        6
    );
    assert_eq!(
        density
            .pair()
            .challenger()
            .selected()
            .unwrap()
            .selected_packet_cost(),
        10
    );
    assert!(density.pair().hard_constraints_preserved());
    assert_eq!(density.pair().bounds().state_slot_cap(), 8);
    assert_eq!(density.pair().bounds().transition_attempt_cap(), 24);

    let breadth = public.case(SelectorChallengerComparisonCaseV1::Perturbation(
        SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder,
    ));
    assert!(breadth.fixes_positive_production_regret());
    assert_eq!(
        breadth
            .pair()
            .challenger()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        2_000_000
    );
    assert_eq!(
        breadth
            .pair()
            .challenger()
            .selected()
            .unwrap()
            .optional_acceptance_order()
            .len(),
        2
    );

    let large = public.case(SelectorChallengerComparisonCaseV1::Perturbation(
        SelectorPerturbationCaseV1::OracleCapThirteenIneligible,
    ));
    assert_eq!(
        large.pair().mode(),
        evidentrail_bench::BoundedSelectorChallengerModeV1::OrderAwareBeam
    );
    assert_eq!(large.pair().optional_packet_count(), 13);
    assert_eq!(large.pair().bounds().state_slot_cap(), 129);
    assert_eq!(large.pair().bounds().depth_cap(), 13);
    assert_eq!(large.pair().bounds().transition_attempt_cap(), 131_072);
    assert!(!large.pair().observation().transition_cap_reached());
    assert!(large.pair().observation().transition_attempts().unwrap() > 0);

    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let source_oracle = selection.case(case).full_selection_oracle();
        assert!(source_oracle.selection_problem_digest().is_some());
        let pair = public.case(SelectorChallengerComparisonCaseV1::SyntheticFull(case));
        assert_eq!(
            pair.pair().problem_digest(),
            source_oracle.selection_problem_digest().unwrap()
        );
    }

    let perturbation_annotations = SelectorPerturbationCaseV1::ALL.map(|case| {
        let expected = match case {
            SelectorPerturbationCaseV1::DensityTrap => {
                SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 400_000 }
            }
            SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder => {
                SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 500_000 }
            }
            SelectorPerturbationCaseV1::FixedOverheadTerminal => {
                SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore {
                    reason: NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget,
                }
            }
            SelectorPerturbationCaseV1::MandatoryOverBudgetTerminal => {
                SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore {
                    reason: NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget,
                }
            }
            SelectorPerturbationCaseV1::OracleCapThirteenIneligible => {
                SelectorPerturbationExpectedOutcomeV1::OptionalPacketCapIneligible {
                    packet_count: 13,
                    cap: 12,
                }
            }
            _ => SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 0 },
        };
        SelectorPerturbationGovernedAnnotationV1::new(
            perturbations.digest(),
            case,
            perturbations.case(case).digest(),
            expected,
        )
    });
    let governed_perturbations =
        evaluate_governed_selector_perturbation_corpus_v1(&perturbations, perturbation_annotations)
            .unwrap();

    let annotations = annotations(&ledgers);
    let hidden = hidden_manifest(artifact(225));
    let governed_selection = evaluate_governed_synthetic_three_lane_selection_corpus_v1(
        &selection,
        &source,
        governed_selection_inputs(
            &selection,
            &source,
            &annotations,
            &ledgers,
            &blocks,
            &hidden,
        ),
    )
    .unwrap();
    let governed = evaluate_governed_selector_challenger_comparison_v1(
        &public,
        &governed_perturbations,
        governed_selection.full_selection_oracle_report(),
    )
    .unwrap();
    assert_eq!(governed.recall_better_count(), 0);
    assert_eq!(governed.recall_equal_count(), 5);
    assert_eq!(governed.recall_regression_count(), 0);
    assert_eq!(governed.recall_not_evaluated_count(), 1);
    assert!(
        governed
            .recall_cases()
            .iter()
            .filter(|case| case.challenger().is_some())
            .all(|case| case.relation() == SelectorChallengerRecallRelationV1::Equal)
    );
    assert_eq!(
        governed.blockers(),
        &[
            SelectorChallengerAdmissionBlockerV1::SelectedCostTradeoff,
            SelectorChallengerAdmissionBlockerV1::NoGovernedLargeUniverseQualityCase,
            SelectorChallengerAdmissionBlockerV1::NoMeasuredWallTimeOrPeakRss,
        ]
    );
    assert!(!governed.production_promotion_eligible());
    assert!(governed.remains_evaluation_only());
    assert!(!governed.contains_scalar_composite());
    assert!(!governed.claims_population_quality());

    let debug = format!("{public:?} {governed:?}");
    for canary in [STRUCTURAL_CANARY, QUESTION_CANARY, "fatal crash"] {
        assert!(!debug.contains(canary));
    }
}
