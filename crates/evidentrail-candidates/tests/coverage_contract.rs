use std::collections::{BTreeMap, BTreeSet};

use evidentrail_candidates::{
    BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1, CandidateNeedsMoreReasonV1,
    CoverageBlockAnnotationV1, CoverageCandidateUniverseV1, CoverageFacetRoleV1,
    CoverageGenerationDecisionV1, CoverageSentinelKindV1, FailureSignalKindV1,
    MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1, MAX_COVERAGE_SOURCE_LANES_V1, MAX_PRIMARY_BLOCKS_V1,
    MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1, MAX_TIME_COVERAGE_STRATA_V1,
    OnsetBoundaryRoleV1, OnsetSignalKindV1, ReconstructionRiskKindV1, SourceCoverageStratumKindV1,
    generate_failure_coverage_candidates_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FramingPolicy, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordFragmentReason,
    RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_select::{AFFINITY_SCALE_V1, ProductionFacetKindV1};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FixtureLane {
    Stdout,
    Stderr,
}

#[derive(Clone)]
struct RecordSpec {
    lane: FixtureLane,
    member: u16,
    payload: Vec<u8>,
    state: RecordState,
}

impl RecordSpec {
    fn line(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            lane: FixtureLane::Stderr,
            member: 0,
            payload: payload.into(),
            state: RecordState::Complete,
        }
    }

    fn on(mut self, lane: FixtureLane) -> Self {
        self.lane = lane;
        self
    }

    fn on_member(mut self, member: u16) -> Self {
        self.member = member;
        self
    }

    fn fragment(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            state: RecordState::AdapterFragment {
                reason: RecordFragmentReason::MalformedProviderFraming,
            },
            ..Self::line(payload)
        }
    }
}

fn ledger(seed: u8, records: &[RecordSpec]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([41; 32]);
    let plan_digest = PlanDigest::from_bytes([42; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([43; 32]);
    let adapter = AdapterIdentity::new("coverage-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let mut lane_sequences = BTreeMap::<(u16, FixtureLane), u64>::new();
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;

    for (position, record) in records.iter().enumerate() {
        let lane_identity = (record.member, record.lane);
        let lane_sequence = lane_sequences.entry(lane_identity).or_default();
        let mut member = b"coverage-fixture-member".to_vec();
        member.extend_from_slice(&record.member.to_be_bytes());
        let stream = match record.lane {
            FixtureLane::Stdout => SourceStream::Stdout,
            FixtureLane::Stderr => SourceStream::Stderr,
        };
        let lane = LaneKey::new(SourceMember::new(member).unwrap(), stream);
        let record_bytes = RecordBytes::framed(record.payload.clone(), b"\n".to_vec());
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(record_bytes.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(record_bytes.source_len()).unwrap())
            .unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(u64::try_from(position).unwrap()),
                    lane,
                    LaneSequence::new(*lane_sequence),
                ),
                record_bytes,
                record.state,
            ))
            .unwrap();
        *lane_sequence = lane_sequence.checked_add(1).unwrap();
    }

    let record_count = u64::try_from(records.len()).unwrap();
    let completeness = if records.iter().any(|record| !record.state.is_complete()) {
        FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::MalformedProviderFraming),
            None,
        )
    } else {
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 141,
        })
    };
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
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

fn ready(blocks: &BlockIndex<'_>) -> CoverageCandidateUniverseV1 {
    match generate_failure_coverage_candidates_v1(blocks).unwrap() {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(reason) => {
            panic!("unexpected needs_more: {}", reason.code())
        }
    }
}

fn fallback_singleton_index(
    ledger: &EventLedger,
    confidence: BlockConfidence,
    reverse_assignments: bool,
) -> BlockIndex<'_> {
    let mut assignments = ledger
        .events()
        .iter()
        .map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"coverage-fallback-singleton-v1".to_vec(), b"1".to_vec()),
                BlockState::FallbackSingleton,
                confidence,
            )
        })
        .collect::<Vec<_>>();
    if reverse_assignments {
        assignments.reverse();
    }
    BlockIndex::reconcile(ledger, assignments).unwrap()
}

fn annotation(
    universe: &CoverageCandidateUniverseV1,
    block_id: evidentrail_core::BlockId,
) -> &CoverageBlockAnnotationV1 {
    universe
        .annotations()
        .binary_search_by_key(&block_id, CoverageBlockAnnotationV1::block_id)
        .map(|position| &universe.annotations()[position])
        .unwrap()
}

fn has_boundary(annotation: &CoverageBlockAnnotationV1, role: OnsetBoundaryRoleV1) -> bool {
    annotation
        .onset_boundaries()
        .iter()
        .any(|fact| fact.role() == role)
}

fn has_sentinel(annotation: &CoverageBlockAnnotationV1, kind: CoverageSentinelKindV1) -> bool {
    annotation
        .sentinels()
        .iter()
        .any(|sentinel| sentinel.kind() == kind)
}

#[test]
fn complete_multiline_and_repeated_failure_blocks_stay_intact() {
    let records = [
        RecordSpec::line(b"service ready".to_vec()),
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"  File \"app.py\", line 7, in run".to_vec()),
        RecordSpec::line(b"ValueError: bad input".to_vec()),
        RecordSpec::line(b"request continuing".to_vec()),
        RecordSpec::line(b"ERROR: second failure".to_vec()),
    ];
    let ledger = ledger(51, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let trace = blocks.block_for_event(ledger.events()[1].id()).unwrap();
    let second = blocks.block_for_event(ledger.events()[5].id()).unwrap();
    let before_trace = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let trace_annotation = annotation(&universe, trace.id());
    let second_annotation = annotation(&universe, second.id());

    assert_eq!(blocks.expand_block(trace.id()).unwrap().events().len(), 3);
    assert_eq!(
        trace_annotation
            .failure()
            .unwrap()
            .failure_block_ordinal_in_lane(),
        0
    );
    assert_eq!(
        trace_annotation
            .failure()
            .unwrap()
            .failure_block_count_in_lane(),
        2
    );
    assert!(trace_annotation.failure().unwrap().is_first_in_lane());
    assert!(second_annotation.failure().unwrap().is_last_in_lane());
    assert!(has_boundary(
        trace_annotation,
        OnsetBoundaryRoleV1::FirstFailureInLane
    ));
    assert!(has_boundary(
        annotation(&universe, before_trace.id()),
        OnsetBoundaryRoleV1::LastAvailableBeforeFirstFailure
    ));
    assert_eq!(universe.annotations().len(), blocks.len());
}

#[test]
fn absence_reports_do_not_steal_the_first_failure_boundary() {
    let records = [
        RecordSpec::line(b"health check: NO ERROR, no panic".to_vec()),
        RecordSpec::line(b"worker ready without failure".to_vec()),
        RecordSpec::line(b"no ERROR at startup; ERROR request REQ-7 upstream timed out".to_vec()),
        RecordSpec::line(b"retry failed".to_vec()),
    ];
    let ledger = ledger(79, &records);
    let blocks = fallback_singleton_index(&ledger, BlockConfidence::Certain, false);
    let universe = ready(&blocks);
    let ids = ledger
        .events()
        .iter()
        .map(|event| blocks.block_for_event(event.id()).unwrap().id())
        .collect::<Vec<_>>();

    assert!(annotation(&universe, ids[0]).failure().is_none());
    assert!(annotation(&universe, ids[1]).failure().is_none());
    assert!(has_boundary(
        annotation(&universe, ids[2]),
        OnsetBoundaryRoleV1::FirstFailureInLane
    ));
    assert!(has_boundary(
        annotation(&universe, ids[1]),
        OnsetBoundaryRoleV1::LastAvailableBeforeFirstFailure
    ));
    assert!(annotation(&universe, ids[3]).failure().is_some());
}

#[test]
fn explicit_onset_and_pre_onset_context_are_order_facts_not_causal_claims() {
    let records = [
        RecordSpec::line(b"serving normally".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"deployment started".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"serving after rollout".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"restarted".to_vec()).on(FixtureLane::Stdout),
    ];
    let ledger = ledger(52, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let before = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let first = blocks.block_for_event(ledger.events()[1].id()).unwrap();
    let later = blocks.block_for_event(ledger.events()[3].id()).unwrap();

    assert!(has_boundary(
        annotation(&universe, first.id()),
        OnsetBoundaryRoleV1::FirstExplicitOnsetInLane
    ));
    assert!(has_boundary(
        annotation(&universe, before.id()),
        OnsetBoundaryRoleV1::LastAvailableBeforeFirstExplicitOnset
    ));
    assert!(!has_boundary(
        annotation(&universe, later.id()),
        OnsetBoundaryRoleV1::FirstExplicitOnsetInLane
    ));
    assert_eq!(
        annotation(&universe, first.id()).onset_signals()[0].kind(),
        OnsetSignalKindV1::Deployment
    );
    assert_eq!(
        annotation(&universe, later.id()).onset_signals()[0].kind(),
        OnsetSignalKindV1::Restart
    );
}

#[test]
fn first_failure_and_source_stream_coverage_are_lane_local_under_interleaving() {
    let records = [
        RecordSpec::line(b"stdout ready".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"stderr ready".to_vec())
            .on(FixtureLane::Stderr)
            .on_member(1),
        RecordSpec::line(b"ERROR stdout".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"fatal: stderr".to_vec())
            .on(FixtureLane::Stderr)
            .on_member(1),
    ];
    let ledger = ledger(53, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);

    for (ready_event, failure_event) in [(0, 2), (1, 3)] {
        let ready_block = blocks
            .block_for_event(ledger.events()[ready_event].id())
            .unwrap();
        let failure_block = blocks
            .block_for_event(ledger.events()[failure_event].id())
            .unwrap();
        assert!(has_boundary(
            annotation(&universe, failure_block.id()),
            OnsetBoundaryRoleV1::FirstFailureInLane
        ));
        assert!(has_boundary(
            annotation(&universe, ready_block.id()),
            OnsetBoundaryRoleV1::LastAvailableBeforeFirstFailure
        ));
        assert!(has_sentinel(
            annotation(&universe, ready_block.id()),
            CoverageSentinelKindV1::Source(SourceCoverageStratumKindV1::SourceStreamHead)
        ));
        assert!(has_sentinel(
            annotation(&universe, failure_block.id()),
            CoverageSentinelKindV1::Source(SourceCoverageStratumKindV1::SourceStreamTail)
        ));
    }
    assert_eq!(universe.accounting().source_lane_count(), 2);
}

#[test]
fn binary_bytes_punctuation_and_near_substrings_are_handled_without_decoding() {
    let records = [
        RecordSpec::line(b"\xffterror\0errorish panickingish".to_vec()),
        RecordSpec::line(b"ERROR!!!".to_vec()),
    ];
    let ledger = ledger(54, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let first = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let second = blocks.block_for_event(ledger.events()[1].id()).unwrap();

    assert!(annotation(&universe, first.id()).failure().is_none());
    let failure = annotation(&universe, second.id()).failure().unwrap();
    assert_eq!(failure.signal_occurrence_count(), 1);
    assert_eq!(failure.signals()[0].kind(), FailureSignalKindV1::Error);
    assert_eq!(universe.accounting().failure_signal_observations(), 1);
}

#[test]
fn fragments_and_uncertain_boundaries_are_explicit_risk_sentinels() {
    let records = [RecordSpec::fragment(b"ERROR fragment \xff".to_vec())];
    let ledger = ledger(55, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let block = &blocks.blocks()[0];
    let annotation = annotation(&universe, block.id());

    for risk in [
        ReconstructionRiskKindV1::UnknownConfidence,
        ReconstructionRiskKindV1::AmbiguousBoundary,
        ReconstructionRiskKindV1::Fragment,
    ] {
        assert!(annotation.reconstruction_risks().contains(&risk));
        assert!(has_sentinel(
            annotation,
            CoverageSentinelKindV1::ReconstructionRisk(risk)
        ));
    }
    assert_eq!(
        blocks.expand_block(block.id()).unwrap().exact_bytes(),
        b"ERROR fragment \xff\n"
    );
}

#[test]
fn all_fallback_risk_facts_are_exhaustive_but_selection_authority_is_stratified() {
    const BLOCK_COUNT: usize = 257;
    let records = (0..BLOCK_COUNT)
        .map(|position| {
            RecordSpec::line(format!("ordinary fallback block {position:04}").into_bytes())
        })
        .collect::<Vec<_>>();
    let source = ledger(67, &records);
    let canonical_blocks = fallback_singleton_index(&source, BlockConfidence::Unknown, false);
    let permuted_blocks = fallback_singleton_index(&source, BlockConfidence::Unknown, true);
    let canonical = ready(&canonical_blocks);
    let permuted = ready(&permuted_blocks);

    assert_eq!(canonical, permuted);
    assert_eq!(canonical.annotations().len(), BLOCK_COUNT);
    assert!(canonical.annotations().iter().all(|annotation| {
        annotation.reconstruction_risks()
            == [
                ReconstructionRiskKindV1::UnknownConfidence,
                ReconstructionRiskKindV1::FallbackSingleton,
            ]
    }));
    assert_eq!(
        canonical.accounting().reconstruction_risk_fact_count(),
        BLOCK_COUNT * 2
    );
    assert_eq!(
        canonical
            .accounting()
            .reconstruction_risk_representative_count(),
        MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1 * 2
    );

    let expected_offsets = [0, 64, 128, 192, 256];
    let expected_representatives = expected_offsets
        .iter()
        .map(|offset| canonical_blocks.blocks()[*offset].id())
        .collect::<BTreeSet<_>>();
    for risk in [
        ReconstructionRiskKindV1::UnknownConfidence,
        ReconstructionRiskKindV1::FallbackSingleton,
    ] {
        let actual_representatives = canonical
            .annotations()
            .iter()
            .filter(|annotation| {
                has_sentinel(annotation, CoverageSentinelKindV1::ReconstructionRisk(risk))
            })
            .map(CoverageBlockAnnotationV1::block_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_representatives, expected_representatives);
    }

    let non_risk_sentinel_bound = 4 + MAX_TIME_COVERAGE_STRATA_V1;
    let risk_sentinel_bound = 2 * MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1;
    assert!(
        canonical.accounting().emitted_sentinel_count()
            <= non_risk_sentinel_bound + risk_sentinel_bound
    );
    assert!(
        canonical.accounting().emitted_affinity_count()
            <= non_risk_sentinel_bound + risk_sentinel_bound
    );
}

#[test]
fn only_the_five_authorized_lane_two_facet_families_are_emitted() {
    let records = [
        RecordSpec::line(b"ordinary head".to_vec()),
        RecordSpec::line(b"deployment".to_vec()),
        RecordSpec::line(b"ERROR tail".to_vec()),
    ];
    let ledger = ledger(56, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let kinds = universe
        .facets()
        .iter()
        .map(|facet| facet.kind())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        kinds,
        BTreeSet::from([
            ProductionFacetKindV1::FailureRole,
            ProductionFacetKindV1::OnsetRole,
            ProductionFacetKindV1::SourceCoverageStratum,
            ProductionFacetKindV1::TimeCoverageStratum,
            ProductionFacetKindV1::ReconstructionRiskCoverage,
        ])
    );
    assert!(universe.facets().iter().all(|facet| matches!(
        facet.role(),
        CoverageFacetRoleV1::Failure(_)
            | CoverageFacetRoleV1::ExplicitOnset(_)
            | CoverageFacetRoleV1::OnsetBoundary(_)
            | CoverageFacetRoleV1::Source(_)
            | CoverageFacetRoleV1::AcquisitionOrderStratum { .. }
            | CoverageFacetRoleV1::ReconstructionRisk(_)
    )));
    for facet in universe.facets() {
        let expected_weight = if facet.kind().is_coverage_only() {
            AFFINITY_SCALE_V1 / BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1
        } else {
            AFFINITY_SCALE_V1
        };
        assert_eq!(facet.facet().weight().micros(), expected_weight);
    }
}

#[test]
fn assignment_permutation_cannot_change_canonical_annotations() {
    let records = [
        RecordSpec::line(b"ready".to_vec()),
        RecordSpec::line(b"ERROR one".to_vec()),
        RecordSpec::line(b"deployment".to_vec()),
    ];
    let ledger = ledger(57, &records);
    let canonical = frame_source_lanes_v1(&ledger).unwrap();
    let mut assignments = canonical
        .blocks()
        .iter()
        .map(|block| {
            BlockAssignment::new_same_lane_v1(
                block.lane().clone(),
                block
                    .member_ids()
                    .iter()
                    .copied()
                    .zip(block.member_lane_sequences().iter().copied()),
                block.framing_policy().clone(),
                block.state(),
                block.confidence(),
            )
        })
        .collect::<Vec<_>>();
    assignments.reverse();
    let permuted = BlockIndex::reconcile(&ledger, assignments).unwrap();

    assert_eq!(ready(&canonical), ready(&permuted));
}

#[test]
fn first_position_failure_has_no_fabricated_predecessor() {
    let records = [
        RecordSpec::line(b"ERROR first visible block".to_vec()),
        RecordSpec::line(b"later context".to_vec()),
    ];
    let ledger = ledger(59, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let first = blocks.block_for_event(ledger.events()[0].id()).unwrap();

    assert!(has_boundary(
        annotation(&universe, first.id()),
        OnsetBoundaryRoleV1::FirstFailureInLane
    ));
    assert!(universe.annotations().iter().all(|candidate| !has_boundary(
        candidate,
        OnsetBoundaryRoleV1::LastAvailableBeforeFirstFailure
    )));
}

#[test]
fn duplicate_failure_payloads_remain_distinct_occurrence_annotations() {
    let records = [
        RecordSpec::line(b"ERROR duplicate".to_vec()),
        RecordSpec::line(b"ERROR duplicate".to_vec()),
    ];
    let ledger = ledger(60, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let first = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let second = blocks.block_for_event(ledger.events()[1].id()).unwrap();

    assert_ne!(first.id(), second.id());
    assert_eq!(
        annotation(&universe, first.id())
            .failure()
            .unwrap()
            .failure_block_ordinal_in_lane(),
        0
    );
    assert_eq!(
        annotation(&universe, second.id())
            .failure()
            .unwrap()
            .failure_block_ordinal_in_lane(),
        1
    );
}

#[test]
fn negated_failure_text_does_not_create_a_failure_role() {
    let records = [RecordSpec::line(b"no ERROR was observed".to_vec())];
    let ledger = ledger(61, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let block = &blocks.blocks()[0];
    assert!(annotation(&universe, block.id()).failure().is_none());
    assert!(!universe.facets().iter().any(|facet| {
        facet.role() == CoverageFacetRoleV1::Failure(FailureSignalKindV1::Error)
            && facet.kind() == ProductionFacetKindV1::FailureRole
    }));
}

#[test]
fn empty_input_and_deterministic_replay_preserve_the_exhaustive_map() {
    let empty_ledger = ledger(62, &[]);
    let empty_blocks = frame_source_lanes_v1(&empty_ledger).unwrap();
    let empty = ready(&empty_blocks);
    assert!(empty.annotations().is_empty());
    assert!(empty.facets().is_empty());
    assert_eq!(empty.accounting().scanned_bytes(), 0);

    let records = [
        RecordSpec::line(b"ready".to_vec()),
        RecordSpec::line(b"deployment".to_vec()),
        RecordSpec::line(b"ERROR replay".to_vec()),
    ];
    let first_ledger = ledger(63, &records);
    let replay_ledger = ledger(63, &records);
    let first_blocks = frame_source_lanes_v1(&first_ledger).unwrap();
    let replay_blocks = frame_source_lanes_v1(&replay_ledger).unwrap();
    assert_eq!(ready(&first_blocks), ready(&replay_blocks));
}

#[test]
fn primary_block_source_lane_and_signal_caps_fail_without_partial_output() {
    let too_many_blocks = (0..=MAX_PRIMARY_BLOCKS_V1)
        .map(|position| RecordSpec::line(format!("ordinary {position}").into_bytes()))
        .collect::<Vec<_>>();
    let block_ledger = ledger(64, &too_many_blocks);
    let block_index = frame_source_lanes_v1(&block_ledger).unwrap();
    assert!(matches!(
        generate_failure_coverage_candidates_v1(&block_index).unwrap(),
        CoverageGenerationDecisionV1::NeedsMore(reason)
            if reason.reason() == CandidateNeedsMoreReasonV1::PrimaryBlockCountCap
    ));

    let too_many_lanes = (0..=MAX_COVERAGE_SOURCE_LANES_V1)
        .map(|member| {
            RecordSpec::line(b"ordinary".to_vec()).on_member(u16::try_from(member).unwrap())
        })
        .collect::<Vec<_>>();
    let lane_ledger = ledger(65, &too_many_lanes);
    let lane_index = frame_source_lanes_v1(&lane_ledger).unwrap();
    assert!(matches!(
        generate_failure_coverage_candidates_v1(&lane_index).unwrap(),
        CoverageGenerationDecisionV1::NeedsMore(reason)
            if reason.reason() == CandidateNeedsMoreReasonV1::CoverageSourceLaneCap
    ));

    let mut signals = Vec::with_capacity((MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1 + 1) * 6);
    for _ in 0..=MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1 {
        signals.extend_from_slice(b"ERROR ");
    }
    let signal_ledger = ledger(66, &[RecordSpec::line(signals)]);
    let signal_index = frame_source_lanes_v1(&signal_ledger).unwrap();
    assert!(matches!(
        generate_failure_coverage_candidates_v1(&signal_index).unwrap(),
        CoverageGenerationDecisionV1::NeedsMore(reason)
            if reason.reason() == CandidateNeedsMoreReasonV1::CoverageSignalObservationCap
    ));
}

#[test]
fn diagnostics_never_expose_payload_member_or_identity_canaries() {
    let canary = "COVERAGE_SECRET_CANARY";
    let records = [
        RecordSpec::line(format!("ERROR {canary}").into_bytes()),
        RecordSpec::fragment(format!("deployment {canary}").into_bytes()),
    ];
    let ledger = ledger(58, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let rendered = format!("{universe:?} {:?}", universe.annotations());

    assert!(!rendered.contains(canary));
    assert!(!rendered.contains("coverage-fixture-member"));
    assert!(!rendered.contains("blk_"));
    assert!(!rendered.contains("evt_"));
}

#[test]
fn needs_more_reason_codes_for_lane_two_are_contentless() {
    for reason in [
        CandidateNeedsMoreReasonV1::CoverageAnalysisTokenCap,
        CandidateNeedsMoreReasonV1::CoverageSignalObservationCap,
        CandidateNeedsMoreReasonV1::CoverageSourceLaneCap,
        CandidateNeedsMoreReasonV1::CoverageFacetOutputCap,
        CandidateNeedsMoreReasonV1::CoverageAffinityOutputCap,
        CandidateNeedsMoreReasonV1::CoverageSentinelOutputCap,
    ] {
        let debug = format!("{reason:?}");
        assert!(debug.contains(reason.code()));
        assert!(!debug.contains("COVERAGE_SECRET_CANARY"));
    }
}
