#![cfg(feature = "benchmark-instrumentation")]

use std::collections::{BTreeMap, BTreeSet};

use evidentrail_candidates::{
    CandidateGenerationDecisionV1, CoverageGenerationDecisionV1,
    ProviderCorrelationGenerationDecisionV1, generate_failure_coverage_candidates_v1,
    generate_lexical_candidates_v1, generate_provider_correlations_v1,
};
use evidentrail_compile::{
    PreparedThreeLaneAblationSetV1, ReadyCandidateLanesV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1, ThreeLaneProposalPreparationDecisionV1,
    prepare_ready_three_lane_ablations_v1, prepare_three_lane_ablations_v1,
    prepare_three_lane_proposal_universe_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, FramingPolicy, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, ResultId, RetrievalId, SourceIdentityDigest,
    SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_select::{AffinityV1, FacetIdV1, PacketIdV1, ProductionFacetV1};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn result_id(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn fixture_ledger(seed: u8) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("ablation-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"fixture-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let correlation = ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([91; 32]),
        ProviderAttestedRelationKindV1::TraceIdentity,
        ProviderAttestationValueV1::new(b"opaque-correlation".to_vec()).unwrap(),
    );
    let records = [
        b"ordinary E0425 query-only record".as_slice(),
        b"Traceback (most recent call last):".as_slice(),
        b"ValueError: provider-linked failure".as_slice(),
        b"ordinary provider peer".as_slice(),
    ];
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0_u64;
    for (position, raw) in records.iter().enumerate() {
        source_bytes += u64::try_from(raw.len() + 1).unwrap();
        let sequence = u64::try_from(position).unwrap();
        let mut envelope = RawEnvelopeV1::new(
            envelope_identity.clone(),
            EnvelopeOrdering::new(
                AcquisitionSequence::new(sequence),
                lane.clone(),
                LaneSequence::new(sequence),
            ),
            RecordBytes::framed(raw.to_vec(), b"\n".to_vec()),
            RecordState::Complete,
        );
        if position >= 2 {
            envelope = envelope.with_provider_attestations(
                ProviderAttestationsV1::new([correlation.clone()]).unwrap(),
            );
        }
        builder.accept(envelope).unwrap();
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    u64::try_from(records.len()).unwrap(),
                    source_bytes - u64::try_from(records.len()).unwrap(),
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
                    code: 211,
                }),
            )
            .unwrap(),
        )
        .unwrap()
}

fn singleton_blocks(ledger: &EventLedger, reverse: bool) -> BlockIndex<'_> {
    let mut assignments = ledger
        .events()
        .iter()
        .map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"ablation-singleton".to_vec(), b"1".to_vec()),
                BlockState::FallbackSingleton,
                BlockConfidence::Certain,
            )
        })
        .collect::<Vec<_>>();
    if reverse {
        assignments.reverse();
    }
    BlockIndex::reconcile(ledger, assignments).unwrap()
}

fn prepared_set(
    decision: ThreeLaneAblationPreparationDecisionV1,
) -> PreparedThreeLaneAblationSetV1 {
    match decision {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(needs_more) => {
            panic!("unexpected needs_more: {}", needs_more.reason().code())
        }
    }
}

fn expected_affinities(
    mask: ThreeLaneAblationMaskV1,
    lexical: &evidentrail_candidates::LexicalCandidateUniverseV1,
    coverage: &evidentrail_candidates::CoverageCandidateUniverseV1,
    provider: &evidentrail_candidates::ProviderCorrelationUniverseV1,
) -> BTreeMap<PacketIdV1, BTreeMap<FacetIdV1, AffinityV1>> {
    let mut expected: BTreeMap<PacketIdV1, BTreeMap<FacetIdV1, AffinityV1>> = lexical
        .primary_blocks()
        .iter()
        .map(|block| (block.packet_id(), BTreeMap::new()))
        .collect::<BTreeMap<_, _>>();
    let mut merge = |packet_id: PacketIdV1, affinities: &[evidentrail_select::FacetAffinityV1]| {
        let target = expected.get_mut(&packet_id).unwrap();
        for affinity in affinities {
            target
                .entry(affinity.facet_id())
                .and_modify(|current| *current = (*current).max(affinity.affinity()))
                .or_insert(affinity.affinity());
        }
    };
    if mask.includes(evidentrail_compile::CandidateLaneV1::Lexical) {
        for block in lexical.primary_blocks() {
            merge(block.packet_id(), block.affinities());
        }
    }
    if mask.includes(evidentrail_compile::CandidateLaneV1::Coverage) {
        for annotation in coverage.annotations() {
            merge(
                PacketIdV1::from_bytes(*annotation.block_id().as_bytes()),
                annotation.affinities(),
            );
        }
    }
    if mask.includes(evidentrail_compile::CandidateLaneV1::Provider) {
        for annotation in provider.annotations() {
            merge(
                PacketIdV1::from_bytes(*annotation.block_id().as_bytes()),
                annotation.affinities(),
            );
        }
    }
    expected
}

fn expected_facets(
    mask: ThreeLaneAblationMaskV1,
    lexical: &evidentrail_candidates::LexicalCandidateUniverseV1,
    coverage: &evidentrail_candidates::CoverageCandidateUniverseV1,
    provider: &evidentrail_candidates::ProviderCorrelationUniverseV1,
) -> Vec<ProductionFacetV1> {
    let mut expected = BTreeMap::new();
    if mask.includes(evidentrail_compile::CandidateLaneV1::Lexical) {
        for facet in lexical.facets() {
            expected.insert(facet.facet().id(), facet.facet().clone());
        }
    }
    if mask.includes(evidentrail_compile::CandidateLaneV1::Coverage) {
        for facet in coverage.facets() {
            expected.insert(facet.facet().id(), facet.facet().clone());
        }
    }
    if mask.includes(evidentrail_compile::CandidateLaneV1::Provider) {
        for facet in provider.facets() {
            expected.insert(facet.facet().id(), facet.facet().clone());
        }
    }
    expected.into_values().collect()
}

#[test]
fn full_is_production_identical_and_masks_are_deterministic_receipt_bound() {
    let ledger = fixture_ledger(61);
    let replay = fixture_ledger(61);
    let blocks = singleton_blocks(&ledger, false);
    let permuted = singleton_blocks(&ledger, true);
    let replay_blocks = singleton_blocks(&replay, false);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let question = b"diagnose E0425 ValueError";
    let production = match prepare_three_lane_proposal_universe_v1(
        question,
        &ledger,
        &blocks,
        result_id(61),
        &tokenizer,
    )
    .unwrap()
    {
        ThreeLaneProposalPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneProposalPreparationDecisionV1::NeedsMore(_) => panic!("fixture must prepare"),
    };
    let first = prepared_set(
        prepare_three_lane_ablations_v1(question, &ledger, &blocks, result_id(61), &tokenizer)
            .unwrap(),
    );
    let reordered = prepared_set(
        prepare_three_lane_ablations_v1(question, &ledger, &permuted, result_id(61), &tokenizer)
            .unwrap(),
    );
    let replayed = prepared_set(
        prepare_three_lane_ablations_v1(
            question,
            &replay,
            &replay_blocks,
            result_id(61),
            &tokenizer,
        )
        .unwrap(),
    );

    assert_eq!(
        first
            .configuration(ThreeLaneAblationMaskV1::Full)
            .prepared(),
        &production
    );
    assert_eq!(first, reordered);
    assert_eq!(first, replayed);
    assert_eq!(
        first
            .configurations()
            .iter()
            .map(|configured| configured.mask())
            .collect::<Vec<_>>(),
        ThreeLaneAblationMaskV1::ALL
    );
    assert_eq!(
        first
            .configurations()
            .iter()
            .map(|configured| configured.config_digest())
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        first
            .configurations()
            .iter()
            .map(|configured| configured.prepared().receipt().digest())
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let full_input = production.receipt().input();
    for configured in first.configurations() {
        let input = configured.prepared().receipt().input();
        assert_eq!(input.retrieval_id(), full_input.retrieval_id());
        assert_eq!(input.plan_id(), full_input.plan_id());
        assert_eq!(input.plan_digest(), full_input.plan_digest());
        assert_eq!(
            input.acquisition_receipt_id(),
            full_input.acquisition_receipt_id()
        );
        assert_eq!(input.question_digest(), full_input.question_digest());
    }
    let debug = format!("{first:?}");
    assert!(!debug.contains("E0425"));
    assert!(!debug.contains("ValueError"));
    assert!(!debug.contains(&format!("{:?}", full_input.digest())));
}

#[test]
fn every_mask_is_the_exact_union_of_only_its_included_lane_authority() {
    let ledger = fixture_ledger(62);
    let blocks = singleton_blocks(&ledger, false);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let question = b"diagnose E0425 ValueError";
    let lexical = match generate_lexical_candidates_v1(question, &blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let coverage = match generate_failure_coverage_candidates_v1(&blocks).unwrap() {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let provider = match generate_provider_correlations_v1(&blocks).unwrap() {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    assert!(!lexical.facets().is_empty());
    assert!(!coverage.facets().is_empty());
    assert!(!provider.facets().is_empty());
    assert!(!provider.edges().is_empty());
    let prepared = prepared_set(
        prepare_ready_three_lane_ablations_v1(
            &ledger,
            &blocks,
            result_id(62),
            &tokenizer,
            ReadyCandidateLanesV1::new(&lexical, &coverage, &provider),
        )
        .unwrap(),
    );

    for mask in ThreeLaneAblationMaskV1::ALL {
        let actual = prepared.configuration(mask).prepared();
        assert_eq!(
            actual.facets(),
            expected_facets(mask, &lexical, &coverage, &provider)
        );
        let expected = expected_affinities(mask, &lexical, &coverage, &provider);
        let expected_proposals = expected
            .iter()
            .filter(|(_, affinities)| !affinities.is_empty())
            .map(|(packet_id, _)| *packet_id)
            .collect::<BTreeSet<_>>();
        let actual_proposals = actual
            .proposal_packets()
            .iter()
            .map(|packet| packet.id())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_proposals, expected_proposals);
        for packet in actual.proposal_packets() {
            let actual_affinities = packet
                .affinities()
                .iter()
                .map(|affinity| (affinity.facet_id(), affinity.affinity()))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(actual_affinities, expected[&packet.id()]);
        }
        if !mask.includes(evidentrail_compile::CandidateLaneV1::Lexical) {
            assert!(actual.mandatory().is_empty());
            assert!(
                actual
                    .packet_metadata()
                    .iter()
                    .all(|metadata| metadata.mandatory_reasons().is_empty())
            );
        }
    }
}

#[test]
fn excluded_lexical_output_cannot_change_without_lexical_structural_material() {
    let ledger = fixture_ledger(63);
    let blocks = singleton_blocks(&ledger, false);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let lexical_a = match generate_lexical_candidates_v1(b"E0425", &blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let lexical_b = match generate_lexical_candidates_v1(b"unmatched-token", &blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    assert_ne!(lexical_a, lexical_b);
    let coverage = match generate_failure_coverage_candidates_v1(&blocks).unwrap() {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let provider = match generate_provider_correlations_v1(&blocks).unwrap() {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let prepare = |lexical| {
        prepared_set(
            prepare_ready_three_lane_ablations_v1(
                &ledger,
                &blocks,
                result_id(63),
                &tokenizer,
                ReadyCandidateLanesV1::new(lexical, &coverage, &provider),
            )
            .unwrap(),
        )
    };
    let first = prepare(&lexical_a);
    let second = prepare(&lexical_b);
    let first = first
        .configuration(ThreeLaneAblationMaskV1::WithoutLexical)
        .prepared();
    let second = second
        .configuration(ThreeLaneAblationMaskV1::WithoutLexical)
        .prepared();

    assert_eq!(first.facets(), second.facets());
    assert_eq!(first.packet_metadata(), second.packet_metadata());
    assert_eq!(first.proposal_packets(), second.proposal_packets());
    assert_eq!(first.mandatory(), second.mandatory());
    assert_eq!(first.certification(), second.certification());
    assert_ne!(first.receipt().input(), second.receipt().input());
}
