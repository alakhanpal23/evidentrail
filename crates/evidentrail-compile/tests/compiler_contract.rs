use std::collections::BTreeSet;

use evidentrail_candidates::{
    CandidateGenerationDecisionV1, CandidateNeedsMoreReasonV1, CoverageGenerationDecisionV1,
    LexicalCandidateUniverseV1, MAX_QUESTION_BYTES_V1, ProviderCorrelationGenerationDecisionV1,
    generate_failure_coverage_candidates_v1, generate_lexical_candidates_v1,
    generate_provider_correlations_v1,
};
use evidentrail_compile::{
    CandidateLaneV1, LaneUniverseViolationV1, PROPOSAL_PREPARATION_CONTRACT_VERSION_V1,
    PROPOSAL_RECEIPT_INTEGER_ENCODING_V1, PreparedThreeLaneProposalUniverseV1,
    PreparedThreeLaneSelectionDecisionV1, ReadyCandidateLanesV1, ThreeLaneCompileErrorV1,
    ThreeLaneNeedsMoreV1, ThreeLaneProposalPreparationDecisionV1, compile_ready_three_lanes_v1,
    compile_three_lanes_v1, prepare_three_lane_proposal_universe_v1,
    select_prepared_three_lane_proposals_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FramingPolicy, LaneKey, LaneSequence, LedgerBuilder, NativeEventId, PlanDigest,
    PlanId, PolicyAuthorization, ProviderAttestationScopeDigestV1, ProviderAttestationValueV1,
    ProviderAttestationsV1, ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, ResultId, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_select::{PacketIdV1, ProductionFacetKindV1, SelectionConstraintV1, TotalTokenBudgetV1};
use sha2::{Digest, Sha256};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn result_id(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn complete() -> FetchCompleteness {
    FetchCompleteness::complete(CompletenessProof::OtherVersioned {
        version: 1,
        code: 161,
    })
}

fn ledger(seed: u8, records: Vec<RecordBytes>, completeness: FetchCompleteness) -> EventLedger {
    ledger_with_native_ids(
        seed,
        records.into_iter().map(|record| (record, None)).collect(),
        completeness,
    )
}

fn ledger_with_native_ids(
    seed: u8,
    records: Vec<(RecordBytes, Option<Vec<u8>>)>,
    completeness: FetchCompleteness,
) -> EventLedger {
    ledger_with_provider_evidence(
        seed,
        records
            .into_iter()
            .map(|(record, native_event_id)| {
                (record, native_event_id, ProviderAttestationsV1::default())
            })
            .collect(),
        completeness,
    )
}

fn ledger_with_provider_evidence(
    seed: u8,
    records: Vec<(RecordBytes, Option<Vec<u8>>, ProviderAttestationsV1)>,
    completeness: FetchCompleteness,
) -> EventLedger {
    ledger_with_provider_evidence_and_plan(seed, 31, 32, records, completeness)
}

fn ledger_with_provider_evidence_and_plan(
    seed: u8,
    plan_id_seed: u8,
    plan_digest_seed: u8,
    records: Vec<(RecordBytes, Option<Vec<u8>>, ProviderAttestationsV1)>,
    completeness: FetchCompleteness,
) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([plan_id_seed; 32]);
    let plan_digest = PlanDigest::from_bytes([plan_digest_seed; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([33; 32]);
    let adapter = AdapterIdentity::new("compile-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"compile-fixture-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;
    for (position, (record, native_event_id, attestations)) in records.iter().enumerate() {
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(record.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(record.source_len()).unwrap())
            .unwrap();
        let sequence = u64::try_from(position).unwrap();
        let mut envelope = RawEnvelopeV1::new(
            envelope_identity.clone(),
            EnvelopeOrdering::new(
                AcquisitionSequence::new(sequence),
                lane.clone(),
                LaneSequence::new(sequence),
            ),
            record.clone(),
            RecordState::Complete,
        );
        if let Some(native_event_id) = native_event_id {
            envelope =
                envelope.with_native_event_id(NativeEventId::new(native_event_id.clone()).unwrap());
        }
        envelope = envelope.with_provider_attestations(attestations.clone());
        builder.accept(envelope).unwrap();
    }
    let record_count = u64::try_from(records.len()).unwrap();
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

fn lines(seed: u8, lines: &[&[u8]]) -> EventLedger {
    ledger(
        seed,
        lines
            .iter()
            .map(|line| RecordBytes::framed(line.to_vec(), b"\n".to_vec()))
            .collect(),
        complete(),
    )
}

fn singleton_index(ledger: &EventLedger, reverse: bool) -> BlockIndex<'_> {
    let mut assignments = ledger
        .events()
        .iter()
        .map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"compile-singleton-v1".to_vec(), b"1".to_vec()),
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

fn ready_lexical(question: &[u8], blocks: &BlockIndex<'_>) -> LexicalCandidateUniverseV1 {
    match generate_lexical_candidates_v1(question, blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(reason) => {
            panic!("unexpected lexical needs_more: {}", reason.code())
        }
    }
}

fn expect_prepared(
    decision: ThreeLaneProposalPreparationDecisionV1,
) -> PreparedThreeLaneProposalUniverseV1 {
    match decision {
        ThreeLaneProposalPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneProposalPreparationDecisionV1::NeedsMore(needs_more) => {
            panic!(
                "unexpected preparation needs_more: {}",
                needs_more.reason().code()
            )
        }
    }
}

fn independent_receipt_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("fixture field length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn independent_receipt_len(hasher: &mut Sha256, length: usize) {
    hasher.update(
        u64::try_from(length)
            .expect("fixture collection length fits u64")
            .to_le_bytes(),
    );
}

fn independently_recompute_input_digest(
    prepared: &PreparedThreeLaneProposalUniverseV1,
    ledger: &EventLedger,
) -> [u8; 32] {
    let input = prepared.receipt().input();
    let mut adapter = Sha256::new();
    adapter.update(b"evidentrail/compile/adapter-identity-digest/v1\0");
    independent_receipt_field(&mut adapter, ledger.adapter().kind().as_bytes());
    independent_receipt_field(&mut adapter, ledger.adapter().version().as_bytes());
    let adapter_digest: [u8; 32] = adapter.finalize().into();
    assert_eq!(input.adapter_identity_digest().as_bytes(), &adapter_digest);

    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/compile/proposal-preparation-input/v1\0");
    independent_receipt_field(&mut hasher, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1);
    hasher.update(PROPOSAL_PREPARATION_CONTRACT_VERSION_V1.to_le_bytes());
    independent_receipt_field(&mut hasher, input.result_id().as_bytes());
    independent_receipt_field(&mut hasher, input.question_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.retrieval_id().as_bytes());
    independent_receipt_field(&mut hasher, input.plan_id().as_bytes());
    independent_receipt_field(&mut hasher, input.plan_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.source_identity_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.acquisition_receipt_id().as_bytes());
    independent_receipt_field(&mut hasher, &adapter_digest);
    independent_receipt_field(&mut hasher, input.candidate_config_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.compiler_config_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.renderer_digest().as_bytes());
    independent_receipt_field(&mut hasher, input.tokenizer_digest().as_bytes());
    independent_receipt_field(
        &mut hasher,
        input.tokenizer_bound_contract_digest().as_bytes(),
    );
    hasher.finalize().into()
}

fn independently_recompute_proposal_receipt(
    prepared: &PreparedThreeLaneProposalUniverseV1,
    ledger: &EventLedger,
) -> [u8; 32] {
    let independent_input = independently_recompute_input_digest(prepared, ledger);
    assert_eq!(
        prepared.receipt().input().digest().as_bytes(),
        &independent_input
    );

    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/compile/proposal-universe-receipt/v1\0");
    independent_receipt_field(&mut hasher, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1);
    hasher.update(PROPOSAL_PREPARATION_CONTRACT_VERSION_V1.to_le_bytes());
    independent_receipt_field(&mut hasher, &independent_input);
    let accounting = prepared.receipt().accounting();
    for value in [
        accounting.exhaustive_primary_block_count(),
        accounting.exhaustive_member_event_count(),
        accounting.exhaustive_member_source_bytes(),
        accounting.proposal_packet_count(),
        accounting.proposal_unique_member_event_count(),
        accounting.proposal_member_source_bytes(),
        accounting.retained_raw_nonproposal_block_count(),
        accounting.retained_raw_nonproposal_member_event_count(),
        accounting.retained_raw_nonproposal_source_bytes(),
        accounting.proposal_affinity_count(),
        accounting.mandatory_proposal_count(),
        accounting.facet_count(),
    ] {
        hasher.update(value.to_le_bytes());
    }

    let mut facets = prepared.facets().iter().collect::<Vec<_>>();
    facets.sort_unstable_by_key(|facet| facet.id());
    independent_receipt_len(&mut hasher, facets.len());
    for facet in facets {
        independent_receipt_field(&mut hasher, facet.id().as_bytes());
        independent_receipt_field(&mut hasher, facet.kind().code().as_bytes());
        hasher.update(facet.weight().micros().to_le_bytes());
    }

    let mut metadata = prepared.packet_metadata().iter().collect::<Vec<_>>();
    metadata.sort_unstable_by_key(|entry| entry.block_id());
    independent_receipt_len(&mut hasher, metadata.len());
    for entry in metadata {
        independent_receipt_field(&mut hasher, entry.block_id().as_bytes());
        independent_receipt_field(&mut hasher, entry.packet_id().as_bytes());
        independent_receipt_len(&mut hasher, entry.ordered_event_ids().len());
        for event_id in entry.ordered_event_ids() {
            independent_receipt_field(&mut hasher, event_id.as_bytes());
        }
        let mut reasons = entry.mandatory_reasons().to_vec();
        reasons.sort_unstable_by_key(|reason| (reason.facet_id(), reason.identifier_kind()));
        independent_receipt_len(&mut hasher, reasons.len());
        for reason in reasons {
            independent_receipt_field(&mut hasher, reason.facet_id().as_bytes());
            independent_receipt_field(&mut hasher, reason.identifier_kind().code().as_bytes());
        }
    }

    let mut proposals = prepared.proposal_packets().iter().collect::<Vec<_>>();
    proposals.sort_unstable_by_key(|packet| packet.id());
    independent_receipt_len(&mut hasher, proposals.len());
    for packet in proposals {
        independent_receipt_field(&mut hasher, packet.id().as_bytes());
        independent_receipt_len(&mut hasher, packet.event_ids().len());
        for event_id in packet.event_ids() {
            independent_receipt_field(&mut hasher, event_id.as_bytes());
        }
        let cost = packet.composable_token_upper_bound();
        independent_receipt_field(&mut hasher, cost.cost_model().artifact_digest().as_bytes());
        hasher.update(cost.upper_bound_tokens().to_le_bytes());
        independent_receipt_len(&mut hasher, packet.affinities().len());
        for affinity in packet.affinities() {
            independent_receipt_field(&mut hasher, affinity.facet_id().as_bytes());
            hasher.update(affinity.affinity().micros().to_le_bytes());
        }
    }

    let mut mandatory = prepared.mandatory().to_vec();
    mandatory
        .sort_unstable_by_key(|entry| (entry.packet_id(), entry.validated_identifier_facet_id()));
    independent_receipt_len(&mut hasher, mandatory.len());
    for entry in mandatory {
        independent_receipt_field(&mut hasher, entry.packet_id().as_bytes());
        independent_receipt_field(
            &mut hasher,
            entry.validated_identifier_facet_id().as_bytes(),
        );
    }

    match prepared.certification() {
        Some(certification) => {
            hasher.update([1]);
            independent_receipt_field(
                &mut hasher,
                certification.cost_model().artifact_digest().as_bytes(),
            );
            independent_receipt_field(
                &mut hasher,
                certification
                    .tokenizer_bound()
                    .tokenizer_digest()
                    .as_bytes(),
            );
            independent_receipt_field(
                &mut hasher,
                certification.tokenizer_bound().contract_digest().as_bytes(),
            );
            hasher.update(
                certification
                    .fixed_overhead()
                    .upper_bound_tokens()
                    .to_le_bytes(),
            );
            hasher.update(certification.universe_upper_bound().to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

#[test]
fn multiple_validated_ids_in_one_block_force_one_packet_and_retain_every_reason() {
    let source = lines(
        101,
        &[b"error E0425 trace 123e4567-e89b-12d3-a456-426614174000"],
    );
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let tokenizer = Utf8ByteTokenizerV1::new();
    let decision = compile_three_lanes_v1(
        b"diagnose E0425 and 123e4567-e89b-12d3-a456-426614174000",
        &source,
        &blocks,
        result_id(101),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &tokenizer,
    )
    .unwrap();
    let compiled = decision.selected().unwrap();
    let metadata = &compiled.packet_metadata()[0];

    assert_eq!(compiled.selection().packets().len(), 1);
    assert_eq!(compiled.packet_metadata().len(), 1);
    assert_eq!(metadata.mandatory_reasons().len(), 2);
    assert_eq!(
        compiled.selection().packets()[0]
            .forcing_constraint()
            .mandatory_facet_id(),
        metadata.canonical_forcing_facet_id()
    );
    assert!(matches!(
        compiled.selection().packets()[0].forcing_constraint(),
        SelectionConstraintV1::MandatoryValidatedIdentifier { .. }
    ));
    assert_eq!(compiled.certification().packet_bounds().len(), blocks.len());
    assert!(
        compiled
            .facets()
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id())
    );
    assert!(
        compiled
            .facets()
            .iter()
            .any(|facet| { facet.kind() == ProductionFacetKindV1::ValidatedQueryIdentifier })
    );
    compiled
        .certification()
        .verify_selection(&source, result_id(101), compiled.selection(), &tokenizer)
        .unwrap();

    let mandatory_limit = compiled
        .certification()
        .fixed_overhead()
        .upper_bound_tokens()
        .checked_add(
            compiled.certification().packet_bounds()[0]
                .cost()
                .upper_bound_tokens(),
        )
        .unwrap()
        - 1;
    assert_eq!(
        compile_three_lanes_v1(
            b"diagnose E0425 and 123e4567-e89b-12d3-a456-426614174000",
            &source,
            &blocks,
            result_id(101),
            TotalTokenBudgetV1::new(mandatory_limit).unwrap(),
            &tokenizer,
        )
        .unwrap()
        .needs_more(),
        Some(ThreeLaneNeedsMoreV1::MandatoryCostExceedsAvailablePacketBudget)
    );
}

#[test]
fn provider_lane_facets_join_the_same_certified_primary_packet_universe() {
    let attested = ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([110; 32]),
        ProviderAttestedRelationKindV1::TraceIdentity,
        ProviderAttestationValueV1::new(b"provider-attested-shared".to_vec()).unwrap(),
    );
    let attestations = || ProviderAttestationsV1::new([attested.clone()]).unwrap();
    let source = ledger_with_provider_evidence(
        110,
        vec![
            (
                RecordBytes::framed(b"first plain record".to_vec(), b"\n".to_vec()),
                None,
                attestations(),
            ),
            (
                RecordBytes::framed(b"second plain record".to_vec(), b"\n".to_vec()),
                None,
                attestations(),
            ),
        ],
        complete(),
    );
    let blocks = singleton_index(&source, false);
    let decision = compile_three_lanes_v1(
        b"plain record",
        &source,
        &blocks,
        result_id(110),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap();
    let compiled = decision.selected().unwrap();
    let provider_facet = compiled
        .facets()
        .iter()
        .find(|facet| facet.kind() == ProductionFacetKindV1::ProviderAttestedGraphRelation)
        .unwrap();

    assert_eq!(compiled.packet_metadata().len(), blocks.len());
    assert_eq!(compiled.certification().packet_bounds().len(), blocks.len());
    assert!(
        compiled
            .selection()
            .packets()
            .iter()
            .all(|packet| packet.forcing_constraint().mandatory_facet_id().is_none())
    );
    assert!(compiled.selection().packets().iter().any(|packet| {
        packet
            .affinities()
            .iter()
            .any(|affinity| affinity.facet_id() == provider_facet.id())
    }));
}

#[test]
fn assignment_order_and_replay_do_not_change_compilation() {
    let records = [
        b"request timeout".as_slice(),
        b"ERROR downstream".as_slice(),
        b"recovery complete".as_slice(),
    ];
    let first = lines(102, &records);
    let replay = lines(102, &records);
    let first_blocks = singleton_index(&first, false);
    let permuted_blocks = singleton_index(&first, true);
    let replay_blocks = singleton_index(&replay, false);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let compile = |ledger, blocks| {
        compile_three_lanes_v1(
            b"timeout downstream",
            ledger,
            blocks,
            result_id(102),
            TotalTokenBudgetV1::new(1_000_000).unwrap(),
            &tokenizer,
        )
        .unwrap()
    };

    assert_eq!(
        compile(&first, &first_blocks),
        compile(&first, &permuted_blocks)
    );
    assert_eq!(
        compile(&first, &first_blocks),
        compile(&replay, &replay_blocks)
    );
}

#[test]
fn empty_and_no_packet_fit_are_typed_non_successes() {
    let empty = lines(103, &[]);
    let empty_blocks = frame_source_lanes_v1(&empty).unwrap();
    let tokenizer = Utf8ByteTokenizerV1::new();
    assert_eq!(
        compile_three_lanes_v1(
            b"timeout",
            &empty,
            &empty_blocks,
            result_id(103),
            TotalTokenBudgetV1::new(1_000_000).unwrap(),
            &tokenizer,
        )
        .unwrap()
        .needs_more(),
        Some(ThreeLaneNeedsMoreV1::EmptyPrimaryUniverse)
    );

    let source = lines(104, &[b"timeout while reading"]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let fitting = compile_three_lanes_v1(
        b"timeout",
        &source,
        &blocks,
        result_id(104),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &tokenizer,
    )
    .unwrap();
    let fixed = fitting
        .selected()
        .unwrap()
        .certification()
        .fixed_overhead()
        .upper_bound_tokens();
    assert_eq!(
        compile_three_lanes_v1(
            b"timeout",
            &source,
            &blocks,
            result_id(104),
            TotalTokenBudgetV1::new(fixed).unwrap(),
            &tokenizer,
        )
        .unwrap()
        .needs_more(),
        Some(ThreeLaneNeedsMoreV1::NoSelectedPacketFits)
    );
    assert_eq!(
        compile_three_lanes_v1(
            b"timeout",
            &source,
            &blocks,
            result_id(104),
            TotalTokenBudgetV1::new(0).unwrap(),
            &tokenizer,
        )
        .unwrap()
        .needs_more(),
        Some(ThreeLaneNeedsMoreV1::FixedOverheadExceedsTotalBudget)
    );
}

#[test]
fn partial_acquisition_and_arbitrary_bytes_are_preserved_without_upgrade() {
    let partial = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
        None,
    );
    let source = ledger(
        105,
        vec![
            RecordBytes::whole(vec![0, 0xff, b'E', b'R', b'R', b'O', b'R', b'\n']),
            RecordBytes::framed(b"tail\\bytes".to_vec(), b"\r\n".to_vec()),
        ],
        partial.clone(),
    );
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let tokenizer = Utf8ByteTokenizerV1::new();
    let decision = compile_three_lanes_v1(
        &[0xff, 0, b'e', b'r', b'r', b'o', b'r'],
        &source,
        &blocks,
        result_id(105),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &tokenizer,
    )
    .unwrap();
    let compiled = decision.selected().unwrap();

    assert_eq!(source.fetch_completion().completeness(), &partial);
    assert_eq!(compiled.certification().packet_bounds().len(), blocks.len());
    assert_eq!(
        compiled
            .packet_metadata()
            .iter()
            .map(|packet| packet.ordered_event_ids().len())
            .sum::<usize>(),
        source.len()
    );
}

#[test]
fn retrieval_and_primary_block_lane_mismatches_fail_closed() {
    let first = lines(
        106,
        &[
            b"Traceback (most recent call last):",
            b"  File \"app.py\", line 1",
            b"ValueError: failure",
        ],
    );
    let second = lines(107, &[b"other retrieval"]);
    let first_blocks = frame_source_lanes_v1(&first).unwrap();
    let second_blocks = frame_source_lanes_v1(&second).unwrap();
    let first_coverage = match generate_failure_coverage_candidates_v1(&first_blocks).unwrap() {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let first_provider = match generate_provider_correlations_v1(&first_blocks).unwrap() {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(_) => panic!("fixture must be ready"),
    };
    let foreign_lexical = ready_lexical(b"failure", &second_blocks);
    let tokenizer = Utf8ByteTokenizerV1::new();

    assert_eq!(
        compile_ready_three_lanes_v1(
            &first,
            &first_blocks,
            result_id(106),
            TotalTokenBudgetV1::new(1_000_000).unwrap(),
            &tokenizer,
            ReadyCandidateLanesV1::new(&foreign_lexical, &first_coverage, &first_provider,),
        ),
        Err(ThreeLaneCompileErrorV1::LaneUniverse {
            lane: CandidateLaneV1::Lexical,
            violation: LaneUniverseViolationV1::RetrievalMismatch,
        })
    );

    let singleton_blocks = singleton_index(&first, false);
    let mismatched_lexical = ready_lexical(b"failure", &singleton_blocks);
    assert_eq!(
        compile_ready_three_lanes_v1(
            &first,
            &first_blocks,
            result_id(106),
            TotalTokenBudgetV1::new(1_000_000).unwrap(),
            &tokenizer,
            ReadyCandidateLanesV1::new(&mismatched_lexical, &first_coverage, &first_provider,),
        ),
        Err(ThreeLaneCompileErrorV1::LaneUniverse {
            lane: CandidateLaneV1::Lexical,
            violation: LaneUniverseViolationV1::UnknownBlock,
        })
    );
}

#[test]
fn candidate_caps_translate_to_typed_non_success_without_partial_compilation() {
    let source = lines(108, &[b"one event"]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let oversized_question = vec![b'q'; MAX_QUESTION_BYTES_V1 + 1];
    let decision = compile_three_lanes_v1(
        &oversized_question,
        &source,
        &blocks,
        result_id(108),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap();

    assert_eq!(
        decision.needs_more(),
        Some(ThreeLaneNeedsMoreV1::CandidateLane {
            lane: CandidateLaneV1::Lexical,
            reason: CandidateNeedsMoreReasonV1::QuestionBytesCap,
        })
    );
}

#[test]
fn zero_affinity_blocks_remain_exhaustive_metadata_but_are_not_certified_proposals() {
    const BLOCK_COUNT: usize = 257;
    let source = ledger(
        110,
        (0..BLOCK_COUNT)
            .map(|position| {
                let mut bytes = vec![b'Z'; 1_024];
                bytes.extend_from_slice(format!(" ordinary {position:04}").as_bytes());
                RecordBytes::framed(bytes, b"\n".to_vec())
            })
            .collect(),
        complete(),
    );
    let blocks = singleton_index(&source, false);
    let lexical = ready_lexical(&[], &blocks);
    let coverage = match generate_failure_coverage_candidates_v1(&blocks).unwrap() {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(_) => panic!("coverage fixture must be ready"),
    };
    let provider = match generate_provider_correlations_v1(&blocks).unwrap() {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(_) => {
            panic!("provider fixture must be ready")
        }
    };
    let zero_affinity_packet_ids = blocks
        .blocks()
        .iter()
        .filter(|block| {
            lexical
                .primary_blocks()
                .iter()
                .find(|candidate| candidate.block_id() == block.id())
                .unwrap()
                .affinities()
                .is_empty()
                && coverage
                    .annotations()
                    .iter()
                    .find(|annotation| annotation.block_id() == block.id())
                    .unwrap()
                    .affinities()
                    .is_empty()
                && provider
                    .annotations()
                    .iter()
                    .find(|annotation| annotation.block_id() == block.id())
                    .unwrap()
                    .affinities()
                    .is_empty()
        })
        .map(|block| PacketIdV1::from_bytes(*block.id().as_bytes()))
        .collect::<BTreeSet<_>>();
    assert!(!zero_affinity_packet_ids.is_empty());

    let tokenizer = Utf8ByteTokenizerV1::new();
    let decision = compile_ready_three_lanes_v1(
        &source,
        &blocks,
        result_id(110),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &tokenizer,
        ReadyCandidateLanesV1::new(&lexical, &coverage, &provider),
    )
    .unwrap();
    let compiled = decision.selected().expect("bounded proposals must fit");
    let proposals = compiled
        .proposal_packet_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let certified = compiled
        .certification()
        .packet_bounds()
        .iter()
        .map(|bound| bound.packet_id())
        .collect::<BTreeSet<_>>();
    let metadata = compiled
        .packet_metadata()
        .iter()
        .map(|metadata| metadata.packet_id())
        .collect::<BTreeSet<_>>();

    assert!(proposals.is_disjoint(&zero_affinity_packet_ids));
    assert!(zero_affinity_packet_ids.is_disjoint(&certified));
    assert!(zero_affinity_packet_ids.is_subset(&metadata));
    assert_eq!(certified, proposals);
    assert_eq!(metadata.len(), BLOCK_COUNT);
    assert!(proposals.len() < BLOCK_COUNT);
    let accounting = compiled.proposal_receipt().accounting();
    assert_eq!(
        accounting.exhaustive_primary_block_count(),
        u64::try_from(BLOCK_COUNT).unwrap()
    );
    assert_eq!(
        accounting.proposal_packet_count(),
        u64::try_from(proposals.len()).unwrap()
    );
    assert_eq!(
        accounting.retained_raw_nonproposal_block_count(),
        u64::try_from(zero_affinity_packet_ids.len()).unwrap()
    );
    assert!(compiled.selection().packets().iter().all(|selected| {
        proposals.contains(&selected.packet().id())
            && !zero_affinity_packet_ids.contains(&selected.packet().id())
    }));
    compiled
        .certification()
        .verify_selection(&source, result_id(110), compiled.selection(), &tokenizer)
        .unwrap();
}

#[test]
fn preparation_receipt_is_budget_independent_and_selection_edges_are_exact() {
    let source = lines(111, &[b"timeout while reading one packet"]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let tokenizer = Utf8ByteTokenizerV1::new();
    let prepared = expect_prepared(
        prepare_three_lane_proposal_universe_v1(
            b"timeout",
            &source,
            &blocks,
            result_id(111),
            &tokenizer,
        )
        .unwrap(),
    );
    let receipt = prepared.receipt();
    let accounting = receipt.accounting();
    assert_eq!(accounting.exhaustive_primary_block_count(), 1);
    assert_eq!(accounting.exhaustive_member_event_count(), 1);
    assert_eq!(accounting.proposal_packet_count(), 1);
    assert_eq!(accounting.proposal_unique_member_event_count(), 1);
    assert_eq!(accounting.retained_raw_nonproposal_block_count(), 0);
    assert_eq!(accounting.retained_raw_nonproposal_member_event_count(), 0);
    assert_eq!(
        accounting.exhaustive_member_source_bytes(),
        u64::try_from(source.events()[0].raw().len()).unwrap()
    );
    assert_eq!(
        accounting.proposal_member_source_bytes(),
        accounting.exhaustive_member_source_bytes()
    );

    let proposal = &prepared.proposal_packets()[0];
    let proposal_id = proposal.id();
    let proposal_event_ids = proposal.event_ids().to_vec();
    let metadata = prepared.proposal_metadata(proposal_id).unwrap();
    let metadata_event_ids = metadata.ordered_event_ids().to_vec();
    assert_eq!(metadata.packet_id(), proposal_id);
    assert_eq!(
        metadata
            .ordered_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        proposal_event_ids.iter().copied().collect::<BTreeSet<_>>()
    );
    let certification = prepared.certification().unwrap();
    let exact_budget = certification.universe_upper_bound();
    let exact = select_prepared_three_lane_proposals_v1(
        &source,
        prepared.clone(),
        TotalTokenBudgetV1::new(exact_budget).unwrap(),
        &tokenizer,
    )
    .unwrap();
    let selected = match exact {
        PreparedThreeLaneSelectionDecisionV1::Selected(selected) => selected,
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            panic!(
                "exact certified edge must fit: {}",
                needs_more.reason().code()
            )
        }
    };
    assert_eq!(selected.proposal_receipt(), receipt);
    assert_eq!(
        selected
            .proposal_metadata(proposal_id)
            .unwrap()
            .ordered_event_ids(),
        metadata_event_ids
    );

    let one_below = select_prepared_three_lane_proposals_v1(
        &source,
        prepared,
        TotalTokenBudgetV1::new(exact_budget - 1).unwrap(),
        &tokenizer,
    )
    .unwrap();
    let needs_more = match one_below {
        PreparedThreeLaneSelectionDecisionV1::Selected(_) => {
            panic!("one below the only packet's certified edge cannot fit")
        }
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => needs_more,
    };
    assert_eq!(
        needs_more.reason(),
        ThreeLaneNeedsMoreV1::NoSelectedPacketFits
    );
    assert_eq!(needs_more.receipt(), receipt);
    assert_eq!(
        needs_more
            .prepared()
            .proposal_metadata(proposal_id)
            .unwrap()
            .ordered_event_ids(),
        metadata_event_ids
    );
}

#[test]
fn proposal_receipt_is_deterministic_and_binds_inputs_and_canonical_universe() {
    let records = [
        b"Traceback (most recent call last):".as_slice(),
        b"  File \"app.py\", line 9".as_slice(),
        b"ValueError: timeout".as_slice(),
    ];
    let source = lines(112, &records);
    let replay = lines(112, &records);
    let blocks = singleton_index(&source, false);
    let permuted = singleton_index(&source, true);
    let replay_blocks = singleton_index(&replay, false);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let prepare = |question: &[u8], ledger: &EventLedger, blocks: &BlockIndex<'_>, result| {
        expect_prepared(
            prepare_three_lane_proposal_universe_v1(question, ledger, blocks, result, &tokenizer)
                .unwrap(),
        )
    };
    let first = prepare(b"timeout", &source, &blocks, result_id(112));
    let reordered = prepare(b"timeout", &source, &permuted, result_id(112));
    let replayed = prepare(b"timeout", &replay, &replay_blocks, result_id(112));

    assert_eq!(first.receipt(), reordered.receipt());
    assert_eq!(first.receipt(), replayed.receipt());
    assert_eq!(first.packet_metadata(), reordered.packet_metadata());
    assert_eq!(first.proposal_packets(), reordered.proposal_packets());
    assert_ne!(
        first.receipt().digest(),
        prepare(b"different question", &source, &blocks, result_id(112))
            .receipt()
            .digest()
    );
    assert_ne!(
        first.receipt().digest(),
        prepare(b"timeout", &source, &blocks, result_id(113))
            .receipt()
            .digest()
    );
    let foreign = lines(113, &records);
    let foreign_blocks = singleton_index(&foreign, false);
    assert_ne!(
        first.receipt().digest(),
        prepare(b"timeout", &foreign, &foreign_blocks, result_id(112))
            .receipt()
            .digest()
    );
    let changed_plan = ledger_with_provider_evidence_and_plan(
        112,
        41,
        42,
        records
            .iter()
            .map(|record| {
                (
                    RecordBytes::framed(record.to_vec(), b"\n".to_vec()),
                    None,
                    ProviderAttestationsV1::default(),
                )
            })
            .collect(),
        complete(),
    );
    let changed_plan_blocks = singleton_index(&changed_plan, false);
    assert_ne!(
        first.receipt().digest(),
        prepare(
            b"timeout",
            &changed_plan,
            &changed_plan_blocks,
            result_id(112),
        )
        .receipt()
        .digest()
    );
}

#[test]
fn empty_zero_proposal_input_is_typed_without_dummy_authority() {
    let source = lines(114, &[]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let decision = prepare_three_lane_proposal_universe_v1(
        b"timeout",
        &source,
        &blocks,
        result_id(114),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap();
    let needs_more = decision.needs_more().unwrap();

    assert_eq!(
        needs_more.reason(),
        ThreeLaneNeedsMoreV1::EmptyPrimaryUniverse
    );
    assert_eq!(needs_more.input().retrieval_id(), source.retrieval_id());
    assert_eq!(
        needs_more.input().acquisition_receipt_id(),
        source.acquisition_receipt_id()
    );
    assert!(decision.prepared().is_none());
}

#[test]
fn proposal_receipt_integer_encoding_has_a_frozen_golden_digest() {
    assert_eq!(
        evidentrail_compile::proposal_candidate_config_digest_v1().as_bytes(),
        &[
            0x0f, 0x13, 0x7c, 0xb7, 0x19, 0xa4, 0x7c, 0xee, 0x65, 0x57, 0x52, 0x16, 0x07, 0x53,
            0xdc, 0xdb, 0x27, 0x9c, 0xf1, 0x37, 0x65, 0x31, 0xb6, 0x30, 0x8a, 0x3d, 0xaf, 0x25,
            0x9a, 0xc0, 0x85, 0x96,
        ]
    );
    assert_eq!(
        evidentrail_compile::proposal_compiler_config_digest_v1().as_bytes(),
        &[
            0xab, 0xe6, 0x19, 0x78, 0xcc, 0x5f, 0x4e, 0xdc, 0x4f, 0x5c, 0x41, 0x6e, 0x0f, 0xfc,
            0x32, 0xdb, 0xcb, 0xa4, 0x70, 0x5e, 0xe2, 0x11, 0x94, 0x1e, 0xc5, 0xe2, 0xb5, 0xed,
            0x4e, 0xef, 0xb0, 0x47,
        ]
    );
    let source = lines(115, &[b"ERROR golden receipt"]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let prepared = expect_prepared(
        prepare_three_lane_proposal_universe_v1(
            b"golden",
            &source,
            &blocks,
            result_id(115),
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap(),
    );

    let independently_recomputed = independently_recompute_proposal_receipt(&prepared, &source);
    assert_eq!(
        prepared.receipt().digest().as_bytes(),
        &independently_recomputed
    );
    assert_eq!(
        independently_recomputed,
        [
            125, 142, 248, 228, 245, 78, 135, 214, 168, 73, 104, 209, 92, 147, 183, 206, 131, 233,
            110, 249, 78, 203, 74, 167, 220, 138, 8, 248, 145, 34, 112, 221,
        ]
    );
}

#[test]
fn diagnostics_never_expose_question_payload_result_or_membership_canaries() {
    const CANARY: &str = "SECRET_COMPILE_QUESTION_PAYLOAD_RESULT_MEMBER";
    let source = lines(109, &[CANARY.as_bytes()]);
    let blocks = frame_source_lanes_v1(&source).unwrap();
    let decision = compile_three_lanes_v1(
        CANARY.as_bytes(),
        &source,
        &blocks,
        ResultId::from_bytes(*b"SECRET_RESULT_ID_SECRET_RESULT_I"),
        TotalTokenBudgetV1::new(1_000_000).unwrap(),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap();
    let rendered = format!(
        "{decision:?} {:?}",
        ThreeLaneCompileErrorV1::LexicalMembershipMismatch
    );

    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("SECRET_RESULT"));
}
