use std::collections::{BTreeMap, BTreeSet};

use evidentrail_candidates::{
    CandidateGenerationDecisionV1, CoverageBlockAnnotationV1, CoverageGenerationDecisionV1,
    LexicalCandidateUniverseV1, MandatoryIdentifierReasonV1, PrimaryBlockCandidateV1,
    ProviderBlockAnnotationV1, ProviderCorrelationGenerationDecisionV1,
    generate_failure_coverage_candidates_v1, generate_lexical_candidates_v1,
    generate_provider_correlations_v1,
};
use evidentrail_core::{
    BlockId, BlockIndex, EventId, EventLedger, ResultId, derive_question_digest_v1,
};
use evidentrail_evidence::{
    CompiledPacketMembershipV1, Utf8ByteTokenizerV1, certify_compiled_costs_v1,
};
use evidentrail_select::{
    AffinityV1, FacetAffinityV1, FacetIdV1, IntactPacketV1, MandatoryPacketV1, NeedsMoreReasonV1,
    PacketConstructionError, PacketIdV1, ProductionFacetKindV1, ProductionFacetV1,
    SelectionDecisionV1, SelectionProblemV1, TotalTokenBudgetV1,
};

use crate::proposal::{
    PreparedThreeLaneNeedsMoreV1, PreparedThreeLaneProposalUniverseV1,
    PreparedThreeLaneSelectionDecisionV1, ProposalPreparationInputReceiptV1,
    ProposalUniverseAccountingErrorV1, ProposalUniverseAccountingPartsV1,
    ProposalUniverseAccountingV1, ProposalUniverseReceiptV1,
    ThreeLaneProposalPreparationDecisionV1, ThreeLaneProposalPreparationNeedsMoreV1,
};
use crate::types::{
    CandidateLaneV1, CertifiedThreeLaneSelectionV1, CompiledPacketMetadataV1,
    LaneUniverseViolationV1, ReadyCandidateLanesV1, ThreeLaneCompileDecisionV1,
    ThreeLaneCompileErrorV1, ThreeLaneNeedsMoreV1,
};
#[cfg(feature = "benchmark-instrumentation")]
use crate::{
    PreparedThreeLaneAblationSetV1, PreparedThreeLaneAblationV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1,
};

struct ExpectedBlock {
    packet_id: PacketIdV1,
    ordered_event_ids: Vec<EventId>,
}

struct PendingProposal {
    packet_id: PacketIdV1,
    ordered_event_ids: Vec<EventId>,
    affinities: Vec<FacetAffinityV1>,
}

struct ValidatedReadyCandidateLanesV1<'a> {
    lanes: ReadyCandidateLanesV1<'a>,
    expected: BTreeMap<BlockId, ExpectedBlock>,
    lexical_blocks: BTreeMap<BlockId, &'a PrimaryBlockCandidateV1>,
    coverage_annotations: BTreeMap<BlockId, &'a CoverageBlockAnnotationV1>,
    provider_annotations: BTreeMap<BlockId, &'a ProviderBlockAnnotationV1>,
    lexical_facet_ids: BTreeSet<FacetIdV1>,
    coverage_facet_ids: BTreeSet<FacetIdV1>,
    provider_facet_ids: BTreeSet<FacetIdV1>,
}

#[derive(Clone, Copy)]
struct LaneInclusionV1 {
    lexical: bool,
    coverage: bool,
    provider: bool,
}

impl LaneInclusionV1 {
    const FULL: Self = Self {
        lexical: true,
        coverage: true,
        provider: true,
    };

    #[cfg(feature = "benchmark-instrumentation")]
    const fn from_ablation(mask: ThreeLaneAblationMaskV1) -> Self {
        Self {
            lexical: mask.includes(CandidateLaneV1::Lexical),
            coverage: mask.includes(CandidateLaneV1::Coverage),
            provider: mask.includes(CandidateLaneV1::Provider),
        }
    }
}

/// Run all three deterministic candidate lanes and compile their ready outputs
/// into one certified selection universe.
pub fn compile_three_lanes_v1(
    question: &[u8],
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<ThreeLaneCompileDecisionV1, ThreeLaneCompileErrorV1> {
    let preparation =
        prepare_three_lane_proposal_universe_v1(question, ledger, blocks, result_id, tokenizer)?;
    compile_prepared_compatibility_v1(ledger, total_token_budget, tokenizer, preparation)
}

/// Generate and freeze the complete three-lane proposal universe without
/// consulting a final output budget.
pub fn prepare_three_lane_proposal_universe_v1(
    question: &[u8],
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<ThreeLaneProposalPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let input = ProposalPreparationInputReceiptV1::new(
        result_id,
        derive_question_digest_v1(question),
        ledger,
        tokenizer,
    );
    let lexical = generate_lexical_candidates_v1(question, blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Lexical,
            source,
        }
    })?;
    let lexical = match lexical {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneProposalPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Lexical,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };

    let coverage = generate_failure_coverage_candidates_v1(blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Coverage,
            source,
        }
    })?;
    let coverage = match coverage {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneProposalPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Coverage,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };

    let provider = generate_provider_correlations_v1(blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Provider,
            source,
        }
    })?;
    let provider = match provider {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneProposalPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Provider,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };

    prepare_ready_three_lane_proposal_universe_with_input_v1(
        ledger,
        blocks,
        result_id,
        tokenizer,
        ReadyCandidateLanesV1::new(&lexical, &coverage, &provider),
        input,
    )
}

/// Opt-in, label-free benchmark instrumentation that generates every active
/// lane exactly once and freezes Full plus each leave-one-lane-out universe.
///
/// This API accepts no annotation, requirement, resource cap, or measurement.
/// The default production feature set does not expose it.
#[cfg(feature = "benchmark-instrumentation")]
pub fn prepare_three_lane_ablations_v1(
    question: &[u8],
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<ThreeLaneAblationPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let input = ProposalPreparationInputReceiptV1::new(
        result_id,
        derive_question_digest_v1(question),
        ledger,
        tokenizer,
    );
    let lexical = generate_lexical_candidates_v1(question, blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Lexical,
            source,
        }
    })?;
    let lexical = match lexical {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneAblationPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Lexical,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };
    let coverage = generate_failure_coverage_candidates_v1(blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Coverage,
            source,
        }
    })?;
    let coverage = match coverage {
        CoverageGenerationDecisionV1::Ready(universe) => universe,
        CoverageGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneAblationPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Coverage,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };
    let provider = generate_provider_correlations_v1(blocks).map_err(|source| {
        ThreeLaneCompileErrorV1::CandidateBuild {
            lane: CandidateLaneV1::Provider,
            source,
        }
    })?;
    let provider = match provider {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(reason) => {
            return Ok(ThreeLaneAblationPreparationDecisionV1::NeedsMore(Box::new(
                ThreeLaneProposalPreparationNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::CandidateLane {
                        lane: CandidateLaneV1::Provider,
                        reason: reason.reason(),
                    },
                    input,
                ),
            )));
        }
    };
    prepare_ready_three_lane_ablations_with_input_v1(
        ledger,
        blocks,
        result_id,
        tokenizer,
        ReadyCandidateLanesV1::new(&lexical, &coverage, &provider),
        input,
    )
}

/// Opt-in benchmark preparation from one already-generated set of typed lane
/// outputs. All three lanes are validated once before any mask is reconciled.
#[cfg(feature = "benchmark-instrumentation")]
pub fn prepare_ready_three_lane_ablations_v1(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
    lanes: ReadyCandidateLanesV1<'_>,
) -> Result<ThreeLaneAblationPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let input = ProposalPreparationInputReceiptV1::new(
        result_id,
        lanes.lexical().question_digest(),
        ledger,
        tokenizer,
    );
    prepare_ready_three_lane_ablations_with_input_v1(
        ledger, blocks, result_id, tokenizer, lanes, input,
    )
}

#[cfg(feature = "benchmark-instrumentation")]
fn prepare_ready_three_lane_ablations_with_input_v1(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
    lanes: ReadyCandidateLanesV1<'_>,
    full_input: ProposalPreparationInputReceiptV1,
) -> Result<ThreeLaneAblationPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let expected = expected_primary_blocks(ledger, blocks)?;
    if expected.is_empty() {
        return Ok(ThreeLaneAblationPreparationDecisionV1::NeedsMore(Box::new(
            ThreeLaneProposalPreparationNeedsMoreV1::new(
                ThreeLaneNeedsMoreV1::EmptyPrimaryUniverse,
                full_input,
            ),
        )));
    }
    let validated = validate_ready_candidate_lanes_v1(blocks, expected, lanes)?;
    let prepare = |mask| {
        let input = if mask == ThreeLaneAblationMaskV1::Full {
            full_input
        } else {
            ProposalPreparationInputReceiptV1::new_with_candidate_config_digest(
                result_id,
                full_input.question_digest(),
                ledger,
                tokenizer,
                crate::ablation::masked_candidate_config_digest_v1(mask),
            )
        };
        reconcile_validated_ready_candidate_lanes_v1(
            ledger,
            result_id,
            tokenizer,
            &validated,
            input,
            LaneInclusionV1::from_ablation(mask),
        )
        .map(|prepared| PreparedThreeLaneAblationV1::new(mask, prepared))
    };
    let configurations = [
        prepare(ThreeLaneAblationMaskV1::Full)?,
        prepare(ThreeLaneAblationMaskV1::WithoutLexical)?,
        prepare(ThreeLaneAblationMaskV1::WithoutCoverage)?,
        prepare(ThreeLaneAblationMaskV1::WithoutProvider)?,
    ];
    Ok(ThreeLaneAblationPreparationDecisionV1::Prepared(Box::new(
        PreparedThreeLaneAblationSetV1::new(configurations),
    )))
}

/// Reconcile already-ready lane outputs, certify renderer costs, and invoke
/// the deterministic intact-packet selector.
pub fn compile_ready_three_lanes_v1(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
    lanes: ReadyCandidateLanesV1<'_>,
) -> Result<ThreeLaneCompileDecisionV1, ThreeLaneCompileErrorV1> {
    let preparation =
        prepare_ready_three_lane_proposal_universe_v1(ledger, blocks, result_id, tokenizer, lanes)?;
    compile_prepared_compatibility_v1(ledger, total_token_budget, tokenizer, preparation)
}

/// Validate already-ready lane outputs and freeze the exact proposal universe
/// without consulting a final output budget.
pub fn prepare_ready_three_lane_proposal_universe_v1(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
    lanes: ReadyCandidateLanesV1<'_>,
) -> Result<ThreeLaneProposalPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let input = ProposalPreparationInputReceiptV1::new(
        result_id,
        lanes.lexical().question_digest(),
        ledger,
        tokenizer,
    );
    prepare_ready_three_lane_proposal_universe_with_input_v1(
        ledger, blocks, result_id, tokenizer, lanes, input,
    )
}

fn prepare_ready_three_lane_proposal_universe_with_input_v1(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
    lanes: ReadyCandidateLanesV1<'_>,
    input: ProposalPreparationInputReceiptV1,
) -> Result<ThreeLaneProposalPreparationDecisionV1, ThreeLaneCompileErrorV1> {
    let expected = expected_primary_blocks(ledger, blocks)?;
    if expected.is_empty() {
        return Ok(ThreeLaneProposalPreparationDecisionV1::NeedsMore(Box::new(
            ThreeLaneProposalPreparationNeedsMoreV1::new(
                ThreeLaneNeedsMoreV1::EmptyPrimaryUniverse,
                input,
            ),
        )));
    }

    let validated = validate_ready_candidate_lanes_v1(blocks, expected, lanes)?;
    let prepared = reconcile_validated_ready_candidate_lanes_v1(
        ledger,
        result_id,
        tokenizer,
        &validated,
        input,
        LaneInclusionV1::FULL,
    )?;
    Ok(ThreeLaneProposalPreparationDecisionV1::Prepared(Box::new(
        prepared,
    )))
}

fn validate_ready_candidate_lanes_v1<'a>(
    blocks: &BlockIndex<'_>,
    expected: BTreeMap<BlockId, ExpectedBlock>,
    lanes: ReadyCandidateLanesV1<'a>,
) -> Result<ValidatedReadyCandidateLanesV1<'a>, ThreeLaneCompileErrorV1> {
    validate_lane_retrievals(blocks, lanes)?;
    let lexical_blocks = validate_lexical_blocks(&expected, lanes.lexical())?;
    let coverage_annotations = validate_lane_block_map(
        CandidateLaneV1::Coverage,
        &expected,
        lanes
            .coverage()
            .annotations()
            .iter()
            .map(|annotation| (annotation.block_id(), annotation)),
    )?;
    let provider_annotations = validate_lane_block_map(
        CandidateLaneV1::Provider,
        &expected,
        lanes
            .provider()
            .annotations()
            .iter()
            .map(|annotation| (annotation.block_id(), annotation)),
    )?;

    let lexical_facet_ids = lanes
        .lexical()
        .facets()
        .iter()
        .map(|facet| facet.facet().id())
        .collect::<BTreeSet<_>>();
    let coverage_facet_ids = lanes
        .coverage()
        .facets()
        .iter()
        .map(|facet| facet.facet().id())
        .collect::<BTreeSet<_>>();
    let provider_facet_ids = lanes
        .provider()
        .facets()
        .iter()
        .map(|facet| facet.facet().id())
        .collect::<BTreeSet<_>>();
    Ok(ValidatedReadyCandidateLanesV1 {
        lanes,
        expected,
        lexical_blocks,
        coverage_annotations,
        provider_annotations,
        lexical_facet_ids,
        coverage_facet_ids,
        provider_facet_ids,
    })
}

fn reconcile_validated_ready_candidate_lanes_v1(
    ledger: &EventLedger,
    result_id: ResultId,
    tokenizer: &Utf8ByteTokenizerV1,
    validated: &ValidatedReadyCandidateLanesV1<'_>,
    input: ProposalPreparationInputReceiptV1,
    inclusion: LaneInclusionV1,
) -> Result<PreparedThreeLaneProposalUniverseV1, ThreeLaneCompileErrorV1> {
    let facets = merge_facets(validated.lanes, inclusion)?;
    let mut affinities = validated
        .expected
        .keys()
        .copied()
        .map(|block_id| (block_id, BTreeMap::<FacetIdV1, AffinityV1>::new()))
        .collect::<BTreeMap<_, _>>();
    if inclusion.lexical {
        for (block_id, candidate) in &validated.lexical_blocks {
            merge_affinities(
                CandidateLaneV1::Lexical,
                *block_id,
                candidate.affinities(),
                &validated.lexical_facet_ids,
                &mut affinities,
            )?;
        }
    }
    if inclusion.coverage {
        for (block_id, annotation) in &validated.coverage_annotations {
            merge_affinities(
                CandidateLaneV1::Coverage,
                *block_id,
                annotation.affinities(),
                &validated.coverage_facet_ids,
                &mut affinities,
            )?;
        }
    }
    if inclusion.provider {
        for (block_id, annotation) in &validated.provider_annotations {
            merge_affinities(
                CandidateLaneV1::Provider,
                *block_id,
                annotation.affinities(),
                &validated.provider_facet_ids,
                &mut affinities,
            )?;
        }
    }

    let mut pending_proposals = Vec::with_capacity(validated.expected.len());
    let mut mandatory = Vec::new();
    let mut packet_metadata = Vec::with_capacity(validated.expected.len());
    for (block_id, expected_block) in &validated.expected {
        let block_affinities = affinities
            .remove(block_id)
            .ok_or(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch)?;
        let merged_affinities = block_affinities
            .iter()
            .map(|(facet_id, affinity)| FacetAffinityV1::new(*facet_id, *affinity))
            .collect::<Vec<_>>();
        let mandatory_reasons = if inclusion.lexical {
            let lexical = validated.lexical_blocks.get(block_id).copied().ok_or(
                ThreeLaneCompileErrorV1::LaneUniverse {
                    lane: CandidateLaneV1::Lexical,
                    violation: LaneUniverseViolationV1::MissingBlock,
                },
            )?;
            canonical_mandatory_reasons(
                lexical.mandatory_reasons(),
                &facets,
                &validated.lexical_facet_ids,
                &block_affinities,
            )?
        } else {
            Vec::new()
        };
        if let Some(forcing) = mandatory_reasons.first() {
            if merged_affinities.is_empty() {
                return Err(ThreeLaneCompileErrorV1::PacketConstruction(
                    PacketConstructionError::EmptyAffinitySet,
                ));
            }
            mandatory.push(MandatoryPacketV1::validated_identifier(
                expected_block.packet_id,
                forcing.facet_id(),
            ));
        }
        // Metadata remains exhaustive. Only blocks granted explicit positive
        // affinity enter the proposal and cost-certificate universe.
        if !merged_affinities.is_empty() {
            pending_proposals.push(PendingProposal {
                packet_id: expected_block.packet_id,
                ordered_event_ids: expected_block.ordered_event_ids.clone(),
                affinities: merged_affinities,
            });
        }
        packet_metadata.push(CompiledPacketMetadataV1::new(
            *block_id,
            expected_block.packet_id,
            expected_block.ordered_event_ids.clone(),
            mandatory_reasons,
        ));
    }

    let canonical_facets = facets.into_values().collect::<Vec<_>>();
    let certification = if pending_proposals.is_empty() {
        None
    } else {
        let memberships = pending_proposals
            .iter()
            .map(|proposal| {
                CompiledPacketMembershipV1::new(
                    proposal.packet_id,
                    proposal.ordered_event_ids.iter().copied(),
                )
                .map_err(ThreeLaneCompileErrorV1::CostCertification)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Some(
            certify_compiled_costs_v1(ledger, result_id, memberships, tokenizer)
                .map_err(ThreeLaneCompileErrorV1::CostCertification)?,
        )
    };
    let mut packets = Vec::with_capacity(pending_proposals.len());
    for proposal in pending_proposals {
        let mut certified_event_ids = proposal.ordered_event_ids.clone();
        certified_event_ids.sort_unstable();
        let cost = certification
            .as_ref()
            .ok_or(ThreeLaneCompileErrorV1::PreparedBindingMismatch)?
            .packet_cost(proposal.packet_id, &certified_event_ids)
            .map_err(ThreeLaneCompileErrorV1::CostCertification)?;
        packets.push(
            IntactPacketV1::new(
                proposal.packet_id,
                proposal.ordered_event_ids,
                cost,
                proposal.affinities,
            )
            .map_err(ThreeLaneCompileErrorV1::PacketConstruction)?,
        );
    }
    let accounting = proposal_accounting(
        ledger,
        &packet_metadata,
        &packets,
        &mandatory,
        &canonical_facets,
    )?;
    let receipt = ProposalUniverseReceiptV1::new(
        input,
        accounting,
        &canonical_facets,
        &packet_metadata,
        &packets,
        &mandatory,
        certification.as_ref(),
    );
    Ok(PreparedThreeLaneProposalUniverseV1::new(
        receipt,
        canonical_facets,
        packet_metadata,
        packets,
        mandatory,
        certification,
    ))
}

/// Select from an already-frozen proposal universe under one final budget.
/// A budget non-success returns the owned preparation unchanged for retry.
pub fn select_prepared_three_lane_proposals_v1(
    ledger: &EventLedger,
    prepared: PreparedThreeLaneProposalUniverseV1,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<PreparedThreeLaneSelectionDecisionV1, ThreeLaneCompileErrorV1> {
    if !prepared.receipt().input().matches(ledger, tokenizer) {
        return Err(ThreeLaneCompileErrorV1::PreparedBindingMismatch);
    }
    select_bound_prepared_three_lane_proposals_v1(ledger, prepared, total_token_budget, tokenizer)
}

/// Benchmark-only selection of one mask-specific prepared ablation.
///
/// This validates the exact masked candidate-configuration receipt and then
/// delegates to the same selector and cost-certificate path as the production
/// Full configuration. It is available only through the explicit benchmark
/// instrumentation feature and does not alter the ordinary product path.
#[cfg(feature = "benchmark-instrumentation")]
pub fn select_prepared_three_lane_ablation_v1(
    ledger: &EventLedger,
    configured: &PreparedThreeLaneAblationV1,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<PreparedThreeLaneSelectionDecisionV1, ThreeLaneCompileErrorV1> {
    let prepared = configured.prepared().clone();
    if !prepared.receipt().input().matches_candidate_config(
        ledger,
        tokenizer,
        crate::ablation::masked_candidate_config_digest_v1(configured.mask()),
    ) {
        return Err(ThreeLaneCompileErrorV1::PreparedBindingMismatch);
    }
    select_bound_prepared_three_lane_proposals_v1(ledger, prepared, total_token_budget, tokenizer)
}

/// Benchmark-only reconstruction of the exact production selection problem
/// for one already-validated ablation configuration.
///
/// This is deliberately available only behind `benchmark-instrumentation`.
/// It shares the production constructor below, performs the same receipt and
/// candidate-configuration binding check as benchmark selection, and exposes
/// no product/runtime entry point. An empty proposal universe remains a
/// compiler-level `NoProposalPackets` decision and therefore has no selection
/// problem to evaluate.
#[cfg(feature = "benchmark-instrumentation")]
pub fn benchmark_selection_problem_for_prepared_three_lane_ablation_v1(
    ledger: &EventLedger,
    configured: &PreparedThreeLaneAblationV1,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<SelectionProblemV1, ThreeLaneCompileErrorV1> {
    if !configured
        .prepared()
        .receipt()
        .input()
        .matches_candidate_config(
            ledger,
            tokenizer,
            crate::ablation::masked_candidate_config_digest_v1(configured.mask()),
        )
    {
        return Err(ThreeLaneCompileErrorV1::PreparedBindingMismatch);
    }
    build_bound_selection_problem_v1(configured.prepared(), total_token_budget)
}

fn select_bound_prepared_three_lane_proposals_v1(
    ledger: &EventLedger,
    prepared: PreparedThreeLaneProposalUniverseV1,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<PreparedThreeLaneSelectionDecisionV1, ThreeLaneCompileErrorV1> {
    if prepared.proposal_packets().is_empty() {
        return Ok(PreparedThreeLaneSelectionDecisionV1::NeedsMore(Box::new(
            PreparedThreeLaneNeedsMoreV1::new(ThreeLaneNeedsMoreV1::NoProposalPackets, prepared),
        )));
    }
    let certification = prepared
        .certification()
        .ok_or(ThreeLaneCompileErrorV1::PreparedBindingMismatch)?;
    let mut proposal_packet_ids = prepared
        .proposal_packets()
        .iter()
        .map(IntactPacketV1::id)
        .collect::<Vec<_>>();
    proposal_packet_ids.sort_unstable();
    let problem = build_bound_selection_problem_v1(&prepared, total_token_budget)?;
    let selection = problem
        .select()
        .map_err(ThreeLaneCompileErrorV1::SelectionInvariant)?;
    let selection = match selection {
        SelectionDecisionV1::Selected(selection) if selection.packets().is_empty() => {
            return Ok(PreparedThreeLaneSelectionDecisionV1::NeedsMore(Box::new(
                PreparedThreeLaneNeedsMoreV1::new(
                    ThreeLaneNeedsMoreV1::NoSelectedPacketFits,
                    prepared,
                ),
            )));
        }
        SelectionDecisionV1::Selected(selection) => selection,
        SelectionDecisionV1::NeedsMore(needs_more) => {
            let reason = match needs_more.reason() {
                NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget => {
                    ThreeLaneNeedsMoreV1::FixedOverheadExceedsTotalBudget
                }
                NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget => {
                    ThreeLaneNeedsMoreV1::MandatoryCostExceedsAvailablePacketBudget
                }
            };
            return Ok(PreparedThreeLaneSelectionDecisionV1::NeedsMore(Box::new(
                PreparedThreeLaneNeedsMoreV1::new(reason, prepared),
            )));
        }
    };
    certification
        .verify_selection(
            ledger,
            prepared.receipt().input().result_id(),
            &selection,
            tokenizer,
        )
        .map_err(ThreeLaneCompileErrorV1::CertificateVerification)?;
    let parts = prepared.into_parts();
    let certification = parts
        .certification
        .ok_or(ThreeLaneCompileErrorV1::PreparedBindingMismatch)?;
    Ok(PreparedThreeLaneSelectionDecisionV1::Selected(Box::new(
        CertifiedThreeLaneSelectionV1::new(
            parts.receipt,
            parts.facets,
            parts.packet_metadata,
            proposal_packet_ids,
            selection,
            certification,
        ),
    )))
}

fn build_bound_selection_problem_v1(
    prepared: &PreparedThreeLaneProposalUniverseV1,
    total_token_budget: TotalTokenBudgetV1,
) -> Result<SelectionProblemV1, ThreeLaneCompileErrorV1> {
    let certification = prepared
        .certification()
        .ok_or(ThreeLaneCompileErrorV1::PreparedBindingMismatch)?;
    SelectionProblemV1::new(
        prepared.facets().iter().cloned(),
        prepared.proposal_packets().iter().cloned(),
        prepared.mandatory().iter().copied(),
        total_token_budget,
        certification.fixed_overhead(),
    )
    .map_err(ThreeLaneCompileErrorV1::SelectionProblem)
}

fn compile_prepared_compatibility_v1(
    ledger: &EventLedger,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
    preparation: ThreeLaneProposalPreparationDecisionV1,
) -> Result<ThreeLaneCompileDecisionV1, ThreeLaneCompileErrorV1> {
    let prepared = match preparation {
        ThreeLaneProposalPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneProposalPreparationDecisionV1::NeedsMore(needs_more) => {
            return Ok(ThreeLaneCompileDecisionV1::NeedsMore(needs_more.reason()));
        }
    };
    match select_prepared_three_lane_proposals_v1(ledger, prepared, total_token_budget, tokenizer)?
    {
        PreparedThreeLaneSelectionDecisionV1::Selected(selected) => {
            Ok(ThreeLaneCompileDecisionV1::Selected(selected))
        }
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            Ok(ThreeLaneCompileDecisionV1::NeedsMore(needs_more.reason()))
        }
    }
}

fn proposal_accounting(
    ledger: &EventLedger,
    metadata: &[CompiledPacketMetadataV1],
    packets: &[IntactPacketV1],
    mandatory: &[MandatoryPacketV1],
    facets: &[ProductionFacetV1],
) -> Result<ProposalUniverseAccountingV1, ThreeLaneCompileErrorV1> {
    let mut exhaustive_events = BTreeSet::new();
    let mut exhaustive_source_bytes = 0_u64;
    for entry in metadata {
        for event_id in entry.ordered_event_ids() {
            if !exhaustive_events.insert(*event_id) {
                return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
            }
            let event_bytes = u64::try_from(
                ledger
                    .event(*event_id)
                    .map_err(|_| ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch)?
                    .raw()
                    .len(),
            )
            .map_err(|_| {
                ThreeLaneCompileErrorV1::ProposalAccounting(
                    ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
                )
            })?;
            exhaustive_source_bytes = exhaustive_source_bytes.checked_add(event_bytes).ok_or(
                ThreeLaneCompileErrorV1::ProposalAccounting(
                    ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
                ),
            )?;
        }
    }
    let mut proposal_events = BTreeSet::new();
    let mut proposal_source_bytes = 0_u64;
    let mut proposal_affinity_count = 0_u64;
    for packet in packets {
        proposal_affinity_count = proposal_affinity_count
            .checked_add(checked_count(packet.affinities().len())?)
            .ok_or(ThreeLaneCompileErrorV1::ProposalAccounting(
                ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
            ))?;
        for event_id in packet.event_ids() {
            if !proposal_events.insert(*event_id) || !exhaustive_events.contains(event_id) {
                return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
            }
            let event_bytes = u64::try_from(
                ledger
                    .event(*event_id)
                    .map_err(|_| ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch)?
                    .raw()
                    .len(),
            )
            .map_err(|_| {
                ThreeLaneCompileErrorV1::ProposalAccounting(
                    ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
                )
            })?;
            proposal_source_bytes = proposal_source_bytes.checked_add(event_bytes).ok_or(
                ThreeLaneCompileErrorV1::ProposalAccounting(
                    ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
                ),
            )?;
        }
    }
    if exhaustive_events.len() != ledger.len() {
        return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
    }
    let exhaustive_block_count = checked_count(metadata.len())?;
    let exhaustive_event_count = checked_count(exhaustive_events.len())?;
    let proposal_packet_count = checked_count(packets.len())?;
    let proposal_event_count = checked_count(proposal_events.len())?;
    ProposalUniverseAccountingV1::new(ProposalUniverseAccountingPartsV1 {
        exhaustive_primary_block_count: exhaustive_block_count,
        exhaustive_member_event_count: exhaustive_event_count,
        exhaustive_member_source_bytes: exhaustive_source_bytes,
        proposal_packet_count,
        proposal_unique_member_event_count: proposal_event_count,
        proposal_member_source_bytes: proposal_source_bytes,
        retained_raw_nonproposal_block_count: exhaustive_block_count
            .checked_sub(proposal_packet_count)
            .ok_or(ThreeLaneCompileErrorV1::ProposalAccounting(
                ProposalUniverseAccountingErrorV1::PartitionInvariant,
            ))?,
        retained_raw_nonproposal_member_event_count: exhaustive_event_count
            .checked_sub(proposal_event_count)
            .ok_or(ThreeLaneCompileErrorV1::ProposalAccounting(
                ProposalUniverseAccountingErrorV1::PartitionInvariant,
            ))?,
        retained_raw_nonproposal_source_bytes: exhaustive_source_bytes
            .checked_sub(proposal_source_bytes)
            .ok_or(ThreeLaneCompileErrorV1::ProposalAccounting(
                ProposalUniverseAccountingErrorV1::PartitionInvariant,
            ))?,
        proposal_affinity_count,
        mandatory_proposal_count: checked_count(mandatory.len())?,
        facet_count: checked_count(facets.len())?,
    })
    .map_err(ThreeLaneCompileErrorV1::ProposalAccounting)
}

fn checked_count(length: usize) -> Result<u64, ThreeLaneCompileErrorV1> {
    u64::try_from(length).map_err(|_| {
        ThreeLaneCompileErrorV1::ProposalAccounting(
            ProposalUniverseAccountingErrorV1::ArithmeticOverflow,
        )
    })
}

fn expected_primary_blocks(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
) -> Result<BTreeMap<BlockId, ExpectedBlock>, ThreeLaneCompileErrorV1> {
    if ledger.retrieval_id() != blocks.retrieval_id() {
        return Err(ThreeLaneCompileErrorV1::LedgerBlockRetrievalMismatch);
    }
    let mut expected = BTreeMap::new();
    let mut seen_events = BTreeSet::new();
    for block in blocks.blocks() {
        if expected
            .insert(
                block.id(),
                ExpectedBlock {
                    packet_id: PacketIdV1::from_bytes(*block.id().as_bytes()),
                    ordered_event_ids: block.member_ids().to_vec(),
                },
            )
            .is_some()
        {
            return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
        }
        for event_id in block.member_ids() {
            if !ledger.contains(*event_id) || !seen_events.insert(*event_id) {
                return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
            }
        }
    }
    if seen_events.len() != ledger.len()
        || ledger
            .events()
            .iter()
            .any(|event| !seen_events.contains(&event.id()))
    {
        return Err(ThreeLaneCompileErrorV1::LedgerBlockEventUniverseMismatch);
    }
    Ok(expected)
}

fn validate_lane_retrievals(
    blocks: &BlockIndex<'_>,
    lanes: ReadyCandidateLanesV1<'_>,
) -> Result<(), ThreeLaneCompileErrorV1> {
    for (lane, retrieval_id) in [
        (CandidateLaneV1::Lexical, lanes.lexical().retrieval_id()),
        (CandidateLaneV1::Coverage, lanes.coverage().retrieval_id()),
        (CandidateLaneV1::Provider, lanes.provider().retrieval_id()),
    ] {
        if retrieval_id != blocks.retrieval_id() {
            return Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane,
                violation: LaneUniverseViolationV1::RetrievalMismatch,
            });
        }
    }
    Ok(())
}

fn validate_lexical_blocks<'a>(
    expected: &BTreeMap<BlockId, ExpectedBlock>,
    lexical: &'a LexicalCandidateUniverseV1,
) -> Result<BTreeMap<BlockId, &'a PrimaryBlockCandidateV1>, ThreeLaneCompileErrorV1> {
    let blocks = validate_lane_block_map(
        CandidateLaneV1::Lexical,
        expected,
        lexical
            .primary_blocks()
            .iter()
            .map(|candidate| (candidate.block_id(), candidate)),
    )?;
    for (block_id, candidate) in &blocks {
        let expected = expected
            .get(block_id)
            .ok_or(ThreeLaneCompileErrorV1::LaneUniverse {
                lane: CandidateLaneV1::Lexical,
                violation: LaneUniverseViolationV1::UnknownBlock,
            })?;
        if candidate.packet_id() != expected.packet_id {
            return Err(ThreeLaneCompileErrorV1::LexicalPacketIdMismatch);
        }
        if candidate.ordered_event_ids() != expected.ordered_event_ids {
            return Err(ThreeLaneCompileErrorV1::LexicalMembershipMismatch);
        }
    }
    Ok(blocks)
}

fn validate_lane_block_map<'a, T>(
    lane: CandidateLaneV1,
    expected: &BTreeMap<BlockId, ExpectedBlock>,
    entries: impl IntoIterator<Item = (BlockId, &'a T)>,
) -> Result<BTreeMap<BlockId, &'a T>, ThreeLaneCompileErrorV1> {
    let mut actual = BTreeMap::new();
    for (block_id, entry) in entries {
        if !expected.contains_key(&block_id) {
            return Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane,
                violation: LaneUniverseViolationV1::UnknownBlock,
            });
        }
        if actual.insert(block_id, entry).is_some() {
            return Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane,
                violation: LaneUniverseViolationV1::DuplicateBlock,
            });
        }
    }
    if expected
        .keys()
        .any(|block_id| !actual.contains_key(block_id))
    {
        return Err(ThreeLaneCompileErrorV1::LaneUniverse {
            lane,
            violation: LaneUniverseViolationV1::MissingBlock,
        });
    }
    Ok(actual)
}

fn merge_facets(
    lanes: ReadyCandidateLanesV1<'_>,
    inclusion: LaneInclusionV1,
) -> Result<BTreeMap<FacetIdV1, ProductionFacetV1>, ThreeLaneCompileErrorV1> {
    let mut facets = BTreeMap::new();
    if inclusion.lexical {
        for facet in lanes.lexical().facets() {
            insert_facet(&mut facets, facet.facet())?;
        }
    }
    if inclusion.coverage {
        for facet in lanes.coverage().facets() {
            insert_facet(&mut facets, facet.facet())?;
        }
    }
    if inclusion.provider {
        for facet in lanes.provider().facets() {
            insert_facet(&mut facets, facet.facet())?;
        }
    }
    Ok(facets)
}

fn insert_facet(
    facets: &mut BTreeMap<FacetIdV1, ProductionFacetV1>,
    facet: &ProductionFacetV1,
) -> Result<(), ThreeLaneCompileErrorV1> {
    match facets.get(&facet.id()) {
        Some(existing) if existing != facet => Err(ThreeLaneCompileErrorV1::FacetMaterialCollision),
        Some(_) => Ok(()),
        None => {
            facets.insert(facet.id(), facet.clone());
            Ok(())
        }
    }
}

fn merge_affinities(
    lane: CandidateLaneV1,
    block_id: BlockId,
    incoming: &[FacetAffinityV1],
    authorized_facets: &BTreeSet<FacetIdV1>,
    by_block: &mut BTreeMap<BlockId, BTreeMap<FacetIdV1, AffinityV1>>,
) -> Result<(), ThreeLaneCompileErrorV1> {
    let target = by_block
        .get_mut(&block_id)
        .ok_or(ThreeLaneCompileErrorV1::LaneUniverse {
            lane,
            violation: LaneUniverseViolationV1::UnknownBlock,
        })?;
    for affinity in incoming {
        if !authorized_facets.contains(&affinity.facet_id()) {
            return Err(ThreeLaneCompileErrorV1::UnknownAffinityFacet { lane });
        }
        target
            .entry(affinity.facet_id())
            .and_modify(|current| *current = (*current).max(affinity.affinity()))
            .or_insert(affinity.affinity());
    }
    Ok(())
}

fn canonical_mandatory_reasons(
    reasons: &[MandatoryIdentifierReasonV1],
    facets: &BTreeMap<FacetIdV1, ProductionFacetV1>,
    lexical_facet_ids: &BTreeSet<FacetIdV1>,
    affinities: &BTreeMap<FacetIdV1, AffinityV1>,
) -> Result<Vec<MandatoryIdentifierReasonV1>, ThreeLaneCompileErrorV1> {
    let mut canonical = BTreeMap::<FacetIdV1, MandatoryIdentifierReasonV1>::new();
    for reason in reasons {
        let facet = facets
            .get(&reason.facet_id())
            .ok_or(ThreeLaneCompileErrorV1::MandatoryReasonMismatch)?;
        if !lexical_facet_ids.contains(&reason.facet_id())
            || facet.kind() != ProductionFacetKindV1::ValidatedQueryIdentifier
            || !affinities.contains_key(&reason.facet_id())
        {
            return Err(ThreeLaneCompileErrorV1::MandatoryReasonMismatch);
        }
        match canonical.get(&reason.facet_id()) {
            Some(existing) if existing.identifier_kind() != reason.identifier_kind() => {
                return Err(ThreeLaneCompileErrorV1::MandatoryReasonMismatch);
            }
            Some(_) => {}
            None => {
                canonical.insert(reason.facet_id(), *reason);
            }
        }
    }
    Ok(canonical.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidentrail_select::{AFFINITY_SCALE_V1, FacetWeightV1};

    #[test]
    fn equal_facets_deduplicate_but_same_id_unequal_material_fails_closed() {
        let first = ProductionFacetV1::new(
            ProductionFacetKindV1::QueryTerm,
            b"canonical-key",
            FacetWeightV1::new(1).unwrap(),
        )
        .unwrap();
        let unequal = ProductionFacetV1::new(
            ProductionFacetKindV1::QueryTerm,
            b"canonical-key",
            FacetWeightV1::new(2).unwrap(),
        )
        .unwrap();
        assert_eq!(first.id(), unequal.id());
        assert_ne!(first, unequal);

        let mut facets = BTreeMap::new();
        insert_facet(&mut facets, &first).unwrap();
        insert_facet(&mut facets, &first).unwrap();
        assert_eq!(facets.len(), 1);
        assert_eq!(
            insert_facet(&mut facets, &unequal),
            Err(ThreeLaneCompileErrorV1::FacetMaterialCollision)
        );
    }

    #[test]
    fn duplicate_equal_facet_affinities_merge_by_deterministic_maximum() {
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::FailureRole,
            b"failure-role",
            FacetWeightV1::new(AFFINITY_SCALE_V1).unwrap(),
        )
        .unwrap();
        let block_id = BlockId::from_bytes([7; 32]);
        let facets = BTreeSet::from([facet.id()]);
        let mut by_block = BTreeMap::from([(block_id, BTreeMap::new())]);
        let low = AffinityV1::new(1).unwrap();
        let high = AffinityV1::new(AFFINITY_SCALE_V1).unwrap();

        merge_affinities(
            CandidateLaneV1::Coverage,
            block_id,
            &[FacetAffinityV1::new(facet.id(), low)],
            &facets,
            &mut by_block,
        )
        .unwrap();
        merge_affinities(
            CandidateLaneV1::Provider,
            block_id,
            &[
                FacetAffinityV1::new(facet.id(), high),
                FacetAffinityV1::new(facet.id(), low),
            ],
            &facets,
            &mut by_block,
        )
        .unwrap();

        assert_eq!(by_block[&block_id][&facet.id()], high);
    }

    #[test]
    fn lane_block_and_affinity_maps_reject_missing_extra_duplicate_and_foreign_material() {
        let block_id = BlockId::from_bytes([8; 32]);
        let unknown_block_id = BlockId::from_bytes([9; 32]);
        let expected = BTreeMap::from([(
            block_id,
            ExpectedBlock {
                packet_id: PacketIdV1::from_bytes([8; 32]),
                ordered_event_ids: vec![EventId::from_bytes([8; 32])],
            },
        )]);
        let first = 1u8;
        let duplicate = 2u8;
        assert_eq!(
            validate_lane_block_map(
                CandidateLaneV1::Coverage,
                &expected,
                std::iter::empty::<(BlockId, &u8)>(),
            ),
            Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane: CandidateLaneV1::Coverage,
                violation: LaneUniverseViolationV1::MissingBlock,
            })
        );
        assert_eq!(
            validate_lane_block_map(
                CandidateLaneV1::Coverage,
                &expected,
                [(unknown_block_id, &first)],
            ),
            Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane: CandidateLaneV1::Coverage,
                violation: LaneUniverseViolationV1::UnknownBlock,
            })
        );
        assert_eq!(
            validate_lane_block_map(
                CandidateLaneV1::Coverage,
                &expected,
                [(block_id, &first), (block_id, &duplicate)],
            ),
            Err(ThreeLaneCompileErrorV1::LaneUniverse {
                lane: CandidateLaneV1::Coverage,
                violation: LaneUniverseViolationV1::DuplicateBlock,
            })
        );

        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::FailureRole,
            b"foreign-facet",
            FacetWeightV1::new(1).unwrap(),
        )
        .unwrap();
        let mut by_block = BTreeMap::from([(block_id, BTreeMap::new())]);
        assert_eq!(
            merge_affinities(
                CandidateLaneV1::Coverage,
                block_id,
                &[FacetAffinityV1::new(
                    facet.id(),
                    AffinityV1::new(1).unwrap(),
                )],
                &BTreeSet::new(),
                &mut by_block,
            ),
            Err(ThreeLaneCompileErrorV1::UnknownAffinityFacet {
                lane: CandidateLaneV1::Coverage,
            })
        );
    }
}
