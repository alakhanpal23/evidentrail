//! Deterministic, model-independent benchmark methods for Evidentrail.
//!
//! Methods consume an immutable [`evidentrail_core::EventLedger`] and return exact
//! event references. They never decode, concatenate, split, or rewrite event
//! payloads. The first baselines deliberately stay simple: chronological raw
//! truncation and deterministic ASCII query-term grep plus head/tail sentinels.

mod aggregator;
mod baselines;
mod bounded_selector_challenger;
mod cost_matched_selector_stress;
mod evaluator;
mod fidelity;
mod manifest;
mod measurement;
mod method;
mod metrics;
mod producer_comparison;
mod producer_frontier;
mod producer_proposals;
mod producer_renderer;
mod resources;
mod run_manifest;
mod runner;
mod selector_challenger_comparison;
mod selector_perturbation_corpus;
mod small_selection_oracle;
mod three_lane_ablation;
mod three_lane_ablation_corpus;
mod three_lane_ablation_evaluation;
mod three_lane_ablation_selection_corpus;
mod three_lane_selection_oracle_corpus;

pub use aggregator::{
    ExactPairedRunComparisonInputV1, GovernedRunAggregateV1, GovernedRunCaseInputV1,
    GovernedRunRecallV1, PairedPublicCaseInputV1, PublicRunAccountingV1, PublicRunAggregateV1,
    PublicRunComparisonInputV1, RunAggregateDimensionV1, RunAggregationError,
    aggregate_governed_run_v1,
};
pub use baselines::{
    GrepHeadTail, GrepHeadTailConfig, QuotaHybrid, QuotaHybridConfig, RawChronological,
};
pub use bounded_selector_challenger::{
    BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1, BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1,
    BOUNDED_SELECTOR_CHALLENGER_POLICY_NAME_V1, BOUNDED_SELECTOR_CHALLENGER_POLICY_VERSION_V1,
    BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1, BoundedSelectorChallengerErrorV1,
    BoundedSelectorChallengerIdentityV1, BoundedSelectorChallengerModeV1,
    BoundedSelectorCostRelationV1, BoundedSelectorNeedsMoreV1, BoundedSelectorObjectiveRelationV1,
    BoundedSelectorOutcomeV1, BoundedSelectorPacketIdV1, BoundedSelectorPlanSourceV1,
    BoundedSelectorSearchBoundsV1, BoundedSelectorSearchObservationV1,
    BoundedSelectorSelectedPlanV1, FrozenBoundedSelectorPairV1,
    bounded_selector_challenger_identity_v1, evaluate_bounded_selector_challenger_v1,
};
pub use evidentrail_compile::{
    PreparedThreeLaneAblationSetV1, PreparedThreeLaneAblationV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1, prepare_ready_three_lane_ablations_v1,
    prepare_three_lane_ablations_v1, three_lane_ablation_config_digest_v1,
    three_lane_ablation_method_family_digest_v1,
};
pub use cost_matched_selector_stress::{
    COST_MATCHED_CHALLENGER_POLICY_NAME_V1, COST_MATCHED_CHALLENGER_POLICY_VERSION_V1,
    COST_MATCHED_STRESS_CASE_COUNT_V1, COST_MATCHED_STRESS_MIN_OPTIONAL_PACKETS_V1,
    CostMatchedCostRelationV1, CostMatchedObjectiveRelationV1, CostMatchedPlanSourceV1,
    CostMatchedRecallRelationV1, CostMatchedResourceEnvelopeV1, CostMatchedStressCaseV1,
    CostMatchedStressErrorV1, CostMatchedStressFamilyV1, CostMatchedStressGovernedAnnotationV1,
    CostMatchedStressRecallV1, CostMatchedStressRequirementV1, FrozenCostMatchedPlanV1,
    FrozenCostMatchedStressCaseV1, FrozenCostMatchedStressCorpusV1,
    FrozenCostMatchedStressDigestV1, GovernedCostMatchedStressCaseV1,
    GovernedCostMatchedStressCorpusV1, MAX_COST_MATCHED_STRESS_ALTERNATIVES_V1,
    MAX_COST_MATCHED_STRESS_EVENTS_PER_ALTERNATIVE_V1, MAX_COST_MATCHED_STRESS_REQUIREMENTS_V1,
    STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1, STRUCTURED_DP_POLICY_NAME_V1,
    STRUCTURED_DP_POLICY_VERSION_V1, STRUCTURED_DP_STATE_SLOT_CAP_V1,
    STRUCTURED_DP_TRANSITION_CAP_V1, StructuredDpIneligibleReasonV1, StructuredDpOutcomeV1,
    StructuredDpWorkReceiptV1, evaluate_governed_cost_matched_selector_stress_v1,
    freeze_cost_matched_selector_stress_corpus_v1, synthetic_cost_matched_stress_annotations_v1,
};
pub use evaluator::{
    CaseAccountingDimensionV1, CaseEvaluationError, GovernedCaseEvaluationV1,
    GovernedRequirementRecallV1, PublicCaseAccountingV1, PublicCaseEvaluationResultV1,
    evaluate_governed_case_v1, evaluate_governed_case_with_presentation_v1,
};
pub use fidelity::{
    EvidenceRepresentationClaimV1, EvidenceRepresentationClassV1,
    FrozenExternalRepresentationSubmissionV1, GovernedNeedsDownstreamVdsV1,
    GovernedRepresentationFidelityOutcomeV1, GovernedRepresentationFidelityPolicyV1,
    GovernedRepresentationScoreSubmissionV1, MAX_FIDELITY_METHOD_IDENTITY_BYTES_V1,
    MAX_FIDELITY_RENDERED_CANDIDATE_BYTES_V1, MAX_FIDELITY_REQUIREMENTS_V1,
    MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1, MAX_REPRESENTATION_CLAIMS_V1,
    NonExactFidelityDispositionV1, PinnedTransformedExpectationV1, RepresentationFidelityErrorV1,
    RequirementFidelityPolicyV1, ReversibleEncodingIdentityV1, ascii_byte_escape_v1_identity,
    derive_reversible_encoded_representation_artifact_digest_v1,
    derive_source_exact_representation_artifact_digest_v1,
    evaluate_governed_representation_fidelity_v1,
};
pub use manifest::{
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1, EvidenceTargetV1, ExpectedAcquisitionClassV1,
    ManifestError, WeightedDiagnosticRequirementV1,
};
pub use measurement::{
    CandidateRendererIdentityV1, FrozenCandidateRenderingV1, FrozenCandidateSelectionDigestV1,
    MeasurementEnvironmentV1, MeasurementHarnessIdentityV1, MeasurementProvenanceError,
    MeasurementProvenanceReceiptV1, MeasurementTrustBoundaryV1, RenderedCandidateArtifactV1,
    TokenizerIdentityV1, derive_frozen_candidate_selection_digest_v1,
};
pub use method::{
    AccountingSummary, BenchmarkMethod, ByteBudget, CandidateCost, MethodDescriptor, MethodError,
    MethodInput, MethodResult, SelectedEvent, SelectionReason,
};
pub use metrics::{
    CaseDiagnosticRecall, DiagnosticRequirement, MetricError, RequiredEvidenceRecall,
    candidate_cost, diagnostic_requirement_coverage, required_evidence_recall,
};
pub use producer_comparison::{
    GovernedProducerProposalComparisonV1, ProducerProposalComparisonErrorV1,
    ProducerProposalComparisonSideV1, ProducerProposalParetoRelationV1,
};
pub use producer_frontier::{
    FrozenProducerProposalFrontierPlanV1, GovernedProducerProposalFrontierDigestV1,
    GovernedProducerProposalFrontierPointV1, GovernedProducerProposalFrontierV1,
    MAX_PRODUCER_PROPOSAL_FRONTIER_POINTS_V1, ProducerProposalFrontierErrorV1,
    ProducerProposalFrontierPlanDigestV1, ProducerProposalFrontierPlanPointV1,
    evaluate_governed_producer_proposal_frontier_v1,
};
pub use producer_proposals::{
    FrozenProducerProposalUniverseDigestV1, FrozenProducerProposalUniverseV1,
    GovernedProducerProposalEvaluationV1, MAX_PRODUCER_PROPOSAL_MEMBER_REFERENCES_V1,
    MAX_PRODUCER_PROPOSAL_MEMBERS_PER_PACKET_V1, MAX_PRODUCER_PROPOSAL_PACKETS_V1,
    MeasuredProducerProposalResourcesV1, ProducerProposalAccountingV1,
    ProducerProposalAcquisitionBindingV1, ProducerProposalCapViolationsV1, ProducerProposalErrorV1,
    ProducerProposalIdV1, ProducerProposalIdentityV1, ProducerProposalMeasurementEnvironmentV1,
    ProducerProposalMeasurementReceiptV1, ProducerProposalPacketV1, ProducerProposalResourceCapV1,
    ProducerProposalResourceDimensionV1, ProducerProposalResourceEnvelopeV1,
    RenderedProducerProposalArtifactV1, evaluate_governed_producer_proposals_v1,
};
pub use producer_renderer::{
    CanonicalProducerProposalArtifactV1, MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1,
    ProducerProposalRenderErrorV1, ProducerProposalRenderLimitV1,
    ProducerProposalRendererIdentityV1, canonical_producer_proposal_renderer_v1_identity,
    render_canonical_producer_proposals_v1,
};
pub use resources::{
    CandidateCapViolations, CandidateResourceCap, CandidateResourceDimension,
    CandidateResourceEnvelope, CandidateResourceError, MeasuredCandidateResources,
    candidate_resource_envelope, cost_pareto_dominates,
};
pub use run_manifest::{
    BenchmarkBudgetV1, BenchmarkRunIdentityDimensionV1, BenchmarkRunIdentityV1,
    EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1, ExternalSystemResultEnvelopeV1,
    GovernedCaseArtifactBindingV1, GovernedCaseArtifactJoinV1, RunManifestError,
};
pub use runner::{
    FrozenPublicCaseRunV1, FrozenPublicRunV1, HermeticGovernedCaseInputV1,
    HermeticPublicCaseInputV1, HermeticRunnerError, MeasurementValidatedCaseV1,
    MeasurementValidatedPublicRunV1, bind_hermetic_measurement_receipts_v1,
    evaluate_measurement_validated_hermetic_run_v1, execute_hermetic_public_run_v1,
};
pub use selector_challenger_comparison::{
    BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1, FrozenSelectorChallengerComparisonCaseV1,
    FrozenSelectorChallengerComparisonV1, GovernedSelectorChallengerComparisonV1,
    GovernedSelectorChallengerRecallCaseV1, SelectorChallengerAdmissionBlockerV1,
    SelectorChallengerComparisonCaseV1, SelectorChallengerComparisonErrorV1,
    SelectorChallengerRecallRelationV1, evaluate_governed_selector_challenger_comparison_v1,
    freeze_selector_challenger_comparison_v1,
};
pub use selector_perturbation_corpus::{
    FrozenSelectorPerturbationCaseDigestV1, FrozenSelectorPerturbationCaseV1,
    FrozenSelectorPerturbationCorpusDigestV1, FrozenSelectorPerturbationCorpusV1,
    FrozenSelectorPerturbationOutcomeV1, GovernedSelectorPerturbationCaseV1,
    GovernedSelectorPerturbationReportV1, SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1,
    SelectorPerturbationCapIneligibleV1, SelectorPerturbationCaseV1,
    SelectorPerturbationCorpusErrorV1, SelectorPerturbationExpectedOutcomeV1,
    SelectorPerturbationFamilyDistributionV1, SelectorPerturbationFamilyV1,
    SelectorPerturbationGovernedAnnotationV1, evaluate_governed_selector_perturbation_corpus_v1,
    freeze_selector_perturbation_corpus_v1,
};
pub use small_selection_oracle::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    EXACT_SELECTION_ORACLE_TIE_BREAK_V1, ExactSelectionOracleErrorV1,
    ExactSmallSelectionNeedsMoreV1, ExactSmallSelectionOracleDecisionV1, ExactSmallSelectionPlanV1,
    ExactSmallSelectionRegretDecisionV1, ExactSmallSelectionRegretV1,
    MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, evaluate_exact_small_selection_oracle_v1,
    evaluate_exact_small_selection_regret_v1,
};
pub use three_lane_ablation::{
    FrozenThreeLaneAblationSetV1, FrozenThreeLaneAblationV1, ThreeLaneAblationFreezeErrorV1,
    freeze_prepared_three_lane_ablations_v1,
};
pub use three_lane_ablation_corpus::{
    ExactFamilyMacroRecallComponentV1, ExactLaneRemovalDeltaComponentV1,
    FamilyMacroLaneRemovalDeltaV1, FamilyMacroRequirementRecallV1,
    FrozenPublicSyntheticThreeLaneAblationCaseV1, FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    FrozenPublicSyntheticThreeLaneCorpusDigestV1, GovernedSyntheticThreeLaneAblationCaseInputV1,
    GovernedSyntheticThreeLaneAblationCaseV1, GovernedSyntheticThreeLaneAblationCorpusV1,
    GovernedSyntheticThreeLaneCorpusDigestV1, LaneRemovalDeltaDirectionV1,
    SyntheticThreeLaneAblationCaseV1, SyntheticThreeLaneAblationFamilyV1,
    SyntheticThreeLaneAblationPublicCaseInputV1, SyntheticThreeLaneCorpusErrorV1,
    SyntheticThreeLaneCorpusScopeV1, evaluate_governed_synthetic_three_lane_ablation_corpus_v1,
    freeze_public_synthetic_three_lane_ablation_corpus_v1,
    synthetic_three_lane_ablation_corpus_identity_v1,
};
pub use three_lane_ablation_evaluation::{
    FrozenPublicThreeLaneAblationBatchDigestV1, FrozenPublicThreeLaneAblationBatchV1,
    FrozenPublicThreeLaneAblationPointDigestV1, FrozenPublicThreeLaneAblationPointV1,
    GovernedThreeLaneAblationBatchDigestV1, GovernedThreeLaneAblationBatchV1,
    GovernedThreeLaneAblationPointV1, ThreeLaneAblationEvaluationErrorV1,
    ThreeLaneAblationMeasurementAllocationV1, ThreeLaneAblationPublicPointInputV1,
    evaluate_governed_three_lane_ablation_batch_v1, freeze_public_three_lane_ablation_batch_v1,
};
pub use three_lane_ablation_selection_corpus::{
    AlternativeOracleBudgetFeasibilityV1, ExactSelectedFamilyLaneRemovalDeltasV1,
    ExactSelectedFamilyMaskComponentV1, ExactSelectedFamilyMaskComponentsV1,
    ExactSelectedLaneRemovalDeltaComponentV1, FrozenFacetSaturationAuditV1,
    FrozenMatchedBaselineOutcomeV1, FrozenMatchedBaselineSetV1, FrozenProposalAffinityAuditV1,
    FrozenProposalPacketAuditV1, FrozenPublicSyntheticThreeLaneSelectionCorpusV1,
    FrozenSyntheticCompiledRenderV1, FrozenSyntheticThreeLaneNeedsMoreV1,
    FrozenSyntheticThreeLaneSelectedV1, FrozenSyntheticThreeLaneSelectionCaseDigestV1,
    FrozenSyntheticThreeLaneSelectionCaseV1, FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    FrozenSyntheticThreeLaneSelectionDecisionV1, FrozenSyntheticThreeLaneSelectionOutcomeDigestV1,
    FrozenSyntheticThreeLaneSelectionOutcomeV1, GovernedMaskSelectionAttributionV1,
    GovernedMatchedBaselineOutcomeV1, GovernedRequirementSelectionAttributionV1,
    GovernedSyntheticThreeLaneSelectionCaseInputV1, GovernedSyntheticThreeLaneSelectionCaseV1,
    GovernedSyntheticThreeLaneSelectionCorpusV1, GovernedSyntheticThreeLaneSelectionPointV1,
    MatchedBaselineArmV1, RequiredAlternativeSelectionAttributionV1,
    RequiredEventSelectionAttributionV1, RequiredEventSelectionDispositionV1,
    RequiredEventSelectionResidualV1, RequirementSelectionAttributionClassV1,
    SyntheticThreeLaneNeedsMoreClassV1, SyntheticThreeLaneSelectionBudgetScheduleDigestV1,
    SyntheticThreeLaneSelectionBudgetScheduleV1, SyntheticThreeLaneSelectionPublicCaseInputV1,
    ThreeLaneSelectionCorpusErrorV1, evaluate_governed_synthetic_three_lane_selection_corpus_v1,
    freeze_public_synthetic_three_lane_selection_corpus_v1,
    synthetic_three_lane_selection_budget_schedule_v1,
};
pub use three_lane_selection_oracle_corpus::{
    FrozenSyntheticFullSelectionOracleDecisionV1, FrozenSyntheticFullSelectionOracleDigestV1,
    FrozenSyntheticFullSelectionOracleEvaluatedV1, FrozenSyntheticFullSelectionOracleIneligibleV1,
    FrozenSyntheticFullSelectionOracleNeedsMoreV1, FrozenSyntheticFullSelectionOracleV1,
    GovernedSyntheticFullSelectionOracleCaseV1, GovernedSyntheticFullSelectionOracleReportV1,
};
