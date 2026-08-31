use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{
    PreparedThreeLaneAblationSetV1, PreparedThreeLaneProposalUniverseV1,
    PreparedThreeLaneSelectionDecisionV1, ThreeLaneAblationMaskV1, ThreeLaneCompileErrorV1,
    ThreeLaneNeedsMoreV1, select_prepared_three_lane_ablation_v1,
};
use evidentrail_core::{
    BlockIndex, EventId, EventLedger, EvidenceReferenceConstructionError, EvidenceReferenceV1,
    EvidenceTargetRef, ExpansionRelationV1, UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_evidence::{
    CompiledBriefError, OwnedRenderedCompiledBriefV1, Utf8ByteTokenizerV1,
    compiled_renderer_digest_v1, render_cost_certified_compiled_log_brief_v1,
    utf8_byte_tokenizer_digest_v1,
};
use evidentrail_schema::ArtifactDigest;
use evidentrail_select::{
    FacetIdV1, ProductionFacetKindV1, SelectionConstraintV1, SelectionV1, TotalTokenBudgetV1,
};
use sha2::{Digest as _, Sha256};

use crate::evaluator::{evaluate_requirements_v1, selected_targets_v1};
use crate::three_lane_selection_oracle_corpus::{
    build_governed_full_selection_oracle_report_v1, freeze_synthetic_full_selection_oracle_v1,
};
use crate::{
    BenchmarkMethod, ByteBudget, CaseEvaluationError, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, ExpectedAcquisitionClassV1,
    FrozenPublicSyntheticThreeLaneAblationCorpusV1, FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    GovernedCaseArtifactJoinV1, GovernedCaseEvaluationV1, GovernedRequirementRecallV1,
    GovernedSyntheticThreeLaneAblationCaseInputV1, GovernedSyntheticThreeLaneAblationCorpusV1,
    GrepHeadTail, MethodError, MethodInput, MethodResult, ProducerProposalIdV1, QuotaHybrid,
    QuotaHybridConfig, RawChronological, SyntheticThreeLaneAblationCaseV1,
    SyntheticThreeLaneAblationFamilyV1, SyntheticThreeLaneCorpusErrorV1,
    SyntheticThreeLaneCorpusScopeV1, evaluate_governed_case_v1,
    evaluate_governed_synthetic_three_lane_ablation_corpus_v1,
};

const PUBLIC_SELECTION_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-synthetic-three-lane-selection-corpus/v1\0";
const PUBLIC_SELECTION_CASE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-synthetic-three-lane-selection-case/v1\0";
const PUBLIC_SELECTION_OUTCOME_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-synthetic-three-lane-selection-outcome/v1\0";
const SELECTION_BUDGET_SCHEDULE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/synthetic-three-lane-selection-budget-schedule/v1\0";
const GOVERNED_SELECTION_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-synthetic-three-lane-selection-corpus/v1\0";
const MATCHED_BASELINE_OUTCOME_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/matched-selection-baseline-outcome/v1\0";
const MATCHED_BASELINE_SET_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/matched-selection-baseline-set/v1\0";

/// Closed preregistered schedule used by the first conformance tranche.
///
/// Five cases use a deliberately generous fixed byte-token budget. The
/// partial-acquisition distractor case uses a deliberately tiny fixed budget
/// to retain an honest budget-infeasible outcome. These values are public and
/// fixed before governed annotations are accepted.
#[must_use]
pub fn synthetic_three_lane_selection_budget_schedule_v1()
-> SyntheticThreeLaneSelectionBudgetScheduleV1 {
    SyntheticThreeLaneSelectionBudgetScheduleV1::try_new([
        (
            SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead,
            16_384,
        ),
        (SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle, 16_384),
        (
            SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail,
            16_384,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved,
            16_384,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors,
            64,
        ),
        (
            SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes,
            16_384,
        ),
    ])
    .expect("frozen synthetic schedule is valid")
}

/// Domain-separated identity of an exact six-case token-budget schedule.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyntheticThreeLaneSelectionBudgetScheduleDigestV1([u8; 32]);

impl SyntheticThreeLaneSelectionBudgetScheduleDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SyntheticThreeLaneSelectionBudgetScheduleDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyntheticThreeLaneSelectionBudgetScheduleDigestV1(<redacted>)")
    }
}

/// Canonical one-budget-per-case public schedule.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SyntheticThreeLaneSelectionBudgetScheduleV1 {
    digest: SyntheticThreeLaneSelectionBudgetScheduleDigestV1,
    budgets: [TotalTokenBudgetV1; 6],
}

impl SyntheticThreeLaneSelectionBudgetScheduleV1 {
    pub fn try_new<Entries>(entries: Entries) -> Result<Self, ThreeLaneSelectionCorpusErrorV1>
    where
        Entries: IntoIterator<Item = (SyntheticThreeLaneAblationCaseV1, u64)>,
    {
        let mut budgets = [None; 6];
        for (case, tokens) in entries {
            let budget = TotalTokenBudgetV1::new(tokens)
                .map_err(|_| ThreeLaneSelectionCorpusErrorV1::InvalidTokenBudget)?;
            let index = case_index(case);
            if budgets[index].replace(budget).is_some() {
                return Err(ThreeLaneSelectionCorpusErrorV1::DuplicateBudgetCase);
            }
        }
        if budgets.iter().any(Option::is_none) {
            return Err(ThreeLaneSelectionCorpusErrorV1::MissingBudgetCases {
                count: budgets.iter().filter(|entry| entry.is_none()).count(),
            });
        }
        let budgets = budgets.map(|entry| entry.expect("presence checked"));
        let mut hasher = Sha256::new();
        update_field(&mut hasher, SELECTION_BUDGET_SCHEDULE_DOMAIN_V1)?;
        for (case, budget) in SyntheticThreeLaneAblationCaseV1::ALL
            .into_iter()
            .zip(budgets)
        {
            update_field(&mut hasher, case.identity_digest().as_bytes())?;
            update_u64(&mut hasher, budget.tokens());
        }
        Ok(Self {
            digest: SyntheticThreeLaneSelectionBudgetScheduleDigestV1(hasher.finalize().into()),
            budgets,
        })
    }

    #[must_use]
    pub const fn digest(self) -> SyntheticThreeLaneSelectionBudgetScheduleDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn budget(self, case: SyntheticThreeLaneAblationCaseV1) -> TotalTokenBudgetV1 {
        self.budgets[case_index(case)]
    }
}

impl fmt::Debug for SyntheticThreeLaneSelectionBudgetScheduleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneSelectionBudgetScheduleV1")
            .field("schedule_identity_present", &true)
            .field("case_count", &self.budgets.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSyntheticThreeLaneSelectionOutcomeDigestV1([u8; 32]);

impl FrozenSyntheticThreeLaneSelectionOutcomeDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionOutcomeDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSyntheticThreeLaneSelectionOutcomeDigestV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSyntheticThreeLaneSelectionCaseDigestV1([u8; 32]);

impl FrozenSyntheticThreeLaneSelectionCaseDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionCaseDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSyntheticThreeLaneSelectionCaseDigestV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSyntheticThreeLaneSelectionCorpusDigestV1([u8; 32]);

impl FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSyntheticThreeLaneSelectionCorpusDigestV1(<redacted>)")
    }
}

/// Public-stage case material. Its signature contains no governed annotation.
pub struct SyntheticThreeLaneSelectionPublicCaseInputV1<'a> {
    case: SyntheticThreeLaneAblationCaseV1,
    prepared: &'a PreparedThreeLaneAblationSetV1,
    ledger: &'a EventLedger,
    question_bytes: &'a [u8],
    reference_authorized_at: UnixTimestampNanos,
    reference_expires_at: UnixTimestampNanos,
}

impl<'a> SyntheticThreeLaneSelectionPublicCaseInputV1<'a> {
    #[must_use]
    pub const fn new(
        case: SyntheticThreeLaneAblationCaseV1,
        prepared: &'a PreparedThreeLaneAblationSetV1,
        ledger: &'a EventLedger,
        question_bytes: &'a [u8],
        reference_authorized_at: UnixTimestampNanos,
        reference_expires_at: UnixTimestampNanos,
    ) -> Self {
        Self {
            case,
            prepared,
            ledger,
            question_bytes,
            reference_authorized_at,
            reference_expires_at,
        }
    }
}

impl fmt::Debug for SyntheticThreeLaneSelectionPublicCaseInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneSelectionPublicCaseInputV1")
            .field("case", &self.case)
            .field("prepared_authority_present", &true)
            .field("ledger_binding_present", &true)
            .field("question_byte_count", &self.question_bytes.len())
            .field("reference_interval_present", &true)
            .finish()
    }
}

/// Exact canonical compiled render retained from the pre-annotation stage.
/// Debug never exposes the rendered text or authorized bytes.
pub struct FrozenSyntheticCompiledRenderV1 {
    artifact_digest: ArtifactDigest,
    rendered: OwnedRenderedCompiledBriefV1,
}

impl FrozenSyntheticCompiledRenderV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn artifact(&self) -> &OwnedRenderedCompiledBriefV1 {
        &self.rendered
    }

    #[must_use]
    pub fn text(&self) -> &str {
        self.rendered.text()
    }

    #[must_use]
    pub const fn token_count(&self) -> u64 {
        self.rendered.brief().cost().total_rendered_tokens()
    }

    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.rendered.brief().cost().total_rendered_bytes()
    }
}

impl fmt::Debug for FrozenSyntheticCompiledRenderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticCompiledRenderV1")
            .field("artifact_identity_present", &true)
            .field("token_count", &self.token_count())
            .field("byte_count", &self.byte_count())
            .finish()
    }
}

/// Successful exact selector and canonical-render receipt.
pub struct FrozenSyntheticThreeLaneSelectedV1 {
    proposal_receipt_digest: ArtifactDigest,
    selected_packet_ids: Vec<ProducerProposalIdV1>,
    selected_event_ids: Vec<EventId>,
    selected_unique_source_bytes: u64,
    coverage_only_token_charge: u64,
    coverage_only_token_limit: u64,
    render: FrozenSyntheticCompiledRenderV1,
}

impl FrozenSyntheticThreeLaneSelectedV1 {
    #[must_use]
    pub const fn proposal_receipt_digest(&self) -> ArtifactDigest {
        self.proposal_receipt_digest
    }

    #[must_use]
    pub fn selected_packet_ids(&self) -> &[ProducerProposalIdV1] {
        &self.selected_packet_ids
    }

    #[must_use]
    pub fn selected_event_ids(&self) -> &[EventId] {
        &self.selected_event_ids
    }

    #[must_use]
    pub fn selected_packet_count(&self) -> u64 {
        u64::try_from(self.selected_packet_ids.len())
            .expect("V1 selected packet count is schema bounded")
    }

    #[must_use]
    pub const fn selected_unique_source_bytes(&self) -> u64 {
        self.selected_unique_source_bytes
    }

    #[must_use]
    pub const fn coverage_only_token_charge(&self) -> u64 {
        self.coverage_only_token_charge
    }

    #[must_use]
    pub const fn coverage_only_token_limit(&self) -> u64 {
        self.coverage_only_token_limit
    }

    #[must_use]
    pub const fn render(&self) -> &FrozenSyntheticCompiledRenderV1 {
        &self.render
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticThreeLaneSelectedV1")
            .field("proposal_receipt_present", &true)
            .field("selected_packet_count", &self.selected_packet_ids.len())
            .field("selected_event_count", &self.selected_event_ids.len())
            .field(
                "selected_unique_source_bytes",
                &self.selected_unique_source_bytes,
            )
            .field(
                "coverage_only_token_charge",
                &self.coverage_only_token_charge,
            )
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .field("render", &self.render)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyntheticThreeLaneNeedsMoreClassV1 {
    EmptyProposalUniverse,
    BudgetInfeasible,
}

impl SyntheticThreeLaneNeedsMoreClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyProposalUniverse => "empty_proposal_universe",
            Self::BudgetInfeasible => "budget_infeasible",
        }
    }
}

impl fmt::Debug for SyntheticThreeLaneNeedsMoreClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneNeedsMoreClassV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenSyntheticThreeLaneNeedsMoreV1 {
    proposal_receipt_digest: ArtifactDigest,
    reason: ThreeLaneNeedsMoreV1,
    class: SyntheticThreeLaneNeedsMoreClassV1,
}

impl FrozenSyntheticThreeLaneNeedsMoreV1 {
    #[must_use]
    pub const fn proposal_receipt_digest(self) -> ArtifactDigest {
        self.proposal_receipt_digest
    }

    #[must_use]
    pub const fn reason(self) -> ThreeLaneNeedsMoreV1 {
        self.reason
    }

    #[must_use]
    pub const fn class(self) -> SyntheticThreeLaneNeedsMoreClassV1 {
        self.class
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticThreeLaneNeedsMoreV1")
            .field("proposal_receipt_present", &true)
            .field("reason", &self.reason)
            .field("class", &self.class)
            .finish()
    }
}

/// One exact production facet/affinity contribution attached to a proposal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenProposalAffinityAuditV1 {
    facet_id: FacetIdV1,
    kind: ProductionFacetKindV1,
    weight_micros: u32,
    affinity_micros: u32,
}

impl FrozenProposalAffinityAuditV1 {
    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn kind(self) -> ProductionFacetKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn weight_micros(self) -> u32 {
        self.weight_micros
    }

    #[must_use]
    pub const fn affinity_micros(self) -> u32 {
        self.affinity_micros
    }
}

impl fmt::Debug for FrozenProposalAffinityAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenProposalAffinityAuditV1")
            .field("kind", &self.kind)
            .field("weight_micros", &self.weight_micros)
            .field("affinity_micros", &self.affinity_micros)
            .finish()
    }
}

/// Exact selected packet occupying one of the shared facet's closed top-k
/// coverage slots with at least the audited packet's affinity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenFacetSaturationAuditV1 {
    facet_id: FacetIdV1,
    kind: ProductionFacetKindV1,
    candidate_affinity_micros: u32,
    selected_packet_id: ProducerProposalIdV1,
    selected_affinity_micros: u32,
}

impl FrozenFacetSaturationAuditV1 {
    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn kind(self) -> ProductionFacetKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn candidate_affinity_micros(self) -> u32 {
        self.candidate_affinity_micros
    }

    #[must_use]
    pub const fn selected_packet_id(self) -> ProducerProposalIdV1 {
        self.selected_packet_id
    }

    #[must_use]
    pub const fn selected_affinity_micros(self) -> u32 {
        self.selected_affinity_micros
    }
}

impl fmt::Debug for FrozenFacetSaturationAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenFacetSaturationAuditV1")
            .field("kind", &self.kind)
            .field("candidate_affinity_micros", &self.candidate_affinity_micros)
            .field("selected_packet_identity_present", &true)
            .field("selected_affinity_micros", &self.selected_affinity_micros)
            .finish()
    }
}

/// Complete label-free selector facts for one exact proposal packet.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenProposalPacketAuditV1 {
    packet_id: ProducerProposalIdV1,
    member_event_ids: Vec<EventId>,
    token_cost_upper_bound: u64,
    affinities: Vec<FrozenProposalAffinityAuditV1>,
    mandatory_facet_ids: Vec<FacetIdV1>,
    selected: bool,
    selected_marginal_gain_numerator: Option<u64>,
    selected_constraint: Option<SelectionConstraintV1>,
    post_selection_marginal_gain_numerator: Option<u64>,
    fits_remaining_total_budget: Option<bool>,
    fits_remaining_coverage_slice: Option<bool>,
    saturations: Vec<FrozenFacetSaturationAuditV1>,
}

impl FrozenProposalPacketAuditV1 {
    #[must_use]
    pub const fn packet_id(&self) -> ProducerProposalIdV1 {
        self.packet_id
    }

    #[must_use]
    pub fn member_event_ids(&self) -> &[EventId] {
        &self.member_event_ids
    }

    #[must_use]
    pub const fn token_cost_upper_bound(&self) -> u64 {
        self.token_cost_upper_bound
    }

    #[must_use]
    pub fn affinities(&self) -> &[FrozenProposalAffinityAuditV1] {
        &self.affinities
    }

    #[must_use]
    pub fn mandatory_facet_ids(&self) -> &[FacetIdV1] {
        &self.mandatory_facet_ids
    }

    #[must_use]
    pub fn is_mandatory(&self) -> bool {
        !self.mandatory_facet_ids.is_empty()
    }

    #[must_use]
    pub const fn is_selected(&self) -> bool {
        self.selected
    }

    #[must_use]
    pub const fn selected_marginal_gain_numerator(&self) -> Option<u64> {
        self.selected_marginal_gain_numerator
    }

    #[must_use]
    pub const fn selected_constraint(&self) -> Option<SelectionConstraintV1> {
        self.selected_constraint
    }

    #[must_use]
    pub const fn post_selection_marginal_gain_numerator(&self) -> Option<u64> {
        self.post_selection_marginal_gain_numerator
    }

    #[must_use]
    pub const fn fits_remaining_total_budget(&self) -> Option<bool> {
        self.fits_remaining_total_budget
    }

    #[must_use]
    pub const fn fits_remaining_coverage_slice(&self) -> Option<bool> {
        self.fits_remaining_coverage_slice
    }

    #[must_use]
    pub fn saturations(&self) -> &[FrozenFacetSaturationAuditV1] {
        &self.saturations
    }
}

impl fmt::Debug for FrozenProposalPacketAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenProposalPacketAuditV1")
            .field("packet_identity_present", &true)
            .field("member_event_count", &self.member_event_ids.len())
            .field("token_cost_upper_bound", &self.token_cost_upper_bound)
            .field("affinity_count", &self.affinities.len())
            .field("mandatory_reason_count", &self.mandatory_facet_ids.len())
            .field("selected", &self.selected)
            .field(
                "selected_marginal_gain_numerator",
                &self.selected_marginal_gain_numerator,
            )
            .field("selected_constraint", &self.selected_constraint)
            .field(
                "post_selection_marginal_gain_numerator",
                &self.post_selection_marginal_gain_numerator,
            )
            .field(
                "fits_remaining_total_budget",
                &self.fits_remaining_total_budget,
            )
            .field(
                "fits_remaining_coverage_slice",
                &self.fits_remaining_coverage_slice,
            )
            .field("saturation_count", &self.saturations.len())
            .finish()
    }
}

/// Closed deterministic baseline roster evaluated at the Full compiled arm's
/// exact selected unique-source-byte cost. This is a matched byte-budget
/// comparator, never a scalar comparison with compiled render tokens.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchedBaselineArmV1 {
    RawChronological,
    GrepHeadTail,
    QuotaHybrid,
}

impl MatchedBaselineArmV1 {
    pub const ALL: [Self; 3] = [
        Self::RawChronological,
        Self::GrepHeadTail,
        Self::QuotaHybrid,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RawChronological => "raw_chronological",
            Self::GrepHeadTail => "grep_head_tail",
            Self::QuotaHybrid => "quota_hybrid",
        }
    }
}

impl fmt::Debug for MatchedBaselineArmV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedBaselineArmV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One exact label-free deterministic baseline outcome.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenMatchedBaselineOutcomeV1 {
    digest: ArtifactDigest,
    arm: MatchedBaselineArmV1,
    result: MethodResult,
}

impl FrozenMatchedBaselineOutcomeV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn arm(&self) -> MatchedBaselineArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn result(&self) -> &MethodResult {
        &self.result
    }
}

impl fmt::Debug for FrozenMatchedBaselineOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenMatchedBaselineOutcomeV1")
            .field("outcome_identity_present", &true)
            .field("arm", &self.arm)
            .field("accounting", &self.result.accounting())
            .finish()
    }
}

/// Public, annotation-free matched source-byte comparator set.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenMatchedBaselineSetV1 {
    digest: ArtifactDigest,
    matched_source_byte_budget: ByteBudget,
    outcomes: [FrozenMatchedBaselineOutcomeV1; 3],
}

impl FrozenMatchedBaselineSetV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn matched_source_byte_budget(&self) -> ByteBudget {
        self.matched_source_byte_budget
    }

    #[must_use]
    pub fn outcomes(&self) -> &[FrozenMatchedBaselineOutcomeV1; 3] {
        &self.outcomes
    }

    #[must_use]
    pub fn outcome(&self, arm: MatchedBaselineArmV1) -> &FrozenMatchedBaselineOutcomeV1 {
        &self.outcomes[baseline_arm_index(arm)]
    }

    /// This comparator matches only unique authorized source bytes selected by
    /// the Full compiled arm. It does not equate baseline bytes with compiled
    /// renderer framing or fixed overhead.
    #[must_use]
    pub const fn budget_basis_code(&self) -> &'static str {
        "full_selected_unique_source_bytes_only"
    }

    #[must_use]
    pub const fn contains_total_output_envelope_parity(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn limitation_code(&self) -> &'static str {
        "raw_method_result_bytes_not_equivalent_to_compiled_renderer_overhead"
    }
}

impl fmt::Debug for FrozenMatchedBaselineSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenMatchedBaselineSetV1")
            .field("set_identity_present", &true)
            .field(
                "matched_source_byte_budget",
                &self.matched_source_byte_budget,
            )
            .field("outcome_count", &self.outcomes.len())
            .field("budget_basis", &self.budget_basis_code())
            .field("contains_total_output_envelope_parity", &false)
            .field("limitation", &self.limitation_code())
            .finish()
    }
}

pub enum FrozenSyntheticThreeLaneSelectionDecisionV1 {
    Selected(Box<FrozenSyntheticThreeLaneSelectedV1>),
    NeedsMore(FrozenSyntheticThreeLaneNeedsMoreV1),
}

impl FrozenSyntheticThreeLaneSelectionDecisionV1 {
    #[must_use]
    pub const fn selected(&self) -> Option<&FrozenSyntheticThreeLaneSelectedV1> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<FrozenSyntheticThreeLaneNeedsMoreV1> {
        match self {
            Self::Selected(_) => None,
            Self::NeedsMore(needs_more) => Some(*needs_more),
        }
    }

    #[must_use]
    pub fn selected_event_ids(&self) -> &[EventId] {
        match self {
            Self::Selected(selected) => selected.selected_event_ids(),
            Self::NeedsMore(_) => &[],
        }
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(selected) => formatter
                .debug_struct("FrozenSyntheticThreeLaneSelectionDecisionV1")
                .field("state", &"selected")
                .field("summary", selected)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_struct("FrozenSyntheticThreeLaneSelectionDecisionV1")
                .field("state", &"needs_more")
                .field("summary", needs_more)
                .finish(),
        }
    }
}

pub struct FrozenSyntheticThreeLaneSelectionOutcomeV1 {
    digest: FrozenSyntheticThreeLaneSelectionOutcomeDigestV1,
    mask: ThreeLaneAblationMaskV1,
    budget: TotalTokenBudgetV1,
    decision: FrozenSyntheticThreeLaneSelectionDecisionV1,
    fixed_overhead_tokens: Option<u64>,
    mandatory_packet_tokens: u64,
    proposal_audits: Vec<FrozenProposalPacketAuditV1>,
}

impl FrozenSyntheticThreeLaneSelectionOutcomeV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSyntheticThreeLaneSelectionOutcomeDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn budget(&self) -> TotalTokenBudgetV1 {
        self.budget
    }

    #[must_use]
    pub const fn decision(&self) -> &FrozenSyntheticThreeLaneSelectionDecisionV1 {
        &self.decision
    }

    #[must_use]
    pub const fn fixed_overhead_tokens(&self) -> Option<u64> {
        self.fixed_overhead_tokens
    }

    #[must_use]
    pub const fn mandatory_packet_tokens(&self) -> u64 {
        self.mandatory_packet_tokens
    }

    #[must_use]
    pub fn proposal_audits(&self) -> &[FrozenProposalPacketAuditV1] {
        &self.proposal_audits
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticThreeLaneSelectionOutcomeV1")
            .field("outcome_identity_present", &true)
            .field("mask", &self.mask)
            .field("budget", &self.budget)
            .field("decision", &self.decision)
            .field("fixed_overhead_tokens", &self.fixed_overhead_tokens)
            .field("mandatory_packet_tokens", &self.mandatory_packet_tokens)
            .field("proposal_audit_count", &self.proposal_audits.len())
            .finish()
    }
}

pub struct FrozenSyntheticThreeLaneSelectionCaseV1 {
    digest: FrozenSyntheticThreeLaneSelectionCaseDigestV1,
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    source_public_batch_digest: crate::FrozenPublicThreeLaneAblationBatchDigestV1,
    acquisition_class: ExpectedAcquisitionClassV1,
    shared_producer_wall_time_nanos: u64,
    shared_producer_peak_rss_bytes: u64,
    outcomes: [FrozenSyntheticThreeLaneSelectionOutcomeV1; 4],
    full_selection_oracle: crate::FrozenSyntheticFullSelectionOracleV1,
    matched_baselines: FrozenMatchedBaselineSetV1,
}

impl FrozenSyntheticThreeLaneSelectionCaseV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSyntheticThreeLaneSelectionCaseDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn source_public_batch_digest(
        &self,
    ) -> crate::FrozenPublicThreeLaneAblationBatchDigestV1 {
        self.source_public_batch_digest
    }

    #[must_use]
    pub const fn acquisition_class(&self) -> ExpectedAcquisitionClassV1 {
        self.acquisition_class
    }

    #[must_use]
    pub const fn shared_producer_wall_time_nanos(&self) -> u64 {
        self.shared_producer_wall_time_nanos
    }

    #[must_use]
    pub const fn shared_producer_peak_rss_bytes(&self) -> u64 {
        self.shared_producer_peak_rss_bytes
    }

    #[must_use]
    pub fn outcomes(&self) -> &[FrozenSyntheticThreeLaneSelectionOutcomeV1; 4] {
        &self.outcomes
    }

    #[must_use]
    pub fn outcome(
        &self,
        mask: ThreeLaneAblationMaskV1,
    ) -> &FrozenSyntheticThreeLaneSelectionOutcomeV1 {
        &self.outcomes[mask_index(mask)]
    }

    #[must_use]
    pub const fn full_selection_oracle(&self) -> &crate::FrozenSyntheticFullSelectionOracleV1 {
        &self.full_selection_oracle
    }

    #[must_use]
    pub const fn matched_baselines(&self) -> &FrozenMatchedBaselineSetV1 {
        &self.matched_baselines
    }
}

impl fmt::Debug for FrozenSyntheticThreeLaneSelectionCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticThreeLaneSelectionCaseV1")
            .field("case_identity_present", &true)
            .field("case", &self.case)
            .field("family", &self.family)
            .field("source_public_batch_binding_present", &true)
            .field("acquisition_class", &self.acquisition_class)
            .field("outcome_count", &self.outcomes.len())
            .field("full_selection_oracle", &self.full_selection_oracle)
            .field("matched_baselines", &self.matched_baselines)
            .field("shared_batch_cost_full_charged", &true)
            .finish()
    }
}

/// Complete public selector/render package frozen before annotations enter.
pub struct FrozenPublicSyntheticThreeLaneSelectionCorpusV1 {
    digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    source_public_corpus_digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    scope: SyntheticThreeLaneCorpusScopeV1,
    budget_schedule: SyntheticThreeLaneSelectionBudgetScheduleV1,
    renderer_digest: ArtifactDigest,
    tokenizer_digest: ArtifactDigest,
    cases: [FrozenSyntheticThreeLaneSelectionCaseV1; 6],
}

impl FrozenPublicSyntheticThreeLaneSelectionCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn source_public_corpus_digest(
        &self,
    ) -> FrozenPublicSyntheticThreeLaneCorpusDigestV1 {
        self.source_public_corpus_digest
    }

    #[must_use]
    pub const fn scope(&self) -> SyntheticThreeLaneCorpusScopeV1 {
        self.scope
    }

    #[must_use]
    pub const fn budget_schedule(&self) -> SyntheticThreeLaneSelectionBudgetScheduleV1 {
        self.budget_schedule
    }

    #[must_use]
    pub const fn renderer_digest(&self) -> ArtifactDigest {
        self.renderer_digest
    }

    #[must_use]
    pub const fn tokenizer_digest(&self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub fn cases(&self) -> &[FrozenSyntheticThreeLaneSelectionCaseV1; 6] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SyntheticThreeLaneAblationCaseV1,
    ) -> &FrozenSyntheticThreeLaneSelectionCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub const fn contains_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn staging_trust_boundary_code(&self) -> &'static str {
        "public_selection_and_render_data_boundary_not_external_temporal_attestation"
    }
}

impl fmt::Debug for FrozenPublicSyntheticThreeLaneSelectionCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicSyntheticThreeLaneSelectionCorpusV1")
            .field("corpus_identity_present", &true)
            .field("source_public_corpus_binding_present", &true)
            .field("scope", &self.scope)
            .field("budget_schedule", &self.budget_schedule)
            .field("renderer_identity_present", &true)
            .field("tokenizer_identity_present", &true)
            .field("case_count", &self.cases.len())
            .field("contains_annotations", &false)
            .field(
                "staging_trust_boundary",
                &self.staging_trust_boundary_code(),
            )
            .finish()
    }
}

/// Run and freeze all 24 real selector/compiled-render outcomes before any
/// governed annotation is accepted.
pub fn freeze_public_synthetic_three_lane_selection_corpus_v1<'a, Inputs>(
    source: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    schedule: SyntheticThreeLaneSelectionBudgetScheduleV1,
    inputs: Inputs,
) -> Result<FrozenPublicSyntheticThreeLaneSelectionCorpusV1, ThreeLaneSelectionCorpusErrorV1>
where
    Inputs: IntoIterator<Item = SyntheticThreeLaneSelectionPublicCaseInputV1<'a>>,
{
    let mut by_case = std::array::from_fn::<_, 6, _>(|_| None);
    for input in inputs {
        let index = case_index(input.case);
        if by_case[index].replace(input).is_some() {
            return Err(ThreeLaneSelectionCorpusErrorV1::DuplicateCase);
        }
    }
    if by_case.iter().any(Option::is_none) {
        return Err(ThreeLaneSelectionCorpusErrorV1::MissingCases {
            count: by_case.iter().filter(|entry| entry.is_none()).count(),
        });
    }
    let tokenizer = Utf8ByteTokenizerV1::new();
    let cases = by_case
        .into_iter()
        .zip(SyntheticThreeLaneAblationCaseV1::ALL)
        .map(|(input, case)| {
            let input = input.ok_or(ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 })?;
            freeze_selection_case(source, schedule, case, input, &tokenizer)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [FrozenSyntheticThreeLaneSelectionCaseV1; 6] = cases
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 })?;
    let renderer_digest = compiled_renderer_digest_v1();
    let tokenizer_digest = utf8_byte_tokenizer_digest_v1();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_SELECTION_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, source.digest().as_bytes())?;
    update_field(&mut hasher, source.scope().code().as_bytes())?;
    update_field(&mut hasher, schedule.digest().as_bytes())?;
    update_field(&mut hasher, renderer_digest.as_bytes())?;
    update_field(&mut hasher, tokenizer_digest.as_bytes())?;
    for case in &cases {
        update_field(&mut hasher, case.digest.as_bytes())?;
    }
    Ok(FrozenPublicSyntheticThreeLaneSelectionCorpusV1 {
        digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1(hasher.finalize().into()),
        source_public_corpus_digest: source.digest(),
        scope: source.scope(),
        budget_schedule: schedule,
        renderer_digest,
        tokenizer_digest,
        cases,
    })
}

fn freeze_selection_case(
    source: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    schedule: SyntheticThreeLaneSelectionBudgetScheduleV1,
    case: SyntheticThreeLaneAblationCaseV1,
    input: SyntheticThreeLaneSelectionPublicCaseInputV1<'_>,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<FrozenSyntheticThreeLaneSelectionCaseV1, ThreeLaneSelectionCorpusErrorV1> {
    if input.case != case || input.reference_authorized_at >= input.reference_expires_at {
        return Err(ThreeLaneSelectionCorpusErrorV1::CaseBindingMismatch);
    }
    let source_case = source.case(case);
    let source_batch = source_case.batch();
    if derive_question_digest_v1(input.question_bytes) != source_batch.ablations().question_digest()
        || source_batch.public_case().question_digest()
            != source_batch.ablations().question_digest()
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::CaseBindingMismatch);
    }
    if source_batch.acquisition_binding().retrieval_id() != input.ledger.retrieval_id()
        || source_batch.acquisition_binding().plan_id() != input.ledger.plan_id()
        || source_batch.acquisition_binding().plan_digest() != input.ledger.plan_digest()
        || source_batch.acquisition_binding().acquisition_receipt_id()
            != input.ledger.acquisition_receipt_id()
        || source_batch.acquisition_binding().source_identity_digest()
            != input.ledger.source_identity_digest()
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::LedgerBindingMismatch);
    }
    let budget = schedule.budget(case);
    let outcomes = ThreeLaneAblationMaskV1::ALL
        .into_iter()
        .map(|mask| {
            validate_prepared_binding(
                source_batch.ablations(),
                input.prepared,
                input.ledger,
                mask,
            )?;
            let configured = input.prepared.configuration(mask);
            let decision =
                select_prepared_three_lane_ablation_v1(input.ledger, configured, budget, tokenizer)
                    .map_err(ThreeLaneSelectionCorpusErrorV1::Compiler)?;
            freeze_selection_outcome(
                input.ledger,
                configured.prepared(),
                mask,
                budget,
                decision,
                input.reference_authorized_at,
                input.reference_expires_at,
                tokenizer,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outcomes: [FrozenSyntheticThreeLaneSelectionOutcomeV1; 4] = outcomes
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::MissingMasks)?;
    let full_selection_oracle = freeze_synthetic_full_selection_oracle_v1(
        case,
        source_batch.digest(),
        input.ledger,
        input.prepared.configuration(ThreeLaneAblationMaskV1::Full),
        budget,
        tokenizer,
        &outcomes[mask_index(ThreeLaneAblationMaskV1::Full)],
    )?;
    let matched_baselines = freeze_matched_baselines(
        input.ledger,
        input.question_bytes,
        outcomes[mask_index(ThreeLaneAblationMaskV1::Full)]
            .decision
            .selected()
            .map_or(
                0,
                FrozenSyntheticThreeLaneSelectedV1::selected_unique_source_bytes,
            ),
    )?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_SELECTION_CASE_DOMAIN_V1)?;
    update_field(&mut hasher, case.identity_digest().as_bytes())?;
    update_field(&mut hasher, case.family().identity_digest().as_bytes())?;
    update_field(&mut hasher, source_batch.digest().as_bytes())?;
    update_u64(&mut hasher, budget.tokens());
    update_u64(&mut hasher, source_batch.shared_wall_time_nanos());
    update_u64(&mut hasher, source_batch.shared_peak_rss_bytes());
    for outcome in &outcomes {
        update_field(&mut hasher, outcome.digest.as_bytes())?;
    }
    update_field(&mut hasher, full_selection_oracle.digest().as_bytes())?;
    update_field(&mut hasher, matched_baselines.digest.as_bytes())?;
    Ok(FrozenSyntheticThreeLaneSelectionCaseV1 {
        digest: FrozenSyntheticThreeLaneSelectionCaseDigestV1(hasher.finalize().into()),
        case,
        family: case.family(),
        source_public_batch_digest: source_batch.digest(),
        acquisition_class: source_batch.acquisition_binding().acquisition_class(),
        shared_producer_wall_time_nanos: source_batch.shared_wall_time_nanos(),
        shared_producer_peak_rss_bytes: source_batch.shared_peak_rss_bytes(),
        outcomes,
        full_selection_oracle,
        matched_baselines,
    })
}

fn freeze_matched_baselines(
    ledger: &EventLedger,
    question_bytes: &[u8],
    matched_source_bytes: u64,
) -> Result<FrozenMatchedBaselineSetV1, ThreeLaneSelectionCorpusErrorV1> {
    let matched_source_bytes = usize::try_from(matched_source_bytes)
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
    let budget = ByteBudget::new(matched_source_bytes);
    let quarter = matched_source_bytes / 4;
    let remainder = matched_source_bytes % 4;
    let quota = QuotaHybrid::new(QuotaHybridConfig::new(
        quarter
            .checked_add(remainder)
            .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?,
        quarter,
        quarter,
        quarter,
        2,
        2,
        3,
    ));
    let input = MethodInput::new(ledger, question_bytes, budget);
    let results = [
        RawChronological
            .run(input)
            .map_err(ThreeLaneSelectionCorpusErrorV1::Method)?,
        GrepHeadTail::default()
            .run(input)
            .map_err(ThreeLaneSelectionCorpusErrorV1::Method)?,
        quota
            .run(input)
            .map_err(ThreeLaneSelectionCorpusErrorV1::Method)?,
    ];
    let outcomes = MatchedBaselineArmV1::ALL
        .into_iter()
        .zip(results)
        .map(|(arm, result)| {
            let digest = derive_baseline_outcome_digest(arm, &result)?;
            Ok(FrozenMatchedBaselineOutcomeV1 {
                digest,
                arm,
                result,
            })
        })
        .collect::<Result<Vec<_>, ThreeLaneSelectionCorpusErrorV1>>()?;
    let outcomes: [FrozenMatchedBaselineOutcomeV1; 3] = outcomes
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch)?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, MATCHED_BASELINE_SET_DOMAIN_V1)?;
    update_u64(&mut hasher, checked_u64(matched_source_bytes)?);
    for outcome in &outcomes {
        update_field(&mut hasher, outcome.digest.as_bytes())?;
    }
    Ok(FrozenMatchedBaselineSetV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        matched_source_byte_budget: budget,
        outcomes,
    })
}

fn derive_baseline_outcome_digest(
    arm: MatchedBaselineArmV1,
    result: &MethodResult,
) -> Result<ArtifactDigest, ThreeLaneSelectionCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, MATCHED_BASELINE_OUTCOME_DOMAIN_V1)?;
    update_field(&mut hasher, arm.code().as_bytes())?;
    update_field(&mut hasher, result.method().name().as_bytes())?;
    update_field(&mut hasher, result.method().version().as_bytes())?;
    update_field(&mut hasher, result.retrieval_id().as_bytes())?;
    update_u64(
        &mut hasher,
        checked_u64(result.candidate_event_ids().len())?,
    );
    for event_id in result.candidate_event_ids() {
        update_field(&mut hasher, event_id.as_bytes())?;
    }
    update_u64(&mut hasher, checked_u64(result.selected().len())?);
    for selected in result.selected() {
        update_field(&mut hasher, selected.event_id().as_bytes())?;
        update_u64(&mut hasher, selected.ordinal());
        update_u64(&mut hasher, checked_u64(selected.source_byte_cost())?);
        update_u64(&mut hasher, checked_u64(selected.reasons().len())?);
        for reason in selected.reasons() {
            update_field(&mut hasher, reason.code().as_bytes())?;
        }
    }
    let accounting = result.accounting();
    for value in [
        accounting.received_event_count(),
        accounting.candidate_event_count(),
        accounting.candidate_cost().unique_source_bytes(),
        accounting.selected_event_count(),
        accounting.retained_raw_event_count(),
        accounting.budget_excluded_candidate_count(),
        accounting.selected_source_bytes(),
        accounting.budget().bytes(),
    ] {
        update_u64(&mut hasher, checked_u64(value)?);
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn validate_prepared_binding(
    frozen: &crate::FrozenThreeLaneAblationSetV1,
    prepared: &PreparedThreeLaneAblationSetV1,
    ledger: &EventLedger,
    mask: ThreeLaneAblationMaskV1,
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    let configured = prepared.configuration(mask);
    let receipt = configured.prepared().receipt();
    let input = receipt.input();
    let universe = frozen.configuration(mask).universe();
    let producer = universe.producer();
    if configured.mask() != mask
        || configured.config_digest() != producer.config_artifact_digest()
        || receipt.digest() != producer.producer_receipt_artifact_digest()
        || input.question_digest() != frozen.question_digest()
        || input.retrieval_id() != ledger.retrieval_id()
        || input.plan_id() != ledger.plan_id()
        || input.plan_digest() != ledger.plan_digest()
        || input.source_identity_digest() != ledger.source_identity_digest()
        || input.acquisition_receipt_id() != ledger.acquisition_receipt_id()
        || universe.acquisition_binding().retrieval_id() != ledger.retrieval_id()
        || universe.acquisition_binding().plan_id() != ledger.plan_id()
        || universe.acquisition_binding().plan_digest() != ledger.plan_digest()
        || universe.acquisition_binding().acquisition_receipt_id()
            != ledger.acquisition_receipt_id()
        || universe.acquisition_binding().source_identity_digest()
            != ledger.source_identity_digest()
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch);
    }
    let prepared_packets = configured
        .prepared()
        .proposal_packets()
        .iter()
        .map(|packet| {
            (
                ProducerProposalIdV1::from_bytes(*packet.id().as_bytes()),
                packet.event_ids().iter().copied().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let frozen_packets = universe
        .proposals()
        .iter()
        .map(|packet| {
            (
                packet.id(),
                packet
                    .member_event_ids()
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if prepared_packets != frozen_packets {
        return Err(ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn freeze_selection_outcome(
    ledger: &EventLedger,
    prepared: &PreparedThreeLaneProposalUniverseV1,
    mask: ThreeLaneAblationMaskV1,
    budget: TotalTokenBudgetV1,
    decision: PreparedThreeLaneSelectionDecisionV1,
    reference_authorized_at: UnixTimestampNanos,
    reference_expires_at: UnixTimestampNanos,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<FrozenSyntheticThreeLaneSelectionOutcomeV1, ThreeLaneSelectionCorpusErrorV1> {
    let selection = match &decision {
        PreparedThreeLaneSelectionDecisionV1::Selected(selected) => Some(selected.selection()),
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(_) => None,
    };
    let fixed_overhead_tokens = prepared
        .certification()
        .map(|certification| certification.fixed_overhead().upper_bound_tokens());
    let mandatory_packet_tokens =
        prepared
            .mandatory()
            .iter()
            .try_fold(0_u64, |sum, mandatory| {
                let cost = prepared
                    .proposal_packets()
                    .iter()
                    .find(|packet| packet.id() == mandatory.packet_id())
                    .ok_or(ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch)?
                    .composable_token_upper_bound()
                    .upper_bound_tokens();
                sum.checked_add(cost)
                    .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)
            })?;
    let proposal_audits = build_proposal_audits(prepared, selection)?;
    let frozen = match decision {
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            let reason = needs_more.reason();
            let class = if reason == ThreeLaneNeedsMoreV1::NoProposalPackets {
                SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse
            } else {
                SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible
            };
            FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(
                FrozenSyntheticThreeLaneNeedsMoreV1 {
                    proposal_receipt_digest: needs_more.receipt().digest(),
                    reason,
                    class,
                },
            )
        }
        PreparedThreeLaneSelectionDecisionV1::Selected(selected) => {
            let selection = selected.selection().clone();
            let references = selection
                .packets()
                .iter()
                .map(|packet| {
                    EvidenceReferenceV1::issue(
                        selected.result_id(),
                        packet
                            .packet()
                            .event_ids()
                            .iter()
                            .copied()
                            .map(EvidenceTargetRef::Event),
                        [ExpansionRelationV1::Exact],
                        reference_authorized_at,
                        reference_expires_at,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(ThreeLaneSelectionCorpusErrorV1::Reference)?;
            let rendered = render_cost_certified_compiled_log_brief_v1(
                ledger,
                selected.result_id(),
                selected.question_digest(),
                ledger.plan_digest(),
                selection.clone(),
                references,
                reference_authorized_at,
                tokenizer,
                selected.certification(),
            )
            .map_err(ThreeLaneSelectionCorpusErrorV1::Render)?
            .into_owned();
            let selected_packet_ids = selection
                .packets()
                .iter()
                .map(|packet| ProducerProposalIdV1::from_bytes(*packet.packet().id().as_bytes()))
                .collect::<Vec<_>>();
            let selected_event_ids = selection
                .packets()
                .iter()
                .flat_map(|packet| packet.packet().event_ids().iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let selected_unique_source_bytes =
                selected_event_ids.iter().try_fold(0_u64, |sum, event_id| {
                    let length = u64::try_from(
                        ledger
                            .event(*event_id)
                            .map_err(|_| ThreeLaneSelectionCorpusErrorV1::SelectedEventMismatch)?
                            .raw()
                            .len(),
                    )
                    .map_err(|_| ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
                    sum.checked_add(length)
                        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)
                })?;
            let artifact_digest =
                ArtifactDigest::from_bytes(Sha256::digest(rendered.text()).into());
            FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(Box::new(
                FrozenSyntheticThreeLaneSelectedV1 {
                    proposal_receipt_digest: selected.proposal_receipt().digest(),
                    selected_packet_ids,
                    selected_event_ids,
                    selected_unique_source_bytes,
                    coverage_only_token_charge: selection.coverage_only_token_cost(),
                    coverage_only_token_limit: selection.coverage_only_token_limit(),
                    render: FrozenSyntheticCompiledRenderV1 {
                        artifact_digest,
                        rendered,
                    },
                },
            ))
        }
    };
    let digest = derive_outcome_digest(
        mask,
        budget,
        &frozen,
        fixed_overhead_tokens,
        mandatory_packet_tokens,
        &proposal_audits,
    )?;
    Ok(FrozenSyntheticThreeLaneSelectionOutcomeV1 {
        digest,
        mask,
        budget,
        decision: frozen,
        fixed_overhead_tokens,
        mandatory_packet_tokens,
        proposal_audits,
    })
}

fn build_proposal_audits(
    prepared: &PreparedThreeLaneProposalUniverseV1,
    selection: Option<&SelectionV1>,
) -> Result<Vec<FrozenProposalPacketAuditV1>, ThreeLaneSelectionCorpusErrorV1> {
    let facets = prepared
        .facets()
        .iter()
        .map(|facet| (facet.id(), (facet.kind(), facet.weight().micros())))
        .collect::<BTreeMap<_, _>>();
    let mandatory_by_packet = prepared
        .mandatory()
        .iter()
        .map(|mandatory| {
            (
                mandatory.packet_id(),
                mandatory.validated_identifier_facet_id(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut selected_by_packet = BTreeMap::new();
    let mut selected_coverage = BTreeMap::<FacetIdV1, Vec<(ProducerProposalIdV1, u32)>>::new();
    if let Some(selection) = selection {
        for selected in selection.packets() {
            if selected_by_packet
                .insert(
                    selected.packet().id(),
                    (
                        selected.marginal_gain().numerator(),
                        selected.forcing_constraint(),
                    ),
                )
                .is_some()
            {
                return Err(ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch);
            }
            for affinity in selected.affinities() {
                selected_coverage
                    .entry(affinity.facet_id())
                    .or_default()
                    .push((
                        ProducerProposalIdV1::from_bytes(*selected.packet().id().as_bytes()),
                        affinity.affinity().micros(),
                    ));
            }
        }
        for entries in selected_coverage.values_mut() {
            entries.sort_unstable_by(|left, right| {
                right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
            });
        }
    }

    let remaining_total_budget = selection.map(|selection| {
        selection
            .total_token_budget()
            .tokens()
            .saturating_sub(selection.reserved_fixed_overhead().upper_bound_tokens())
            .saturating_sub(selection.selected_packet_cost())
    });
    let remaining_coverage_budget = selection.map(|selection| {
        selection
            .coverage_only_token_limit()
            .saturating_sub(selection.coverage_only_token_cost())
    });

    let mut audits = Vec::with_capacity(prepared.proposal_packets().len());
    for packet in prepared.proposal_packets() {
        let packet_id = ProducerProposalIdV1::from_bytes(*packet.id().as_bytes());
        let mut affinities = Vec::with_capacity(packet.affinities().len());
        for affinity in packet.affinities() {
            let (kind, weight_micros) = facets
                .get(&affinity.facet_id())
                .copied()
                .ok_or(ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch)?;
            affinities.push(FrozenProposalAffinityAuditV1 {
                facet_id: affinity.facet_id(),
                kind,
                weight_micros,
                affinity_micros: affinity.affinity().micros(),
            });
        }
        affinities.sort_unstable_by_key(|affinity| affinity.facet_id);

        let mandatory_facet_ids = mandatory_by_packet
            .get(&packet.id())
            .copied()
            .into_iter()
            .collect::<Vec<_>>();
        let selected_facts = selected_by_packet.get(&packet.id()).copied();
        let selected = selected_facts.is_some();
        let (post_selection_marginal_gain_numerator, coverage_only_after_selection) =
            if selection.is_some() && !selected {
                let mut gain = 0_u64;
                let mut has_primary_gain = false;
                for affinity in &affinities {
                    let selected = selected_coverage
                        .get(&affinity.facet_id)
                        .map(Vec::as_slice)
                        .unwrap_or_default();
                    let cardinality = usize::from(affinity.kind.saturation_cardinality().count());
                    let occupied_threshold = selected
                        .get(cardinality.saturating_sub(1))
                        .map(|entry| entry.1)
                        .unwrap_or(0);
                    let delta = affinity.affinity_micros.saturating_sub(occupied_threshold);
                    let contribution = u64::from(affinity.weight_micros)
                        .checked_mul(u64::from(delta))
                        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
                    gain = gain
                        .checked_add(contribution)
                        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
                    if contribution > 0 && !affinity.kind.is_coverage_only() {
                        has_primary_gain = true;
                    }
                }
                (Some(gain), Some(gain > 0 && !has_primary_gain))
            } else {
                (None, None)
            };

        let packet_cost = packet.composable_token_upper_bound().upper_bound_tokens();
        let fits_remaining_total_budget = remaining_total_budget
            .filter(|_| !selected)
            .map(|remaining| packet_cost <= remaining);
        let fits_remaining_coverage_slice = remaining_coverage_budget
            .filter(|_| !selected)
            .zip(coverage_only_after_selection)
            .map(|(remaining, coverage_only)| !coverage_only || packet_cost <= remaining);

        let mut saturations = Vec::new();
        if selection.is_some() && !selected {
            for affinity in &affinities {
                let cardinality = usize::from(affinity.kind.saturation_cardinality().count());
                for &(selected_packet_id, selected_affinity_micros) in selected_coverage
                    .get(&affinity.facet_id)
                    .into_iter()
                    .flat_map(|entries| entries.iter().take(cardinality))
                    .filter(|entry| entry.1 >= affinity.affinity_micros)
                {
                    saturations.push(FrozenFacetSaturationAuditV1 {
                        facet_id: affinity.facet_id,
                        kind: affinity.kind,
                        candidate_affinity_micros: affinity.affinity_micros,
                        selected_packet_id,
                        selected_affinity_micros,
                    });
                }
            }
            saturations.sort_unstable_by_key(|entry| (entry.facet_id, entry.selected_packet_id));
        }

        audits.push(FrozenProposalPacketAuditV1 {
            packet_id,
            member_event_ids: packet.event_ids().to_vec(),
            token_cost_upper_bound: packet_cost,
            affinities,
            mandatory_facet_ids,
            selected,
            selected_marginal_gain_numerator: selected_facts.map(|facts| facts.0),
            selected_constraint: selected_facts.map(|facts| facts.1),
            post_selection_marginal_gain_numerator,
            fits_remaining_total_budget,
            fits_remaining_coverage_slice,
            saturations,
        });
    }
    audits.sort_unstable_by_key(|audit| audit.packet_id);
    Ok(audits)
}

fn hash_proposal_audit(
    hasher: &mut Sha256,
    audit: &FrozenProposalPacketAuditV1,
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    update_field(hasher, audit.packet_id.as_bytes())?;
    update_u64(hasher, checked_u64(audit.member_event_ids.len())?);
    for event_id in &audit.member_event_ids {
        update_field(hasher, event_id.as_bytes())?;
    }
    update_u64(hasher, audit.token_cost_upper_bound);
    update_u64(hasher, checked_u64(audit.affinities.len())?);
    for affinity in &audit.affinities {
        update_field(hasher, affinity.facet_id.as_bytes())?;
        update_field(hasher, affinity.kind.code().as_bytes())?;
        hasher.update(affinity.weight_micros.to_le_bytes());
        hasher.update(affinity.affinity_micros.to_le_bytes());
    }
    update_u64(hasher, checked_u64(audit.mandatory_facet_ids.len())?);
    for facet_id in &audit.mandatory_facet_ids {
        update_field(hasher, facet_id.as_bytes())?;
    }
    hasher.update([u8::from(audit.selected)]);
    update_optional_u64(hasher, audit.selected_marginal_gain_numerator);
    match audit.selected_constraint {
        Some(constraint) => {
            hasher.update([1]);
            update_field(hasher, constraint.code().as_bytes())?;
            match constraint.mandatory_facet_id() {
                Some(facet_id) => {
                    hasher.update([1]);
                    update_field(hasher, facet_id.as_bytes())?;
                }
                None => hasher.update([0]),
            }
        }
        None => hasher.update([0]),
    }
    update_optional_u64(hasher, audit.post_selection_marginal_gain_numerator);
    update_optional_bool(hasher, audit.fits_remaining_total_budget);
    update_optional_bool(hasher, audit.fits_remaining_coverage_slice);
    update_u64(hasher, checked_u64(audit.saturations.len())?);
    for saturation in &audit.saturations {
        update_field(hasher, saturation.facet_id.as_bytes())?;
        update_field(hasher, saturation.kind.code().as_bytes())?;
        hasher.update(saturation.candidate_affinity_micros.to_le_bytes());
        update_field(hasher, saturation.selected_packet_id.as_bytes())?;
        hasher.update(saturation.selected_affinity_micros.to_le_bytes());
    }
    Ok(())
}

fn derive_outcome_digest(
    mask: ThreeLaneAblationMaskV1,
    budget: TotalTokenBudgetV1,
    decision: &FrozenSyntheticThreeLaneSelectionDecisionV1,
    fixed_overhead_tokens: Option<u64>,
    mandatory_packet_tokens: u64,
    proposal_audits: &[FrozenProposalPacketAuditV1],
) -> Result<FrozenSyntheticThreeLaneSelectionOutcomeDigestV1, ThreeLaneSelectionCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_SELECTION_OUTCOME_DOMAIN_V1)?;
    hasher.update([mask.bits()]);
    update_u64(&mut hasher, budget.tokens());
    update_optional_u64(&mut hasher, fixed_overhead_tokens);
    update_u64(&mut hasher, mandatory_packet_tokens);
    update_u64(&mut hasher, checked_u64(proposal_audits.len())?);
    for audit in proposal_audits {
        hash_proposal_audit(&mut hasher, audit)?;
    }
    match decision {
        FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            hasher.update([0]);
            update_field(&mut hasher, needs_more.proposal_receipt_digest.as_bytes())?;
            update_field(&mut hasher, needs_more.reason.code().as_bytes())?;
            update_field(&mut hasher, needs_more.class.code().as_bytes())?;
        }
        FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(selected) => {
            hasher.update([1]);
            update_field(&mut hasher, selected.proposal_receipt_digest.as_bytes())?;
            update_u64(
                &mut hasher,
                checked_u64(selected.selected_packet_ids.len())?,
            );
            for packet_id in &selected.selected_packet_ids {
                update_field(&mut hasher, packet_id.as_bytes())?;
            }
            update_u64(&mut hasher, checked_u64(selected.selected_event_ids.len())?);
            for event_id in &selected.selected_event_ids {
                update_field(&mut hasher, event_id.as_bytes())?;
            }
            update_u64(&mut hasher, selected.selected_unique_source_bytes);
            update_u64(&mut hasher, selected.coverage_only_token_charge);
            update_u64(&mut hasher, selected.coverage_only_token_limit);
            update_field(&mut hasher, selected.render.artifact_digest.as_bytes())?;
            update_u64(&mut hasher, selected.render.token_count());
            update_u64(&mut hasher, selected.render.byte_count());
        }
    }
    Ok(FrozenSyntheticThreeLaneSelectionOutcomeDigestV1(
        hasher.finalize().into(),
    ))
}

/// Governed-stage input. The exact selection case, source producer batch,
/// annotation artifact join, ledger, and block universe are joined as a
/// bijection before any recall is computed.
pub struct GovernedSyntheticThreeLaneSelectionCaseInputV1<'input, 'ledger> {
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    public_selection_case_digest: FrozenSyntheticThreeLaneSelectionCaseDigestV1,
    source_public_batch_digest: crate::FrozenPublicThreeLaneAblationBatchDigestV1,
    artifact_join: GovernedCaseArtifactJoinV1,
    annotation: &'input EvidentrailBenchAnnotationSpecV1,
    ledger: &'ledger EventLedger,
    block_index: &'input BlockIndex<'ledger>,
}

impl<'input, 'ledger> GovernedSyntheticThreeLaneSelectionCaseInputV1<'input, 'ledger> {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        case: SyntheticThreeLaneAblationCaseV1,
        family: SyntheticThreeLaneAblationFamilyV1,
        public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
        public_selection_case_digest: FrozenSyntheticThreeLaneSelectionCaseDigestV1,
        source_public_batch_digest: crate::FrozenPublicThreeLaneAblationBatchDigestV1,
        artifact_join: GovernedCaseArtifactJoinV1,
        annotation: &'input EvidentrailBenchAnnotationSpecV1,
        ledger: &'ledger EventLedger,
        block_index: &'input BlockIndex<'ledger>,
    ) -> Self {
        Self {
            case,
            family,
            public_selection_corpus_digest,
            public_selection_case_digest,
            source_public_batch_digest,
            artifact_join,
            annotation,
            ledger,
            block_index,
        }
    }

    pub(crate) const fn oracle_case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    pub(crate) const fn oracle_source_public_batch_digest(
        &self,
    ) -> crate::FrozenPublicThreeLaneAblationBatchDigestV1 {
        self.source_public_batch_digest
    }

    pub(crate) const fn oracle_annotation(&self) -> &EvidentrailBenchAnnotationSpecV1 {
        self.annotation
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneSelectionCaseInputV1<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneSelectionCaseInputV1")
            .field("case", &self.case)
            .field("family", &self.family)
            .field("public_selection_bindings_present", &true)
            .field("source_public_batch_binding_present", &true)
            .field("artifact_join", &self.artifact_join)
            .field("annotation_identity_present", &true)
            .field("ledger_binding_present", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequiredEventSelectionResidualV1 {
    None,
    SelectedRequiredEventMiss,
    EmptyProposalUniverse,
    BudgetInfeasible,
}

impl RequiredEventSelectionResidualV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SelectedRequiredEventMiss => "selected_required_event_miss",
            Self::EmptyProposalUniverse => "empty_proposal_universe",
            Self::BudgetInfeasible => "budget_infeasible",
        }
    }
}

impl fmt::Debug for RequiredEventSelectionResidualV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredEventSelectionResidualV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Governed exact-recall/accounting result for one label-free frozen matched
/// source-byte baseline arm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedMatchedBaselineOutcomeV1 {
    arm: MatchedBaselineArmV1,
    public_outcome_digest: ArtifactDigest,
    evaluation: GovernedCaseEvaluationV1,
}

impl GovernedMatchedBaselineOutcomeV1 {
    #[must_use]
    pub const fn arm(self) -> MatchedBaselineArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn public_outcome_digest(self) -> ArtifactDigest {
        self.public_outcome_digest
    }

    #[must_use]
    pub const fn evaluation(self) -> GovernedCaseEvaluationV1 {
        self.evaluation
    }
}

impl fmt::Debug for GovernedMatchedBaselineOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedMatchedBaselineOutcomeV1")
            .field("arm", &self.arm)
            .field("public_outcome_binding_present", &true)
            .field("evaluation", &self.evaluation)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequiredEventSelectionDispositionV1 {
    SelectedAndRendered,
    CandidateAbsent,
    ObjectiveSaturated,
    BudgetInfeasible,
    SelectorOrderingUnattributed,
}

impl RequiredEventSelectionDispositionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelectedAndRendered => "selected_and_rendered",
            Self::CandidateAbsent => "candidate_absent",
            Self::ObjectiveSaturated => "objective_saturated",
            Self::BudgetInfeasible => "budget_infeasible",
            Self::SelectorOrderingUnattributed => "selector_ordering_unattributed",
        }
    }
}

impl fmt::Debug for RequiredEventSelectionDispositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredEventSelectionDispositionV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AlternativeOracleBudgetFeasibilityV1 {
    Feasible,
    Infeasible,
    Unrepresentable,
    BoundNotEvaluated,
}

impl AlternativeOracleBudgetFeasibilityV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Feasible => "feasible",
            Self::Infeasible => "infeasible",
            Self::Unrepresentable => "unrepresentable",
            Self::BoundNotEvaluated => "bound_not_evaluated",
        }
    }
}

impl fmt::Debug for AlternativeOracleBudgetFeasibilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlternativeOracleBudgetFeasibilityV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Governed attribution for one required event. Packet audits are cloned from
/// the label-free public freeze; no post-label candidate facts are generated.
#[derive(Clone, PartialEq, Eq)]
pub struct RequiredEventSelectionAttributionV1 {
    event_id: EventId,
    containing_packets: Vec<FrozenProposalPacketAuditV1>,
    disposition: RequiredEventSelectionDispositionV1,
}

impl RequiredEventSelectionAttributionV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub fn containing_packets(&self) -> &[FrozenProposalPacketAuditV1] {
        &self.containing_packets
    }

    #[must_use]
    pub const fn disposition(&self) -> RequiredEventSelectionDispositionV1 {
        self.disposition
    }
}

impl fmt::Debug for RequiredEventSelectionAttributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredEventSelectionAttributionV1")
            .field("event_identity_present", &true)
            .field("containing_packet_count", &self.containing_packets.len())
            .field("disposition", &self.disposition)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RequiredAlternativeSelectionAttributionV1 {
    requirement_index: u64,
    alternative_index: u64,
    all_members_in_proposal_universe: bool,
    minimum_compiled_token_bound: Option<u64>,
    oracle_budget_feasibility: AlternativeOracleBudgetFeasibilityV1,
    events: Vec<RequiredEventSelectionAttributionV1>,
}

impl RequiredAlternativeSelectionAttributionV1 {
    #[must_use]
    pub const fn requirement_index(&self) -> u64 {
        self.requirement_index
    }

    #[must_use]
    pub const fn alternative_index(&self) -> u64 {
        self.alternative_index
    }

    #[must_use]
    pub const fn all_members_in_proposal_universe(&self) -> bool {
        self.all_members_in_proposal_universe
    }

    #[must_use]
    pub const fn minimum_compiled_token_bound(&self) -> Option<u64> {
        self.minimum_compiled_token_bound
    }

    #[must_use]
    pub const fn oracle_budget_feasibility(&self) -> AlternativeOracleBudgetFeasibilityV1 {
        self.oracle_budget_feasibility
    }

    #[must_use]
    pub fn events(&self) -> &[RequiredEventSelectionAttributionV1] {
        &self.events
    }
}

impl fmt::Debug for RequiredAlternativeSelectionAttributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredAlternativeSelectionAttributionV1")
            .field("requirement_index", &self.requirement_index)
            .field("alternative_index", &self.alternative_index)
            .field(
                "all_members_in_proposal_universe",
                &self.all_members_in_proposal_universe,
            )
            .field(
                "minimum_compiled_token_bound",
                &self.minimum_compiled_token_bound,
            )
            .field("oracle_budget_feasibility", &self.oracle_budget_feasibility)
            .field("event_count", &self.events.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequirementSelectionAttributionClassV1 {
    Satisfied,
    CandidateRecallMiss,
    ObjectiveSaturation,
    BudgetInfeasible,
    RenderReferenceMismatch,
    SelectorOrderingUnattributed,
}

impl RequirementSelectionAttributionClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::CandidateRecallMiss => "candidate_recall_miss",
            Self::ObjectiveSaturation => "objective_saturation",
            Self::BudgetInfeasible => "budget_infeasible",
            Self::RenderReferenceMismatch => "render_reference_mismatch",
            Self::SelectorOrderingUnattributed => "selector_ordering_unattributed",
        }
    }
}

impl fmt::Debug for RequirementSelectionAttributionClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequirementSelectionAttributionClassV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedRequirementSelectionAttributionV1 {
    requirement_index: u64,
    class: RequirementSelectionAttributionClassV1,
    alternatives: Vec<RequiredAlternativeSelectionAttributionV1>,
}

impl GovernedRequirementSelectionAttributionV1 {
    #[must_use]
    pub const fn requirement_index(&self) -> u64 {
        self.requirement_index
    }

    #[must_use]
    pub const fn class(&self) -> RequirementSelectionAttributionClassV1 {
        self.class
    }

    #[must_use]
    pub fn alternatives(&self) -> &[RequiredAlternativeSelectionAttributionV1] {
        &self.alternatives
    }
}

impl fmt::Debug for GovernedRequirementSelectionAttributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedRequirementSelectionAttributionV1")
            .field("requirement_index", &self.requirement_index)
            .field("class", &self.class)
            .field("alternative_count", &self.alternatives.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedMaskSelectionAttributionV1 {
    mask: ThreeLaneAblationMaskV1,
    render_reference_mapping_exact: bool,
    requirements: Vec<GovernedRequirementSelectionAttributionV1>,
}

impl GovernedMaskSelectionAttributionV1 {
    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn render_reference_mapping_exact(&self) -> bool {
        self.render_reference_mapping_exact
    }

    #[must_use]
    pub fn requirements(&self) -> &[GovernedRequirementSelectionAttributionV1] {
        &self.requirements
    }
}

impl fmt::Debug for GovernedMaskSelectionAttributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedMaskSelectionAttributionV1")
            .field("mask", &self.mask)
            .field(
                "render_reference_mapping_exact",
                &self.render_reference_mapping_exact,
            )
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedSyntheticThreeLaneSelectionPointV1 {
    mask: ThreeLaneAblationMaskV1,
    public_outcome_digest: FrozenSyntheticThreeLaneSelectionOutcomeDigestV1,
    recall: GovernedRequirementRecallV1,
    selected_packet_count: u64,
    selected_event_count: u64,
    selected_unique_source_bytes: u64,
    selected_render_tokens: u64,
    coverage_only_token_charge: Option<u64>,
    coverage_only_token_limit: Option<u64>,
    acquisition_class: ExpectedAcquisitionClassV1,
    needs_more_class: Option<SyntheticThreeLaneNeedsMoreClassV1>,
    residual: RequiredEventSelectionResidualV1,
}

impl GovernedSyntheticThreeLaneSelectionPointV1 {
    #[must_use]
    pub const fn mask(self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn public_outcome_digest(self) -> FrozenSyntheticThreeLaneSelectionOutcomeDigestV1 {
        self.public_outcome_digest
    }

    #[must_use]
    pub const fn required_event_recall(self) -> GovernedRequirementRecallV1 {
        self.recall
    }

    #[must_use]
    pub const fn selected_packet_count(self) -> u64 {
        self.selected_packet_count
    }

    #[must_use]
    pub const fn selected_event_count(self) -> u64 {
        self.selected_event_count
    }

    #[must_use]
    pub const fn selected_unique_source_bytes(self) -> u64 {
        self.selected_unique_source_bytes
    }

    #[must_use]
    pub const fn selected_render_tokens(self) -> u64 {
        self.selected_render_tokens
    }

    #[must_use]
    pub const fn coverage_only_token_charge(self) -> Option<u64> {
        self.coverage_only_token_charge
    }

    #[must_use]
    pub const fn coverage_only_token_limit(self) -> Option<u64> {
        self.coverage_only_token_limit
    }

    #[must_use]
    pub const fn acquisition_class(self) -> ExpectedAcquisitionClassV1 {
        self.acquisition_class
    }

    #[must_use]
    pub const fn needs_more_class(self) -> Option<SyntheticThreeLaneNeedsMoreClassV1> {
        self.needs_more_class
    }

    #[must_use]
    pub const fn residual(self) -> RequiredEventSelectionResidualV1 {
        self.residual
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneSelectionPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneSelectionPointV1")
            .field("mask", &self.mask)
            .field("public_outcome_binding_present", &true)
            .field("recall", &self.recall)
            .field("selected_packet_count", &self.selected_packet_count)
            .field("selected_event_count", &self.selected_event_count)
            .field(
                "selected_unique_source_bytes",
                &self.selected_unique_source_bytes,
            )
            .field("selected_render_tokens", &self.selected_render_tokens)
            .field(
                "coverage_only_token_charge",
                &self.coverage_only_token_charge,
            )
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .field("acquisition_class", &self.acquisition_class)
            .field("needs_more_class", &self.needs_more_class)
            .field("residual", &self.residual)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSyntheticThreeLaneSelectionCaseV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    public_case_digest: FrozenSyntheticThreeLaneSelectionCaseDigestV1,
    points: [GovernedSyntheticThreeLaneSelectionPointV1; 4],
    attributions: [GovernedMaskSelectionAttributionV1; 4],
    matched_baselines: [GovernedMatchedBaselineOutcomeV1; 3],
}

impl GovernedSyntheticThreeLaneSelectionCaseV1 {
    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub fn points(&self) -> &[GovernedSyntheticThreeLaneSelectionPointV1; 4] {
        &self.points
    }

    #[must_use]
    pub fn point(
        &self,
        mask: ThreeLaneAblationMaskV1,
    ) -> GovernedSyntheticThreeLaneSelectionPointV1 {
        self.points[mask_index(mask)]
    }

    #[must_use]
    pub fn matched_baselines(&self) -> &[GovernedMatchedBaselineOutcomeV1; 3] {
        &self.matched_baselines
    }

    #[must_use]
    pub fn attribution(
        &self,
        mask: ThreeLaneAblationMaskV1,
    ) -> &GovernedMaskSelectionAttributionV1 {
        &self.attributions[mask_index(mask)]
    }

    #[must_use]
    pub fn matched_baseline(&self, arm: MatchedBaselineArmV1) -> GovernedMatchedBaselineOutcomeV1 {
        self.matched_baselines[baseline_arm_index(arm)]
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneSelectionCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneSelectionCaseV1")
            .field("case", &self.case)
            .field("family", &self.family)
            .field("public_case_binding_present", &true)
            .field("point_count", &self.points.len())
            .field("attribution_count", &self.attributions.len())
            .field("matched_baseline_count", &self.matched_baselines.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactSelectedFamilyMaskComponentV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    point: GovernedSyntheticThreeLaneSelectionPointV1,
}

impl ExactSelectedFamilyMaskComponentV1 {
    #[must_use]
    pub const fn case(self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn point(self) -> GovernedSyntheticThreeLaneSelectionPointV1 {
        self.point
    }
}

impl fmt::Debug for ExactSelectedFamilyMaskComponentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSelectedFamilyMaskComponentV1")
            .field("case", &self.case)
            .field("point", &self.point)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExactSelectedFamilyMaskComponentsV1 {
    family: SyntheticThreeLaneAblationFamilyV1,
    mask: ThreeLaneAblationMaskV1,
    components: Vec<ExactSelectedFamilyMaskComponentV1>,
}

impl ExactSelectedFamilyMaskComponentsV1 {
    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub fn components(&self) -> &[ExactSelectedFamilyMaskComponentV1] {
        &self.components
    }
}

impl fmt::Debug for ExactSelectedFamilyMaskComponentsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSelectedFamilyMaskComponentsV1")
            .field("family", &self.family)
            .field("mask", &self.mask)
            .field("component_count", &self.components.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactSelectedLaneRemovalDeltaComponentV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    ablated_mask: ThreeLaneAblationMaskV1,
    signed_numerator_delta: i128,
    common_denominator: u64,
}

impl ExactSelectedLaneRemovalDeltaComponentV1 {
    #[must_use]
    pub const fn case(self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn ablated_mask(self) -> ThreeLaneAblationMaskV1 {
        self.ablated_mask
    }

    /// Exact `ablated - Full` weighted-recall delta.
    #[must_use]
    pub const fn exact_rational_delta(self) -> (i128, u64) {
        (self.signed_numerator_delta, self.common_denominator)
    }
}

impl fmt::Debug for ExactSelectedLaneRemovalDeltaComponentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSelectedLaneRemovalDeltaComponentV1")
            .field("case", &self.case)
            .field("ablated_mask", &self.ablated_mask)
            .field("signed_numerator_delta", &self.signed_numerator_delta)
            .field("common_denominator", &self.common_denominator)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExactSelectedFamilyLaneRemovalDeltasV1 {
    family: SyntheticThreeLaneAblationFamilyV1,
    ablated_mask: ThreeLaneAblationMaskV1,
    components: Vec<ExactSelectedLaneRemovalDeltaComponentV1>,
}

impl ExactSelectedFamilyLaneRemovalDeltasV1 {
    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn ablated_mask(&self) -> ThreeLaneAblationMaskV1 {
        self.ablated_mask
    }

    #[must_use]
    pub fn components(&self) -> &[ExactSelectedLaneRemovalDeltaComponentV1] {
        &self.components
    }
}

impl fmt::Debug for ExactSelectedFamilyLaneRemovalDeltasV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSelectedFamilyLaneRemovalDeltasV1")
            .field("family", &self.family)
            .field("ablated_mask", &self.ablated_mask)
            .field("component_count", &self.components.len())
            .finish()
    }
}

pub struct GovernedSyntheticThreeLaneSelectionCorpusV1 {
    digest: ArtifactDigest,
    public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    producer_proposal_corpus: GovernedSyntheticThreeLaneAblationCorpusV1,
    full_selection_oracle_report: crate::GovernedSyntheticFullSelectionOracleReportV1,
    cases: [GovernedSyntheticThreeLaneSelectionCaseV1; 6],
    family_mask_components: Vec<ExactSelectedFamilyMaskComponentsV1>,
    family_lane_removal_deltas: Vec<ExactSelectedFamilyLaneRemovalDeltasV1>,
}

impl GovernedSyntheticThreeLaneSelectionCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn public_selection_corpus_digest(
        &self,
    ) -> FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
        self.public_selection_corpus_digest
    }

    /// Retains all original producer-universe evaluations, five-axis cap
    /// violations, and conservative shared-batch full charges.
    #[must_use]
    pub const fn producer_proposal_corpus(&self) -> &GovernedSyntheticThreeLaneAblationCorpusV1 {
        &self.producer_proposal_corpus
    }

    #[must_use]
    pub const fn full_selection_oracle_report(
        &self,
    ) -> &crate::GovernedSyntheticFullSelectionOracleReportV1 {
        &self.full_selection_oracle_report
    }

    #[must_use]
    pub fn cases(&self) -> &[GovernedSyntheticThreeLaneSelectionCaseV1; 6] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SyntheticThreeLaneAblationCaseV1,
    ) -> &GovernedSyntheticThreeLaneSelectionCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub fn family_mask_components(&self) -> &[ExactSelectedFamilyMaskComponentsV1] {
        &self.family_mask_components
    }

    #[must_use]
    pub fn family_lane_removal_deltas(&self) -> &[ExactSelectedFamilyLaneRemovalDeltasV1] {
        &self.family_lane_removal_deltas
    }

    #[must_use]
    pub const fn contains_scalar_composite(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_auc(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_winner(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_statistical_claim(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_general_quality_claim(&self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneSelectionCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneSelectionCorpusV1")
            .field("governed_identity_present", &true)
            .field("public_selection_binding_present", &true)
            .field("producer_proposal_corpus", &self.producer_proposal_corpus)
            .field(
                "full_selection_oracle_report",
                &self.full_selection_oracle_report,
            )
            .field("case_count", &self.cases.len())
            .field(
                "family_mask_component_count",
                &self.family_mask_components.len(),
            )
            .field(
                "family_lane_removal_delta_count",
                &self.family_lane_removal_deltas.len(),
            )
            .field("contains_scalar_composite", &false)
            .field("contains_auc", &false)
            .field("contains_winner", &false)
            .field("contains_statistical_claim", &false)
            .field("contains_general_quality_claim", &false)
            .finish()
    }
}

pub fn evaluate_governed_synthetic_three_lane_selection_corpus_v1<'input, 'ledger, Inputs>(
    public: &FrozenPublicSyntheticThreeLaneSelectionCorpusV1,
    source_public: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    inputs: Inputs,
) -> Result<GovernedSyntheticThreeLaneSelectionCorpusV1, ThreeLaneSelectionCorpusErrorV1>
where
    'ledger: 'input,
    Inputs: IntoIterator<Item = GovernedSyntheticThreeLaneSelectionCaseInputV1<'input, 'ledger>>,
{
    if public.source_public_corpus_digest != source_public.digest() {
        return Err(ThreeLaneSelectionCorpusErrorV1::ForeignSourceCorpus);
    }
    let mut by_case = std::array::from_fn::<_, 6, _>(|_| None);
    for input in inputs {
        if input.public_selection_corpus_digest != public.digest {
            return Err(ThreeLaneSelectionCorpusErrorV1::ForeignSelectionCorpus);
        }
        let index = case_index(input.case);
        if by_case[index].replace(input).is_some() {
            return Err(ThreeLaneSelectionCorpusErrorV1::DuplicateCase);
        }
    }
    if by_case.iter().any(Option::is_none) {
        return Err(ThreeLaneSelectionCorpusErrorV1::MissingCases {
            count: by_case.iter().filter(|entry| entry.is_none()).count(),
        });
    }
    let inputs = by_case
        .into_iter()
        .zip(SyntheticThreeLaneAblationCaseV1::ALL)
        .map(|(input, case)| {
            let input = input.ok_or(ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 })?;
            let public_case = public.case(case);
            if input.case != case
                || input.family != case.family()
                || input.public_selection_case_digest != public_case.digest
                || input.source_public_batch_digest != public_case.source_public_batch_digest
                || input.source_public_batch_digest != source_public.case(case).batch().digest()
            {
                return Err(ThreeLaneSelectionCorpusErrorV1::CaseBindingMismatch);
            }
            Ok(input)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let producer_inputs = inputs.iter().map(|input| {
        GovernedSyntheticThreeLaneAblationCaseInputV1::new(
            input.case,
            input.family,
            source_public.digest(),
            input.source_public_batch_digest,
            input.artifact_join,
            input.annotation,
            input.ledger,
            input.block_index,
        )
    });
    let producer_proposal_corpus =
        evaluate_governed_synthetic_three_lane_ablation_corpus_v1(source_public, producer_inputs)
            .map_err(ThreeLaneSelectionCorpusErrorV1::SourceCorpusEvaluation)?;

    let cases = inputs
        .iter()
        .zip(SyntheticThreeLaneAblationCaseV1::ALL)
        .map(|(input, case)| {
            score_selection_case(
                public.case(case),
                source_public.case(case).batch().public_case(),
                input,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [GovernedSyntheticThreeLaneSelectionCaseV1; 6] = cases
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 })?;
    let family_mask_components = build_family_mask_components(&cases);
    let family_lane_removal_deltas = build_family_lane_removal_deltas(&cases)?;
    let full_selection_oracle_report =
        build_governed_full_selection_oracle_report_v1(public.digest, &public.cases, &inputs)?;
    let digest = derive_governed_digest(
        public.digest,
        producer_proposal_corpus.digest(),
        full_selection_oracle_report.digest(),
        &cases,
        &family_lane_removal_deltas,
    )?;
    Ok(GovernedSyntheticThreeLaneSelectionCorpusV1 {
        digest,
        public_selection_corpus_digest: public.digest,
        producer_proposal_corpus,
        full_selection_oracle_report,
        cases,
        family_mask_components,
        family_lane_removal_deltas,
    })
}

fn score_selection_case(
    public: &FrozenSyntheticThreeLaneSelectionCaseV1,
    public_case_spec: &EvidentrailBenchCaseSpecV1,
    input: &GovernedSyntheticThreeLaneSelectionCaseInputV1<'_, '_>,
) -> Result<GovernedSyntheticThreeLaneSelectionCaseV1, ThreeLaneSelectionCorpusErrorV1> {
    if input
        .annotation
        .diagnostic_requirements()
        .iter()
        .any(|requirement| {
            requirement
                .alternatives()
                .iter()
                .flatten()
                .any(|target| !matches!(target, crate::EvidenceTargetV1::Event(_)))
        })
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::NonEventRequirementTarget);
    }
    let points = ThreeLaneAblationMaskV1::ALL.map(|mask| {
        let outcome = public.outcome(mask);
        let selected_event_ids = outcome
            .decision
            .selected_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let selected_targets = selected_targets_v1(None, &selected_event_ids);
        let recall = evaluate_requirements_v1(input.annotation, &selected_targets)
            .map_err(ThreeLaneSelectionCorpusErrorV1::CaseEvaluation)?;
        let (packet_count, source_bytes, render_tokens, charge, limit, needs_more_class) =
            match &outcome.decision {
                FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(selected) => (
                    checked_u64(selected.selected_packet_ids.len())?,
                    selected.selected_unique_source_bytes,
                    selected.render.token_count(),
                    Some(selected.coverage_only_token_charge),
                    Some(selected.coverage_only_token_limit),
                    None,
                ),
                FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
                    (0, 0, 0, None, None, Some(needs_more.class))
                }
            };
        let residual = match (&outcome.decision, recall.is_perfect()) {
            (FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(_), true) => {
                RequiredEventSelectionResidualV1::None
            }
            (FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(_), false) => {
                RequiredEventSelectionResidualV1::SelectedRequiredEventMiss
            }
            (FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(needs_more), _) => {
                match needs_more.class {
                    SyntheticThreeLaneNeedsMoreClassV1::EmptyProposalUniverse => {
                        RequiredEventSelectionResidualV1::EmptyProposalUniverse
                    }
                    SyntheticThreeLaneNeedsMoreClassV1::BudgetInfeasible => {
                        RequiredEventSelectionResidualV1::BudgetInfeasible
                    }
                }
            }
        };
        Ok(GovernedSyntheticThreeLaneSelectionPointV1 {
            mask,
            public_outcome_digest: outcome.digest,
            recall,
            selected_packet_count: packet_count,
            selected_event_count: checked_u64(selected_event_ids.len())?,
            selected_unique_source_bytes: source_bytes,
            selected_render_tokens: render_tokens,
            coverage_only_token_charge: charge,
            coverage_only_token_limit: limit,
            acquisition_class: public.acquisition_class,
            needs_more_class,
            residual,
        })
    });
    let [full, without_lexical, without_coverage, without_provider] = points;
    let attributions = ThreeLaneAblationMaskV1::ALL
        .map(|mask| build_mask_selection_attribution(input.annotation, public.outcome(mask)));
    let [
        full_attribution,
        lexical_attribution,
        coverage_attribution,
        provider_attribution,
    ] = attributions;
    let matched_baselines = public
        .matched_baselines
        .outcomes
        .iter()
        .map(|outcome| {
            let evaluation = evaluate_governed_case_v1(
                input.artifact_join,
                public_case_spec,
                input.annotation,
                input.ledger,
                &outcome.result,
                Some(input.block_index),
            )
            .map_err(ThreeLaneSelectionCorpusErrorV1::CaseEvaluation)?;
            Ok(GovernedMatchedBaselineOutcomeV1 {
                arm: outcome.arm,
                public_outcome_digest: outcome.digest,
                evaluation,
            })
        })
        .collect::<Result<Vec<_>, ThreeLaneSelectionCorpusErrorV1>>()?;
    let matched_baselines: [GovernedMatchedBaselineOutcomeV1; 3] = matched_baselines
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::PreparedBindingMismatch)?;
    Ok(GovernedSyntheticThreeLaneSelectionCaseV1 {
        case: public.case,
        family: public.family,
        public_case_digest: public.digest,
        points: [
            full?,
            without_lexical?,
            without_coverage?,
            without_provider?,
        ],
        attributions: [
            full_attribution?,
            lexical_attribution?,
            coverage_attribution?,
            provider_attribution?,
        ],
        matched_baselines,
    })
}

fn build_mask_selection_attribution(
    annotation: &EvidentrailBenchAnnotationSpecV1,
    outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
) -> Result<GovernedMaskSelectionAttributionV1, ThreeLaneSelectionCorpusErrorV1> {
    let render_reference_mapping_exact = render_reference_mapping_exact(outcome);
    let selected_event_ids = outcome
        .decision
        .selected_event_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let selected_targets = selected_targets_v1(None, &selected_event_ids);
    let requirements = annotation
        .diagnostic_requirements()
        .iter()
        .enumerate()
        .map(|(requirement_index, requirement)| {
            let requirement_index = checked_u64(requirement_index)?;
            let alternatives = requirement
                .alternatives()
                .iter()
                .enumerate()
                .map(|(alternative_index, alternative)| {
                    let alternative_index = checked_u64(alternative_index)?;
                    let event_ids = alternative
                        .iter()
                        .map(|target| match target {
                            crate::EvidenceTargetV1::Event(event_id) => Ok(*event_id),
                            _ => Err(ThreeLaneSelectionCorpusErrorV1::NonEventRequirementTarget),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let (minimum_compiled_token_bound, oracle_budget_feasibility) =
                        alternative_oracle_bound(outcome, &event_ids)?;
                    let events = event_ids
                        .into_iter()
                        .map(|event_id| {
                            let containing_packets = outcome
                                .proposal_audits
                                .iter()
                                .filter(|packet| packet.member_event_ids.contains(&event_id))
                                .cloned()
                                .collect::<Vec<_>>();
                            let disposition = if selected_event_ids.contains(&event_id)
                                && render_reference_mapping_exact
                            {
                                RequiredEventSelectionDispositionV1::SelectedAndRendered
                            } else if containing_packets.is_empty() {
                                RequiredEventSelectionDispositionV1::CandidateAbsent
                            } else if matches!(
                                outcome.decision,
                                FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(_)
                            ) {
                                RequiredEventSelectionDispositionV1::BudgetInfeasible
                            } else if containing_packets.iter().all(|packet| {
                                packet.post_selection_marginal_gain_numerator == Some(0)
                            }) {
                                RequiredEventSelectionDispositionV1::ObjectiveSaturated
                            } else {
                                RequiredEventSelectionDispositionV1::SelectorOrderingUnattributed
                            };
                            RequiredEventSelectionAttributionV1 {
                                event_id,
                                containing_packets,
                                disposition,
                            }
                        })
                        .collect::<Vec<_>>();
                    Ok(RequiredAlternativeSelectionAttributionV1 {
                        requirement_index,
                        alternative_index,
                        all_members_in_proposal_universe: events
                            .iter()
                            .all(|event| !event.containing_packets.is_empty()),
                        minimum_compiled_token_bound,
                        oracle_budget_feasibility,
                        events,
                    })
                })
                .collect::<Result<Vec<_>, ThreeLaneSelectionCorpusErrorV1>>()?;
            let class = if !render_reference_mapping_exact {
                RequirementSelectionAttributionClassV1::RenderReferenceMismatch
            } else if requirement.is_satisfied_by(&selected_targets) {
                RequirementSelectionAttributionClassV1::Satisfied
            } else if !alternatives
                .iter()
                .any(|alternative| alternative.all_members_in_proposal_universe)
            {
                RequirementSelectionAttributionClassV1::CandidateRecallMiss
            } else if alternatives.iter().any(|alternative| {
                alternative.oracle_budget_feasibility
                    == AlternativeOracleBudgetFeasibilityV1::Feasible
                    && alternative.events.iter().all(|event| {
                        matches!(
                            event.disposition,
                            RequiredEventSelectionDispositionV1::SelectedAndRendered
                                | RequiredEventSelectionDispositionV1::ObjectiveSaturated
                        )
                    })
            }) {
                RequirementSelectionAttributionClassV1::ObjectiveSaturation
            } else if alternatives
                .iter()
                .filter(|alternative| alternative.all_members_in_proposal_universe)
                .all(|alternative| {
                    alternative.oracle_budget_feasibility
                        == AlternativeOracleBudgetFeasibilityV1::Infeasible
                })
            {
                RequirementSelectionAttributionClassV1::BudgetInfeasible
            } else {
                RequirementSelectionAttributionClassV1::SelectorOrderingUnattributed
            };
            Ok(GovernedRequirementSelectionAttributionV1 {
                requirement_index,
                class,
                alternatives,
            })
        })
        .collect::<Result<Vec<_>, ThreeLaneSelectionCorpusErrorV1>>()?;
    Ok(GovernedMaskSelectionAttributionV1 {
        mask: outcome.mask,
        render_reference_mapping_exact,
        requirements,
    })
}

fn render_reference_mapping_exact(outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1) -> bool {
    let FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(selected) = &outcome.decision else {
        return true;
    };
    let mut rendered_packet_ids = BTreeSet::new();
    let mut rendered_event_ids = BTreeSet::new();
    for packet in selected.render.artifact().brief().evidence() {
        rendered_packet_ids.insert(ProducerProposalIdV1::from_bytes(
            *packet.packet_id().as_bytes(),
        ));
        let canonical = packet
            .canonical_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let material = packet
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<BTreeSet<_>>();
        let referenced = packet
            .reference()
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) => Some(*event_id),
                EvidenceTargetRef::Block(_) => None,
            })
            .collect::<Option<BTreeSet<_>>>();
        if canonical != material
            || referenced.as_ref() != Some(&canonical)
            || packet.reference().allowed_relations() != [ExpansionRelationV1::Exact]
        {
            return false;
        }
        rendered_event_ids.extend(canonical);
    }
    rendered_packet_ids
        == selected
            .selected_packet_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
        && rendered_event_ids
            == selected
                .selected_event_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
}

fn alternative_oracle_bound(
    outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
    event_ids: &[EventId],
) -> Result<(Option<u64>, AlternativeOracleBudgetFeasibilityV1), ThreeLaneSelectionCorpusErrorV1> {
    if event_ids.iter().any(|event_id| {
        !outcome
            .proposal_audits
            .iter()
            .any(|packet| packet.member_event_ids.contains(event_id))
    }) {
        return Ok((None, AlternativeOracleBudgetFeasibilityV1::Unrepresentable));
    }
    let Some(fixed_overhead) = outcome.fixed_overhead_tokens else {
        return Ok((
            None,
            AlternativeOracleBudgetFeasibilityV1::BoundNotEvaluated,
        ));
    };
    if event_ids.len() > 20 {
        return Ok((
            None,
            AlternativeOracleBudgetFeasibilityV1::BoundNotEvaluated,
        ));
    }
    let mut event_positions = BTreeMap::new();
    for (position, event_id) in event_ids.iter().copied().enumerate() {
        event_positions.insert(event_id, position);
    }
    let full_mask = (1_usize << event_ids.len()).saturating_sub(1);
    let packet_mask = |packet: &FrozenProposalPacketAuditV1| {
        packet
            .member_event_ids
            .iter()
            .filter_map(|event_id| event_positions.get(event_id).copied())
            .fold(0_usize, |mask, position| mask | (1_usize << position))
    };
    let mandatory_mask = outcome
        .proposal_audits
        .iter()
        .filter(|packet| packet.is_mandatory())
        .fold(0_usize, |mask, packet| mask | packet_mask(packet));
    let state_count = 1_usize
        .checked_shl(
            u32::try_from(event_ids.len())
                .map_err(|_| ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?,
        )
        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
    let mut costs = vec![u64::MAX; state_count];
    costs[mandatory_mask] = outcome.mandatory_packet_tokens;
    for packet in outcome
        .proposal_audits
        .iter()
        .filter(|packet| !packet.is_mandatory())
    {
        let coverage = packet_mask(packet);
        if coverage == 0 {
            continue;
        }
        let mut next = costs.clone();
        for (mask, cost) in costs.iter().copied().enumerate() {
            if cost == u64::MAX {
                continue;
            }
            let combined = mask | coverage;
            let combined_cost = cost
                .checked_add(packet.token_cost_upper_bound)
                .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
            next[combined] = next[combined].min(combined_cost);
        }
        costs = next;
    }
    let packet_cost = costs[full_mask];
    if packet_cost == u64::MAX {
        return Ok((None, AlternativeOracleBudgetFeasibilityV1::Unrepresentable));
    }
    let minimum_bound = fixed_overhead
        .checked_add(packet_cost)
        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?;
    let feasibility = if minimum_bound <= outcome.budget.tokens() {
        AlternativeOracleBudgetFeasibilityV1::Feasible
    } else {
        AlternativeOracleBudgetFeasibilityV1::Infeasible
    };
    Ok((Some(minimum_bound), feasibility))
}

fn build_family_mask_components(
    cases: &[GovernedSyntheticThreeLaneSelectionCaseV1; 6],
) -> Vec<ExactSelectedFamilyMaskComponentsV1> {
    SyntheticThreeLaneAblationFamilyV1::ALL
        .into_iter()
        .flat_map(|family| {
            ThreeLaneAblationMaskV1::ALL.into_iter().map(move |mask| {
                ExactSelectedFamilyMaskComponentsV1 {
                    family,
                    mask,
                    components: cases
                        .iter()
                        .filter(|case| case.family == family)
                        .map(|case| ExactSelectedFamilyMaskComponentV1 {
                            case: case.case,
                            point: case.point(mask),
                        })
                        .collect(),
                }
            })
        })
        .collect()
}

fn build_family_lane_removal_deltas(
    cases: &[GovernedSyntheticThreeLaneSelectionCaseV1; 6],
) -> Result<Vec<ExactSelectedFamilyLaneRemovalDeltasV1>, ThreeLaneSelectionCorpusErrorV1> {
    let ablated_masks = [
        ThreeLaneAblationMaskV1::WithoutLexical,
        ThreeLaneAblationMaskV1::WithoutCoverage,
        ThreeLaneAblationMaskV1::WithoutProvider,
    ];
    SyntheticThreeLaneAblationFamilyV1::ALL
        .into_iter()
        .flat_map(|family| {
            ablated_masks.into_iter().map(move |ablated_mask| {
                let components = cases
                    .iter()
                    .filter(|case| case.family == family)
                    .map(|case| {
                        let full = case
                            .point(ThreeLaneAblationMaskV1::Full)
                            .required_event_recall();
                        let ablated = case.point(ablated_mask).required_event_recall();
                        if full.total_weight_micros() != ablated.total_weight_micros()
                            || full.requirement_count() != ablated.requirement_count()
                        {
                            return Err(ThreeLaneSelectionCorpusErrorV1::RecallUniverseMismatch);
                        }
                        Ok(ExactSelectedLaneRemovalDeltaComponentV1 {
                            case: case.case,
                            ablated_mask,
                            signed_numerator_delta: i128::from(ablated.satisfied_weight_micros())
                                - i128::from(full.satisfied_weight_micros()),
                            common_denominator: full.total_weight_micros(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ExactSelectedFamilyLaneRemovalDeltasV1 {
                    family,
                    ablated_mask,
                    components,
                })
            })
        })
        .collect()
}

fn derive_governed_digest(
    public_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    producer_corpus_digest: crate::GovernedSyntheticThreeLaneCorpusDigestV1,
    full_selection_oracle_report_digest: ArtifactDigest,
    cases: &[GovernedSyntheticThreeLaneSelectionCaseV1; 6],
    deltas: &[ExactSelectedFamilyLaneRemovalDeltasV1],
) -> Result<ArtifactDigest, ThreeLaneSelectionCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_SELECTION_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, public_digest.as_bytes())?;
    update_field(&mut hasher, producer_corpus_digest.as_bytes())?;
    update_field(&mut hasher, full_selection_oracle_report_digest.as_bytes())?;
    for case in cases {
        update_field(&mut hasher, case.public_case_digest.as_bytes())?;
        for point in &case.points {
            update_field(&mut hasher, point.public_outcome_digest.as_bytes())?;
            update_u64(&mut hasher, point.recall.satisfied_requirement_count());
            update_u64(&mut hasher, point.recall.requirement_count());
            update_u64(&mut hasher, point.recall.satisfied_weight_micros());
            update_u64(&mut hasher, point.recall.total_weight_micros());
            update_u64(&mut hasher, point.selected_packet_count);
            update_u64(&mut hasher, point.selected_event_count);
            update_u64(&mut hasher, point.selected_unique_source_bytes);
            update_u64(&mut hasher, point.selected_render_tokens);
            update_optional_u64(&mut hasher, point.coverage_only_token_charge);
            update_optional_u64(&mut hasher, point.coverage_only_token_limit);
            update_field(&mut hasher, point.acquisition_class.code().as_bytes())?;
            match point.needs_more_class {
                Some(class) => {
                    hasher.update([1]);
                    update_field(&mut hasher, class.code().as_bytes())?;
                }
                None => hasher.update([0]),
            }
            update_field(&mut hasher, point.residual.code().as_bytes())?;
        }
        for attribution in &case.attributions {
            hasher.update([attribution.mask.bits()]);
            hasher.update([u8::from(attribution.render_reference_mapping_exact)]);
            update_u64(&mut hasher, checked_u64(attribution.requirements.len())?);
            for requirement in &attribution.requirements {
                update_u64(&mut hasher, requirement.requirement_index);
                update_field(&mut hasher, requirement.class.code().as_bytes())?;
                update_u64(&mut hasher, checked_u64(requirement.alternatives.len())?);
                for alternative in &requirement.alternatives {
                    update_u64(&mut hasher, alternative.alternative_index);
                    hasher.update([u8::from(alternative.all_members_in_proposal_universe)]);
                    update_optional_u64(&mut hasher, alternative.minimum_compiled_token_bound);
                    update_field(
                        &mut hasher,
                        alternative.oracle_budget_feasibility.code().as_bytes(),
                    )?;
                    update_u64(&mut hasher, checked_u64(alternative.events.len())?);
                    for event in &alternative.events {
                        update_field(&mut hasher, event.event_id.as_bytes())?;
                        update_field(&mut hasher, event.disposition.code().as_bytes())?;
                        update_u64(&mut hasher, checked_u64(event.containing_packets.len())?);
                        for packet in &event.containing_packets {
                            update_field(&mut hasher, packet.packet_id.as_bytes())?;
                        }
                    }
                }
            }
        }
        for baseline in &case.matched_baselines {
            update_field(&mut hasher, baseline.arm.code().as_bytes())?;
            update_field(&mut hasher, baseline.public_outcome_digest.as_bytes())?;
            let binding = baseline.evaluation.artifact_binding();
            update_field(
                &mut hasher,
                binding.public_case_artifact_digest().as_bytes(),
            )?;
            update_field(&mut hasher, binding.annotation_artifact_digest().as_bytes())?;
            let result = baseline.evaluation.public_result();
            update_field(&mut hasher, result.method().name().as_bytes())?;
            update_field(&mut hasher, result.method().version().as_bytes())?;
            update_field(&mut hasher, result.retrieval_id().as_bytes())?;
            update_field(&mut hasher, result.presentation_receipt_id().as_bytes())?;
            let accounting = result.accounting();
            for value in [
                accounting.received_event_count(),
                accounting.candidate_event_count(),
                accounting.candidate_source_bytes(),
                accounting.selected_event_count(),
                accounting.selected_source_bytes(),
                accounting.retained_raw_event_count(),
                accounting.budget_excluded_candidate_count(),
                accounting.source_byte_budget(),
                accounting.shown_verbatim_event_count(),
                accounting.pattern_represented_event_count(),
                accounting.presentation_retained_raw_event_count(),
            ] {
                update_u64(&mut hasher, value);
            }
            let recall = baseline.evaluation.diagnostic_recall();
            update_u64(&mut hasher, recall.requirement_count());
            update_u64(&mut hasher, recall.satisfied_requirement_count());
            update_u64(&mut hasher, recall.total_weight_micros());
            update_u64(&mut hasher, recall.satisfied_weight_micros());
        }
    }
    for delta in deltas {
        update_field(&mut hasher, delta.family.identity_digest().as_bytes())?;
        hasher.update([delta.ablated_mask.bits()]);
        for component in &delta.components {
            update_field(&mut hasher, component.case.identity_digest().as_bytes())?;
            hasher.update(component.signed_numerator_delta.to_le_bytes());
            update_u64(&mut hasher, component.common_denominator);
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneSelectionCorpusErrorV1 {
    InvalidTokenBudget,
    DuplicateBudgetCase,
    MissingBudgetCases { count: usize },
    DuplicateCase,
    MissingCases { count: usize },
    MissingMasks,
    CaseBindingMismatch,
    LedgerBindingMismatch,
    PreparedBindingMismatch,
    ForeignSelectionCorpus,
    ForeignSourceCorpus,
    NonEventRequirementTarget,
    SelectedEventMismatch,
    RecallUniverseMismatch,
    ExactOracleBindingMismatch,
    ExactOracleDecisionMismatch,
    ArithmeticOverflow,
    DigestLengthOverflow,
    Compiler(ThreeLaneCompileErrorV1),
    ExactOracle(crate::ExactSelectionOracleErrorV1),
    Method(MethodError),
    Reference(EvidenceReferenceConstructionError),
    Render(CompiledBriefError),
    SourceCorpusEvaluation(SyntheticThreeLaneCorpusErrorV1),
    CaseEvaluation(CaseEvaluationError),
}

impl ThreeLaneSelectionCorpusErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTokenBudget => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_INVALID_TOKEN_BUDGET",
            Self::DuplicateBudgetCase => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_DUPLICATE_BUDGET_CASE",
            Self::MissingBudgetCases { .. } => {
                "EVIDENTRAIL_BENCH_SELECTION_CORPUS_MISSING_BUDGET_CASES"
            }
            Self::DuplicateCase => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_DUPLICATE_CASE",
            Self::MissingCases { .. } => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_MISSING_CASES",
            Self::MissingMasks => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_MISSING_MASKS",
            Self::CaseBindingMismatch => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_CASE_BINDING",
            Self::LedgerBindingMismatch => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_LEDGER_BINDING",
            Self::PreparedBindingMismatch => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_PREPARED_BINDING",
            Self::ForeignSelectionCorpus => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_FOREIGN_SELECTION",
            Self::ForeignSourceCorpus => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_FOREIGN_SOURCE",
            Self::NonEventRequirementTarget => {
                "EVIDENTRAIL_BENCH_SELECTION_CORPUS_NON_EVENT_REQUIREMENT"
            }
            Self::SelectedEventMismatch => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_SELECTED_EVENT",
            Self::RecallUniverseMismatch => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_RECALL_UNIVERSE",
            Self::ExactOracleBindingMismatch => {
                "EVIDENTRAIL_BENCH_SELECTION_CORPUS_EXACT_ORACLE_BINDING"
            }
            Self::ExactOracleDecisionMismatch => {
                "EVIDENTRAIL_BENCH_SELECTION_CORPUS_EXACT_ORACLE_DECISION"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_ARITHMETIC_OVERFLOW",
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_DIGEST_LENGTH",
            Self::Compiler(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_COMPILER",
            Self::ExactOracle(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_EXACT_ORACLE",
            Self::Method(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_METHOD",
            Self::Reference(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_REFERENCE",
            Self::Render(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_RENDER",
            Self::SourceCorpusEvaluation(_) => {
                "EVIDENTRAIL_BENCH_SELECTION_CORPUS_SOURCE_EVALUATION"
            }
            Self::CaseEvaluation(_) => "EVIDENTRAIL_BENCH_SELECTION_CORPUS_CASE_EVALUATION",
        }
    }
}

impl fmt::Debug for ThreeLaneSelectionCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ThreeLaneSelectionCorpusErrorV1");
        debug.field("code", &self.code());
        match self {
            Self::MissingBudgetCases { count } | Self::MissingCases { count } => {
                debug.field("count", count);
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for ThreeLaneSelectionCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ThreeLaneSelectionCorpusErrorV1 {}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn update_optional_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_u64(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn update_optional_bool(hasher: &mut Sha256, value: Option<bool>) {
    match value {
        Some(value) => hasher.update([1, u8::from(value)]),
        None => hasher.update([0]),
    }
}

fn checked_u64(value: usize) -> Result<u64, ThreeLaneSelectionCorpusErrorV1> {
    u64::try_from(value).map_err(|_| ThreeLaneSelectionCorpusErrorV1::DigestLengthOverflow)
}

const fn mask_index(mask: ThreeLaneAblationMaskV1) -> usize {
    match mask {
        ThreeLaneAblationMaskV1::Full => 0,
        ThreeLaneAblationMaskV1::WithoutLexical => 1,
        ThreeLaneAblationMaskV1::WithoutCoverage => 2,
        ThreeLaneAblationMaskV1::WithoutProvider => 3,
    }
}

const fn baseline_arm_index(arm: MatchedBaselineArmV1) -> usize {
    match arm {
        MatchedBaselineArmV1::RawChronological => 0,
        MatchedBaselineArmV1::GrepHeadTail => 1,
        MatchedBaselineArmV1::QuotaHybrid => 2,
    }
}

const fn case_index(case: SyntheticThreeLaneAblationCaseV1) -> usize {
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => 0,
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => 1,
        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => 2,
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => 3,
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => 4,
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => 5,
    }
}
