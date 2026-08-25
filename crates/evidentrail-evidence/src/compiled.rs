use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EventLedger, EvidenceReferenceV1, EvidenceTargetRef, ExactnessBasis,
    ExpansionRelationV1, PresentationAssignment, PresentationReceipt,
    ResultStatusConstructionError, ResultStatusV1, UnixTimestampNanos,
};
use evidentrail_schema::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_LOG_BRIEF_EVIDENCE_PACKETS, MAX_WIRE_OBJECT_BYTES,
};
use evidentrail_schema::{
    AcquisitionReceiptId, ArtifactDigest, EvidenceReferenceId, PlanDigest, PresentationCounts,
    PresentationDisposition, PresentationReceiptId, QuestionDigest, ResultId, SourceStream,
};
use evidentrail_select::{
    COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, ComposableCostModelV1, ComposablePacketCostV1,
    FacetAffinityV1, ObjectiveGainV1, PacketIdV1, ProductionFacetKindV1, SelectionConstraintV1,
    SelectionStrategyV1, SelectionV1,
};
use sha2::{Digest, Sha256};

use super::compiled_cost::{
    CompiledCostCertificationError, CompiledCostCertificationV1, Utf8ByteTokenizerV1,
};
use super::{BoundedText, PinnedTokenizer, RenderLimitExceeded, render_acquisition};

/// Semantic contract version for [`CompiledLogBriefV1`].
pub const COMPILED_LOG_BRIEF_CONTRACT_VERSION_V1: u16 = 2;
/// Contract version of the deterministic compiled text renderer.
pub const COMPILED_TEXT_RENDERER_CONTRACT_VERSION_V1: u16 = 2;

const COMPILED_RENDERER_MANIFEST_V1: &[u8] = b"evidentrail-evidence/compiled-text-renderer/v2\0sections=status,scope,evidence,coverage\0packet-citations=result-scoped-ordinal-alias-v1\0packet-members=intact-ledger-order\0packet-order=diagnostic-then-reconstruction-then-breadth-v1\0packet-roles=canonical-closed-facet-kind-codes-v1\0marginal-gain=presentation-order-consistent\0evidence-bytes=ascii-byte-escape-v1\0structured-ids=full-canonical\0newlines=lf\0model-authored-text=none";
const COMPILED_COST_MODEL_DOMAIN_V1: &[u8] = b"evidentrail/evidence/compiled-cost-model/v1\0";

/// Frozen identity of the canonical V1 compiled renderer.
#[must_use]
pub fn compiled_renderer_digest_v1() -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(COMPILED_RENDERER_MANIFEST_V1).into())
}

/// Legacy identity for caller-declared composable costs.
///
/// This does not certify a bound. Production compiled-cost certification uses
/// [`CompiledCostCertificationV1`], whose distinct identity also commits to an
/// explicit tokenizer-bound contract. This function remains for selector and
/// renderer fixtures that intentionally exercise caller-declared costs.
#[must_use]
pub fn compiled_cost_model_v1(tokenizer_digest: ArtifactDigest) -> ComposableCostModelV1 {
    let renderer_digest = compiled_renderer_digest_v1();
    let mut hasher = Sha256::new();
    hasher.update(COMPILED_COST_MODEL_DOMAIN_V1);
    update_digest_field(&mut hasher, renderer_digest.as_bytes());
    update_digest_field(&mut hasher, tokenizer_digest.as_bytes());
    ComposableCostModelV1::new(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("digest field length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

/// Whole-artifact accounting retained with a compiled result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompiledCostAccountingV1 {
    cost_model: ComposableCostModelV1,
    total_token_budget: u64,
    reserved_fixed_overhead: u64,
    mandatory_token_cost: u64,
    selected_packet_cost: u64,
    accounted_token_upper_bound: u64,
    coverage_only_token_limit: u64,
    coverage_only_token_cost: u64,
    total_rendered_tokens: u64,
    total_rendered_bytes: u64,
    tokenizer_digest: ArtifactDigest,
    renderer_digest: ArtifactDigest,
    additive_bound_certified: bool,
}

impl CompiledCostAccountingV1 {
    #[must_use]
    pub const fn cost_model(self) -> ComposableCostModelV1 {
        self.cost_model
    }

    #[must_use]
    pub const fn total_token_budget(self) -> u64 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(self) -> u64 {
        self.reserved_fixed_overhead
    }

    #[must_use]
    pub const fn mandatory_token_cost(self) -> u64 {
        self.mandatory_token_cost
    }

    #[must_use]
    pub const fn selected_packet_cost(self) -> u64 {
        self.selected_packet_cost
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(self) -> u64 {
        self.accounted_token_upper_bound
    }

    /// Maximum optional cost available to pure breadth-coverage marginal gain.
    #[must_use]
    pub const fn coverage_only_token_limit(self) -> u64 {
        self.coverage_only_token_limit
    }

    /// Selected cost actually charged to the pure breadth-coverage slice.
    #[must_use]
    pub const fn coverage_only_token_cost(self) -> u64 {
        self.coverage_only_token_cost
    }

    #[must_use]
    pub const fn total_rendered_tokens(self) -> u64 {
        self.total_rendered_tokens
    }

    #[must_use]
    pub const fn total_rendered_bytes(self) -> u64 {
        self.total_rendered_bytes
    }

    #[must_use]
    pub const fn tokenizer_digest(self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub const fn renderer_digest(self) -> ArtifactDigest {
        self.renderer_digest
    }

    /// Whether the additive upper bound was independently compiled from the
    /// exact ledger, memberships, renderer grammar, and tokenizer contract.
    #[must_use]
    pub const fn is_additive_bound_certified(self) -> bool {
        self.additive_bound_certified
    }
}

impl fmt::Debug for CompiledCostAccountingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledCostAccountingV1")
            .field("total_token_budget", &self.total_token_budget)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_token_cost", &self.mandatory_token_cost)
            .field("selected_packet_cost", &self.selected_packet_cost)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .field("coverage_only_token_cost", &self.coverage_only_token_cost)
            .field("total_rendered_tokens", &self.total_rendered_tokens)
            .field("total_rendered_bytes", &self.total_rendered_bytes)
            .field("additive_bound_certified", &self.additive_bound_certified)
            .finish()
    }
}

/// Exhaustive acquisition/presentation summary for a compiled result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompiledCoverageV1 {
    acquisition_receipt_id: AcquisitionReceiptId,
    presentation_receipt_id: PresentationReceiptId,
    acknowledged_records: usize,
    presentation_counts: PresentationCounts,
    source_exact_records: usize,
    post_policy_records: usize,
    omitted_by_policy_records: usize,
}

impl CompiledCoverageV1 {
    #[must_use]
    pub const fn acquisition_receipt_id(self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn presentation_receipt_id(self) -> PresentationReceiptId {
        self.presentation_receipt_id
    }

    #[must_use]
    pub const fn acknowledged_records(self) -> usize {
        self.acknowledged_records
    }

    #[must_use]
    pub const fn presentation_counts(self) -> PresentationCounts {
        self.presentation_counts
    }

    #[must_use]
    pub const fn source_exact_records(self) -> usize {
        self.source_exact_records
    }

    #[must_use]
    pub const fn post_policy_records(self) -> usize {
        self.post_policy_records
    }

    #[must_use]
    pub const fn omitted_by_policy_records(self) -> usize {
        self.omitted_by_policy_records
    }
}

impl fmt::Debug for CompiledCoverageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledCoverageV1")
            .field("acknowledged_records", &self.acknowledged_records)
            .field("presentation_counts", &self.presentation_counts)
            .field("source_exact_records", &self.source_exact_records)
            .field("post_policy_records", &self.post_policy_records)
            .field("omitted_by_policy_records", &self.omitted_by_policy_records)
            .finish()
    }
}

/// One exact authorized event inside an intact selected packet.
pub struct CompiledEventEvidenceV1<'ledger> {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    authorized_bytes: &'ledger [u8],
}

impl<'ledger> CompiledEventEvidenceV1<'ledger> {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }

    #[must_use]
    pub const fn authorized_bytes(&self) -> &'ledger [u8] {
        self.authorized_bytes
    }
}

impl fmt::Debug for CompiledEventEvidenceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledEventEvidenceV1")
            .field("exactness_code", &self.exactness_basis.code())
            .field("stream_code", &self.stream.code())
            .field("authorized_byte_count", &self.authorized_bytes.len())
            .finish()
    }
}

/// Full deterministic selector evidence for one displayed intact packet.
pub struct CompiledEvidencePacketV1<'ledger> {
    ordinal: usize,
    packet_id: PacketIdV1,
    reference: EvidenceReferenceV1,
    canonical_event_ids: Vec<EventId>,
    events: Vec<CompiledEventEvidenceV1<'ledger>>,
    affinities: Vec<FacetAffinityV1>,
    facet_kinds: Vec<ProductionFacetKindV1>,
    marginal_gain: ObjectiveGainV1,
    forcing_constraint: SelectionConstraintV1,
    composable_token_upper_bound: ComposablePacketCostV1,
}

impl<'ledger> CompiledEvidencePacketV1<'ledger> {
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    /// Selector-canonical event identity order used for deterministic ties.
    #[must_use]
    pub fn canonical_event_ids(&self) -> &[EventId] {
        &self.canonical_event_ids
    }

    /// Packet members in immutable sealed-ledger order for exact reading.
    #[must_use]
    pub fn events(&self) -> &[CompiledEventEvidenceV1<'ledger>] {
        &self.events
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }

    #[must_use]
    pub fn facet_kinds(&self) -> &[ProductionFacetKindV1] {
        &self.facet_kinds
    }

    #[must_use]
    pub const fn marginal_gain(&self) -> ObjectiveGainV1 {
        self.marginal_gain
    }

    #[must_use]
    pub const fn forcing_constraint(&self) -> SelectionConstraintV1 {
        self.forcing_constraint
    }

    #[must_use]
    pub const fn composable_token_upper_bound(&self) -> ComposablePacketCostV1 {
        self.composable_token_upper_bound
    }
}

impl fmt::Debug for CompiledEvidencePacketV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledEvidencePacketV1")
            .field("ordinal", &self.ordinal)
            .field("event_count", &self.events.len())
            .field("affinity_count", &self.affinities.len())
            .field("facet_kind_count", &self.facet_kinds.len())
            .field("marginal_gain", &self.marginal_gain)
            .field("forcing_constraint", &self.forcing_constraint)
            .field(
                "composable_token_upper_bound",
                &self.composable_token_upper_bound,
            )
            .finish()
    }
}

/// Structured deterministic compiled brief. It contains no generated diagnosis.
pub struct CompiledLogBriefV1<'ledger> {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    reference_authorized_at: UnixTimestampNanos,
    status: ResultStatusV1,
    selection_strategy: SelectionStrategyV1,
    normalized_gain: ObjectiveGainV1,
    cost: CompiledCostAccountingV1,
    coverage: CompiledCoverageV1,
    evidence: Vec<CompiledEvidencePacketV1<'ledger>>,
}

impl<'ledger> CompiledLogBriefV1<'ledger> {
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        COMPILED_LOG_BRIEF_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn reference_authorized_at(&self) -> UnixTimestampNanos {
        self.reference_authorized_at
    }

    #[must_use]
    pub const fn untrusted_data(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn status(&self) -> &ResultStatusV1 {
        &self.status
    }

    #[must_use]
    pub const fn selection_strategy(&self) -> SelectionStrategyV1 {
        self.selection_strategy
    }

    #[must_use]
    pub const fn normalized_gain(&self) -> ObjectiveGainV1 {
        self.normalized_gain
    }

    #[must_use]
    pub const fn cost(&self) -> CompiledCostAccountingV1 {
        self.cost
    }

    #[must_use]
    pub const fn coverage(&self) -> CompiledCoverageV1 {
        self.coverage
    }

    #[must_use]
    pub fn evidence(&self) -> &[CompiledEvidencePacketV1<'ledger>] {
        &self.evidence
    }
}

impl fmt::Debug for CompiledLogBriefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledLogBriefV1")
            .field("contract_version", &self.contract_version())
            .field("untrusted_data", &true)
            .field("acquisition_code", &self.status.acquisition().code())
            .field("selection_code", &self.status.selection().code())
            .field("selection_strategy", &self.selection_strategy)
            .field("evidence_packet_count", &self.evidence.len())
            .field("cost", &self.cost)
            .field("coverage", &self.coverage)
            .finish()
    }
}

pub struct RenderedCompiledBriefV1<'ledger> {
    brief: CompiledLogBriefV1<'ledger>,
    text: String,
}

impl<'ledger> RenderedCompiledBriefV1<'ledger> {
    #[must_use]
    pub const fn brief(&self) -> &CompiledLogBriefV1<'ledger> {
        &self.brief
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Copy authorized event bytes exactly once; do not render or tokenize again.
    #[must_use]
    pub fn into_owned(self) -> OwnedRenderedCompiledBriefV1 {
        let CompiledLogBriefV1 {
            result_id,
            question_digest,
            plan_digest,
            reference_authorized_at,
            status,
            selection_strategy,
            normalized_gain,
            cost,
            coverage,
            evidence,
        } = self.brief;
        let evidence = evidence
            .into_iter()
            .map(|packet| OwnedCompiledEvidencePacketV1 {
                ordinal: packet.ordinal,
                packet_id: packet.packet_id,
                reference: packet.reference,
                canonical_event_ids: packet.canonical_event_ids,
                events: packet
                    .events
                    .into_iter()
                    .map(|event| OwnedCompiledEventEvidenceV1 {
                        event_id: event.event_id,
                        exactness_basis: event.exactness_basis,
                        stream: event.stream,
                        authorized_bytes: event.authorized_bytes.to_vec(),
                    })
                    .collect(),
                affinities: packet.affinities,
                facet_kinds: packet.facet_kinds,
                marginal_gain: packet.marginal_gain,
                forcing_constraint: packet.forcing_constraint,
                composable_token_upper_bound: packet.composable_token_upper_bound,
            })
            .collect();
        OwnedRenderedCompiledBriefV1 {
            brief: OwnedCompiledLogBriefV1 {
                result_id,
                question_digest,
                plan_digest,
                reference_authorized_at,
                status,
                selection_strategy,
                normalized_gain,
                cost,
                coverage,
                evidence,
            },
            text: self.text,
        }
    }
}

impl fmt::Debug for RenderedCompiledBriefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedCompiledBriefV1")
            .field("brief", &self.brief)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

pub struct OwnedCompiledEventEvidenceV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    authorized_bytes: Vec<u8>,
}

impl OwnedCompiledEventEvidenceV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }

    #[must_use]
    pub fn authorized_bytes(&self) -> &[u8] {
        &self.authorized_bytes
    }
}

impl fmt::Debug for OwnedCompiledEventEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedCompiledEventEvidenceV1")
            .field("exactness_code", &self.exactness_basis.code())
            .field("stream_code", &self.stream.code())
            .field("authorized_byte_count", &self.authorized_bytes.len())
            .finish()
    }
}

pub struct OwnedCompiledEvidencePacketV1 {
    ordinal: usize,
    packet_id: PacketIdV1,
    reference: EvidenceReferenceV1,
    canonical_event_ids: Vec<EventId>,
    events: Vec<OwnedCompiledEventEvidenceV1>,
    affinities: Vec<FacetAffinityV1>,
    facet_kinds: Vec<ProductionFacetKindV1>,
    marginal_gain: ObjectiveGainV1,
    forcing_constraint: SelectionConstraintV1,
    composable_token_upper_bound: ComposablePacketCostV1,
}

impl OwnedCompiledEvidencePacketV1 {
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub fn canonical_event_ids(&self) -> &[EventId] {
        &self.canonical_event_ids
    }

    #[must_use]
    pub fn events(&self) -> &[OwnedCompiledEventEvidenceV1] {
        &self.events
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }

    #[must_use]
    pub fn facet_kinds(&self) -> &[ProductionFacetKindV1] {
        &self.facet_kinds
    }

    #[must_use]
    pub const fn marginal_gain(&self) -> ObjectiveGainV1 {
        self.marginal_gain
    }

    #[must_use]
    pub const fn forcing_constraint(&self) -> SelectionConstraintV1 {
        self.forcing_constraint
    }

    #[must_use]
    pub const fn composable_token_upper_bound(&self) -> ComposablePacketCostV1 {
        self.composable_token_upper_bound
    }
}

impl fmt::Debug for OwnedCompiledEvidencePacketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedCompiledEvidencePacketV1")
            .field("ordinal", &self.ordinal)
            .field("event_count", &self.events.len())
            .field("affinity_count", &self.affinities.len())
            .field("facet_kind_count", &self.facet_kinds.len())
            .field("marginal_gain", &self.marginal_gain)
            .field("forcing_constraint", &self.forcing_constraint)
            .field(
                "composable_token_upper_bound",
                &self.composable_token_upper_bound,
            )
            .finish()
    }
}

pub struct OwnedCompiledLogBriefV1 {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    reference_authorized_at: UnixTimestampNanos,
    status: ResultStatusV1,
    selection_strategy: SelectionStrategyV1,
    normalized_gain: ObjectiveGainV1,
    cost: CompiledCostAccountingV1,
    coverage: CompiledCoverageV1,
    evidence: Vec<OwnedCompiledEvidencePacketV1>,
}

impl OwnedCompiledLogBriefV1 {
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        COMPILED_LOG_BRIEF_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn reference_authorized_at(&self) -> UnixTimestampNanos {
        self.reference_authorized_at
    }

    #[must_use]
    pub const fn untrusted_data(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn status(&self) -> &ResultStatusV1 {
        &self.status
    }

    #[must_use]
    pub const fn selection_strategy(&self) -> SelectionStrategyV1 {
        self.selection_strategy
    }

    #[must_use]
    pub const fn normalized_gain(&self) -> ObjectiveGainV1 {
        self.normalized_gain
    }

    #[must_use]
    pub const fn cost(&self) -> CompiledCostAccountingV1 {
        self.cost
    }

    #[must_use]
    pub const fn coverage(&self) -> CompiledCoverageV1 {
        self.coverage
    }

    #[must_use]
    pub fn evidence(&self) -> &[OwnedCompiledEvidencePacketV1] {
        &self.evidence
    }
}

impl fmt::Debug for OwnedCompiledLogBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedCompiledLogBriefV1")
            .field("contract_version", &self.contract_version())
            .field("acquisition_code", &self.status.acquisition().code())
            .field("selection_code", &self.status.selection().code())
            .field("selection_strategy", &self.selection_strategy)
            .field("evidence_packet_count", &self.evidence.len())
            .field("cost", &self.cost)
            .field("coverage", &self.coverage)
            .finish()
    }
}

pub struct OwnedRenderedCompiledBriefV1 {
    brief: OwnedCompiledLogBriefV1,
    text: String,
}

impl OwnedRenderedCompiledBriefV1 {
    #[must_use]
    pub const fn brief(&self) -> &OwnedCompiledLogBriefV1 {
        &self.brief
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for OwnedRenderedCompiledBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRenderedCompiledBriefV1")
            .field("brief", &self.brief)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledCostModelViolationReasonV1 {
    RenderExceedsTotalBudget,
    RenderExceedsAccountedUpperBound,
}

impl CompiledCostModelViolationReasonV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RenderExceedsTotalBudget => "render_exceeds_total_budget",
            Self::RenderExceedsAccountedUpperBound => "render_exceeds_accounted_upper_bound",
        }
    }
}

/// Stable contentless failure from compiled evidence validation or rendering.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompiledBriefError {
    PlanDigestMismatch,
    TooManyEvidencePackets,
    UnknownSelectedEvent,
    OverlappingSelectedEvent,
    ReferenceCountMismatch,
    ReferenceUnavailable,
    DuplicateReferenceIdentity,
    ReferenceTargetsMismatch,
    ReferenceRelationsNotExactOnly,
    CostModelIdentityMismatch,
    UnsupportedTokenizerBound,
    CostCertificationMismatch,
    SelectionAccountingInvariantViolation,
    RenderedByteLimitExceeded,
    TokenizerFailure,
    TokenCountOutOfRange,
    RenderedByteCountOverflow,
    CostModelViolation(CompiledCostModelViolationReasonV1),
    CompiledMasqueradesAsPassthrough,
    CompiledHasNoPresentedEvidence,
    PresentationInvariantViolation,
}

impl CompiledBriefError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlanDigestMismatch => "EVIDENTRAIL_COMPILED_PLAN_DIGEST_MISMATCH",
            Self::TooManyEvidencePackets => "EVIDENTRAIL_COMPILED_TOO_MANY_EVIDENCE_PACKETS",
            Self::UnknownSelectedEvent => "EVIDENTRAIL_COMPILED_UNKNOWN_SELECTED_EVENT",
            Self::OverlappingSelectedEvent => "EVIDENTRAIL_COMPILED_OVERLAPPING_SELECTED_EVENT",
            Self::ReferenceCountMismatch => "EVIDENTRAIL_COMPILED_REFERENCE_COUNT_MISMATCH",
            Self::ReferenceUnavailable => "EVIDENTRAIL_COMPILED_REFERENCE_UNAVAILABLE",
            Self::DuplicateReferenceIdentity => "EVIDENTRAIL_COMPILED_DUPLICATE_REFERENCE_IDENTITY",
            Self::ReferenceTargetsMismatch => "EVIDENTRAIL_COMPILED_REFERENCE_TARGETS_MISMATCH",
            Self::ReferenceRelationsNotExactOnly => {
                "EVIDENTRAIL_COMPILED_REFERENCE_RELATIONS_NOT_EXACT_ONLY"
            }
            Self::CostModelIdentityMismatch => "EVIDENTRAIL_COMPILED_COST_MODEL_IDENTITY_MISMATCH",
            Self::UnsupportedTokenizerBound => "EVIDENTRAIL_COMPILED_UNSUPPORTED_TOKENIZER_BOUND",
            Self::CostCertificationMismatch => "EVIDENTRAIL_COMPILED_COST_CERTIFICATION_MISMATCH",
            Self::SelectionAccountingInvariantViolation => {
                "EVIDENTRAIL_COMPILED_SELECTION_ACCOUNTING_INVARIANT_VIOLATION"
            }
            Self::RenderedByteLimitExceeded => "EVIDENTRAIL_COMPILED_RENDERED_BYTE_LIMIT_EXCEEDED",
            Self::TokenizerFailure => "EVIDENTRAIL_COMPILED_TOKENIZER_FAILURE",
            Self::TokenCountOutOfRange => "EVIDENTRAIL_COMPILED_TOKEN_COUNT_OUT_OF_RANGE",
            Self::RenderedByteCountOverflow => "EVIDENTRAIL_COMPILED_RENDERED_BYTE_COUNT_OVERFLOW",
            Self::CostModelViolation(_) => "EVIDENTRAIL_COMPILED_COST_MODEL_VIOLATION",
            Self::CompiledMasqueradesAsPassthrough => "EVIDENTRAIL_COMPILED_MASQUERADES_AS_PASSTHROUGH",
            Self::CompiledHasNoPresentedEvidence => "EVIDENTRAIL_COMPILED_HAS_NO_PRESENTED_EVIDENCE",
            Self::PresentationInvariantViolation => {
                "EVIDENTRAIL_COMPILED_PRESENTATION_INVARIANT_VIOLATION"
            }
        }
    }

    #[must_use]
    pub const fn cost_model_violation_reason(self) -> Option<CompiledCostModelViolationReasonV1> {
        match self {
            Self::CostModelViolation(reason) => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Debug for CompiledBriefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CompiledBriefError");
        debug.field("code", &self.code());
        if let Some(reason) = self.cost_model_violation_reason() {
            debug.field("reason_code", &reason.code());
        }
        debug.finish()
    }
}

impl fmt::Display for CompiledBriefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CompiledBriefError {}

/// Validate, whole-render, whole-tokenize, and only then issue compiled status.
/// Packet/facet material is supplied by a caller-owned deterministic fixture;
/// this function performs no candidate generation or model inference.
#[allow(clippy::too_many_arguments)]
pub fn render_compiled_log_brief_v1<'ledger, T>(
    ledger: &'ledger EventLedger,
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    selection: SelectionV1,
    references: impl IntoIterator<Item = EvidenceReferenceV1>,
    now: UnixTimestampNanos,
    tokenizer: &T,
) -> Result<RenderedCompiledBriefV1<'ledger>, CompiledBriefError>
where
    T: PinnedTokenizer + ?Sized,
{
    let cost_model = compiled_cost_model_v1(tokenizer.digest());
    render_compiled_log_brief_with_cost_model_v1(
        ledger,
        result_id,
        question_digest,
        plan_digest,
        selection,
        references,
        now,
        tokenizer,
        cost_model,
        false,
    )
}

/// Verify a renderer-derived cost certificate, whole-render, whole-tokenize,
/// and only then issue compiled status.
///
/// Unlike [`render_compiled_log_brief_v1`], this path never treats manually
/// constructed composable cost objects as certified.
#[allow(clippy::too_many_arguments)]
pub fn render_cost_certified_compiled_log_brief_v1<'ledger>(
    ledger: &'ledger EventLedger,
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    selection: SelectionV1,
    references: impl IntoIterator<Item = EvidenceReferenceV1>,
    now: UnixTimestampNanos,
    tokenizer: &Utf8ByteTokenizerV1,
    certification: &CompiledCostCertificationV1,
) -> Result<RenderedCompiledBriefV1<'ledger>, CompiledBriefError> {
    certification
        .verify_selection(ledger, result_id, &selection, tokenizer)
        .map_err(map_cost_certification_error)?;
    render_compiled_log_brief_with_cost_model_v1(
        ledger,
        result_id,
        question_digest,
        plan_digest,
        selection,
        references,
        now,
        tokenizer,
        certification.cost_model(),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_compiled_log_brief_with_cost_model_v1<'ledger, T>(
    ledger: &'ledger EventLedger,
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    selection: SelectionV1,
    references: impl IntoIterator<Item = EvidenceReferenceV1>,
    now: UnixTimestampNanos,
    tokenizer: &T,
    cost_model: ComposableCostModelV1,
    additive_bound_certified: bool,
) -> Result<RenderedCompiledBriefV1<'ledger>, CompiledBriefError>
where
    T: PinnedTokenizer + ?Sized,
{
    if ledger.plan_digest() != plan_digest {
        return Err(CompiledBriefError::PlanDigestMismatch);
    }
    if selection.packets().len() > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
        return Err(CompiledBriefError::TooManyEvidencePackets);
    }
    let optional_budget = selection
        .total_token_budget()
        .tokens()
        .checked_sub(selection.reserved_fixed_overhead().upper_bound_tokens())
        .and_then(|available| available.checked_sub(selection.mandatory_token_cost()))
        .ok_or(CompiledBriefError::SelectionAccountingInvariantViolation)?;
    if selection.accounted_token_upper_bound() > selection.total_token_budget().tokens()
        || selection.selected_packet_cost() < selection.mandatory_token_cost()
        || selection.coverage_only_token_limit()
            != optional_budget / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1
        || selection.coverage_only_token_cost() > selection.coverage_only_token_limit()
        || selection.coverage_only_token_cost()
            > selection.selected_packet_cost() - selection.mandatory_token_cost()
    {
        return Err(CompiledBriefError::SelectionAccountingInvariantViolation);
    }

    let tokenizer_digest = tokenizer.digest();
    let renderer_digest = compiled_renderer_digest_v1();
    if selection.reserved_fixed_overhead().cost_model() != cost_model
        || selection
            .packets()
            .iter()
            .any(|packet| packet.composable_token_upper_bound().cost_model() != cost_model)
    {
        return Err(CompiledBriefError::CostModelIdentityMismatch);
    }

    let references = references.into_iter().collect::<Vec<_>>();
    if references.len() != selection.packets().len() {
        return Err(CompiledBriefError::ReferenceCountMismatch);
    }
    let mut reference_ids = BTreeSet::<EvidenceReferenceId>::new();
    let mut selected_event_ids = BTreeSet::new();
    let mut evidence = Vec::with_capacity(selection.packets().len());

    for (ordinal, (selected, reference)) in selection.packets().iter().zip(references).enumerate() {
        let packet = selected.packet();
        let packet_set = packet.event_ids().iter().copied().collect::<BTreeSet<_>>();
        for event_id in &packet_set {
            if !ledger.contains(*event_id) {
                return Err(CompiledBriefError::UnknownSelectedEvent);
            }
            if !selected_event_ids.insert(*event_id) {
                return Err(CompiledBriefError::OverlappingSelectedEvent);
            }
        }
        reference
            .authorize(result_id, ExpansionRelationV1::Exact, now)
            .map_err(|_| CompiledBriefError::ReferenceUnavailable)?;
        if !reference_ids.insert(reference.id()) {
            return Err(CompiledBriefError::DuplicateReferenceIdentity);
        }
        if reference.allowed_relations() != [ExpansionRelationV1::Exact] {
            return Err(CompiledBriefError::ReferenceRelationsNotExactOnly);
        }
        let reference_set = reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) => Ok(*event_id),
                EvidenceTargetRef::Block(_) => Err(CompiledBriefError::ReferenceTargetsMismatch),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if reference_set != packet_set || reference.targets().len() != packet_set.len() {
            return Err(CompiledBriefError::ReferenceTargetsMismatch);
        }

        let events = ledger
            .events()
            .iter()
            .filter(|event| packet_set.contains(&event.id()))
            .map(|event| CompiledEventEvidenceV1 {
                event_id: event.id(),
                exactness_basis: event.exactness_basis(),
                stream: event.lane().stream().clone(),
                authorized_bytes: event.raw(),
            })
            .collect::<Vec<_>>();
        if events.len() != packet_set.len() {
            return Err(CompiledBriefError::UnknownSelectedEvent);
        }
        evidence.push(CompiledEvidencePacketV1 {
            ordinal,
            packet_id: packet.id(),
            reference,
            canonical_event_ids: packet.event_ids().to_vec(),
            events,
            affinities: selected.affinities().to_vec(),
            facet_kinds: selected.facet_kinds().to_vec(),
            marginal_gain: selected.marginal_gain(),
            forcing_constraint: selected.forcing_constraint(),
            composable_token_upper_bound: selected.composable_token_upper_bound(),
        });
    }

    let presentation_receipt = PresentationReceipt::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            let disposition = if selected_event_ids.contains(&event.id()) {
                PresentationDisposition::ShownVerbatim
            } else {
                PresentationDisposition::RetainedRaw
            };
            PresentationAssignment::new(event.id(), disposition)
        }),
    )
    .map_err(|_| CompiledBriefError::PresentationInvariantViolation)?;
    let presentation_counts = presentation_receipt.counts();
    // The checked core API remains the sole authority for empty/all-verbatim
    // compiled rejection. This provisional value is not exposed unless the
    // whole-render cost gate below succeeds.
    let status = ResultStatusV1::compiled(ledger, presentation_receipt)
        .map_err(map_status_construction_error)?;

    let mut text = BoundedText::new(MAX_WIRE_OBJECT_BYTES);
    render_compiled_text(&mut text, ledger, result_id, &evidence, presentation_counts)
        .map_err(|_| CompiledBriefError::RenderedByteLimitExceeded)?;
    let text = text.finish();
    let total_rendered_tokens = tokenizer
        .count_tokens(&text)
        .map_err(|_| CompiledBriefError::TokenizerFailure)?;
    if total_rendered_tokens > JSON_SAFE_INTEGER_MAX {
        return Err(CompiledBriefError::TokenCountOutOfRange);
    }
    if total_rendered_tokens > selection.total_token_budget().tokens() {
        return Err(CompiledBriefError::CostModelViolation(
            CompiledCostModelViolationReasonV1::RenderExceedsTotalBudget,
        ));
    }
    if total_rendered_tokens > selection.accounted_token_upper_bound() {
        return Err(CompiledBriefError::CostModelViolation(
            CompiledCostModelViolationReasonV1::RenderExceedsAccountedUpperBound,
        ));
    }

    let total_rendered_bytes =
        u64::try_from(text.len()).map_err(|_| CompiledBriefError::RenderedByteCountOverflow)?;
    if additive_bound_certified && total_rendered_bytes > selection.accounted_token_upper_bound() {
        return Err(CompiledBriefError::CostModelViolation(
            CompiledCostModelViolationReasonV1::RenderExceedsAccountedUpperBound,
        ));
    }
    let acquisition_counts = ledger.acquisition_receipt().counts();
    let presentation_receipt = status.selection().presentation_receipt();
    let coverage = CompiledCoverageV1 {
        acquisition_receipt_id: ledger.acquisition_receipt_id(),
        presentation_receipt_id: presentation_receipt.id(),
        acknowledged_records: ledger.acquisition_receipt().acknowledged_count(),
        presentation_counts: presentation_receipt.counts(),
        source_exact_records: acquisition_counts.source_exact,
        post_policy_records: acquisition_counts.post_policy,
        omitted_by_policy_records: acquisition_counts.omitted_by_policy,
    };
    let cost = CompiledCostAccountingV1 {
        cost_model,
        total_token_budget: selection.total_token_budget().tokens(),
        reserved_fixed_overhead: selection.reserved_fixed_overhead().upper_bound_tokens(),
        mandatory_token_cost: selection.mandatory_token_cost(),
        selected_packet_cost: selection.selected_packet_cost(),
        accounted_token_upper_bound: selection.accounted_token_upper_bound(),
        coverage_only_token_limit: selection.coverage_only_token_limit(),
        coverage_only_token_cost: selection.coverage_only_token_cost(),
        total_rendered_tokens,
        total_rendered_bytes,
        tokenizer_digest,
        renderer_digest,
        additive_bound_certified,
    };
    let brief = CompiledLogBriefV1 {
        result_id,
        question_digest,
        plan_digest,
        reference_authorized_at: now,
        status,
        selection_strategy: selection.strategy(),
        normalized_gain: selection.normalized_gain(),
        cost,
        coverage,
        evidence,
    };
    Ok(RenderedCompiledBriefV1 { brief, text })
}

fn map_cost_certification_error(error: CompiledCostCertificationError) -> CompiledBriefError {
    match error {
        CompiledCostCertificationError::UnsupportedTokenizerBound => {
            CompiledBriefError::UnsupportedTokenizerBound
        }
        _ => CompiledBriefError::CostCertificationMismatch,
    }
}

fn map_status_construction_error(error: ResultStatusConstructionError) -> CompiledBriefError {
    match error {
        ResultStatusConstructionError::CompiledMasqueradesAsPassthrough => {
            CompiledBriefError::CompiledMasqueradesAsPassthrough
        }
        ResultStatusConstructionError::CompiledHasNoPresentedEvidence => {
            CompiledBriefError::CompiledHasNoPresentedEvidence
        }
        _ => CompiledBriefError::PresentationInvariantViolation,
    }
}

fn render_compiled_text(
    text: &mut BoundedText,
    ledger: &EventLedger,
    result_id: ResultId,
    evidence: &[CompiledEvidencePacketV1<'_>],
    presentation_counts: PresentationCounts,
) -> Result<(), RenderLimitExceeded> {
    render_compiled_header_v1(text, ledger, result_id)?;
    if evidence.is_empty() {
        text.push("  (none)\n")?;
    }
    for packet in evidence {
        let events = packet
            .events
            .iter()
            .map(|event| CompiledEventRenderV1 {
                exactness_code: event.exactness_basis.code(),
                stream_code: event.stream.code(),
                authorized_bytes: event.authorized_bytes,
            })
            .collect::<Vec<_>>();
        let role_codes = packet
            .facet_kinds
            .iter()
            .map(|kind| kind.code())
            .collect::<Vec<_>>();
        render_compiled_packet_v1(
            text,
            packet.ordinal,
            packet.forcing_constraint.code(),
            packet.marginal_gain.numerator(),
            packet.composable_token_upper_bound.upper_bound_tokens(),
            &role_codes,
            &events,
        )?;
    }
    render_compiled_coverage_v1(text, ledger, presentation_counts)
}

pub(super) fn render_compiled_header_v1(
    text: &mut BoundedText,
    ledger: &EventLedger,
    result_id: ResultId,
) -> Result<(), RenderLimitExceeded> {
    text.push("STATUS\n  result: ")?;
    text.push(&result_id.canonical_token())?;
    text.push("\n  untrusted_data: true\n  acquisition: ")?;
    render_acquisition(text, ledger.fetch_completion().completeness())?;
    text.push("\n  selection: COMPILED\n\n")?;

    let acquisition_counts = ledger.acquisition_receipt().counts();
    text.push("SCOPE\n  acknowledged_records: ")?;
    text.push(
        &ledger
            .acquisition_receipt()
            .acknowledged_count()
            .to_string(),
    )?;
    text.push("\n  persisted_events: ")?;
    text.push(&ledger.len().to_string())?;
    text.push("\n  policy_omitted_records: ")?;
    text.push(&acquisition_counts.omitted_by_policy.to_string())?;
    text.push("\n\nEVIDENCE\n")?;
    Ok(())
}

pub(super) struct CompiledEventRenderV1<'a> {
    pub(super) exactness_code: &'static str,
    pub(super) stream_code: &'static str,
    pub(super) authorized_bytes: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_compiled_packet_v1(
    text: &mut BoundedText,
    ordinal: usize,
    forcing_code: &str,
    marginal_gain_numerator: u64,
    composable_token_upper_bound: u64,
    role_codes: &[&str],
    events: &[CompiledEventRenderV1<'_>],
) -> Result<(), RenderLimitExceeded> {
    let display_ordinal = ordinal.checked_add(1).ok_or(RenderLimitExceeded)?;
    text.push("  [E")?;
    text.push_usize(display_ordinal)?;
    text.push("]\n    expand: E")?;
    text.push_usize(display_ordinal)?;
    text.push(" exact\n    forcing: ")?;
    text.push(forcing_code)?;
    text.push("\n    marginal_gain_numerator: ")?;
    text.push(&marginal_gain_numerator.to_string())?;
    text.push("\n    composable_token_upper_bound: ")?;
    text.push(&composable_token_upper_bound.to_string())?;
    text.push("\n    roles: ")?;
    for (index, role) in role_codes.iter().enumerate() {
        if index > 0 {
            text.push(",")?;
        }
        text.push(role)?;
    }
    text.push("\n    event_count: ")?;
    text.push_usize(events.len())?;
    text.push("\n")?;
    for (event_index, event) in events.iter().enumerate() {
        let display_event_index = event_index.checked_add(1).ok_or(RenderLimitExceeded)?;
        text.push("    event_")?;
        text.push_usize(display_event_index)?;
        text.push(":\n      exactness: ")?;
        text.push(event.exactness_code)?;
        text.push("\n      stream: ")?;
        text.push(event.stream_code)?;
        text.push("\n      data_encoding: ascii_byte_escape_v1\n      data: ")?;
        text.push_escaped(event.authorized_bytes)?;
        text.push("\n")?;
    }
    Ok(())
}

pub(super) fn render_compiled_coverage_v1(
    text: &mut BoundedText,
    ledger: &EventLedger,
    presentation_counts: PresentationCounts,
) -> Result<(), RenderLimitExceeded> {
    let acquisition_counts = ledger.acquisition_receipt().counts();
    text.push("\nCOVERAGE\n  shown_verbatim: ")?;
    text.push(&presentation_counts.shown_verbatim.to_string())?;
    text.push("\n  pattern_represented: ")?;
    text.push(&presentation_counts.pattern_represented.to_string())?;
    text.push("\n  retained_raw: ")?;
    text.push(&presentation_counts.retained_raw.to_string())?;
    text.push("\n  source_exact_records: ")?;
    text.push(&acquisition_counts.source_exact.to_string())?;
    text.push("\n  post_policy_records: ")?;
    text.push(&acquisition_counts.post_policy.to_string())?;
    text.push("\n  policy_omitted_records: ")?;
    text.push(&acquisition_counts.omitted_by_policy.to_string())?;
    text.push("\n")?;
    Ok(())
}
