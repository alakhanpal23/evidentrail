use std::fmt;

use evidentrail_core::{BlockId, RetrievalId};
use evidentrail_select::{FacetAffinityV1, FacetIdV1, ProductionFacetKindV1, ProductionFacetV1};

use crate::types::CandidateNeedsMoreV1;

pub const COVERAGE_CANDIDATE_POLICY_NAME_V1: &[u8] = b"evidentrail/failure-onset-raw-coverage";
pub const COVERAGE_CANDIDATE_POLICY_VERSION_V1: &[u8] = b"2";
/// Denominator applied to source/time breadth-facet weights. The numerator is
/// exactly one; diagnostic, onset, and reconstruction-risk facets retain full
/// V1 weight.
pub const BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1: u32 = 4;

/// Closed, byte-recognized failure vocabulary. These are syntactic signals,
/// never diagnoses, causal claims, or mandatory-selection authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureSignalKindV1 {
    Error,
    Fatal,
    Critical,
    Panic,
    Exception,
    Assertion,
    CompilerError,
    Crash,
    Failure,
}

impl FailureSignalKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Fatal => "fatal",
            Self::Critical => "critical",
            Self::Panic => "panic",
            Self::Exception => "exception",
            Self::Assertion => "assertion",
            Self::CompilerError => "compiler_error",
            Self::Crash => "crash",
            Self::Failure => "failure",
        }
    }
}

impl fmt::Debug for FailureSignalKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailureSignalKindV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Closed, byte-recognized operational-onset vocabulary. Observation of one
/// token is reported literally and never promoted to a root-cause claim.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OnsetSignalKindV1 {
    Deployment,
    Restart,
    Migration,
    ConfigurationChange,
    FeatureFlagChange,
}

impl OnsetSignalKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Restart => "restart",
            Self::Migration => "migration",
            Self::ConfigurationChange => "configuration_change",
            Self::FeatureFlagChange => "feature_flag_change",
        }
    }
}

impl fmt::Debug for OnsetSignalKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnsetSignalKindV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FailureSignalCountV1 {
    kind: FailureSignalKindV1,
    occurrence_count: u32,
}

impl FailureSignalCountV1 {
    #[must_use]
    pub(crate) const fn new(kind: FailureSignalKindV1, occurrence_count: u32) -> Self {
        Self {
            kind,
            occurrence_count,
        }
    }

    #[must_use]
    pub const fn kind(self) -> FailureSignalKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn occurrence_count(self) -> u32 {
        self.occurrence_count
    }
}

impl fmt::Debug for FailureSignalCountV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailureSignalCountV1")
            .field("kind", &self.kind)
            .field("occurrence_count", &self.occurrence_count)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OnsetSignalCountV1 {
    kind: OnsetSignalKindV1,
    occurrence_count: u32,
}

impl OnsetSignalCountV1 {
    #[must_use]
    pub(crate) const fn new(kind: OnsetSignalKindV1, occurrence_count: u32) -> Self {
        Self {
            kind,
            occurrence_count,
        }
    }

    #[must_use]
    pub const fn kind(self) -> OnsetSignalKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn occurrence_count(self) -> u32 {
        self.occurrence_count
    }
}

impl fmt::Debug for OnsetSignalCountV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnsetSignalCountV1")
            .field("kind", &self.kind)
            .field("occurrence_count", &self.occurrence_count)
            .finish()
    }
}

/// Transparent occurrence facts for one complete primary failure block.
#[derive(Clone, PartialEq, Eq)]
pub struct FailureBlockFactV1 {
    signals: Vec<FailureSignalCountV1>,
    signal_occurrence_count: u32,
    failure_block_ordinal_in_lane: u32,
    failure_block_count_in_lane: u32,
}

impl FailureBlockFactV1 {
    #[must_use]
    pub(crate) const fn new(
        signals: Vec<FailureSignalCountV1>,
        signal_occurrence_count: u32,
        failure_block_ordinal_in_lane: u32,
        failure_block_count_in_lane: u32,
    ) -> Self {
        Self {
            signals,
            signal_occurrence_count,
            failure_block_ordinal_in_lane,
            failure_block_count_in_lane,
        }
    }

    #[must_use]
    pub fn signals(&self) -> &[FailureSignalCountV1] {
        &self.signals
    }

    #[must_use]
    pub const fn signal_occurrence_count(&self) -> u32 {
        self.signal_occurrence_count
    }

    #[must_use]
    pub const fn failure_block_ordinal_in_lane(&self) -> u32 {
        self.failure_block_ordinal_in_lane
    }

    #[must_use]
    pub const fn failure_block_count_in_lane(&self) -> u32 {
        self.failure_block_count_in_lane
    }

    #[must_use]
    pub const fn is_first_in_lane(&self) -> bool {
        self.failure_block_ordinal_in_lane == 0
    }

    #[must_use]
    pub fn is_last_in_lane(&self) -> bool {
        self.failure_block_ordinal_in_lane.checked_add(1) == Some(self.failure_block_count_in_lane)
    }
}

impl fmt::Debug for FailureBlockFactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailureBlockFactV1")
            .field("signal_kind_count", &self.signals.len())
            .field("signal_occurrence_count", &self.signal_occurrence_count)
            .field(
                "failure_block_ordinal_in_lane",
                &self.failure_block_ordinal_in_lane,
            )
            .field(
                "failure_block_count_in_lane",
                &self.failure_block_count_in_lane,
            )
            .finish()
    }
}

/// Boundary labels describe only visible ordering within one source lane.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OnsetBoundaryRoleV1 {
    FirstFailureInLane,
    LastAvailableBeforeFirstFailure,
    FirstExplicitOnsetInLane,
    LastAvailableBeforeFirstExplicitOnset,
}

impl OnsetBoundaryRoleV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstFailureInLane => "first_failure_in_lane",
            Self::LastAvailableBeforeFirstFailure => "last_available_before_first_failure",
            Self::FirstExplicitOnsetInLane => "first_explicit_onset_in_lane",
            Self::LastAvailableBeforeFirstExplicitOnset => {
                "last_available_before_first_explicit_onset"
            }
        }
    }
}

impl fmt::Debug for OnsetBoundaryRoleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnsetBoundaryRoleV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OnsetBoundaryFactV1 {
    role: OnsetBoundaryRoleV1,
    boundary_block_id: BlockId,
}

impl OnsetBoundaryFactV1 {
    #[must_use]
    pub(crate) const fn new(role: OnsetBoundaryRoleV1, boundary_block_id: BlockId) -> Self {
        Self {
            role,
            boundary_block_id,
        }
    }

    #[must_use]
    pub const fn role(self) -> OnsetBoundaryRoleV1 {
        self.role
    }

    /// The visible first failure/onset block this ordering fact is relative to.
    #[must_use]
    pub const fn boundary_block_id(self) -> BlockId {
        self.boundary_block_id
    }
}

impl fmt::Debug for OnsetBoundaryFactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnsetBoundaryFactV1")
            .field("role", &self.role)
            .field("boundary_present", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceCoverageStratumKindV1 {
    RetrievalHead,
    RetrievalTail,
    SourceStreamHead,
    SourceStreamTail,
}

impl SourceCoverageStratumKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RetrievalHead => "retrieval_head",
            Self::RetrievalTail => "retrieval_tail",
            Self::SourceStreamHead => "source_stream_head",
            Self::SourceStreamTail => "source_stream_tail",
        }
    }
}

impl fmt::Debug for SourceCoverageStratumKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceCoverageStratumKindV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReconstructionRiskKindV1 {
    MediumConfidence,
    LowConfidence,
    UnknownConfidence,
    AmbiguousBoundary,
    FallbackSingleton,
    Fragment,
}

impl ReconstructionRiskKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MediumConfidence => "medium_confidence",
            Self::LowConfidence => "low_confidence",
            Self::UnknownConfidence => "unknown_confidence",
            Self::AmbiguousBoundary => "ambiguous_boundary",
            Self::FallbackSingleton => "fallback_singleton",
            Self::Fragment => "fragment",
        }
    }
}

impl fmt::Debug for ReconstructionRiskKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconstructionRiskKindV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageSentinelKindV1 {
    Source(SourceCoverageStratumKindV1),
    AcquisitionOrderStratum { index: u8, count: u8 },
    ReconstructionRisk(ReconstructionRiskKindV1),
}

impl fmt::Debug for CoverageSentinelKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(kind) => formatter
                .debug_struct("CoverageSentinelKindV1")
                .field("family", &"source")
                .field("kind", kind)
                .finish(),
            Self::AcquisitionOrderStratum { index, count } => formatter
                .debug_struct("CoverageSentinelKindV1")
                .field("family", &"acquisition_order")
                .field("index", index)
                .field("count", count)
                .finish(),
            Self::ReconstructionRisk(kind) => formatter
                .debug_struct("CoverageSentinelKindV1")
                .field("family", &"reconstruction_risk")
                .field("kind", kind)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoverageSentinelV1 {
    kind: CoverageSentinelKindV1,
    facet_id: FacetIdV1,
}

impl CoverageSentinelV1 {
    #[must_use]
    pub(crate) const fn new(kind: CoverageSentinelKindV1, facet_id: FacetIdV1) -> Self {
        Self { kind, facet_id }
    }

    #[must_use]
    pub const fn kind(self) -> CoverageSentinelKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }
}

impl fmt::Debug for CoverageSentinelV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageSentinelV1")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageFacetRoleV1 {
    Failure(FailureSignalKindV1),
    ExplicitOnset(OnsetSignalKindV1),
    OnsetBoundary(OnsetBoundaryRoleV1),
    Source(SourceCoverageStratumKindV1),
    AcquisitionOrderStratum { index: u8, count: u8 },
    ReconstructionRisk(ReconstructionRiskKindV1),
}

impl fmt::Debug for CoverageFacetRoleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageFacetRoleV1")
            .field(
                "family",
                &match self {
                    Self::Failure(_) => "failure",
                    Self::ExplicitOnset(_) | Self::OnsetBoundary(_) => "onset",
                    Self::Source(_) => "source",
                    Self::AcquisitionOrderStratum { .. } => "time",
                    Self::ReconstructionRisk(_) => "reconstruction_risk",
                },
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CoverageFacetV1 {
    facet: ProductionFacetV1,
    role: CoverageFacetRoleV1,
}

impl CoverageFacetV1 {
    #[must_use]
    pub(crate) const fn new(facet: ProductionFacetV1, role: CoverageFacetRoleV1) -> Self {
        Self { facet, role }
    }

    #[must_use]
    pub const fn facet(&self) -> &ProductionFacetV1 {
        &self.facet
    }

    #[must_use]
    pub const fn kind(&self) -> ProductionFacetKindV1 {
        self.facet.kind()
    }

    #[must_use]
    pub const fn role(&self) -> CoverageFacetRoleV1 {
        self.role
    }
}

impl fmt::Debug for CoverageFacetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageFacetV1")
            .field("kind", &self.kind())
            .field("role", &self.role)
            .finish()
    }
}

/// Independent lane-2 annotation keyed only by a reconciled primary BlockId.
/// It carries no alternate packet membership and no mandatory authority.
#[derive(Clone, PartialEq, Eq)]
pub struct CoverageBlockAnnotationV1 {
    block_id: BlockId,
    failure: Option<FailureBlockFactV1>,
    onset_signals: Vec<OnsetSignalCountV1>,
    onset_boundaries: Vec<OnsetBoundaryFactV1>,
    reconstruction_risks: Vec<ReconstructionRiskKindV1>,
    sentinels: Vec<CoverageSentinelV1>,
    affinities: Vec<FacetAffinityV1>,
}

impl CoverageBlockAnnotationV1 {
    #[must_use]
    pub(crate) const fn new(
        block_id: BlockId,
        failure: Option<FailureBlockFactV1>,
        onset_signals: Vec<OnsetSignalCountV1>,
        onset_boundaries: Vec<OnsetBoundaryFactV1>,
        reconstruction_risks: Vec<ReconstructionRiskKindV1>,
        sentinels: Vec<CoverageSentinelV1>,
        affinities: Vec<FacetAffinityV1>,
    ) -> Self {
        Self {
            block_id,
            failure,
            onset_signals,
            onset_boundaries,
            reconstruction_risks,
            sentinels,
            affinities,
        }
    }

    #[must_use]
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    #[must_use]
    pub const fn failure(&self) -> Option<&FailureBlockFactV1> {
        self.failure.as_ref()
    }

    #[must_use]
    pub fn onset_signals(&self) -> &[OnsetSignalCountV1] {
        &self.onset_signals
    }

    #[must_use]
    pub fn onset_boundaries(&self) -> &[OnsetBoundaryFactV1] {
        &self.onset_boundaries
    }

    /// Exhaustive transparent facts derived only from the reconciled block's
    /// confidence, boundary state, and fragment state. Presence here does not
    /// grant selector affinity or claim that this block represents its peers.
    #[must_use]
    pub fn reconstruction_risks(&self) -> &[ReconstructionRiskKindV1] {
        &self.reconstruction_risks
    }

    #[must_use]
    pub fn sentinels(&self) -> &[CoverageSentinelV1] {
        &self.sentinels
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }
}

impl fmt::Debug for CoverageBlockAnnotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageBlockAnnotationV1")
            .field("failure_present", &self.failure.is_some())
            .field("onset_signal_kind_count", &self.onset_signals.len())
            .field("onset_boundary_count", &self.onset_boundaries.len())
            .field(
                "reconstruction_risk_fact_count",
                &self.reconstruction_risks.len(),
            )
            .field("sentinel_count", &self.sentinels.len())
            .field("affinity_count", &self.affinities.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoverageAccountingV1 {
    scanned_bytes: u64,
    scanned_analysis_tokens: u64,
    failure_signal_observations: usize,
    onset_signal_observations: usize,
    reconstruction_risk_fact_count: usize,
    reconstruction_risk_representative_count: usize,
    source_lane_count: usize,
    emitted_facet_count: usize,
    emitted_affinity_count: usize,
    emitted_sentinel_count: usize,
}

pub(crate) struct CoverageAccountingPartsV1 {
    pub(crate) scanned_bytes: u64,
    pub(crate) scanned_analysis_tokens: u64,
    pub(crate) failure_signal_observations: usize,
    pub(crate) onset_signal_observations: usize,
    pub(crate) reconstruction_risk_fact_count: usize,
    pub(crate) reconstruction_risk_representative_count: usize,
    pub(crate) source_lane_count: usize,
    pub(crate) emitted_facet_count: usize,
    pub(crate) emitted_affinity_count: usize,
    pub(crate) emitted_sentinel_count: usize,
}

impl CoverageAccountingV1 {
    #[must_use]
    pub(crate) const fn new(parts: CoverageAccountingPartsV1) -> Self {
        Self {
            scanned_bytes: parts.scanned_bytes,
            scanned_analysis_tokens: parts.scanned_analysis_tokens,
            failure_signal_observations: parts.failure_signal_observations,
            onset_signal_observations: parts.onset_signal_observations,
            reconstruction_risk_fact_count: parts.reconstruction_risk_fact_count,
            reconstruction_risk_representative_count: parts
                .reconstruction_risk_representative_count,
            source_lane_count: parts.source_lane_count,
            emitted_facet_count: parts.emitted_facet_count,
            emitted_affinity_count: parts.emitted_affinity_count,
            emitted_sentinel_count: parts.emitted_sentinel_count,
        }
    }

    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn scanned_analysis_tokens(self) -> u64 {
        self.scanned_analysis_tokens
    }

    #[must_use]
    pub const fn failure_signal_observations(self) -> usize {
        self.failure_signal_observations
    }

    #[must_use]
    pub const fn onset_signal_observations(self) -> usize {
        self.onset_signal_observations
    }

    /// Number of exhaustive `(block, risk-kind)` facts recorded before any
    /// representative selection.
    #[must_use]
    pub const fn reconstruction_risk_fact_count(self) -> usize {
        self.reconstruction_risk_fact_count
    }

    /// Number of `(block, risk-kind)` facts given a reconstruction-risk
    /// sentinel and affinity by the bounded representative policy.
    #[must_use]
    pub const fn reconstruction_risk_representative_count(self) -> usize {
        self.reconstruction_risk_representative_count
    }

    #[must_use]
    pub const fn source_lane_count(self) -> usize {
        self.source_lane_count
    }

    #[must_use]
    pub const fn emitted_facet_count(self) -> usize {
        self.emitted_facet_count
    }

    #[must_use]
    pub const fn emitted_affinity_count(self) -> usize {
        self.emitted_affinity_count
    }

    #[must_use]
    pub const fn emitted_sentinel_count(self) -> usize {
        self.emitted_sentinel_count
    }
}

impl fmt::Debug for CoverageAccountingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageAccountingV1")
            .field("scanned_bytes", &self.scanned_bytes)
            .field("scanned_analysis_tokens", &self.scanned_analysis_tokens)
            .field(
                "failure_signal_observations",
                &self.failure_signal_observations,
            )
            .field("onset_signal_observations", &self.onset_signal_observations)
            .field(
                "reconstruction_risk_fact_count",
                &self.reconstruction_risk_fact_count,
            )
            .field(
                "reconstruction_risk_representative_count",
                &self.reconstruction_risk_representative_count,
            )
            .field("source_lane_count", &self.source_lane_count)
            .field("emitted_facet_count", &self.emitted_facet_count)
            .field("emitted_affinity_count", &self.emitted_affinity_count)
            .field("emitted_sentinel_count", &self.emitted_sentinel_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CoverageCandidateUniverseV1 {
    retrieval_id: RetrievalId,
    facets: Vec<CoverageFacetV1>,
    annotations: Vec<CoverageBlockAnnotationV1>,
    accounting: CoverageAccountingV1,
}

impl CoverageCandidateUniverseV1 {
    pub const CONTRACT_VERSION: u16 = 1;

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        Self::CONTRACT_VERSION
    }

    #[must_use]
    pub const fn policy_name(&self) -> &'static [u8] {
        COVERAGE_CANDIDATE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn policy_version(&self) -> &'static [u8] {
        COVERAGE_CANDIDATE_POLICY_VERSION_V1
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub fn facets(&self) -> &[CoverageFacetV1] {
        &self.facets
    }

    /// Exactly one annotation per reconciled primary block, sorted by BlockId.
    #[must_use]
    pub fn annotations(&self) -> &[CoverageBlockAnnotationV1] {
        &self.annotations
    }

    #[must_use]
    pub const fn accounting(&self) -> CoverageAccountingV1 {
        self.accounting
    }

    pub(crate) fn new(
        retrieval_id: RetrievalId,
        facets: Vec<CoverageFacetV1>,
        annotations: Vec<CoverageBlockAnnotationV1>,
        accounting: CoverageAccountingV1,
    ) -> Self {
        Self {
            retrieval_id,
            facets,
            annotations,
            accounting,
        }
    }
}

impl fmt::Debug for CoverageCandidateUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverageCandidateUniverseV1")
            .field("facet_count", &self.facets.len())
            .field("annotation_count", &self.annotations.len())
            .field("accounting", &self.accounting)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum CoverageGenerationDecisionV1 {
    Ready(CoverageCandidateUniverseV1),
    NeedsMore(CandidateNeedsMoreV1),
}

impl CoverageGenerationDecisionV1 {
    #[must_use]
    pub const fn ready(&self) -> Option<&CoverageCandidateUniverseV1> {
        match self {
            Self::Ready(universe) => Some(universe),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<CandidateNeedsMoreV1> {
        match self {
            Self::Ready(_) => None,
            Self::NeedsMore(reason) => Some(*reason),
        }
    }
}

impl fmt::Debug for CoverageGenerationDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(universe) => formatter
                .debug_struct("CoverageGenerationDecisionV1")
                .field("state", &"ready")
                .field("summary", universe)
                .finish(),
            Self::NeedsMore(reason) => formatter
                .debug_struct("CoverageGenerationDecisionV1")
                .field("state", &"needs_more")
                .field("reason", reason)
                .finish(),
        }
    }
}
