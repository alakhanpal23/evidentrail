//! Frozen, hermetic incident-outcome conformance corpus.
//!
//! Public construction owns only synthetic authorized records, symptom-focused
//! questions, operational scope, acquisition completeness, and label-blind
//! method/oracle receipts. Fault families, acceptable diagnoses, abstention
//! authority, evidence requirements, and claim policy enter through a separate
//! governed join. This type boundary is not external process attestation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{
    PreparedThreeLaneSelectionDecisionV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1,
    benchmark_selection_problem_for_prepared_three_lane_ablation_v1,
    prepare_three_lane_ablations_v1, select_prepared_three_lane_ablation_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries, FetchCompleteness,
    FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons, FetchTiming,
    FetchUnknownReason, FramingPolicy, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, ProviderAttestationScopeDigestV1, ProviderAttestationValueV1,
    ProviderAttestationsV1, ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, ResultId, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::{ObjectiveGainV1, TotalTokenBudgetV1};
use sha2::{Digest as _, Sha256};

use crate::{
    BenchmarkMethod, Bm25fConfigV1, Bm25fWholeEventV1, ByteBudget, EvidenceTargetV1,
    EvidentrailBenchAnnotationSpecV1, ExpectedAcquisitionClassV1, GrepHeadTail, GrepHeadTailConfig,
    MethodInput, QuotaHybrid, QuotaHybridConfig, RawChronological, WeightedDiagnosticRequirementV1,
    evaluate_exact_small_selection_oracle_v1,
};
use crate::{ExactSelectionOracleErrorV1, ExactSmallSelectionOracleDecisionV1};

const PUBLIC_ARM_DOMAIN_V1: &[u8] = b"evidentrail/bench/hermetic-incident-arm/v1\0";
const PUBLIC_ORACLE_DOMAIN_V1: &[u8] = b"evidentrail/bench/hermetic-incident-oracle/v1\0";
const PUBLIC_CASE_DOMAIN_V1: &[u8] = b"evidentrail/bench/hermetic-incident-public-case/v1\0";
const PUBLIC_CORPUS_DOMAIN_V1: &[u8] = b"evidentrail/bench/hermetic-incident-public-corpus/v1\0";
const GOVERNED_ANNOTATION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/hermetic-incident-governed-annotation/v1\0";
const GOVERNED_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/hermetic-incident-governed-corpus/v1\0";

pub const HERMETIC_INCIDENT_CASE_COUNT_V1: usize = 8;
pub const HERMETIC_INCIDENT_RECORD_COUNT_V1: usize = 10;
pub const HERMETIC_INCIDENT_TOTAL_TOKEN_BUDGET_V1: u64 = 16_384;
pub const MAX_HERMETIC_INCIDENT_CLAIM_BYTES_V1: usize = 256;
pub const MAX_HERMETIC_INCIDENT_ROOT_ALTERNATIVES_V1: usize = 4;
pub const MAX_HERMETIC_INCIDENT_REQUIREMENTS_V1: usize = 8;

/// Neutral public identities. Names deliberately encode no hidden cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HermeticIncidentCaseV1 {
    Case01,
    Case02,
    Case03,
    Case04,
    Case05,
    Case06,
    Case07,
    Case08,
}

impl HermeticIncidentCaseV1 {
    pub const ALL: [Self; HERMETIC_INCIDENT_CASE_COUNT_V1] = [
        Self::Case01,
        Self::Case02,
        Self::Case03,
        Self::Case04,
        Self::Case05,
        Self::Case06,
        Self::Case07,
        Self::Case08,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Case01 => "case_01_v1",
            Self::Case02 => "case_02_v1",
            Self::Case03 => "case_03_v1",
            Self::Case04 => "case_04_v1",
            Self::Case05 => "case_05_v1",
            Self::Case06 => "case_06_v1",
            Self::Case07 => "case_07_v1",
            Self::Case08 => "case_08_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HermeticIncidentRuntimeV1 {
    Python,
    Jvm,
    DotNet,
    JavaScript,
    Rust,
    Go,
    Kubernetes,
    MultiService,
}

impl HermeticIncidentRuntimeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Jvm => "jvm",
            Self::DotNet => "dotnet",
            Self::JavaScript => "javascript",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Kubernetes => "kubernetes",
            Self::MultiService => "multi_service",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HermeticIncidentArmV1 {
    FullThreeLane,
    RawChronological,
    GrepHeadTail,
    QuotaHybrid,
    Bm25fWholeEvent,
}

impl HermeticIncidentArmV1 {
    pub const ALL: [Self; 5] = [
        Self::FullThreeLane,
        Self::RawChronological,
        Self::GrepHeadTail,
        Self::QuotaHybrid,
        Self::Bm25fWholeEvent,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FullThreeLane => "production_full_three_lane_v1",
            Self::RawChronological => "raw_chronological_v1",
            Self::GrepHeadTail => "grep_head_tail_v1",
            Self::QuotaHybrid => "quota_hybrid_v1",
            Self::Bm25fWholeEvent => "bm25f_whole_event_v1",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HermeticIncidentCorpusErrorV1 {
    FixtureInvariant,
    ArithmeticOverflow,
    DigestLengthOverflow,
    LedgerBuild,
    Compiler,
    FullMethodNeedsMore,
    Baseline,
    ExactOracle,
    ExactOracleIneligible,
    DuplicateCase,
    MissingCase,
    ForeignCase,
    AnnotationBounds,
    EvidenceTargetMismatch,
    OutcomeMismatch,
    AbstentionAuthorityMismatch,
    ClaimPolicyConflict,
}

impl HermeticIncidentCorpusErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixtureInvariant => "EVIDENTRAIL_BENCH_INCIDENT_FIXTURE",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_INCIDENT_ARITHMETIC",
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_INCIDENT_DIGEST_LENGTH",
            Self::LedgerBuild => "EVIDENTRAIL_BENCH_INCIDENT_LEDGER",
            Self::Compiler => "EVIDENTRAIL_BENCH_INCIDENT_COMPILER",
            Self::FullMethodNeedsMore => "EVIDENTRAIL_BENCH_INCIDENT_FULL_NEEDS_MORE",
            Self::Baseline => "EVIDENTRAIL_BENCH_INCIDENT_BASELINE",
            Self::ExactOracle => "EVIDENTRAIL_BENCH_INCIDENT_EXACT_ORACLE",
            Self::ExactOracleIneligible => "EVIDENTRAIL_BENCH_INCIDENT_EXACT_ORACLE_INELIGIBLE",
            Self::DuplicateCase => "EVIDENTRAIL_BENCH_INCIDENT_DUPLICATE_CASE",
            Self::MissingCase => "EVIDENTRAIL_BENCH_INCIDENT_MISSING_CASE",
            Self::ForeignCase => "EVIDENTRAIL_BENCH_INCIDENT_FOREIGN_CASE",
            Self::AnnotationBounds => "EVIDENTRAIL_BENCH_INCIDENT_ANNOTATION_BOUNDS",
            Self::EvidenceTargetMismatch => "EVIDENTRAIL_BENCH_INCIDENT_EVIDENCE_TARGET",
            Self::OutcomeMismatch => "EVIDENTRAIL_BENCH_INCIDENT_OUTCOME_MISMATCH",
            Self::AbstentionAuthorityMismatch => "EVIDENTRAIL_BENCH_INCIDENT_ABSTENTION_AUTHORITY",
            Self::ClaimPolicyConflict => "EVIDENTRAIL_BENCH_INCIDENT_CLAIM_POLICY_CONFLICT",
        }
    }
}

impl fmt::Debug for HermeticIncidentCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentCorpusErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for HermeticIncidentCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for HermeticIncidentCorpusErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenHermeticIncidentArmOutcomeV1 {
    digest: ArtifactDigest,
    arm: HermeticIncidentArmV1,
    producer_receipt_digest: Option<ArtifactDigest>,
    method_config_digest: Option<ArtifactDigest>,
    selected_event_ids: Vec<EventId>,
    selected_unique_source_bytes: u64,
    selected_packet_count: u64,
    accounted_token_upper_bound: Option<u64>,
    objective_gain: Option<ObjectiveGainV1>,
}

impl FrozenHermeticIncidentArmOutcomeV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn arm(&self) -> HermeticIncidentArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn producer_receipt_digest(&self) -> Option<ArtifactDigest> {
        self.producer_receipt_digest
    }

    #[must_use]
    pub const fn method_config_digest(&self) -> Option<ArtifactDigest> {
        self.method_config_digest
    }

    #[must_use]
    pub fn selected_event_ids(&self) -> &[EventId] {
        &self.selected_event_ids
    }

    #[must_use]
    pub const fn selected_unique_source_bytes(&self) -> u64 {
        self.selected_unique_source_bytes
    }

    #[must_use]
    pub const fn selected_packet_count(&self) -> u64 {
        self.selected_packet_count
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(&self) -> Option<u64> {
        self.accounted_token_upper_bound
    }

    #[must_use]
    pub const fn objective_gain(&self) -> Option<ObjectiveGainV1> {
        self.objective_gain
    }
}

impl fmt::Debug for FrozenHermeticIncidentArmOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenHermeticIncidentArmOutcomeV1")
            .field("outcome_identity_present", &true)
            .field("arm", &self.arm)
            .field(
                "producer_receipt_identity_present",
                &self.producer_receipt_digest.is_some(),
            )
            .field(
                "method_config_identity_present",
                &self.method_config_digest.is_some(),
            )
            .field("selected_event_count", &self.selected_event_ids.len())
            .field(
                "selected_unique_source_bytes",
                &self.selected_unique_source_bytes,
            )
            .field("selected_packet_count", &self.selected_packet_count)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("objective_gain_present", &self.objective_gain.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenHermeticIncidentExactOracleV1 {
    digest: ArtifactDigest,
    selected_event_ids: Vec<EventId>,
    selected_packet_count: u64,
    objective_gain: ObjectiveGainV1,
    accounted_token_upper_bound: u64,
    reachable_subset_count: u64,
}

impl FrozenHermeticIncidentExactOracleV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub fn selected_event_ids(&self) -> &[EventId] {
        &self.selected_event_ids
    }

    #[must_use]
    pub const fn selected_packet_count(&self) -> u64 {
        self.selected_packet_count
    }

    #[must_use]
    pub const fn objective_gain(&self) -> ObjectiveGainV1 {
        self.objective_gain
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(&self) -> u64 {
        self.accounted_token_upper_bound
    }

    #[must_use]
    pub const fn reachable_subset_count(&self) -> u64 {
        self.reachable_subset_count
    }

    #[must_use]
    pub const fn optional_packet_cap(&self) -> usize {
        crate::MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    }

    #[must_use]
    pub const fn oracle_policy_name(&self) -> &'static [u8] {
        crate::EXACT_SELECTION_ORACLE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn oracle_policy_version(&self) -> &'static [u8] {
        crate::EXACT_SELECTION_ORACLE_POLICY_VERSION_V1
    }
}

impl fmt::Debug for FrozenHermeticIncidentExactOracleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenHermeticIncidentExactOracleV1")
            .field("oracle_identity_present", &true)
            .field("selected_event_count", &self.selected_event_ids.len())
            .field("selected_packet_count", &self.selected_packet_count)
            .field("objective_gain", &self.objective_gain)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("reachable_subset_count", &self.reachable_subset_count)
            .field(
                "optional_packet_cap",
                &crate::MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct FrozenHermeticIncidentPublicCaseV1 {
    digest: ArtifactDigest,
    case: HermeticIncidentCaseV1,
    runtime: HermeticIncidentRuntimeV1,
    scope_components: Vec<Vec<u8>>,
    question: Vec<u8>,
    expected_acquisition_class: ExpectedAcquisitionClassV1,
    total_token_budget: u64,
    matched_source_byte_budget: u64,
    ledger: evidentrail_core::EventLedger,
    outcomes: [FrozenHermeticIncidentArmOutcomeV1; 5],
    exact_oracle: FrozenHermeticIncidentExactOracleV1,
}

impl PartialEq for FrozenHermeticIncidentPublicCaseV1 {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for FrozenHermeticIncidentPublicCaseV1 {}

impl FrozenHermeticIncidentPublicCaseV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> HermeticIncidentCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn runtime(&self) -> HermeticIncidentRuntimeV1 {
        self.runtime
    }

    #[must_use]
    pub fn scope_components(&self) -> &[Vec<u8>] {
        &self.scope_components
    }

    #[must_use]
    pub fn question(&self) -> &[u8] {
        &self.question
    }

    #[must_use]
    pub const fn expected_acquisition_class(&self) -> ExpectedAcquisitionClassV1 {
        self.expected_acquisition_class
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> u64 {
        self.total_token_budget
    }

    /// Exact unique authorized source bytes selected by the Full arm. This is
    /// the byte budget used for each cheap baseline and is not renderer-output
    /// parity.
    #[must_use]
    pub const fn matched_source_byte_budget(&self) -> u64 {
        self.matched_source_byte_budget
    }

    #[must_use]
    pub const fn ledger(&self) -> &evidentrail_core::EventLedger {
        &self.ledger
    }

    #[must_use]
    pub fn outcomes(&self) -> &[FrozenHermeticIncidentArmOutcomeV1; 5] {
        &self.outcomes
    }

    #[must_use]
    pub fn outcome(&self, arm: HermeticIncidentArmV1) -> &FrozenHermeticIncidentArmOutcomeV1 {
        &self.outcomes[arm_index(arm)]
    }

    #[must_use]
    pub const fn exact_oracle(&self) -> &FrozenHermeticIncidentExactOracleV1 {
        &self.exact_oracle
    }

    #[must_use]
    pub const fn contains_governed_labels(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn budget_basis_code(&self) -> &'static str {
        "full_selected_unique_authorized_source_bytes_only"
    }
}

impl fmt::Debug for FrozenHermeticIncidentPublicCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenHermeticIncidentPublicCaseV1")
            .field("case_identity_present", &true)
            .field("case", &self.case)
            .field("runtime", &self.runtime)
            .field("scope_component_count", &self.scope_components.len())
            .field("question_byte_count", &self.question.len())
            .field(
                "expected_acquisition_class",
                &self.expected_acquisition_class,
            )
            .field("total_token_budget", &self.total_token_budget)
            .field(
                "matched_source_byte_budget",
                &self.matched_source_byte_budget,
            )
            .field("ledger", &self.ledger)
            .field("outcome_count", &self.outcomes.len())
            .field("exact_oracle", &self.exact_oracle)
            .field("contains_governed_labels", &false)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenHermeticIncidentPublicCorpusV1 {
    digest: ArtifactDigest,
    cases: [FrozenHermeticIncidentPublicCaseV1; HERMETIC_INCIDENT_CASE_COUNT_V1],
    complete_count: u64,
    partial_count: u64,
    unknown_count: u64,
}

impl FrozenHermeticIncidentPublicCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub fn cases(&self) -> &[FrozenHermeticIncidentPublicCaseV1; HERMETIC_INCIDENT_CASE_COUNT_V1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: HermeticIncidentCaseV1) -> &FrozenHermeticIncidentPublicCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub const fn complete_count(&self) -> u64 {
        self.complete_count
    }

    #[must_use]
    pub const fn partial_count(&self) -> u64 {
        self.partial_count
    }

    #[must_use]
    pub const fn unknown_count(&self) -> u64 {
        self.unknown_count
    }

    #[must_use]
    pub const fn contains_governed_labels(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn scope_code(&self) -> &'static str {
        "synthetic_hermetic_conformance_only_v1"
    }

    #[must_use]
    pub const fn claims_hosted_quality(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn staging_trust_boundary_code(&self) -> &'static str {
        "label_free_data_boundary_not_external_temporal_attestation"
    }
}

impl fmt::Debug for FrozenHermeticIncidentPublicCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenHermeticIncidentPublicCorpusV1")
            .field("corpus_identity_present", &true)
            .field("case_count", &self.cases.len())
            .field("complete_count", &self.complete_count)
            .field("partial_count", &self.partial_count)
            .field("unknown_count", &self.unknown_count)
            .field("scope", &self.scope_code())
            .field("contains_governed_labels", &false)
            .field("claims_hosted_quality", &false)
            .field(
                "staging_trust_boundary",
                &self.staging_trust_boundary_code(),
            )
            .finish()
    }
}

struct SourceExactPolicyV1;

impl DeterministicPolicy for SourceExactPolicyV1 {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone)]
struct FixtureRecordV1 {
    component: Vec<u8>,
    stream: SourceStream,
    payload: Vec<u8>,
    terminator: Vec<u8>,
    attestations: ProviderAttestationsV1,
}

impl FixtureRecordV1 {
    fn new(
        component: &[u8],
        stream: SourceStream,
        payload: impl Into<Vec<u8>>,
        position: usize,
    ) -> Self {
        Self {
            component: component.to_vec(),
            stream,
            payload: payload.into(),
            terminator: if position + 1 == HERMETIC_INCIDENT_RECORD_COUNT_V1 {
                Vec::new()
            } else if position % 3 == 0 {
                b"\r\n".to_vec()
            } else {
                b"\n".to_vec()
            },
            attestations: ProviderAttestationsV1::default(),
        }
    }
}

fn case_index(case: HermeticIncidentCaseV1) -> usize {
    HermeticIncidentCaseV1::ALL
        .iter()
        .position(|candidate| *candidate == case)
        .expect("closed incident case roster")
}

const fn arm_index(arm: HermeticIncidentArmV1) -> usize {
    match arm {
        HermeticIncidentArmV1::FullThreeLane => 0,
        HermeticIncidentArmV1::RawChronological => 1,
        HermeticIncidentArmV1::GrepHeadTail => 2,
        HermeticIncidentArmV1::QuotaHybrid => 3,
        HermeticIncidentArmV1::Bm25fWholeEvent => 4,
    }
}

fn runtime(case: HermeticIncidentCaseV1) -> HermeticIncidentRuntimeV1 {
    match case {
        HermeticIncidentCaseV1::Case01 => HermeticIncidentRuntimeV1::Python,
        HermeticIncidentCaseV1::Case02 => HermeticIncidentRuntimeV1::Jvm,
        HermeticIncidentCaseV1::Case03 => HermeticIncidentRuntimeV1::DotNet,
        HermeticIncidentCaseV1::Case04 => HermeticIncidentRuntimeV1::JavaScript,
        HermeticIncidentCaseV1::Case05 => HermeticIncidentRuntimeV1::Rust,
        HermeticIncidentCaseV1::Case06 => HermeticIncidentRuntimeV1::Go,
        HermeticIncidentCaseV1::Case07 => HermeticIncidentRuntimeV1::Kubernetes,
        HermeticIncidentCaseV1::Case08 => HermeticIncidentRuntimeV1::MultiService,
    }
}

fn scope_components(case: HermeticIncidentCaseV1) -> &'static [&'static [u8]] {
    match case {
        HermeticIncidentCaseV1::Case01 => &[b"checkout-api", b"orders-db"],
        HermeticIncidentCaseV1::Case02 => &[b"search-api", b"profile-service"],
        HermeticIncidentCaseV1::Case03 => &[b"edge-proxy", b"identity-api"],
        HermeticIncidentCaseV1::Case04 => &[b"upload-api", b"node-worker"],
        HermeticIncidentCaseV1::Case05 => &[b"ingest-gateway", b"rust-decoder"],
        HermeticIncidentCaseV1::Case06 => &[b"go-worker", b"cluster-dns"],
        HermeticIncidentCaseV1::Case07 => &[b"image-worker", b"node-agent"],
        HermeticIncidentCaseV1::Case08 => {
            &[b"checkout-api", b"inventory-api", b"deployment-controller"]
        }
    }
}

fn question(case: HermeticIncidentCaseV1) -> &'static [u8] {
    match case {
        HermeticIncidentCaseV1::Case01 => {
            b"Why did checkout request req-7f91 begin returning HTTP 500?"
        }
        HermeticIncidentCaseV1::Case02 => {
            b"Why are search requests timing out while profile remains healthy?"
        }
        HermeticIncidentCaseV1::Case03 => {
            b"Why is the edge proxy returning 502 for identity traffic?"
        }
        HermeticIncidentCaseV1::Case04 => {
            b"Why do upload health checks time out during large requests?"
        }
        HermeticIncidentCaseV1::Case05 => {
            b"What caused the ingest decoder panic and downstream 503s?"
        }
        HermeticIncidentCaseV1::Case06 => {
            b"Why did the Go worker begin hitting dependency deadlines?"
        }
        HermeticIncidentCaseV1::Case07 => {
            b"Can the authorized logs establish why the image worker restarted?"
        }
        HermeticIncidentCaseV1::Case08 => {
            b"Can the retained logs establish why checkout trace 9f2 failed?"
        }
    }
}

fn acquisition_class(case: HermeticIncidentCaseV1) -> ExpectedAcquisitionClassV1 {
    match case {
        HermeticIncidentCaseV1::Case07 => ExpectedAcquisitionClassV1::Partial,
        HermeticIncidentCaseV1::Case08 => ExpectedAcquisitionClassV1::Unknown,
        HermeticIncidentCaseV1::Case01
        | HermeticIncidentCaseV1::Case02
        | HermeticIncidentCaseV1::Case03
        | HermeticIncidentCaseV1::Case04
        | HermeticIncidentCaseV1::Case05
        | HermeticIncidentCaseV1::Case06 => ExpectedAcquisitionClassV1::Complete,
    }
}

fn completeness(case: HermeticIncidentCaseV1) -> FetchCompleteness {
    match acquisition_class(case) {
        ExpectedAcquisitionClassV1::Complete => {
            FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted)
        }
        ExpectedAcquisitionClassV1::Partial => FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            None,
        ),
        ExpectedAcquisitionClassV1::Unknown => {
            FetchCompleteness::unknown(FetchUnknownReason::RetentionUnobservable)
        }
    }
}

fn trace_attestations(
    case: HermeticIncidentCaseV1,
    value: &[u8],
) -> Result<ProviderAttestationsV1, HermeticIncidentCorpusErrorV1> {
    let seed = u8::try_from(case_index(case))
        .map_err(|_| HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
    ProviderAttestationsV1::new([ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([0xa0_u8.wrapping_add(seed); 32]),
        ProviderAttestedRelationKindV1::TraceIdentity,
        ProviderAttestationValueV1::new(value.to_vec())
            .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)?,
    )])
    .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)
}

fn replace_record(
    records: &mut [FixtureRecordV1],
    position: usize,
    component: &[u8],
    stream: SourceStream,
    payload: impl Into<Vec<u8>>,
) {
    let terminator = records[position].terminator.clone();
    records[position] = FixtureRecordV1 {
        component: component.to_vec(),
        stream,
        payload: payload.into(),
        terminator,
        attestations: ProviderAttestationsV1::default(),
    };
}

fn fixture_records(
    case: HermeticIncidentCaseV1,
) -> Result<Vec<FixtureRecordV1>, HermeticIncidentCorpusErrorV1> {
    let scope = scope_components(case);
    let runtime = runtime(case).code();
    let mut records = (0..HERMETIC_INCIDENT_RECORD_COUNT_V1)
        .map(|position| {
            let component = scope[position % scope.len()];
            FixtureRecordV1::new(
                component,
                if position % 4 == 3 {
                    SourceStream::Stderr
                } else {
                    SourceStream::Stdout
                },
                format!(
                    "runtime={runtime} component={} heartbeat seq={position:02} status=ok",
                    String::from_utf8_lossy(component)
                )
                .into_bytes(),
                position,
            )
        })
        .collect::<Vec<_>>();
    match case {
        HermeticIncidentCaseV1::Case01 => {
            replace_record(
                &mut records,
                2,
                scope[0],
                SourceStream::Stderr,
                b"ERROR req-7f91 secret volume /run/orders unavailable after release 42".to_vec(),
            );
            replace_record(
                &mut records,
                5,
                scope[0],
                SourceStream::Stderr,
                b"req-7f91 psycopg.OperationalError connect localhost:5432 refused".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stdout,
                b"req-7f91 POST /checkout status=500 latency_ms=2031".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case02 => {
            replace_record(
                &mut records,
                2,
                scope[0],
                SourceStream::Stdout,
                b"ERROR search-executor active=32 max=32 queue_depth=148 completed=0".to_vec(),
            );
            replace_record(
                &mut records,
                5,
                scope[1],
                SourceStream::Stdout,
                b"GET /profile status=200 p99_ms=34".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stderr,
                b"java.util.concurrent.TimeoutException waiting for search-executor".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case03 => {
            replace_record(
                &mut records,
                1,
                scope[0],
                SourceStream::Stdout,
                b"ERROR certificate alias=auth-client NotAfter=2026-08-23T23:59:59Z".to_vec(),
            );
            replace_record(
                &mut records,
                6,
                scope[1],
                SourceStream::Stderr,
                b"System.Security.Authentication.AuthenticationException certificate expired"
                    .to_vec(),
            );
            replace_record(
                &mut records,
                9,
                scope[0],
                SourceStream::Stdout,
                b"upstream=identity-api status=502 tls_handshake=failed".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case04 => {
            replace_record(
                &mut records,
                2,
                scope[0],
                SourceStream::Stdout,
                b"POST /upload Content-Length=50331648 accepted".to_vec(),
            );
            replace_record(
                &mut records,
                4,
                scope[1],
                SourceStream::Stderr,
                b"ERROR event_loop_lag_ms=4280 operation=JSON.parse mode=synchronous".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stderr,
                b"readiness health check timeout active_uploads=41".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case05 => {
            replace_record(
                &mut records,
                2,
                scope[0],
                SourceStream::LogStream,
                b"ERROR frame len=\xff\xff\xff\x7f bytes=\0\x80EVIDENTRAIL_BRIEF_V1\n".to_vec(),
            );
            replace_record(
                &mut records,
                5,
                scope[1],
                SourceStream::Stderr,
                b"thread decoder-3 panicked: range end index 2147483647 out of range".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stdout,
                b"POST /ingest status=503 decoder_unavailable=true".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case06 => {
            replace_record(
                &mut records,
                2,
                scope[0],
                SourceStream::Stdout,
                b"ERROR resolver search=svc.example.invalid ndots=5 nameserver=10.96.0.10".to_vec(),
            );
            replace_record(
                &mut records,
                5,
                scope[1],
                SourceStream::Stderr,
                b"query dependency.svc.example.invalid A -> NXDOMAIN".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stderr,
                b"rpc error: code=DeadlineExceeded desc=context deadline exceeded".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case07 => {
            // The public scope contains node-agent, but the bounded partial
            // acquisition contains image-worker records only.
            for record in &mut records {
                record.component = scope[0].to_vec();
                record.stream = SourceStream::Container;
            }
            replace_record(
                &mut records,
                4,
                scope[0],
                SourceStream::Container,
                b"worker memory pressure observed rss_bytes=132120576".to_vec(),
            );
            replace_record(
                &mut records,
                6,
                scope[0],
                SourceStream::Container,
                b"image-worker restarted exitCode=137 reason unavailable in retained source"
                    .to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Container,
                b"queue_depth=912 replicas_ready=0".to_vec(),
            );
        }
        HermeticIncidentCaseV1::Case08 => {
            // deployment-controller is in operational scope but predecessor
            // ordering is explicitly unobservable in this unknown acquisition.
            for (position, record) in records.iter_mut().enumerate() {
                record.component = scope[position % 2].to_vec();
            }
            replace_record(
                &mut records,
                3,
                scope[0],
                SourceStream::Stdout,
                b"trace=9f2 inventory request payload_field=sku_id client_schema=v2".to_vec(),
            );
            replace_record(
                &mut records,
                5,
                scope[1],
                SourceStream::Stderr,
                b"trace=9f2 status=422 unknown field sku_id expected item_id schema=v3".to_vec(),
            );
            replace_record(
                &mut records,
                8,
                scope[0],
                SourceStream::Stderr,
                b"trace=9f2 checkout inventory validation failed status=502".to_vec(),
            );
            replace_record(
                &mut records,
                9,
                scope[1],
                SourceStream::LogStream,
                b"retention predecessor unavailable deployment ordering unknown".to_vec(),
            );
            for position in [3_usize, 5, 8] {
                records[position].attestations = trace_attestations(case, b"trace-9f2")?;
            }
        }
    }
    Ok(records)
}

fn checked_u64(value: usize) -> Result<u64, HermeticIncidentCorpusErrorV1> {
    u64::try_from(value).map_err(|_| HermeticIncidentCorpusErrorV1::ArithmeticOverflow)
}

fn fixture_identity(
    case: HermeticIncidentCaseV1,
    namespace: u8,
) -> Result<[u8; 32], HermeticIncidentCorpusErrorV1> {
    let index = u8::try_from(case_index(case))
        .map_err(|_| HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
    Ok([namespace.wrapping_add(index); 32])
}

fn build_ledger(
    case: HermeticIncidentCaseV1,
    records: Vec<FixtureRecordV1>,
) -> Result<evidentrail_core::EventLedger, HermeticIncidentCorpusErrorV1> {
    if records.len() != HERMETIC_INCIDENT_RECORD_COUNT_V1 {
        return Err(HermeticIncidentCorpusErrorV1::FixtureInvariant);
    }
    let retrieval_id = RetrievalId::from_bytes(fixture_identity(case, 20)?);
    let plan_id = PlanId::from_bytes(fixture_identity(case, 40)?);
    let plan_digest = PlanDigest::from_bytes(fixture_identity(case, 60)?);
    let source_identity = SourceIdentityDigest::from_bytes(fixture_identity(case, 80)?);
    let adapter = AdapterIdentity::new("hermetic-incident-corpus", "v1")
        .map_err(|_| HermeticIncidentCorpusErrorV1::LedgerBuild)?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicyV1);
    let mut lane_sequences = BTreeMap::<(Vec<u8>, SourceStream), u64>::new();
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    for (position, record) in records.into_iter().enumerate() {
        let lane_key = (record.component.clone(), record.stream.clone());
        let lane_sequence = *lane_sequences.get(&lane_key).unwrap_or(&0);
        lane_sequences.insert(
            lane_key,
            lane_sequence
                .checked_add(1)
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?,
        );
        payload_bytes = payload_bytes
            .checked_add(checked_u64(record.payload.len())?)
            .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
        source_bytes = source_bytes
            .checked_add(checked_u64(record.payload.len())?)
            .and_then(|value| value.checked_add(u64::try_from(record.terminator.len()).ok()?))
            .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
        builder
            .accept(
                RawEnvelopeV1::new(
                    envelope_identity.clone(),
                    EnvelopeOrdering::new(
                        AcquisitionSequence::new(checked_u64(position)?),
                        LaneKey::new(
                            SourceMember::new(record.component)
                                .map_err(|_| HermeticIncidentCorpusErrorV1::LedgerBuild)?,
                            record.stream,
                        ),
                        LaneSequence::new(lane_sequence),
                    ),
                    RecordBytes::framed(record.payload, record.terminator),
                    RecordState::Complete,
                )
                .with_provider_attestations(record.attestations),
            )
            .map_err(|_| HermeticIncidentCorpusErrorV1::LedgerBuild)?;
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    checked_u64(HERMETIC_INCIDENT_RECORD_COUNT_V1)?,
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
            .map_err(|_| HermeticIncidentCorpusErrorV1::LedgerBuild)?,
        )
        .map_err(|_| HermeticIncidentCorpusErrorV1::LedgerBuild)
}

fn block_index(
    ledger: &evidentrail_core::EventLedger,
) -> Result<BlockIndex<'_>, HermeticIncidentCorpusErrorV1> {
    BlockIndex::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"hermetic-incident-singleton".to_vec(), b"v1".to_vec()),
                BlockState::Reconstructed,
                BlockConfidence::Certain,
            )
        }),
    )
    .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), HermeticIncidentCorpusErrorV1> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| HermeticIncidentCorpusErrorV1::DigestLengthOverflow)?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn canonical_event_ids(ids: impl IntoIterator<Item = EventId>) -> Vec<EventId> {
    ids.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn selected_source_bytes(
    ledger: &evidentrail_core::EventLedger,
    selected_event_ids: &[EventId],
) -> Result<u64, HermeticIncidentCorpusErrorV1> {
    selected_event_ids
        .iter()
        .try_fold(0_u64, |total, event_id| {
            let bytes = ledger
                .event(*event_id)
                .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)?
                .raw()
                .len();
            total
                .checked_add(checked_u64(bytes)?)
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)
        })
}

#[allow(clippy::too_many_arguments)]
fn freeze_arm_outcome(
    arm: HermeticIncidentArmV1,
    producer_receipt_digest: Option<ArtifactDigest>,
    method_config_digest: Option<ArtifactDigest>,
    selected_event_ids: impl IntoIterator<Item = EventId>,
    selected_unique_source_bytes: u64,
    selected_packet_count: u64,
    accounted_token_upper_bound: Option<u64>,
    objective_gain: Option<ObjectiveGainV1>,
) -> Result<FrozenHermeticIncidentArmOutcomeV1, HermeticIncidentCorpusErrorV1> {
    let selected_event_ids = canonical_event_ids(selected_event_ids);
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_ARM_DOMAIN_V1);
    hash_field(&mut hasher, arm.code().as_bytes())?;
    match producer_receipt_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest.as_bytes());
        }
        None => hasher.update([0]),
    }
    match method_config_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(checked_u64(selected_event_ids.len())?.to_be_bytes());
    for event_id in &selected_event_ids {
        hasher.update(event_id.as_bytes());
    }
    hasher.update(selected_unique_source_bytes.to_be_bytes());
    hasher.update(selected_packet_count.to_be_bytes());
    match accounted_token_upper_bound {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match objective_gain {
        Some(gain) => {
            hasher.update([1]);
            hasher.update(gain.numerator().to_be_bytes());
        }
        None => hasher.update([0]),
    }
    Ok(FrozenHermeticIncidentArmOutcomeV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        arm,
        producer_receipt_digest,
        method_config_digest,
        selected_event_ids,
        selected_unique_source_bytes,
        selected_packet_count,
        accounted_token_upper_bound,
        objective_gain,
    })
}

fn freeze_baseline_outcome<M: BenchmarkMethod>(
    arm: HermeticIncidentArmV1,
    method: &M,
    ledger: &evidentrail_core::EventLedger,
    question: &[u8],
    budget: ByteBudget,
    method_config_digest: Option<ArtifactDigest>,
) -> Result<FrozenHermeticIncidentArmOutcomeV1, HermeticIncidentCorpusErrorV1> {
    let result = method
        .run(MethodInput::new(ledger, question, budget))
        .map_err(|_| HermeticIncidentCorpusErrorV1::Baseline)?;
    let selected_event_ids = result
        .selected()
        .iter()
        .map(crate::SelectedEvent::event_id)
        .collect::<Vec<_>>();
    freeze_arm_outcome(
        arm,
        None,
        method_config_digest,
        selected_event_ids,
        checked_u64(result.accounting().selected_source_bytes())?,
        checked_u64(result.accounting().selected_event_count())?,
        None,
        None,
    )
}

fn freeze_exact_oracle(
    configured: &evidentrail_compile::PreparedThreeLaneAblationV1,
    decision: ExactSmallSelectionOracleDecisionV1,
) -> Result<FrozenHermeticIncidentExactOracleV1, HermeticIncidentCorpusErrorV1> {
    let ExactSmallSelectionOracleDecisionV1::Optimal(plan) = decision else {
        return Err(HermeticIncidentCorpusErrorV1::ExactOracle);
    };
    let selected_event_ids = canonical_event_ids(plan.selected_packet_ids().iter().try_fold(
        Vec::new(),
        |mut event_ids, packet_id| {
            let metadata = configured
                .prepared()
                .proposal_metadata(*packet_id)
                .ok_or(HermeticIncidentCorpusErrorV1::ExactOracle)?;
            event_ids.extend_from_slice(metadata.ordered_event_ids());
            Ok::<_, HermeticIncidentCorpusErrorV1>(event_ids)
        },
    )?);
    let selected_packet_count = checked_u64(plan.selected_packet_ids().len())?;
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_ORACLE_DOMAIN_V1);
    hasher.update(configured.config_digest().as_bytes());
    hasher.update(configured.prepared().receipt().digest().as_bytes());
    hasher.update(selected_packet_count.to_be_bytes());
    for event_id in &selected_event_ids {
        hasher.update(event_id.as_bytes());
    }
    hasher.update(plan.objective_gain().numerator().to_be_bytes());
    hasher.update(plan.accounted_token_upper_bound().to_be_bytes());
    hasher.update(plan.reachable_subset_count().to_be_bytes());
    Ok(FrozenHermeticIncidentExactOracleV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        selected_event_ids,
        selected_packet_count,
        objective_gain: plan.objective_gain(),
        accounted_token_upper_bound: plan.accounted_token_upper_bound(),
        reachable_subset_count: plan.reachable_subset_count(),
    })
}

fn freeze_public_case(
    case: HermeticIncidentCaseV1,
    mutation: Option<(usize, usize, u8)>,
) -> Result<FrozenHermeticIncidentPublicCaseV1, HermeticIncidentCorpusErrorV1> {
    let mut records = fixture_records(case)?;
    if let Some((record_position, byte_position, replacement)) = mutation {
        let byte = records
            .get_mut(record_position)
            .and_then(|record| record.payload.get_mut(byte_position))
            .ok_or(HermeticIncidentCorpusErrorV1::FixtureInvariant)?;
        *byte = replacement;
    }
    let ledger = build_ledger(case, records)?;
    let blocks = block_index(&ledger)?;
    let question = question(case).to_vec();
    let tokenizer = Utf8ByteTokenizerV1::new();
    let result_seed = u8::try_from(case_index(case))
        .map_err(|_| HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
    let prepared = match prepare_three_lane_ablations_v1(
        &question,
        &ledger,
        &blocks,
        ResultId::from_bytes([0xc0_u8.wrapping_add(result_seed); 32]),
        &tokenizer,
    )
    .map_err(|_| HermeticIncidentCorpusErrorV1::Compiler)?
    {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(_) => {
            return Err(HermeticIncidentCorpusErrorV1::Compiler);
        }
    };
    let configured = prepared.configuration(ThreeLaneAblationMaskV1::Full);
    let token_budget = TotalTokenBudgetV1::new(HERMETIC_INCIDENT_TOTAL_TOKEN_BUDGET_V1)
        .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)?;
    let problem = benchmark_selection_problem_for_prepared_three_lane_ablation_v1(
        &ledger,
        configured,
        token_budget,
        &tokenizer,
    )
    .map_err(|_| HermeticIncidentCorpusErrorV1::Compiler)?;
    let oracle_decision = match evaluate_exact_small_selection_oracle_v1(&problem) {
        Ok(decision) => decision,
        Err(ExactSelectionOracleErrorV1::TooManyOptionalPackets) => {
            return Err(HermeticIncidentCorpusErrorV1::ExactOracleIneligible);
        }
        Err(_) => return Err(HermeticIncidentCorpusErrorV1::ExactOracle),
    };
    let exact_oracle = freeze_exact_oracle(configured, oracle_decision)?;
    let selection =
        select_prepared_three_lane_ablation_v1(&ledger, configured, token_budget, &tokenizer)
            .map_err(|_| HermeticIncidentCorpusErrorV1::Compiler)?;
    let PreparedThreeLaneSelectionDecisionV1::Selected(selection) = selection else {
        return Err(HermeticIncidentCorpusErrorV1::FullMethodNeedsMore);
    };
    let full_event_ids = canonical_event_ids(
        selection
            .selection()
            .packets()
            .iter()
            .flat_map(|packet| packet.packet().event_ids().iter().copied()),
    );
    let full_source_bytes = selected_source_bytes(&ledger, &full_event_ids)?;
    let full = freeze_arm_outcome(
        HermeticIncidentArmV1::FullThreeLane,
        Some(selection.proposal_receipt().digest()),
        None,
        full_event_ids,
        full_source_bytes,
        checked_u64(selection.selection().packets().len())?,
        Some(selection.selection().accounted_token_upper_bound()),
        Some(selection.selection().normalized_gain()),
    )?;
    let matched_source_byte_budget = usize::try_from(full_source_bytes)
        .map_err(|_| HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
    let byte_budget = ByteBudget::new(matched_source_byte_budget);
    let quarter = matched_source_byte_budget / 4;
    let remainder = matched_source_byte_budget % 4;
    let quota = QuotaHybrid::new(QuotaHybridConfig::new(
        quarter
            .checked_add(remainder)
            .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?,
        quarter,
        quarter,
        quarter,
        2,
        2,
        3,
    ));
    let raw = freeze_baseline_outcome(
        HermeticIncidentArmV1::RawChronological,
        &RawChronological,
        &ledger,
        &question,
        byte_budget,
        None,
    )?;
    let grep = freeze_baseline_outcome(
        HermeticIncidentArmV1::GrepHeadTail,
        &GrepHeadTail::new(GrepHeadTailConfig::new(2, 2)),
        &ledger,
        &question,
        byte_budget,
        None,
    )?;
    let quota = freeze_baseline_outcome(
        HermeticIncidentArmV1::QuotaHybrid,
        &quota,
        &ledger,
        &question,
        byte_budget,
        None,
    )?;
    let bm25f_config = Bm25fConfigV1;
    let bm25f = freeze_baseline_outcome(
        HermeticIncidentArmV1::Bm25fWholeEvent,
        &Bm25fWholeEventV1::new(bm25f_config),
        &ledger,
        &question,
        byte_budget,
        Some(bm25f_config.digest()),
    )?;
    let outcomes = [full, raw, grep, quota, bm25f];
    let scope_components = scope_components(case)
        .iter()
        .map(|component| component.to_vec())
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_CASE_DOMAIN_V1);
    hash_field(&mut hasher, case.code().as_bytes())?;
    hash_field(&mut hasher, runtime(case).code().as_bytes())?;
    hasher.update(checked_u64(scope_components.len())?.to_be_bytes());
    for component in &scope_components {
        hash_field(&mut hasher, component)?;
    }
    hash_field(&mut hasher, &question)?;
    hasher.update(derive_question_digest_v1(&question).as_bytes());
    hash_field(&mut hasher, acquisition_class(case).code().as_bytes())?;
    hasher.update(ledger.retrieval_id().as_bytes());
    hasher.update(ledger.plan_id().as_bytes());
    hasher.update(ledger.plan_digest().as_bytes());
    hasher.update(ledger.source_identity_digest().as_bytes());
    hasher.update(ledger.acquisition_receipt_id().as_bytes());
    hasher.update(checked_u64(ledger.len())?.to_be_bytes());
    for event in ledger.events() {
        hasher.update(event.id().as_bytes());
        hash_field(&mut hasher, event.lane().member().as_bytes())?;
        hash_field(&mut hasher, event.lane().stream().code().as_bytes())?;
        hash_field(&mut hasher, event.raw())?;
    }
    hasher.update(HERMETIC_INCIDENT_TOTAL_TOKEN_BUDGET_V1.to_be_bytes());
    hasher.update(full_source_bytes.to_be_bytes());
    for outcome in &outcomes {
        hasher.update(outcome.digest.as_bytes());
    }
    hasher.update(exact_oracle.digest.as_bytes());
    Ok(FrozenHermeticIncidentPublicCaseV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        case,
        runtime: runtime(case),
        scope_components,
        question,
        expected_acquisition_class: acquisition_class(case),
        total_token_budget: HERMETIC_INCIDENT_TOTAL_TOKEN_BUDGET_V1,
        matched_source_byte_budget: full_source_bytes,
        ledger,
        outcomes,
        exact_oracle,
    })
}

fn freeze_public_corpus_from_order(
    cases: impl IntoIterator<Item = HermeticIncidentCaseV1>,
    mutation: Option<(HermeticIncidentCaseV1, usize, usize, u8)>,
) -> Result<FrozenHermeticIncidentPublicCorpusV1, HermeticIncidentCorpusErrorV1> {
    let mut seen = BTreeSet::new();
    let mut frozen = Vec::new();
    for case in cases {
        if !seen.insert(case) {
            return Err(HermeticIncidentCorpusErrorV1::DuplicateCase);
        }
        let case_mutation = mutation.and_then(|(target, record, byte, replacement)| {
            (case == target).then_some((record, byte, replacement))
        });
        frozen.push(freeze_public_case(case, case_mutation)?);
    }
    if seen != HermeticIncidentCaseV1::ALL.into_iter().collect() {
        return Err(HermeticIncidentCorpusErrorV1::MissingCase);
    }
    frozen.sort_unstable_by_key(FrozenHermeticIncidentPublicCaseV1::case);
    let complete_count = checked_u64(
        frozen
            .iter()
            .filter(|case| case.expected_acquisition_class == ExpectedAcquisitionClassV1::Complete)
            .count(),
    )?;
    let partial_count = checked_u64(
        frozen
            .iter()
            .filter(|case| case.expected_acquisition_class == ExpectedAcquisitionClassV1::Partial)
            .count(),
    )?;
    let unknown_count = checked_u64(
        frozen
            .iter()
            .filter(|case| case.expected_acquisition_class == ExpectedAcquisitionClassV1::Unknown)
            .count(),
    )?;
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_CORPUS_DOMAIN_V1);
    hasher.update(checked_u64(frozen.len())?.to_be_bytes());
    for case in &frozen {
        hasher.update(case.digest.as_bytes());
    }
    hasher.update(complete_count.to_be_bytes());
    hasher.update(partial_count.to_be_bytes());
    hasher.update(unknown_count.to_be_bytes());
    Ok(FrozenHermeticIncidentPublicCorpusV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        cases: frozen
            .try_into()
            .map_err(|_| HermeticIncidentCorpusErrorV1::MissingCase)?,
        complete_count,
        partial_count,
        unknown_count,
    })
}

/// Freeze all eight label-blind public cases and every method/oracle receipt.
/// No annotation, fault family, acceptable answer, or evidence target is an
/// input to this function.
pub fn freeze_hermetic_incident_public_corpus_v1()
-> Result<FrozenHermeticIncidentPublicCorpusV1, HermeticIncidentCorpusErrorV1> {
    freeze_public_corpus_from_order(HermeticIncidentCaseV1::ALL, None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HermeticIncidentFaultFamilyV1 {
    DeploymentSecretMount,
    ExecutorSaturation,
    CertificateExpiry,
    EventLoopBlocking,
    BinaryFramingOverflow,
    DnsSearchConfiguration,
    InsufficientAuthorizedScope,
    UnobservableDeploymentOrdering,
}

impl HermeticIncidentFaultFamilyV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DeploymentSecretMount => "deployment_secret_mount_v1",
            Self::ExecutorSaturation => "executor_saturation_v1",
            Self::CertificateExpiry => "certificate_expiry_v1",
            Self::EventLoopBlocking => "event_loop_blocking_v1",
            Self::BinaryFramingOverflow => "binary_framing_overflow_v1",
            Self::DnsSearchConfiguration => "dns_search_configuration_v1",
            Self::InsufficientAuthorizedScope => "insufficient_authorized_scope_v1",
            Self::UnobservableDeploymentOrdering => "unobservable_deployment_ordering_v1",
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HermeticIncidentAbstentionAuthorityV1 {
    MissingAuthorizedScopedComponent(Vec<u8>),
    PredecessorOrderingUnobservable,
}

impl HermeticIncidentAbstentionAuthorityV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingAuthorizedScopedComponent(_) => {
                "partial_acquisition_missing_scoped_component_v1"
            }
            Self::PredecessorOrderingUnobservable => {
                "unknown_acquisition_predecessor_order_unobservable_v1"
            }
        }
    }
}

impl fmt::Debug for HermeticIncidentAbstentionAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentAbstentionAuthorityV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HermeticIncidentExpectedOutcomeV1 {
    Diagnose,
    Abstain(HermeticIncidentAbstentionAuthorityV1),
}

impl HermeticIncidentExpectedOutcomeV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Diagnose => "diagnosis_expected_v1",
            Self::Abstain(_) => "abstention_expected_v1",
        }
    }

    #[must_use]
    pub const fn diagnosis_scoring_eligible(&self) -> bool {
        matches!(self, Self::Diagnose)
    }
}

impl fmt::Debug for HermeticIncidentExpectedOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentExpectedOutcomeV1")
            .field("code", &self.code())
            .field(
                "abstention_authority_present",
                &matches!(self, Self::Abstain(_)),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HermeticIncidentClaimV1(Vec<u8>);

impl HermeticIncidentClaimV1 {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, HermeticIncidentCorpusErrorV1> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_HERMETIC_INCIDENT_CLAIM_BYTES_V1 {
            return Err(HermeticIncidentCorpusErrorV1::AnnotationBounds);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HermeticIncidentClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentClaimV1")
            .field("present", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HermeticIncidentRootAlternativeV1 {
    claims: Vec<HermeticIncidentClaimV1>,
}

impl HermeticIncidentRootAlternativeV1 {
    pub fn new(
        claims: impl IntoIterator<Item = HermeticIncidentClaimV1>,
    ) -> Result<Self, HermeticIncidentCorpusErrorV1> {
        let supplied = claims.into_iter().collect::<Vec<_>>();
        let mut claims = supplied.clone();
        claims.sort_unstable();
        claims.dedup();
        if claims.is_empty() || claims.len() > 4 || claims.len() != supplied.len() {
            return Err(HermeticIncidentCorpusErrorV1::AnnotationBounds);
        }
        Ok(Self { claims })
    }

    #[must_use]
    pub fn claims(&self) -> &[HermeticIncidentClaimV1] {
        &self.claims
    }
}

impl fmt::Debug for HermeticIncidentRootAlternativeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentRootAlternativeV1")
            .field("claim_count", &self.claims.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HermeticIncidentGovernedAnnotationV1 {
    digest: ArtifactDigest,
    case: HermeticIncidentCaseV1,
    public_case_digest: ArtifactDigest,
    fault_family: HermeticIncidentFaultFamilyV1,
    expected_outcome: HermeticIncidentExpectedOutcomeV1,
    acceptable_roots: Vec<HermeticIncidentRootAlternativeV1>,
    forbidden_claims: Vec<HermeticIncidentClaimV1>,
    unsupported_claims: Vec<HermeticIncidentClaimV1>,
    evidence: EvidentrailBenchAnnotationSpecV1,
}

impl HermeticIncidentGovernedAnnotationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new<Roots, Forbidden, Unsupported>(
        case: HermeticIncidentCaseV1,
        public_case_digest: ArtifactDigest,
        fault_family: HermeticIncidentFaultFamilyV1,
        expected_outcome: HermeticIncidentExpectedOutcomeV1,
        acceptable_roots: Roots,
        forbidden_claims: Forbidden,
        unsupported_claims: Unsupported,
        evidence: EvidentrailBenchAnnotationSpecV1,
    ) -> Result<Self, HermeticIncidentCorpusErrorV1>
    where
        Roots: IntoIterator<Item = HermeticIncidentRootAlternativeV1>,
        Forbidden: IntoIterator<Item = HermeticIncidentClaimV1>,
        Unsupported: IntoIterator<Item = HermeticIncidentClaimV1>,
    {
        if evidence.public_case_artifact_digest() != public_case_digest
            || evidence.diagnostic_requirements().is_empty()
            || evidence.diagnostic_requirements().len() > MAX_HERMETIC_INCIDENT_REQUIREMENTS_V1
        {
            return Err(HermeticIncidentCorpusErrorV1::AnnotationBounds);
        }
        let acceptable_roots = canonical_unique(acceptable_roots)?;
        let forbidden_claims = canonical_unique(forbidden_claims)?;
        let unsupported_claims = canonical_unique(unsupported_claims)?;
        if acceptable_roots.len() > MAX_HERMETIC_INCIDENT_ROOT_ALTERNATIVES_V1
            || forbidden_claims.is_empty()
            || unsupported_claims.is_empty()
        {
            return Err(HermeticIncidentCorpusErrorV1::AnnotationBounds);
        }
        match &expected_outcome {
            HermeticIncidentExpectedOutcomeV1::Diagnose if acceptable_roots.is_empty() => {
                return Err(HermeticIncidentCorpusErrorV1::OutcomeMismatch);
            }
            HermeticIncidentExpectedOutcomeV1::Abstain(_) if !acceptable_roots.is_empty() => {
                return Err(HermeticIncidentCorpusErrorV1::OutcomeMismatch);
            }
            HermeticIncidentExpectedOutcomeV1::Diagnose
            | HermeticIncidentExpectedOutcomeV1::Abstain(_) => {}
        }
        let root_claims = acceptable_roots
            .iter()
            .flat_map(HermeticIncidentRootAlternativeV1::claims)
            .collect::<BTreeSet<_>>();
        if forbidden_claims.iter().any(|claim| {
            unsupported_claims.binary_search(claim).is_ok() || root_claims.contains(claim)
        }) || unsupported_claims
            .iter()
            .any(|claim| root_claims.contains(claim))
        {
            return Err(HermeticIncidentCorpusErrorV1::ClaimPolicyConflict);
        }
        let digest = derive_annotation_digest(
            case,
            public_case_digest,
            fault_family,
            &expected_outcome,
            &acceptable_roots,
            &forbidden_claims,
            &unsupported_claims,
            &evidence,
        )?;
        Ok(Self {
            digest,
            case,
            public_case_digest,
            fault_family,
            expected_outcome,
            acceptable_roots,
            forbidden_claims,
            unsupported_claims,
            evidence,
        })
    }

    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> HermeticIncidentCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn public_case_digest(&self) -> ArtifactDigest {
        self.public_case_digest
    }

    #[must_use]
    pub const fn fault_family(&self) -> HermeticIncidentFaultFamilyV1 {
        self.fault_family
    }

    #[must_use]
    pub const fn expected_outcome(&self) -> &HermeticIncidentExpectedOutcomeV1 {
        &self.expected_outcome
    }

    #[must_use]
    pub fn acceptable_roots(&self) -> &[HermeticIncidentRootAlternativeV1] {
        &self.acceptable_roots
    }

    #[must_use]
    pub fn forbidden_claims(&self) -> &[HermeticIncidentClaimV1] {
        &self.forbidden_claims
    }

    #[must_use]
    pub fn unsupported_claims(&self) -> &[HermeticIncidentClaimV1] {
        &self.unsupported_claims
    }

    #[must_use]
    pub const fn evidence(&self) -> &EvidentrailBenchAnnotationSpecV1 {
        &self.evidence
    }
}

impl fmt::Debug for HermeticIncidentGovernedAnnotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticIncidentGovernedAnnotationV1")
            .field("annotation_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("case", &self.case)
            .field("fault_family", &self.fault_family)
            .field("expected_outcome", &self.expected_outcome)
            .field("acceptable_root_count", &self.acceptable_roots.len())
            .field("forbidden_claim_count", &self.forbidden_claims.len())
            .field("unsupported_claim_count", &self.unsupported_claims.len())
            .field("evidence", &self.evidence)
            .finish()
    }
}

fn canonical_unique<T: Ord + Clone>(
    values: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, HermeticIncidentCorpusErrorV1> {
    let supplied = values.into_iter().collect::<Vec<_>>();
    let mut canonical = supplied.clone();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.len() != supplied.len() {
        return Err(HermeticIncidentCorpusErrorV1::AnnotationBounds);
    }
    Ok(canonical)
}

fn hash_target(hasher: &mut Sha256, target: EvidenceTargetV1) {
    match target {
        EvidenceTargetV1::Event(event_id) => {
            hasher.update([0]);
            hasher.update(event_id.as_bytes());
        }
        EvidenceTargetV1::Block(block_id) => {
            hasher.update([1]);
            hasher.update(block_id.as_bytes());
        }
    }
}

fn hash_optional_targets(
    hasher: &mut Sha256,
    targets: Option<&[EvidenceTargetV1]>,
) -> Result<(), HermeticIncidentCorpusErrorV1> {
    match targets {
        Some(targets) => {
            hasher.update([1]);
            hasher.update(checked_u64(targets.len())?.to_be_bytes());
            for target in targets {
                hash_target(hasher, *target);
            }
        }
        None => hasher.update([0]),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_annotation_digest(
    case: HermeticIncidentCaseV1,
    public_case_digest: ArtifactDigest,
    fault_family: HermeticIncidentFaultFamilyV1,
    expected_outcome: &HermeticIncidentExpectedOutcomeV1,
    acceptable_roots: &[HermeticIncidentRootAlternativeV1],
    forbidden_claims: &[HermeticIncidentClaimV1],
    unsupported_claims: &[HermeticIncidentClaimV1],
    evidence: &EvidentrailBenchAnnotationSpecV1,
) -> Result<ArtifactDigest, HermeticIncidentCorpusErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_ANNOTATION_DOMAIN_V1);
    hash_field(&mut hasher, case.code().as_bytes())?;
    hasher.update(public_case_digest.as_bytes());
    hash_field(&mut hasher, fault_family.code().as_bytes())?;
    hash_field(&mut hasher, expected_outcome.code().as_bytes())?;
    match expected_outcome {
        HermeticIncidentExpectedOutcomeV1::Diagnose => hasher.update([0]),
        HermeticIncidentExpectedOutcomeV1::Abstain(authority) => {
            hasher.update([1]);
            hash_field(&mut hasher, authority.code().as_bytes())?;
            match authority {
                HermeticIncidentAbstentionAuthorityV1::MissingAuthorizedScopedComponent(
                    component,
                ) => hash_field(&mut hasher, component)?,
                HermeticIncidentAbstentionAuthorityV1::PredecessorOrderingUnobservable => {
                    hash_field(&mut hasher, &[])?;
                }
            }
        }
    }
    hasher.update(checked_u64(acceptable_roots.len())?.to_be_bytes());
    for alternative in acceptable_roots {
        hasher.update(checked_u64(alternative.claims.len())?.to_be_bytes());
        for claim in &alternative.claims {
            hash_field(&mut hasher, claim.as_bytes())?;
        }
    }
    for claims in [forbidden_claims, unsupported_claims] {
        hasher.update(checked_u64(claims.len())?.to_be_bytes());
        for claim in claims {
            hash_field(&mut hasher, claim.as_bytes())?;
        }
    }
    hasher.update(evidence.public_case_artifact_digest().as_bytes());
    hasher.update(checked_u64(evidence.diagnostic_requirements().len())?.to_be_bytes());
    for requirement in evidence.diagnostic_requirements() {
        hasher.update(requirement.weight_micros().to_be_bytes());
        hasher.update(checked_u64(requirement.alternatives().len())?.to_be_bytes());
        for alternative in requirement.alternatives() {
            hasher.update(checked_u64(alternative.len())?.to_be_bytes());
            for target in alternative {
                hash_target(&mut hasher, *target);
            }
        }
    }
    hash_optional_targets(&mut hasher, evidence.precursor_targets())?;
    hash_optional_targets(&mut hasher, evidence.symptom_targets())?;
    hash_optional_targets(&mut hasher, evidence.supporting_targets())?;
    hash_optional_targets(&mut hasher, evidence.distractor_targets())?;
    hash_optional_targets(&mut hasher, evidence.unsafe_targets())?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactHermeticIncidentRecallV1 {
    satisfied_weight_micros: u64,
    total_weight_micros: u64,
    satisfied_requirement_count: u64,
    requirement_count: u64,
}

impl ExactHermeticIncidentRecallV1 {
    #[must_use]
    pub const fn exact_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }

    #[must_use]
    pub const fn satisfied_requirement_count(self) -> u64 {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn requirement_count(self) -> u64 {
        self.requirement_count
    }

    #[must_use]
    pub const fn is_perfect(self) -> bool {
        self.satisfied_weight_micros == self.total_weight_micros
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedHermeticIncidentArmOutcomeV1 {
    arm: HermeticIncidentArmV1,
    public_outcome_digest: ArtifactDigest,
    method_config_digest: Option<ArtifactDigest>,
    recall: ExactHermeticIncidentRecallV1,
    selected_unique_source_bytes: u64,
    selected_packet_count: u64,
    accounted_token_upper_bound: Option<u64>,
}

impl GovernedHermeticIncidentArmOutcomeV1 {
    #[must_use]
    pub const fn arm(self) -> HermeticIncidentArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn public_outcome_digest(self) -> ArtifactDigest {
        self.public_outcome_digest
    }

    #[must_use]
    pub const fn method_config_digest(self) -> Option<ArtifactDigest> {
        self.method_config_digest
    }

    #[must_use]
    pub const fn recall(self) -> ExactHermeticIncidentRecallV1 {
        self.recall
    }

    #[must_use]
    pub const fn selected_unique_source_bytes(self) -> u64 {
        self.selected_unique_source_bytes
    }

    #[must_use]
    pub const fn selected_packet_count(self) -> u64 {
        self.selected_packet_count
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(self) -> Option<u64> {
        self.accounted_token_upper_bound
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedHermeticIncidentCaseV1 {
    case: HermeticIncidentCaseV1,
    public_case_digest: ArtifactDigest,
    annotation_digest: ArtifactDigest,
    fault_family: HermeticIncidentFaultFamilyV1,
    expected_outcome: HermeticIncidentExpectedOutcomeV1,
    outcomes: [GovernedHermeticIncidentArmOutcomeV1; 5],
    exact_oracle_recall: ExactHermeticIncidentRecallV1,
}

impl GovernedHermeticIncidentCaseV1 {
    #[must_use]
    pub const fn case(&self) -> HermeticIncidentCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn fault_family(&self) -> HermeticIncidentFaultFamilyV1 {
        self.fault_family
    }

    #[must_use]
    pub const fn expected_outcome(&self) -> &HermeticIncidentExpectedOutcomeV1 {
        &self.expected_outcome
    }

    #[must_use]
    pub const fn diagnosis_scoring_eligible(&self) -> bool {
        self.expected_outcome.diagnosis_scoring_eligible()
    }

    #[must_use]
    pub fn outcomes(&self) -> &[GovernedHermeticIncidentArmOutcomeV1; 5] {
        &self.outcomes
    }

    #[must_use]
    pub fn outcome(&self, arm: HermeticIncidentArmV1) -> GovernedHermeticIncidentArmOutcomeV1 {
        self.outcomes[arm_index(arm)]
    }

    #[must_use]
    pub const fn exact_oracle_recall(&self) -> ExactHermeticIncidentRecallV1 {
        self.exact_oracle_recall
    }
}

impl fmt::Debug for GovernedHermeticIncidentCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedHermeticIncidentCaseV1")
            .field("case", &self.case)
            .field("public_case_binding_present", &true)
            .field("annotation_binding_present", &true)
            .field("fault_family", &self.fault_family)
            .field("expected_outcome", &self.expected_outcome)
            .field("outcome_count", &self.outcomes.len())
            .field("exact_oracle_recall", &self.exact_oracle_recall)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HermeticIncidentArmSummaryV1 {
    arm: HermeticIncidentArmV1,
    satisfied_weight_micros: u64,
    total_weight_micros: u64,
    perfect_case_count: u64,
}

impl HermeticIncidentArmSummaryV1 {
    #[must_use]
    pub const fn arm(self) -> HermeticIncidentArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn exact_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }

    #[must_use]
    pub const fn perfect_case_count(self) -> u64 {
        self.perfect_case_count
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedHermeticIncidentOutcomeCorpusV1 {
    digest: ArtifactDigest,
    public_corpus_digest: ArtifactDigest,
    cases: [GovernedHermeticIncidentCaseV1; HERMETIC_INCIDENT_CASE_COUNT_V1],
    arm_summaries: [HermeticIncidentArmSummaryV1; 5],
    diagnosis_expected_count: u64,
    abstention_expected_count: u64,
    exact_oracle_evaluated_count: u64,
}

impl GovernedHermeticIncidentOutcomeCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn public_corpus_digest(&self) -> ArtifactDigest {
        self.public_corpus_digest
    }

    #[must_use]
    pub fn cases(&self) -> &[GovernedHermeticIncidentCaseV1; HERMETIC_INCIDENT_CASE_COUNT_V1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: HermeticIncidentCaseV1) -> &GovernedHermeticIncidentCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub fn arm_summaries(&self) -> &[HermeticIncidentArmSummaryV1; 5] {
        &self.arm_summaries
    }

    #[must_use]
    pub fn arm_summary(&self, arm: HermeticIncidentArmV1) -> HermeticIncidentArmSummaryV1 {
        self.arm_summaries[arm_index(arm)]
    }

    #[must_use]
    pub const fn diagnosis_expected_count(&self) -> u64 {
        self.diagnosis_expected_count
    }

    #[must_use]
    pub const fn abstention_expected_count(&self) -> u64 {
        self.abstention_expected_count
    }

    #[must_use]
    pub const fn exact_oracle_evaluated_count(&self) -> u64 {
        self.exact_oracle_evaluated_count
    }

    #[must_use]
    pub const fn contains_diagnosis_success_score(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_scalar_composite(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_hosted_quality(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn scope_code(&self) -> &'static str {
        "synthetic_hermetic_conformance_only_no_population_claim_v1"
    }
}

impl fmt::Debug for GovernedHermeticIncidentOutcomeCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedHermeticIncidentOutcomeCorpusV1")
            .field("governed_identity_present", &true)
            .field("public_corpus_binding_present", &true)
            .field("case_count", &self.cases.len())
            .field("arm_summary_count", &self.arm_summaries.len())
            .field("diagnosis_expected_count", &self.diagnosis_expected_count)
            .field("abstention_expected_count", &self.abstention_expected_count)
            .field(
                "exact_oracle_evaluated_count",
                &self.exact_oracle_evaluated_count,
            )
            .field("contains_diagnosis_success_score", &false)
            .field("contains_scalar_composite", &false)
            .field("claims_hosted_quality", &false)
            .field("scope", &self.scope_code())
            .finish()
    }
}

fn validate_targets(
    public: &FrozenHermeticIncidentPublicCaseV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
) -> Result<(), HermeticIncidentCorpusErrorV1> {
    let mut targets = Vec::new();
    for requirement in annotation.diagnostic_requirements() {
        for target in requirement.alternatives().iter().flatten() {
            targets.push(*target);
        }
    }
    for optional in [
        annotation.precursor_targets(),
        annotation.symptom_targets(),
        annotation.supporting_targets(),
        annotation.distractor_targets(),
        annotation.unsafe_targets(),
    ]
    .into_iter()
    .flatten()
    {
        targets.extend_from_slice(optional);
    }
    if targets.into_iter().any(|target| match target {
        EvidenceTargetV1::Event(event_id) => !public.ledger.contains(event_id),
        EvidenceTargetV1::Block(_) => true,
    }) {
        return Err(HermeticIncidentCorpusErrorV1::EvidenceTargetMismatch);
    }
    Ok(())
}

fn validate_outcome_authority(
    public: &FrozenHermeticIncidentPublicCaseV1,
    annotation: &HermeticIncidentGovernedAnnotationV1,
) -> Result<(), HermeticIncidentCorpusErrorV1> {
    match &annotation.expected_outcome {
        HermeticIncidentExpectedOutcomeV1::Diagnose => {
            if public.expected_acquisition_class != ExpectedAcquisitionClassV1::Complete
                || annotation.acceptable_roots.is_empty()
            {
                return Err(HermeticIncidentCorpusErrorV1::OutcomeMismatch);
            }
        }
        HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::MissingAuthorizedScopedComponent(component),
        ) => {
            if public.expected_acquisition_class != ExpectedAcquisitionClassV1::Partial
                || !public
                    .scope_components
                    .iter()
                    .any(|scope| scope == component)
                || public
                    .ledger
                    .events()
                    .iter()
                    .any(|event| event.lane().member().as_bytes() == component)
                || !annotation.acceptable_roots.is_empty()
            {
                return Err(HermeticIncidentCorpusErrorV1::AbstentionAuthorityMismatch);
            }
        }
        HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::PredecessorOrderingUnobservable,
        ) => {
            if public.expected_acquisition_class != ExpectedAcquisitionClassV1::Unknown
                || !annotation.acceptable_roots.is_empty()
            {
                return Err(HermeticIncidentCorpusErrorV1::AbstentionAuthorityMismatch);
            }
        }
    }
    Ok(())
}

fn evaluate_recall(
    requirements: &[WeightedDiagnosticRequirementV1],
    selected_event_ids: &[EventId],
) -> Result<ExactHermeticIncidentRecallV1, HermeticIncidentCorpusErrorV1> {
    let selected = selected_event_ids
        .iter()
        .copied()
        .map(EvidenceTargetV1::Event)
        .collect::<BTreeSet<_>>();
    let mut satisfied_weight_micros = 0_u64;
    let mut total_weight_micros = 0_u64;
    let mut satisfied_requirement_count = 0_u64;
    for requirement in requirements {
        total_weight_micros = total_weight_micros
            .checked_add(requirement.weight_micros())
            .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
        if requirement.is_satisfied_by(&selected) {
            satisfied_weight_micros = satisfied_weight_micros
                .checked_add(requirement.weight_micros())
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
            satisfied_requirement_count = satisfied_requirement_count
                .checked_add(1)
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
        }
    }
    Ok(ExactHermeticIncidentRecallV1 {
        satisfied_weight_micros,
        total_weight_micros,
        satisfied_requirement_count,
        requirement_count: checked_u64(requirements.len())?,
    })
}

fn govern_case(
    public: &FrozenHermeticIncidentPublicCaseV1,
    annotation: HermeticIncidentGovernedAnnotationV1,
) -> Result<GovernedHermeticIncidentCaseV1, HermeticIncidentCorpusErrorV1> {
    if annotation.case != public.case
        || annotation.public_case_digest != public.digest
        || annotation.evidence.public_case_artifact_digest() != public.digest
    {
        return Err(HermeticIncidentCorpusErrorV1::ForeignCase);
    }
    validate_targets(public, &annotation.evidence)?;
    validate_outcome_authority(public, &annotation)?;
    let outcomes = public
        .outcomes
        .iter()
        .map(|outcome| {
            Ok(GovernedHermeticIncidentArmOutcomeV1 {
                arm: outcome.arm,
                public_outcome_digest: outcome.digest,
                method_config_digest: outcome.method_config_digest,
                recall: evaluate_recall(
                    annotation.evidence.diagnostic_requirements(),
                    &outcome.selected_event_ids,
                )?,
                selected_unique_source_bytes: outcome.selected_unique_source_bytes,
                selected_packet_count: outcome.selected_packet_count,
                accounted_token_upper_bound: outcome.accounted_token_upper_bound,
            })
        })
        .collect::<Result<Vec<_>, HermeticIncidentCorpusErrorV1>>()?
        .try_into()
        .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)?;
    let exact_oracle_recall = evaluate_recall(
        annotation.evidence.diagnostic_requirements(),
        &public.exact_oracle.selected_event_ids,
    )?;
    Ok(GovernedHermeticIncidentCaseV1 {
        case: public.case,
        public_case_digest: public.digest,
        annotation_digest: annotation.digest,
        fault_family: annotation.fault_family,
        expected_outcome: annotation.expected_outcome,
        outcomes,
        exact_oracle_recall,
    })
}

/// Join exactly one hidden annotation to every public case and compute only
/// exact required-evidence recall. Abstention cases remain ineligible for any
/// diagnosis-success claim even when their insufficiency evidence is retained.
pub fn govern_hermetic_incident_outcome_corpus_v1(
    public: &FrozenHermeticIncidentPublicCorpusV1,
    annotations: impl IntoIterator<Item = HermeticIncidentGovernedAnnotationV1>,
) -> Result<GovernedHermeticIncidentOutcomeCorpusV1, HermeticIncidentCorpusErrorV1> {
    let mut by_case = std::array::from_fn::<_, HERMETIC_INCIDENT_CASE_COUNT_V1, _>(|_| None);
    for annotation in annotations {
        let index = case_index(annotation.case);
        if by_case[index].replace(annotation).is_some() {
            return Err(HermeticIncidentCorpusErrorV1::DuplicateCase);
        }
    }
    if by_case.iter().any(Option::is_none) {
        return Err(HermeticIncidentCorpusErrorV1::MissingCase);
    }
    let cases = by_case
        .into_iter()
        .zip(HermeticIncidentCaseV1::ALL)
        .map(|(annotation, case)| {
            govern_case(
                public.case(case),
                annotation.ok_or(HermeticIncidentCorpusErrorV1::MissingCase)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnosis_expected_count = checked_u64(
        cases
            .iter()
            .filter(|case| case.diagnosis_scoring_eligible())
            .count(),
    )?;
    let abstention_expected_count = checked_u64(cases.len())?
        .checked_sub(diagnosis_expected_count)
        .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
    let arm_summaries = HermeticIncidentArmV1::ALL.map(|arm| {
        let mut satisfied_weight_micros = 0_u64;
        let mut total_weight_micros = 0_u64;
        let mut perfect_case_count = 0_u64;
        for case in &cases {
            let recall = case.outcome(arm).recall;
            satisfied_weight_micros = satisfied_weight_micros
                .checked_add(recall.satisfied_weight_micros)
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
            total_weight_micros = total_weight_micros
                .checked_add(recall.total_weight_micros)
                .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
            if recall.is_perfect() {
                perfect_case_count = perfect_case_count
                    .checked_add(1)
                    .ok_or(HermeticIncidentCorpusErrorV1::ArithmeticOverflow)?;
            }
        }
        Ok(HermeticIncidentArmSummaryV1 {
            arm,
            satisfied_weight_micros,
            total_weight_micros,
            perfect_case_count,
        })
    });
    let arm_summaries: [HermeticIncidentArmSummaryV1; 5] = arm_summaries
        .into_iter()
        .collect::<Result<Vec<_>, HermeticIncidentCorpusErrorV1>>()?
        .try_into()
        .map_err(|_| HermeticIncidentCorpusErrorV1::FixtureInvariant)?;
    let cases: [GovernedHermeticIncidentCaseV1; HERMETIC_INCIDENT_CASE_COUNT_V1] = cases
        .try_into()
        .map_err(|_| HermeticIncidentCorpusErrorV1::MissingCase)?;
    let mut hasher = Sha256::new();
    hasher.update(GOVERNED_CORPUS_DOMAIN_V1);
    hasher.update(public.digest.as_bytes());
    for case in &cases {
        hash_field(&mut hasher, case.case.code().as_bytes())?;
        hasher.update(case.public_case_digest.as_bytes());
        hasher.update(case.annotation_digest.as_bytes());
        for outcome in &case.outcomes {
            hasher.update(outcome.public_outcome_digest.as_bytes());
            hasher.update(outcome.recall.satisfied_weight_micros.to_be_bytes());
            hasher.update(outcome.recall.total_weight_micros.to_be_bytes());
        }
        hasher.update(
            case.exact_oracle_recall
                .satisfied_weight_micros
                .to_be_bytes(),
        );
        hasher.update(case.exact_oracle_recall.total_weight_micros.to_be_bytes());
    }
    for summary in arm_summaries {
        hash_field(&mut hasher, summary.arm.code().as_bytes())?;
        hasher.update(summary.satisfied_weight_micros.to_be_bytes());
        hasher.update(summary.total_weight_micros.to_be_bytes());
        hasher.update(summary.perfect_case_count.to_be_bytes());
    }
    hasher.update(diagnosis_expected_count.to_be_bytes());
    hasher.update(abstention_expected_count.to_be_bytes());
    Ok(GovernedHermeticIncidentOutcomeCorpusV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        public_corpus_digest: public.digest,
        cases,
        arm_summaries,
        diagnosis_expected_count,
        abstention_expected_count,
        exact_oracle_evaluated_count: checked_u64(HERMETIC_INCIDENT_CASE_COUNT_V1)?,
    })
}

fn fault_family(case: HermeticIncidentCaseV1) -> HermeticIncidentFaultFamilyV1 {
    match case {
        HermeticIncidentCaseV1::Case01 => HermeticIncidentFaultFamilyV1::DeploymentSecretMount,
        HermeticIncidentCaseV1::Case02 => HermeticIncidentFaultFamilyV1::ExecutorSaturation,
        HermeticIncidentCaseV1::Case03 => HermeticIncidentFaultFamilyV1::CertificateExpiry,
        HermeticIncidentCaseV1::Case04 => HermeticIncidentFaultFamilyV1::EventLoopBlocking,
        HermeticIncidentCaseV1::Case05 => HermeticIncidentFaultFamilyV1::BinaryFramingOverflow,
        HermeticIncidentCaseV1::Case06 => HermeticIncidentFaultFamilyV1::DnsSearchConfiguration,
        HermeticIncidentCaseV1::Case07 => {
            HermeticIncidentFaultFamilyV1::InsufficientAuthorizedScope
        }
        HermeticIncidentCaseV1::Case08 => {
            HermeticIncidentFaultFamilyV1::UnobservableDeploymentOrdering
        }
    }
}

fn root_claim(case: HermeticIncidentCaseV1) -> Option<&'static [u8]> {
    match case {
        HermeticIncidentCaseV1::Case01 => {
            Some(b"gold-only:orders-secret-volume-absent-after-rollout")
        }
        HermeticIncidentCaseV1::Case02 => {
            Some(b"gold-only:search-executor-saturated-at-worker-cap")
        }
        HermeticIncidentCaseV1::Case03 => Some(b"gold-only:auth-client-certificate-expired"),
        HermeticIncidentCaseV1::Case04 => {
            Some(b"gold-only:synchronous-json-parse-blocked-node-event-loop")
        }
        HermeticIncidentCaseV1::Case05 => {
            Some(b"gold-only:unbounded-frame-length-reached-rust-slice")
        }
        HermeticIncidentCaseV1::Case06 => {
            Some(b"gold-only:invalid-dns-search-suffix-caused-nxdomain")
        }
        HermeticIncidentCaseV1::Case07 | HermeticIncidentCaseV1::Case08 => None,
    }
}

fn role_positions(
    case: HermeticIncidentCaseV1,
) -> (&'static [usize], &'static [usize], &'static [usize]) {
    match case {
        HermeticIncidentCaseV1::Case01 => (&[2], &[8], &[5]),
        HermeticIncidentCaseV1::Case02 => (&[2], &[8], &[5]),
        HermeticIncidentCaseV1::Case03 => (&[1], &[9], &[6]),
        HermeticIncidentCaseV1::Case04 => (&[4], &[8], &[2]),
        HermeticIncidentCaseV1::Case05 => (&[2], &[5], &[8]),
        HermeticIncidentCaseV1::Case06 => (&[2], &[8], &[5]),
        HermeticIncidentCaseV1::Case07 => (&[], &[6], &[4, 8]),
        HermeticIncidentCaseV1::Case08 => (&[], &[8], &[5, 9]),
    }
}

fn ids_at(
    public: &FrozenHermeticIncidentPublicCaseV1,
    positions: &[usize],
) -> Result<Vec<EventId>, HermeticIncidentCorpusErrorV1> {
    positions
        .iter()
        .map(|position| {
            public
                .ledger
                .events()
                .get(*position)
                .map(evidentrail_core::Event::id)
                .ok_or(HermeticIncidentCorpusErrorV1::FixtureInvariant)
        })
        .collect()
}

fn hidden_annotation_for_case(
    public: &FrozenHermeticIncidentPublicCaseV1,
) -> Result<HermeticIncidentGovernedAnnotationV1, HermeticIncidentCorpusErrorV1> {
    let (precursor_positions, symptom_positions, supporting_positions) =
        role_positions(public.case);
    let precursors = ids_at(public, precursor_positions)?;
    let symptoms = ids_at(public, symptom_positions)?;
    let supporting = ids_at(public, supporting_positions)?;
    let classified = precursors
        .iter()
        .chain(&symptoms)
        .chain(&supporting)
        .copied()
        .collect::<BTreeSet<_>>();
    let distractors = public
        .ledger
        .events()
        .iter()
        .map(evidentrail_core::Event::id)
        .filter(|event_id| !classified.contains(event_id))
        .map(EvidenceTargetV1::Event)
        .collect::<Vec<_>>();
    let expected_outcome = match public.case {
        HermeticIncidentCaseV1::Case07 => HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::MissingAuthorizedScopedComponent(
                b"node-agent".to_vec(),
            ),
        ),
        HermeticIncidentCaseV1::Case08 => HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::PredecessorOrderingUnobservable,
        ),
        HermeticIncidentCaseV1::Case01
        | HermeticIncidentCaseV1::Case02
        | HermeticIncidentCaseV1::Case03
        | HermeticIncidentCaseV1::Case04
        | HermeticIncidentCaseV1::Case05
        | HermeticIncidentCaseV1::Case06 => HermeticIncidentExpectedOutcomeV1::Diagnose,
    };
    let requirements = match expected_outcome {
        HermeticIncidentExpectedOutcomeV1::Diagnose => {
            let mut causal = precursors
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect::<Vec<_>>();
            causal.push(EvidenceTargetV1::Event(
                *symptoms
                    .first()
                    .ok_or(HermeticIncidentCorpusErrorV1::FixtureInvariant)?,
            ));
            let support = supporting
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect::<Vec<_>>();
            vec![
                WeightedDiagnosticRequirementV1::new(700_000, [causal])
                    .map_err(|_| HermeticIncidentCorpusErrorV1::AnnotationBounds)?,
                WeightedDiagnosticRequirementV1::new(300_000, [support])
                    .map_err(|_| HermeticIncidentCorpusErrorV1::AnnotationBounds)?,
            ]
        }
        HermeticIncidentExpectedOutcomeV1::Abstain(_) => {
            let mut authority_evidence = symptoms
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect::<Vec<_>>();
            authority_evidence.push(EvidenceTargetV1::Event(
                *supporting
                    .last()
                    .ok_or(HermeticIncidentCorpusErrorV1::FixtureInvariant)?,
            ));
            vec![
                WeightedDiagnosticRequirementV1::new(1_000_000, [authority_evidence])
                    .map_err(|_| HermeticIncidentCorpusErrorV1::AnnotationBounds)?,
            ]
        }
    };
    let evidence = EvidentrailBenchAnnotationSpecV1::new(
        public.digest,
        requirements,
        (!precursors.is_empty()).then(|| {
            precursors
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect()
        }),
        Some(
            symptoms
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect(),
        ),
        Some(
            supporting
                .iter()
                .copied()
                .map(EvidenceTargetV1::Event)
                .collect(),
        ),
        Some(distractors),
        None,
    )
    .map_err(|_| HermeticIncidentCorpusErrorV1::AnnotationBounds)?;
    let acceptable_roots = root_claim(public.case)
        .map(|root| {
            HermeticIncidentRootAlternativeV1::new([HermeticIncidentClaimV1::new(root.to_vec())?])
        })
        .transpose()?
        .into_iter();
    let forbidden = HermeticIncidentClaimV1::new(
        format!(
            "gold-only:{}:assert-causation-from-later-symptom",
            public.case.code()
        )
        .into_bytes(),
    )?;
    let unsupported = HermeticIncidentClaimV1::new(
        format!(
            "gold-only:{}:unobserved-destructive-data-loss",
            public.case.code()
        )
        .into_bytes(),
    )?;
    HermeticIncidentGovernedAnnotationV1::try_new(
        public.case,
        public.digest,
        fault_family(public.case),
        expected_outcome,
        acceptable_roots,
        [forbidden],
        [unsupported],
        evidence,
    )
}

/// Construct the closed hidden annotations only after a public corpus exists.
pub fn synthetic_hermetic_incident_annotations_v1(
    public: &FrozenHermeticIncidentPublicCorpusV1,
) -> Result<Vec<HermeticIncidentGovernedAnnotationV1>, HermeticIncidentCorpusErrorV1> {
    HermeticIncidentCaseV1::ALL
        .into_iter()
        .map(|case| hidden_annotation_for_case(public.case(case)))
        .collect()
}

/// Convenience constructor for the fully staged synthetic conformance asset.
pub fn build_governed_hermetic_incident_outcome_corpus_v1()
-> Result<GovernedHermeticIncidentOutcomeCorpusV1, HermeticIncidentCorpusErrorV1> {
    let public = freeze_hermetic_incident_public_corpus_v1()?;
    let annotations = synthetic_hermetic_incident_annotations_v1(&public)?;
    govern_hermetic_incident_outcome_corpus_v1(&public, annotations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_case_order_is_canonical_and_raw_mutation_changes_receipts() {
        let forward = freeze_public_corpus_from_order(HermeticIncidentCaseV1::ALL, None).unwrap();
        let mut reverse_order = HermeticIncidentCaseV1::ALL;
        reverse_order.reverse();
        let reverse = freeze_public_corpus_from_order(reverse_order, None).unwrap();
        assert_eq!(forward.digest, reverse.digest);

        let original = forward.case(HermeticIncidentCaseV1::Case01);
        let replacement = original.ledger.events()[0].payload()[0] ^ 0x01;
        let mutated = freeze_public_corpus_from_order(
            HermeticIncidentCaseV1::ALL,
            Some((HermeticIncidentCaseV1::Case01, 0, 0, replacement)),
        )
        .unwrap();
        assert_ne!(forward.digest, mutated.digest);
        assert_ne!(
            original.digest,
            mutated.case(HermeticIncidentCaseV1::Case01).digest
        );
        assert_ne!(
            original.ledger.events()[0].id(),
            mutated.case(HermeticIncidentCaseV1::Case01).ledger.events()[0].id()
        );
    }

    #[test]
    fn public_case_roster_rejects_missing_and_duplicate_inputs() {
        assert_eq!(
            freeze_public_corpus_from_order(HermeticIncidentCaseV1::ALL.into_iter().take(7), None,)
                .unwrap_err(),
            HermeticIncidentCorpusErrorV1::MissingCase
        );
        let mut duplicate = HermeticIncidentCaseV1::ALL.to_vec();
        duplicate.push(HermeticIncidentCaseV1::Case01);
        assert_eq!(
            freeze_public_corpus_from_order(duplicate, None).unwrap_err(),
            HermeticIncidentCorpusErrorV1::DuplicateCase
        );
    }
}
