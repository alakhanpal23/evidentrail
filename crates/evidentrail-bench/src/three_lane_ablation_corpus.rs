use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{ThreeLaneAblationMaskV1, three_lane_ablation_method_family_digest_v1};
use evidentrail_core::{BlockIndex, EventLedger};
use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    EvidentrailBenchAnnotationSpecV1, FrozenPublicThreeLaneAblationBatchDigestV1,
    FrozenPublicThreeLaneAblationBatchV1, GovernedCaseArtifactJoinV1,
    GovernedThreeLaneAblationBatchV1, ProducerProposalMeasurementEnvironmentV1,
    ThreeLaneAblationEvaluationErrorV1, ThreeLaneAblationMeasurementAllocationV1,
    evaluate_governed_three_lane_ablation_batch_v1,
};

const SYNTHETIC_CORPUS_IDENTITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/synthetic-three-lane-ablation-corpus-identity/v1\0";
const SYNTHETIC_CASE_IDENTITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/synthetic-three-lane-ablation-case-identity/v1\0";
const SYNTHETIC_FAMILY_IDENTITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/synthetic-three-lane-ablation-family-identity/v1\0";
const PUBLIC_SYNTHETIC_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-synthetic-three-lane-ablation-corpus/v1\0";
const GOVERNED_SYNTHETIC_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-synthetic-three-lane-ablation-corpus/v1\0";

/// Closed generator families in the first-party synthetic conformance corpus.
///
/// Cases in the same family reuse a generator design and must not be treated
/// as independent statistical samples.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyntheticThreeLaneAblationFamilyV1 {
    Lexical,
    Coverage,
    Provider,
    Mixed,
    StructuralSafety,
}

impl SyntheticThreeLaneAblationFamilyV1 {
    pub const ALL: [Self; 5] = [
        Self::Lexical,
        Self::Coverage,
        Self::Provider,
        Self::Mixed,
        Self::StructuralSafety,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lexical => "lexical_generator_family_v1",
            Self::Coverage => "coverage_generator_family_v1",
            Self::Provider => "provider_generator_family_v1",
            Self::Mixed => "mixed_generator_family_v1",
            Self::StructuralSafety => "structural_safety_generator_family_v1",
        }
    }

    #[must_use]
    pub fn identity_digest(self) -> ArtifactDigest {
        derive_static_identity(SYNTHETIC_FAMILY_IDENTITY_DOMAIN_V1, self.code())
    }
}

impl fmt::Debug for SyntheticThreeLaneAblationFamilyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneAblationFamilyV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Immutable case roster for the first-party synthetic conformance corpus.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyntheticThreeLaneAblationCaseV1 {
    ValidatedIdentifierNearHead,
    FailureOnsetMiddle,
    ProviderCorrelationNearTail,
    MixedJointInterleaved,
    PartialRepeatedDistractors,
    UnknownArbitraryStructuralBytes,
}

impl SyntheticThreeLaneAblationCaseV1 {
    pub const ALL: [Self; 6] = [
        Self::ValidatedIdentifierNearHead,
        Self::FailureOnsetMiddle,
        Self::ProviderCorrelationNearTail,
        Self::MixedJointInterleaved,
        Self::PartialRepeatedDistractors,
        Self::UnknownArbitraryStructuralBytes,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ValidatedIdentifierNearHead => "validated_identifier_near_head_v1",
            Self::FailureOnsetMiddle => "failure_onset_middle_v1",
            Self::ProviderCorrelationNearTail => "provider_correlation_near_tail_v1",
            Self::MixedJointInterleaved => "mixed_joint_interleaved_v1",
            Self::PartialRepeatedDistractors => "partial_repeated_distractors_v1",
            Self::UnknownArbitraryStructuralBytes => "unknown_arbitrary_structural_bytes_v1",
        }
    }

    #[must_use]
    pub const fn family(self) -> SyntheticThreeLaneAblationFamilyV1 {
        match self {
            Self::ValidatedIdentifierNearHead => SyntheticThreeLaneAblationFamilyV1::Lexical,
            Self::FailureOnsetMiddle | Self::PartialRepeatedDistractors => {
                SyntheticThreeLaneAblationFamilyV1::Coverage
            }
            Self::ProviderCorrelationNearTail => SyntheticThreeLaneAblationFamilyV1::Provider,
            Self::MixedJointInterleaved => SyntheticThreeLaneAblationFamilyV1::Mixed,
            Self::UnknownArbitraryStructuralBytes => {
                SyntheticThreeLaneAblationFamilyV1::StructuralSafety
            }
        }
    }

    #[must_use]
    pub fn identity_digest(self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(SYNTHETIC_CASE_IDENTITY_DOMAIN_V1);
        hasher.update([case_index(self) as u8]);
        hasher.update([family_index(self.family()) as u8]);
        hasher.update(self.code().as_bytes());
        hasher.update(self.family().identity_digest().as_bytes());
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

impl fmt::Debug for SyntheticThreeLaneAblationCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneAblationCaseV1")
            .field("code", &self.code())
            .field("family", &self.family())
            .finish()
    }
}

/// Frozen identity of this exact closed corpus roster and its family mapping.
#[must_use]
pub fn synthetic_three_lane_ablation_corpus_identity_v1() -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(SYNTHETIC_CORPUS_IDENTITY_DOMAIN_V1);
    hasher.update([u8::try_from(SyntheticThreeLaneAblationCaseV1::ALL.len())
        .expect("closed case roster fits u8")]);
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        hasher.update([case_index(case) as u8]);
        hasher.update(case.identity_digest().as_bytes());
        hasher.update(case.family().identity_digest().as_bytes());
    }
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

/// Honest scope of this hand-authored first-party corpus.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyntheticThreeLaneCorpusScopeV1 {
    SyntheticConformanceOnlyGeneratorFamiliesNotIndependent,
}

impl SyntheticThreeLaneCorpusScopeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SyntheticConformanceOnlyGeneratorFamiliesNotIndependent => {
                "synthetic_conformance_only_generator_families_not_independent_v1"
            }
        }
    }
}

impl fmt::Debug for SyntheticThreeLaneCorpusScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneCorpusScopeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Domain-separated identity of a completely frozen public six-case corpus.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenPublicSyntheticThreeLaneCorpusDigestV1([u8; 32]);

impl FrozenPublicSyntheticThreeLaneCorpusDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenPublicSyntheticThreeLaneCorpusDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPublicSyntheticThreeLaneCorpusDigestV1(<redacted>)")
    }
}

/// Domain-separated identity of the governed six-case result.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernedSyntheticThreeLaneCorpusDigestV1([u8; 32]);

impl GovernedSyntheticThreeLaneCorpusDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneCorpusDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GovernedSyntheticThreeLaneCorpusDigestV1(<redacted>)")
    }
}

/// One public-stage input. It owns an already-frozen exact four-mask batch and
/// has no annotation or requirement field.
pub struct SyntheticThreeLaneAblationPublicCaseInputV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    batch: FrozenPublicThreeLaneAblationBatchV1,
}

impl SyntheticThreeLaneAblationPublicCaseInputV1 {
    #[must_use]
    pub const fn new(
        case: SyntheticThreeLaneAblationCaseV1,
        batch: FrozenPublicThreeLaneAblationBatchV1,
    ) -> Self {
        Self { case, batch }
    }
}

impl fmt::Debug for SyntheticThreeLaneAblationPublicCaseInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticThreeLaneAblationPublicCaseInputV1")
            .field("case", &self.case)
            .field("batch", &self.batch)
            .finish()
    }
}

/// One immutable public corpus case.
pub struct FrozenPublicSyntheticThreeLaneAblationCaseV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    batch: FrozenPublicThreeLaneAblationBatchV1,
}

impl FrozenPublicSyntheticThreeLaneAblationCaseV1 {
    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn batch(&self) -> &FrozenPublicThreeLaneAblationBatchV1 {
        &self.batch
    }
}

impl fmt::Debug for FrozenPublicSyntheticThreeLaneAblationCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicSyntheticThreeLaneAblationCaseV1")
            .field("case", &self.case)
            .field("family", &self.family)
            .field("batch_identity_present", &true)
            .finish()
    }
}

/// Complete label-free public corpus package.
///
/// Type staging keeps annotation values out of this object, but cannot attest
/// that an external caller had not inspected labels before construction.
pub struct FrozenPublicSyntheticThreeLaneAblationCorpusV1 {
    digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    corpus_identity: ArtifactDigest,
    scope: SyntheticThreeLaneCorpusScopeV1,
    method_family_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cases: [FrozenPublicSyntheticThreeLaneAblationCaseV1; 6],
}

impl FrozenPublicSyntheticThreeLaneAblationCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenPublicSyntheticThreeLaneCorpusDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn corpus_identity(&self) -> ArtifactDigest {
        self.corpus_identity
    }

    #[must_use]
    pub const fn scope(&self) -> SyntheticThreeLaneCorpusScopeV1 {
        self.scope
    }

    #[must_use]
    pub const fn method_family_digest(&self) -> ArtifactDigest {
        self.method_family_digest
    }

    #[must_use]
    pub const fn environment(&self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.environment
    }

    #[must_use]
    pub fn cases(&self) -> &[FrozenPublicSyntheticThreeLaneAblationCaseV1; 6] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SyntheticThreeLaneAblationCaseV1,
    ) -> &FrozenPublicSyntheticThreeLaneAblationCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub const fn contains_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn staging_trust_boundary_code(&self) -> &'static str {
        "label_free_data_boundary_not_external_temporal_attestation"
    }
}

impl fmt::Debug for FrozenPublicSyntheticThreeLaneAblationCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicSyntheticThreeLaneAblationCorpusV1")
            .field("corpus_identity_present", &true)
            .field("scope", &self.scope)
            .field("method_family_identity_present", &true)
            .field("environment", &self.environment)
            .field("case_count", &self.cases.len())
            .field("contains_annotations", &false)
            .field(
                "staging_trust_boundary",
                &self.staging_trust_boundary_code(),
            )
            .finish()
    }
}

/// Freeze the exact six-case public corpus. Every input batch already commits
/// its four renders, caps, and self-asserted measurement receipts.
pub fn freeze_public_synthetic_three_lane_ablation_corpus_v1<Cases>(
    cases: Cases,
) -> Result<FrozenPublicSyntheticThreeLaneAblationCorpusV1, SyntheticThreeLaneCorpusErrorV1>
where
    Cases: IntoIterator<Item = SyntheticThreeLaneAblationPublicCaseInputV1>,
{
    let mut by_case = std::array::from_fn::<_, 6, _>(|_| None);
    for input in cases {
        let index = case_index(input.case);
        if by_case[index].replace(input).is_some() {
            return Err(SyntheticThreeLaneCorpusErrorV1::DuplicateCase);
        }
    }
    if by_case.iter().any(Option::is_none) {
        return Err(SyntheticThreeLaneCorpusErrorV1::MissingCases {
            count: by_case.iter().filter(|case| case.is_none()).count(),
        });
    }
    let inputs = by_case
        .into_iter()
        .map(|input| input.ok_or(SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 }))
        .collect::<Result<Vec<_>, _>>()?;

    let expected_method = three_lane_ablation_method_family_digest_v1();
    let environment = inputs
        .first()
        .ok_or(SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 6 })?
        .batch
        .environment();
    let mut seen_public_cases = BTreeSet::new();
    let mut seen_batches = BTreeSet::new();
    let cases = inputs
        .into_iter()
        .zip(SyntheticThreeLaneAblationCaseV1::ALL)
        .map(|(input, expected_case)| {
            if input.case != expected_case
                || input.batch.public_case_artifact_digest() != expected_case.identity_digest()
            {
                return Err(SyntheticThreeLaneCorpusErrorV1::CaseIdentityMismatch);
            }
            if input.batch.method_family_digest() != expected_method {
                return Err(SyntheticThreeLaneCorpusErrorV1::MethodFamilyMismatch);
            }
            if input.batch.environment() != environment {
                return Err(SyntheticThreeLaneCorpusErrorV1::MeasurementEnvironmentMismatch);
            }
            if input.batch.allocation()
                != ThreeLaneAblationMeasurementAllocationV1::ConservativeSharedBatchFullChargeEachConfiguration
            {
                return Err(SyntheticThreeLaneCorpusErrorV1::MeasurementAllocationMismatch);
            }
            if !seen_public_cases.insert(input.batch.public_case_artifact_digest()) {
                return Err(SyntheticThreeLaneCorpusErrorV1::DuplicatePublicCaseArtifact);
            }
            if !seen_batches.insert(input.batch.digest()) {
                return Err(SyntheticThreeLaneCorpusErrorV1::DuplicatePublicBatch);
            }
            Ok(FrozenPublicSyntheticThreeLaneAblationCaseV1 {
                case: expected_case,
                family: expected_case.family(),
                batch: input.batch,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [FrozenPublicSyntheticThreeLaneAblationCaseV1; 6] = cases
        .try_into()
        .map_err(|_| SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 })?;
    let corpus_identity = synthetic_three_lane_ablation_corpus_identity_v1();
    let scope =
        SyntheticThreeLaneCorpusScopeV1::SyntheticConformanceOnlyGeneratorFamiliesNotIndependent;
    let digest =
        derive_public_corpus_digest(corpus_identity, scope, expected_method, environment, &cases)?;
    Ok(FrozenPublicSyntheticThreeLaneAblationCorpusV1 {
        digest,
        corpus_identity,
        scope,
        method_family_digest: expected_method,
        environment,
        cases,
    })
}

/// Governed-only case input. The claimed case, family, corpus, and batch are
/// checked as a complete bijection before any case is evaluated.
pub struct GovernedSyntheticThreeLaneAblationCaseInputV1<'input, 'ledger> {
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    public_corpus_digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    artifact_join: GovernedCaseArtifactJoinV1,
    annotation: &'input EvidentrailBenchAnnotationSpecV1,
    ledger: &'ledger EventLedger,
    block_index: &'input BlockIndex<'ledger>,
}

impl<'input, 'ledger> GovernedSyntheticThreeLaneAblationCaseInputV1<'input, 'ledger> {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        case: SyntheticThreeLaneAblationCaseV1,
        family: SyntheticThreeLaneAblationFamilyV1,
        public_corpus_digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
        public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
        artifact_join: GovernedCaseArtifactJoinV1,
        annotation: &'input EvidentrailBenchAnnotationSpecV1,
        ledger: &'ledger EventLedger,
        block_index: &'input BlockIndex<'ledger>,
    ) -> Self {
        Self {
            case,
            family,
            public_corpus_digest,
            public_batch_digest,
            artifact_join,
            annotation,
            ledger,
            block_index,
        }
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneAblationCaseInputV1<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneAblationCaseInputV1")
            .field("case", &self.case)
            .field("family", &self.family)
            .field("public_corpus_binding_present", &true)
            .field("public_batch_binding_present", &true)
            .field("artifact_join", &self.artifact_join)
            .field("annotation_identity_present", &true)
            .field("ledger_binding_present", &true)
            .field("block_binding_present", &true)
            .finish()
    }
}

/// One governed case and all four of its retained evaluations/violations.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSyntheticThreeLaneAblationCaseV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    family: SyntheticThreeLaneAblationFamilyV1,
    batch: GovernedThreeLaneAblationBatchV1,
}

impl GovernedSyntheticThreeLaneAblationCaseV1 {
    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn batch(&self) -> &GovernedThreeLaneAblationBatchV1 {
        &self.batch
    }
}

impl fmt::Debug for GovernedSyntheticThreeLaneAblationCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneAblationCaseV1")
            .field("case", &self.case)
            .field("family", &self.family)
            .field("batch", &self.batch)
            .finish()
    }
}

/// One exact case component of an unweighted family macro recall.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactFamilyMacroRecallComponentV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    satisfied_requirement_count: u64,
    requirement_count: u64,
    satisfied_weight_micros: u64,
    total_weight_micros: u64,
}

impl ExactFamilyMacroRecallComponentV1 {
    #[must_use]
    pub const fn case(self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
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
    pub const fn exact_weight_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }
}

impl fmt::Debug for ExactFamilyMacroRecallComponentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactFamilyMacroRecallComponentV1")
            .field("case", &self.case)
            .field(
                "satisfied_requirement_count",
                &self.satisfied_requirement_count,
            )
            .field("requirement_count", &self.requirement_count)
            .field("satisfied_weight_micros", &self.satisfied_weight_micros)
            .field("total_weight_micros", &self.total_weight_micros)
            .finish()
    }
}

/// Transparent family macro: the exact arithmetic is the unweighted mean of
/// the retained per-case rational components. No decimal or scalar composite
/// is materialized.
#[derive(Clone, PartialEq, Eq)]
pub struct FamilyMacroRequirementRecallV1 {
    family: SyntheticThreeLaneAblationFamilyV1,
    mask: ThreeLaneAblationMaskV1,
    components: Vec<ExactFamilyMacroRecallComponentV1>,
}

impl FamilyMacroRequirementRecallV1 {
    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub fn components(&self) -> &[ExactFamilyMacroRecallComponentV1] {
        &self.components
    }

    #[must_use]
    pub const fn formula_code(&self) -> &'static str {
        "unweighted_mean_of_exact_case_weighted_requirement_recall_components"
    }
}

impl fmt::Debug for FamilyMacroRequirementRecallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FamilyMacroRequirementRecallV1")
            .field("family", &self.family)
            .field("mask", &self.mask)
            .field("component_count", &self.components.len())
            .field("formula", &self.formula_code())
            .finish()
    }
}

/// Direction of the exact `(ablated - Full)` weighted-recall component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LaneRemovalDeltaDirectionV1 {
    AblatedLower,
    Equal,
    AblatedHigher,
}

impl LaneRemovalDeltaDirectionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AblatedLower => "ablated_lower",
            Self::Equal => "equal",
            Self::AblatedHigher => "ablated_higher",
        }
    }
}

impl fmt::Debug for LaneRemovalDeltaDirectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaneRemovalDeltaDirectionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact per-case lane-removal delta component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactLaneRemovalDeltaComponentV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    ablated_mask: ThreeLaneAblationMaskV1,
    full_satisfied_weight_micros: u64,
    ablated_satisfied_weight_micros: u64,
    total_weight_micros: u64,
}

impl ExactLaneRemovalDeltaComponentV1 {
    #[must_use]
    pub const fn case(self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn ablated_mask(self) -> ThreeLaneAblationMaskV1 {
        self.ablated_mask
    }

    #[must_use]
    pub const fn full_ratio(self) -> (u64, u64) {
        (self.full_satisfied_weight_micros, self.total_weight_micros)
    }

    #[must_use]
    pub const fn ablated_ratio(self) -> (u64, u64) {
        (
            self.ablated_satisfied_weight_micros,
            self.total_weight_micros,
        )
    }

    #[must_use]
    pub const fn direction(self) -> LaneRemovalDeltaDirectionV1 {
        if self.ablated_satisfied_weight_micros < self.full_satisfied_weight_micros {
            LaneRemovalDeltaDirectionV1::AblatedLower
        } else if self.ablated_satisfied_weight_micros > self.full_satisfied_weight_micros {
            LaneRemovalDeltaDirectionV1::AblatedHigher
        } else {
            LaneRemovalDeltaDirectionV1::Equal
        }
    }

    /// Unsigned numerator magnitude and exact shared denominator for
    /// `(ablated - Full)`.
    #[must_use]
    pub const fn exact_delta_magnitude_ratio(self) -> (u64, u64) {
        (
            self.ablated_satisfied_weight_micros
                .abs_diff(self.full_satisfied_weight_micros),
            self.total_weight_micros,
        )
    }
}

impl fmt::Debug for ExactLaneRemovalDeltaComponentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactLaneRemovalDeltaComponentV1")
            .field("case", &self.case)
            .field("ablated_mask", &self.ablated_mask)
            .field("direction", &self.direction())
            .field("delta_magnitude_ratio", &self.exact_delta_magnitude_ratio())
            .finish()
    }
}

/// Transparent family macro lane-removal delta represented as exact case
/// components. Same-family cases are explicitly non-independent.
#[derive(Clone, PartialEq, Eq)]
pub struct FamilyMacroLaneRemovalDeltaV1 {
    family: SyntheticThreeLaneAblationFamilyV1,
    ablated_mask: ThreeLaneAblationMaskV1,
    components: Vec<ExactLaneRemovalDeltaComponentV1>,
}

impl FamilyMacroLaneRemovalDeltaV1 {
    #[must_use]
    pub const fn family(&self) -> SyntheticThreeLaneAblationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn ablated_mask(&self) -> ThreeLaneAblationMaskV1 {
        self.ablated_mask
    }

    #[must_use]
    pub fn components(&self) -> &[ExactLaneRemovalDeltaComponentV1] {
        &self.components
    }

    #[must_use]
    pub const fn formula_code(&self) -> &'static str {
        "unweighted_mean_of_exact_case_ablated_minus_full_recall_components"
    }
}

impl fmt::Debug for FamilyMacroLaneRemovalDeltaV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FamilyMacroLaneRemovalDeltaV1")
            .field("family", &self.family)
            .field("ablated_mask", &self.ablated_mask)
            .field("component_count", &self.components.len())
            .field("formula", &self.formula_code())
            .finish()
    }
}

/// Governed corpus result. Every case retains all four evaluations, resources,
/// and cap violations. Summaries expose exact recall components only.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSyntheticThreeLaneAblationCorpusV1 {
    digest: GovernedSyntheticThreeLaneCorpusDigestV1,
    public_corpus_digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    public_run_manifest_artifact_digest: ArtifactDigest,
    scope: SyntheticThreeLaneCorpusScopeV1,
    method_family_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cases: [GovernedSyntheticThreeLaneAblationCaseV1; 6],
    family_macro_recalls: Vec<FamilyMacroRequirementRecallV1>,
    family_lane_removal_deltas: Vec<FamilyMacroLaneRemovalDeltaV1>,
}

impl GovernedSyntheticThreeLaneAblationCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> GovernedSyntheticThreeLaneCorpusDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_corpus_digest(&self) -> FrozenPublicSyntheticThreeLaneCorpusDigestV1 {
        self.public_corpus_digest
    }

    #[must_use]
    pub const fn public_run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn scope(&self) -> SyntheticThreeLaneCorpusScopeV1 {
        self.scope
    }

    #[must_use]
    pub const fn method_family_digest(&self) -> ArtifactDigest {
        self.method_family_digest
    }

    #[must_use]
    pub const fn environment(&self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.environment
    }

    #[must_use]
    pub fn cases(&self) -> &[GovernedSyntheticThreeLaneAblationCaseV1; 6] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SyntheticThreeLaneAblationCaseV1,
    ) -> &GovernedSyntheticThreeLaneAblationCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub fn family_macro_recalls(&self) -> &[FamilyMacroRequirementRecallV1] {
        &self.family_macro_recalls
    }

    #[must_use]
    pub fn family_lane_removal_deltas(&self) -> &[FamilyMacroLaneRemovalDeltaV1] {
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
    pub const fn contains_vds_claim(&self) -> bool {
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

impl fmt::Debug for GovernedSyntheticThreeLaneAblationCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticThreeLaneAblationCorpusV1")
            .field("governed_identity_present", &true)
            .field("public_corpus_binding_present", &true)
            .field("public_run_manifest_binding_present", &true)
            .field("scope", &self.scope)
            .field("method_family_identity_present", &true)
            .field("environment", &self.environment)
            .field("case_count", &self.cases.len())
            .field(
                "family_macro_recall_count",
                &self.family_macro_recalls.len(),
            )
            .field(
                "family_lane_removal_delta_count",
                &self.family_lane_removal_deltas.len(),
            )
            .field("contains_scalar_composite", &false)
            .field("contains_auc", &false)
            .field("contains_winner", &false)
            .field("contains_vds_claim", &false)
            .field("contains_statistical_claim", &false)
            .field("contains_general_quality_claim", &false)
            .finish()
    }
}

/// Validate the exact six-case governed join before evaluating any case.
pub fn evaluate_governed_synthetic_three_lane_ablation_corpus_v1<'input, 'ledger, Inputs>(
    public: &FrozenPublicSyntheticThreeLaneAblationCorpusV1,
    inputs: Inputs,
) -> Result<GovernedSyntheticThreeLaneAblationCorpusV1, SyntheticThreeLaneCorpusErrorV1>
where
    'ledger: 'input,
    Inputs: IntoIterator<Item = GovernedSyntheticThreeLaneAblationCaseInputV1<'input, 'ledger>>,
{
    let mut by_case = std::array::from_fn::<_, 6, _>(|_| None);
    let mut public_run_manifest = None;
    let mut annotation_artifacts = BTreeSet::new();
    for input in inputs {
        if input.public_corpus_digest != public.digest {
            return Err(SyntheticThreeLaneCorpusErrorV1::ForeignCorpus);
        }
        if input.family != input.case.family() {
            return Err(SyntheticThreeLaneCorpusErrorV1::FamilyMismatch);
        }
        let index = case_index(input.case);
        if by_case[index].is_some() {
            return Err(SyntheticThreeLaneCorpusErrorV1::DuplicateCase);
        }
        let public_case = public.case(input.case);
        if input.public_batch_digest != public_case.batch.digest() {
            return Err(SyntheticThreeLaneCorpusErrorV1::ForeignPublicBatch);
        }
        let binding = input.artifact_join.artifact_binding();
        if binding.public_case_artifact_digest() != public_case.batch.public_case_artifact_digest()
            || input.annotation.public_case_artifact_digest()
                != public_case.batch.public_case_artifact_digest()
        {
            return Err(SyntheticThreeLaneCorpusErrorV1::ForeignCaseJoin);
        }
        match public_run_manifest {
            None => {
                public_run_manifest =
                    Some(input.artifact_join.public_run_manifest_artifact_digest())
            }
            Some(expected)
                if expected != input.artifact_join.public_run_manifest_artifact_digest() =>
            {
                return Err(SyntheticThreeLaneCorpusErrorV1::ForeignRunManifest);
            }
            Some(_) => {}
        }
        if !annotation_artifacts.insert(binding.annotation_artifact_digest()) {
            return Err(SyntheticThreeLaneCorpusErrorV1::DuplicateAnnotationArtifact);
        }
        by_case[index] = Some(input);
    }
    if by_case.iter().any(Option::is_none) {
        return Err(SyntheticThreeLaneCorpusErrorV1::MissingCases {
            count: by_case.iter().filter(|case| case.is_none()).count(),
        });
    }
    let public_run_manifest_artifact_digest =
        public_run_manifest.ok_or(SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 6 })?;

    let cases = by_case
        .into_iter()
        .zip(SyntheticThreeLaneAblationCaseV1::ALL)
        .map(|(input, case)| {
            let input = input.ok_or(SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 })?;
            let batch = evaluate_governed_three_lane_ablation_batch_v1(
                public.case(case).batch(),
                input.artifact_join,
                input.annotation,
                input.ledger,
                input.block_index,
            )
            .map_err(SyntheticThreeLaneCorpusErrorV1::CaseEvaluation)?;
            Ok(GovernedSyntheticThreeLaneAblationCaseV1 {
                case,
                family: case.family(),
                batch,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [GovernedSyntheticThreeLaneAblationCaseV1; 6] = cases
        .try_into()
        .map_err(|_| SyntheticThreeLaneCorpusErrorV1::MissingCases { count: 1 })?;
    let family_macro_recalls = build_family_macro_recalls(&cases);
    let family_lane_removal_deltas = build_family_lane_removal_deltas(&cases)?;
    let digest = derive_governed_corpus_digest(
        public.digest,
        public_run_manifest_artifact_digest,
        &cases,
        &family_macro_recalls,
        &family_lane_removal_deltas,
    )?;
    Ok(GovernedSyntheticThreeLaneAblationCorpusV1 {
        digest,
        public_corpus_digest: public.digest,
        public_run_manifest_artifact_digest,
        scope: public.scope,
        method_family_digest: public.method_family_digest,
        environment: public.environment,
        cases,
        family_macro_recalls,
        family_lane_removal_deltas,
    })
}

/// Contentless public-corpus and governed-corpus failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyntheticThreeLaneCorpusErrorV1 {
    DuplicateCase,
    MissingCases { count: usize },
    CaseIdentityMismatch,
    MethodFamilyMismatch,
    MeasurementEnvironmentMismatch,
    MeasurementAllocationMismatch,
    DuplicatePublicCaseArtifact,
    DuplicatePublicBatch,
    ForeignCorpus,
    ForeignPublicBatch,
    FamilyMismatch,
    ForeignCaseJoin,
    ForeignRunManifest,
    DuplicateAnnotationArtifact,
    RecallUniverseMismatch,
    DigestLengthOverflow,
    CaseEvaluation(ThreeLaneAblationEvaluationErrorV1),
}

impl SyntheticThreeLaneCorpusErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateCase => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_DUPLICATE_CASE",
            Self::MissingCases { .. } => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_MISSING_CASES",
            Self::CaseIdentityMismatch => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_CASE_IDENTITY",
            Self::MethodFamilyMismatch => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_METHOD_FAMILY",
            Self::MeasurementEnvironmentMismatch => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_MEASUREMENT_ENVIRONMENT"
            }
            Self::MeasurementAllocationMismatch => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_MEASUREMENT_ALLOCATION"
            }
            Self::DuplicatePublicCaseArtifact => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_DUPLICATE_PUBLIC_CASE_ARTIFACT"
            }
            Self::DuplicatePublicBatch => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_DUPLICATE_PUBLIC_BATCH"
            }
            Self::ForeignCorpus => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FOREIGN_CORPUS",
            Self::ForeignPublicBatch => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FOREIGN_PUBLIC_BATCH"
            }
            Self::FamilyMismatch => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FAMILY_MISMATCH",
            Self::ForeignCaseJoin => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FOREIGN_CASE_JOIN",
            Self::ForeignRunManifest => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_FOREIGN_RUN_MANIFEST"
            }
            Self::DuplicateAnnotationArtifact => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_DUPLICATE_ANNOTATION_ARTIFACT"
            }
            Self::RecallUniverseMismatch => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_RECALL_UNIVERSE",
            Self::DigestLengthOverflow => {
                "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_DIGEST_LENGTH_OVERFLOW"
            }
            Self::CaseEvaluation(_) => "EVIDENTRAIL_BENCH_SYNTHETIC_ABLATION_CORPUS_CASE_EVALUATION",
        }
    }
}

impl fmt::Debug for SyntheticThreeLaneCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SyntheticThreeLaneCorpusErrorV1");
        debug.field("code", &self.code());
        if let Self::MissingCases { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for SyntheticThreeLaneCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SyntheticThreeLaneCorpusErrorV1 {}

fn build_family_macro_recalls(
    cases: &[GovernedSyntheticThreeLaneAblationCaseV1; 6],
) -> Vec<FamilyMacroRequirementRecallV1> {
    SyntheticThreeLaneAblationFamilyV1::ALL
        .into_iter()
        .flat_map(|family| {
            ThreeLaneAblationMaskV1::ALL.into_iter().map(move |mask| {
                let components = cases
                    .iter()
                    .filter(|case| case.family == family)
                    .map(|case| {
                        let recall = case.batch.evaluation(mask).evaluation().recall();
                        ExactFamilyMacroRecallComponentV1 {
                            case: case.case,
                            satisfied_requirement_count: recall.satisfied_requirement_count(),
                            requirement_count: recall.requirement_count(),
                            satisfied_weight_micros: recall.satisfied_weight_micros(),
                            total_weight_micros: recall.total_weight_micros(),
                        }
                    })
                    .collect();
                FamilyMacroRequirementRecallV1 {
                    family,
                    mask,
                    components,
                }
            })
        })
        .collect()
}

fn build_family_lane_removal_deltas(
    cases: &[GovernedSyntheticThreeLaneAblationCaseV1; 6],
) -> Result<Vec<FamilyMacroLaneRemovalDeltaV1>, SyntheticThreeLaneCorpusErrorV1> {
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
                            .batch
                            .evaluation(ThreeLaneAblationMaskV1::Full)
                            .evaluation()
                            .recall();
                        let ablated = case.batch.evaluation(ablated_mask).evaluation().recall();
                        if full.total_weight_micros() != ablated.total_weight_micros()
                            || full.requirement_count() != ablated.requirement_count()
                        {
                            return Err(SyntheticThreeLaneCorpusErrorV1::RecallUniverseMismatch);
                        }
                        Ok(ExactLaneRemovalDeltaComponentV1 {
                            case: case.case,
                            ablated_mask,
                            full_satisfied_weight_micros: full.satisfied_weight_micros(),
                            ablated_satisfied_weight_micros: ablated.satisfied_weight_micros(),
                            total_weight_micros: full.total_weight_micros(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(FamilyMacroLaneRemovalDeltaV1 {
                    family,
                    ablated_mask,
                    components,
                })
            })
        })
        .collect()
}

fn derive_public_corpus_digest(
    corpus_identity: ArtifactDigest,
    scope: SyntheticThreeLaneCorpusScopeV1,
    method_family_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cases: &[FrozenPublicSyntheticThreeLaneAblationCaseV1; 6],
) -> Result<FrozenPublicSyntheticThreeLaneCorpusDigestV1, SyntheticThreeLaneCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_SYNTHETIC_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, corpus_identity.as_bytes())?;
    update_field(&mut hasher, scope.code().as_bytes())?;
    update_field(&mut hasher, method_family_digest.as_bytes())?;
    update_environment(&mut hasher, environment)?;
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in cases {
        update_field(&mut hasher, case.case.code().as_bytes())?;
        update_field(&mut hasher, case.case.identity_digest().as_bytes())?;
        update_field(&mut hasher, case.family.code().as_bytes())?;
        update_field(&mut hasher, case.family.identity_digest().as_bytes())?;
        update_field(&mut hasher, case.batch.digest().as_bytes())?;
    }
    Ok(FrozenPublicSyntheticThreeLaneCorpusDigestV1(
        hasher.finalize().into(),
    ))
}

fn derive_governed_corpus_digest(
    public_corpus_digest: FrozenPublicSyntheticThreeLaneCorpusDigestV1,
    public_run_manifest_artifact_digest: ArtifactDigest,
    cases: &[GovernedSyntheticThreeLaneAblationCaseV1; 6],
    family_macro_recalls: &[FamilyMacroRequirementRecallV1],
    family_lane_removal_deltas: &[FamilyMacroLaneRemovalDeltaV1],
) -> Result<GovernedSyntheticThreeLaneCorpusDigestV1, SyntheticThreeLaneCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_SYNTHETIC_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, public_corpus_digest.as_bytes())?;
    update_field(&mut hasher, public_run_manifest_artifact_digest.as_bytes())?;
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in cases {
        update_field(&mut hasher, case.case.code().as_bytes())?;
        update_field(&mut hasher, case.family.code().as_bytes())?;
        update_field(&mut hasher, case.batch.digest().as_bytes())?;
    }
    update_u64(&mut hasher, checked_u64(family_macro_recalls.len())?);
    for summary in family_macro_recalls {
        update_field(&mut hasher, summary.family.code().as_bytes())?;
        update_mask(&mut hasher, summary.mask)?;
        update_u64(&mut hasher, checked_u64(summary.components.len())?);
        for component in &summary.components {
            update_field(&mut hasher, component.case.code().as_bytes())?;
            update_u64(&mut hasher, component.satisfied_requirement_count);
            update_u64(&mut hasher, component.requirement_count);
            update_u64(&mut hasher, component.satisfied_weight_micros);
            update_u64(&mut hasher, component.total_weight_micros);
        }
    }
    update_u64(&mut hasher, checked_u64(family_lane_removal_deltas.len())?);
    for summary in family_lane_removal_deltas {
        update_field(&mut hasher, summary.family.code().as_bytes())?;
        update_mask(&mut hasher, summary.ablated_mask)?;
        update_u64(&mut hasher, checked_u64(summary.components.len())?);
        for component in &summary.components {
            update_field(&mut hasher, component.case.code().as_bytes())?;
            update_u64(&mut hasher, component.full_satisfied_weight_micros);
            update_u64(&mut hasher, component.ablated_satisfied_weight_micros);
            update_u64(&mut hasher, component.total_weight_micros);
        }
    }
    Ok(GovernedSyntheticThreeLaneCorpusDigestV1(
        hasher.finalize().into(),
    ))
}

fn update_environment(
    hasher: &mut Sha256,
    environment: ProducerProposalMeasurementEnvironmentV1,
) -> Result<(), SyntheticThreeLaneCorpusErrorV1> {
    update_u64(hasher, environment.contract_version());
    update_field(hasher, environment.renderer().artifact_digest().as_bytes())?;
    update_u64(hasher, environment.renderer().contract_version());
    update_field(hasher, environment.tokenizer_artifact_digest().as_bytes())?;
    update_u64(hasher, environment.tokenizer_contract_version());
    update_field(
        hasher,
        environment.measurement_harness_artifact_digest().as_bytes(),
    )?;
    update_u64(hasher, environment.measurement_harness_contract_version());
    Ok(())
}

fn update_mask(
    hasher: &mut Sha256,
    mask: ThreeLaneAblationMaskV1,
) -> Result<(), SyntheticThreeLaneCorpusErrorV1> {
    hasher.update([mask.bits()]);
    update_field(hasher, mask.code().as_bytes())
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), SyntheticThreeLaneCorpusErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn checked_u64(value: usize) -> Result<u64, SyntheticThreeLaneCorpusErrorV1> {
    u64::try_from(value).map_err(|_| SyntheticThreeLaneCorpusErrorV1::DigestLengthOverflow)
}

fn derive_static_identity(domain: &[u8], code: &str) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(code.as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into())
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

const fn family_index(family: SyntheticThreeLaneAblationFamilyV1) -> usize {
    match family {
        SyntheticThreeLaneAblationFamilyV1::Lexical => 0,
        SyntheticThreeLaneAblationFamilyV1::Coverage => 1,
        SyntheticThreeLaneAblationFamilyV1::Provider => 2,
        SyntheticThreeLaneAblationFamilyV1::Mixed => 3,
        SyntheticThreeLaneAblationFamilyV1::StructuralSafety => 4,
    }
}
