use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{
    ThreeLaneAblationMaskV1, three_lane_ablation_config_digest_v1,
    three_lane_ablation_method_family_digest_v1,
};
use evidentrail_core::{BlockIndex, EventLedger};
use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::three_lane_ablation::FrozenThreeLaneAblationSetV1;
use crate::{
    CanonicalProducerProposalArtifactV1, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, FrozenProducerProposalFrontierPlanV1,
    FrozenProducerProposalUniverseDigestV1, GovernedCaseArtifactJoinV1,
    GovernedProducerProposalEvaluationV1, GovernedProducerProposalFrontierV1,
    ProducerProposalAcquisitionBindingV1, ProducerProposalErrorV1, ProducerProposalFrontierErrorV1,
    ProducerProposalIdentityV1, ProducerProposalMeasurementEnvironmentV1,
    ProducerProposalMeasurementReceiptV1, ProducerProposalResourceCapV1,
    evaluate_governed_producer_proposal_frontier_v1, evaluate_governed_producer_proposals_v1,
};

const PUBLIC_ABLATION_POINT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-three-lane-ablation-point/v1\0";
const PUBLIC_ABLATION_BATCH_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-three-lane-ablation-batch/v1\0";
const GOVERNED_ABLATION_BATCH_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-three-lane-ablation-batch/v1\0";

/// Closed V1 allocation rule for a compiler batch that generated and
/// validated all three lanes exactly once.
///
/// The complete nonzero batch wall-time and peak-RSS observations are charged
/// to every mask. Canonical render bytes and token counts remain specific to
/// each configured universe. V1 deliberately offers no separable-cost claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneAblationMeasurementAllocationV1 {
    ConservativeSharedBatchFullChargeEachConfiguration,
}

impl ThreeLaneAblationMeasurementAllocationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConservativeSharedBatchFullChargeEachConfiguration => {
                "conservative_shared_batch_full_charge_each_configuration_v1"
            }
        }
    }
}

impl fmt::Debug for ThreeLaneAblationMeasurementAllocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneAblationMeasurementAllocationV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Domain-separated identity for one frozen public mask outcome.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenPublicThreeLaneAblationPointDigestV1([u8; 32]);

impl FrozenPublicThreeLaneAblationPointDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenPublicThreeLaneAblationPointDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPublicThreeLaneAblationPointDigestV1(<redacted>)")
    }
}

/// Domain-separated identity for the complete pre-annotation public package.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenPublicThreeLaneAblationBatchDigestV1([u8; 32]);

impl FrozenPublicThreeLaneAblationBatchDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenPublicThreeLaneAblationBatchDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPublicThreeLaneAblationBatchDigestV1(<redacted>)")
    }
}

/// Domain-separated identity for the post-annotation governed package.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernedThreeLaneAblationBatchDigestV1([u8; 32]);

impl GovernedThreeLaneAblationBatchDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GovernedThreeLaneAblationBatchDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GovernedThreeLaneAblationBatchDigestV1(<redacted>)")
    }
}

/// Unvalidated public-stage material for exactly one claimed mask.
///
/// Construction accepts no hidden annotation or requirement. The owning
/// batch constructor validates the mask/universe/render/receipt bijection.
pub struct ThreeLaneAblationPublicPointInputV1 {
    mask: ThreeLaneAblationMaskV1,
    cap: ProducerProposalResourceCapV1,
    canonical_artifact: CanonicalProducerProposalArtifactV1,
    measurement: ProducerProposalMeasurementReceiptV1,
}

impl ThreeLaneAblationPublicPointInputV1 {
    #[must_use]
    pub const fn new(
        mask: ThreeLaneAblationMaskV1,
        cap: ProducerProposalResourceCapV1,
        canonical_artifact: CanonicalProducerProposalArtifactV1,
        measurement: ProducerProposalMeasurementReceiptV1,
    ) -> Self {
        Self {
            mask,
            cap,
            canonical_artifact,
            measurement,
        }
    }
}

impl fmt::Debug for ThreeLaneAblationPublicPointInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneAblationPublicPointInputV1")
            .field("mask", &self.mask)
            .field("cap", &self.cap)
            .field("canonical_artifact", &self.canonical_artifact)
            .field("measurement", &self.measurement)
            .finish()
    }
}

/// One immutable public configured-producer outcome.
pub struct FrozenPublicThreeLaneAblationPointV1 {
    digest: FrozenPublicThreeLaneAblationPointDigestV1,
    mask: ThreeLaneAblationMaskV1,
    cap: ProducerProposalResourceCapV1,
    canonical_artifact: CanonicalProducerProposalArtifactV1,
    measurement: ProducerProposalMeasurementReceiptV1,
}

impl FrozenPublicThreeLaneAblationPointV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenPublicThreeLaneAblationPointDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn cap(&self) -> ProducerProposalResourceCapV1 {
        self.cap
    }

    #[must_use]
    pub const fn canonical_artifact(&self) -> &CanonicalProducerProposalArtifactV1 {
        &self.canonical_artifact
    }

    #[must_use]
    pub const fn measurement(&self) -> ProducerProposalMeasurementReceiptV1 {
        self.measurement
    }

    #[must_use]
    pub const fn universe_digest(&self) -> FrozenProducerProposalUniverseDigestV1 {
        self.measurement.universe_digest()
    }

    #[must_use]
    pub const fn producer(&self) -> ProducerProposalIdentityV1 {
        self.measurement.producer()
    }
}

impl fmt::Debug for FrozenPublicThreeLaneAblationPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicThreeLaneAblationPointV1")
            .field("mask", &self.mask)
            .field("cap", &self.cap)
            .field("canonical_artifact", &self.canonical_artifact)
            .field("measurement", &self.measurement)
            .field("point_identity_present", &true)
            .finish()
    }
}

/// Immutable four-mask public plan and observed-output package.
///
/// This type cannot contain hidden annotations. Its construction boundary is
/// useful for process staging but is not external temporal attestation that a
/// caller had not previously inspected labels.
pub struct FrozenPublicThreeLaneAblationBatchV1 {
    digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    public_case_artifact_digest: ArtifactDigest,
    public_case: EvidentrailBenchCaseSpecV1,
    ablations: FrozenThreeLaneAblationSetV1,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    method_family_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
    shared_wall_time_nanos: u64,
    shared_peak_rss_bytes: u64,
    frontier_plan: FrozenProducerProposalFrontierPlanV1,
    points: [FrozenPublicThreeLaneAblationPointV1; 4],
}

impl FrozenPublicThreeLaneAblationBatchV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenPublicThreeLaneAblationBatchDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn public_case(&self) -> &EvidentrailBenchCaseSpecV1 {
        &self.public_case
    }

    #[must_use]
    pub const fn ablations(&self) -> &FrozenThreeLaneAblationSetV1 {
        &self.ablations
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
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
    pub const fn allocation(&self) -> ThreeLaneAblationMeasurementAllocationV1 {
        self.allocation
    }

    #[must_use]
    pub const fn shared_wall_time_nanos(&self) -> u64 {
        self.shared_wall_time_nanos
    }

    #[must_use]
    pub const fn shared_peak_rss_bytes(&self) -> u64 {
        self.shared_peak_rss_bytes
    }

    #[must_use]
    pub const fn frontier_plan(&self) -> &FrozenProducerProposalFrontierPlanV1 {
        &self.frontier_plan
    }

    #[must_use]
    pub fn points(&self) -> &[FrozenPublicThreeLaneAblationPointV1; 4] {
        &self.points
    }

    #[must_use]
    pub fn point(&self, mask: ThreeLaneAblationMaskV1) -> &FrozenPublicThreeLaneAblationPointV1 {
        &self.points[mask_index(mask)]
    }

    #[must_use]
    pub const fn staging_trust_boundary_code(&self) -> &'static str {
        "typed_public_before_governed_stage_not_external_temporal_attestation"
    }
}

impl fmt::Debug for FrozenPublicThreeLaneAblationBatchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicThreeLaneAblationBatchV1")
            .field("batch_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("acquisition_binding", &self.acquisition_binding)
            .field("method_family_identity_present", &true)
            .field("environment", &self.environment)
            .field("allocation", &self.allocation)
            .field("configuration_count", &self.points.len())
            .field(
                "staging_trust_boundary",
                &self.staging_trust_boundary_code(),
            )
            .finish()
    }
}

/// Freeze the complete label-free four-mask batch before annotations are
/// accepted by any API in this protocol.
#[allow(clippy::too_many_arguments)]
pub fn freeze_public_three_lane_ablation_batch_v1<Points>(
    public_case_artifact_digest: ArtifactDigest,
    public_case: EvidentrailBenchCaseSpecV1,
    ablations: FrozenThreeLaneAblationSetV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
    point_inputs: Points,
) -> Result<FrozenPublicThreeLaneAblationBatchV1, ThreeLaneAblationEvaluationErrorV1>
where
    Points: IntoIterator<Item = ThreeLaneAblationPublicPointInputV1>,
{
    validate_ablation_set(public_case_artifact_digest, &public_case, &ablations)?;
    let mut inputs = [None, None, None, None];
    for input in point_inputs {
        let index = mask_index(input.mask);
        if inputs[index].replace(input).is_some() {
            return Err(ThreeLaneAblationEvaluationErrorV1::DuplicateMask);
        }
    }
    if inputs.iter().any(Option::is_none) {
        return Err(ThreeLaneAblationEvaluationErrorV1::MissingMasks {
            count: inputs.iter().filter(|input| input.is_none()).count(),
        });
    }
    let [full, without_lexical, without_coverage, without_provider] = inputs;
    let inputs = [
        full.ok_or(ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?,
        without_lexical.ok_or(ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?,
        without_coverage.ok_or(ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?,
        without_provider.ok_or(ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?,
    ];
    let points = inputs
        .into_iter()
        .zip(ThreeLaneAblationMaskV1::ALL)
        .map(|(input, mask)| {
            validate_public_point(&ablations, environment, allocation, mask, input)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let points: [FrozenPublicThreeLaneAblationPointV1; 4] = points
        .try_into()
        .map_err(|_| ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?;

    let first_measured = points[0].measurement.measured();
    if points.iter().any(|point| {
        point.measurement.measured().wall_time_nanos() != first_measured.wall_time_nanos()
            || point.measurement.measured().peak_rss_bytes() != first_measured.peak_rss_bytes()
    }) {
        return Err(ThreeLaneAblationEvaluationErrorV1::SharedBatchCostMismatch);
    }
    let frontier_plan = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        ThreeLaneAblationMaskV1::ALL.into_iter().map(|mask| {
            (
                ablations.configuration(mask).universe(),
                points[mask_index(mask)].cap,
            )
        }),
    )
    .map_err(ThreeLaneAblationEvaluationErrorV1::Frontier)?;
    let acquisition_binding = ablations
        .configuration(ThreeLaneAblationMaskV1::Full)
        .universe()
        .acquisition_binding();
    let method_family_digest = ablations.method_family_digest();
    let digest = derive_public_batch_digest(
        public_case_artifact_digest,
        acquisition_binding,
        method_family_digest,
        environment,
        allocation,
        frontier_plan.digest(),
        &points,
    )?;
    Ok(FrozenPublicThreeLaneAblationBatchV1 {
        digest,
        public_case_artifact_digest,
        public_case,
        ablations,
        acquisition_binding,
        method_family_digest,
        environment,
        allocation,
        shared_wall_time_nanos: first_measured.wall_time_nanos(),
        shared_peak_rss_bytes: first_measured.peak_rss_bytes(),
        frontier_plan,
        points,
    })
}

/// One exact governed mask outcome retained alongside the frontier.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedThreeLaneAblationPointV1 {
    mask: ThreeLaneAblationMaskV1,
    evaluation: GovernedProducerProposalEvaluationV1,
}

impl GovernedThreeLaneAblationPointV1 {
    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn evaluation(&self) -> &GovernedProducerProposalEvaluationV1 {
        &self.evaluation
    }
}

impl fmt::Debug for GovernedThreeLaneAblationPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedThreeLaneAblationPointV1")
            .field("mask", &self.mask)
            .field("evaluation", &self.evaluation)
            .finish()
    }
}

/// Governed four-mask evaluations plus their exact non-scalar frontier.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedThreeLaneAblationBatchV1 {
    digest: GovernedThreeLaneAblationBatchDigestV1,
    public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
    evaluations: [GovernedThreeLaneAblationPointV1; 4],
    frontier: GovernedProducerProposalFrontierV1,
}

impl GovernedThreeLaneAblationBatchV1 {
    #[must_use]
    pub const fn digest(&self) -> GovernedThreeLaneAblationBatchDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_batch_digest(&self) -> FrozenPublicThreeLaneAblationBatchDigestV1 {
        self.public_batch_digest
    }

    #[must_use]
    pub const fn allocation(&self) -> ThreeLaneAblationMeasurementAllocationV1 {
        self.allocation
    }

    #[must_use]
    pub fn evaluations(&self) -> &[GovernedThreeLaneAblationPointV1; 4] {
        &self.evaluations
    }

    #[must_use]
    pub fn evaluation(&self, mask: ThreeLaneAblationMaskV1) -> &GovernedThreeLaneAblationPointV1 {
        &self.evaluations[mask_index(mask)]
    }

    #[must_use]
    pub const fn frontier(&self) -> &GovernedProducerProposalFrontierV1 {
        &self.frontier
    }

    #[must_use]
    pub const fn contains_scalar_score(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_auc(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_verified_winner(&self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedThreeLaneAblationBatchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedThreeLaneAblationBatchV1")
            .field("governed_identity_present", &true)
            .field("public_batch_binding_present", &true)
            .field("allocation", &self.allocation)
            .field("evaluation_count", &self.evaluations.len())
            .field("frontier", &self.frontier)
            .field("contains_scalar_score", &false)
            .field("contains_auc", &false)
            .field("contains_verified_winner", &false)
            .finish()
    }
}

/// Admit hidden annotations only after an immutable public batch exists, then
/// evaluate its exact four points and construct the existing non-scalar
/// configured-producer frontier.
pub fn evaluate_governed_three_lane_ablation_batch_v1(
    public_batch: &FrozenPublicThreeLaneAblationBatchV1,
    artifact_join: GovernedCaseArtifactJoinV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: &BlockIndex<'_>,
) -> Result<GovernedThreeLaneAblationBatchV1, ThreeLaneAblationEvaluationErrorV1> {
    let evaluations = ThreeLaneAblationMaskV1::ALL
        .into_iter()
        .map(|mask| {
            let point = public_batch.point(mask);
            let universe = public_batch.ablations.configuration(mask).universe();
            evaluate_governed_producer_proposals_v1(
                artifact_join,
                &public_batch.public_case,
                annotation,
                ledger,
                block_index,
                universe,
                point.measurement,
                point.cap,
            )
            .map(|evaluation| GovernedThreeLaneAblationPointV1 { mask, evaluation })
            .map_err(ThreeLaneAblationEvaluationErrorV1::Producer)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evaluations: [GovernedThreeLaneAblationPointV1; 4] = evaluations
        .try_into()
        .map_err(|_| ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 })?;
    let frontier = evaluate_governed_producer_proposal_frontier_v1(
        &public_batch.frontier_plan,
        evaluations.iter().map(|point| point.evaluation.clone()),
    )
    .map_err(ThreeLaneAblationEvaluationErrorV1::Frontier)?;
    let digest = derive_governed_batch_digest(public_batch.digest, &evaluations, &frontier)?;
    Ok(GovernedThreeLaneAblationBatchV1 {
        digest,
        public_batch_digest: public_batch.digest,
        allocation: public_batch.allocation,
        evaluations,
        frontier,
    })
}

/// Contentless public-stage and governed-stage failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneAblationEvaluationErrorV1 {
    PublicCaseBindingMismatch,
    AcquisitionBindingMismatch,
    MethodFamilyMismatch,
    ConfigurationIdentityMismatch,
    DuplicateMask,
    MissingMasks { count: usize },
    MaskBindingMismatch,
    CanonicalRenderBindingMismatch,
    MeasurementBindingMismatch,
    MeasurementEnvironmentMismatch,
    SharedBatchCostMismatch,
    DigestLengthOverflow,
    Producer(ProducerProposalErrorV1),
    Frontier(ProducerProposalFrontierErrorV1),
}

impl ThreeLaneAblationEvaluationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PublicCaseBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_PUBLIC_CASE_BINDING",
            Self::AcquisitionBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_ACQUISITION_BINDING",
            Self::MethodFamilyMismatch => "EVIDENTRAIL_BENCH_ABLATION_METHOD_FAMILY",
            Self::ConfigurationIdentityMismatch => {
                "EVIDENTRAIL_BENCH_ABLATION_CONFIGURATION_IDENTITY"
            }
            Self::DuplicateMask => "EVIDENTRAIL_BENCH_ABLATION_DUPLICATE_MASK",
            Self::MissingMasks { .. } => "EVIDENTRAIL_BENCH_ABLATION_MISSING_MASKS",
            Self::MaskBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_MASK_BINDING",
            Self::CanonicalRenderBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_RENDER_BINDING",
            Self::MeasurementBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_MEASUREMENT_BINDING",
            Self::MeasurementEnvironmentMismatch => {
                "EVIDENTRAIL_BENCH_ABLATION_ENVIRONMENT_BINDING"
            }
            Self::SharedBatchCostMismatch => {
                "EVIDENTRAIL_BENCH_ABLATION_SHARED_BATCH_COST_MISMATCH"
            }
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_ABLATION_DIGEST_LENGTH_OVERFLOW",
            Self::Producer(_) => "EVIDENTRAIL_BENCH_ABLATION_GOVERNED_EVALUATION",
            Self::Frontier(_) => "EVIDENTRAIL_BENCH_ABLATION_FRONTIER",
        }
    }
}

impl fmt::Debug for ThreeLaneAblationEvaluationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ThreeLaneAblationEvaluationErrorV1");
        debug.field("code", &self.code());
        if let Self::MissingMasks { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for ThreeLaneAblationEvaluationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ThreeLaneAblationEvaluationErrorV1 {}

fn validate_ablation_set(
    public_case_artifact_digest: ArtifactDigest,
    public_case: &EvidentrailBenchCaseSpecV1,
    ablations: &FrozenThreeLaneAblationSetV1,
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
    let expected_method = three_lane_ablation_method_family_digest_v1();
    if ablations.method_family_digest() != expected_method {
        return Err(ThreeLaneAblationEvaluationErrorV1::MethodFamilyMismatch);
    }
    if ablations.question_digest() != public_case.question_digest() {
        return Err(ThreeLaneAblationEvaluationErrorV1::PublicCaseBindingMismatch);
    }
    let expected_acquisition = ablations
        .configuration(ThreeLaneAblationMaskV1::Full)
        .universe()
        .acquisition_binding();
    for mask in ThreeLaneAblationMaskV1::ALL {
        let configured = ablations.configuration(mask);
        if configured.mask() != mask {
            return Err(ThreeLaneAblationEvaluationErrorV1::MaskBindingMismatch);
        }
        let universe = configured.universe();
        if universe.public_case_artifact_digest() != public_case_artifact_digest
            || universe.plan_digest() != public_case.plan_digest()
            || universe.acquisition_class() != public_case.expected_acquisition_class()
        {
            return Err(ThreeLaneAblationEvaluationErrorV1::PublicCaseBindingMismatch);
        }
        if universe.acquisition_binding() != expected_acquisition {
            return Err(ThreeLaneAblationEvaluationErrorV1::AcquisitionBindingMismatch);
        }
        let producer = universe.producer();
        if producer.method_artifact_digest() != expected_method {
            return Err(ThreeLaneAblationEvaluationErrorV1::MethodFamilyMismatch);
        }
        if producer.config_artifact_digest() != three_lane_ablation_config_digest_v1(mask) {
            return Err(ThreeLaneAblationEvaluationErrorV1::ConfigurationIdentityMismatch);
        }
    }
    Ok(())
}

fn validate_public_point(
    ablations: &FrozenThreeLaneAblationSetV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
    expected_mask: ThreeLaneAblationMaskV1,
    input: ThreeLaneAblationPublicPointInputV1,
) -> Result<FrozenPublicThreeLaneAblationPointV1, ThreeLaneAblationEvaluationErrorV1> {
    if input.mask != expected_mask {
        return Err(ThreeLaneAblationEvaluationErrorV1::MaskBindingMismatch);
    }
    let universe = ablations.configuration(expected_mask).universe();
    if !input.canonical_artifact.has_valid_integrity()
        || input.canonical_artifact.universe_digest() != universe.digest()
        || input.canonical_artifact.acquisition_binding() != universe.acquisition_binding()
        || input.canonical_artifact.renderer() != environment.renderer()
    {
        return Err(ThreeLaneAblationEvaluationErrorV1::CanonicalRenderBindingMismatch);
    }
    if input.measurement.environment() != environment {
        return Err(ThreeLaneAblationEvaluationErrorV1::MeasurementEnvironmentMismatch);
    }
    if !input.measurement.matches(universe)
        || input.measurement.producer() != universe.producer()
        || input.measurement.rendered_artifact().artifact_digest()
            != input.canonical_artifact.artifact_digest()
        || input.measurement.rendered_artifact().byte_count()
            != input.canonical_artifact.byte_count()
    {
        return Err(ThreeLaneAblationEvaluationErrorV1::MeasurementBindingMismatch);
    }
    let digest = derive_public_point_digest(
        expected_mask,
        universe.digest(),
        universe.producer(),
        input.cap,
        &input.canonical_artifact,
        input.measurement,
        allocation,
    )?;
    Ok(FrozenPublicThreeLaneAblationPointV1 {
        digest,
        mask: expected_mask,
        cap: input.cap,
        canonical_artifact: input.canonical_artifact,
        measurement: input.measurement,
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_public_point_digest(
    mask: ThreeLaneAblationMaskV1,
    universe_digest: FrozenProducerProposalUniverseDigestV1,
    producer: ProducerProposalIdentityV1,
    cap: ProducerProposalResourceCapV1,
    artifact: &CanonicalProducerProposalArtifactV1,
    measurement: ProducerProposalMeasurementReceiptV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
) -> Result<FrozenPublicThreeLaneAblationPointDigestV1, ThreeLaneAblationEvaluationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_ABLATION_POINT_DOMAIN_V1)?;
    update_mask(&mut hasher, mask)?;
    update_field(&mut hasher, universe_digest.as_bytes())?;
    update_producer(&mut hasher, producer)?;
    update_cap(&mut hasher, cap);
    update_field(
        &mut hasher,
        artifact.renderer().artifact_digest().as_bytes(),
    )?;
    update_u64(&mut hasher, artifact.renderer().contract_version());
    update_field(&mut hasher, artifact.artifact_digest().as_bytes())?;
    update_u64(&mut hasher, artifact.byte_count());
    update_u64(&mut hasher, artifact.proposal_packet_count());
    update_u64(&mut hasher, artifact.member_occurrence_count());
    update_u64(&mut hasher, artifact.occurrence_source_bytes());
    update_u64(&mut hasher, artifact.unique_member_event_count());
    update_u64(&mut hasher, artifact.unique_member_source_bytes());
    update_field(&mut hasher, measurement.digest().as_bytes())?;
    update_environment(&mut hasher, measurement.environment())?;
    update_u64(
        &mut hasher,
        measurement.measured().canonical_proposal_render_tokens(),
    );
    update_u64(&mut hasher, measurement.measured().wall_time_nanos());
    update_u64(&mut hasher, measurement.measured().peak_rss_bytes());
    update_field(&mut hasher, allocation.code().as_bytes())?;
    Ok(FrozenPublicThreeLaneAblationPointDigestV1(
        hasher.finalize().into(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn derive_public_batch_digest(
    public_case_artifact_digest: ArtifactDigest,
    acquisition: ProducerProposalAcquisitionBindingV1,
    method_family_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    allocation: ThreeLaneAblationMeasurementAllocationV1,
    frontier_plan_digest: crate::ProducerProposalFrontierPlanDigestV1,
    points: &[FrozenPublicThreeLaneAblationPointV1; 4],
) -> Result<FrozenPublicThreeLaneAblationBatchDigestV1, ThreeLaneAblationEvaluationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_ABLATION_BATCH_DOMAIN_V1)?;
    update_field(&mut hasher, public_case_artifact_digest.as_bytes())?;
    update_acquisition(&mut hasher, acquisition)?;
    update_field(&mut hasher, method_family_digest.as_bytes())?;
    update_environment(&mut hasher, environment)?;
    update_field(&mut hasher, allocation.code().as_bytes())?;
    update_field(&mut hasher, frontier_plan_digest.as_bytes())?;
    update_u64(&mut hasher, 4);
    for point in points {
        update_mask(&mut hasher, point.mask)?;
        update_field(&mut hasher, point.digest.as_bytes())?;
    }
    Ok(FrozenPublicThreeLaneAblationBatchDigestV1(
        hasher.finalize().into(),
    ))
}

fn derive_governed_batch_digest(
    public_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    evaluations: &[GovernedThreeLaneAblationPointV1; 4],
    frontier: &GovernedProducerProposalFrontierV1,
) -> Result<GovernedThreeLaneAblationBatchDigestV1, ThreeLaneAblationEvaluationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_ABLATION_BATCH_DOMAIN_V1)?;
    update_field(&mut hasher, public_digest.as_bytes())?;
    update_field(&mut hasher, frontier.digest().as_bytes())?;
    update_u64(&mut hasher, 4);
    for point in evaluations {
        update_mask(&mut hasher, point.mask)?;
        update_field(&mut hasher, point.evaluation.universe_digest().as_bytes())?;
        update_producer(&mut hasher, point.evaluation.producer())?;
        update_field(
            &mut hasher,
            point.evaluation.measurement_receipt_digest().as_bytes(),
        )?;
        update_cap(&mut hasher, point.evaluation.resource_cap());
        let recall = point.evaluation.recall();
        update_u64(&mut hasher, recall.requirement_count());
        update_u64(&mut hasher, recall.satisfied_requirement_count());
        update_u64(&mut hasher, recall.total_weight_micros());
        update_u64(&mut hasher, recall.satisfied_weight_micros());
    }
    Ok(GovernedThreeLaneAblationBatchDigestV1(
        hasher.finalize().into(),
    ))
}

const fn mask_index(mask: ThreeLaneAblationMaskV1) -> usize {
    match mask {
        ThreeLaneAblationMaskV1::Full => 0,
        ThreeLaneAblationMaskV1::WithoutLexical => 1,
        ThreeLaneAblationMaskV1::WithoutCoverage => 2,
        ThreeLaneAblationMaskV1::WithoutProvider => 3,
    }
}

fn update_mask(
    hasher: &mut Sha256,
    mask: ThreeLaneAblationMaskV1,
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
    hasher.update([mask.bits()]);
    update_field(hasher, mask.code().as_bytes())
}

fn update_acquisition(
    hasher: &mut Sha256,
    acquisition: ProducerProposalAcquisitionBindingV1,
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
    update_field(hasher, acquisition.retrieval_id().as_bytes())?;
    update_field(hasher, acquisition.plan_id().as_bytes())?;
    update_field(hasher, acquisition.plan_digest().as_bytes())?;
    update_field(hasher, acquisition.acquisition_receipt_id().as_bytes())?;
    update_field(hasher, acquisition.source_identity_digest().as_bytes())?;
    update_field(hasher, acquisition.acquisition_class().code().as_bytes())
}

fn update_producer(
    hasher: &mut Sha256,
    producer: ProducerProposalIdentityV1,
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
    update_field(hasher, producer.method_artifact_digest().as_bytes())?;
    update_field(hasher, producer.config_artifact_digest().as_bytes())?;
    update_field(
        hasher,
        producer.producer_receipt_artifact_digest().as_bytes(),
    )
}

fn update_environment(
    hasher: &mut Sha256,
    environment: ProducerProposalMeasurementEnvironmentV1,
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
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

fn update_cap(hasher: &mut Sha256, cap: ProducerProposalResourceCapV1) {
    for value in [
        cap.proposal_packet_count(),
        cap.unique_member_source_bytes(),
        cap.canonical_proposal_render_tokens(),
        cap.wall_time_nanos(),
        cap.peak_rss_bytes(),
    ] {
        update_u64(hasher, value);
    }
}

fn update_field(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), ThreeLaneAblationEvaluationErrorV1> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| ThreeLaneAblationEvaluationErrorV1::DigestLengthOverflow)?;
    update_u64(hasher, length);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
