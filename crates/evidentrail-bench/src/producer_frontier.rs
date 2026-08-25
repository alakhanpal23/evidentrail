use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::resources::lower_is_better_pareto_dominates;
use crate::{
    FrozenProducerProposalUniverseDigestV1, FrozenProducerProposalUniverseV1,
    GovernedCaseArtifactBindingV1, GovernedProducerProposalEvaluationV1,
    GovernedRequirementRecallV1, MeasurementTrustBoundaryV1, ProducerProposalAcquisitionBindingV1,
    ProducerProposalCapViolationsV1, ProducerProposalIdentityV1,
    ProducerProposalMeasurementEnvironmentV1, ProducerProposalResourceCapV1,
    ProducerProposalResourceEnvelopeV1,
};

const PRODUCER_PROPOSAL_FRONTIER_PLAN_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/producer-proposal-frontier-plan/v1\0";
const GOVERNED_PRODUCER_PROPOSAL_FRONTIER_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-producer-proposal-frontier/v1\0";

/// Maximum preregistered configured-producer points in one V1 frontier.
pub const MAX_PRODUCER_PROPOSAL_FRONTIER_POINTS_V1: usize = 256;

/// Domain-separated identity of a label-free, preregistered frontier plan.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProducerProposalFrontierPlanDigestV1([u8; 32]);

impl ProducerProposalFrontierPlanDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProducerProposalFrontierPlanDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProducerProposalFrontierPlanDigestV1(<redacted>)")
    }
}

/// Domain-separated identity of the complete governed frontier artifact.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernedProducerProposalFrontierDigestV1([u8; 32]);

impl GovernedProducerProposalFrontierDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GovernedProducerProposalFrontierDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GovernedProducerProposalFrontierDigestV1(<redacted>)")
    }
}

/// One exact configured-producer universe and its preregistered five-axis cap.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalFrontierPlanPointV1 {
    universe_digest: FrozenProducerProposalUniverseDigestV1,
    producer: ProducerProposalIdentityV1,
    cap: ProducerProposalResourceCapV1,
}

impl ProducerProposalFrontierPlanPointV1 {
    #[must_use]
    pub const fn universe_digest(self) -> FrozenProducerProposalUniverseDigestV1 {
        self.universe_digest
    }

    #[must_use]
    pub const fn producer(self) -> ProducerProposalIdentityV1 {
        self.producer
    }

    #[must_use]
    pub const fn cap(self) -> ProducerProposalResourceCapV1 {
        self.cap
    }
}

impl fmt::Debug for ProducerProposalFrontierPlanPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalFrontierPlanPointV1")
            .field("universe_identity_present", &true)
            .field("producer_identity_present", &true)
            .field("cap", &self.cap)
            .finish()
    }
}

/// Immutable label-free configured-producer frontier plan.
///
/// Construction accepts only already-frozen public proposal universes and no
/// annotation, requirement, recall, or outcome. All points must share the same
/// public case, exact acquisition, method artifact, and closed measurement
/// environment. Config and producer-receipt artifacts remain exact per point
/// and are never treated as equal merely because the method artifact matches.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenProducerProposalFrontierPlanV1 {
    digest: ProducerProposalFrontierPlanDigestV1,
    public_case_artifact_digest: ArtifactDigest,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    method_artifact_digest: ArtifactDigest,
    measurement_environment: ProducerProposalMeasurementEnvironmentV1,
    points: Vec<ProducerProposalFrontierPlanPointV1>,
}

impl FrozenProducerProposalFrontierPlanV1 {
    pub fn try_new<'universe, Points>(
        measurement_environment: ProducerProposalMeasurementEnvironmentV1,
        requested_points: Points,
    ) -> Result<Self, ProducerProposalFrontierErrorV1>
    where
        Points: IntoIterator<
            Item = (
                &'universe FrozenProducerProposalUniverseV1,
                ProducerProposalResourceCapV1,
            ),
        >,
    {
        let mut public_case_artifact_digest = None;
        let mut acquisition_binding = None;
        let mut method_artifact_digest = None;
        let mut points = Vec::new();
        for (universe, cap) in requested_points {
            if points.len() >= MAX_PRODUCER_PROPOSAL_FRONTIER_POINTS_V1 {
                return Err(ProducerProposalFrontierErrorV1::TooManyRequestedPoints);
            }
            match public_case_artifact_digest {
                None => public_case_artifact_digest = Some(universe.public_case_artifact_digest()),
                Some(expected) if expected != universe.public_case_artifact_digest() => {
                    return Err(ProducerProposalFrontierErrorV1::PublicCaseBindingMismatch);
                }
                Some(_) => {}
            }
            match acquisition_binding {
                None => acquisition_binding = Some(universe.acquisition_binding()),
                Some(expected) if expected != universe.acquisition_binding() => {
                    return Err(ProducerProposalFrontierErrorV1::AcquisitionBindingMismatch);
                }
                Some(_) => {}
            }
            match method_artifact_digest {
                None => method_artifact_digest = Some(universe.producer().method_artifact_digest()),
                Some(expected) if expected != universe.producer().method_artifact_digest() => {
                    return Err(ProducerProposalFrontierErrorV1::MethodArtifactMismatch);
                }
                Some(_) => {}
            }
            points.push(ProducerProposalFrontierPlanPointV1 {
                universe_digest: universe.digest(),
                producer: universe.producer(),
                cap,
            });
        }
        if points.is_empty() {
            return Err(ProducerProposalFrontierErrorV1::EmptyRequestedPoints);
        }
        points.sort_unstable_by_key(|point| plan_point_key(*point));
        if points
            .windows(2)
            .any(|pair| plan_point_key(pair[0]) == plan_point_key(pair[1]))
        {
            return Err(ProducerProposalFrontierErrorV1::DuplicateUniverseCapPoint);
        }
        let public_case_artifact_digest = public_case_artifact_digest
            .ok_or(ProducerProposalFrontierErrorV1::CollectionLengthOverflow)?;
        let acquisition_binding =
            acquisition_binding.ok_or(ProducerProposalFrontierErrorV1::CollectionLengthOverflow)?;
        let method_artifact_digest = method_artifact_digest
            .ok_or(ProducerProposalFrontierErrorV1::CollectionLengthOverflow)?;
        let digest = derive_plan_digest(
            public_case_artifact_digest,
            acquisition_binding,
            method_artifact_digest,
            measurement_environment,
            &points,
        )?;
        Ok(Self {
            digest,
            public_case_artifact_digest,
            acquisition_binding,
            method_artifact_digest,
            measurement_environment,
            points,
        })
    }

    #[must_use]
    pub const fn digest(&self) -> ProducerProposalFrontierPlanDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
    }

    #[must_use]
    pub const fn method_artifact_digest(&self) -> ArtifactDigest {
        self.method_artifact_digest
    }

    #[must_use]
    pub const fn measurement_environment(&self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.measurement_environment
    }

    #[must_use]
    pub fn points(&self) -> &[ProducerProposalFrontierPlanPointV1] {
        &self.points
    }

    /// The plan contains no hidden annotation or outcome input.
    #[must_use]
    pub const fn freeze_boundary_code(&self) -> &'static str {
        "public_universes_and_caps_frozen_before_hidden_annotations"
    }
}

impl fmt::Debug for FrozenProducerProposalFrontierPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenProducerProposalFrontierPlanV1")
            .field("public_case_binding_present", &true)
            .field("acquisition_binding", &self.acquisition_binding)
            .field("method_artifact_present", &true)
            .field("measurement_environment", &self.measurement_environment)
            .field("requested_point_count", &self.points.len())
            .field("freeze_boundary", &self.freeze_boundary_code())
            .finish()
    }
}

/// One governed outcome at an exactly preregistered universe/cap point.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedProducerProposalFrontierPointV1 {
    planned: ProducerProposalFrontierPlanPointV1,
    measurement_receipt_digest: ArtifactDigest,
    measurement_trust_boundary: MeasurementTrustBoundaryV1,
    resources: ProducerProposalResourceEnvelopeV1,
    cap_violations: Option<ProducerProposalCapViolationsV1>,
    recall: GovernedRequirementRecallV1,
}

impl GovernedProducerProposalFrontierPointV1 {
    #[must_use]
    pub const fn planned(&self) -> ProducerProposalFrontierPlanPointV1 {
        self.planned
    }

    #[must_use]
    pub const fn measurement_receipt_digest(&self) -> ArtifactDigest {
        self.measurement_receipt_digest
    }

    #[must_use]
    pub const fn measurement_trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        self.measurement_trust_boundary
    }

    #[must_use]
    pub const fn resources(&self) -> ProducerProposalResourceEnvelopeV1 {
        self.resources
    }

    #[must_use]
    pub fn cap_violations(&self) -> Option<&ProducerProposalCapViolationsV1> {
        self.cap_violations.as_ref()
    }

    #[must_use]
    pub const fn recall(&self) -> GovernedRequirementRecallV1 {
        self.recall
    }
}

impl fmt::Debug for GovernedProducerProposalFrontierPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedProducerProposalFrontierPointV1")
            .field("planned", &self.planned)
            .field("measurement_binding_present", &true)
            .field(
                "measurement_trust_boundary",
                &self.measurement_trust_boundary,
            )
            .field("resources", &self.resources)
            .field("cap_violations", &self.cap_violations)
            .field("recall", &self.recall)
            .finish()
    }
}

/// Governed exact Pareto frontier over a preregistered configured-producer plan.
///
/// Every planned point and cap violation is retained. `frontier_points` are the
/// exact non-dominated subset of cap-eligible points under weighted requirement
/// recall (higher is better) and the five Protocol K resource axes (lower is
/// better). Ineligible points remain in `points` with every violation, but can
/// never enter `frontier_points`. No scalar, AUC, rank, or winner is computed.
/// V1 resource observations remain self-asserted reproducibility inputs.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedProducerProposalFrontierV1 {
    digest: GovernedProducerProposalFrontierDigestV1,
    plan_digest: ProducerProposalFrontierPlanDigestV1,
    artifact_binding: GovernedCaseArtifactBindingV1,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    method_artifact_digest: ArtifactDigest,
    measurement_environment: ProducerProposalMeasurementEnvironmentV1,
    points: Vec<GovernedProducerProposalFrontierPointV1>,
    frontier_indices: Vec<usize>,
}

impl GovernedProducerProposalFrontierV1 {
    #[must_use]
    pub const fn digest(&self) -> GovernedProducerProposalFrontierDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> ProducerProposalFrontierPlanDigestV1 {
        self.plan_digest
    }

    #[must_use]
    pub const fn artifact_binding(&self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
    }

    #[must_use]
    pub const fn method_artifact_digest(&self) -> ArtifactDigest {
        self.method_artifact_digest
    }

    #[must_use]
    pub const fn measurement_environment(&self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.measurement_environment
    }

    #[must_use]
    pub fn points(&self) -> &[GovernedProducerProposalFrontierPointV1] {
        &self.points
    }

    #[must_use]
    pub fn frontier_points(
        &self,
    ) -> impl ExactSizeIterator<Item = &GovernedProducerProposalFrontierPointV1> {
        self.frontier_indices
            .iter()
            .map(|index| &self.points[*index])
    }

    pub fn eligible_points(
        &self,
    ) -> impl Iterator<Item = &GovernedProducerProposalFrontierPointV1> {
        self.points
            .iter()
            .filter(|point| point.cap_violations.is_none())
    }

    pub fn ineligible_points(
        &self,
    ) -> impl Iterator<Item = &GovernedProducerProposalFrontierPointV1> {
        self.points
            .iter()
            .filter(|point| point.cap_violations.is_some())
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

impl fmt::Debug for GovernedProducerProposalFrontierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedProducerProposalFrontierV1")
            .field("plan_binding_present", &true)
            .field("artifact_binding", &self.artifact_binding)
            .field("acquisition_binding", &self.acquisition_binding)
            .field("method_artifact_present", &true)
            .field("measurement_environment", &self.measurement_environment)
            .field("point_count", &self.points.len())
            .field("eligible_point_count", &self.eligible_points().count())
            .field("ineligible_point_count", &self.ineligible_points().count())
            .field("frontier_point_count", &self.frontier_indices.len())
            .field("contains_scalar_score", &false)
            .field("contains_auc", &false)
            .field("contains_verified_winner", &false)
            .finish()
    }
}

/// Join exactly one governed outcome to every preregistered public point.
pub fn evaluate_governed_producer_proposal_frontier_v1<Outcomes>(
    plan: &FrozenProducerProposalFrontierPlanV1,
    outcomes: Outcomes,
) -> Result<GovernedProducerProposalFrontierV1, ProducerProposalFrontierErrorV1>
where
    Outcomes: IntoIterator<Item = GovernedProducerProposalEvaluationV1>,
{
    let planned = plan
        .points
        .iter()
        .copied()
        .map(|point| (plan_point_key(point), point))
        .collect::<BTreeMap<_, _>>();
    let mut artifact_binding = None;
    let mut recall_universe = None;
    let mut received = BTreeMap::new();
    for outcome in outcomes {
        if outcome.artifact_binding().public_case_artifact_digest()
            != plan.public_case_artifact_digest
        {
            return Err(ProducerProposalFrontierErrorV1::PublicCaseBindingMismatch);
        }
        match artifact_binding {
            None => artifact_binding = Some(outcome.artifact_binding()),
            Some(expected) if expected != outcome.artifact_binding() => {
                return Err(ProducerProposalFrontierErrorV1::AnnotationBindingMismatch);
            }
            Some(_) => {}
        }
        if outcome.acquisition_binding() != plan.acquisition_binding {
            return Err(ProducerProposalFrontierErrorV1::AcquisitionBindingMismatch);
        }
        if outcome.measurement_environment() != plan.measurement_environment {
            return Err(ProducerProposalFrontierErrorV1::MeasurementEnvironmentMismatch);
        }
        if outcome.producer().method_artifact_digest() != plan.method_artifact_digest {
            return Err(ProducerProposalFrontierErrorV1::MethodArtifactMismatch);
        }
        let key = outcome_key(&outcome);
        let planned_point = planned
            .get(&key)
            .copied()
            .ok_or(ProducerProposalFrontierErrorV1::UnplannedOutcomePoint)?;
        if outcome.producer() != planned_point.producer {
            return Err(ProducerProposalFrontierErrorV1::ProducerIdentityMismatch);
        }
        if received.contains_key(&key) {
            return Err(ProducerProposalFrontierErrorV1::DuplicateOutcomePoint);
        }
        let current_recall_universe = (
            outcome.recall().requirement_count(),
            outcome.recall().total_weight_micros(),
        );
        match recall_universe {
            None => recall_universe = Some(current_recall_universe),
            Some(expected) if expected != current_recall_universe => {
                return Err(ProducerProposalFrontierErrorV1::RecallUniverseMismatch);
            }
            Some(_) => {}
        }
        let expected_violations = planned_point.cap.check(outcome.resources()).err();
        if expected_violations.as_ref() != outcome.cap_violations() {
            return Err(ProducerProposalFrontierErrorV1::CapViolationMismatch);
        }
        let point = GovernedProducerProposalFrontierPointV1 {
            planned: planned_point,
            measurement_receipt_digest: outcome.measurement_receipt_digest(),
            measurement_trust_boundary: outcome.measurement_trust_boundary(),
            resources: outcome.resources(),
            cap_violations: outcome.cap_violations().cloned(),
            recall: outcome.recall(),
        };
        received.insert(key, point);
    }
    if received.len() != planned.len() {
        return Err(ProducerProposalFrontierErrorV1::MissingOutcomePoints {
            count: planned.len().saturating_sub(received.len()),
        });
    }
    let artifact_binding =
        artifact_binding.ok_or(ProducerProposalFrontierErrorV1::MissingOutcomePoints {
            count: planned.len(),
        })?;
    let mut points = Vec::with_capacity(plan.points.len());
    for planned_point in &plan.points {
        let point = received
            .remove(&plan_point_key(*planned_point))
            .ok_or(ProducerProposalFrontierErrorV1::MissingOutcomePoints { count: 1 })?;
        points.push(point);
    }
    let frontier_indices = non_dominated_indices(&points);
    let digest = derive_frontier_digest(plan.digest, artifact_binding, &points, &frontier_indices)?;
    Ok(GovernedProducerProposalFrontierV1 {
        digest,
        plan_digest: plan.digest,
        artifact_binding,
        acquisition_binding: plan.acquisition_binding,
        method_artifact_digest: plan.method_artifact_digest,
        measurement_environment: plan.measurement_environment,
        points,
        frontier_indices,
    })
}

/// Contentless plan, join, and frontier construction failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalFrontierErrorV1 {
    EmptyRequestedPoints,
    TooManyRequestedPoints,
    DuplicateUniverseCapPoint,
    PublicCaseBindingMismatch,
    AnnotationBindingMismatch,
    AcquisitionBindingMismatch,
    MethodArtifactMismatch,
    MeasurementEnvironmentMismatch,
    ProducerIdentityMismatch,
    RecallUniverseMismatch,
    CapViolationMismatch,
    DuplicateOutcomePoint,
    UnplannedOutcomePoint,
    MissingOutcomePoints { count: usize },
    CollectionLengthOverflow,
}

impl ProducerProposalFrontierErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyRequestedPoints => "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_EMPTY_REQUESTED_POINTS",
            Self::TooManyRequestedPoints => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_TOO_MANY_REQUESTED_POINTS"
            }
            Self::DuplicateUniverseCapPoint => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_DUPLICATE_UNIVERSE_CAP_POINT"
            }
            Self::PublicCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_PUBLIC_CASE_BINDING_MISMATCH"
            }
            Self::AnnotationBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_ANNOTATION_BINDING_MISMATCH"
            }
            Self::AcquisitionBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_ACQUISITION_BINDING_MISMATCH"
            }
            Self::MethodArtifactMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_METHOD_ARTIFACT_MISMATCH"
            }
            Self::MeasurementEnvironmentMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_MEASUREMENT_ENVIRONMENT_MISMATCH"
            }
            Self::ProducerIdentityMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_PRODUCER_IDENTITY_MISMATCH"
            }
            Self::RecallUniverseMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_RECALL_UNIVERSE_MISMATCH"
            }
            Self::CapViolationMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_CAP_VIOLATION_MISMATCH",
            Self::DuplicateOutcomePoint => "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_DUPLICATE_OUTCOME_POINT",
            Self::UnplannedOutcomePoint => "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_UNPLANNED_OUTCOME_POINT",
            Self::MissingOutcomePoints { .. } => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_MISSING_OUTCOME_POINTS"
            }
            Self::CollectionLengthOverflow => {
                "EVIDENTRAIL_BENCH_PROPOSAL_FRONTIER_COLLECTION_LENGTH_OVERFLOW"
            }
        }
    }
}

impl fmt::Debug for ProducerProposalFrontierErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ProducerProposalFrontierErrorV1");
        debug.field("code", &self.code());
        if let Self::MissingOutcomePoints { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for ProducerProposalFrontierErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProducerProposalFrontierErrorV1 {}

type FrontierPointKey = ([u64; 5], [u8; 32]);

fn plan_point_key(point: ProducerProposalFrontierPlanPointV1) -> FrontierPointKey {
    (cap_axes(point.cap), *point.universe_digest.as_bytes())
}

fn outcome_key(outcome: &GovernedProducerProposalEvaluationV1) -> FrontierPointKey {
    (
        cap_axes(outcome.resource_cap()),
        *outcome.universe_digest().as_bytes(),
    )
}

const fn cap_axes(cap: ProducerProposalResourceCapV1) -> [u64; 5] {
    [
        cap.proposal_packet_count(),
        cap.unique_member_source_bytes(),
        cap.canonical_proposal_render_tokens(),
        cap.wall_time_nanos(),
        cap.peak_rss_bytes(),
    ]
}

const fn resource_axes(resources: ProducerProposalResourceEnvelopeV1) -> [u64; 5] {
    [
        resources.proposal_packet_count(),
        resources.unique_member_source_bytes(),
        resources.canonical_proposal_render_tokens(),
        resources.wall_time_nanos(),
        resources.peak_rss_bytes(),
    ]
}

fn non_dominated_indices(points: &[GovernedProducerProposalFrontierPointV1]) -> Vec<usize> {
    (0..points.len())
        .filter(|candidate| {
            points[*candidate].cap_violations.is_none()
                && !(0..points.len()).any(|challenger| {
                    challenger != *candidate
                        && points[challenger].cap_violations.is_none()
                        && dominates(&points[challenger], &points[*candidate])
                })
        })
        .collect()
}

fn dominates(
    left: &GovernedProducerProposalFrontierPointV1,
    right: &GovernedProducerProposalFrontierPointV1,
) -> bool {
    let quality_no_worse =
        left.recall.satisfied_weight_micros() >= right.recall.satisfied_weight_micros();
    let quality_strict =
        left.recall.satisfied_weight_micros() > right.recall.satisfied_weight_micros();
    let left_costs = resource_axes(left.resources);
    let right_costs = resource_axes(right.resources);
    let cost_strict = lower_is_better_pareto_dominates(left_costs, right_costs);
    let cost_no_worse = cost_strict || left_costs == right_costs;
    quality_no_worse && cost_no_worse && (quality_strict || cost_strict)
}

fn derive_plan_digest(
    public_case_artifact_digest: ArtifactDigest,
    acquisition: ProducerProposalAcquisitionBindingV1,
    method_artifact_digest: ArtifactDigest,
    environment: ProducerProposalMeasurementEnvironmentV1,
    points: &[ProducerProposalFrontierPlanPointV1],
) -> Result<ProducerProposalFrontierPlanDigestV1, ProducerProposalFrontierErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PRODUCER_PROPOSAL_FRONTIER_PLAN_DOMAIN_V1)?;
    update_field(&mut hasher, public_case_artifact_digest.as_bytes())?;
    update_acquisition(&mut hasher, acquisition)?;
    update_field(&mut hasher, method_artifact_digest.as_bytes())?;
    update_environment(&mut hasher, environment)?;
    update_u64(&mut hasher, checked_u64(points.len())?)?;
    for point in points {
        update_field(&mut hasher, point.universe_digest.as_bytes())?;
        update_producer(&mut hasher, point.producer)?;
        update_axes(&mut hasher, cap_axes(point.cap))?;
    }
    Ok(ProducerProposalFrontierPlanDigestV1(
        hasher.finalize().into(),
    ))
}

fn derive_frontier_digest(
    plan_digest: ProducerProposalFrontierPlanDigestV1,
    artifact_binding: GovernedCaseArtifactBindingV1,
    points: &[GovernedProducerProposalFrontierPointV1],
    frontier_indices: &[usize],
) -> Result<GovernedProducerProposalFrontierDigestV1, ProducerProposalFrontierErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_PRODUCER_PROPOSAL_FRONTIER_DOMAIN_V1)?;
    update_field(&mut hasher, plan_digest.as_bytes())?;
    update_field(
        &mut hasher,
        artifact_binding.public_case_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        artifact_binding.annotation_artifact_digest().as_bytes(),
    )?;
    update_u64(&mut hasher, checked_u64(points.len())?)?;
    let frontier = frontier_indices.iter().copied().collect::<BTreeSet<_>>();
    for (index, point) in points.iter().enumerate() {
        update_field(&mut hasher, point.planned.universe_digest.as_bytes())?;
        update_producer(&mut hasher, point.planned.producer)?;
        update_axes(&mut hasher, cap_axes(point.planned.cap))?;
        update_field(&mut hasher, point.measurement_receipt_digest.as_bytes())?;
        update_field(
            &mut hasher,
            point.measurement_trust_boundary.code().as_bytes(),
        )?;
        update_u64(&mut hasher, point.resources.unique_member_event_count())?;
        update_axes(&mut hasher, resource_axes(point.resources))?;
        match &point.cap_violations {
            None => update_u64(&mut hasher, 0)?,
            Some(violations) => {
                update_u64(&mut hasher, checked_u64(violations.len())?)?;
                for dimension in violations.dimensions() {
                    update_field(&mut hasher, dimension.code().as_bytes())?;
                }
            }
        }
        update_u64(&mut hasher, point.recall.requirement_count())?;
        update_u64(&mut hasher, point.recall.satisfied_requirement_count())?;
        update_u64(&mut hasher, point.recall.total_weight_micros())?;
        update_u64(&mut hasher, point.recall.satisfied_weight_micros())?;
        update_u64(&mut hasher, u64::from(frontier.contains(&index)))?;
    }
    Ok(GovernedProducerProposalFrontierDigestV1(
        hasher.finalize().into(),
    ))
}

fn update_acquisition(
    hasher: &mut Sha256,
    acquisition: ProducerProposalAcquisitionBindingV1,
) -> Result<(), ProducerProposalFrontierErrorV1> {
    update_field(hasher, acquisition.retrieval_id().as_bytes())?;
    update_field(hasher, acquisition.plan_id().as_bytes())?;
    update_field(hasher, acquisition.plan_digest().as_bytes())?;
    update_field(hasher, acquisition.acquisition_receipt_id().as_bytes())?;
    update_field(hasher, acquisition.source_identity_digest().as_bytes())?;
    update_field(hasher, acquisition.acquisition_class().code().as_bytes())
}

fn update_environment(
    hasher: &mut Sha256,
    environment: ProducerProposalMeasurementEnvironmentV1,
) -> Result<(), ProducerProposalFrontierErrorV1> {
    update_u64(hasher, environment.contract_version())?;
    update_field(hasher, environment.renderer().artifact_digest().as_bytes())?;
    update_u64(hasher, environment.renderer().contract_version())?;
    update_field(hasher, environment.tokenizer_artifact_digest().as_bytes())?;
    update_u64(hasher, environment.tokenizer_contract_version())?;
    update_field(
        hasher,
        environment.measurement_harness_artifact_digest().as_bytes(),
    )?;
    update_u64(hasher, environment.measurement_harness_contract_version())
}

fn update_producer(
    hasher: &mut Sha256,
    producer: ProducerProposalIdentityV1,
) -> Result<(), ProducerProposalFrontierErrorV1> {
    update_field(hasher, producer.method_artifact_digest().as_bytes())?;
    update_field(hasher, producer.config_artifact_digest().as_bytes())?;
    update_field(
        hasher,
        producer.producer_receipt_artifact_digest().as_bytes(),
    )
}

fn update_axes(hasher: &mut Sha256, axes: [u64; 5]) -> Result<(), ProducerProposalFrontierErrorV1> {
    for value in axes {
        update_u64(hasher, value)?;
    }
    Ok(())
}

fn checked_u64(value: usize) -> Result<u64, ProducerProposalFrontierErrorV1> {
    u64::try_from(value).map_err(|_| ProducerProposalFrontierErrorV1::CollectionLengthOverflow)
}

fn update_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), ProducerProposalFrontierErrorV1> {
    hasher.update(checked_u64(value.len())?.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) -> Result<(), ProducerProposalFrontierErrorV1> {
    update_field(hasher, &value.to_le_bytes())
}
