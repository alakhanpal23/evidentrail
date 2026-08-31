use std::error::Error as StdError;
use std::fmt;

use crate::resources::lower_is_better_pareto_dominates;
use crate::{
    GovernedProducerProposalEvaluationV1, GovernedRequirementRecallV1, MeasurementTrustBoundaryV1,
    ProducerProposalCapViolationsV1, ProducerProposalIdentityV1, ProducerProposalResourceCapV1,
    ProducerProposalResourceEnvelopeV1,
};

/// Direction of one explicit, non-scalar Pareto relation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalParetoRelationV1 {
    LeftStrictlyDominates,
    RightStrictlyDominates,
    Equal,
    Incomparable,
}

impl ProducerProposalParetoRelationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LeftStrictlyDominates => "left_strictly_dominates",
            Self::RightStrictlyDominates => "right_strictly_dominates",
            Self::Equal => "equal",
            Self::Incomparable => "incomparable",
        }
    }
}

impl fmt::Debug for ProducerProposalParetoRelationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalParetoRelationV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Side of an exactly aligned producer comparison.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalComparisonSideV1 {
    Left,
    Right,
}

impl ProducerProposalComparisonSideV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

impl fmt::Debug for ProducerProposalComparisonSideV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalComparisonSideV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact matched pair of governed producer-proposal evaluations.
///
/// Quality compares only the preregistered exact weighted-recall rational;
/// satisfied requirement count remains retained accounting. Cost compares
/// exactly the five lower-is-better Protocol K dimensions. Unique member-event
/// count remains accounting and is never promoted into a sixth cost axis. No
/// cross-dimension scalar score is constructed. Both sides must bind the same
/// closed renderer, tokenizer artifact, and measurement-harness environment.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedProducerProposalComparisonV1 {
    left: GovernedProducerProposalEvaluationV1,
    right: GovernedProducerProposalEvaluationV1,
    quality_relation: ProducerProposalParetoRelationV1,
    cost_relation: ProducerProposalParetoRelationV1,
    joint_relation: ProducerProposalParetoRelationV1,
}

impl GovernedProducerProposalComparisonV1 {
    pub fn try_new(
        left: GovernedProducerProposalEvaluationV1,
        right: GovernedProducerProposalEvaluationV1,
    ) -> Result<Self, ProducerProposalComparisonErrorV1> {
        if left.artifact_binding() != right.artifact_binding() {
            return Err(ProducerProposalComparisonErrorV1::CaseArtifactBindingMismatch);
        }
        if left.acquisition_binding() != right.acquisition_binding() {
            return Err(ProducerProposalComparisonErrorV1::AcquisitionBindingMismatch);
        }
        if left.measurement_environment() != right.measurement_environment() {
            return Err(ProducerProposalComparisonErrorV1::MeasurementEnvironmentMismatch);
        }
        if left.resource_cap() != right.resource_cap() {
            return Err(ProducerProposalComparisonErrorV1::ResourceCapMismatch);
        }
        if left.recall().requirement_count() != right.recall().requirement_count()
            || left.recall().total_weight_micros() != right.recall().total_weight_micros()
        {
            return Err(ProducerProposalComparisonErrorV1::RecallUniverseMismatch);
        }

        let quality_relation = quality_relation(left.recall(), right.recall());
        let cost_relation = cost_relation(left.resources(), right.resources());
        let joint_relation = joint_relation(quality_relation, cost_relation);
        Ok(Self {
            left,
            right,
            quality_relation,
            cost_relation,
            joint_relation,
        })
    }

    #[must_use]
    pub const fn left(&self) -> &GovernedProducerProposalEvaluationV1 {
        &self.left
    }

    #[must_use]
    pub const fn right(&self) -> &GovernedProducerProposalEvaluationV1 {
        &self.right
    }

    #[must_use]
    pub const fn resource_cap(&self) -> ProducerProposalResourceCapV1 {
        self.left.resource_cap()
    }

    #[must_use]
    pub const fn left_resources(&self) -> ProducerProposalResourceEnvelopeV1 {
        self.left.resources()
    }

    #[must_use]
    pub const fn right_resources(&self) -> ProducerProposalResourceEnvelopeV1 {
        self.right.resources()
    }

    #[must_use]
    pub const fn left_recall(&self) -> GovernedRequirementRecallV1 {
        self.left.recall()
    }

    #[must_use]
    pub const fn right_recall(&self) -> GovernedRequirementRecallV1 {
        self.right.recall()
    }

    #[must_use]
    pub fn left_cap_violations(&self) -> Option<&ProducerProposalCapViolationsV1> {
        self.left.cap_violations()
    }

    #[must_use]
    pub fn right_cap_violations(&self) -> Option<&ProducerProposalCapViolationsV1> {
        self.right.cap_violations()
    }

    #[must_use]
    pub const fn left_producer(&self) -> ProducerProposalIdentityV1 {
        self.left.producer()
    }

    #[must_use]
    pub const fn right_producer(&self) -> ProducerProposalIdentityV1 {
        self.right.producer()
    }

    #[must_use]
    pub const fn left_measurement_trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        self.left.measurement_trust_boundary()
    }

    #[must_use]
    pub const fn right_measurement_trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        self.right.measurement_trust_boundary()
    }

    #[must_use]
    pub const fn quality_relation(&self) -> ProducerProposalParetoRelationV1 {
        self.quality_relation
    }

    #[must_use]
    pub const fn cost_relation(&self) -> ProducerProposalParetoRelationV1 {
        self.cost_relation
    }

    /// Joint quality/cost Pareto relation without a winner or trust claim.
    ///
    /// A side dominates when it is no worse in both groups and strictly better
    /// in at least one. Equality in one group is valid when the other improves.
    #[must_use]
    pub const fn joint_relation(&self) -> ProducerProposalParetoRelationV1 {
        self.joint_relation
    }

    /// Both evaluations satisfy the same exact Protocol K cap.
    #[must_use]
    pub fn both_k_eligible(&self) -> bool {
        self.left.cap_violations().is_none() && self.right.cap_violations().is_none()
    }

    /// Return a joint strict Pareto winner only under verified measurements.
    ///
    /// Current V1 measurements are self-asserted reproducibility inputs, so
    /// this method fails closed. A future verified trust class must be added
    /// deliberately before this path can return a winner.
    pub fn verified_joint_pareto_winner(
        &self,
    ) -> Result<Option<ProducerProposalComparisonSideV1>, ProducerProposalComparisonErrorV1> {
        if self.left.measurement_trust_boundary()
            == MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
            || self.right.measurement_trust_boundary()
                == MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
        {
            return Err(ProducerProposalComparisonErrorV1::MeasurementTrustNotVerified);
        }
        if !self.both_k_eligible() {
            return Ok(None);
        }
        Ok(match self.joint_relation {
            ProducerProposalParetoRelationV1::LeftStrictlyDominates => {
                Some(ProducerProposalComparisonSideV1::Left)
            }
            ProducerProposalParetoRelationV1::RightStrictlyDominates => {
                Some(ProducerProposalComparisonSideV1::Right)
            }
            _ => None,
        })
    }
}

impl fmt::Debug for GovernedProducerProposalComparisonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedProducerProposalComparisonV1")
            .field("same_governed_case_binding", &true)
            .field("same_acquisition_binding", &true)
            .field("same_measurement_environment", &true)
            .field("resource_cap", &self.resource_cap())
            .field("left_resources", &self.left_resources())
            .field("right_resources", &self.right_resources())
            .field("left_recall", &self.left_recall())
            .field("right_recall", &self.right_recall())
            .field("left_cap_violations", &self.left_cap_violations())
            .field("right_cap_violations", &self.right_cap_violations())
            .field("left_producer_identity_present", &true)
            .field("right_producer_identity_present", &true)
            .field(
                "left_measurement_trust_boundary",
                &self.left_measurement_trust_boundary(),
            )
            .field(
                "right_measurement_trust_boundary",
                &self.right_measurement_trust_boundary(),
            )
            .field("quality_relation", &self.quality_relation)
            .field("cost_relation", &self.cost_relation)
            .field("joint_relation", &self.joint_relation)
            .field("contains_cross_dimension_scalar_score", &false)
            .finish()
    }
}

/// Contentless construction or verified-winner refusal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalComparisonErrorV1 {
    CaseArtifactBindingMismatch,
    AcquisitionBindingMismatch,
    MeasurementEnvironmentMismatch,
    ResourceCapMismatch,
    RecallUniverseMismatch,
    MeasurementTrustNotVerified,
}

impl ProducerProposalComparisonErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CaseArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_CASE_ARTIFACT_BINDING_MISMATCH"
            }
            Self::AcquisitionBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_ACQUISITION_BINDING_MISMATCH"
            }
            Self::MeasurementEnvironmentMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_MEASUREMENT_ENVIRONMENT_MISMATCH"
            }
            Self::ResourceCapMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_RESOURCE_CAP_MISMATCH"
            }
            Self::RecallUniverseMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_RECALL_UNIVERSE_MISMATCH"
            }
            Self::MeasurementTrustNotVerified => {
                "EVIDENTRAIL_BENCH_PROPOSAL_COMPARISON_MEASUREMENT_TRUST_NOT_VERIFIED"
            }
        }
    }
}

impl fmt::Debug for ProducerProposalComparisonErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalComparisonErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ProducerProposalComparisonErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProducerProposalComparisonErrorV1 {}

const fn quality_relation(
    left: GovernedRequirementRecallV1,
    right: GovernedRequirementRecallV1,
) -> ProducerProposalParetoRelationV1 {
    if left.satisfied_weight_micros() > right.satisfied_weight_micros() {
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    } else if right.satisfied_weight_micros() > left.satisfied_weight_micros() {
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    } else {
        ProducerProposalParetoRelationV1::Equal
    }
}

const fn cost_relation(
    left: ProducerProposalResourceEnvelopeV1,
    right: ProducerProposalResourceEnvelopeV1,
) -> ProducerProposalParetoRelationV1 {
    let left_costs = [
        left.proposal_packet_count(),
        left.unique_member_source_bytes(),
        left.canonical_proposal_render_tokens(),
        left.wall_time_nanos(),
        left.peak_rss_bytes(),
    ];
    let right_costs = [
        right.proposal_packet_count(),
        right.unique_member_source_bytes(),
        right.canonical_proposal_render_tokens(),
        right.wall_time_nanos(),
        right.peak_rss_bytes(),
    ];
    classify_relation(
        lower_is_better_pareto_dominates(left_costs, right_costs),
        lower_is_better_pareto_dominates(right_costs, left_costs),
        arrays_equal(left_costs, right_costs),
    )
}

const fn joint_relation(
    quality: ProducerProposalParetoRelationV1,
    cost: ProducerProposalParetoRelationV1,
) -> ProducerProposalParetoRelationV1 {
    let left_quality_no_worse = matches!(
        quality,
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
            | ProducerProposalParetoRelationV1::Equal
    );
    let left_cost_no_worse = matches!(
        cost,
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
            | ProducerProposalParetoRelationV1::Equal
    );
    let left_strict = matches!(
        quality,
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    ) || matches!(
        cost,
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    );
    let right_quality_no_worse = matches!(
        quality,
        ProducerProposalParetoRelationV1::RightStrictlyDominates
            | ProducerProposalParetoRelationV1::Equal
    );
    let right_cost_no_worse = matches!(
        cost,
        ProducerProposalParetoRelationV1::RightStrictlyDominates
            | ProducerProposalParetoRelationV1::Equal
    );
    let right_strict = matches!(
        quality,
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    ) || matches!(
        cost,
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    );
    classify_relation(
        left_quality_no_worse && left_cost_no_worse && left_strict,
        right_quality_no_worse && right_cost_no_worse && right_strict,
        matches!(quality, ProducerProposalParetoRelationV1::Equal)
            && matches!(cost, ProducerProposalParetoRelationV1::Equal),
    )
}

const fn classify_relation(
    left_strictly_dominates: bool,
    right_strictly_dominates: bool,
    equal: bool,
) -> ProducerProposalParetoRelationV1 {
    if left_strictly_dominates {
        ProducerProposalParetoRelationV1::LeftStrictlyDominates
    } else if right_strictly_dominates {
        ProducerProposalParetoRelationV1::RightStrictlyDominates
    } else if equal {
        ProducerProposalParetoRelationV1::Equal
    } else {
        ProducerProposalParetoRelationV1::Incomparable
    }
}

const fn arrays_equal<const DIMENSIONS: usize>(
    left: [u64; DIMENSIONS],
    right: [u64; DIMENSIONS],
) -> bool {
    let mut index = 0;
    while index < DIMENSIONS {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}
