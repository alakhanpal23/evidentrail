use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    CandidateResourceEnvelope, EvidentrailBenchRunManifestV1,
    FrozenExternalRepresentationSubmissionV1, GovernedCaseArtifactBindingV1,
    GovernedRepresentationFidelityOutcomeV1, GovernedRepresentationScoreSubmissionV1,
    MethodDescriptor,
};
use evidentrail_schema::ArtifactDigest;

use crate::canonical_public_run_manifest_artifact_v1;

/// Arm label exposed by contentless matched-comparison diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MatchedRepresentationArmV1 {
    FirstParty,
    External,
}

impl MatchedRepresentationArmV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::External => "external",
        }
    }
}

impl fmt::Debug for MatchedRepresentationArmV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedRepresentationArmV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact ordering of two statically decidable representation-recall ratios.
/// This is not an overall product winner or a scalarized resource score.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StaticRepresentationRecallOrderingV1 {
    FirstPartyHigher,
    ExternalHigher,
    Equal,
}

impl StaticRepresentationRecallOrderingV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstPartyHigher => "first_party_higher",
            Self::ExternalHigher => "external_higher",
            Self::Equal => "equal",
        }
    }
}

impl fmt::Debug for StaticRepresentationRecallOrderingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticRepresentationRecallOrderingV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Trust classification retained on each matched resource vector.
///
/// V1 only accepts the self-asserted measurements carried by the frozen
/// representation submission. A later independently attested receipt must use
/// a distinct variant and contract version rather than silently upgrading this
/// classification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MatchedResourceMeasurementTrustV1 {
    SelfAssertedReproducibilityInput,
}

impl MatchedResourceMeasurementTrustV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelfAssertedReproducibilityInput => "self_asserted_reproducibility_input",
        }
    }

    #[must_use]
    pub const fn is_independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for MatchedResourceMeasurementTrustV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedResourceMeasurementTrustV1")
            .field("code", &self.code())
            .field("independently_attested", &false)
            .finish()
    }
}

/// Validated public method and complete five-dimensional resource envelope for
/// one arm of a matched representation comparison.
///
/// The envelope retains the semantics of the frozen submission. For the
/// first-party Log Brief bridge this is displayed-representation accounting,
/// not the still-missing pre-ranking proposal-union receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MatchedRepresentationArmReceiptV1 {
    method: MethodDescriptor,
    resources: CandidateResourceEnvelope,
    representation_submission_artifact_digest: ArtifactDigest,
    measurement_trust: MatchedResourceMeasurementTrustV1,
}

impl MatchedRepresentationArmReceiptV1 {
    fn from_submission(submission: &FrozenExternalRepresentationSubmissionV1) -> Self {
        Self {
            method: submission.method(),
            resources: submission.resources(),
            representation_submission_artifact_digest: submission.artifact_digest(),
            measurement_trust: MatchedResourceMeasurementTrustV1::SelfAssertedReproducibilityInput,
        }
    }

    #[must_use]
    pub const fn method(self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn resources(self) -> CandidateResourceEnvelope {
        self.resources
    }

    #[must_use]
    pub const fn representation_submission_artifact_digest(self) -> ArtifactDigest {
        self.representation_submission_artifact_digest
    }

    #[must_use]
    pub const fn measurement_trust(self) -> MatchedResourceMeasurementTrustV1 {
        self.measurement_trust
    }
}

impl fmt::Debug for MatchedRepresentationArmReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedRepresentationArmReceiptV1")
            .field("method", &self.method)
            .field("resources", &self.resources)
            .field("submission_artifact_bound", &true)
            .field("measurement_trust", &self.measurement_trust)
            .finish()
    }
}

/// Both validated arms retained on every matched comparison outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MatchedRepresentationArmsV1 {
    first_party: MatchedRepresentationArmReceiptV1,
    external: MatchedRepresentationArmReceiptV1,
}

impl MatchedRepresentationArmsV1 {
    #[must_use]
    pub const fn first_party(self) -> MatchedRepresentationArmReceiptV1 {
        self.first_party
    }

    #[must_use]
    pub const fn external(self) -> MatchedRepresentationArmReceiptV1 {
        self.external
    }
}

impl fmt::Debug for MatchedRepresentationArmsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedRepresentationArmsV1")
            .field("first_party", &self.first_party)
            .field("external", &self.external)
            .finish()
    }
}

/// Two governed static scores over the same case and annotation binding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MatchedStaticRepresentationScoresV1 {
    artifact_binding: GovernedCaseArtifactBindingV1,
    arms: MatchedRepresentationArmsV1,
    first_party: GovernedRepresentationScoreSubmissionV1,
    external: GovernedRepresentationScoreSubmissionV1,
}

impl MatchedStaticRepresentationScoresV1 {
    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn arms(self) -> MatchedRepresentationArmsV1 {
        self.arms
    }

    #[must_use]
    pub const fn first_party_score(self) -> GovernedRepresentationScoreSubmissionV1 {
        self.first_party
    }

    #[must_use]
    pub const fn external_score(self) -> GovernedRepresentationScoreSubmissionV1 {
        self.external
    }

    #[must_use]
    pub fn exact_recall_ordering(self) -> StaticRepresentationRecallOrderingV1 {
        let (first_satisfied, first_total) = self.first_party.exact_weight_ratio();
        let (external_satisfied, external_total) = self.external.exact_weight_ratio();
        let first_cross = u128::from(first_satisfied) * u128::from(external_total);
        let external_cross = u128::from(external_satisfied) * u128::from(first_total);
        match first_cross.cmp(&external_cross) {
            std::cmp::Ordering::Greater => StaticRepresentationRecallOrderingV1::FirstPartyHigher,
            std::cmp::Ordering::Less => StaticRepresentationRecallOrderingV1::ExternalHigher,
            std::cmp::Ordering::Equal => StaticRepresentationRecallOrderingV1::Equal,
        }
    }
}

impl fmt::Debug for MatchedStaticRepresentationScoresV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedStaticRepresentationScoresV1")
            .field("artifact_binding_present", &true)
            .field("arms", &self.arms)
            .field("first_party_score", &self.first_party)
            .field("external_score", &self.external)
            .field("overall_product_winner_claimed", &false)
            .finish()
    }
}

/// Typed comparison stop when either representation cannot be statically
/// judged by the closed fidelity policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MatchedRepresentationNeedsDownstreamVdsV1 {
    artifact_binding: GovernedCaseArtifactBindingV1,
    arms: MatchedRepresentationArmsV1,
    first_party_requires_vds: bool,
    external_requires_vds: bool,
}

impl MatchedRepresentationNeedsDownstreamVdsV1 {
    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn arms(self) -> MatchedRepresentationArmsV1 {
        self.arms
    }

    #[must_use]
    pub const fn first_party_requires_vds(self) -> bool {
        self.first_party_requires_vds
    }

    #[must_use]
    pub const fn external_requires_vds(self) -> bool {
        self.external_requires_vds
    }
}

impl fmt::Debug for MatchedRepresentationNeedsDownstreamVdsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedRepresentationNeedsDownstreamVdsV1")
            .field("artifact_binding_present", &true)
            .field("arms", &self.arms)
            .field("first_party_requires_vds", &self.first_party_requires_vds)
            .field("external_requires_vds", &self.external_requires_vds)
            .field("contains_scalar_score", &false)
            .finish()
    }
}

/// Governed matched-representation result. Resource vectors remain separate;
/// this type never folds quality and cost into one number.
#[derive(Clone, PartialEq, Eq)]
pub enum MatchedRepresentationComparisonV1 {
    Static(Box<MatchedStaticRepresentationScoresV1>),
    NeedsDownstreamVds(Box<MatchedRepresentationNeedsDownstreamVdsV1>),
}

impl MatchedRepresentationComparisonV1 {
    #[must_use]
    pub fn arms(&self) -> MatchedRepresentationArmsV1 {
        match self {
            Self::Static(scores) => scores.arms(),
            Self::NeedsDownstreamVds(needs_vds) => needs_vds.arms(),
        }
    }

    pub fn exact_recall_ordering(
        &self,
    ) -> Result<StaticRepresentationRecallOrderingV1, MatchedRepresentationErrorV1> {
        match self {
            Self::Static(scores) => Ok(scores.exact_recall_ordering()),
            Self::NeedsDownstreamVds(_) => Err(MatchedRepresentationErrorV1::NeedsDownstreamVds),
        }
    }
}

impl fmt::Debug for MatchedRepresentationComparisonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(scores) => formatter
                .debug_struct("MatchedRepresentationComparisonV1")
                .field("classification", &"static")
                .field("scores", scores)
                .finish(),
            Self::NeedsDownstreamVds(needs_vds) => formatter
                .debug_struct("MatchedRepresentationComparisonV1")
                .field("classification", &"needs_downstream_vds")
                .field("decision", needs_vds)
                .finish(),
        }
    }
}

/// Join two already-governed representation outcomes under matched public run
/// dimensions. Runtime and peak-memory fields must be nonzero explicit
/// observations, but remain self-asserted unless their source receipt says
/// otherwise.
#[allow(clippy::too_many_arguments)]
pub fn compare_matched_representations_v1(
    first_party_manifest: &EvidentrailBenchRunManifestV1,
    first_party_submission: &FrozenExternalRepresentationSubmissionV1,
    first_party_outcome: GovernedRepresentationFidelityOutcomeV1,
    external_manifest: &EvidentrailBenchRunManifestV1,
    external_submission: &FrozenExternalRepresentationSubmissionV1,
    external_outcome: GovernedRepresentationFidelityOutcomeV1,
) -> Result<MatchedRepresentationComparisonV1, MatchedRepresentationErrorV1> {
    first_party_manifest
        .ensure_paired_comparable_with(external_manifest)
        .map_err(|_| MatchedRepresentationErrorV1::RunsNotComparable)?;
    let first_party_run =
        canonical_public_run_manifest_artifact_v1(first_party_manifest).map_err(|_| {
            MatchedRepresentationErrorV1::RunManifestArtifactMismatch {
                arm: MatchedRepresentationArmV1::FirstParty,
            }
        })?;
    let external_run =
        canonical_public_run_manifest_artifact_v1(external_manifest).map_err(|_| {
            MatchedRepresentationErrorV1::RunManifestArtifactMismatch {
                arm: MatchedRepresentationArmV1::External,
            }
        })?;
    validate_submission(
        MatchedRepresentationArmV1::FirstParty,
        first_party_manifest,
        first_party_run.artifact_digest(),
        first_party_submission,
    )?;
    validate_submission(
        MatchedRepresentationArmV1::External,
        external_manifest,
        external_run.artifact_digest(),
        external_submission,
    )?;
    if first_party_submission.public_case_artifact_digest()
        != external_submission.public_case_artifact_digest()
    {
        return Err(MatchedRepresentationErrorV1::PublicCaseMismatch);
    }
    if first_party_submission.method() == external_submission.method() {
        return Err(MatchedRepresentationErrorV1::MethodIdentityCollision);
    }
    let arms = MatchedRepresentationArmsV1 {
        first_party: MatchedRepresentationArmReceiptV1::from_submission(first_party_submission),
        external: MatchedRepresentationArmReceiptV1::from_submission(external_submission),
    };

    let first_binding = outcome_binding(first_party_outcome);
    let external_binding = outcome_binding(external_outcome);
    if first_binding != external_binding
        || first_binding.public_case_artifact_digest()
            != first_party_submission.public_case_artifact_digest()
    {
        return Err(MatchedRepresentationErrorV1::GovernedBindingMismatch);
    }
    if outcome_submission_digest(first_party_outcome) != first_party_submission.artifact_digest() {
        return Err(MatchedRepresentationErrorV1::OutcomeSubmissionMismatch {
            arm: MatchedRepresentationArmV1::FirstParty,
        });
    }
    if outcome_submission_digest(external_outcome) != external_submission.artifact_digest() {
        return Err(MatchedRepresentationErrorV1::OutcomeSubmissionMismatch {
            arm: MatchedRepresentationArmV1::External,
        });
    }

    match (first_party_outcome, external_outcome) {
        (
            GovernedRepresentationFidelityOutcomeV1::Scored(first_party),
            GovernedRepresentationFidelityOutcomeV1::Scored(external),
        ) => {
            if first_party.requirement_count() != external.requirement_count()
                || first_party.total_weight_micros() != external.total_weight_micros()
            {
                return Err(MatchedRepresentationErrorV1::StaticScoreUniverseMismatch);
            }
            Ok(MatchedRepresentationComparisonV1::Static(Box::new(
                MatchedStaticRepresentationScoresV1 {
                    artifact_binding: first_binding,
                    arms,
                    first_party,
                    external,
                },
            )))
        }
        (first_party, external) => Ok(MatchedRepresentationComparisonV1::NeedsDownstreamVds(
            Box::new(MatchedRepresentationNeedsDownstreamVdsV1 {
                artifact_binding: first_binding,
                arms,
                first_party_requires_vds: matches!(
                    first_party,
                    GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(_)
                ),
                external_requires_vds: matches!(
                    external,
                    GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(_)
                ),
            }),
        )),
    }
}

fn validate_submission(
    arm: MatchedRepresentationArmV1,
    manifest: &EvidentrailBenchRunManifestV1,
    run_manifest_artifact_digest: evidentrail_schema::ArtifactDigest,
    submission: &FrozenExternalRepresentationSubmissionV1,
) -> Result<(), MatchedRepresentationErrorV1> {
    if submission.public_run_manifest_artifact_digest() != run_manifest_artifact_digest
        || submission.run_identity() != manifest.identity()
    {
        return Err(MatchedRepresentationErrorV1::RunManifestArtifactMismatch { arm });
    }
    if manifest
        .public_case_artifact_digests()
        .binary_search(&submission.public_case_artifact_digest())
        .is_err()
    {
        return Err(MatchedRepresentationErrorV1::PublicCaseMismatch);
    }
    let resources = submission.resources();
    if resources.wall_time_nanos() == 0 {
        return Err(MatchedRepresentationErrorV1::MissingRuntimeMeasurement {
            arm,
            dimension: MatchedRuntimeDimensionV1::WallTimeNanos,
        });
    }
    if resources.peak_memory_bytes() == 0 {
        return Err(MatchedRepresentationErrorV1::MissingRuntimeMeasurement {
            arm,
            dimension: MatchedRuntimeDimensionV1::PeakMemoryBytes,
        });
    }
    Ok(())
}

const fn outcome_binding(
    outcome: GovernedRepresentationFidelityOutcomeV1,
) -> GovernedCaseArtifactBindingV1 {
    match outcome {
        GovernedRepresentationFidelityOutcomeV1::Scored(score) => score.artifact_binding(),
        GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(needs_vds) => {
            needs_vds.artifact_binding()
        }
    }
}

const fn outcome_submission_digest(
    outcome: GovernedRepresentationFidelityOutcomeV1,
) -> evidentrail_schema::ArtifactDigest {
    match outcome {
        GovernedRepresentationFidelityOutcomeV1::Scored(score) => {
            score.representation_submission_artifact_digest()
        }
        GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(needs_vds) => {
            needs_vds.representation_submission_artifact_digest()
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MatchedRuntimeDimensionV1 {
    WallTimeNanos,
    PeakMemoryBytes,
}

impl MatchedRuntimeDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WallTimeNanos => "wall_time_nanos",
            Self::PeakMemoryBytes => "peak_memory_bytes",
        }
    }
}

impl fmt::Debug for MatchedRuntimeDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedRuntimeDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless matched-representation construction/comparison failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MatchedRepresentationErrorV1 {
    RunsNotComparable,
    RunManifestArtifactMismatch {
        arm: MatchedRepresentationArmV1,
    },
    PublicCaseMismatch,
    MethodIdentityCollision,
    GovernedBindingMismatch,
    OutcomeSubmissionMismatch {
        arm: MatchedRepresentationArmV1,
    },
    MissingRuntimeMeasurement {
        arm: MatchedRepresentationArmV1,
        dimension: MatchedRuntimeDimensionV1,
    },
    StaticScoreUniverseMismatch,
    NeedsDownstreamVds,
}

impl MatchedRepresentationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RunsNotComparable => "EVIDENTRAIL_BENCH_HARNESS_MATCHED_RUNS_NOT_COMPARABLE",
            Self::RunManifestArtifactMismatch { .. } => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_RUN_MANIFEST_ARTIFACT_MISMATCH"
            }
            Self::PublicCaseMismatch => "EVIDENTRAIL_BENCH_HARNESS_MATCHED_PUBLIC_CASE_MISMATCH",
            Self::MethodIdentityCollision => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_METHOD_IDENTITY_COLLISION"
            }
            Self::GovernedBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_GOVERNED_BINDING_MISMATCH"
            }
            Self::OutcomeSubmissionMismatch { .. } => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_OUTCOME_SUBMISSION_MISMATCH"
            }
            Self::MissingRuntimeMeasurement { .. } => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_RUNTIME_MEASUREMENT_MISSING"
            }
            Self::StaticScoreUniverseMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_MATCHED_STATIC_SCORE_UNIVERSE_MISMATCH"
            }
            Self::NeedsDownstreamVds => "EVIDENTRAIL_BENCH_HARNESS_MATCHED_NEEDS_DOWNSTREAM_VDS",
        }
    }
}

impl fmt::Debug for MatchedRepresentationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("MatchedRepresentationErrorV1");
        debug.field("code", &self.code());
        match self {
            Self::RunManifestArtifactMismatch { arm } | Self::OutcomeSubmissionMismatch { arm } => {
                debug.field("arm", &arm.code());
            }
            Self::MissingRuntimeMeasurement { arm, dimension } => {
                debug
                    .field("arm", &arm.code())
                    .field("dimension", &dimension.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for MatchedRepresentationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for MatchedRepresentationErrorV1 {}
