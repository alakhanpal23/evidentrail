use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;

use crate::{
    CandidateResourceCap, CandidateResourceDimension, CandidateResourceEnvelope,
    CandidateResourceError,
};

/// One required identity field in a benchmark run.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BenchmarkRunIdentityDimensionV1 {
    System,
    Build,
    Dataset,
    Seed,
    Budget,
}

impl BenchmarkRunIdentityDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Build => "build",
            Self::Dataset => "dataset",
            Self::Seed => "seed",
            Self::Budget => "budget",
        }
    }
}

impl fmt::Debug for BenchmarkRunIdentityDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BenchmarkRunIdentityDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// A complete, explicit five-dimensional candidate-evaluation budget.
///
/// `None` means a dimension was absent in the materialized manifest and is
/// rejected. An explicit zero remains distinct from absence. Values are kept
/// within the exact-integer range shared by JSON benchmark artifacts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkBudgetV1 {
    cap: CandidateResourceCap,
}

impl BenchmarkBudgetV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        unique_candidate_event_count: Option<u64>,
        unique_candidate_source_bytes: Option<u64>,
        canonical_candidate_tokens: Option<u64>,
        wall_time_nanos: Option<u64>,
        peak_memory_bytes: Option<u64>,
    ) -> Result<Self, RunManifestError> {
        let unique_candidate_event_count = required_budget_dimension(
            unique_candidate_event_count,
            CandidateResourceDimension::UniqueCandidateEventCount,
        )?;
        let unique_candidate_source_bytes = required_budget_dimension(
            unique_candidate_source_bytes,
            CandidateResourceDimension::UniqueCandidateSourceBytes,
        )?;
        let canonical_candidate_tokens = required_budget_dimension(
            canonical_candidate_tokens,
            CandidateResourceDimension::CanonicalCandidateTokens,
        )?;
        let wall_time_nanos =
            required_budget_dimension(wall_time_nanos, CandidateResourceDimension::WallTimeNanos)?;
        let peak_memory_bytes = required_budget_dimension(
            peak_memory_bytes,
            CandidateResourceDimension::PeakMemoryBytes,
        )?;

        let cap = CandidateResourceCap::try_new(
            unique_candidate_event_count,
            unique_candidate_source_bytes,
            canonical_candidate_tokens,
            wall_time_nanos,
            peak_memory_bytes,
        )
        .map_err(map_budget_construction_error)?;
        Ok(Self { cap })
    }

    #[must_use]
    pub const fn cap(self) -> CandidateResourceCap {
        self.cap
    }

    #[must_use]
    pub const fn unique_candidate_event_count(self) -> u64 {
        self.cap.unique_candidate_event_count()
    }

    #[must_use]
    pub const fn unique_candidate_source_bytes(self) -> u64 {
        self.cap.unique_candidate_source_bytes()
    }

    #[must_use]
    pub const fn canonical_candidate_tokens(self) -> u64 {
        self.cap.canonical_candidate_tokens()
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.cap.wall_time_nanos()
    }

    #[must_use]
    pub const fn peak_memory_bytes(self) -> u64 {
        self.cap.peak_memory_bytes()
    }
}

impl fmt::Debug for BenchmarkBudgetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BenchmarkBudgetV1")
            .field("all_dimensions_present", &true)
            .finish()
    }
}

/// Immutable identity of one system build at one dataset, seed, and budget.
///
/// System and build are opaque artifacts. This admits subprocesses, containers,
/// or observed services without linking any competitor implementation into the
/// benchmark crate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkRunIdentityV1 {
    system_artifact_digest: ArtifactDigest,
    build_artifact_digest: ArtifactDigest,
    dataset_artifact_digest: ArtifactDigest,
    seed: u64,
    budget: BenchmarkBudgetV1,
}

impl BenchmarkRunIdentityV1 {
    pub fn try_new(
        system_artifact_digest: Option<ArtifactDigest>,
        build_artifact_digest: Option<ArtifactDigest>,
        dataset_artifact_digest: Option<ArtifactDigest>,
        seed: Option<u64>,
        budget: Option<BenchmarkBudgetV1>,
    ) -> Result<Self, RunManifestError> {
        let system_artifact_digest =
            system_artifact_digest.ok_or(RunManifestError::MissingRunIdentityDimension {
                dimension: BenchmarkRunIdentityDimensionV1::System,
            })?;
        let build_artifact_digest =
            build_artifact_digest.ok_or(RunManifestError::MissingRunIdentityDimension {
                dimension: BenchmarkRunIdentityDimensionV1::Build,
            })?;
        let dataset_artifact_digest =
            dataset_artifact_digest.ok_or(RunManifestError::MissingRunIdentityDimension {
                dimension: BenchmarkRunIdentityDimensionV1::Dataset,
            })?;
        let seed = seed.ok_or(RunManifestError::MissingRunIdentityDimension {
            dimension: BenchmarkRunIdentityDimensionV1::Seed,
        })?;
        if seed > JSON_SAFE_INTEGER_MAX {
            return Err(RunManifestError::SeedExceedsJsonSafeInteger);
        }
        let budget = budget.ok_or(RunManifestError::MissingRunIdentityDimension {
            dimension: BenchmarkRunIdentityDimensionV1::Budget,
        })?;

        Ok(Self {
            system_artifact_digest,
            build_artifact_digest,
            dataset_artifact_digest,
            seed,
            budget,
        })
    }

    #[must_use]
    pub const fn system_artifact_digest(self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn build_artifact_digest(self) -> ArtifactDigest {
        self.build_artifact_digest
    }

    #[must_use]
    pub const fn dataset_artifact_digest(self) -> ArtifactDigest {
        self.dataset_artifact_digest
    }

    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    #[must_use]
    pub const fn budget(self) -> BenchmarkBudgetV1 {
        self.budget
    }
}

impl fmt::Debug for BenchmarkRunIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BenchmarkRunIdentityV1")
            .field("system_identity_present", &true)
            .field("build_identity_present", &true)
            .field("dataset_identity_present", &true)
            .field("seed_present", &true)
            .field("budget", &self.budget)
            .finish()
    }
}

/// Public, label-free run manifest.
///
/// Its case artifacts, execution identity, and budget may be shared with an
/// external system. Hidden annotations, adjudication, and scores have no field
/// in this type.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidentrailBenchRunManifestV1 {
    identity: BenchmarkRunIdentityV1,
    public_case_artifact_digests: Vec<ArtifactDigest>,
}

impl EvidentrailBenchRunManifestV1 {
    pub fn new<Cases>(
        identity: BenchmarkRunIdentityV1,
        public_case_artifact_digests: Cases,
    ) -> Result<Self, RunManifestError>
    where
        Cases: IntoIterator<Item = ArtifactDigest>,
    {
        let public_case_artifact_digests = public_case_artifact_digests
            .into_iter()
            .collect::<BTreeSet<_>>();
        if public_case_artifact_digests.is_empty() {
            return Err(RunManifestError::EmptyPublicCaseArtifacts);
        }
        validate_json_safe_len(public_case_artifact_digests.len())?;

        Ok(Self {
            identity,
            public_case_artifact_digests: public_case_artifact_digests.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn identity(&self) -> BenchmarkRunIdentityV1 {
        self.identity
    }

    #[must_use]
    pub fn public_case_artifact_digests(&self) -> &[ArtifactDigest] {
        &self.public_case_artifact_digests
    }

    /// Verify that two runs form a matched paired comparison.
    ///
    /// System and build are intentionally allowed to differ. Dataset, case
    /// cohort, seed, and every budget dimension must match. Crossed budget
    /// vectors receive a distinct typed rejection instead of being scalarized.
    pub fn ensure_paired_comparable_with(&self, other: &Self) -> Result<(), RunManifestError> {
        if self.identity.dataset_artifact_digest != other.identity.dataset_artifact_digest {
            return Err(RunManifestError::DatasetIdentityMismatch);
        }
        if self.public_case_artifact_digests != other.public_case_artifact_digests {
            return Err(RunManifestError::PublicCaseCohortMismatch);
        }
        if self.identity.seed != other.identity.seed {
            return Err(RunManifestError::SeedMismatch);
        }

        let left_budget = self.identity.budget;
        let right_budget = other.identity.budget;
        if left_budget == right_budget {
            return Ok(());
        }
        if budgets_are_incomparable(left_budget, right_budget) {
            return Err(RunManifestError::IncomparableBudgets);
        }
        Err(RunManifestError::BudgetMismatch)
    }
}

impl fmt::Debug for EvidentrailBenchRunManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidentrailBenchRunManifestV1")
            .field("identity", &self.identity)
            .field(
                "public_case_artifact_count",
                &self.public_case_artifact_digests.len(),
            )
            .finish()
    }
}

/// Governed link between one public run artifact and its hidden evaluation.
///
/// This type lives outside [`EvidentrailBenchRunManifestV1`] so a public run and an
/// external-system invocation cannot receive annotation or scoring artifacts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GovernedCaseArtifactBindingV1 {
    public_case_artifact_digest: ArtifactDigest,
    annotation_artifact_digest: ArtifactDigest,
}

impl GovernedCaseArtifactBindingV1 {
    #[must_use]
    pub const fn new(
        public_case_artifact_digest: ArtifactDigest,
        annotation_artifact_digest: ArtifactDigest,
    ) -> Self {
        Self {
            public_case_artifact_digest,
            annotation_artifact_digest,
        }
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn annotation_artifact_digest(self) -> ArtifactDigest {
        self.annotation_artifact_digest
    }
}

impl fmt::Debug for GovernedCaseArtifactBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedCaseArtifactBindingV1")
            .field("public_case_artifact_present", &true)
            .field("annotation_artifact_present", &true)
            .finish()
    }
}

/// Manifest-validated governed case/annotation join.
///
/// This token can only be obtained from
/// [`EvidentrailBenchHiddenEvaluationManifestV1::resolve_case_binding`], preventing
/// the case evaluator from accepting an unverified annotation artifact link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedCaseArtifactJoinV1 {
    public_run_manifest_artifact_digest: ArtifactDigest,
    artifact_binding: GovernedCaseArtifactBindingV1,
}

impl GovernedCaseArtifactJoinV1 {
    #[must_use]
    pub const fn public_run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }
}

impl fmt::Debug for GovernedCaseArtifactJoinV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedCaseArtifactJoinV1")
            .field("public_run_manifest_binding_present", &true)
            .field("manifest_validated_binding_present", &true)
            .finish()
    }
}

/// Governed-only, exact one-to-one case-to-annotation linkage for a public
/// benchmark run.
///
/// Bindings are canonicalized by public case artifact. Construction requires
/// exactly the public run's case cohort and rejects reuse of either a public
/// case or an annotation artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidentrailBenchHiddenEvaluationManifestV1 {
    public_run_manifest_artifact_digest: ArtifactDigest,
    annotation_set_artifact_digest: ArtifactDigest,
    scoring_spec_artifact_digest: ArtifactDigest,
    case_bindings: Vec<GovernedCaseArtifactBindingV1>,
}

impl EvidentrailBenchHiddenEvaluationManifestV1 {
    pub fn new<Bindings>(
        public_run_manifest_artifact_digest: ArtifactDigest,
        public_run_manifest: &EvidentrailBenchRunManifestV1,
        annotation_set_artifact_digest: ArtifactDigest,
        scoring_spec_artifact_digest: ArtifactDigest,
        case_bindings: Bindings,
    ) -> Result<Self, RunManifestError>
    where
        Bindings: IntoIterator<Item = GovernedCaseArtifactBindingV1>,
    {
        let mut case_bindings = case_bindings.into_iter().collect::<Vec<_>>();
        if case_bindings.is_empty() {
            return Err(RunManifestError::EmptyGovernedCaseBindings);
        }
        validate_json_safe_len(case_bindings.len())?;
        case_bindings.sort_unstable();

        for adjacent in case_bindings.windows(2) {
            if adjacent[0].public_case_artifact_digest == adjacent[1].public_case_artifact_digest {
                return Err(RunManifestError::DuplicateGovernedPublicCaseArtifact);
            }
        }
        let mut annotation_artifacts = BTreeSet::new();
        for binding in &case_bindings {
            if !annotation_artifacts.insert(binding.annotation_artifact_digest) {
                return Err(RunManifestError::DuplicateGovernedAnnotationArtifact);
            }
        }

        let expected_cases = public_run_manifest
            .public_case_artifact_digests
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let actual_cases = case_bindings
            .iter()
            .map(|binding| binding.public_case_artifact_digest)
            .collect::<BTreeSet<_>>();
        let extra_count = actual_cases.difference(&expected_cases).count();
        if extra_count != 0 {
            return Err(RunManifestError::ExtraGovernedCaseBindings { count: extra_count });
        }
        let missing_count = expected_cases.difference(&actual_cases).count();
        if missing_count != 0 {
            return Err(RunManifestError::MissingGovernedCaseBindings {
                count: missing_count,
            });
        }

        Ok(Self {
            public_run_manifest_artifact_digest,
            annotation_set_artifact_digest,
            scoring_spec_artifact_digest,
            case_bindings,
        })
    }

    #[must_use]
    pub const fn public_run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn annotation_set_artifact_digest(&self) -> ArtifactDigest {
        self.annotation_set_artifact_digest
    }

    #[must_use]
    pub const fn scoring_spec_artifact_digest(&self) -> ArtifactDigest {
        self.scoring_spec_artifact_digest
    }

    #[must_use]
    pub fn case_bindings(&self) -> &[GovernedCaseArtifactBindingV1] {
        &self.case_bindings
    }

    #[must_use]
    pub fn binding_for_public_case(
        &self,
        public_case_artifact_digest: ArtifactDigest,
    ) -> Option<GovernedCaseArtifactBindingV1> {
        self.case_bindings
            .binary_search_by_key(&public_case_artifact_digest, |binding| {
                binding.public_case_artifact_digest
            })
            .ok()
            .map(|index| self.case_bindings[index])
    }

    pub fn resolve_case_binding(
        &self,
        artifact_binding: GovernedCaseArtifactBindingV1,
    ) -> Result<GovernedCaseArtifactJoinV1, RunManifestError> {
        if self.binding_for_public_case(artifact_binding.public_case_artifact_digest())
            != Some(artifact_binding)
        {
            return Err(RunManifestError::GovernedCaseArtifactBindingMismatch);
        }
        Ok(GovernedCaseArtifactJoinV1 {
            public_run_manifest_artifact_digest: self.public_run_manifest_artifact_digest,
            artifact_binding,
        })
    }
}

impl fmt::Debug for EvidentrailBenchHiddenEvaluationManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidentrailBenchHiddenEvaluationManifestV1")
            .field("public_run_manifest_link_present", &true)
            .field("annotation_set_link_present", &true)
            .field("scoring_spec_link_present", &true)
            .field("case_binding_count", &self.case_bindings.len())
            .finish()
    }
}

/// Score-free result material returned by any pinned external system.
///
/// The envelope records raw and normalized output artifacts plus measured
/// candidate resources. It deliberately contains neither hidden annotations
/// nor a benchmark score. A governed evaluator can link a later score artifact
/// without importing, wrapping, or depending on the external implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExternalSystemResultEnvelopeV1 {
    public_run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    raw_output_artifact_digest: ArtifactDigest,
    normalized_output_artifact_digest: ArtifactDigest,
    candidate_resources: CandidateResourceEnvelope,
}

impl ExternalSystemResultEnvelopeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_run_manifest_artifact_digest: ArtifactDigest,
        run_manifest: &EvidentrailBenchRunManifestV1,
        public_case_artifact_digest: ArtifactDigest,
        raw_output_artifact_digest: ArtifactDigest,
        normalized_output_artifact_digest: ArtifactDigest,
        candidate_resources: CandidateResourceEnvelope,
    ) -> Result<Self, RunManifestError> {
        if run_manifest
            .public_case_artifact_digests
            .binary_search(&public_case_artifact_digest)
            .is_err()
        {
            return Err(RunManifestError::UnknownPublicCaseArtifact);
        }
        run_manifest
            .identity
            .budget
            .cap()
            .check(candidate_resources)
            .map_err(|_| RunManifestError::CandidateResourceCapExceeded)?;

        Ok(Self {
            public_run_manifest_artifact_digest,
            run_identity: run_manifest.identity,
            public_case_artifact_digest,
            raw_output_artifact_digest,
            normalized_output_artifact_digest,
            candidate_resources,
        })
    }

    #[must_use]
    pub const fn public_run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn raw_output_artifact_digest(self) -> ArtifactDigest {
        self.raw_output_artifact_digest
    }

    #[must_use]
    pub const fn normalized_output_artifact_digest(self) -> ArtifactDigest {
        self.normalized_output_artifact_digest
    }

    #[must_use]
    pub const fn candidate_resources(self) -> CandidateResourceEnvelope {
        self.candidate_resources
    }
}

impl fmt::Debug for ExternalSystemResultEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalSystemResultEnvelopeV1")
            .field("public_run_manifest_link_present", &true)
            .field("run_identity", &self.run_identity)
            .field("public_case_link_present", &true)
            .field("raw_output_link_present", &true)
            .field("normalized_output_link_present", &true)
            .field("candidate_resources_present", &true)
            .field("contains_score", &false)
            .finish()
    }
}

/// Contentless construction and paired-comparison failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunManifestError {
    MissingRunIdentityDimension {
        dimension: BenchmarkRunIdentityDimensionV1,
    },
    MissingBudgetDimension {
        dimension: CandidateResourceDimension,
    },
    BudgetDimensionExceedsJsonSafeInteger {
        dimension: CandidateResourceDimension,
    },
    BudgetConstructionInvariantViolation,
    SeedExceedsJsonSafeInteger,
    EmptyPublicCaseArtifacts,
    EmptyGovernedCaseBindings,
    DuplicateGovernedPublicCaseArtifact,
    DuplicateGovernedAnnotationArtifact,
    GovernedCaseArtifactBindingMismatch,
    MissingGovernedCaseBindings {
        count: usize,
    },
    ExtraGovernedCaseBindings {
        count: usize,
    },
    CollectionLengthOverflow,
    DatasetIdentityMismatch,
    PublicCaseCohortMismatch,
    SeedMismatch,
    BudgetMismatch,
    IncomparableBudgets,
    UnknownPublicCaseArtifact,
    CandidateResourceCapExceeded,
}

impl RunManifestError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingRunIdentityDimension { .. } => {
                "EVIDENTRAIL_BENCH_RUN_MISSING_IDENTITY_DIMENSION"
            }
            Self::MissingBudgetDimension { .. } => "EVIDENTRAIL_BENCH_RUN_MISSING_BUDGET_DIMENSION",
            Self::BudgetDimensionExceedsJsonSafeInteger { .. } => {
                "EVIDENTRAIL_BENCH_RUN_BUDGET_DIMENSION_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::BudgetConstructionInvariantViolation => {
                "EVIDENTRAIL_BENCH_RUN_BUDGET_CONSTRUCTION_INVARIANT_VIOLATION"
            }
            Self::SeedExceedsJsonSafeInteger => "EVIDENTRAIL_BENCH_RUN_SEED_EXCEEDS_JSON_SAFE_INTEGER",
            Self::EmptyPublicCaseArtifacts => "EVIDENTRAIL_BENCH_RUN_EMPTY_PUBLIC_CASE_ARTIFACTS",
            Self::EmptyGovernedCaseBindings => "EVIDENTRAIL_BENCH_RUN_EMPTY_GOVERNED_CASE_BINDINGS",
            Self::DuplicateGovernedPublicCaseArtifact => {
                "EVIDENTRAIL_BENCH_RUN_DUPLICATE_GOVERNED_PUBLIC_CASE_ARTIFACT"
            }
            Self::DuplicateGovernedAnnotationArtifact => {
                "EVIDENTRAIL_BENCH_RUN_DUPLICATE_GOVERNED_ANNOTATION_ARTIFACT"
            }
            Self::GovernedCaseArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_RUN_GOVERNED_CASE_ARTIFACT_BINDING_MISMATCH"
            }
            Self::MissingGovernedCaseBindings { .. } => {
                "EVIDENTRAIL_BENCH_RUN_MISSING_GOVERNED_CASE_BINDINGS"
            }
            Self::ExtraGovernedCaseBindings { .. } => {
                "EVIDENTRAIL_BENCH_RUN_EXTRA_GOVERNED_CASE_BINDINGS"
            }
            Self::CollectionLengthOverflow => "EVIDENTRAIL_BENCH_RUN_COLLECTION_LENGTH_OVERFLOW",
            Self::DatasetIdentityMismatch => "EVIDENTRAIL_BENCH_RUN_DATASET_IDENTITY_MISMATCH",
            Self::PublicCaseCohortMismatch => "EVIDENTRAIL_BENCH_RUN_PUBLIC_CASE_COHORT_MISMATCH",
            Self::SeedMismatch => "EVIDENTRAIL_BENCH_RUN_SEED_MISMATCH",
            Self::BudgetMismatch => "EVIDENTRAIL_BENCH_RUN_BUDGET_MISMATCH",
            Self::IncomparableBudgets => "EVIDENTRAIL_BENCH_RUN_INCOMPARABLE_BUDGETS",
            Self::UnknownPublicCaseArtifact => "EVIDENTRAIL_BENCH_RUN_UNKNOWN_PUBLIC_CASE_ARTIFACT",
            Self::CandidateResourceCapExceeded => "EVIDENTRAIL_BENCH_RUN_CANDIDATE_RESOURCE_CAP_EXCEEDED",
        }
    }
}

impl fmt::Debug for RunManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RunManifestError");
        debug.field("code", &self.code());
        match self {
            Self::MissingRunIdentityDimension { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            Self::MissingBudgetDimension { dimension }
            | Self::BudgetDimensionExceedsJsonSafeInteger { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            Self::MissingGovernedCaseBindings { count }
            | Self::ExtraGovernedCaseBindings { count } => {
                debug.field("count", count);
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for RunManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RunManifestError {}

fn required_budget_dimension(
    value: Option<u64>,
    dimension: CandidateResourceDimension,
) -> Result<u64, RunManifestError> {
    let value = value.ok_or(RunManifestError::MissingBudgetDimension { dimension })?;
    if value > JSON_SAFE_INTEGER_MAX {
        return Err(RunManifestError::BudgetDimensionExceedsJsonSafeInteger { dimension });
    }
    Ok(value)
}

fn map_budget_construction_error(_error: CandidateResourceError) -> RunManifestError {
    RunManifestError::BudgetConstructionInvariantViolation
}

fn validate_json_safe_len(length: usize) -> Result<(), RunManifestError> {
    let length = u64::try_from(length).map_err(|_| RunManifestError::CollectionLengthOverflow)?;
    if length > JSON_SAFE_INTEGER_MAX {
        return Err(RunManifestError::CollectionLengthOverflow);
    }
    Ok(())
}

const fn budgets_are_incomparable(left: BenchmarkBudgetV1, right: BenchmarkBudgetV1) -> bool {
    !budget_is_no_greater(left, right) && !budget_is_no_greater(right, left)
}

const fn budget_is_no_greater(left: BenchmarkBudgetV1, right: BenchmarkBudgetV1) -> bool {
    left.unique_candidate_event_count() <= right.unique_candidate_event_count()
        && left.unique_candidate_source_bytes() <= right.unique_candidate_source_bytes()
        && left.canonical_candidate_tokens() <= right.canonical_candidate_tokens()
        && left.wall_time_nanos() <= right.wall_time_nanos()
        && left.peak_memory_bytes() <= right.peak_memory_bytes()
}
