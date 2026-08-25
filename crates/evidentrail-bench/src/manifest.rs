use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use evidentrail_schema::{ArtifactDigest, BlockId, EventId, PlanDigest, QuestionDigest};

use crate::CandidateResourceCap;

/// One exact evidence reference in a governed benchmark annotation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceTargetV1 {
    Event(EventId),
    Block(BlockId),
}

impl EvidenceTargetV1 {
    /// Stable target-kind code that does not expose the referenced identity.
    #[must_use]
    pub const fn kind_code(self) -> &'static str {
        match self {
            Self::Event(_) => "event",
            Self::Block(_) => "block",
        }
    }
}

impl fmt::Debug for EvidenceTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceTargetV1")
            .field("kind", &self.kind_code())
            .finish()
    }
}

/// One diagnostic fact with one or more jointly sufficient evidence choices.
///
/// Each alternative is a set: all targets in one alternative are required,
/// while satisfying any alternative satisfies the requirement. Construction
/// sorts and deduplicates both targets and equivalent alternatives.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WeightedDiagnosticRequirementV1 {
    weight_micros: u64,
    alternatives: Vec<Vec<EvidenceTargetV1>>,
}

impl WeightedDiagnosticRequirementV1 {
    pub fn new<A, I>(weight_micros: u64, alternatives: A) -> Result<Self, ManifestError>
    where
        A: IntoIterator<Item = I>,
        I: IntoIterator<Item = EvidenceTargetV1>,
    {
        if weight_micros == 0 || weight_micros > JSON_SAFE_INTEGER_MAX {
            return Err(ManifestError::InvalidRequirementWeightMicros);
        }

        let mut canonical = BTreeSet::new();
        let mut saw_alternative = false;
        for alternative in alternatives {
            saw_alternative = true;
            let targets = alternative.into_iter().collect::<BTreeSet<_>>();
            if targets.is_empty() {
                return Err(ManifestError::EmptyRequirementAlternative);
            }
            canonical.insert(targets.into_iter().collect::<Vec<_>>());
        }
        if !saw_alternative {
            return Err(ManifestError::EmptyRequirementAlternatives);
        }

        Ok(Self {
            weight_micros,
            alternatives: canonical.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn weight_micros(&self) -> u64 {
        self.weight_micros
    }

    #[must_use]
    pub fn alternatives(&self) -> &[Vec<EvidenceTargetV1>] {
        &self.alternatives
    }

    #[must_use]
    pub fn is_satisfied_by(&self, selected: &BTreeSet<EvidenceTargetV1>) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| alternative.iter().all(|target| selected.contains(target)))
    }
}

impl fmt::Debug for WeightedDiagnosticRequirementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unique_target_count = self
            .alternatives
            .iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        formatter
            .debug_struct("WeightedDiagnosticRequirementV1")
            .field("weight_micros", &self.weight_micros)
            .field("alternative_count", &self.alternatives.len())
            .field("unique_target_count", &unique_target_count)
            .finish()
    }
}

/// Expected top-level acquisition state for a public benchmark case.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExpectedAcquisitionClassV1 {
    Complete,
    Partial,
    Unknown,
}

impl ExpectedAcquisitionClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Debug for ExpectedAcquisitionClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpectedAcquisitionClassV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Public, label-free benchmark case metadata.
///
/// Gold evidence, evidence roles, root cause, and fix labels are deliberately
/// absent. Annotation identities and all case-to-annotation linkage live only
/// in the governed evaluation manifest outside the public/runtime case path.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidentrailBenchCaseSpecV1 {
    source_artifact_digests: Vec<ArtifactDigest>,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    split_artifact_digests: Vec<ArtifactDigest>,
    leakage_artifact_digests: Vec<ArtifactDigest>,
    budget_points: Vec<CandidateResourceCap>,
    expected_acquisition_class: ExpectedAcquisitionClassV1,
}

impl EvidentrailBenchCaseSpecV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Sources, Splits, Leakage, Budgets>(
        source_artifact_digests: Sources,
        question_digest: QuestionDigest,
        plan_digest: PlanDigest,
        split_artifact_digests: Splits,
        leakage_artifact_digests: Leakage,
        budget_points: Budgets,
        expected_acquisition_class: ExpectedAcquisitionClassV1,
    ) -> Result<Self, ManifestError>
    where
        Sources: IntoIterator<Item = ArtifactDigest>,
        Splits: IntoIterator<Item = ArtifactDigest>,
        Leakage: IntoIterator<Item = ArtifactDigest>,
        Budgets: IntoIterator<Item = CandidateResourceCap>,
    {
        let source_artifact_digests =
            canonical_artifacts(source_artifact_digests, ManifestError::EmptySourceArtifacts)?;
        let split_artifact_digests =
            canonical_artifacts(split_artifact_digests, ManifestError::EmptySplitArtifacts)?;
        let leakage_artifact_digests = canonical_artifacts(
            leakage_artifact_digests,
            ManifestError::EmptyLeakageArtifacts,
        )?;
        let budget_points = canonical_budget_points(budget_points)?;

        Ok(Self {
            source_artifact_digests,
            question_digest,
            plan_digest,
            split_artifact_digests,
            leakage_artifact_digests,
            budget_points,
            expected_acquisition_class,
        })
    }

    #[must_use]
    pub fn source_artifact_digests(&self) -> &[ArtifactDigest] {
        &self.source_artifact_digests
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
    pub fn split_artifact_digests(&self) -> &[ArtifactDigest] {
        &self.split_artifact_digests
    }

    #[must_use]
    pub fn leakage_artifact_digests(&self) -> &[ArtifactDigest] {
        &self.leakage_artifact_digests
    }

    #[must_use]
    pub fn budget_points(&self) -> &[CandidateResourceCap] {
        &self.budget_points
    }

    #[must_use]
    pub const fn expected_acquisition_class(&self) -> ExpectedAcquisitionClassV1 {
        self.expected_acquisition_class
    }
}

impl fmt::Debug for EvidentrailBenchCaseSpecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidentrailBenchCaseSpecV1")
            .field("source_artifact_count", &self.source_artifact_digests.len())
            .field("split_artifact_count", &self.split_artifact_digests.len())
            .field(
                "leakage_artifact_count",
                &self.leakage_artifact_digests.len(),
            )
            .field("budget_point_count", &self.budget_points.len())
            .field(
                "expected_acquisition_class",
                &self.expected_acquisition_class,
            )
            .finish()
    }
}

/// Governed benchmark labels linked to one immutable public case artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidentrailBenchAnnotationSpecV1 {
    public_case_artifact_digest: ArtifactDigest,
    diagnostic_requirements: Vec<WeightedDiagnosticRequirementV1>,
    precursor_targets: Option<Vec<EvidenceTargetV1>>,
    symptom_targets: Option<Vec<EvidenceTargetV1>>,
    supporting_targets: Option<Vec<EvidenceTargetV1>>,
    distractor_targets: Option<Vec<EvidenceTargetV1>>,
    unsafe_targets: Option<Vec<EvidenceTargetV1>>,
}

impl EvidentrailBenchAnnotationSpecV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Requirements>(
        public_case_artifact_digest: ArtifactDigest,
        diagnostic_requirements: Requirements,
        precursor_targets: Option<Vec<EvidenceTargetV1>>,
        symptom_targets: Option<Vec<EvidenceTargetV1>>,
        supporting_targets: Option<Vec<EvidenceTargetV1>>,
        distractor_targets: Option<Vec<EvidenceTargetV1>>,
        unsafe_targets: Option<Vec<EvidenceTargetV1>>,
    ) -> Result<Self, ManifestError>
    where
        Requirements: IntoIterator<Item = WeightedDiagnosticRequirementV1>,
    {
        let diagnostic_requirements = diagnostic_requirements.into_iter().collect::<Vec<_>>();
        if diagnostic_requirements.is_empty() {
            return Err(ManifestError::EmptyDiagnosticRequirements);
        }
        validate_json_safe_len(diagnostic_requirements.len())?;

        Ok(Self {
            public_case_artifact_digest,
            diagnostic_requirements,
            precursor_targets: canonical_optional_targets(precursor_targets)?,
            symptom_targets: canonical_optional_targets(symptom_targets)?,
            supporting_targets: canonical_optional_targets(supporting_targets)?,
            distractor_targets: canonical_optional_targets(distractor_targets)?,
            unsafe_targets: canonical_optional_targets(unsafe_targets)?,
        })
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub fn diagnostic_requirements(&self) -> &[WeightedDiagnosticRequirementV1] {
        &self.diagnostic_requirements
    }

    #[must_use]
    pub fn precursor_targets(&self) -> Option<&[EvidenceTargetV1]> {
        self.precursor_targets.as_deref()
    }

    #[must_use]
    pub fn symptom_targets(&self) -> Option<&[EvidenceTargetV1]> {
        self.symptom_targets.as_deref()
    }

    #[must_use]
    pub fn supporting_targets(&self) -> Option<&[EvidenceTargetV1]> {
        self.supporting_targets.as_deref()
    }

    #[must_use]
    pub fn distractor_targets(&self) -> Option<&[EvidenceTargetV1]> {
        self.distractor_targets.as_deref()
    }

    #[must_use]
    pub fn unsafe_targets(&self) -> Option<&[EvidenceTargetV1]> {
        self.unsafe_targets.as_deref()
    }
}

impl fmt::Debug for EvidentrailBenchAnnotationSpecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidentrailBenchAnnotationSpecV1")
            .field("public_case_artifact_present", &true)
            .field(
                "diagnostic_requirement_count",
                &self.diagnostic_requirements.len(),
            )
            .field(
                "precursor_target_count",
                &optional_len(&self.precursor_targets),
            )
            .field("symptom_target_count", &optional_len(&self.symptom_targets))
            .field(
                "supporting_target_count",
                &optional_len(&self.supporting_targets),
            )
            .field(
                "distractor_target_count",
                &optional_len(&self.distractor_targets),
            )
            .field("unsafe_target_count", &optional_len(&self.unsafe_targets))
            .finish()
    }
}

/// Contentless case/annotation construction failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    InvalidRequirementWeightMicros,
    EmptyRequirementAlternatives,
    EmptyRequirementAlternative,
    EmptySourceArtifacts,
    EmptySplitArtifacts,
    EmptyLeakageArtifacts,
    EmptyBudgetPoints,
    BudgetPointExceedsJsonSafeInteger,
    EmptyDiagnosticRequirements,
    EmptyRoleTargetSet,
    CollectionLengthOverflow,
}

impl ManifestError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequirementWeightMicros => {
                "EVIDENTRAIL_BENCH_MANIFEST_INVALID_REQUIREMENT_WEIGHT_MICROS"
            }
            Self::EmptyRequirementAlternatives => {
                "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_REQUIREMENT_ALTERNATIVES"
            }
            Self::EmptyRequirementAlternative => {
                "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_REQUIREMENT_ALTERNATIVE"
            }
            Self::EmptySourceArtifacts => "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_SOURCE_ARTIFACTS",
            Self::EmptySplitArtifacts => "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_SPLIT_ARTIFACTS",
            Self::EmptyLeakageArtifacts => "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_LEAKAGE_ARTIFACTS",
            Self::EmptyBudgetPoints => "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_BUDGET_POINTS",
            Self::BudgetPointExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_MANIFEST_BUDGET_POINT_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::EmptyDiagnosticRequirements => {
                "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_DIAGNOSTIC_REQUIREMENTS"
            }
            Self::EmptyRoleTargetSet => "EVIDENTRAIL_BENCH_MANIFEST_EMPTY_ROLE_TARGET_SET",
            Self::CollectionLengthOverflow => "EVIDENTRAIL_BENCH_MANIFEST_COLLECTION_LENGTH_OVERFLOW",
        }
    }
}

impl fmt::Debug for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ManifestError {}

fn canonical_artifacts(
    artifacts: impl IntoIterator<Item = ArtifactDigest>,
    empty_error: ManifestError,
) -> Result<Vec<ArtifactDigest>, ManifestError> {
    let artifacts = artifacts.into_iter().collect::<BTreeSet<_>>();
    if artifacts.is_empty() {
        return Err(empty_error);
    }
    validate_json_safe_len(artifacts.len())?;
    Ok(artifacts.into_iter().collect())
}

fn canonical_budget_points(
    budget_points: impl IntoIterator<Item = CandidateResourceCap>,
) -> Result<Vec<CandidateResourceCap>, ManifestError> {
    let mut budget_points = budget_points.into_iter().collect::<Vec<_>>();
    if budget_points.is_empty() {
        return Err(ManifestError::EmptyBudgetPoints);
    }
    validate_json_safe_len(budget_points.len())?;
    if budget_points.iter().any(|point| {
        budget_key(*point)
            .into_iter()
            .any(|value| value > JSON_SAFE_INTEGER_MAX)
    }) {
        return Err(ManifestError::BudgetPointExceedsJsonSafeInteger);
    }
    budget_points.sort_unstable_by_key(|point| budget_key(*point));
    budget_points.dedup_by_key(|point| budget_key(*point));
    Ok(budget_points)
}

const fn budget_key(point: CandidateResourceCap) -> [u64; 5] {
    [
        point.unique_candidate_event_count(),
        point.unique_candidate_source_bytes(),
        point.canonical_candidate_tokens(),
        point.wall_time_nanos(),
        point.peak_memory_bytes(),
    ]
}

fn canonical_optional_targets(
    targets: Option<Vec<EvidenceTargetV1>>,
) -> Result<Option<Vec<EvidenceTargetV1>>, ManifestError> {
    targets
        .map(|targets| {
            let targets = targets.into_iter().collect::<BTreeSet<_>>();
            if targets.is_empty() {
                return Err(ManifestError::EmptyRoleTargetSet);
            }
            validate_json_safe_len(targets.len())?;
            Ok(targets.into_iter().collect())
        })
        .transpose()
}

fn validate_json_safe_len(length: usize) -> Result<(), ManifestError> {
    let length = u64::try_from(length).map_err(|_| ManifestError::CollectionLengthOverflow)?;
    if length > JSON_SAFE_INTEGER_MAX {
        return Err(ManifestError::CollectionLengthOverflow);
    }
    Ok(())
}

fn optional_len(targets: &Option<Vec<EvidenceTargetV1>>) -> usize {
    targets.as_ref().map_or(0, Vec::len)
}
