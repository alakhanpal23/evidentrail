use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{
    PROPOSAL_COMPILER_POLICY_NAME_V1, PROPOSAL_COMPILER_POLICY_VERSION_V1,
    proposal_candidate_config_digest_v1, proposal_compiler_config_digest_v1,
};
use evidentrail_schema::ArtifactDigest;

use crate::constrained_matched_case::prepare_constrained_pinned_drain_matched_case_with_observer_v1;
use crate::peak_rss_observer::execute_with_macos_time_peak_rss_v1;
use crate::{
    ConstrainedMatchedCaseErrorV1, ExitCategoryV1, FinalizedConstrainedPinnedDrainMatchedCaseV1,
    FirstPartyConstrainedSubprocessTargetV1, LegacyDrainJsonLimitsV1,
    LegacyDrainNormalizationErrorV1, MacOsTimePeakRssObserverV1, MacOsTimePeakRssReceiptV1,
    PeakRssMeasurementUnitV1, PeakRssObserverErrorV1, PinnedDrainMatchedArmV1,
    PinnedLegacyDrainExecutionTargetV1, PreparedConstrainedPinnedDrainMatchedCaseV1,
    PublicSubprocessInvocationV1, StdinDeliveryV1, StreamCaptureStateV1,
    SubprocessExecutionReceiptV1, artifact_digest_for_bytes_v1, strict_identity_normalize_v1,
    strict_normalize_pinned_legacy_drain_full_membership_v1,
};

pub const CONSTRAINED_PAIRED_TRIAL_COUNT_V1: usize = 3;
pub const CONSTRAINED_PAIRED_TRIAL_CONTRACT_VERSION_V1: u16 = 1;
pub const CONSTRAINED_FIRST_PARTY_POLICY_IDENTITY_CONTRACT_VERSION_V1: u16 = 1;

const RECEIPT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/constrained-paired-trials/v1";
const TRIAL_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/constrained-paired-trial/v1";
const ARM_OBSERVATION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/constrained-paired-trial-arm/v1";
const SUMMARY_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/integer-spread/v1";
const FIRST_PARTY_POLICY_IDENTITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-selector-compiler-policy/v1";

/// Canonical identity of the first-party candidate/selector/compiler policy
/// used by this binary. It is derived from the production compiler's frozen
/// policy name/version and its complete candidate/compiler config digests;
/// callers cannot substitute a descriptive label for these commitments.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConstrainedFirstPartyPolicyIdentityV1 {
    artifact_digest: ArtifactDigest,
    candidate_config_digest: ArtifactDigest,
    compiler_config_digest: ArtifactDigest,
    compiler_policy_name: &'static [u8],
    compiler_policy_version: &'static [u8],
}

impl ConstrainedFirstPartyPolicyIdentityV1 {
    fn current_v1() -> Result<Self, ConstrainedPairedTrialErrorV1> {
        if PROPOSAL_COMPILER_POLICY_NAME_V1.is_empty()
            || PROPOSAL_COMPILER_POLICY_VERSION_V1.is_empty()
        {
            return Err(ConstrainedPairedTrialErrorV1::InvalidPolicyIdentity);
        }
        let candidate_config_digest = proposal_candidate_config_digest_v1();
        let compiler_config_digest = proposal_compiler_config_digest_v1();
        let artifact_digest = derive_first_party_policy_identity_digest_v1(
            candidate_config_digest,
            compiler_config_digest,
            PROPOSAL_COMPILER_POLICY_NAME_V1,
            PROPOSAL_COMPILER_POLICY_VERSION_V1,
        )?;
        Ok(Self {
            artifact_digest,
            candidate_config_digest,
            compiler_config_digest,
            compiler_policy_name: PROPOSAL_COMPILER_POLICY_NAME_V1,
            compiler_policy_version: PROPOSAL_COMPILER_POLICY_VERSION_V1,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn candidate_config_digest(self) -> ArtifactDigest {
        self.candidate_config_digest
    }

    #[must_use]
    pub const fn compiler_config_digest(self) -> ArtifactDigest {
        self.compiler_config_digest
    }

    #[must_use]
    pub const fn compiler_policy_name(self) -> &'static [u8] {
        self.compiler_policy_name
    }

    #[must_use]
    pub const fn compiler_policy_version(self) -> &'static [u8] {
        self.compiler_policy_version
    }

    pub fn verify_expected_artifact_digest_v1(
        self,
        expected: ArtifactDigest,
    ) -> Result<(), ConstrainedPairedTrialErrorV1> {
        if expected != self.artifact_digest {
            return Err(ConstrainedPairedTrialErrorV1::ExpectedPolicyMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ConstrainedFirstPartyPolicyIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedFirstPartyPolicyIdentityV1")
            .field(
                "contract_version",
                &CONSTRAINED_FIRST_PARTY_POLICY_IDENTITY_CONTRACT_VERSION_V1,
            )
            .field("candidate_config_bound", &true)
            .field("compiler_config_bound", &true)
            .field("compiler_policy_name_bound", &true)
            .field("compiler_policy_version_bound", &true)
            .finish()
    }
}

/// Preregistered external-arm order. Trial zero uses the order already
/// performed by constrained preparation; every subsequent trial alternates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedPairedTrialOrderV1 {
    PinnedDrainThenFirstParty,
    FirstPartyThenPinnedDrain,
}

impl ConstrainedPairedTrialOrderV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PinnedDrainThenFirstParty => "pinned_drain_then_first_party",
            Self::FirstPartyThenPinnedDrain => "first_party_then_pinned_drain",
        }
    }

    #[must_use]
    pub const fn preregistered_for_index(index: usize) -> Self {
        if index % 2 == 0 {
            Self::PinnedDrainThenFirstParty
        } else {
            Self::FirstPartyThenPinnedDrain
        }
    }
}

impl fmt::Debug for ConstrainedPairedTrialOrderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedTrialOrderV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One arm's complete raw subprocess observation for one paired trial.
/// Captured stdout/stderr bytes remain available through `execution`; wall
/// time is retained there, while the observer receipt retains the exact RSS
/// value and binds the raw report digest.
#[derive(Clone, PartialEq, Eq)]
pub struct ConstrainedPairedTrialArmObservationV1 {
    artifact_digest: ArtifactDigest,
    arm: PinnedDrainMatchedArmV1,
    execution: SubprocessExecutionReceiptV1,
    peak_rss: MacOsTimePeakRssReceiptV1,
}

impl ConstrainedPairedTrialArmObservationV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn arm(&self) -> PinnedDrainMatchedArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn execution(&self) -> &SubprocessExecutionReceiptV1 {
        &self.execution
    }

    #[must_use]
    pub const fn peak_rss_receipt(&self) -> MacOsTimePeakRssReceiptV1 {
        self.peak_rss
    }

    #[must_use]
    pub const fn wall_time_nanos(&self) -> u64 {
        self.execution.wall_time_nanos()
    }

    #[must_use]
    pub const fn peak_rss_bytes(&self) -> u64 {
        self.peak_rss.peak_rss_bytes()
    }

    #[must_use]
    pub const fn stdout_artifact_digest(&self) -> ArtifactDigest {
        self.execution.stdout().artifact_digest()
    }

    #[must_use]
    pub const fn stdout_byte_count(&self) -> usize {
        self.execution.stdout().byte_count()
    }

    #[must_use]
    pub const fn direct_process_rss_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn child_tree_rss_claimed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn independently_attested(&self) -> bool {
        false
    }
}

impl fmt::Debug for ConstrainedPairedTrialArmObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedTrialArmObservationV1")
            .field("arm", &self.arm)
            .field("execution", &self.execution)
            .field("peak_rss", &self.peak_rss)
            .field("artifact_bound", &true)
            .field("direct_process_rss_only", &true)
            .field("child_tree_rss_claimed", &false)
            .field("independently_attested", &false)
            .field("contains_hidden_annotations", &false)
            .finish()
    }
}

/// One complete paired trial. Arm fields retain semantic identity independent
/// of execution order so a consumer cannot accidentally transpose results.
#[derive(Clone, PartialEq, Eq)]
pub struct ConstrainedPairedTrialV1 {
    artifact_digest: ArtifactDigest,
    index: u8,
    order: ConstrainedPairedTrialOrderV1,
    first_party: ConstrainedPairedTrialArmObservationV1,
    pinned_drain: ConstrainedPairedTrialArmObservationV1,
}

impl ConstrainedPairedTrialV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    #[must_use]
    pub const fn order(&self) -> ConstrainedPairedTrialOrderV1 {
        self.order
    }

    #[must_use]
    pub const fn first_party(&self) -> &ConstrainedPairedTrialArmObservationV1 {
        &self.first_party
    }

    #[must_use]
    pub const fn pinned_drain(&self) -> &ConstrainedPairedTrialArmObservationV1 {
        &self.pinned_drain
    }
}

impl fmt::Debug for ConstrainedPairedTrialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedTrialV1")
            .field("index", &self.index)
            .field("order", &self.order)
            .field("first_party", &self.first_party)
            .field("pinned_drain", &self.pinned_drain)
            .field("artifact_bound", &true)
            .field("contains_hidden_annotations", &false)
            .finish()
    }
}

/// Deterministic exact-integer distribution summary. MAD is the median of
/// each observation's unsigned absolute deviation from the median.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IntegerSpreadV1 {
    artifact_digest: ArtifactDigest,
    count: u64,
    minimum: u64,
    median: u64,
    maximum: u64,
    median_absolute_deviation: u64,
}

impl IntegerSpreadV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    #[must_use]
    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    #[must_use]
    pub const fn median(self) -> u64 {
        self.median
    }

    #[must_use]
    pub const fn maximum(self) -> u64 {
        self.maximum
    }

    #[must_use]
    pub const fn median_absolute_deviation(self) -> u64 {
        self.median_absolute_deviation
    }
}

impl fmt::Debug for IntegerSpreadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegerSpreadV1")
            .field("count", &self.count)
            .field("minimum", &self.minimum)
            .field("median", &self.median)
            .field("maximum", &self.maximum)
            .field("median_absolute_deviation", &self.median_absolute_deviation)
            .field("artifact_bound", &true)
            .finish()
    }
}

/// Per-arm repeatability dimensions. No dimensions are scalarized together.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConstrainedPairedArmRepeatabilityV1 {
    wall_time_nanos: IntegerSpreadV1,
    peak_rss_bytes: IntegerSpreadV1,
    stdout_artifact_digest: ArtifactDigest,
    stdout_byte_count: u64,
}

impl ConstrainedPairedArmRepeatabilityV1 {
    #[must_use]
    pub const fn wall_time_nanos(self) -> IntegerSpreadV1 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> IntegerSpreadV1 {
        self.peak_rss_bytes
    }

    #[must_use]
    pub const fn stdout_artifact_digest(self) -> ArtifactDigest {
        self.stdout_artifact_digest
    }

    #[must_use]
    pub const fn stdout_byte_count(self) -> u64 {
        self.stdout_byte_count
    }
}

impl fmt::Debug for ConstrainedPairedArmRepeatabilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedArmRepeatabilityV1")
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("peak_rss_bytes", &self.peak_rss_bytes)
            .field("stdout_artifact_bound", &true)
            .field("stdout_byte_count", &self.stdout_byte_count)
            .finish()
    }
}

/// Frozen public multi-trial receipt around one finalized constrained case.
/// It exposes raw trial observations and separate exact summaries, never a
/// scalar comparison or representation-quality result.
pub struct ConstrainedPairedMultiTrialReceiptV1 {
    artifact_digest: ArtifactDigest,
    finalized_case_artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    first_party_invocation_digest: crate::InvocationDigestV1,
    pinned_drain_invocation_digest: crate::InvocationDigestV1,
    first_party_executable_build_artifact_digest: ArtifactDigest,
    pinned_drain_executable_build_artifact_digest: ArtifactDigest,
    proposal_audit_artifact_digest: ArtifactDigest,
    first_party_policy_identity: ConstrainedFirstPartyPolicyIdentityV1,
    observer_executable_build_artifact_digest: ArtifactDigest,
    observer_report_format_artifact_digest: ArtifactDigest,
    observer_measurement_mechanism_artifact_digest: ArtifactDigest,
    trials: Box<[ConstrainedPairedTrialV1]>,
    first_party: ConstrainedPairedArmRepeatabilityV1,
    pinned_drain: ConstrainedPairedArmRepeatabilityV1,
}

impl ConstrainedPairedMultiTrialReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn finalized_case_artifact_digest(&self) -> ArtifactDigest {
        self.finalized_case_artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn first_party_invocation_digest(&self) -> crate::InvocationDigestV1 {
        self.first_party_invocation_digest
    }

    #[must_use]
    pub const fn pinned_drain_invocation_digest(&self) -> crate::InvocationDigestV1 {
        self.pinned_drain_invocation_digest
    }

    #[must_use]
    pub const fn first_party_executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.first_party_executable_build_artifact_digest
    }

    #[must_use]
    pub const fn pinned_drain_executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.pinned_drain_executable_build_artifact_digest
    }

    #[must_use]
    pub const fn proposal_audit_artifact_digest(&self) -> ArtifactDigest {
        self.proposal_audit_artifact_digest
    }

    #[must_use]
    pub const fn first_party_policy_identity(&self) -> ConstrainedFirstPartyPolicyIdentityV1 {
        self.first_party_policy_identity
    }

    #[must_use]
    pub const fn observer_executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.observer_executable_build_artifact_digest
    }

    #[must_use]
    pub const fn observer_report_format_artifact_digest(&self) -> ArtifactDigest {
        self.observer_report_format_artifact_digest
    }

    #[must_use]
    pub const fn observer_measurement_mechanism_artifact_digest(&self) -> ArtifactDigest {
        self.observer_measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub fn trials(&self) -> &[ConstrainedPairedTrialV1] {
        &self.trials
    }

    #[must_use]
    pub const fn first_party(&self) -> ConstrainedPairedArmRepeatabilityV1 {
        self.first_party
    }

    #[must_use]
    pub const fn pinned_drain(&self) -> ConstrainedPairedArmRepeatabilityV1 {
        self.pinned_drain
    }

    #[must_use]
    pub fn trial_count(&self) -> usize {
        self.trials.len()
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_scalar_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_quality_claim(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn child_tree_rss_claimed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn independently_attested(&self) -> bool {
        false
    }

    pub fn verify_finalized_case_artifact_v1(
        &self,
        expected: ArtifactDigest,
    ) -> Result<(), ConstrainedPairedTrialErrorV1> {
        if expected != self.finalized_case_artifact_digest {
            return Err(ConstrainedPairedTrialErrorV1::FinalizedCaseBindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ConstrainedPairedMultiTrialReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedMultiTrialReceiptV1")
            .field(
                "contract_version",
                &CONSTRAINED_PAIRED_TRIAL_CONTRACT_VERSION_V1,
            )
            .field("finalized_case_bound", &true)
            .field("public_case_bound", &true)
            .field("invocations_bound", &true)
            .field("arm_builds_bound", &true)
            .field("proposal_audit_bound", &true)
            .field(
                "first_party_policy_identity",
                &self.first_party_policy_identity,
            )
            .field("observer_build_bound", &true)
            .field("observer_format_bound", &true)
            .field("observer_mechanism_bound", &true)
            .field("trial_count", &self.trials.len())
            .field("first_party", &self.first_party)
            .field("pinned_drain", &self.pinned_drain)
            .field("direct_process_rss_only", &true)
            .field("child_tree_rss_claimed", &false)
            .field("independently_attested", &false)
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("contains_quality_claim", &false)
            .finish()
    }
}

/// Owns the baseline/finalized case and its public repeatability receipt.
pub struct ConstrainedPairedMultiTrialRunV1 {
    prepared: PreparedConstrainedPinnedDrainMatchedCaseV1,
    finalized: FinalizedConstrainedPinnedDrainMatchedCaseV1,
    receipt: ConstrainedPairedMultiTrialReceiptV1,
}

impl ConstrainedPairedMultiTrialRunV1 {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedConstrainedPinnedDrainMatchedCaseV1 {
        &self.prepared
    }

    #[must_use]
    pub const fn finalized(&self) -> &FinalizedConstrainedPinnedDrainMatchedCaseV1 {
        &self.finalized
    }

    #[must_use]
    pub const fn receipt(&self) -> &ConstrainedPairedMultiTrialReceiptV1 {
        &self.receipt
    }
}

impl fmt::Debug for ConstrainedPairedMultiTrialRunV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedMultiTrialRunV1")
            .field("prepared", &self.prepared)
            .field("finalized", &self.finalized)
            .field("receipt", &self.receipt)
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("contains_quality_claim", &false)
            .finish()
    }
}

/// Run the fixed three-trial schedule. Trial zero is the fully governed
/// constrained preparation itself; later trials rerun the exact frozen public
/// invocations, so this function introduces no unreported warm-up inside one
/// call. The receipt does not attest that the host or executables had no prior
/// invocations before this call.
///
/// This convenience entry point admits the canonical policy compiled into the
/// current binary. Preregistered runs should call
/// [`run_constrained_paired_trials_for_expected_policy_v1`] with the frozen
/// policy-identity digest so source-policy drift fails before any subprocess
/// execution.
pub fn run_constrained_paired_trials_v1(
    first_party_target: FirstPartyConstrainedSubprocessTargetV1,
    pinned_drain_target: PinnedLegacyDrainExecutionTargetV1,
) -> Result<ConstrainedPairedMultiTrialRunV1, ConstrainedPairedTrialErrorV1> {
    let policy_identity = current_constrained_first_party_policy_identity_v1()?;
    run_constrained_paired_trials_for_expected_policy_v1(
        policy_identity.artifact_digest(),
        first_party_target,
        pinned_drain_target,
    )
}

/// Return the canonical candidate/selector/compiler policy identity compiled
/// into this harness and the first-party production path.
pub fn current_constrained_first_party_policy_identity_v1()
-> Result<ConstrainedFirstPartyPolicyIdentityV1, ConstrainedPairedTrialErrorV1> {
    ConstrainedFirstPartyPolicyIdentityV1::current_v1()
}

/// Run the fixed schedule only when the preregistered policy identity matches
/// the canonical identity compiled into this binary. This comparison is the
/// first operation and therefore fails before observer construction or either
/// arm's subprocess execution. The production audit is reconciled against the
/// same identity after baseline preparation and before any repeated trial.
pub fn run_constrained_paired_trials_for_expected_policy_v1(
    expected_policy_artifact_digest: ArtifactDigest,
    first_party_target: FirstPartyConstrainedSubprocessTargetV1,
    pinned_drain_target: PinnedLegacyDrainExecutionTargetV1,
) -> Result<ConstrainedPairedMultiTrialRunV1, ConstrainedPairedTrialErrorV1> {
    let policy_identity = current_constrained_first_party_policy_identity_v1()?;
    policy_identity.verify_expected_artifact_digest_v1(expected_policy_artifact_digest)?;
    run_admitted_constrained_paired_trials_v1(
        policy_identity,
        first_party_target,
        pinned_drain_target,
    )
}

fn run_admitted_constrained_paired_trials_v1(
    policy_identity: ConstrainedFirstPartyPolicyIdentityV1,
    first_party_target: FirstPartyConstrainedSubprocessTargetV1,
    pinned_drain_target: PinnedLegacyDrainExecutionTargetV1,
) -> Result<ConstrainedPairedMultiTrialRunV1, ConstrainedPairedTrialErrorV1> {
    let observer = MacOsTimePeakRssObserverV1::try_system_v1()?;
    let prepared = prepare_constrained_pinned_drain_matched_case_with_observer_v1(
        first_party_target,
        pinned_drain_target,
        &observer,
    )?;
    validate_prepared_policy_identity_v1(&prepared, policy_identity)?;
    let mut trials = Vec::with_capacity(CONSTRAINED_PAIRED_TRIAL_COUNT_V1);
    trials.push(freeze_baseline_trial_v1(&prepared)?);

    for index in 1..CONSTRAINED_PAIRED_TRIAL_COUNT_V1 {
        let order = ConstrainedPairedTrialOrderV1::preregistered_for_index(index);
        let (first_party, pinned_drain) = match order {
            ConstrainedPairedTrialOrderV1::PinnedDrainThenFirstParty => {
                let pinned_drain = execute_pinned_drain_trial_v1(&prepared, &observer)?;
                let first_party = execute_first_party_trial_v1(&prepared, &observer)?;
                (first_party, pinned_drain)
            }
            ConstrainedPairedTrialOrderV1::FirstPartyThenPinnedDrain => {
                let first_party = execute_first_party_trial_v1(&prepared, &observer)?;
                let pinned_drain = execute_pinned_drain_trial_v1(&prepared, &observer)?;
                (first_party, pinned_drain)
            }
        };
        trials.push(freeze_trial_v1(index, order, first_party, pinned_drain)?);
    }

    let finalized = prepared.try_finalize()?;
    let receipt = freeze_multi_trial_receipt_v1(&prepared, &finalized, policy_identity, trials)?;
    Ok(ConstrainedPairedMultiTrialRunV1 {
        prepared,
        finalized,
        receipt,
    })
}

fn validate_prepared_policy_identity_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    policy_identity: ConstrainedFirstPartyPolicyIdentityV1,
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    let input = prepared.proposal_audit().audit().input();
    if input.candidate_config_digest() != policy_identity.candidate_config_digest()
        || input.compiler_config_digest() != policy_identity.compiler_config_digest()
    {
        return Err(ConstrainedPairedTrialErrorV1::ProductionPolicyMismatch);
    }
    Ok(())
}

fn freeze_baseline_trial_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
) -> Result<ConstrainedPairedTrialV1, ConstrainedPairedTrialErrorV1> {
    let first_party = freeze_arm_observation_v1(
        PinnedDrainMatchedArmV1::FirstParty,
        prepared.first_party_subprocess_receipt().invocation(),
        prepared
            .first_party_subprocess_receipt()
            .execution()
            .clone(),
        prepared.first_party_peak_rss_observer_receipt(),
        prepared
            .first_party_manifest()
            .identity()
            .budget()
            .peak_memory_bytes(),
    )?;
    validate_first_party_output_v1(prepared, &first_party)?;
    let pinned_drain_peak = prepared
        .drain_peak_rss_observer_receipt()
        .ok_or(ConstrainedPairedTrialErrorV1::MissingObservation)?;
    let pinned_drain = freeze_arm_observation_v1(
        PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
        prepared.drain_invocation(),
        prepared.drain_execution().clone(),
        pinned_drain_peak,
        prepared
            .drain_manifest()
            .identity()
            .budget()
            .peak_memory_bytes(),
    )?;
    validate_pinned_drain_output_v1(prepared, &pinned_drain)?;
    freeze_trial_v1(
        0,
        ConstrainedPairedTrialOrderV1::PinnedDrainThenFirstParty,
        first_party,
        pinned_drain,
    )
}

fn execute_first_party_trial_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    observer: &MacOsTimePeakRssObserverV1,
) -> Result<ConstrainedPairedTrialArmObservationV1, ConstrainedPairedTrialErrorV1> {
    let invocation = prepared.first_party_subprocess_receipt().invocation();
    let binding = prepared.peak_rss_observation_binding(PinnedDrainMatchedArmV1::FirstParty)?;
    let (execution, peak_rss) = execute_with_macos_time_peak_rss_v1(observer, invocation, binding)?;
    let observation = freeze_arm_observation_v1(
        PinnedDrainMatchedArmV1::FirstParty,
        invocation,
        execution,
        peak_rss,
        prepared
            .first_party_manifest()
            .identity()
            .budget()
            .peak_memory_bytes(),
    )?;
    validate_first_party_output_v1(prepared, &observation)?;
    Ok(observation)
}

fn execute_pinned_drain_trial_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    observer: &MacOsTimePeakRssObserverV1,
) -> Result<ConstrainedPairedTrialArmObservationV1, ConstrainedPairedTrialErrorV1> {
    let invocation = prepared.drain_invocation();
    let binding = prepared
        .peak_rss_observation_binding(PinnedDrainMatchedArmV1::PinnedDrainFullMembership)?;
    let (execution, peak_rss) = execute_with_macos_time_peak_rss_v1(observer, invocation, binding)?;
    let observation = freeze_arm_observation_v1(
        PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
        invocation,
        execution,
        peak_rss,
        prepared
            .drain_manifest()
            .identity()
            .budget()
            .peak_memory_bytes(),
    )?;
    validate_pinned_drain_output_v1(prepared, &observation)?;
    Ok(observation)
}

fn freeze_arm_observation_v1(
    arm: PinnedDrainMatchedArmV1,
    invocation: &PublicSubprocessInvocationV1,
    execution: SubprocessExecutionReceiptV1,
    peak_rss: MacOsTimePeakRssReceiptV1,
    peak_rss_cap: u64,
) -> Result<ConstrainedPairedTrialArmObservationV1, ConstrainedPairedTrialErrorV1> {
    let binding = peak_rss.observation().binding();
    if execution.invocation_digest() != invocation.digest()
        || execution.run_manifest_artifact_digest() != invocation.run_manifest_artifact_digest()
        || execution.run_identity() != invocation.run_identity()
        || execution.public_case_artifact_digest() != invocation.public_case_artifact_digest()
        || execution.stdin_artifact_digest() != invocation.stdin().artifact_digest()
        || execution.stdin_delivery() != StdinDeliveryV1::Complete
        || execution.exit_category() != ExitCategoryV1::Success
        || execution.stdout().state() != StreamCaptureStateV1::Complete
        || execution.stderr().state() != StreamCaptureStateV1::Complete
        || !execution.stderr().bytes().is_empty()
        || !execution.termination_causes().is_empty()
        || !execution.child_reaped()
        || !execution.executable_path_digest_verified_before_spawn()
        || !execution.executable_path_digest_verified_after_spawn()
        || execution.wall_time_nanos() == 0
        || execution.wall_time_nanos() > invocation.limits().wall_nanos()
        || peak_rss.invocation_digest() != invocation.digest()
        || peak_rss.stdout_artifact_digest() != execution.stdout().artifact_digest()
        || peak_rss.stderr_artifact_digest() != execution.stderr().artifact_digest()
        || peak_rss.raw_report_byte_count() == 0
        || peak_rss.peak_rss_bytes() == 0
        || peak_rss.peak_rss_bytes() > peak_rss_cap
        || peak_rss.unit() != PeakRssMeasurementUnitV1::Bytes
        || !peak_rss.observer_digest_verified_before_spawn()
        || !peak_rss.observer_digest_verified_after_reap()
        || peak_rss.observer_digest_before_spawn()
            != peak_rss.observer_executable_build_artifact_digest()
        || peak_rss.observer_digest_after_reap()
            != peak_rss.observer_executable_build_artifact_digest()
        || !peak_rss.directly_timed_process_only()
        || peak_rss.child_tree_peak_rss_claimed()
        || peak_rss.independently_attested()
        || binding.arm() != arm
        || binding.system_artifact_digest() != invocation.program().system_artifact_digest()
        || binding.executable_build_artifact_digest()
            != invocation.program().executable_build_artifact_digest()
        || binding.public_run_manifest_artifact_digest()
            != invocation.run_manifest_artifact_digest()
        || binding.public_case_artifact_digest() != invocation.public_case_artifact_digest()
    {
        return Err(ConstrainedPairedTrialErrorV1::ArmObservationBindingMismatch);
    }
    let artifact_digest = derive_arm_observation_artifact_digest_v1(arm, &execution, peak_rss)?;
    Ok(ConstrainedPairedTrialArmObservationV1 {
        artifact_digest,
        arm,
        execution,
        peak_rss,
    })
}

fn validate_first_party_output_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    observation: &ConstrainedPairedTrialArmObservationV1,
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    strict_identity_normalize_v1(observation.execution())?;
    let expected = prepared
        .first_party_subprocess_receipt()
        .execution()
        .stdout();
    if observation.execution().stdout().artifact_digest() != expected.artifact_digest()
        || observation.execution().stdout().bytes() != expected.bytes()
    {
        return Err(ConstrainedPairedTrialErrorV1::OutputMismatch);
    }
    Ok(())
}

fn validate_pinned_drain_output_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    observation: &ConstrainedPairedTrialArmObservationV1,
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    let normalized = strict_normalize_pinned_legacy_drain_full_membership_v1(
        prepared.drain_invocation(),
        observation.execution(),
        LegacyDrainJsonLimitsV1::default(),
    )?;
    if normalized.artifact_digest() != prepared.drain_full_membership().artifact_digest()
        || observation.execution().stdout().artifact_digest()
            != prepared.drain_execution().stdout().artifact_digest()
        || observation.execution().stdout().bytes() != prepared.drain_execution().stdout().bytes()
    {
        return Err(ConstrainedPairedTrialErrorV1::OutputMismatch);
    }
    Ok(())
}

fn freeze_trial_v1(
    index: usize,
    order: ConstrainedPairedTrialOrderV1,
    first_party: ConstrainedPairedTrialArmObservationV1,
    pinned_drain: ConstrainedPairedTrialArmObservationV1,
) -> Result<ConstrainedPairedTrialV1, ConstrainedPairedTrialErrorV1> {
    if index >= CONSTRAINED_PAIRED_TRIAL_COUNT_V1
        || order != ConstrainedPairedTrialOrderV1::preregistered_for_index(index)
        || first_party.arm() != PinnedDrainMatchedArmV1::FirstParty
        || pinned_drain.arm() != PinnedDrainMatchedArmV1::PinnedDrainFullMembership
    {
        return Err(ConstrainedPairedTrialErrorV1::TrialScheduleMismatch);
    }
    let index = u8::try_from(index).map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?;
    let artifact_digest = derive_trial_artifact_digest_v1(
        index,
        order,
        first_party.artifact_digest(),
        pinned_drain.artifact_digest(),
    )?;
    Ok(ConstrainedPairedTrialV1 {
        artifact_digest,
        index,
        order,
        first_party,
        pinned_drain,
    })
}

fn freeze_multi_trial_receipt_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    finalized: &FinalizedConstrainedPinnedDrainMatchedCaseV1,
    first_party_policy_identity: ConstrainedFirstPartyPolicyIdentityV1,
    trials: Vec<ConstrainedPairedTrialV1>,
) -> Result<ConstrainedPairedMultiTrialReceiptV1, ConstrainedPairedTrialErrorV1> {
    validate_prepared_policy_identity_v1(prepared, first_party_policy_identity)?;
    validate_schedule_v1(
        &trials
            .iter()
            .map(|trial| (trial.index(), trial.order()))
            .collect::<Vec<_>>(),
    )?;
    let first_reference = trials
        .first()
        .ok_or(ConstrainedPairedTrialErrorV1::MissingTrial)?
        .first_party();
    let drain_reference = trials
        .first()
        .ok_or(ConstrainedPairedTrialErrorV1::MissingTrial)?
        .pinned_drain();
    validate_common_pair_binding_v1(first_reference, drain_reference)?;
    for trial in &trials {
        validate_cross_trial_binding_v1(first_reference, trial.first_party())?;
        validate_cross_trial_binding_v1(drain_reference, trial.pinned_drain())?;
    }
    let first_party = summarize_arm_v1(trials.iter().map(ConstrainedPairedTrialV1::first_party))?;
    let pinned_drain = summarize_arm_v1(trials.iter().map(ConstrainedPairedTrialV1::pinned_drain))?;
    let artifact_digest = derive_multi_trial_receipt_artifact_digest_v1(
        prepared,
        finalized,
        &trials,
        first_party,
        pinned_drain,
        first_reference,
        first_party_policy_identity,
    )?;
    Ok(ConstrainedPairedMultiTrialReceiptV1 {
        artifact_digest,
        finalized_case_artifact_digest: finalized.artifact_digest(),
        public_case_artifact_digest: prepared.public_case_artifact_digest(),
        first_party_invocation_digest: prepared
            .first_party_subprocess_receipt()
            .invocation()
            .digest(),
        pinned_drain_invocation_digest: prepared.drain_invocation().digest(),
        first_party_executable_build_artifact_digest: first_reference
            .peak_rss_receipt()
            .observation()
            .binding()
            .executable_build_artifact_digest(),
        pinned_drain_executable_build_artifact_digest: drain_reference
            .peak_rss_receipt()
            .observation()
            .binding()
            .executable_build_artifact_digest(),
        proposal_audit_artifact_digest: prepared.proposal_audit().artifact_digest(),
        first_party_policy_identity,
        observer_executable_build_artifact_digest: first_reference
            .peak_rss_receipt()
            .observer_executable_build_artifact_digest(),
        observer_report_format_artifact_digest: first_reference
            .peak_rss_receipt()
            .report_format_artifact_digest(),
        observer_measurement_mechanism_artifact_digest: first_reference
            .peak_rss_receipt()
            .measurement_mechanism_artifact_digest(),
        trials: trials.into_boxed_slice(),
        first_party,
        pinned_drain,
    })
}

fn validate_schedule_v1(
    schedule: &[(u8, ConstrainedPairedTrialOrderV1)],
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    if schedule.len() != CONSTRAINED_PAIRED_TRIAL_COUNT_V1 {
        return Err(ConstrainedPairedTrialErrorV1::TrialCountMismatch);
    }
    for (expected_index, (index, order)) in schedule.iter().copied().enumerate() {
        if usize::from(index) != expected_index
            || order != ConstrainedPairedTrialOrderV1::preregistered_for_index(expected_index)
        {
            return Err(ConstrainedPairedTrialErrorV1::TrialScheduleMismatch);
        }
    }
    Ok(())
}

fn validate_cross_trial_binding_v1(
    reference: &ConstrainedPairedTrialArmObservationV1,
    observed: &ConstrainedPairedTrialArmObservationV1,
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    let reference_rss = reference.peak_rss_receipt();
    let observed_rss = observed.peak_rss_receipt();
    if reference.arm() != observed.arm()
        || reference.execution().invocation_digest() != observed.execution().invocation_digest()
        || reference.execution().run_manifest_artifact_digest()
            != observed.execution().run_manifest_artifact_digest()
        || reference.execution().public_case_artifact_digest()
            != observed.execution().public_case_artifact_digest()
        || reference.execution().stdin_artifact_digest()
            != observed.execution().stdin_artifact_digest()
        || reference.stdout_artifact_digest() != observed.stdout_artifact_digest()
        || reference.execution().stdout().bytes() != observed.execution().stdout().bytes()
        || reference_rss.observer_executable_build_artifact_digest()
            != observed_rss.observer_executable_build_artifact_digest()
        || reference_rss.report_format_artifact_digest()
            != observed_rss.report_format_artifact_digest()
        || reference_rss.measurement_mechanism_artifact_digest()
            != observed_rss.measurement_mechanism_artifact_digest()
        || reference_rss.unit() != observed_rss.unit()
    {
        return Err(ConstrainedPairedTrialErrorV1::CrossTrialBindingMismatch);
    }
    Ok(())
}

fn validate_common_pair_binding_v1(
    first_party: &ConstrainedPairedTrialArmObservationV1,
    pinned_drain: &ConstrainedPairedTrialArmObservationV1,
) -> Result<(), ConstrainedPairedTrialErrorV1> {
    let first_rss = first_party.peak_rss_receipt();
    let drain_rss = pinned_drain.peak_rss_receipt();
    if first_party.arm() != PinnedDrainMatchedArmV1::FirstParty
        || pinned_drain.arm() != PinnedDrainMatchedArmV1::PinnedDrainFullMembership
        || first_party.execution().public_case_artifact_digest()
            != pinned_drain.execution().public_case_artifact_digest()
        || first_party.execution().stdin_artifact_digest()
            != pinned_drain.execution().stdin_artifact_digest()
        || first_rss.observer_executable_build_artifact_digest()
            != drain_rss.observer_executable_build_artifact_digest()
        || first_rss.report_format_artifact_digest() != drain_rss.report_format_artifact_digest()
        || first_rss.measurement_mechanism_artifact_digest()
            != drain_rss.measurement_mechanism_artifact_digest()
        || first_rss.unit() != drain_rss.unit()
    {
        return Err(ConstrainedPairedTrialErrorV1::CrossTrialBindingMismatch);
    }
    Ok(())
}

fn summarize_arm_v1<'trial>(
    observations: impl Iterator<Item = &'trial ConstrainedPairedTrialArmObservationV1>,
) -> Result<ConstrainedPairedArmRepeatabilityV1, ConstrainedPairedTrialErrorV1> {
    let observations = observations.collect::<Vec<_>>();
    if observations.len() != CONSTRAINED_PAIRED_TRIAL_COUNT_V1 {
        return Err(ConstrainedPairedTrialErrorV1::TrialCountMismatch);
    }
    let reference = observations
        .first()
        .ok_or(ConstrainedPairedTrialErrorV1::MissingTrial)?;
    let wall_time_nanos = summarize_values_v1(
        &observations
            .iter()
            .map(|observation| observation.wall_time_nanos())
            .collect::<Vec<_>>(),
    )?;
    let peak_rss_bytes = summarize_values_v1(
        &observations
            .iter()
            .map(|observation| observation.peak_rss_bytes())
            .collect::<Vec<_>>(),
    )?;
    let stdout_byte_count = u64::try_from(reference.stdout_byte_count())
        .map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?;
    Ok(ConstrainedPairedArmRepeatabilityV1 {
        wall_time_nanos,
        peak_rss_bytes,
        stdout_artifact_digest: reference.stdout_artifact_digest(),
        stdout_byte_count,
    })
}

fn summarize_values_v1(values: &[u64]) -> Result<IntegerSpreadV1, ConstrainedPairedTrialErrorV1> {
    if values.len() != CONSTRAINED_PAIRED_TRIAL_COUNT_V1
        || values.len() % 2 == 0
        || values.contains(&0)
    {
        return Err(ConstrainedPairedTrialErrorV1::InvalidSummaryInput);
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    let mut deviations = values
        .iter()
        .map(|value| value.abs_diff(median))
        .collect::<Vec<_>>();
    deviations.sort_unstable();
    let median_absolute_deviation = deviations[deviations.len() / 2];
    let minimum = *sorted
        .first()
        .ok_or(ConstrainedPairedTrialErrorV1::InvalidSummaryInput)?;
    let maximum = *sorted
        .last()
        .ok_or(ConstrainedPairedTrialErrorV1::InvalidSummaryInput)?;
    let count = u64::try_from(values.len()).map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?;
    let artifact_digest = derive_summary_artifact_digest_v1(
        count,
        minimum,
        median,
        maximum,
        median_absolute_deviation,
    )?;
    Ok(IntegerSpreadV1 {
        artifact_digest,
        count,
        minimum,
        median,
        maximum,
        median_absolute_deviation,
    })
}

fn derive_arm_observation_artifact_digest_v1(
    arm: PinnedDrainMatchedArmV1,
    execution: &SubprocessExecutionReceiptV1,
    peak_rss: MacOsTimePeakRssReceiptV1,
) -> Result<ArtifactDigest, ConstrainedPairedTrialErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, ARM_OBSERVATION_DOMAIN_V1)?;
    append_field(&mut bytes, arm.code().as_bytes())?;
    append_field(&mut bytes, execution.invocation_digest().as_bytes())?;
    append_field(
        &mut bytes,
        execution.run_manifest_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        execution.public_case_artifact_digest().as_bytes(),
    )?;
    append_field(&mut bytes, execution.stdin_artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stdout().artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stderr().artifact_digest().as_bytes())?;
    append_field(
        &mut bytes,
        &u64::try_from(execution.stdout().byte_count())
            .map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?
            .to_le_bytes(),
    )?;
    append_field(
        &mut bytes,
        &u64::try_from(execution.stderr().byte_count())
            .map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?
            .to_le_bytes(),
    )?;
    append_field(&mut bytes, &execution.wall_time_nanos().to_le_bytes())?;
    append_field(&mut bytes, peak_rss.artifact_digest().as_bytes())?;
    append_field(&mut bytes, &peak_rss.peak_rss_bytes().to_le_bytes())?;
    append_field(&mut bytes, peak_rss.raw_report_artifact_digest().as_bytes())?;
    append_field(&mut bytes, &peak_rss.raw_report_byte_count().to_le_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_trial_artifact_digest_v1(
    index: u8,
    order: ConstrainedPairedTrialOrderV1,
    first_party: ArtifactDigest,
    pinned_drain: ArtifactDigest,
) -> Result<ArtifactDigest, ConstrainedPairedTrialErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, TRIAL_DOMAIN_V1)?;
    append_field(&mut bytes, &[index])?;
    append_field(&mut bytes, order.code().as_bytes())?;
    append_field(&mut bytes, first_party.as_bytes())?;
    append_field(&mut bytes, pinned_drain.as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_summary_artifact_digest_v1(
    count: u64,
    minimum: u64,
    median: u64,
    maximum: u64,
    median_absolute_deviation: u64,
) -> Result<ArtifactDigest, ConstrainedPairedTrialErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, SUMMARY_DOMAIN_V1)?;
    for value in [count, minimum, median, maximum, median_absolute_deviation] {
        append_field(&mut bytes, &value.to_le_bytes())?;
    }
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_first_party_policy_identity_digest_v1(
    candidate_config_digest: ArtifactDigest,
    compiler_config_digest: ArtifactDigest,
    compiler_policy_name: &[u8],
    compiler_policy_version: &[u8],
) -> Result<ArtifactDigest, ConstrainedPairedTrialErrorV1> {
    if compiler_policy_name.is_empty() || compiler_policy_version.is_empty() {
        return Err(ConstrainedPairedTrialErrorV1::InvalidPolicyIdentity);
    }
    let mut bytes = Vec::new();
    append_field(&mut bytes, FIRST_PARTY_POLICY_IDENTITY_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &CONSTRAINED_FIRST_PARTY_POLICY_IDENTITY_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, compiler_policy_name)?;
    append_field(&mut bytes, compiler_policy_version)?;
    append_field(&mut bytes, candidate_config_digest.as_bytes())?;
    append_field(&mut bytes, compiler_config_digest.as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn derive_multi_trial_receipt_artifact_digest_v1(
    prepared: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    finalized: &FinalizedConstrainedPinnedDrainMatchedCaseV1,
    trials: &[ConstrainedPairedTrialV1],
    first_party: ConstrainedPairedArmRepeatabilityV1,
    pinned_drain: ConstrainedPairedArmRepeatabilityV1,
    reference: &ConstrainedPairedTrialArmObservationV1,
    first_party_policy_identity: ConstrainedFirstPartyPolicyIdentityV1,
) -> Result<ArtifactDigest, ConstrainedPairedTrialErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, RECEIPT_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &CONSTRAINED_PAIRED_TRIAL_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(
        &mut bytes,
        first_party_policy_identity.artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        first_party_policy_identity
            .candidate_config_digest()
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        first_party_policy_identity
            .compiler_config_digest()
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        &u64::try_from(CONSTRAINED_PAIRED_TRIAL_COUNT_V1)
            .map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?
            .to_le_bytes(),
    )?;
    append_field(&mut bytes, finalized.artifact_digest().as_bytes())?;
    append_field(
        &mut bytes,
        prepared.public_case_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        prepared
            .first_party_subprocess_receipt()
            .invocation()
            .digest()
            .as_bytes(),
    )?;
    append_field(&mut bytes, prepared.drain_invocation().digest().as_bytes())?;
    append_field(
        &mut bytes,
        prepared.proposal_audit().artifact_digest().as_bytes(),
    )?;
    let observer = reference.peak_rss_receipt();
    append_field(
        &mut bytes,
        observer
            .observer_executable_build_artifact_digest()
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        observer.report_format_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        observer.measurement_mechanism_artifact_digest().as_bytes(),
    )?;
    for trial in trials {
        append_field(&mut bytes, trial.artifact_digest().as_bytes())?;
    }
    for summary in [first_party, pinned_drain] {
        append_field(
            &mut bytes,
            summary.wall_time_nanos().artifact_digest().as_bytes(),
        )?;
        append_field(
            &mut bytes,
            summary.peak_rss_bytes().artifact_digest().as_bytes(),
        )?;
        append_field(&mut bytes, summary.stdout_artifact_digest().as_bytes())?;
        append_field(&mut bytes, &summary.stdout_byte_count().to_le_bytes())?;
    }
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ConstrainedPairedTrialErrorV1> {
    let length = u64::try_from(value.len()).map_err(|_| ConstrainedPairedTrialErrorV1::Overflow)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedPairedTrialErrorV1 {
    MissingObservation,
    TrialCountMismatch,
    MissingTrial,
    TrialScheduleMismatch,
    ArmObservationBindingMismatch,
    CrossTrialBindingMismatch,
    OutputMismatch,
    InvalidPolicyIdentity,
    ExpectedPolicyMismatch,
    ProductionPolicyMismatch,
    InvalidSummaryInput,
    FinalizedCaseBindingMismatch,
    Overflow,
    Constrained(ConstrainedMatchedCaseErrorV1),
    PeakRss(PeakRssObserverErrorV1),
    Normalization(LegacyDrainNormalizationErrorV1),
    Harness(crate::HarnessError),
}

impl ConstrainedPairedTrialErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingObservation => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_MISSING_OBSERVATION",
            Self::TrialCountMismatch => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_COUNT_MISMATCH",
            Self::MissingTrial => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_MISSING_TRIAL",
            Self::TrialScheduleMismatch => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_SCHEDULE_MISMATCH",
            Self::ArmObservationBindingMismatch => {
                "EVIDENTRAIL_BENCH_PAIRED_TRIAL_ARM_BINDING_MISMATCH"
            }
            Self::CrossTrialBindingMismatch => {
                "EVIDENTRAIL_BENCH_PAIRED_TRIAL_CROSS_TRIAL_BINDING_MISMATCH"
            }
            Self::OutputMismatch => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_OUTPUT_MISMATCH",
            Self::InvalidPolicyIdentity => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_INVALID_POLICY_IDENTITY",
            Self::ExpectedPolicyMismatch => {
                "EVIDENTRAIL_BENCH_PAIRED_TRIAL_EXPECTED_POLICY_MISMATCH"
            }
            Self::ProductionPolicyMismatch => {
                "EVIDENTRAIL_BENCH_PAIRED_TRIAL_PRODUCTION_POLICY_MISMATCH"
            }
            Self::InvalidSummaryInput => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_INVALID_SUMMARY_INPUT",
            Self::FinalizedCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_PAIRED_TRIAL_FINALIZED_CASE_BINDING_MISMATCH"
            }
            Self::Overflow => "EVIDENTRAIL_BENCH_PAIRED_TRIAL_OVERFLOW",
            Self::Constrained(error) => error.code(),
            Self::PeakRss(error) => error.code(),
            Self::Normalization(error) => error.code(),
            Self::Harness(error) => error.code(),
        }
    }
}

impl fmt::Debug for ConstrainedPairedTrialErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedPairedTrialErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ConstrainedPairedTrialErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ConstrainedPairedTrialErrorV1 {}

impl From<ConstrainedMatchedCaseErrorV1> for ConstrainedPairedTrialErrorV1 {
    fn from(error: ConstrainedMatchedCaseErrorV1) -> Self {
        Self::Constrained(error)
    }
}

impl From<PeakRssObserverErrorV1> for ConstrainedPairedTrialErrorV1 {
    fn from(error: PeakRssObserverErrorV1) -> Self {
        Self::PeakRss(error)
    }
}

impl From<LegacyDrainNormalizationErrorV1> for ConstrainedPairedTrialErrorV1 {
    fn from(error: LegacyDrainNormalizationErrorV1) -> Self {
        Self::Normalization(error)
    }
}

impl From<crate::HarnessError> for ConstrainedPairedTrialErrorV1 {
    fn from(error: crate::HarnessError) -> Self {
        Self::Harness(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odd_integer_summary_is_exact_and_deterministic() {
        let summary = summarize_values_v1(&[100, 10, 20]).unwrap();
        assert_eq!(summary.count(), 3);
        assert_eq!(summary.minimum(), 10);
        assert_eq!(summary.median(), 20);
        assert_eq!(summary.maximum(), 100);
        assert_eq!(summary.median_absolute_deviation(), 10);
        assert_eq!(summary, summarize_values_v1(&[20, 100, 10]).unwrap());
    }

    #[test]
    fn missing_duplicate_reordered_and_even_schedules_fail_closed() {
        let valid = [
            (0, ConstrainedPairedTrialOrderV1::PinnedDrainThenFirstParty),
            (1, ConstrainedPairedTrialOrderV1::FirstPartyThenPinnedDrain),
            (2, ConstrainedPairedTrialOrderV1::PinnedDrainThenFirstParty),
        ];
        assert_eq!(validate_schedule_v1(&valid), Ok(()));
        assert_eq!(
            validate_schedule_v1(&valid[..2]),
            Err(ConstrainedPairedTrialErrorV1::TrialCountMismatch)
        );
        assert_eq!(
            validate_schedule_v1(&[valid[0], valid[0], valid[2],]),
            Err(ConstrainedPairedTrialErrorV1::TrialScheduleMismatch)
        );
        assert_eq!(
            validate_schedule_v1(&[valid[1], valid[0], valid[2]]),
            Err(ConstrainedPairedTrialErrorV1::TrialScheduleMismatch)
        );
        assert_eq!(
            summarize_values_v1(&[1, 2]),
            Err(ConstrainedPairedTrialErrorV1::InvalidSummaryInput)
        );
        assert_eq!(
            summarize_values_v1(&[1, 0, 2]),
            Err(ConstrainedPairedTrialErrorV1::InvalidSummaryInput)
        );
    }

    #[test]
    fn canonical_policy_identity_is_automatic_and_expected_mismatch_fails_closed() {
        let identity = current_constrained_first_party_policy_identity_v1().unwrap();
        assert_eq!(
            identity.candidate_config_digest(),
            proposal_candidate_config_digest_v1()
        );
        assert_eq!(
            identity.compiler_config_digest(),
            proposal_compiler_config_digest_v1()
        );
        assert_eq!(
            identity.compiler_policy_name(),
            PROPOSAL_COMPILER_POLICY_NAME_V1
        );
        assert_eq!(
            identity.compiler_policy_version(),
            PROPOSAL_COMPILER_POLICY_VERSION_V1
        );
        assert_eq!(
            identity.verify_expected_artifact_digest_v1(identity.artifact_digest()),
            Ok(())
        );

        let foreign = artifact_digest_for_bytes_v1(b"foreign-policy-identity");
        assert_ne!(foreign, identity.artifact_digest());
        assert_eq!(
            identity.verify_expected_artifact_digest_v1(foreign),
            Err(ConstrainedPairedTrialErrorV1::ExpectedPolicyMismatch)
        );

        let mutated = derive_first_party_policy_identity_digest_v1(
            ArtifactDigest::from_bytes([0x5a; 32]),
            identity.compiler_config_digest(),
            identity.compiler_policy_name(),
            identity.compiler_policy_version(),
        )
        .unwrap();
        assert_ne!(mutated, identity.artifact_digest());
    }

    #[test]
    fn diagnostics_are_contentless() {
        for error in [
            ConstrainedPairedTrialErrorV1::OutputMismatch,
            ConstrainedPairedTrialErrorV1::ExpectedPolicyMismatch,
            ConstrainedPairedTrialErrorV1::ProductionPolicyMismatch,
        ] {
            assert_eq!(error.to_string(), error.code());
            let debug = format!("{error:?}");
            assert!(!debug.contains("Traceback"));
            assert!(!debug.contains("request_id"));
            assert!(!debug.contains("/Users/"));
        }
    }
}
