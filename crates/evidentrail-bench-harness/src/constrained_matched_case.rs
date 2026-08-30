use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    BenchmarkBudgetV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchRunManifestV1, MethodDescriptor,
};
use evidentrail_candidates::{ValidatedIdentifierKindV1, preprocess_query_v1};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockState, CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink,
    EventLedger, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming,
    LaneKey, LaneSequence, LedgerBuilder, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_product::{
    CompiledProductResultV1, DeterministicProductDecisionV1, MemoryProductV1,
    ThreeLaneProposalAuditV1,
};
use evidentrail_schema::{ArtifactDigest, BlockId, EventId, PlanDigest, ResultId};

use crate::first_party_subprocess::execute_and_freeze_constrained_first_party_subprocess_v1;
use crate::pinned_matched_case::{MatchedCasePreparationV1, prepare_matched_case_v1};
use crate::{
    BoundPeakRssObservationV1, FinalizedPinnedDrainMatchedCaseV1,
    FirstPartyConstrainedSubprocessErrorV1, FirstPartyConstrainedSubprocessReceiptV1,
    FirstPartyConstrainedSubprocessTargetV1, FirstPartyParentOracleBuildV1,
    MacOsTimePeakRssObserverV1, MacOsTimePeakRssReceiptV1, MatchedCostComparisonEligibilityV1,
    PeakRssObservationBindingV1, PinnedLegacyDrainExecutionTargetV1, PinnedDrainMatchedArmV1,
    PreparedPinnedDrainMatchedCaseErrorV1, PreparedPinnedDrainMatchedCaseV1,
    PublicCaseInputBindingV1, artifact_digest_for_bytes_v1,
};

pub const CONSTRAINED_MATCHED_GENERATOR_VERSION_V1: u16 = 1;
pub const CONSTRAINED_MATCHED_GENERATOR_SEED_V1: u64 = 0x0014_4f47_4252_4945;
pub const CONSTRAINED_MATCHED_QUESTION_V1: &[u8] =
    b"why did request 550e8400-e29b-41d4-a716-446655440000 fail with database timeout?";
pub const CONSTRAINED_MATCHED_IDENTIFIER_V1: &[u8] = b"550e8400-e29b-41d4-a716-446655440000";

const GENERATOR_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-generator/v1";
const PREPARATION_CONTRACT_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-matched-case/v3\0generator-version=1\0public-only=true\0first-party=compiled-required\0first-party-subprocess=raw-stdin-through-captured-output\0parent-owned-render=byte-exact-oracle\0three-lane-selected-required\0drain=full-membership\0peak-rss=common-pinned-macos-time-l-direct-process\0cost-ordering=eligible-only-after-common-scope-observer-validation";
const SPLIT_IDENTITY_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-split/v1";
const LEAKAGE_IDENTITY_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-leakage/v1";
const PLAN_IDENTITY_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-plan/v1";
const RESULT_IDENTITY_V1: &[u8] = b"evidentrail/bench-harness/constrained-pinned-drain-result/v1";
const AUDIT_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/validated-three-lane-proposal-audit/v1";
const FINALIZED_CONSTRAINED_MATCHED_CASE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/finalized-constrained-pinned-drain-matched-case/v2";
const DISTRACTOR_RECORD_COUNT_V1: usize = 192;
const DISTRACTOR_FILLER_BYTES_V1: usize = 620;
const EXPECTED_RUNTIME_COUNT_V1: u64 = 4;
const EXPECTED_STREAM_COUNT_V1: u64 = 3;
const CONSTRAINED_TOKEN_BUDGET_V1: u64 = 180_000;
const CONSTRAINED_WALL_NANOS_V1: u64 = 20_000_000_000;
const CONSTRAINED_PEAK_BYTES_V1: u64 = 10_000_000_000;
const CONSTRAINED_EVENT_CAP_V1: u64 = 4_096;
const CONSTRAINED_SOURCE_BYTE_CAP_V1: u64 = 4 * 1024 * 1024;

// Frozen after the generator is finalized. Construction verifies it before
// either system executes.
pub const CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1: ArtifactDigest =
    ArtifactDigest::from_bytes([
        0xbf, 0x32, 0x9d, 0x44, 0xa0, 0x3d, 0x76, 0x54, 0xf6, 0x99, 0x6a, 0x4e, 0xec, 0x96, 0xa6,
        0xfb, 0x2c, 0xdd, 0x93, 0xd3, 0xdb, 0xdb, 0xfb, 0x25, 0xe1, 0xd6, 0x93, 0x0a, 0xbe, 0x01,
        0xfe, 0x0f,
    ]);

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy)]
enum RuntimeLaneV1 {
    PythonStderr,
    JvmStdout,
    RustStderr,
    GoLog,
}

impl RuntimeLaneV1 {
    const fn position(self) -> usize {
        match self {
            Self::PythonStderr => 0,
            Self::JvmStdout => 1,
            Self::RustStderr => 2,
            Self::GoLog => 3,
        }
    }

    const fn runtime_code(self) -> &'static str {
        match self {
            Self::PythonStderr => "python",
            Self::JvmStdout => "jvm",
            Self::RustStderr => "rust",
            Self::GoLog => "go",
        }
    }

    const fn member(self) -> &'static [u8] {
        match self {
            Self::PythonStderr => b"synthetic/python-api.py",
            Self::JvmStdout => b"synthetic/orders.jar",
            Self::RustStderr => b"synthetic/rust-worker",
            Self::GoLog => b"synthetic/go-cache",
        }
    }

    fn stream(self) -> SourceStream {
        match self {
            Self::PythonStderr | Self::RustStderr => SourceStream::Stderr,
            Self::JvmStdout => SourceStream::Stdout,
            Self::GoLog => SourceStream::LogStream,
        }
    }
}

struct GeneratedRecordV1 {
    lane: RuntimeLaneV1,
    lane_sequence: u64,
    payload: Vec<u8>,
    terminator: Vec<u8>,
}

struct GeneratedConstrainedCaseV1 {
    raw_input: Vec<u8>,
    ledger: EventLedger,
    record_count: u64,
    intact_failure_block_member_count: u64,
    input_artifact_digest: ArtifactDigest,
    generator_artifact_digest: ArtifactDigest,
}

/// Frozen public generator identity and independently checked output facts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConstrainedMatchedGeneratorReceiptV1 {
    generator_artifact_digest: ArtifactDigest,
    generator_version: u16,
    seed: u64,
    input_artifact_digest: ArtifactDigest,
    input_byte_count: u64,
    record_count: u64,
    runtime_count: u64,
    stream_count: u64,
    validated_identifier_count: u64,
    intact_failure_block_member_count: u64,
}

impl ConstrainedMatchedGeneratorReceiptV1 {
    #[must_use]
    pub const fn generator_artifact_digest(self) -> ArtifactDigest {
        self.generator_artifact_digest
    }

    #[must_use]
    pub const fn generator_version(self) -> u16 {
        self.generator_version
    }

    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    #[must_use]
    pub const fn input_artifact_digest(self) -> ArtifactDigest {
        self.input_artifact_digest
    }

    #[must_use]
    pub const fn input_byte_count(self) -> u64 {
        self.input_byte_count
    }

    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    #[must_use]
    pub const fn runtime_count(self) -> u64 {
        self.runtime_count
    }

    #[must_use]
    pub const fn stream_count(self) -> u64 {
        self.stream_count
    }

    #[must_use]
    pub const fn validated_identifier_count(self) -> u64 {
        self.validated_identifier_count
    }

    #[must_use]
    pub const fn intact_failure_block_member_count(self) -> u64 {
        self.intact_failure_block_member_count
    }
}

impl fmt::Debug for ConstrainedMatchedGeneratorReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedMatchedGeneratorReceiptV1")
            .field("generator_version", &self.generator_version)
            .field("seed_bound", &true)
            .field("input_artifact_bound", &true)
            .field("input_byte_count", &self.input_byte_count)
            .field("record_count", &self.record_count)
            .field("runtime_count", &self.runtime_count)
            .field("stream_count", &self.stream_count)
            .field(
                "validated_identifier_count",
                &self.validated_identifier_count,
            )
            .field(
                "intact_failure_block_member_count",
                &self.intact_failure_block_member_count,
            )
            .finish()
    }
}

/// A validated view of the production-selected proposal audit. It retains the
/// original product audit rather than reconstructing or synthesizing one.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedThreeLaneProposalAuditReceiptV1 {
    artifact_digest: ArtifactDigest,
    audit: ThreeLaneProposalAuditV1,
    exhaustive_primary_block_count: u64,
    exhaustive_unique_member_event_count: u64,
    exhaustive_member_source_bytes: u64,
    proposal_packet_count: u64,
    proposal_unique_member_event_count: u64,
    proposal_member_source_bytes: u64,
    retained_raw_nonproposal_block_count: u64,
    retained_raw_nonproposal_unique_member_event_count: u64,
    retained_raw_nonproposal_source_bytes: u64,
    proposal_affinity_count: u64,
    mandatory_proposal_count: u64,
    facet_count: u64,
    selected_packet_count: u64,
    selected_unique_member_event_count: u64,
    certification_packet_count: u64,
    validated_identifier_mandatory_reason_count: u64,
    validated_identifier_failure_block_selected: bool,
}

impl ValidatedThreeLaneProposalAuditReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn audit(&self) -> &ThreeLaneProposalAuditV1 {
        &self.audit
    }

    #[must_use]
    pub const fn proposal_packet_count(&self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn exhaustive_primary_block_count(&self) -> u64 {
        self.exhaustive_primary_block_count
    }

    #[must_use]
    pub const fn exhaustive_unique_member_event_count(&self) -> u64 {
        self.exhaustive_unique_member_event_count
    }

    #[must_use]
    pub const fn exhaustive_member_source_bytes(&self) -> u64 {
        self.exhaustive_member_source_bytes
    }

    #[must_use]
    pub const fn proposal_unique_member_event_count(&self) -> u64 {
        self.proposal_unique_member_event_count
    }

    #[must_use]
    pub const fn proposal_member_source_bytes(&self) -> u64 {
        self.proposal_member_source_bytes
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_block_count(&self) -> u64 {
        self.retained_raw_nonproposal_block_count
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_unique_member_event_count(&self) -> u64 {
        self.retained_raw_nonproposal_unique_member_event_count
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_source_bytes(&self) -> u64 {
        self.retained_raw_nonproposal_source_bytes
    }

    #[must_use]
    pub const fn proposal_affinity_count(&self) -> u64 {
        self.proposal_affinity_count
    }

    #[must_use]
    pub const fn mandatory_proposal_count(&self) -> u64 {
        self.mandatory_proposal_count
    }

    #[must_use]
    pub const fn facet_count(&self) -> u64 {
        self.facet_count
    }

    #[must_use]
    pub const fn selected_packet_count(&self) -> u64 {
        self.selected_packet_count
    }

    #[must_use]
    pub const fn selected_unique_member_event_count(&self) -> u64 {
        self.selected_unique_member_event_count
    }

    #[must_use]
    pub const fn certification_packet_count(&self) -> u64 {
        self.certification_packet_count
    }

    #[must_use]
    pub const fn validated_identifier_mandatory_reason_count(&self) -> u64 {
        self.validated_identifier_mandatory_reason_count
    }

    #[must_use]
    pub const fn validated_identifier_failure_block_selected(&self) -> bool {
        self.validated_identifier_failure_block_selected
    }
}

impl fmt::Debug for ValidatedThreeLaneProposalAuditReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedThreeLaneProposalAuditReceiptV1")
            .field("production_audit_state", &self.audit.code())
            .field("input_receipt_bound", &true)
            .field("proposal_universe_receipt_bound", &true)
            .field(
                "exhaustive_primary_block_count",
                &self.exhaustive_primary_block_count,
            )
            .field(
                "exhaustive_unique_member_event_count",
                &self.exhaustive_unique_member_event_count,
            )
            .field("proposal_packet_count", &self.proposal_packet_count)
            .field(
                "proposal_unique_member_event_count",
                &self.proposal_unique_member_event_count,
            )
            .field(
                "retained_raw_nonproposal_block_count",
                &self.retained_raw_nonproposal_block_count,
            )
            .field(
                "retained_raw_nonproposal_unique_member_event_count",
                &self.retained_raw_nonproposal_unique_member_event_count,
            )
            .field("proposal_affinity_count", &self.proposal_affinity_count)
            .field("mandatory_proposal_count", &self.mandatory_proposal_count)
            .field("facet_count", &self.facet_count)
            .field("selected_packet_count", &self.selected_packet_count)
            .field(
                "selected_unique_member_event_count",
                &self.selected_unique_member_event_count,
            )
            .field(
                "certification_packet_count",
                &self.certification_packet_count,
            )
            .field(
                "validated_identifier_mandatory_reason_count",
                &self.validated_identifier_mandatory_reason_count,
            )
            .field(
                "validated_identifier_failure_block_selected",
                &self.validated_identifier_failure_block_selected,
            )
            .field("product_artifact_bound", &true)
            .finish()
    }
}

/// Second, constrained matched preparation. It is constructible only from an
/// actual compiled product result with a complete selected producer audit.
pub struct PreparedConstrainedPinnedDrainMatchedCaseV1 {
    inner: PreparedPinnedDrainMatchedCaseV1,
    generator: ConstrainedMatchedGeneratorReceiptV1,
    proposal_audit: ValidatedThreeLaneProposalAuditReceiptV1,
    first_party_subprocess: FirstPartyConstrainedSubprocessReceiptV1,
}

impl PreparedConstrainedPinnedDrainMatchedCaseV1 {
    #[must_use]
    pub const fn generator(&self) -> ConstrainedMatchedGeneratorReceiptV1 {
        self.generator
    }

    #[must_use]
    pub const fn proposal_audit(&self) -> &ValidatedThreeLaneProposalAuditReceiptV1 {
        &self.proposal_audit
    }

    #[must_use]
    pub const fn public_case(&self) -> &EvidentrailBenchCaseSpecV1 {
        self.inner.public_case()
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.inner.public_case_artifact_digest()
    }

    #[must_use]
    pub const fn ledger(&self) -> &EventLedger {
        self.inner.ledger()
    }

    #[must_use]
    pub const fn first_party_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        self.inner.first_party_manifest()
    }

    #[must_use]
    pub const fn drain_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        self.inner.drain_manifest()
    }

    #[must_use]
    pub const fn first_party_case_input(&self) -> &PublicCaseInputBindingV1 {
        self.inner.first_party_case_input()
    }

    #[must_use]
    pub const fn first_party_method(&self) -> MethodDescriptor {
        self.inner.first_party_method()
    }

    #[must_use]
    pub const fn first_party_subprocess_receipt(
        &self,
    ) -> &FirstPartyConstrainedSubprocessReceiptV1 {
        &self.first_party_subprocess
    }

    #[must_use]
    pub const fn drain_full_membership(&self) -> &crate::LegacyDrainFullMembershipArtifactV1 {
        self.inner.drain_full_membership()
    }

    #[must_use]
    pub fn first_party_rendered_artifact_digest(&self) -> ArtifactDigest {
        self.inner.first_party_rendered_artifact_digest()
    }

    #[must_use]
    pub const fn first_party_wall_time_nanos(&self) -> u64 {
        self.inner.first_party_wall_time_nanos()
    }

    #[must_use]
    pub const fn first_party_token_provenance(&self) -> crate::CanonicalTokenCountProvenanceV1 {
        self.inner.first_party_token_provenance()
    }

    #[must_use]
    pub const fn drain_token_provenance(&self) -> crate::CanonicalTokenCountProvenanceV1 {
        self.inner.drain_token_provenance()
    }

    #[must_use]
    pub const fn drain_invocation(&self) -> &crate::PublicSubprocessInvocationV1 {
        self.inner.drain_invocation()
    }

    #[must_use]
    pub const fn drain_execution(&self) -> &crate::SubprocessExecutionReceiptV1 {
        self.inner.drain_execution()
    }

    #[must_use]
    pub const fn drain_target_class(&self) -> crate::PinnedLegacyDrainTargetClassV1 {
        self.inner.drain_target_class()
    }

    #[must_use]
    pub const fn first_party_peak_rss_observer_receipt(&self) -> MacOsTimePeakRssReceiptV1 {
        self.first_party_subprocess.peak_rss_observer_receipt()
    }

    #[must_use]
    pub const fn drain_peak_rss_observer_receipt(&self) -> Option<MacOsTimePeakRssReceiptV1> {
        self.inner.drain_peak_rss_observer_receipt()
    }

    #[must_use]
    pub const fn first_party_proposal_audit_available(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn drain_proposal_audit_available(&self) -> bool {
        false
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
    pub const fn contains_downstream_vds_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn representation_quality_scoreable(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn cost_comparison_eligibility(&self) -> MatchedCostComparisonEligibilityV1 {
        MatchedCostComparisonEligibilityV1::common_process_scope_and_peak_rss_observer_v1()
    }

    pub fn peak_rss_observation_binding(
        &self,
        arm: PinnedDrainMatchedArmV1,
    ) -> Result<PeakRssObservationBindingV1, ConstrainedMatchedCaseErrorV1> {
        self.inner
            .peak_rss_observation_binding(arm)
            .map_err(Into::into)
    }

    pub fn try_finalize(
        &self,
    ) -> Result<FinalizedConstrainedPinnedDrainMatchedCaseV1, ConstrainedMatchedCaseErrorV1> {
        let first_observer_receipt = self.first_party_peak_rss_observer_receipt();
        let drain_observer_receipt = self
            .drain_peak_rss_observer_receipt()
            .ok_or(ConstrainedMatchedCaseErrorV1::PeakRssObserverMismatch)?;
        if first_observer_receipt.measurement_mechanism_artifact_digest()
            != drain_observer_receipt.measurement_mechanism_artifact_digest()
            || first_observer_receipt.observer_executable_build_artifact_digest()
                != drain_observer_receipt.observer_executable_build_artifact_digest()
            || first_observer_receipt.report_format_artifact_digest()
                != drain_observer_receipt.report_format_artifact_digest()
            || first_observer_receipt.unit() != drain_observer_receipt.unit()
        {
            return Err(ConstrainedMatchedCaseErrorV1::PeakRssObserverMismatch);
        }
        let observations = [
            first_observer_receipt.observation(),
            drain_observer_receipt.observation(),
        ];
        let finalized = self.inner.try_finalize(&observations)?;
        if finalized
            .first_party_peak_rss()
            .measurement_mechanism_artifact_digest()
            != finalized
                .drain_peak_rss()
                .measurement_mechanism_artifact_digest()
            || finalized.first_party_peak_rss().unit() != finalized.drain_peak_rss().unit()
        {
            return Err(ConstrainedMatchedCaseErrorV1::PeakRssObserverMismatch);
        }
        let artifact_digest = derive_finalized_constrained_artifact_digest_v1(
            finalized.artifact_digest(),
            self.generator.generator_artifact_digest,
            self.generator.input_artifact_digest,
            self.proposal_audit.artifact_digest,
            self.first_party_subprocess.artifact_digest(),
            self.cost_comparison_eligibility(),
        )?;
        Ok(FinalizedConstrainedPinnedDrainMatchedCaseV1 {
            artifact_digest,
            finalized,
            generator: self.generator,
            proposal_audit: self.proposal_audit.clone(),
            first_party_subprocess: self.first_party_subprocess.clone(),
        })
    }
}

impl fmt::Debug for PreparedConstrainedPinnedDrainMatchedCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedConstrainedPinnedDrainMatchedCaseV1")
            .field("generator", &self.generator)
            .field("proposal_audit", &self.proposal_audit)
            .field("compiled_product_required", &true)
            .field("first_party_subprocess", &self.first_party_subprocess)
            .field("full_membership_drain_present", &true)
            .field("peak_rss_present", &true)
            .field("cost_comparison", &self.cost_comparison_eligibility())
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("contains_downstream_vds_outcome", &false)
            .field("representation_quality_scoreable", &false)
            .finish()
    }
}

pub struct FinalizedConstrainedPinnedDrainMatchedCaseV1 {
    artifact_digest: ArtifactDigest,
    finalized: FinalizedPinnedDrainMatchedCaseV1,
    generator: ConstrainedMatchedGeneratorReceiptV1,
    proposal_audit: ValidatedThreeLaneProposalAuditReceiptV1,
    first_party_subprocess: FirstPartyConstrainedSubprocessReceiptV1,
}

impl FinalizedConstrainedPinnedDrainMatchedCaseV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn first_party_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        self.finalized.first_party_manifest()
    }

    #[must_use]
    pub const fn drain_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        self.finalized.drain_manifest()
    }

    #[must_use]
    pub const fn first_party_receipt(&self) -> &crate::FirstPartyLogBriefRepresentationReceiptV1 {
        self.finalized.first_party_receipt()
    }

    #[must_use]
    pub const fn drain_receipt(&self) -> &crate::LegacyDrainFullMembershipRepresentationReceiptV1 {
        self.finalized.drain_receipt()
    }

    #[must_use]
    pub const fn first_party_peak_rss(&self) -> BoundPeakRssObservationV1 {
        self.finalized.first_party_peak_rss()
    }

    #[must_use]
    pub const fn drain_peak_rss(&self) -> BoundPeakRssObservationV1 {
        self.finalized.drain_peak_rss()
    }

    #[must_use]
    pub const fn generator(&self) -> ConstrainedMatchedGeneratorReceiptV1 {
        self.generator
    }

    #[must_use]
    pub const fn proposal_audit(&self) -> &ValidatedThreeLaneProposalAuditReceiptV1 {
        &self.proposal_audit
    }

    #[must_use]
    pub const fn first_party_subprocess_receipt(
        &self,
    ) -> &FirstPartyConstrainedSubprocessReceiptV1 {
        &self.first_party_subprocess
    }

    #[must_use]
    pub const fn first_party_proposal_audit_available(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn drain_proposal_audit_available(&self) -> bool {
        false
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
    pub const fn contains_downstream_vds_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn representation_quality_scoreable(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn cost_comparison_eligibility(&self) -> MatchedCostComparisonEligibilityV1 {
        MatchedCostComparisonEligibilityV1::common_process_scope_and_peak_rss_observer_v1()
    }
}

impl fmt::Debug for FinalizedConstrainedPinnedDrainMatchedCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedConstrainedPinnedDrainMatchedCaseV1")
            .field("generator", &self.generator)
            .field("proposal_audit", &self.proposal_audit)
            .field("first_party_subprocess", &self.first_party_subprocess)
            .field("constrained_artifact_bound", &true)
            .field("peak_rss_bound", &true)
            .field("cost_comparison", &self.cost_comparison_eligibility())
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("contains_downstream_vds_outcome", &false)
            .field("representation_quality_scoreable", &false)
            .finish()
    }
}

/// Prepare one frozen-case process-envelope comparison. The first-party child
/// accepts only the exact generated public bytes and reconstructs this case's
/// specified mixed-lane ledger before calling `MemoryProductV1`; this is not a
/// general raw-log parser or acquisition-parity claim.
pub fn prepare_constrained_pinned_drain_matched_case_v1(
    first_party_target: FirstPartyConstrainedSubprocessTargetV1,
    drain_target: PinnedLegacyDrainExecutionTargetV1,
) -> Result<PreparedConstrainedPinnedDrainMatchedCaseV1, ConstrainedMatchedCaseErrorV1> {
    let peak_rss_observer = MacOsTimePeakRssObserverV1::try_system_v1()
        .map_err(PreparedPinnedDrainMatchedCaseErrorV1::from)?;
    prepare_constrained_pinned_drain_matched_case_with_observer_v1(
        first_party_target,
        drain_target,
        &peak_rss_observer,
    )
}

pub(crate) fn prepare_constrained_pinned_drain_matched_case_with_observer_v1(
    first_party_target: FirstPartyConstrainedSubprocessTargetV1,
    drain_target: PinnedLegacyDrainExecutionTargetV1,
    peak_rss_observer: &MacOsTimePeakRssObserverV1,
) -> Result<PreparedConstrainedPinnedDrainMatchedCaseV1, ConstrainedMatchedCaseErrorV1> {
    let parent_oracle_build = FirstPartyParentOracleBuildV1::capture_current_process_v1()?;
    let plan_digest = constrained_plan_digest();
    let generated = generate_constrained_case_v1(plan_digest)?;
    if generated.input_artifact_digest != CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1 {
        return Err(ConstrainedMatchedCaseErrorV1::InputArtifactMismatch);
    }
    let input_byte_count = u64::try_from(generated.raw_input.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let generator = ConstrainedMatchedGeneratorReceiptV1 {
        generator_artifact_digest: generated.generator_artifact_digest,
        generator_version: CONSTRAINED_MATCHED_GENERATOR_VERSION_V1,
        seed: CONSTRAINED_MATCHED_GENERATOR_SEED_V1,
        input_artifact_digest: generated.input_artifact_digest,
        input_byte_count,
        record_count: generated.record_count,
        runtime_count: EXPECTED_RUNTIME_COUNT_V1,
        stream_count: EXPECTED_STREAM_COUNT_V1,
        validated_identifier_count: 1,
        intact_failure_block_member_count: generated.intact_failure_block_member_count,
    };
    let budget = constrained_budget()?;
    let first_party_build = first_party_target.first_party_build()?;
    let mut inner = prepare_matched_case_v1(
        MatchedCasePreparationV1 {
            preparation_contract_artifact_digest: artifact_digest_for_bytes_v1(
                PREPARATION_CONTRACT_V1,
            ),
            raw_input: &generated.raw_input,
            question: CONSTRAINED_MATCHED_QUESTION_V1,
            plan_digest,
            split_artifact_digest: artifact_digest_for_bytes_v1(SPLIT_IDENTITY_V1),
            leakage_artifact_digest: artifact_digest_for_bytes_v1(LEAKAGE_IDENTITY_V1),
            result_id: constrained_result_id(),
            seed: CONSTRAINED_MATCHED_GENERATOR_SEED_V1,
            budget,
            ledger: generated.ledger,
        },
        first_party_build,
        drain_target,
        Some(peak_rss_observer),
    )?;
    let (proposal_audit, independently_validated_owned_render) = {
        let compiled = inner
            .compiled_product_output()
            .ok_or(ConstrainedMatchedCaseErrorV1::FirstPartyNotCompiled)?;
        (
            validate_three_lane_audit_v1(compiled, inner.ledger())?,
            compiled.artifact().text().as_bytes().to_vec(),
        )
    };
    parent_oracle_build.reverify()?;
    let first_party_peak_rss_binding =
        inner.peak_rss_observation_binding(PinnedDrainMatchedArmV1::FirstParty)?;
    let first_party_subprocess = execute_and_freeze_constrained_first_party_subprocess_v1(
        inner.first_party_manifest(),
        inner.first_party_case_input().clone(),
        &first_party_target,
        &parent_oracle_build,
        &independently_validated_owned_render,
        peak_rss_observer,
        first_party_peak_rss_binding,
    )?;
    let drain_peak_rss_observer_receipt = inner
        .drain_peak_rss_observer_receipt()
        .ok_or(ConstrainedMatchedCaseErrorV1::PeakRssObserverMismatch)?;
    if first_party_subprocess
        .peak_rss_observer_receipt()
        .measurement_mechanism_artifact_digest()
        != drain_peak_rss_observer_receipt.measurement_mechanism_artifact_digest()
        || first_party_subprocess
            .peak_rss_observer_receipt()
            .report_format_artifact_digest()
            != drain_peak_rss_observer_receipt.report_format_artifact_digest()
    {
        return Err(ConstrainedMatchedCaseErrorV1::PeakRssObserverMismatch);
    }
    if first_party_subprocess.invocation().program().environment()
        != inner.drain_invocation().program().environment()
        || first_party_subprocess.stdin_artifact_digest()
            != inner.drain_invocation().stdin().artifact_digest()
        || first_party_subprocess.invocation().limits().wall_nanos()
            != inner.drain_invocation().limits().wall_nanos()
        || first_party_subprocess.invocation().case_resolution_trust()
            != inner.drain_invocation().case_resolution_trust()
    {
        return Err(ConstrainedMatchedCaseErrorV1::CommonExecutionScopeMismatch);
    }
    if first_party_subprocess
        .peak_rss_observer_receipt()
        .peak_rss_bytes()
        > inner
            .first_party_manifest()
            .identity()
            .budget()
            .peak_memory_bytes()
        || drain_peak_rss_observer_receipt.peak_rss_bytes()
            > inner
                .drain_manifest()
                .identity()
                .budget()
                .peak_memory_bytes()
    {
        return Err(ConstrainedMatchedCaseErrorV1::PeakRssBudgetExceeded);
    }
    inner.bind_first_party_subprocess_measurement_v1(
        first_party_subprocess.artifact_digest(),
        first_party_subprocess.execution().wall_time_nanos(),
    )?;
    Ok(PreparedConstrainedPinnedDrainMatchedCaseV1 {
        inner,
        generator,
        proposal_audit,
        first_party_subprocess,
    })
}

/// Execute the frozen constrained case through the actual product API inside
/// the benchmark helper. The caller supplies only exact raw public bytes; no
/// annotation or hidden requirement type is accepted.
#[doc(hidden)]
pub fn execute_constrained_first_party_fixture_v1(
    raw_input: &[u8],
) -> Result<Vec<u8>, ConstrainedMatchedCaseErrorV1> {
    let compiled = execute_constrained_first_party_structured_fixture_v1(raw_input)?;
    Ok(compiled.artifact().text().as_bytes().to_vec())
}

/// Execute the same frozen public fixture while retaining the actual owned
/// structured product result for benchmark-only representation challengers.
/// No canonical text parsing, annotation, or governed requirement enters this
/// boundary.
#[doc(hidden)]
pub fn execute_constrained_first_party_structured_fixture_v1(
    raw_input: &[u8],
) -> Result<CompiledProductResultV1, ConstrainedMatchedCaseErrorV1> {
    if artifact_digest_for_bytes_v1(raw_input) != CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1 {
        return Err(ConstrainedMatchedCaseErrorV1::InputArtifactMismatch);
    }
    let expected = constrained_pinned_drain_public_input_v1()?;
    if raw_input != expected {
        return Err(ConstrainedMatchedCaseErrorV1::GeneratorInvariant);
    }
    let plan_digest = constrained_plan_digest();
    let generated = generate_constrained_case_v1(plan_digest)?;
    if generated.raw_input != raw_input {
        return Err(ConstrainedMatchedCaseErrorV1::GeneratorInvariant);
    }
    let budget = constrained_budget()?;
    let validation_ledger = generated.ledger.clone();
    let mut owner = MemoryProductV1::new();
    let decision = owner
        .create_deterministic_result_v1(
            constrained_result_id(),
            CONSTRAINED_MATCHED_QUESTION_V1,
            generated.ledger,
            UnixTimestampNanos::new(1),
            budget.canonical_candidate_tokens(),
        )
        .map_err(|_| ConstrainedMatchedCaseErrorV1::ProductExecutionFailed)?;
    let compiled = match decision {
        DeterministicProductDecisionV1::Compiled(compiled) => compiled,
        DeterministicProductDecisionV1::Passthrough(_)
        | DeterministicProductDecisionV1::NeedsMore(_) => {
            return Err(ConstrainedMatchedCaseErrorV1::FirstPartyNotCompiled);
        }
    };
    validate_three_lane_audit_v1(&compiled, &validation_ledger)?;
    Ok(*compiled)
}

/// Exact generated public stdin bytes. No annotation is consulted.
pub fn constrained_pinned_drain_public_input_v1() -> Result<Vec<u8>, ConstrainedMatchedCaseErrorV1>
{
    Ok(generate_records_v1()?.1)
}

/// Label-free public case specification for the exact constrained fixture.
/// This is derived from the same frozen source, question, plan, budget, split,
/// and leakage identities used by the matched subprocess preparation.
pub fn constrained_pinned_drain_public_case_v1()
-> Result<EvidentrailBenchCaseSpecV1, ConstrainedMatchedCaseErrorV1> {
    let raw_input = constrained_pinned_drain_public_input_v1()?;
    let budget = constrained_budget()?;
    EvidentrailBenchCaseSpecV1::new(
        [artifact_digest_for_bytes_v1(&raw_input)],
        derive_question_digest_v1(CONSTRAINED_MATCHED_QUESTION_V1),
        constrained_plan_digest(),
        [artifact_digest_for_bytes_v1(SPLIT_IDENTITY_V1)],
        [artifact_digest_for_bytes_v1(LEAKAGE_IDENTITY_V1)],
        [budget.cap()],
        evidentrail_bench::ExpectedAcquisitionClassV1::Complete,
    )
    .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)
}

#[must_use]
pub fn constrained_pinned_drain_plan_digest_v1() -> PlanDigest {
    constrained_plan_digest()
}

fn constrained_plan_digest() -> PlanDigest {
    PlanDigest::from_bytes(*artifact_digest_for_bytes_v1(PLAN_IDENTITY_V1).as_bytes())
}

fn constrained_result_id() -> ResultId {
    ResultId::from_bytes(*artifact_digest_for_bytes_v1(RESULT_IDENTITY_V1).as_bytes())
}

fn constrained_budget() -> Result<BenchmarkBudgetV1, ConstrainedMatchedCaseErrorV1> {
    BenchmarkBudgetV1::try_new(
        Some(CONSTRAINED_EVENT_CAP_V1),
        Some(CONSTRAINED_SOURCE_BYTE_CAP_V1),
        Some(CONSTRAINED_TOKEN_BUDGET_V1),
        Some(CONSTRAINED_WALL_NANOS_V1),
        Some(CONSTRAINED_PEAK_BYTES_V1),
    )
    .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)
}

fn generate_constrained_case_v1(
    plan_digest: PlanDigest,
) -> Result<GeneratedConstrainedCaseV1, ConstrainedMatchedCaseErrorV1> {
    validate_question_identifier_v1()?;
    let (records, raw_input) = generate_records_v1()?;
    let input_artifact_digest = artifact_digest_for_bytes_v1(&raw_input);
    let ledger = ledger_from_records_v1(plan_digest, &records, &raw_input)?;
    let intact_failure_block_member_count =
        u64::try_from(validate_intact_failure_block_v1(&ledger)?.member_ids.len())
            .map_err(|_| ConstrainedMatchedCaseErrorV1::FailureBlockInvariant)?;
    let record_count = u64::try_from(records.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let generator_artifact_digest = derive_generator_artifact_digest_v1(
        input_artifact_digest,
        u64::try_from(raw_input.len())
            .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?,
        record_count,
        intact_failure_block_member_count,
    )?;
    Ok(GeneratedConstrainedCaseV1 {
        raw_input,
        ledger,
        record_count,
        intact_failure_block_member_count,
        input_artifact_digest,
        generator_artifact_digest,
    })
}

fn validate_question_identifier_v1() -> Result<(), ConstrainedMatchedCaseErrorV1> {
    let query = preprocess_query_v1(CONSTRAINED_MATCHED_QUESTION_V1)
        .map_err(|_| ConstrainedMatchedCaseErrorV1::QuestionIdentifierInvariant)?;
    if query.identifiers().len() != 1
        || query.identifiers()[0].kind() != ValidatedIdentifierKindV1::CanonicalUuid
        || query.identifiers()[0].canonical_token() != CONSTRAINED_MATCHED_IDENTIFIER_V1
    {
        return Err(ConstrainedMatchedCaseErrorV1::QuestionIdentifierInvariant);
    }
    Ok(())
}

fn generate_records_v1() -> Result<(Vec<GeneratedRecordV1>, Vec<u8>), ConstrainedMatchedCaseErrorV1>
{
    let mut records = Vec::with_capacity(DISTRACTOR_RECORD_COUNT_V1 + 8);
    let mut lane_sequences = [0_u64; 4];
    push_record(
        &mut records,
        &mut lane_sequences,
        RuntimeLaneV1::GoLog,
        format!(
            "2026-08-24T12:00:00Z INFO evidentrail-bench constrained-generator-v1 seed={CONSTRAINED_MATCHED_GENERATOR_SEED_V1} runtimes=python,jvm,rust,go"
        )
        .into_bytes(),
        b"\n".to_vec(),
    )?;

    let mut state = CONSTRAINED_MATCHED_GENERATOR_SEED_V1;
    for ordinal in 0..DISTRACTOR_RECORD_COUNT_V1 {
        if ordinal == 48 {
            push_record(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::PythonStderr,
                b"Traceback (most recent call last):".to_vec(),
                b"\n".to_vec(),
            )?;
            push_distractor(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::JvmStdout,
                10_000,
                next_state(&mut state),
            )?;
            push_record(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::PythonStderr,
                b"  File \"/srv/api/checkout.py\", line 417, in reserve_inventory".to_vec(),
                b"\n".to_vec(),
            )?;
            push_distractor(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::RustStderr,
                10_001,
                next_state(&mut state),
            )?;
            push_record(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::PythonStderr,
                b"    await database.reserve(order_id)".to_vec(),
                b"\n".to_vec(),
            )?;
            push_distractor(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::GoLog,
                10_002,
                next_state(&mut state),
            )?;
            let mut terminal = b"RuntimeError: database timeout request_id=".to_vec();
            terminal.extend_from_slice(CONSTRAINED_MATCHED_IDENTIFIER_V1);
            push_record(
                &mut records,
                &mut lane_sequences,
                RuntimeLaneV1::PythonStderr,
                terminal,
                b"\n".to_vec(),
            )?;
        }

        let lane = match ordinal % 3 {
            0 => RuntimeLaneV1::JvmStdout,
            1 => RuntimeLaneV1::RustStderr,
            _ => RuntimeLaneV1::GoLog,
        };
        push_distractor(
            &mut records,
            &mut lane_sequences,
            lane,
            ordinal,
            next_state(&mut state),
        )?;
    }
    let last = records
        .last_mut()
        .ok_or(ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    last.terminator.clear();

    let mut raw_input = Vec::new();
    for record in &records {
        raw_input.extend_from_slice(&record.payload);
        raw_input.extend_from_slice(&record.terminator);
    }
    Ok((records, raw_input))
}

fn push_distractor(
    records: &mut Vec<GeneratedRecordV1>,
    lane_sequences: &mut [u64; 4],
    lane: RuntimeLaneV1,
    ordinal: usize,
    state: u64,
) -> Result<(), ConstrainedMatchedCaseErrorV1> {
    let minute = (ordinal / 60) % 60;
    let second = ordinal % 60;
    let level = if ordinal % 19 == 0 { "WARN" } else { "INFO" };
    let mut payload = format!(
        "2026-08-24T12:{minute:02}:{second:02}Z {level} runtime={} evidentrail-bench constrained-generator-v1 heartbeat ordinal={ordinal:05} shard={:03} cycle={:08x} filler=",
        lane.runtime_code(),
        state % 97,
        state as u32,
    )
    .into_bytes();
    let filler = match lane {
        RuntimeLaneV1::PythonStderr => b'p',
        RuntimeLaneV1::JvmStdout => b'j',
        RuntimeLaneV1::RustStderr => b'r',
        RuntimeLaneV1::GoLog => b'g',
    };
    payload.resize(payload.len() + DISTRACTOR_FILLER_BYTES_V1, filler);
    payload.extend_from_slice(format!(" end={:016x}", state.rotate_left(17)).as_bytes());
    let terminator = if ordinal % 17 == 0 {
        b"\r\n".to_vec()
    } else {
        b"\n".to_vec()
    };
    push_record(records, lane_sequences, lane, payload, terminator)
}

fn push_record(
    records: &mut Vec<GeneratedRecordV1>,
    lane_sequences: &mut [u64; 4],
    lane: RuntimeLaneV1,
    payload: Vec<u8>,
    terminator: Vec<u8>,
) -> Result<(), ConstrainedMatchedCaseErrorV1> {
    let position = lane.position();
    let lane_sequence = lane_sequences[position];
    lane_sequences[position] = lane_sequence
        .checked_add(1)
        .ok_or(ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    records.push(GeneratedRecordV1 {
        lane,
        lane_sequence,
        payload,
        terminator,
    });
    Ok(())
}

fn next_state(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn ledger_from_records_v1(
    plan_digest: PlanDigest,
    records: &[GeneratedRecordV1],
    raw_input: &[u8],
) -> Result<EventLedger, ConstrainedMatchedCaseErrorV1> {
    let retrieval_id = RetrievalId::from_bytes([0x61; 32]);
    let plan_id = PlanId::from_bytes([0x62; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x63; 32]);
    let adapter = AdapterIdentity::new("constrained-matched-generator", "1")
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_byte_count = 0_u64;
    let mut lanes = BTreeSet::new();
    for (position, record) in records.iter().enumerate() {
        let acquisition_sequence = u64::try_from(position)
            .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
        let lane = LaneKey::new(
            SourceMember::new(record.lane.member().to_vec())
                .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?,
            record.lane.stream(),
        );
        lanes.insert(lane.clone());
        payload_byte_count = payload_byte_count
            .checked_add(
                u64::try_from(record.payload.len())
                    .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?,
            )
            .ok_or(ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(acquisition_sequence),
                    lane,
                    LaneSequence::new(record.lane_sequence),
                ),
                RecordBytes::framed(record.payload.clone(), record.terminator.clone()),
                RecordState::Complete,
            ))
            .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    }
    let record_count = u64::try_from(records.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let source_byte_count = u64::try_from(raw_input.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let lane_count = u64::try_from(lanes.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, payload_byte_count, source_byte_count),
        AttemptCounts::new(lane_count, lane_count),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 84,
        }),
    )
    .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    builder
        .seal(completion)
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)
}

struct FailureBlockFactsV1 {
    block_id: BlockId,
    member_ids: Vec<EventId>,
}

fn validate_intact_failure_block_v1(
    ledger: &EventLedger,
) -> Result<FailureBlockFactsV1, ConstrainedMatchedCaseErrorV1> {
    let blocks = frame_source_lanes_v1(ledger)
        .map_err(|_| ConstrainedMatchedCaseErrorV1::FailureBlockInvariant)?;
    let mut matching = blocks
        .blocks()
        .iter()
        .filter(|block| block.state() == BlockState::Reconstructed)
        .filter_map(|block| {
            blocks
                .expand_block(block.id())
                .ok()
                .map(|expansion| (block.id(), expansion))
        })
        .filter(|(_, expansion)| {
            expansion.events().iter().any(|event| {
                event
                    .payload()
                    .windows(CONSTRAINED_MATCHED_IDENTIFIER_V1.len())
                    .any(|window| window == CONSTRAINED_MATCHED_IDENTIFIER_V1)
            })
        });
    let (block_id, expansion) = matching
        .next()
        .ok_or(ConstrainedMatchedCaseErrorV1::FailureBlockInvariant)?;
    if matching.next().is_some()
        || expansion.events().len() != 4
        || expansion.events().windows(2).any(|events| {
            events[0].lane_sequence().get().checked_add(1) != Some(events[1].lane_sequence().get())
        })
    {
        return Err(ConstrainedMatchedCaseErrorV1::FailureBlockInvariant);
    }
    Ok(FailureBlockFactsV1 {
        block_id,
        member_ids: expansion.events().iter().map(|event| event.id()).collect(),
    })
}

fn validate_three_lane_audit_v1(
    compiled: &CompiledProductResultV1,
    ledger: &EventLedger,
) -> Result<ValidatedThreeLaneProposalAuditReceiptV1, ConstrainedMatchedCaseErrorV1> {
    let audit = compiled
        .proposal_audit()
        .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAuditMissing)?;
    if audit.code() != "selected" || audit.reason().is_some() {
        return Err(ConstrainedMatchedCaseErrorV1::ProposalAuditNotSelected);
    }
    let selected_packet_ids = audit
        .selected_packet_ids()
        .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAuditNotSelected)?;
    let prepared = audit
        .prepared()
        .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAuditNotSelected)?;
    let receipt = audit
        .receipt()
        .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAuditNotSelected)?;
    let input = audit.input();
    let brief = compiled.artifact().brief();
    let cost = brief.cost();
    if selected_packet_ids.is_empty()
        || prepared.proposal_packets().is_empty()
        || prepared.receipt() != receipt
        || receipt.input() != input
        || input.result_id() != compiled.result_id()
        || input.question_digest() != brief.question_digest()
        || input.question_digest() != derive_question_digest_v1(CONSTRAINED_MATCHED_QUESTION_V1)
        || input.retrieval_id() != ledger.retrieval_id()
        || input.plan_id() != ledger.plan_id()
        || input.plan_digest() != ledger.plan_digest()
        || input.plan_digest() != brief.plan_digest()
        || input.source_identity_digest() != ledger.source_identity_digest()
        || input.acquisition_receipt_id() != ledger.acquisition_receipt_id()
        || input.renderer_digest() != cost.renderer_digest()
        || input.tokenizer_digest() != cost.tokenizer_digest()
        || receipt.cost_model() != Some(cost.cost_model())
        || !cost.is_additive_bound_certified()
    {
        return Err(ConstrainedMatchedCaseErrorV1::ProposalAuditBindingMismatch);
    }

    let certification = prepared
        .certification()
        .ok_or(ConstrainedMatchedCaseErrorV1::ProposalCertificationMismatch)?;
    let accounting = receipt.accounting();
    let mut proposal_ids = Vec::with_capacity(prepared.proposal_packets().len());
    let mut proposal_event_ids = BTreeSet::new();
    let mut proposal_member_source_bytes = 0_u64;
    let mut proposal_affinity_count = 0_u64;
    for packet in prepared.proposal_packets() {
        proposal_ids.push(packet.id());
        let metadata = prepared
            .proposal_metadata(packet.id())
            .ok_or(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch)?;
        let mut metadata_members = metadata.ordered_event_ids().to_vec();
        metadata_members.sort_unstable();
        if metadata_members != packet.event_ids()
            || certification
                .packet_cost(packet.id(), packet.event_ids())
                .ok()
                != Some(packet.composable_token_upper_bound())
        {
            return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
        }
        proposal_affinity_count = proposal_affinity_count
            .checked_add(checked_count_v1(packet.affinities().len())?)
            .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
        for event_id in packet.event_ids() {
            if !proposal_event_ids.insert(*event_id) {
                return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
            }
            proposal_member_source_bytes = proposal_member_source_bytes
                .checked_add(event_source_bytes_v1(ledger, *event_id)?)
                .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
        }
    }
    proposal_ids.sort_unstable();
    if proposal_ids.windows(2).any(|pair| pair[0] == pair[1])
        || certification.packet_bounds().len() != proposal_ids.len()
        || certification
            .packet_bounds()
            .iter()
            .map(|bound| bound.packet_id())
            .ne(proposal_ids.iter().copied())
    {
        return Err(ConstrainedMatchedCaseErrorV1::ProposalCertificationMismatch);
    }

    let proposal_id_set = proposal_ids.iter().copied().collect::<BTreeSet<_>>();
    let fresh_blocks = frame_source_lanes_v1(ledger)
        .map_err(|_| ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch)?;
    let mut fresh_block_members = BTreeMap::new();
    for block in fresh_blocks.blocks() {
        if fresh_block_members
            .insert(block.id(), block.member_ids().to_vec())
            .is_some()
        {
            return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
        }
    }
    let mut metadata_block_members = BTreeMap::new();
    let mut metadata_packet_ids = BTreeSet::new();
    let mut exhaustive_event_ids = BTreeSet::new();
    let mut retained_raw_event_ids = BTreeSet::new();
    let mut exhaustive_member_source_bytes = 0_u64;
    let mut retained_raw_nonproposal_source_bytes = 0_u64;
    let mut retained_raw_nonproposal_block_count = 0_u64;
    let mut uuid_reason_pairs = BTreeSet::new();
    let mut uuid_reason_count = 0_u64;
    for metadata in prepared.packet_metadata() {
        if metadata.ordered_event_ids().is_empty()
            || !metadata_packet_ids.insert(metadata.packet_id())
            || metadata_block_members
                .insert(metadata.block_id(), metadata.ordered_event_ids().to_vec())
                .is_some()
        {
            return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
        }
        let retained_raw = !proposal_id_set.contains(&metadata.packet_id());
        if retained_raw {
            retained_raw_nonproposal_block_count = retained_raw_nonproposal_block_count
                .checked_add(1)
                .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
        }
        for event_id in metadata.ordered_event_ids() {
            if !exhaustive_event_ids.insert(*event_id) {
                return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
            }
            let source_bytes = event_source_bytes_v1(ledger, *event_id)?;
            exhaustive_member_source_bytes = exhaustive_member_source_bytes
                .checked_add(source_bytes)
                .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
            if retained_raw {
                if !retained_raw_event_ids.insert(*event_id) {
                    return Err(ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch);
                }
                retained_raw_nonproposal_source_bytes = retained_raw_nonproposal_source_bytes
                    .checked_add(source_bytes)
                    .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
            }
        }
        for reason in metadata.mandatory_reasons() {
            if reason.identifier_kind() == ValidatedIdentifierKindV1::CanonicalUuid {
                uuid_reason_count = uuid_reason_count
                    .checked_add(1)
                    .ok_or(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)?;
                if !uuid_reason_pairs.insert((metadata.packet_id(), reason.facet_id())) {
                    return Err(ConstrainedMatchedCaseErrorV1::ValidatedIdentifierNotMandatory);
                }
            }
        }
    }
    let exhaustive_member_event_count = checked_count_v1(exhaustive_event_ids.len())?;
    let proposal_unique_member_event_count = checked_count_v1(proposal_event_ids.len())?;
    let retained_raw_nonproposal_member_event_count =
        checked_count_v1(retained_raw_event_ids.len())?;
    let exhaustive_primary_block_count = checked_count_v1(metadata_packet_ids.len())?;
    let proposal_packet_count = checked_count_v1(proposal_ids.len())?;
    let facet_ids = prepared
        .facets()
        .iter()
        .map(|facet| facet.id())
        .collect::<BTreeSet<_>>();
    let facet_count = checked_count_v1(facet_ids.len())?;
    let mandatory_proposal_count = checked_count_v1(prepared.mandatory().len())?;
    if metadata_packet_ids.len() != prepared.packet_metadata().len()
        || metadata_block_members != fresh_block_members
        || facet_ids.len() != prepared.facets().len()
        || !proposal_id_set.is_subset(&metadata_packet_ids)
        || exhaustive_event_ids.len() != ledger.len()
        || !proposal_event_ids.is_disjoint(&retained_raw_event_ids)
        || proposal_event_ids
            .union(&retained_raw_event_ids)
            .copied()
            .ne(exhaustive_event_ids.iter().copied())
        || proposal_packet_count.checked_add(retained_raw_nonproposal_block_count)
            != Some(exhaustive_primary_block_count)
        || proposal_unique_member_event_count
            .checked_add(retained_raw_nonproposal_member_event_count)
            != Some(exhaustive_member_event_count)
        || proposal_member_source_bytes.checked_add(retained_raw_nonproposal_source_bytes)
            != Some(exhaustive_member_source_bytes)
        || accounting.exhaustive_primary_block_count() != exhaustive_primary_block_count
        || accounting.exhaustive_member_event_count() != exhaustive_member_event_count
        || accounting.exhaustive_member_source_bytes() != exhaustive_member_source_bytes
        || accounting.proposal_packet_count() != proposal_packet_count
        || accounting.proposal_unique_member_event_count() != proposal_unique_member_event_count
        || accounting.proposal_member_source_bytes() != proposal_member_source_bytes
        || accounting.retained_raw_nonproposal_block_count() != retained_raw_nonproposal_block_count
        || accounting.retained_raw_nonproposal_member_event_count()
            != retained_raw_nonproposal_member_event_count
        || accounting.retained_raw_nonproposal_source_bytes()
            != retained_raw_nonproposal_source_bytes
        || accounting.proposal_affinity_count() != proposal_affinity_count
        || accounting.mandatory_proposal_count() != mandatory_proposal_count
        || accounting.facet_count() != facet_count
    {
        return Err(ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch);
    }

    let mandatory_pairs = prepared
        .mandatory()
        .iter()
        .map(|entry| (entry.packet_id(), entry.validated_identifier_facet_id()))
        .collect::<BTreeSet<_>>();
    if uuid_reason_count == 0
        || uuid_reason_count != mandatory_proposal_count
        || mandatory_pairs.len() != prepared.mandatory().len()
        || mandatory_pairs != uuid_reason_pairs
        || mandatory_pairs.iter().any(|(packet_id, facet_id)| {
            prepared
                .facets()
                .iter()
                .find(|facet| facet.id() == *facet_id)
                .is_none_or(|facet| {
                    facet.kind() != evidentrail_select::ProductionFacetKindV1::ValidatedQueryIdentifier
                })
                || prepared
                    .proposal_packets()
                    .iter()
                    .find(|packet| packet.id() == *packet_id)
                    .is_none_or(|packet| {
                        packet
                            .affinities()
                            .iter()
                            .all(|affinity| affinity.facet_id() != *facet_id)
                    })
        })
    {
        return Err(ConstrainedMatchedCaseErrorV1::ValidatedIdentifierNotMandatory);
    }

    let mut rendered_packet_ids = Vec::with_capacity(brief.evidence().len());
    let mut selected_event_ids = BTreeSet::new();
    for packet in brief.evidence() {
        rendered_packet_ids.push(packet.packet_id());
        let metadata = prepared
            .proposal_metadata(packet.packet_id())
            .ok_or(ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch)?;
        let mut expected_members = metadata.ordered_event_ids().to_vec();
        expected_members.sort_unstable();
        let rendered_members = packet.canonical_event_ids();
        let rendered_event_ids = packet
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<BTreeSet<_>>();
        if rendered_members != expected_members
            || packet.events().len() != rendered_members.len()
            || rendered_event_ids.len() != packet.events().len()
            || rendered_event_ids
                .iter()
                .copied()
                .ne(rendered_members.iter().copied())
            || packet.events().iter().any(|event| {
                ledger.exact_bytes(event.event_id()).ok() != Some(event.authorized_bytes())
            })
            || certification
                .packet_cost(packet.packet_id(), rendered_members)
                .ok()
                != Some(packet.composable_token_upper_bound())
        {
            return Err(ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch);
        }
        for event_id in rendered_members {
            if !selected_event_ids.insert(*event_id) {
                return Err(ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch);
            }
        }
    }
    rendered_packet_ids.sort_unstable();
    if rendered_packet_ids.is_empty()
        || rendered_packet_ids != selected_packet_ids
        || rendered_packet_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch);
    }

    let failure_block = validate_intact_failure_block_v1(ledger)?;
    let failure_metadata = prepared
        .packet_metadata()
        .iter()
        .find(|metadata| metadata.block_id() == failure_block.block_id)
        .ok_or(ConstrainedMatchedCaseErrorV1::ValidatedIdentifierFailureBlockNotSelected)?;
    if failure_metadata.ordered_event_ids() != failure_block.member_ids
        || !selected_packet_ids.contains(&failure_metadata.packet_id())
        || !rendered_packet_ids.contains(&failure_metadata.packet_id())
        || !failure_metadata
            .mandatory_reasons()
            .iter()
            .filter(|reason| reason.identifier_kind() == ValidatedIdentifierKindV1::CanonicalUuid)
            .any(|reason| {
                mandatory_pairs.contains(&(failure_metadata.packet_id(), reason.facet_id()))
            })
    {
        return Err(ConstrainedMatchedCaseErrorV1::ValidatedIdentifierFailureBlockNotSelected);
    }

    let selected_unique_member_event_count = checked_count_v1(selected_event_ids.len())?;
    let validated_accounting = [
        exhaustive_primary_block_count,
        exhaustive_member_event_count,
        exhaustive_member_source_bytes,
        proposal_packet_count,
        proposal_unique_member_event_count,
        proposal_member_source_bytes,
        retained_raw_nonproposal_block_count,
        retained_raw_nonproposal_member_event_count,
        retained_raw_nonproposal_source_bytes,
        proposal_affinity_count,
        mandatory_proposal_count,
        facet_count,
        selected_unique_member_event_count,
        uuid_reason_count,
    ];

    let artifact_digest = derive_audit_receipt_digest_v1(
        input.digest(),
        receipt.digest(),
        &proposal_ids,
        selected_packet_ids,
        artifact_digest_for_bytes_v1(compiled.artifact().text().as_bytes()),
        failure_block.block_id,
        &validated_accounting,
    )?;
    Ok(ValidatedThreeLaneProposalAuditReceiptV1 {
        artifact_digest,
        audit: audit.clone(),
        exhaustive_primary_block_count,
        exhaustive_unique_member_event_count: exhaustive_member_event_count,
        exhaustive_member_source_bytes,
        proposal_packet_count,
        proposal_unique_member_event_count,
        proposal_member_source_bytes,
        retained_raw_nonproposal_block_count,
        retained_raw_nonproposal_unique_member_event_count:
            retained_raw_nonproposal_member_event_count,
        retained_raw_nonproposal_source_bytes,
        proposal_affinity_count,
        mandatory_proposal_count,
        facet_count,
        selected_packet_count: checked_count_v1(selected_packet_ids.len())?,
        selected_unique_member_event_count,
        certification_packet_count: checked_count_v1(certification.packet_bounds().len())?,
        validated_identifier_mandatory_reason_count: uuid_reason_count,
        validated_identifier_failure_block_selected: true,
    })
}

fn checked_count_v1(length: usize) -> Result<u64, ConstrainedMatchedCaseErrorV1> {
    u64::try_from(length).map_err(|_| ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)
}

fn event_source_bytes_v1(
    ledger: &EventLedger,
    event_id: EventId,
) -> Result<u64, ConstrainedMatchedCaseErrorV1> {
    let bytes = ledger
        .exact_bytes(event_id)
        .map_err(|_| ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch)?;
    u64::try_from(bytes.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch)
}

fn derive_generator_artifact_digest_v1(
    input_artifact_digest: ArtifactDigest,
    input_byte_count: u64,
    record_count: u64,
    intact_failure_block_member_count: u64,
) -> Result<ArtifactDigest, ConstrainedMatchedCaseErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, GENERATOR_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &CONSTRAINED_MATCHED_GENERATOR_VERSION_V1.to_le_bytes(),
    )?;
    append_field(
        &mut bytes,
        &CONSTRAINED_MATCHED_GENERATOR_SEED_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, input_artifact_digest.as_bytes())?;
    append_field(&mut bytes, &input_byte_count.to_le_bytes())?;
    append_field(&mut bytes, &record_count.to_le_bytes())?;
    append_field(&mut bytes, &EXPECTED_RUNTIME_COUNT_V1.to_le_bytes())?;
    append_field(&mut bytes, &EXPECTED_STREAM_COUNT_V1.to_le_bytes())?;
    append_field(&mut bytes, &1_u64.to_le_bytes())?;
    append_field(&mut bytes, &intact_failure_block_member_count.to_le_bytes())?;
    append_field(
        &mut bytes,
        derive_question_digest_v1(CONSTRAINED_MATCHED_QUESTION_V1).as_bytes(),
    )?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_audit_receipt_digest_v1(
    input_receipt_digest: ArtifactDigest,
    proposal_receipt_digest: ArtifactDigest,
    proposal_ids: &[evidentrail_select::PacketIdV1],
    selected_ids: &[evidentrail_select::PacketIdV1],
    product_artifact_digest: ArtifactDigest,
    validated_identifier_failure_block_id: BlockId,
    validated_accounting: &[u64],
) -> Result<ArtifactDigest, ConstrainedMatchedCaseErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, AUDIT_RECEIPT_DOMAIN_V1)?;
    append_field(&mut bytes, input_receipt_digest.as_bytes())?;
    append_field(&mut bytes, proposal_receipt_digest.as_bytes())?;
    append_field(
        &mut bytes,
        &u64::try_from(proposal_ids.len())
            .map_err(|_| ConstrainedMatchedCaseErrorV1::ProposalMembershipMismatch)?
            .to_le_bytes(),
    )?;
    for packet_id in proposal_ids {
        append_field(&mut bytes, packet_id.as_bytes())?;
    }
    append_field(
        &mut bytes,
        &u64::try_from(selected_ids.len())
            .map_err(|_| ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch)?
            .to_le_bytes(),
    )?;
    for packet_id in selected_ids {
        append_field(&mut bytes, packet_id.as_bytes())?;
    }
    append_field(&mut bytes, product_artifact_digest.as_bytes())?;
    append_field(&mut bytes, validated_identifier_failure_block_id.as_bytes())?;
    for value in validated_accounting {
        append_field(&mut bytes, &value.to_le_bytes())?;
    }
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_finalized_constrained_artifact_digest_v1(
    inner_finalized_artifact_digest: ArtifactDigest,
    generator_artifact_digest: ArtifactDigest,
    input_artifact_digest: ArtifactDigest,
    proposal_audit_artifact_digest: ArtifactDigest,
    first_party_subprocess_receipt_artifact_digest: ArtifactDigest,
    cost_eligibility: MatchedCostComparisonEligibilityV1,
) -> Result<ArtifactDigest, ConstrainedMatchedCaseErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, FINALIZED_CONSTRAINED_MATCHED_CASE_DOMAIN_V1)?;
    append_field(&mut bytes, &3_u16.to_le_bytes())?;
    append_field(&mut bytes, inner_finalized_artifact_digest.as_bytes())?;
    append_field(&mut bytes, generator_artifact_digest.as_bytes())?;
    append_field(&mut bytes, input_artifact_digest.as_bytes())?;
    append_field(&mut bytes, proposal_audit_artifact_digest.as_bytes())?;
    append_field(
        &mut bytes,
        first_party_subprocess_receipt_artifact_digest.as_bytes(),
    )?;
    append_field(
        &mut bytes,
        cost_eligibility.first_party_scope().code().as_bytes(),
    )?;
    append_field(&mut bytes, cost_eligibility.drain_scope().code().as_bytes())?;
    append_field(&mut bytes, cost_eligibility.code().as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), ConstrainedMatchedCaseErrorV1> {
    let length = u64::try_from(field.len())
        .map_err(|_| ConstrainedMatchedCaseErrorV1::GeneratorInvariant)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedMatchedCaseErrorV1 {
    GeneratorInvariant,
    InputArtifactMismatch,
    QuestionIdentifierInvariant,
    FailureBlockInvariant,
    FirstPartyNotCompiled,
    ProposalAuditMissing,
    ProposalAuditNotSelected,
    ProposalAuditBindingMismatch,
    ProposalMembershipMismatch,
    ProposalAccountingMismatch,
    ProposalCertificationMismatch,
    ValidatedIdentifierNotMandatory,
    ValidatedIdentifierFailureBlockNotSelected,
    ProductArtifactBindingMismatch,
    ProductExecutionFailed,
    PeakRssObserverMismatch,
    PeakRssBudgetExceeded,
    CommonExecutionScopeMismatch,
    FirstPartySubprocess(FirstPartyConstrainedSubprocessErrorV1),
    Matched(PreparedPinnedDrainMatchedCaseErrorV1),
}

impl ConstrainedMatchedCaseErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GeneratorInvariant => "EVIDENTRAIL_BENCH_CONSTRAINED_GENERATOR_INVARIANT",
            Self::InputArtifactMismatch => "EVIDENTRAIL_BENCH_CONSTRAINED_INPUT_ARTIFACT_MISMATCH",
            Self::QuestionIdentifierInvariant => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_QUESTION_IDENTIFIER_INVARIANT"
            }
            Self::FailureBlockInvariant => "EVIDENTRAIL_BENCH_CONSTRAINED_FAILURE_BLOCK_INVARIANT",
            Self::FirstPartyNotCompiled => "EVIDENTRAIL_BENCH_CONSTRAINED_FIRST_PARTY_NOT_COMPILED",
            Self::ProposalAuditMissing => "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_AUDIT_MISSING",
            Self::ProposalAuditNotSelected => "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_AUDIT_NOT_SELECTED",
            Self::ProposalAuditBindingMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_AUDIT_BINDING_MISMATCH"
            }
            Self::ProposalMembershipMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_MEMBERSHIP_MISMATCH"
            }
            Self::ProposalAccountingMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_ACCOUNTING_MISMATCH"
            }
            Self::ProposalCertificationMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_PROPOSAL_CERTIFICATION_MISMATCH"
            }
            Self::ValidatedIdentifierNotMandatory => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_IDENTIFIER_NOT_MANDATORY"
            }
            Self::ValidatedIdentifierFailureBlockNotSelected => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_IDENTIFIER_FAILURE_BLOCK_NOT_SELECTED"
            }
            Self::ProductArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_PRODUCT_ARTIFACT_BINDING_MISMATCH"
            }
            Self::ProductExecutionFailed => "EVIDENTRAIL_BENCH_CONSTRAINED_PRODUCT_EXECUTION_FAILED",
            Self::PeakRssObserverMismatch => "EVIDENTRAIL_BENCH_CONSTRAINED_PEAK_RSS_OBSERVER_MISMATCH",
            Self::PeakRssBudgetExceeded => "EVIDENTRAIL_BENCH_CONSTRAINED_PEAK_RSS_BUDGET_EXCEEDED",
            Self::CommonExecutionScopeMismatch => {
                "EVIDENTRAIL_BENCH_CONSTRAINED_COMMON_EXECUTION_SCOPE_MISMATCH"
            }
            Self::FirstPartySubprocess(error) => error.code(),
            Self::Matched(error) => error.code(),
        }
    }
}

impl fmt::Debug for ConstrainedMatchedCaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedMatchedCaseErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ConstrainedMatchedCaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ConstrainedMatchedCaseErrorV1 {}

impl From<PreparedPinnedDrainMatchedCaseErrorV1> for ConstrainedMatchedCaseErrorV1 {
    fn from(error: PreparedPinnedDrainMatchedCaseErrorV1) -> Self {
        Self::Matched(error)
    }
}

impl From<FirstPartyConstrainedSubprocessErrorV1> for ConstrainedMatchedCaseErrorV1 {
    fn from(error: FirstPartyConstrainedSubprocessErrorV1) -> Self {
        Self::FirstPartySubprocess(error)
    }
}

#[cfg(test)]
mod tests {
    use super::derive_finalized_constrained_artifact_digest_v1;
    use crate::MatchedCostComparisonEligibilityV1;
    use evidentrail_schema::ArtifactDigest;

    #[test]
    fn finalized_constrained_digest_is_repeatable_and_binds_every_wrapper_identity() {
        let identities = [
            ArtifactDigest::from_bytes([0x11; 32]),
            ArtifactDigest::from_bytes([0x22; 32]),
            ArtifactDigest::from_bytes([0x33; 32]),
            ArtifactDigest::from_bytes([0x44; 32]),
            ArtifactDigest::from_bytes([0x55; 32]),
        ];
        let eligibility =
            MatchedCostComparisonEligibilityV1::common_process_scope_and_peak_rss_observer_v1();
        let baseline = derive_finalized_constrained_artifact_digest_v1(
            identities[0],
            identities[1],
            identities[2],
            identities[3],
            identities[4],
            eligibility,
        )
        .unwrap();
        assert_eq!(
            baseline,
            derive_finalized_constrained_artifact_digest_v1(
                identities[0],
                identities[1],
                identities[2],
                identities[3],
                identities[4],
                eligibility,
            )
            .unwrap()
        );
        for position in 0..identities.len() {
            let mut changed = identities;
            changed[position] = ArtifactDigest::from_bytes([0x99; 32]);
            assert_ne!(
                baseline,
                derive_finalized_constrained_artifact_digest_v1(
                    changed[0],
                    changed[1],
                    changed[2],
                    changed[3],
                    changed[4],
                    eligibility,
                )
                .unwrap()
            );
        }
        assert_ne!(
            baseline,
            derive_finalized_constrained_artifact_digest_v1(
                identities[0],
                identities[1],
                identities[2],
                identities[3],
                identities[4],
                MatchedCostComparisonEligibilityV1::unequal_v1(),
            )
            .unwrap()
        );
    }
}
