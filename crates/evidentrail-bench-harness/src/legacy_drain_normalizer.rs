use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use evidentrail_schema::{ArtifactDigest, EventId};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::legacy_drain::{
    LEGACY_DRAIN_HERMETIC_FIXTURE_REVISION_V1,
    legacy_drain_hermetic_fixture_system_artifact_digest_v1,
};
use crate::{
    ExitCategoryV1, ExternalOutputContractV1, InvocationDigestV1, InvocationInputContractV1,
    LEGACY_DRAIN_PINNED_COMMIT_V1, LegacyDrainAdapterModeV1, LegacyDrainAdapterV1,
    LegacyDrainInputAssessmentV1, LegacyDrainInputNormalizationV1, PublicSubprocessInvocationV1,
    StdinDeliveryV1, SubprocessExecutionReceiptV1, artifact_digest_for_bytes_v1,
    legacy_drain_full_membership_adapter_artifact_digest_v1,
};

const NORMALIZER_IDENTITY_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-json-normalizer-contract/v1";
const NORMALIZATION_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-opaque-normalization-receipt/v1";
const FULL_MEMBERSHIP_NORMALIZER_IDENTITY_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-full-membership-normalizer/v1";
const FULL_MEMBERSHIP_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-full-membership-artifact/v1";
const GROUP_PATTERN_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-group-pattern-artifact/v1";
const TRANSFORMED_SAMPLE_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-transformed-sample-artifact/v1";

/// Version of the strict parser for the JSON emitted by the pinned CLI.
pub const LEGACY_DRAIN_JSON_NORMALIZER_CONTRACT_VERSION_V1: u64 = 1;
/// Version of the bounded complete-occurrence membership normalizer.
pub const LEGACY_DRAIN_FULL_MEMBERSHIP_NORMALIZER_CONTRACT_VERSION_V1: u64 = 1;
/// Absolute byte ceiling applied before JSON parsing.
pub const MAX_LEGACY_DRAIN_JSON_BYTES_V1: u64 = 16 * 1024 * 1024;
/// Absolute group ceiling for the strict JSON parser.
pub const MAX_LEGACY_DRAIN_JSON_GROUPS_V1: u64 = 262_144;
/// Absolute ceiling for each aggregate samples/slots collection count.
pub const MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1: u64 = 1_048_576;
/// Absolute byte ceiling for each JSON string value.
pub const MAX_LEGACY_DRAIN_JSON_STRING_BYTES_V1: u64 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainNormalizerLimitDimensionV1 {
    JsonBytes,
    Groups,
    Samples,
    Slots,
    SlotSamples,
    StringBytes,
}

impl LegacyDrainNormalizerLimitDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::JsonBytes => "json_bytes",
            Self::Groups => "groups",
            Self::Samples => "samples",
            Self::Slots => "slots",
            Self::SlotSamples => "slot_samples",
            Self::StringBytes => "string_bytes",
        }
    }

    const fn hard_max(self) -> u64 {
        match self {
            Self::JsonBytes => MAX_LEGACY_DRAIN_JSON_BYTES_V1,
            Self::Groups => MAX_LEGACY_DRAIN_JSON_GROUPS_V1,
            Self::Samples | Self::Slots | Self::SlotSamples => {
                MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1
            }
            Self::StringBytes => MAX_LEGACY_DRAIN_JSON_STRING_BYTES_V1,
        }
    }
}

impl fmt::Debug for LegacyDrainNormalizerLimitDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainNormalizerLimitDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Caller-selected limits, each constrained by an absolute V1 hard ceiling.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainJsonLimitsV1 {
    json_bytes: u64,
    groups: u64,
    samples: u64,
    slots: u64,
    slot_samples: u64,
    string_bytes: u64,
}

impl LegacyDrainJsonLimitsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        json_bytes: u64,
        groups: u64,
        samples: u64,
        slots: u64,
        slot_samples: u64,
        string_bytes: u64,
    ) -> Result<Self, LegacyDrainNormalizationErrorV1> {
        for (value, dimension) in [
            (json_bytes, LegacyDrainNormalizerLimitDimensionV1::JsonBytes),
            (groups, LegacyDrainNormalizerLimitDimensionV1::Groups),
            (samples, LegacyDrainNormalizerLimitDimensionV1::Samples),
            (slots, LegacyDrainNormalizerLimitDimensionV1::Slots),
            (
                slot_samples,
                LegacyDrainNormalizerLimitDimensionV1::SlotSamples,
            ),
            (
                string_bytes,
                LegacyDrainNormalizerLimitDimensionV1::StringBytes,
            ),
        ] {
            if value == 0 || usize::try_from(value).is_err() {
                return Err(LegacyDrainNormalizationErrorV1::InvalidLimit { dimension });
            }
            if value > dimension.hard_max() {
                return Err(LegacyDrainNormalizationErrorV1::LimitExceedsHardBound { dimension });
            }
        }
        Ok(Self {
            json_bytes,
            groups,
            samples,
            slots,
            slot_samples,
            string_bytes,
        })
    }

    #[must_use]
    pub const fn json_bytes(self) -> u64 {
        self.json_bytes
    }

    #[must_use]
    pub const fn groups(self) -> u64 {
        self.groups
    }

    #[must_use]
    pub const fn samples(self) -> u64 {
        self.samples
    }

    #[must_use]
    pub const fn slots(self) -> u64 {
        self.slots
    }

    #[must_use]
    pub const fn slot_samples(self) -> u64 {
        self.slot_samples
    }

    #[must_use]
    pub const fn string_bytes(self) -> u64 {
        self.string_bytes
    }
}

impl Default for LegacyDrainJsonLimitsV1 {
    fn default() -> Self {
        Self {
            json_bytes: MAX_LEGACY_DRAIN_JSON_BYTES_V1,
            groups: MAX_LEGACY_DRAIN_JSON_GROUPS_V1,
            samples: MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1,
            slots: MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1,
            slot_samples: MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1,
            string_bytes: MAX_LEGACY_DRAIN_JSON_STRING_BYTES_V1,
        }
    }
}

impl fmt::Debug for LegacyDrainJsonLimitsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainJsonLimitsV1")
            .field("json_bytes", &self.json_bytes)
            .field("groups", &self.groups)
            .field("samples", &self.samples)
            .field("slots", &self.slots)
            .field("slot_samples", &self.slot_samples)
            .field("string_bytes", &self.string_bytes)
            .finish()
    }
}

/// Why pinned V1 JSON cannot produce candidate `EventId` membership.
///
/// The public input binding supplies original source bytes. The ordinary
/// sampling arm reports only partial member positions, and V1 deliberately
/// does not claim its transformed sample fields were source-validated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainMembershipUnprovableV1 {
    CompleteGroupOccurrencePositionsAbsent,
}

impl LegacyDrainMembershipUnprovableV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CompleteGroupOccurrencePositionsAbsent => {
                "complete_group_occurrence_positions_absent"
            }
        }
    }

    #[must_use]
    pub const fn original_source_record_bytes_present(self) -> bool {
        true
    }

    #[must_use]
    pub const fn sampled_position_indices_structurally_bounded(self) -> bool {
        true
    }

    #[must_use]
    pub const fn sampled_normalized_fields_verified_against_source(self) -> bool {
        false
    }

    #[must_use]
    pub const fn sampled_occurrence_evidence_joinable(self) -> bool {
        false
    }

    #[must_use]
    pub const fn complete_group_occurrence_positions_present(self) -> bool {
        false
    }

    #[must_use]
    pub const fn source_framing_preserved_by_binding(self) -> bool {
        true
    }
}

impl fmt::Debug for LegacyDrainMembershipUnprovableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainMembershipUnprovableV1")
            .field("code", &self.code())
            .field("original_source_record_bytes_present", &true)
            .field("sampled_position_indices_structurally_bounded", &true)
            .field("sampled_normalized_fields_verified_against_source", &false)
            .field("sampled_occurrence_evidence_joinable", &false)
            .field("complete_group_occurrence_positions_present", &false)
            .field("source_framing_preserved_by_binding", &true)
            .finish()
    }
}

/// Strictly parsed but still opaque and non-scoreable pinned CLI output.
///
/// The receipt binds the exact public invocation and raw output artifacts to
/// the V1 parser. It intentionally contains no templates, samples, source
/// text, `EventId`s, governed annotations, recall, or quality score.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainOpaqueNormalizationReceiptV1 {
    normalization_artifact_digest: ArtifactDigest,
    normalizer_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
    invocation_digest: InvocationDigestV1,
    stdin_artifact_digest: ArtifactDigest,
    source_record_map_artifact_digest: ArtifactDigest,
    retained_record_map_artifact_digest: ArtifactDigest,
    raw_stdout_artifact_digest: ArtifactDigest,
    raw_stderr_artifact_digest: ArtifactDigest,
    raw_stdout_byte_count: u64,
    raw_stderr_byte_count: u64,
    input_normalization: LegacyDrainInputNormalizationV1,
    original_count: u64,
    template_count: u64,
    group_count: u64,
    sample_count: u64,
    slot_count: u64,
    slot_sample_count: u64,
    membership_unprovable: LegacyDrainMembershipUnprovableV1,
}

impl LegacyDrainOpaqueNormalizationReceiptV1 {
    #[must_use]
    pub const fn normalization_artifact_digest(self) -> ArtifactDigest {
        self.normalization_artifact_digest
    }

    #[must_use]
    pub const fn normalizer_artifact_digest(self) -> ArtifactDigest {
        self.normalizer_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub const fn invocation_digest(self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn stdin_artifact_digest(self) -> ArtifactDigest {
        self.stdin_artifact_digest
    }

    #[must_use]
    pub const fn source_record_map_artifact_digest(self) -> ArtifactDigest {
        self.source_record_map_artifact_digest
    }

    #[must_use]
    pub const fn retained_record_map_artifact_digest(self) -> ArtifactDigest {
        self.retained_record_map_artifact_digest
    }

    #[must_use]
    pub const fn raw_stdout_artifact_digest(self) -> ArtifactDigest {
        self.raw_stdout_artifact_digest
    }

    #[must_use]
    pub const fn raw_stderr_artifact_digest(self) -> ArtifactDigest {
        self.raw_stderr_artifact_digest
    }

    #[must_use]
    pub const fn raw_stdout_byte_count(self) -> u64 {
        self.raw_stdout_byte_count
    }

    #[must_use]
    pub const fn raw_stderr_byte_count(self) -> u64 {
        self.raw_stderr_byte_count
    }

    #[must_use]
    pub const fn input_normalization(self) -> LegacyDrainInputNormalizationV1 {
        self.input_normalization
    }

    #[must_use]
    pub const fn original_count(self) -> u64 {
        self.original_count
    }

    #[must_use]
    pub const fn template_count(self) -> u64 {
        self.template_count
    }

    #[must_use]
    pub const fn group_count(self) -> u64 {
        self.group_count
    }

    #[must_use]
    pub const fn sample_count(self) -> u64 {
        self.sample_count
    }

    #[must_use]
    pub const fn slot_count(self) -> u64 {
        self.slot_count
    }

    #[must_use]
    pub const fn slot_sample_count(self) -> u64 {
        self.slot_sample_count
    }

    #[must_use]
    pub const fn membership_unprovable(self) -> LegacyDrainMembershipUnprovableV1 {
        self.membership_unprovable
    }

    #[must_use]
    pub const fn candidate_membership_scoreable(self) -> bool {
        false
    }

    #[must_use]
    pub const fn raw_stdout_remains_opaque(self) -> bool {
        true
    }
}

impl fmt::Debug for LegacyDrainOpaqueNormalizationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainOpaqueNormalizationReceiptV1")
            .field("normalization_artifact_binding_present", &true)
            .field("normalizer_artifact_binding_present", &true)
            .field("executable_build_binding_present", &true)
            .field("invocation_binding_present", &true)
            .field("stdin_artifact_binding_present", &true)
            .field("source_record_map_binding_present", &true)
            .field("retained_record_map_binding_present", &true)
            .field("raw_stdout_artifact_binding_present", &true)
            .field("raw_stderr_artifact_binding_present", &true)
            .field("raw_stdout_byte_count", &self.raw_stdout_byte_count)
            .field("raw_stderr_byte_count", &self.raw_stderr_byte_count)
            .field("input_normalization", &self.input_normalization)
            .field("original_count", &self.original_count)
            .field("template_count", &self.template_count)
            .field("group_count", &self.group_count)
            .field("sample_count", &self.sample_count)
            .field("slot_count", &self.slot_count)
            .field("slot_sample_count", &self.slot_sample_count)
            .field("membership", &self.membership_unprovable)
            .field("candidate_membership_scoreable", &false)
            .field("raw_stdout_remains_opaque", &true)
            .field("contains_event_ids", &false)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// One source occurrence represented by a normalized group pattern.
///
/// This relation is not a claim that the original event was shown verbatim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainPatternRepresentedV1 {
    retained_index: u64,
    source_record_ordinal: u64,
    event_id: EventId,
    group_id: u64,
    group_pattern_artifact_digest: ArtifactDigest,
}

impl LegacyDrainPatternRepresentedV1 {
    #[must_use]
    pub const fn retained_index(self) -> u64 {
        self.retained_index
    }

    #[must_use]
    pub const fn source_record_ordinal(self) -> u64 {
        self.source_record_ordinal
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn group_id(self) -> u64 {
        self.group_id
    }

    #[must_use]
    pub const fn group_pattern_artifact_digest(self) -> ArtifactDigest {
        self.group_pattern_artifact_digest
    }
}

impl fmt::Debug for LegacyDrainPatternRepresentedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainPatternRepresentedV1")
            .field("retained_index", &self.retained_index)
            .field("source_record_ordinal", &self.source_record_ordinal)
            .field("event_identity_present", &true)
            .field("group_id", &self.group_id)
            .field("group_pattern_artifact_identity_present", &true)
            .field("shown_verbatim", &false)
            .finish()
    }
}

/// One occurrence emitted as a pinned, validated transformed sample.
///
/// The normalized message/level/timestamp are committed by digest but are
/// never classified as source-exact bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainTransformedSampleV1 {
    retained_index: u64,
    source_record_ordinal: u64,
    event_id: EventId,
    group_id: u64,
    transformed_sample_artifact_digest: ArtifactDigest,
}

impl LegacyDrainTransformedSampleV1 {
    #[must_use]
    pub const fn retained_index(self) -> u64 {
        self.retained_index
    }

    #[must_use]
    pub const fn source_record_ordinal(self) -> u64 {
        self.source_record_ordinal
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn group_id(self) -> u64 {
        self.group_id
    }

    #[must_use]
    pub const fn transformed_sample_artifact_digest(self) -> ArtifactDigest {
        self.transformed_sample_artifact_digest
    }
}

impl fmt::Debug for LegacyDrainTransformedSampleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainTransformedSampleV1")
            .field("retained_index", &self.retained_index)
            .field("source_record_ordinal", &self.source_record_ordinal)
            .field("event_identity_present", &true)
            .field("group_id", &self.group_id)
            .field("transformed_sample_artifact_identity_present", &true)
            .field("source_exact", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainQualityBridgeV1 {
    NeedsRepresentationFidelityOrDownstreamAgentVds,
}

impl LegacyDrainQualityBridgeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NeedsRepresentationFidelityOrDownstreamAgentVds => {
                "needs_representation_fidelity_or_downstream_agent_vds"
            }
        }
    }
}

impl fmt::Debug for LegacyDrainQualityBridgeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainQualityBridgeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Complete occurrence-accounting sidecar for the distinct full-sample arm.
///
/// Every retained source occurrence is mapped to an `EventId`, a pattern, and
/// a source-validated transformed sample. This permits resource/compression
/// and membership accounting. It deliberately cannot grant exact-event recall
/// or `ShownVerbatim` credit without a later representation-fidelity contract
/// or downstream-agent VDS evaluation. The instrumentation arm conservatively
/// charges every retained occurrence and its exact source-record bytes against
/// the run's candidate budget; its full process execution/output measurement
/// is also required. It is never an uncharged side run for the compact arm.
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyDrainFullMembershipArtifactV1 {
    artifact_digest: ArtifactDigest,
    normalizer_artifact_digest: ArtifactDigest,
    adapter_artifact_digest: ArtifactDigest,
    invocation_digest: InvocationDigestV1,
    run_manifest_artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    stdin_artifact_digest: ArtifactDigest,
    source_record_map_artifact_digest: ArtifactDigest,
    retained_record_map_artifact_digest: ArtifactDigest,
    raw_stdout_artifact_digest: ArtifactDigest,
    raw_stderr_artifact_digest: ArtifactDigest,
    raw_stdout_byte_count: u64,
    raw_stderr_byte_count: u64,
    sample_cap: u64,
    charged_candidate_source_bytes: u64,
    pattern_memberships: Vec<LegacyDrainPatternRepresentedV1>,
    transformed_samples: Vec<LegacyDrainTransformedSampleV1>,
    quality_bridge: LegacyDrainQualityBridgeV1,
}

impl LegacyDrainFullMembershipArtifactV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn normalizer_artifact_digest(&self) -> ArtifactDigest {
        self.normalizer_artifact_digest
    }

    #[must_use]
    pub const fn adapter_artifact_digest(&self) -> ArtifactDigest {
        self.adapter_artifact_digest
    }

    #[must_use]
    pub const fn invocation_digest(&self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn stdin_artifact_digest(&self) -> ArtifactDigest {
        self.stdin_artifact_digest
    }

    #[must_use]
    pub const fn source_record_map_artifact_digest(&self) -> ArtifactDigest {
        self.source_record_map_artifact_digest
    }

    #[must_use]
    pub const fn retained_record_map_artifact_digest(&self) -> ArtifactDigest {
        self.retained_record_map_artifact_digest
    }

    #[must_use]
    pub const fn raw_stdout_artifact_digest(&self) -> ArtifactDigest {
        self.raw_stdout_artifact_digest
    }

    #[must_use]
    pub const fn raw_stderr_artifact_digest(&self) -> ArtifactDigest {
        self.raw_stderr_artifact_digest
    }

    #[must_use]
    pub const fn raw_stdout_byte_count(&self) -> u64 {
        self.raw_stdout_byte_count
    }

    #[must_use]
    pub const fn raw_stderr_byte_count(&self) -> u64 {
        self.raw_stderr_byte_count
    }

    #[must_use]
    pub const fn sample_cap(&self) -> u64 {
        self.sample_cap
    }

    #[must_use]
    pub fn charged_candidate_event_count(&self) -> usize {
        self.pattern_memberships.len()
    }

    #[must_use]
    pub const fn charged_candidate_source_bytes(&self) -> u64 {
        self.charged_candidate_source_bytes
    }

    #[must_use]
    pub fn pattern_memberships(&self) -> &[LegacyDrainPatternRepresentedV1] {
        &self.pattern_memberships
    }

    #[must_use]
    pub fn transformed_samples(&self) -> &[LegacyDrainTransformedSampleV1] {
        &self.transformed_samples
    }

    pub fn candidate_event_ids(&self) -> impl ExactSizeIterator<Item = EventId> + '_ {
        self.pattern_memberships
            .iter()
            .map(|member| member.event_id)
    }

    #[must_use]
    pub const fn occurrence_membership_proven(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn resource_and_compression_accounting_available(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn diagnostic_evidence_recall_scoreable(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn source_exact_or_shown_verbatim(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn full_execution_measurement_required(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn quality_bridge(&self) -> LegacyDrainQualityBridgeV1 {
        self.quality_bridge
    }
}

impl fmt::Debug for LegacyDrainFullMembershipArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainFullMembershipArtifactV1")
            .field("artifact_binding_present", &true)
            .field("normalizer_binding_present", &true)
            .field("adapter_binding_present", &true)
            .field("invocation_binding_present", &true)
            .field("run_manifest_binding_present", &true)
            .field("public_case_binding_present", &true)
            .field("stdin_binding_present", &true)
            .field("source_record_map_binding_present", &true)
            .field("retained_record_map_binding_present", &true)
            .field("raw_output_bindings_present", &true)
            .field("raw_stdout_byte_count", &self.raw_stdout_byte_count)
            .field("raw_stderr_byte_count", &self.raw_stderr_byte_count)
            .field("sample_cap", &self.sample_cap)
            .field(
                "charged_candidate_source_bytes",
                &self.charged_candidate_source_bytes,
            )
            .field("pattern_membership_count", &self.pattern_memberships.len())
            .field("transformed_sample_count", &self.transformed_samples.len())
            .field("quality_bridge", &self.quality_bridge)
            .field("diagnostic_evidence_recall_scoreable", &false)
            .field("source_exact_or_shown_verbatim", &false)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainNormalizationErrorV1 {
    InvalidLimit {
        dimension: LegacyDrainNormalizerLimitDimensionV1,
    },
    LimitExceedsHardBound {
        dimension: LegacyDrainNormalizerLimitDimensionV1,
    },
    ObservedLimitExceeded {
        dimension: LegacyDrainNormalizerLimitDimensionV1,
    },
    UnsupportedInvocation,
    UnsupportedInput,
    InvocationExecutionBindingMismatch,
    ExecutionNotAdmissible,
    OutputNotComplete,
    UnexpectedStderr,
    MalformedOrUnsupportedJson,
    IntegerOutsideContract,
    NumericValueInvalid,
    StructuralMismatch,
    FullMembershipModeRequired,
    FullMembershipIncompleteSamples,
    SampleNormalizationMismatch,
    AccountingOverflow,
}

impl LegacyDrainNormalizationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimit { .. } => "LEGACY_DRAIN_NORMALIZER_INVALID_LIMIT",
            Self::LimitExceedsHardBound { .. } => {
                "LEGACY_DRAIN_NORMALIZER_LIMIT_EXCEEDS_HARD_BOUND"
            }
            Self::ObservedLimitExceeded { .. } => "LEGACY_DRAIN_NORMALIZER_OBSERVED_LIMIT_EXCEEDED",
            Self::UnsupportedInvocation => "LEGACY_DRAIN_NORMALIZER_UNSUPPORTED_INVOCATION",
            Self::UnsupportedInput => "LEGACY_DRAIN_NORMALIZER_UNSUPPORTED_INPUT",
            Self::InvocationExecutionBindingMismatch => {
                "LEGACY_DRAIN_NORMALIZER_INVOCATION_EXECUTION_BINDING_MISMATCH"
            }
            Self::ExecutionNotAdmissible => "LEGACY_DRAIN_NORMALIZER_EXECUTION_NOT_ADMISSIBLE",
            Self::OutputNotComplete => "LEGACY_DRAIN_NORMALIZER_OUTPUT_NOT_COMPLETE",
            Self::UnexpectedStderr => "LEGACY_DRAIN_NORMALIZER_UNEXPECTED_STDERR",
            Self::MalformedOrUnsupportedJson => {
                "LEGACY_DRAIN_NORMALIZER_MALFORMED_OR_UNSUPPORTED_JSON"
            }
            Self::IntegerOutsideContract => "LEGACY_DRAIN_NORMALIZER_INTEGER_OUTSIDE_CONTRACT",
            Self::NumericValueInvalid => "LEGACY_DRAIN_NORMALIZER_NUMERIC_VALUE_INVALID",
            Self::StructuralMismatch => "LEGACY_DRAIN_NORMALIZER_STRUCTURAL_MISMATCH",
            Self::FullMembershipModeRequired => {
                "LEGACY_DRAIN_NORMALIZER_FULL_MEMBERSHIP_MODE_REQUIRED"
            }
            Self::FullMembershipIncompleteSamples => {
                "LEGACY_DRAIN_NORMALIZER_FULL_MEMBERSHIP_INCOMPLETE_SAMPLES"
            }
            Self::SampleNormalizationMismatch => {
                "LEGACY_DRAIN_NORMALIZER_SAMPLE_NORMALIZATION_MISMATCH"
            }
            Self::AccountingOverflow => "LEGACY_DRAIN_NORMALIZER_ACCOUNTING_OVERFLOW",
        }
    }
}

impl fmt::Debug for LegacyDrainNormalizationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("LegacyDrainNormalizationErrorV1");
        debug.field("code", &self.code());
        match self {
            Self::InvalidLimit { dimension }
            | Self::LimitExceedsHardBound { dimension }
            | Self::ObservedLimitExceeded { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for LegacyDrainNormalizationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LegacyDrainNormalizationErrorV1 {}

#[must_use]
pub fn legacy_drain_json_normalizer_artifact_digest_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(NORMALIZER_IDENTITY_V1)
}

#[must_use]
pub fn legacy_drain_full_membership_normalizer_artifact_digest_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(FULL_MEMBERSHIP_NORMALIZER_IDENTITY_V1)
}

/// Strictly validate and bind one successful pinned `legacy-drain` JSON run.
///
/// A successful parse returns an opaque, non-scoreable receipt. Pinned V1
/// output cannot return complete candidate membership because the compact arm
/// emits only a bounded prefix of each group's member positions.
pub fn strict_normalize_pinned_legacy_drain_output_v1(
    invocation: &PublicSubprocessInvocationV1,
    execution: &SubprocessExecutionReceiptV1,
    limits: LegacyDrainJsonLimitsV1,
) -> Result<LegacyDrainOpaqueNormalizationReceiptV1, LegacyDrainNormalizationErrorV1> {
    let (adapter, input_normalization) = validate_invocation(invocation)?;
    if adapter.mode() != LegacyDrainAdapterModeV1::OpaqueSampled {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation);
    }
    validate_execution_binding(invocation, execution)?;
    let retained_record_map = invocation
        .source_record_map()
        .legacy_drain_retained_records(invocation.stdin())
        .map_err(|_| LegacyDrainNormalizationErrorV1::UnsupportedInput)?;
    let source_record_count = u64::try_from(invocation.source_record_map().records().len())
        .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?;
    let retained_record_count = u64::try_from(retained_record_map.records().len())
        .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?;
    if input_normalization.logical_line_count() != source_record_count
        || input_normalization.retained_nonblank_line_count() != retained_record_count
    {
        return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
    }

    if execution.exit_category() != ExitCategoryV1::Success
        || execution.stdin_delivery() != StdinDeliveryV1::Complete
        || !execution.termination_causes().is_empty()
        || !execution.child_reaped()
        || !execution.executable_path_digest_verified_before_spawn()
        || !execution.executable_path_digest_verified_after_spawn()
    {
        return Err(LegacyDrainNormalizationErrorV1::ExecutionNotAdmissible);
    }
    let Some(raw_stdout_artifact_digest) = execution.stdout().complete_artifact_digest() else {
        return Err(LegacyDrainNormalizationErrorV1::OutputNotComplete);
    };
    let Some(raw_stderr_artifact_digest) = execution.stderr().complete_artifact_digest() else {
        return Err(LegacyDrainNormalizationErrorV1::OutputNotComplete);
    };
    if !execution.stderr().bytes().is_empty() {
        return Err(LegacyDrainNormalizationErrorV1::UnexpectedStderr);
    }

    let facts = parse_and_validate_json(
        execution.stdout().bytes(),
        input_normalization.retained_nonblank_line_count(),
        adapter.sample_cap(),
        limits,
    )?;
    let raw_stdout_byte_count = u64::try_from(execution.stdout().byte_count())
        .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?;
    let raw_stderr_byte_count = u64::try_from(execution.stderr().byte_count())
        .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?;
    let normalizer_artifact_digest = legacy_drain_json_normalizer_artifact_digest_v1();
    let membership_unprovable =
        LegacyDrainMembershipUnprovableV1::CompleteGroupOccurrencePositionsAbsent;
    let normalization_artifact_digest = derive_normalization_artifact_digest(
        invocation,
        limits,
        normalizer_artifact_digest,
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        input_normalization,
        retained_record_map.map_artifact_digest(),
        facts,
        membership_unprovable,
    )?;

    Ok(LegacyDrainOpaqueNormalizationReceiptV1 {
        normalization_artifact_digest,
        normalizer_artifact_digest,
        executable_build_artifact_digest: invocation.program().executable_build_artifact_digest(),
        invocation_digest: invocation.digest(),
        stdin_artifact_digest: invocation.stdin().artifact_digest(),
        source_record_map_artifact_digest: invocation.source_record_map().map_artifact_digest(),
        retained_record_map_artifact_digest: retained_record_map.map_artifact_digest(),
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        input_normalization,
        original_count: facts.original_count,
        template_count: facts.template_count,
        group_count: facts.group_count,
        sample_count: facts.sample_count,
        slot_count: facts.slot_count,
        slot_sample_count: facts.slot_sample_count,
        membership_unprovable,
    })
}

/// Validate the distinct bounded full-sample instrumentation arm and emit an
/// occurrence-accounting sidecar. This function consumes only public inputs.
/// It does not grant exact-event recall or presentation-fidelity credit.
pub fn strict_normalize_pinned_legacy_drain_full_membership_v1(
    invocation: &PublicSubprocessInvocationV1,
    execution: &SubprocessExecutionReceiptV1,
    limits: LegacyDrainJsonLimitsV1,
) -> Result<LegacyDrainFullMembershipArtifactV1, LegacyDrainNormalizationErrorV1> {
    let (adapter, input_normalization) = validate_invocation(invocation)?;
    if adapter.mode() != LegacyDrainAdapterModeV1::FullMembershipAudit {
        return Err(LegacyDrainNormalizationErrorV1::FullMembershipModeRequired);
    }
    validate_execution_binding(invocation, execution)?;
    let retained_record_map = invocation
        .source_record_map()
        .legacy_drain_retained_records(invocation.stdin())
        .map_err(|_| LegacyDrainNormalizationErrorV1::UnsupportedInput)?;
    let source_record_count = count(invocation.source_record_map().records().len())?;
    let retained_record_count = count(retained_record_map.records().len())?;
    if input_normalization.logical_line_count() != source_record_count
        || input_normalization.retained_nonblank_line_count() != retained_record_count
        || adapter.sample_cap() != retained_record_count
    {
        return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
    }
    if !invocation.stdin().bytes().is_ascii() {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInput);
    }
    if execution.exit_category() != ExitCategoryV1::Success
        || execution.stdin_delivery() != StdinDeliveryV1::Complete
        || !execution.termination_causes().is_empty()
        || !execution.child_reaped()
        || !execution.executable_path_digest_verified_before_spawn()
        || !execution.executable_path_digest_verified_after_spawn()
    {
        return Err(LegacyDrainNormalizationErrorV1::ExecutionNotAdmissible);
    }
    let Some(raw_stdout_artifact_digest) = execution.stdout().complete_artifact_digest() else {
        return Err(LegacyDrainNormalizationErrorV1::OutputNotComplete);
    };
    let Some(raw_stderr_artifact_digest) = execution.stderr().complete_artifact_digest() else {
        return Err(LegacyDrainNormalizationErrorV1::OutputNotComplete);
    };
    if !execution.stderr().bytes().is_empty() {
        return Err(LegacyDrainNormalizationErrorV1::UnexpectedStderr);
    }

    let facts = parse_and_validate_json(
        execution.stdout().bytes(),
        retained_record_count,
        adapter.sample_cap(),
        limits,
    )?;
    if facts.sample_count != retained_record_count {
        return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
    }
    let parsed: PinnedTemplateResultV1 = serde_json::from_slice(execution.stdout().bytes())
        .map_err(|_| LegacyDrainNormalizationErrorV1::MalformedOrUnsupportedJson)?;
    let (pattern_memberships, transformed_samples) =
        validate_full_membership_samples(invocation, &retained_record_map, &parsed, limits)?;
    let charged_candidate_source_bytes =
        retained_record_map
            .records()
            .iter()
            .try_fold(0_u64, |total, retained| {
                let position = usize::try_from(retained.source_record_ordinal())
                    .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?;
                let source_record = invocation
                    .source_record_map()
                    .records()
                    .get(position)
                    .ok_or(LegacyDrainNormalizationErrorV1::StructuralMismatch)?;
                total
                    .checked_add(
                        source_record
                            .source_byte_end()
                            .checked_sub(source_record.source_byte_start())
                            .ok_or(LegacyDrainNormalizationErrorV1::AccountingOverflow)?,
                    )
                    .ok_or(LegacyDrainNormalizationErrorV1::AccountingOverflow)
            })?;
    let raw_stdout_byte_count = count(execution.stdout().byte_count())?;
    let raw_stderr_byte_count = count(execution.stderr().byte_count())?;
    let normalizer_artifact_digest = legacy_drain_full_membership_normalizer_artifact_digest_v1();
    let adapter_artifact_digest = legacy_drain_full_membership_adapter_artifact_digest_v1();
    let quality_bridge =
        LegacyDrainQualityBridgeV1::NeedsRepresentationFidelityOrDownstreamAgentVds;
    let artifact_digest = derive_full_membership_artifact_digest(
        invocation,
        limits,
        normalizer_artifact_digest,
        adapter_artifact_digest,
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        input_normalization,
        retained_record_map.map_artifact_digest(),
        facts,
        adapter.sample_cap(),
        charged_candidate_source_bytes,
        &pattern_memberships,
        &transformed_samples,
        quality_bridge,
    )?;

    Ok(LegacyDrainFullMembershipArtifactV1 {
        artifact_digest,
        normalizer_artifact_digest,
        adapter_artifact_digest,
        invocation_digest: invocation.digest(),
        run_manifest_artifact_digest: invocation.run_manifest_artifact_digest(),
        public_case_artifact_digest: invocation.public_case_artifact_digest(),
        stdin_artifact_digest: invocation.stdin().artifact_digest(),
        source_record_map_artifact_digest: invocation.source_record_map().map_artifact_digest(),
        retained_record_map_artifact_digest: retained_record_map.map_artifact_digest(),
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        sample_cap: adapter.sample_cap(),
        charged_candidate_source_bytes,
        pattern_memberships,
        transformed_samples,
        quality_bridge,
    })
}

fn validate_invocation(
    invocation: &PublicSubprocessInvocationV1,
) -> Result<(LegacyDrainAdapterV1, LegacyDrainInputNormalizationV1), LegacyDrainNormalizationErrorV1>
{
    let program = invocation.program();
    let pinned_target = program.adapter_revision() == Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
        && program.system_artifact_digest()
            == artifact_digest_for_bytes_v1(LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes());
    let hermetic_contract_fixture = program.adapter_revision()
        == Some(LEGACY_DRAIN_HERMETIC_FIXTURE_REVISION_V1)
        && program.system_artifact_digest()
            == legacy_drain_hermetic_fixture_system_artifact_digest_v1();
    if !matches!(
        invocation.input_contract(),
        InvocationInputContractV1::LegacyDrainRawTextKnownNormalization
            | InvocationInputContractV1::LegacyDrainRawTextFullMembership
    ) || program.output_contract() != ExternalOutputContractV1::OpaqueArtifactOnly
        || !(pinned_target || hermetic_contract_fixture)
    {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation);
    }
    let arguments = program.argv();
    let Some(sample_text) = arguments.get(5) else {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation);
    };
    let sample_cap = sample_text
        .parse::<u64>()
        .map_err(|_| LegacyDrainNormalizationErrorV1::UnsupportedInvocation)?;
    let adapter = match invocation.input_contract() {
        InvocationInputContractV1::LegacyDrainRawTextKnownNormalization => {
            LegacyDrainAdapterV1::try_new(sample_cap)
        }
        InvocationInputContractV1::LegacyDrainRawTextFullMembership => {
            LegacyDrainAdapterV1::try_new_full_membership_cap_for_validation(sample_cap)
        }
        InvocationInputContractV1::ByteExact => {
            return Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation);
        }
    }
    .map_err(|_| LegacyDrainNormalizationErrorV1::UnsupportedInvocation)?;
    if arguments != adapter.fixed_argv() {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation);
    }
    let input_normalization = match adapter
        .assess_input(invocation.stdin().bytes())
        .map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)?
    {
        LegacyDrainInputAssessmentV1::SupportedWithNormalization(value) => value,
        LegacyDrainInputAssessmentV1::Unsupported(_) => {
            return Err(LegacyDrainNormalizationErrorV1::UnsupportedInput);
        }
    };
    Ok((adapter, input_normalization))
}

fn validate_execution_binding(
    invocation: &PublicSubprocessInvocationV1,
    execution: &SubprocessExecutionReceiptV1,
) -> Result<(), LegacyDrainNormalizationErrorV1> {
    if execution.invocation_digest() != invocation.digest()
        || execution.run_manifest_artifact_digest() != invocation.run_manifest_artifact_digest()
        || execution.run_identity() != invocation.run_identity()
        || execution.public_case_artifact_digest() != invocation.public_case_artifact_digest()
        || execution.case_resolution_trust() != invocation.case_resolution_trust()
        || execution.stdin_artifact_digest() != invocation.stdin().artifact_digest()
        || execution.output_contract() != invocation.program().output_contract()
    {
        return Err(LegacyDrainNormalizationErrorV1::InvocationExecutionBindingMismatch);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedTemplateResultV1 {
    groups: Vec<PinnedTemplateGroupV1>,
    original_count: u64,
    template_count: u64,
    line_compression: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedTemplateGroupV1 {
    id: u64,
    first_index: u64,
    count: u64,
    template: String,
    samples: Vec<PinnedTemplateSampleV1>,
    slots: Vec<PinnedSlotSummaryV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedTemplateSampleV1 {
    index: u64,
    text: String,
    level: RequiredNullableString,
    timestamp: RequiredNullableString,
}

#[derive(Deserialize)]
struct RequiredNullableString(Option<String>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedSlotSummaryV1 {
    numeric: bool,
    min: f64,
    max: f64,
    median: f64,
    unit: String,
    distinct: u64,
    samples: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParsedFactsV1 {
    original_count: u64,
    template_count: u64,
    group_count: u64,
    sample_count: u64,
    slot_count: u64,
    slot_sample_count: u64,
    line_compression_bits: u64,
}

fn parse_and_validate_json(
    bytes: &[u8],
    expected_original_count: u64,
    sample_cap: u64,
    limits: LegacyDrainJsonLimitsV1,
) -> Result<ParsedFactsV1, LegacyDrainNormalizationErrorV1> {
    let json_byte_count = count(bytes.len())?;
    enforce_observed_limit(
        json_byte_count,
        limits.json_bytes,
        LegacyDrainNormalizerLimitDimensionV1::JsonBytes,
    )?;
    let parsed: PinnedTemplateResultV1 = serde_json::from_slice(bytes)
        .map_err(|_| LegacyDrainNormalizationErrorV1::MalformedOrUnsupportedJson)?;
    check_json_safe(parsed.original_count)?;
    check_json_safe(parsed.template_count)?;
    if parsed.original_count != expected_original_count {
        return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
    }

    let group_count = count(parsed.groups.len())?;
    enforce_observed_limit(
        group_count,
        limits.groups,
        LegacyDrainNormalizerLimitDimensionV1::Groups,
    )?;
    if parsed.template_count != group_count
        || (parsed.original_count == 0) != (parsed.template_count == 0)
    {
        return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
    }

    let expected_compression = if parsed.template_count == 0 {
        0.0
    } else {
        parsed.original_count as f64 / parsed.template_count as f64
    };
    if !parsed.line_compression.is_finite()
        || parsed.line_compression.to_bits() != expected_compression.to_bits()
    {
        return Err(LegacyDrainNormalizationErrorV1::NumericValueInvalid);
    }

    let mut group_member_count = 0_u64;
    let mut sample_count = 0_u64;
    let mut slot_count = 0_u64;
    let mut slot_sample_count = 0_u64;
    let mut previous_first_index = None;
    let mut sampled_indices = BTreeSet::new();

    for (group_ordinal, group) in parsed.groups.iter().enumerate() {
        for value in [group.id, group.first_index, group.count] {
            check_json_safe(value)?;
        }
        if group.id != count(group_ordinal)? || group.count == 0 {
            return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
        }
        if group.first_index >= parsed.original_count
            || previous_first_index.is_some_and(|previous| group.first_index <= previous)
        {
            return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
        }
        previous_first_index = Some(group.first_index);
        group_member_count = checked_add(group_member_count, group.count)?;
        check_string(&group.template, limits)?;

        let group_sample_count = count(group.samples.len())?;
        if group_sample_count != group.count.min(sample_cap) {
            return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
        }
        sample_count = checked_add(sample_count, group_sample_count)?;
        enforce_observed_limit(
            sample_count,
            limits.samples,
            LegacyDrainNormalizerLimitDimensionV1::Samples,
        )?;
        let mut previous_sample_index = None;
        for sample in &group.samples {
            check_json_safe(sample.index)?;
            if sample.index >= parsed.original_count
                || previous_sample_index.is_some_and(|previous| sample.index <= previous)
                || !sampled_indices.insert(sample.index)
            {
                return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
            }
            previous_sample_index = Some(sample.index);
            check_string(&sample.text, limits)?;
            if let Some(level) = &sample.level.0 {
                check_string(level, limits)?;
            }
            if let Some(timestamp) = &sample.timestamp.0 {
                check_string(timestamp, limits)?;
            }
        }
        if group.samples.first().map(|sample| sample.index) != Some(group.first_index) {
            return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
        }

        slot_count = checked_add(slot_count, count(group.slots.len())?)?;
        enforce_observed_limit(
            slot_count,
            limits.slots,
            LegacyDrainNormalizerLimitDimensionV1::Slots,
        )?;
        for slot in &group.slots {
            check_json_safe(slot.distinct)?;
            if !slot.min.is_finite() || !slot.max.is_finite() || !slot.median.is_finite() {
                return Err(LegacyDrainNormalizationErrorV1::NumericValueInvalid);
            }
            if slot.numeric {
                if slot.distinct == 0 || slot.min > slot.median || slot.median > slot.max {
                    return Err(LegacyDrainNormalizationErrorV1::NumericValueInvalid);
                }
            } else if slot.min.to_bits() != 0.0_f64.to_bits()
                || slot.max.to_bits() != 0.0_f64.to_bits()
                || slot.median.to_bits() != 0.0_f64.to_bits()
            {
                return Err(LegacyDrainNormalizationErrorV1::NumericValueInvalid);
            }
            check_string(&slot.unit, limits)?;
            let current_slot_sample_count = count(slot.samples.len())?;
            if current_slot_sample_count > slot.distinct {
                return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
            }
            slot_sample_count = checked_add(slot_sample_count, current_slot_sample_count)?;
            enforce_observed_limit(
                slot_sample_count,
                limits.slot_samples,
                LegacyDrainNormalizerLimitDimensionV1::SlotSamples,
            )?;
            for sample in &slot.samples {
                check_string(sample, limits)?;
            }
        }
    }

    if group_member_count != parsed.original_count {
        return Err(LegacyDrainNormalizationErrorV1::StructuralMismatch);
    }
    Ok(ParsedFactsV1 {
        original_count: parsed.original_count,
        template_count: parsed.template_count,
        group_count,
        sample_count,
        slot_count,
        slot_sample_count,
        line_compression_bits: parsed.line_compression.to_bits(),
    })
}

fn validate_full_membership_samples(
    invocation: &PublicSubprocessInvocationV1,
    retained_record_map: &crate::LegacyDrainRetainedRecordMapV1,
    parsed: &PinnedTemplateResultV1,
    limits: LegacyDrainJsonLimitsV1,
) -> Result<
    (
        Vec<LegacyDrainPatternRepresentedV1>,
        Vec<LegacyDrainTransformedSampleV1>,
    ),
    LegacyDrainNormalizationErrorV1,
> {
    let expected_count = count(retained_record_map.records().len())?;
    let mut pattern_memberships = Vec::with_capacity(retained_record_map.records().len());
    let mut transformed_samples = Vec::with_capacity(retained_record_map.records().len());
    let mut observed_indices = BTreeSet::new();

    for group in &parsed.groups {
        if count(group.samples.len())? != group.count {
            return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
        }
        let group_pattern_artifact_digest = derive_group_pattern_artifact_digest(group)?;
        for sample in &group.samples {
            if !observed_indices.insert(sample.index) {
                return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
            }
            let retained = retained_record_map
                .record_for_retained_index(sample.index)
                .ok_or(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples)?;
            let payload = invocation
                .source_record_map()
                .payload_bytes(invocation.stdin(), retained.source_record_ordinal())
                .ok_or(LegacyDrainNormalizationErrorV1::UnsupportedInput)?;
            let text = std::str::from_utf8(payload)
                .map_err(|_| LegacyDrainNormalizationErrorV1::UnsupportedInput)?;
            validate_pinned_sample_fields(text, sample)?;
            check_string(&sample.text, limits)?;
            let transformed_sample_artifact_digest =
                derive_transformed_sample_artifact_digest(sample)?;
            pattern_memberships.push(LegacyDrainPatternRepresentedV1 {
                retained_index: sample.index,
                source_record_ordinal: retained.source_record_ordinal(),
                event_id: retained.event_id(),
                group_id: group.id,
                group_pattern_artifact_digest,
            });
            transformed_samples.push(LegacyDrainTransformedSampleV1 {
                retained_index: sample.index,
                source_record_ordinal: retained.source_record_ordinal(),
                event_id: retained.event_id(),
                group_id: group.id,
                transformed_sample_artifact_digest,
            });
        }
    }

    if count(observed_indices.len())? != expected_count
        || observed_indices
            .iter()
            .copied()
            .enumerate()
            .any(|(expected, observed)| u64::try_from(expected).ok() != Some(observed))
    {
        return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
    }
    pattern_memberships.sort_unstable_by_key(|member| member.retained_index);
    transformed_samples.sort_unstable_by_key(|sample| sample.retained_index);
    if pattern_memberships
        .iter()
        .zip(&transformed_samples)
        .enumerate()
        .any(|(expected, (member, sample))| {
            u64::try_from(expected).ok() != Some(member.retained_index)
                || member.retained_index != sample.retained_index
                || member.event_id != sample.event_id
        })
    {
        return Err(LegacyDrainNormalizationErrorV1::FullMembershipIncompleteSamples);
    }
    Ok((pattern_memberships, transformed_samples))
}

pub(crate) struct ExpectedPinnedSampleV1 {
    pub(crate) message: String,
    pub(crate) level: Option<String>,
    pub(crate) timestamp: Option<String>,
}

fn validate_pinned_sample_fields(
    source_payload: &str,
    sample: &PinnedTemplateSampleV1,
) -> Result<(), LegacyDrainNormalizationErrorV1> {
    let expected = parse_pinned_ascii_line(source_payload)?;
    if sample.text != expected.message
        || sample.level.0 != expected.level
        || sample.timestamp.0 != expected.timestamp
    {
        return Err(LegacyDrainNormalizationErrorV1::SampleNormalizationMismatch);
    }
    Ok(())
}

pub(crate) fn parse_pinned_ascii_line(
    line: &str,
) -> Result<ExpectedPinnedSampleV1, LegacyDrainNormalizationErrorV1> {
    if !line.is_ascii() {
        return Err(LegacyDrainNormalizationErrorV1::UnsupportedInput);
    }
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(ExpectedPinnedSampleV1 {
            message: String::new(),
            level: None,
            timestamp: None,
        });
    }

    let mut timestamp = None;
    let mut level = None;
    let mut consumed = 0_usize;
    if tokens.len() >= 2 {
        let joined = format!("{} {}", tokens[0], tokens[1]);
        if is_pinned_ascii_timestamp(&joined) {
            timestamp = Some(joined);
            consumed = 2;
        }
    }
    if timestamp.is_none() && is_pinned_ascii_timestamp(tokens[0]) {
        timestamp = Some(tokens[0].to_owned());
        consumed = 1;
    }

    let scan_end = consumed.saturating_add(3).min(tokens.len());
    for (index, token) in tokens.iter().enumerate().take(scan_end).skip(consumed) {
        let bare = token
            .trim_matches(|character| "[](){}<>.,;:'\"".contains(character))
            .to_ascii_lowercase();
        if matches!(
            bare.as_str(),
            "error"
                | "err"
                | "warn"
                | "warning"
                | "fatal"
                | "critical"
                | "crit"
                | "info"
                | "debug"
                | "trace"
                | "notice"
        ) {
            level = Some(bare);
            consumed = index + 1;
            break;
        }
    }

    Ok(ExpectedPinnedSampleV1 {
        message: tokens[consumed..].join(" "),
        level,
        timestamp,
    })
}

fn is_pinned_ascii_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if (10..=13).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_digit) {
        return true;
    }
    if bytes.len() < 10
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || bytes[4] != b'-'
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || bytes[7] != b'-'
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    if bytes.len() == 10 {
        return true;
    }
    if !matches!(bytes[10], b'T' | b' ') || bytes.len() < 19 {
        return false;
    }
    if !bytes[11..13].iter().all(u8::is_ascii_digit)
        || bytes[13] != b':'
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || bytes[16] != b':'
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let mut position = 19;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let fraction_start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == fraction_start {
            return false;
        }
    }
    match &bytes[position..] {
        [] | [b'Z'] => true,
        [b'+' | b'-', a, b, c, d] => [a, b, c, d].iter().all(|byte| byte.is_ascii_digit()),
        [b'+' | b'-', a, b, b':', c, d] => [a, b, c, d].iter().all(|byte| byte.is_ascii_digit()),
        _ => false,
    }
}

fn derive_group_pattern_artifact_digest(
    group: &PinnedTemplateGroupV1,
) -> Result<ArtifactDigest, LegacyDrainNormalizationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GROUP_PATTERN_ARTIFACT_DOMAIN_V1)?;
    for value in [group.id, group.first_index, group.count] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, group.template.as_bytes())?;
    update_u64(&mut hasher, count(group.slots.len())?)?;
    for slot in &group.slots {
        update_u64(&mut hasher, u64::from(slot.numeric))?;
        for value in [
            slot.min.to_bits(),
            slot.max.to_bits(),
            slot.median.to_bits(),
        ] {
            update_u64(&mut hasher, value)?;
        }
        update_field(&mut hasher, slot.unit.as_bytes())?;
        update_u64(&mut hasher, slot.distinct)?;
        update_u64(&mut hasher, count(slot.samples.len())?)?;
        for sample in &slot.samples {
            update_field(&mut hasher, sample.as_bytes())?;
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_transformed_sample_artifact_digest(
    sample: &PinnedTemplateSampleV1,
) -> Result<ArtifactDigest, LegacyDrainNormalizationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, TRANSFORMED_SAMPLE_ARTIFACT_DOMAIN_V1)?;
    update_u64(&mut hasher, sample.index)?;
    update_field(&mut hasher, sample.text.as_bytes())?;
    update_optional_string(&mut hasher, sample.level.0.as_deref())?;
    update_optional_string(&mut hasher, sample.timestamp.0.as_deref())?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_optional_string(
    hasher: &mut Sha256,
    value: Option<&str>,
) -> Result<(), LegacyDrainNormalizationErrorV1> {
    match value {
        Some(value) => {
            update_u64(hasher, 1)?;
            update_field(hasher, value.as_bytes())
        }
        None => update_u64(hasher, 0),
    }
}

fn count(value: usize) -> Result<u64, LegacyDrainNormalizationErrorV1> {
    u64::try_from(value).map_err(|_| LegacyDrainNormalizationErrorV1::AccountingOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, LegacyDrainNormalizationErrorV1> {
    left.checked_add(right)
        .ok_or(LegacyDrainNormalizationErrorV1::AccountingOverflow)
}

fn check_json_safe(value: u64) -> Result<(), LegacyDrainNormalizationErrorV1> {
    if value > JSON_SAFE_INTEGER_MAX {
        return Err(LegacyDrainNormalizationErrorV1::IntegerOutsideContract);
    }
    Ok(())
}

fn check_string(
    value: &str,
    limits: LegacyDrainJsonLimitsV1,
) -> Result<(), LegacyDrainNormalizationErrorV1> {
    enforce_observed_limit(
        count(value.len())?,
        limits.string_bytes,
        LegacyDrainNormalizerLimitDimensionV1::StringBytes,
    )
}

fn enforce_observed_limit(
    observed: u64,
    limit: u64,
    dimension: LegacyDrainNormalizerLimitDimensionV1,
) -> Result<(), LegacyDrainNormalizationErrorV1> {
    if observed > limit {
        return Err(LegacyDrainNormalizationErrorV1::ObservedLimitExceeded { dimension });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_normalization_artifact_digest(
    invocation: &PublicSubprocessInvocationV1,
    limits: LegacyDrainJsonLimitsV1,
    normalizer_artifact_digest: ArtifactDigest,
    raw_stdout_artifact_digest: ArtifactDigest,
    raw_stderr_artifact_digest: ArtifactDigest,
    raw_stdout_byte_count: u64,
    raw_stderr_byte_count: u64,
    input: LegacyDrainInputNormalizationV1,
    retained_record_map_artifact_digest: ArtifactDigest,
    facts: ParsedFactsV1,
    membership: LegacyDrainMembershipUnprovableV1,
) -> Result<ArtifactDigest, LegacyDrainNormalizationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, NORMALIZATION_RECEIPT_DOMAIN_V1)?;
    update_u64(
        &mut hasher,
        LEGACY_DRAIN_JSON_NORMALIZER_CONTRACT_VERSION_V1,
    )?;
    for digest in [
        normalizer_artifact_digest,
        invocation.run_manifest_artifact_digest(),
        invocation.public_case_artifact_digest(),
        invocation.program().system_artifact_digest(),
        invocation.program().executable_build_artifact_digest(),
        invocation.stdin().artifact_digest(),
        invocation.source_record_map().map_artifact_digest(),
        retained_record_map_artifact_digest,
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
    ] {
        update_field(&mut hasher, digest.as_bytes())?;
    }
    update_field(&mut hasher, invocation.digest().as_bytes())?;
    for value in [
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        limits.json_bytes,
        limits.groups,
        limits.samples,
        limits.slots,
        limits.slot_samples,
        limits.string_bytes,
        input.input_byte_count(),
        input.logical_line_count(),
        input.retained_nonblank_line_count(),
        input.dropped_blank_line_count(),
        input.lf_terminator_count(),
        input.crlf_terminator_count(),
        u64::from(input.final_lf_present()),
        facts.original_count,
        facts.template_count,
        facts.group_count,
        facts.sample_count,
        facts.slot_count,
        facts.slot_sample_count,
        facts.line_compression_bits,
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, membership.code().as_bytes())?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_full_membership_artifact_digest(
    invocation: &PublicSubprocessInvocationV1,
    limits: LegacyDrainJsonLimitsV1,
    normalizer_artifact_digest: ArtifactDigest,
    adapter_artifact_digest: ArtifactDigest,
    raw_stdout_artifact_digest: ArtifactDigest,
    raw_stderr_artifact_digest: ArtifactDigest,
    raw_stdout_byte_count: u64,
    raw_stderr_byte_count: u64,
    input: LegacyDrainInputNormalizationV1,
    retained_record_map_artifact_digest: ArtifactDigest,
    facts: ParsedFactsV1,
    sample_cap: u64,
    charged_candidate_source_bytes: u64,
    pattern_memberships: &[LegacyDrainPatternRepresentedV1],
    transformed_samples: &[LegacyDrainTransformedSampleV1],
    quality_bridge: LegacyDrainQualityBridgeV1,
) -> Result<ArtifactDigest, LegacyDrainNormalizationErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FULL_MEMBERSHIP_ARTIFACT_DOMAIN_V1)?;
    update_u64(
        &mut hasher,
        LEGACY_DRAIN_FULL_MEMBERSHIP_NORMALIZER_CONTRACT_VERSION_V1,
    )?;
    for digest in [
        normalizer_artifact_digest,
        adapter_artifact_digest,
        invocation.run_manifest_artifact_digest(),
        invocation.public_case_artifact_digest(),
        invocation.program().system_artifact_digest(),
        invocation.program().executable_build_artifact_digest(),
        invocation.stdin().artifact_digest(),
        invocation.source_record_map().map_artifact_digest(),
        retained_record_map_artifact_digest,
        raw_stdout_artifact_digest,
        raw_stderr_artifact_digest,
    ] {
        update_field(&mut hasher, digest.as_bytes())?;
    }
    update_field(&mut hasher, invocation.digest().as_bytes())?;
    for value in [
        raw_stdout_byte_count,
        raw_stderr_byte_count,
        sample_cap,
        charged_candidate_source_bytes,
        limits.json_bytes,
        limits.groups,
        limits.samples,
        limits.slots,
        limits.slot_samples,
        limits.string_bytes,
        input.input_byte_count(),
        input.logical_line_count(),
        input.retained_nonblank_line_count(),
        input.dropped_blank_line_count(),
        input.lf_terminator_count(),
        input.crlf_terminator_count(),
        u64::from(input.final_lf_present()),
        facts.original_count,
        facts.template_count,
        facts.group_count,
        facts.sample_count,
        facts.slot_count,
        facts.slot_sample_count,
        facts.line_compression_bits,
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, quality_bridge.code().as_bytes())?;
    update_u64(&mut hasher, count(pattern_memberships.len())?)?;
    for member in pattern_memberships {
        for value in [
            member.retained_index,
            member.source_record_ordinal,
            member.group_id,
        ] {
            update_u64(&mut hasher, value)?;
        }
        update_field(&mut hasher, member.event_id.as_bytes())?;
        update_field(&mut hasher, member.group_pattern_artifact_digest.as_bytes())?;
    }
    update_u64(&mut hasher, count(transformed_samples.len())?)?;
    for sample in transformed_samples {
        for value in [
            sample.retained_index,
            sample.source_record_ordinal,
            sample.group_id,
        ] {
            update_u64(&mut hasher, value)?;
        }
        update_field(&mut hasher, sample.event_id.as_bytes())?;
        update_field(
            &mut hasher,
            sample.transformed_sample_artifact_digest.as_bytes(),
        )?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_u64(hasher: &mut Sha256, value: u64) -> Result<(), LegacyDrainNormalizationErrorV1> {
    update_field(hasher, &value.to_le_bytes())
}

fn update_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), LegacyDrainNormalizationErrorV1> {
    hasher.update(count(value.len())?.to_le_bytes());
    hasher.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TWO_RECORDS: &str = r#"{
        "groups": [{
            "id": 0,
            "first_index": 0,
            "count": 2,
            "template": "same <*>",
            "samples": [
                {"index": 0, "text": "same line", "level": null, "timestamp": null},
                {"index": 1, "text": "same line", "level": null, "timestamp": null}
            ],
            "slots": [{
                "numeric": false,
                "min": 0.0,
                "max": 0.0,
                "median": 0.0,
                "unit": "",
                "distinct": 1,
                "samples": ["line"]
            }]
        }],
        "original_count": 2,
        "template_count": 1,
        "line_compression": 2.0
    }"#;

    fn small_limits() -> LegacyDrainJsonLimitsV1 {
        LegacyDrainJsonLimitsV1::try_new(64 * 1024, 16, 32, 32, 64, 1024).unwrap()
    }

    fn parse(
        json: &str,
        expected_original_count: u64,
        sample_cap: u64,
    ) -> Result<ParsedFactsV1, LegacyDrainNormalizationErrorV1> {
        parse_and_validate_json(
            json.as_bytes(),
            expected_original_count,
            sample_cap,
            small_limits(),
        )
    }

    #[test]
    fn duplicate_payload_occurrences_remain_distinct_and_membership_is_unprovable() {
        let facts = parse(VALID_TWO_RECORDS, 2, 2).unwrap();
        assert_eq!(facts.sample_count, 2);
        let status = LegacyDrainMembershipUnprovableV1::CompleteGroupOccurrencePositionsAbsent;
        assert!(status.original_source_record_bytes_present());
        assert!(status.sampled_position_indices_structurally_bounded());
        assert!(!status.sampled_normalized_fields_verified_against_source());
        assert!(!status.sampled_occurrence_evidence_joinable());
        assert!(!status.complete_group_occurrence_positions_present());
        assert!(status.source_framing_preserved_by_binding());
    }

    #[test]
    fn pinned_ascii_line_contract_validates_message_level_and_timestamp_exactly() {
        let cases = [
            (
                "2026-05-22T14:13:00Z [WARN], disk   pressure high",
                "disk pressure high",
                Some("warn"),
                Some("2026-05-22T14:13:00Z"),
            ),
            (
                "2026-05-22 14:13:00 info worker idle",
                "worker idle",
                Some("info"),
                Some("2026-05-22 14:13:00"),
            ),
            (
                "prefix component ERROR failure id=9",
                "failure id=9",
                Some("error"),
                None,
            ),
            (
                "1700000000000 notice epoch record",
                "epoch record",
                Some("notice"),
                Some("1700000000000"),
            ),
        ];
        for (source, message, level, timestamp) in cases {
            let parsed = parse_pinned_ascii_line(source).unwrap();
            assert_eq!(parsed.message, message);
            assert_eq!(parsed.level.as_deref(), level);
            assert_eq!(parsed.timestamp.as_deref(), timestamp);
            let sample = PinnedTemplateSampleV1 {
                index: 0,
                text: message.to_owned(),
                level: RequiredNullableString(level.map(str::to_owned)),
                timestamp: RequiredNullableString(timestamp.map(str::to_owned)),
            };
            assert!(validate_pinned_sample_fields(source, &sample).is_ok());
        }

        let tampered = PinnedTemplateSampleV1 {
            index: 0,
            text: "disk pressure high".to_owned(),
            level: RequiredNullableString(Some("error".to_owned())),
            timestamp: RequiredNullableString(Some("2026-05-22T14:13:00Z".to_owned())),
        };
        assert_eq!(
            validate_pinned_sample_fields(
                "2026-05-22T14:13:00Z WARN disk pressure high",
                &tampered,
            ),
            Err(LegacyDrainNormalizationErrorV1::SampleNormalizationMismatch)
        );
        assert!(matches!(
            parse_pinned_ascii_line("INFO café"),
            Err(LegacyDrainNormalizationErrorV1::UnsupportedInput)
        ));
    }

    #[test]
    fn reordered_fields_are_accepted_but_reordered_groups_are_rejected() {
        let reordered_fields = r#"{
            "line_compression": 1.0,
            "template_count": 1,
            "original_count": 1,
            "groups": [{
                "slots": [],
                "samples": [{"timestamp": null, "level": null, "text": "x", "index": 0}],
                "template": "x",
                "count": 1,
                "first_index": 0,
                "id": 0
            }]
        }"#;
        assert!(parse(reordered_fields, 1, 1).is_ok());

        let reordered_groups = r#"{
            "groups": [
                {"id": 1, "first_index": 1, "count": 1, "template": "b",
                 "samples": [{"index": 1, "text": "b", "level": null, "timestamp": null}], "slots": []},
                {"id": 0, "first_index": 0, "count": 1, "template": "a",
                 "samples": [{"index": 0, "text": "a", "level": null, "timestamp": null}], "slots": []}
            ],
            "original_count": 2, "template_count": 2, "line_compression": 1.0
        }"#;
        assert_eq!(
            parse(reordered_groups, 2, 1),
            Err(LegacyDrainNormalizationErrorV1::StructuralMismatch)
        );
    }

    #[test]
    fn duplicate_keys_and_duplicate_occurrence_positions_fail_closed() {
        let duplicate_key = r#"{
            "groups": [], "original_count": 0, "original_count": 0,
            "template_count": 0, "line_compression": 0.0
        }"#;
        assert_eq!(
            parse(duplicate_key, 0, 1),
            Err(LegacyDrainNormalizationErrorV1::MalformedOrUnsupportedJson)
        );

        let duplicate_index = VALID_TWO_RECORDS.replace(
            "{\"index\": 1, \"text\": \"same line\"",
            "{\"index\": 0, \"text\": \"same line\"",
        );
        assert_eq!(
            parse(&duplicate_index, 2, 2),
            Err(LegacyDrainNormalizationErrorV1::StructuralMismatch)
        );
    }

    #[test]
    fn tampered_counts_and_compression_fail_closed() {
        let count = VALID_TWO_RECORDS.replace("\"count\": 2", "\"count\": 3");
        assert_eq!(
            parse(&count, 2, 2),
            Err(LegacyDrainNormalizationErrorV1::StructuralMismatch)
        );
        let compression =
            VALID_TWO_RECORDS.replace("\"line_compression\": 2.0", "\"line_compression\": 3.0");
        assert_eq!(
            parse(&compression, 2, 2),
            Err(LegacyDrainNormalizationErrorV1::NumericValueInvalid)
        );
    }

    #[test]
    fn byte_and_string_limits_apply_before_semantic_use() {
        let byte_limits = LegacyDrainJsonLimitsV1::try_new(32, 16, 32, 32, 64, 1024).unwrap();
        assert_eq!(
            parse_and_validate_json(VALID_TWO_RECORDS.as_bytes(), 2, 2, byte_limits),
            Err(LegacyDrainNormalizationErrorV1::ObservedLimitExceeded {
                dimension: LegacyDrainNormalizerLimitDimensionV1::JsonBytes,
            })
        );

        let string_limits = LegacyDrainJsonLimitsV1::try_new(64 * 1024, 16, 32, 32, 64, 4).unwrap();
        assert_eq!(
            parse_and_validate_json(VALID_TWO_RECORDS.as_bytes(), 2, 2, string_limits),
            Err(LegacyDrainNormalizationErrorV1::ObservedLimitExceeded {
                dimension: LegacyDrainNormalizerLimitDimensionV1::StringBytes,
            })
        );
        assert!(matches!(
            LegacyDrainJsonLimitsV1::try_new(MAX_LEGACY_DRAIN_JSON_BYTES_V1 + 1, 1, 1, 1, 1, 1),
            Err(LegacyDrainNormalizationErrorV1::LimitExceedsHardBound {
                dimension: LegacyDrainNormalizerLimitDimensionV1::JsonBytes
            })
        ));
    }

    #[test]
    fn unknown_fields_at_every_level_are_rejected() {
        for altered in [
            VALID_TWO_RECORDS.replace(
                "\"original_count\": 2",
                "\"unknown\": 1, \"original_count\": 2",
            ),
            VALID_TWO_RECORDS.replace("\"id\": 0", "\"context\": [], \"id\": 0"),
            VALID_TWO_RECORDS.replace("\"index\": 0", "\"generated_summary\": \"x\", \"index\": 0"),
            VALID_TWO_RECORDS.replace(
                "\"numeric\": false",
                "\"member_ids\": [0], \"numeric\": false",
            ),
        ] {
            assert_eq!(
                parse(&altered, 2, 2),
                Err(LegacyDrainNormalizationErrorV1::MalformedOrUnsupportedJson)
            );
        }
    }

    #[test]
    fn injected_strings_are_inert_and_never_enter_diagnostics() {
        let canary = "GOLD_EVENT_ID=secret\\n{\\\"annotation\\\":true}";
        let injected = VALID_TWO_RECORDS.replacen("same <*>", canary, 1);
        assert!(parse(&injected, 2, 2).is_ok());

        let status = LegacyDrainMembershipUnprovableV1::CompleteGroupOccurrencePositionsAbsent;
        assert!(!format!("{status:?}").contains("GOLD_EVENT_ID"));
        let malformed = format!("{VALID_TWO_RECORDS}{canary}");
        let error = parse(&malformed, 2, 2).unwrap_err();
        assert!(!format!("{error:?}").contains("GOLD_EVENT_ID"));
    }

    #[test]
    fn missing_nullable_fields_and_unsafe_integer_width_are_rejected() {
        let missing_nullable = VALID_TWO_RECORDS.replace(
            ", \"level\": null, \"timestamp\": null",
            ", \"timestamp\": null",
        );
        assert_eq!(
            parse(&missing_nullable, 2, 2),
            Err(LegacyDrainNormalizationErrorV1::MalformedOrUnsupportedJson)
        );
        let unsafe_integer =
            VALID_TWO_RECORDS.replace("\"index\": 1", "\"index\": 9007199254740992");
        assert_eq!(
            parse(&unsafe_integer, 2, 2),
            Err(LegacyDrainNormalizationErrorV1::IntegerOutsideContract)
        );
    }
}
