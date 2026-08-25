//! Hermetic, benchmark-only subprocess execution for external EvidentrailBench arms.
//!
//! This crate is intentionally outside every product dependency path. Its
//! invocation types contain only public run identity, public case identity,
//! explicit input bytes, and execution policy. Governed annotations and hidden
//! evaluation manifests are not accepted by any invocation API.

mod legacy_drain;
mod legacy_drain_normalizer;
mod compact_agent_view;
mod compact_agent_view_admission;
mod constrained_matched_case;
mod constrained_producer_universe;
mod domain;
mod fidelity_bridge;
mod first_party_log_brief;
mod first_party_subprocess;
mod hermetic_drain_fixture;
mod hosted_reader_jsonl;
mod matched_representation;
mod paired_reader;
mod paired_trials;
mod peak_rss_observer;
mod pinned_matched_case;
mod process;
mod public_case_input;
mod reader;
mod submission;

pub use legacy_drain::{
    LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1, LEGACY_DRAIN_PINNED_COMMIT_V1,
    LegacyDrainAdapterModeV1, LegacyDrainAdapterV1, LegacyDrainFullMembershipSupportV1,
    LegacyDrainInputAssessmentV1, LegacyDrainInputNormalizationV1, LegacyDrainUnsupportedInputV1,
    MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_INPUT_BYTES_V1, MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1,
    legacy_drain_full_membership_adapter_artifact_digest_v1,
};
pub use legacy_drain_normalizer::{
    LEGACY_DRAIN_FULL_MEMBERSHIP_NORMALIZER_CONTRACT_VERSION_V1,
    LEGACY_DRAIN_JSON_NORMALIZER_CONTRACT_VERSION_V1, LegacyDrainFullMembershipArtifactV1,
    LegacyDrainJsonLimitsV1, LegacyDrainMembershipUnprovableV1, LegacyDrainNormalizationErrorV1,
    LegacyDrainNormalizerLimitDimensionV1, LegacyDrainOpaqueNormalizationReceiptV1,
    LegacyDrainPatternRepresentedV1, LegacyDrainQualityBridgeV1, LegacyDrainTransformedSampleV1,
    MAX_LEGACY_DRAIN_JSON_BYTES_V1, MAX_LEGACY_DRAIN_JSON_COLLECTION_ITEMS_V1,
    MAX_LEGACY_DRAIN_JSON_GROUPS_V1, MAX_LEGACY_DRAIN_JSON_STRING_BYTES_V1,
    legacy_drain_full_membership_normalizer_artifact_digest_v1,
    legacy_drain_json_normalizer_artifact_digest_v1,
    strict_normalize_pinned_legacy_drain_full_membership_v1,
    strict_normalize_pinned_legacy_drain_output_v1,
};
pub use compact_agent_view::{
    COMPACT_AGENT_VIEW_CONTRACT_VERSION_V1, COMPACT_AGENT_VIEW_RENDERER_CONTRACT_VERSION_V1,
    CompactAgentViewAdmissionProposalV1, CompactAgentViewAdmissionStatusV1,
    CompactAgentViewAuditReceiptV1, CompactAgentViewCaseReductionV1, CompactAgentViewConfigV1,
    CompactAgentViewCorpusReductionReceiptV1, CompactAgentViewErrorV1,
    CompactAgentViewEventProofV1, CompactAgentViewPacketAuditV1,
    CompactAgentViewReaderPreservationReceiptV1, CompactAgentViewV1,
    compact_agent_view_method_descriptor_v1, compact_agent_view_renderer_artifact_digest_v1,
    compare_compact_agent_view_reader_receipts_v1, freeze_compact_compiled_agent_view_v1,
};
pub use compact_agent_view_admission::{
    COMPACT_AGENT_VIEW_ADMISSION_MEASUREMENT_CONTRACT_VERSION_V1,
    COMPACT_AGENT_VIEW_CHALLENGE_CORPUS_CONTRACT_VERSION_V1,
    COMPACT_AGENT_VIEW_CHALLENGE_NEEDS_MORE_CASE_COUNT_V1,
    COMPACT_AGENT_VIEW_CHALLENGE_RENDERED_CASE_COUNT_V1, CompactAgentViewAdmissionErrorV1,
    CompactAgentViewChallengeClassV1, CompactAgentViewChallengeCorpusReceiptV1,
    CompactAgentViewChallengeObservationV1, CompactAgentViewMeasuredArmV1,
    CompactAgentViewNeedsMoreObservationV1, CompactAgentViewProductionAdmissionEvidenceV1,
    CompactAgentViewProductionAdmissionStatusV1, CompactAgentViewProductionCandidateParityV1,
    CompactAgentViewReaderArmMeasurementV1, CompactAgentViewReaderMeasurementPairV1,
    MAX_COMPACT_AGENT_VIEW_MEASURED_READER_PAIRS_V1,
    compact_agent_view_challenge_corpus_identity_v1,
};
pub use constrained_matched_case::{
    CONSTRAINED_MATCHED_GENERATOR_SEED_V1, CONSTRAINED_MATCHED_GENERATOR_VERSION_V1,
    CONSTRAINED_MATCHED_IDENTIFIER_V1, CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1,
    CONSTRAINED_MATCHED_QUESTION_V1, ConstrainedMatchedCaseErrorV1,
    ConstrainedMatchedGeneratorReceiptV1, FinalizedConstrainedPinnedDrainMatchedCaseV1,
    PreparedConstrainedPinnedDrainMatchedCaseV1, ValidatedThreeLaneProposalAuditReceiptV1,
    constrained_pinned_drain_plan_digest_v1, constrained_pinned_drain_public_case_v1,
    constrained_pinned_drain_public_input_v1, execute_constrained_first_party_fixture_v1,
    execute_constrained_first_party_structured_fixture_v1,
    prepare_constrained_pinned_drain_matched_case_v1,
};
pub use constrained_producer_universe::{
    BoundLabelFreeProducerUniverseV1, ConstrainedProducerUniverseBridgeErrorV1,
    ConstrainedProducerUniverseBridgeV1, ProducerUniverseBasisV1,
    freeze_constrained_producer_universes_v1,
};
pub use domain::{
    ClosedEnvironmentV1, EnvironmentBindingV1, ExecutableBuildV1, ExternalOutputContractV1,
    HarnessError, HarnessLimitDimensionV1, HarnessLimitsV1, InvocationDigestV1,
    InvocationInputContractV1, MAX_HARNESS_STREAM_BYTES_V1, MAX_HARNESS_WALL_NANOS_V1,
    PublicCaseInputBindingV1, PublicCaseResolutionTrustV1, PublicCaseStdinBindingV1,
    PublicSubprocessInvocationV1, StdinArtifactClassV1, StdinArtifactV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
};
pub use fidelity_bridge::{
    CanonicalTokenCountProvenanceV1, LegacyDrainFidelityBridgeErrorV1,
    LegacyDrainFullMembershipRepresentationReceiptV1, legacy_drain_compact_method_descriptor_v1,
    legacy_drain_full_membership_method_descriptor_v1,
    freeze_legacy_drain_full_membership_representation_v1, measure_canonical_utf8_byte_tokens_v1,
};
pub use first_party_log_brief::{
    FirstPartyInputUniverseChargeV1, FirstPartyLogBriefBridgeErrorV1,
    FirstPartyLogBriefRepresentationReceiptV1,
    freeze_bound_owned_compiled_log_brief_representation_v1,
    freeze_bound_owned_passthrough_log_brief_representation_v1,
    freeze_compiled_log_brief_representation_v1, freeze_owned_compiled_log_brief_representation_v1,
    freeze_owned_passthrough_log_brief_representation_v1,
    freeze_passthrough_log_brief_representation_v1, log_brief_compiled_method_descriptor_v1,
    log_brief_passthrough_method_descriptor_v1,
};
pub use first_party_subprocess::{
    FIRST_PARTY_CONSTRAINED_SUBPROCESS_ADAPTER_CONTRACT_VERSION_V1,
    FirstPartyConstrainedSubprocessErrorV1, FirstPartyConstrainedSubprocessReceiptV1,
    FirstPartyConstrainedSubprocessTargetV1, FirstPartyOracleTrustV1,
    FirstPartyParentOracleBuildV1, FirstPartySubprocessPeakRssStateV1,
};
#[doc(hidden)]
pub use hermetic_drain_fixture::{
    HermeticDrainFixtureErrorV1, hermetic_legacy_drain_full_membership_fixture_json_v1,
};
pub use hosted_reader_jsonl::{
    HOSTED_READER_FAILURE_RULES_V1, HOSTED_READER_JSONL_ADAPTER_CONTRACT_VERSION_V1,
    HOSTED_READER_JSONL_REQUEST_SCHEMA_VERSION_V1, HOSTED_READER_JSONL_RESPONSE_SCHEMA_VERSION_V1,
    HOSTED_READER_SYSTEM_MESSAGE_V1, HostedReaderDecodingConfigV1, HostedReaderFailureRuleV1,
    HostedReaderJsonlAdapterSpecV1, HostedReaderJsonlCapsV1, HostedReaderJsonlErrorV1,
    HostedReaderJsonlRequestV1, HostedReaderModelMessagesV1,
    hosted_reader_failure_policy_artifact_digest_v1,
    hosted_reader_jsonl_request_contract_artifact_digest_v1,
    hosted_reader_jsonl_response_contract_artifact_digest_v1,
    hosted_reader_prompt_template_artifact_digest_v1,
    hosted_reader_redaction_policy_artifact_digest_v1,
};
pub use matched_representation::{
    MatchedRepresentationArmReceiptV1, MatchedRepresentationArmV1, MatchedRepresentationArmsV1,
    MatchedRepresentationComparisonV1, MatchedRepresentationErrorV1,
    MatchedRepresentationNeedsDownstreamVdsV1, MatchedResourceMeasurementTrustV1,
    MatchedRuntimeDimensionV1, MatchedStaticRepresentationScoresV1,
    StaticRepresentationRecallOrderingV1, compare_matched_representations_v1,
};
pub use paired_reader::{
    CONSTRAINED_READER_CITATION_POLICY_VERSION_V1, CONSTRAINED_READER_CONTEXT_V1,
    CONSTRAINED_READER_PAIR_CONTRACT_VERSION_V1, ConstrainedReaderInputPairV1,
    ConstrainedReaderPairErrorV1, ConstrainedReaderPairRepeatabilityV1,
    FrozenConstrainedReaderPairV1, GovernedConstrainedReaderPairV1, GovernedReaderArmOutcomeV1,
    ReaderArmResourceObservationV1, evaluate_governed_constrained_reader_pair_v1,
    execute_constrained_reader_pair_v1, prepare_constrained_reader_input_pair_v1,
};
pub use paired_trials::{
    CONSTRAINED_FIRST_PARTY_POLICY_IDENTITY_CONTRACT_VERSION_V1,
    CONSTRAINED_PAIRED_TRIAL_CONTRACT_VERSION_V1, CONSTRAINED_PAIRED_TRIAL_COUNT_V1,
    ConstrainedFirstPartyPolicyIdentityV1, ConstrainedPairedArmRepeatabilityV1,
    ConstrainedPairedMultiTrialReceiptV1, ConstrainedPairedMultiTrialRunV1,
    ConstrainedPairedTrialArmObservationV1, ConstrainedPairedTrialErrorV1,
    ConstrainedPairedTrialOrderV1, ConstrainedPairedTrialV1, IntegerSpreadV1,
    current_constrained_first_party_policy_identity_v1,
    run_constrained_paired_trials_for_expected_policy_v1, run_constrained_paired_trials_v1,
};
pub use peak_rss_observer::{
    MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1,
    MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1, MacOsTimePeakRssObserverV1,
    MacOsTimePeakRssReceiptV1, PeakRssObserverErrorV1,
};
pub use pinned_matched_case::{
    BoundPeakRssObservationV1, FinalizedPinnedDrainMatchedCaseV1, FirstPartyInProcessBuildV1,
    MatchedCostComparisonEligibilityV1, MatchedExecutionScopeV1,
    PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1, PINNED_LEGACY_DRAIN_MATCHED_QUESTION_V1,
    PeakRssMeasurementUnitV1, PeakRssObservationBindingV1, PinnedLegacyDrainExecutionTargetV1,
    PinnedLegacyDrainTargetClassV1, PinnedDrainMatchedArmV1, PreparedPinnedDrainMatchedCaseErrorV1,
    PreparedPinnedDrainMatchedCaseV1, pinned_legacy_drain_matched_ledger_v1,
    pinned_legacy_drain_matched_plan_digest_v1, prepare_pinned_drain_matched_case_v1,
};
pub use process::{
    CapturedStreamV1, ExitCategoryV1, HarnessTerminationCauseV1, StdinDeliveryV1,
    StreamCaptureStateV1, SubprocessExecutionReceiptV1, execute_public_subprocess_v1,
};
pub use public_case_input::{
    CANONICAL_PUBLIC_CASE_ARTIFACT_CONTRACT_VERSION_V1,
    CANONICAL_PUBLIC_RUN_MANIFEST_ARTIFACT_CONTRACT_VERSION_V1, CanonicalPublicCaseArtifactV1,
    CanonicalPublicRunManifestArtifactV1, CanonicalPublicSourceRecordMapV1,
    CanonicalPublicSourceRecordV1, LegacyDrainRetainedRecordMapV1, LegacyDrainRetainedSourceRecordV1,
    MAX_CANONICAL_PUBLIC_SOURCE_RECORDS_V1, canonical_public_case_artifact_v1,
    canonical_public_run_manifest_artifact_v1,
};
pub use reader::{
    DETERMINISTIC_FIXTURE_READER_CONTRACT_VERSION_V1, DeterministicFixtureReaderModeV1,
    DeterministicFixtureReaderV1, FrozenReaderSingleShotReceiptV1, GovernedReaderScoreV1,
    GovernedReaderTruthV1, MAX_READER_ANSWER_BYTES_V1, MAX_READER_CITATIONS_V1,
    MAX_READER_CLAIMS_V1, MAX_READER_CONTEXT_BYTES_V1, MAX_READER_METHOD_ARTIFACT_BYTES_V1,
    MAX_READER_QUESTION_BYTES_V1, READER_ANSWER_SCHEMA_VERSION_V1,
    READER_PROMPT_TEMPLATE_VERSION_V1, READER_SINGLE_SHOT_CONTRACT_VERSION_V1,
    ReaderAbstentionAssessmentV1, ReaderAnswerV1, ReaderCauseGranularityV1, ReaderCitationHandleV1,
    ReaderErrorV1, ReaderMethodArtifactV1, ReaderPromptV1, ReaderPublicInputV1,
    ReaderRepeatabilityReceiptV1, ReaderResourceCapsV1, evaluate_governed_reader_v1,
    execute_deterministic_fixture_reader_v1,
};
pub use submission::{
    PeakRssProvenanceV1, PublicExternalResultSubmissionV1,
    SelfAssertedExternalMeasurementReceiptV1, StrictNormalizedExternalOutputV1,
    strict_identity_normalize_v1,
};
