//! Canonical deterministic compilation of Evidentrail's three active evidence lanes.
//!
//! This crate validates the exhaustive primary-block universe, merges only
//! production-computable facets, certifies conservative renderer costs, and
//! invokes intact-packet selection. It performs no rendering, model calls,
//! diagnosis generation, source access, or result persistence.

#[cfg(feature = "benchmark-instrumentation")]
mod ablation;
mod compiler;
mod proposal;
mod types;

#[cfg(feature = "benchmark-instrumentation")]
pub use ablation::{
    PreparedThreeLaneAblationSetV1, PreparedThreeLaneAblationV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1, three_lane_ablation_config_digest_v1,
    three_lane_ablation_method_family_digest_v1,
};
#[cfg(feature = "benchmark-instrumentation")]
pub use compiler::{
    benchmark_selection_problem_for_prepared_three_lane_ablation_v1,
    prepare_ready_three_lane_ablations_v1, prepare_three_lane_ablations_v1,
    select_prepared_three_lane_ablation_v1,
};
pub use compiler::{
    compile_ready_three_lanes_v1, compile_three_lanes_v1,
    prepare_ready_three_lane_proposal_universe_v1, prepare_three_lane_proposal_universe_v1,
    select_prepared_three_lane_proposals_v1,
};
pub use proposal::{
    PROPOSAL_COMPILER_POLICY_NAME_V1, PROPOSAL_COMPILER_POLICY_VERSION_V1,
    PROPOSAL_PREPARATION_CONTRACT_VERSION_V1, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1,
    PreparedThreeLaneNeedsMoreV1, PreparedThreeLaneProposalUniverseV1,
    PreparedThreeLaneSelectionDecisionV1, ProposalPreparationInputReceiptV1,
    ProposalUniverseAccountingErrorV1, ProposalUniverseAccountingV1, ProposalUniverseReceiptV1,
    ThreeLaneProposalPreparationDecisionV1, ThreeLaneProposalPreparationNeedsMoreV1,
    proposal_candidate_config_digest_v1, proposal_compiler_config_digest_v1,
};
pub use types::{
    CandidateLaneV1, CertifiedThreeLaneSelectionV1, CompiledPacketMetadataV1,
    LaneUniverseViolationV1, ReadyCandidateLanesV1, ThreeLaneCompileDecisionV1,
    ThreeLaneCompileErrorV1, ThreeLaneNeedsMoreV1,
};
