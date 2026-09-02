//! Deterministic V1 selection over intact, event-disjoint evidence packets.
//!
//! The objective is normalized monotone facility coverage. Runtime inputs are
//! restricted to nonnegative production-computable facets; there are no gold
//! labels, negative redundancy penalties, floats, overlapping packet costs,
//! learned scores, or packet splitting in this crate.
//!
//! A [`SelectionV1`] is a deterministic candidate set, not a compiled-result
//! token certificate. Its additive costs are caller declarations bound to a
//! pinned composable cost-model identity with fixed overhead reserved. This
//! crate checks their arithmetic and identity consistency, but does not certify
//! their derivation.
//! The downstream renderer must still render the complete artifact and run the
//! pinned tokenizer once over that whole render before issuing `compiled`.

mod problem;
mod types;

pub use problem::{
    NeedsMoreReasonV1, NeedsMoreSelectionV1, ObjectiveEvaluationError,
    OptionalPacketPriorityErrorV1, OptionalPacketPriorityV1, SelectedPacketV1,
    SelectionConstraintV1, SelectionDecisionV1, SelectionInvariantError,
    SelectionProblemConstructionError, SelectionProblemV1, SelectionStrategyV1, SelectionV1,
};
pub use types::{
    AFFINITY_SCALE_V1, AffinityV1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1,
    ComposableCostModelV1, ComposablePacketCostV1, FacetAffinityV1, FacetConstructionError,
    FacetIdV1, FacetSaturationCardinalityV1, FacetWeightV1, FixedPointConstructionError,
    IntactPacketV1, MAX_FACET_SATURATION_CARDINALITY_V1, MAX_FACET_SEMANTIC_KEY_BYTES_V1,
    MAX_MANDATORY_PACKETS_V1, MAX_PACKET_EVENTS_V1, MAX_SELECTION_EVENTS_V1,
    MAX_SELECTION_FACETS_V1, MAX_SELECTION_PACKETS_V1, MandatoryPacketV1, ObjectiveGainV1,
    PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, PacketConstructionError, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1,
    SELECTION_OBJECTIVE_POLICY_NAME_V1, SELECTION_OBJECTIVE_POLICY_VERSION_V1,
    TokenValueConstructionError, TotalTokenBudgetV1,
};
