//! Deterministic active evidence-lane annotations over Evidentrail's exhaustive
//! primary block partition.
//!
//! V1 uses two separate integer components: a linear bounded rarity weight
//! `(N - df + 1) / (N + 1)` for query-term facets, and normalized BM25-style
//! term-frequency/length saturation with `k1=6/5`, `b=3/4` for affinities. It
//! deliberately does not claim BM25's logarithmic IDF.

mod bounds;
mod coverage;
mod coverage_types;
mod lexical;
mod provider;
mod provider_types;
mod query;
mod types;

pub use bounds::{
    MAX_COVERAGE_ANALYSIS_TOKENS_V1, MAX_COVERAGE_OUTPUT_AFFINITIES_V1,
    MAX_COVERAGE_OUTPUT_FACETS_V1, MAX_COVERAGE_OUTPUT_SENTINELS_V1,
    MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1, MAX_COVERAGE_SOURCE_LANES_V1, MAX_EMITTED_SIGNALS_V1,
    MAX_IDENTIFIER_BLOCK_FANOUT_V1, MAX_MANDATORY_BLOCKS_V1, MAX_PRIMARY_BLOCKS_V1,
    MAX_PRIMARY_BYTES_SCANNED_V1, MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1,
    MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1, MAX_PROVIDER_CORRELATION_KEYS_V1,
    MAX_PROVIDER_GRAPH_DEGREE_V1, MAX_PROVIDER_GRAPH_EDGES_V1, MAX_PROVIDER_GRAPH_HOP_DEPTH_V1,
    MAX_PROVIDER_GRAPH_NODES_V1, MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1,
    MAX_PROVIDER_OUTPUT_AFFINITIES_V1, MAX_PROVIDER_OUTPUT_FACETS_V1,
    MAX_PROVIDER_RELATION_FANOUT_V1, MAX_QUERY_TERM_BYTES_V1, MAX_QUERY_TERMS_V1,
    MAX_QUERY_TOKENS_V1, MAX_QUESTION_BYTES_V1,
    MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1, MAX_TIME_COVERAGE_STRATA_V1,
    MAX_VALIDATED_QUERY_IDENTIFIERS_V1, MIN_QUERY_TERM_BYTES_V1,
};
pub use coverage::generate_failure_coverage_candidates_v1;
pub use coverage_types::{
    BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1, COVERAGE_CANDIDATE_POLICY_NAME_V1,
    COVERAGE_CANDIDATE_POLICY_VERSION_V1, CoverageAccountingV1, CoverageBlockAnnotationV1,
    CoverageCandidateUniverseV1, CoverageFacetRoleV1, CoverageFacetV1,
    CoverageGenerationDecisionV1, CoverageSentinelKindV1, CoverageSentinelV1, FailureBlockFactV1,
    FailureSignalCountV1, FailureSignalKindV1, OnsetBoundaryFactV1, OnsetBoundaryRoleV1,
    OnsetSignalCountV1, OnsetSignalKindV1, ReconstructionRiskKindV1, SourceCoverageStratumKindV1,
};
pub use lexical::{annotate_preprocessed_query_v1, generate_lexical_candidates_v1};
pub use provider::generate_provider_correlations_v1;
pub use provider_types::{
    PROVIDER_CORRELATION_POLICY_NAME_V1, PROVIDER_CORRELATION_POLICY_VERSION_V1,
    ProviderBlockAnnotationV1, ProviderBlockRelationV1, ProviderCorrelationAccountingV1,
    ProviderCorrelationCapabilityV1, ProviderCorrelationFacetV1,
    ProviderCorrelationGenerationDecisionV1, ProviderCorrelationKeyV1,
    ProviderCorrelationUniverseV1, ProviderGraphEdgeV1, ProviderOrderingBasisV1,
    ProviderRelationKindV1, ProviderRelationSourceV1,
};
pub use query::{
    PreprocessedQueryV1, QueryTermV1, ValidatedIdentifierKindV1, ValidatedQueryIdentifierV1,
    preprocess_query_v1,
};
pub use types::{
    CANDIDATE_POLICY_NAME_V1, CANDIDATE_POLICY_VERSION_V1, CandidateBuildErrorV1, CandidateFacetV1,
    CandidateGenerationDecisionV1, CandidateNeedsMoreReasonV1, CandidateNeedsMoreV1,
    LexicalCandidateUniverseV1, MandatoryIdentifierReasonV1, PrimaryBlockCandidateV1,
};
