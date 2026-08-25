/// Maximum exact question bytes accepted by the V1 lexical lane.
pub const MAX_QUESTION_BYTES_V1: usize = 64 * 1024;
/// Maximum raw ASCII-token occurrences accepted from one question.
pub const MAX_QUERY_TOKENS_V1: usize = 256;
/// Minimum canonical bytes for a free-text query term.
pub const MIN_QUERY_TERM_BYTES_V1: usize = 2;
/// Maximum bytes in any question token, including a typed identifier.
pub const MAX_QUERY_TERM_BYTES_V1: usize = 128;
/// Maximum distinct non-identifier query terms.
pub const MAX_QUERY_TERMS_V1: usize = 128;
/// Maximum distinct syntactically validated identifiers in one question.
pub const MAX_VALIDATED_QUERY_IDENTIFIERS_V1: usize = 32;
/// Maximum exhaustive primary blocks inspected by this lane.
pub const MAX_PRIMARY_BLOCKS_V1: usize = 4_096;
/// Maximum exact authorized block bytes inspected by this lane.
pub const MAX_PRIMARY_BYTES_SCANNED_V1: u64 = 64 * 1024 * 1024;
/// Maximum primary blocks forced by any one validated identifier.
pub const MAX_IDENTIFIER_BLOCK_FANOUT_V1: usize = 64;
/// Maximum distinct primary blocks forced across all identifiers.
pub const MAX_MANDATORY_BLOCKS_V1: usize = 64;
/// Maximum nonzero affinities plus mandatory-reason records emitted.
pub const MAX_EMITTED_SIGNALS_V1: usize = 65_536;

/// Maximum byte-analysis tokens inspected by failure/coverage lane V1.
pub const MAX_COVERAGE_ANALYSIS_TOKENS_V1: u64 = 8 * 1024 * 1024;
/// Maximum exact failure/onset token observations inspected by lane V1.
pub const MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1: usize = 65_536;
/// Maximum distinct `(source member, stream)` lanes annotated by lane V1.
pub const MAX_COVERAGE_SOURCE_LANES_V1: usize = 1_024;
/// Fixed acquisition-order strata used when emitting time-coverage sentinels.
pub const MAX_TIME_COVERAGE_STRATA_V1: usize = 8;
/// Maximum canonical block representatives with selection authority for each
/// reconstruction-risk kind. Five preserves head, lower-middle, tail, and two
/// evenly spaced interior strata without promoting every risky block.
pub const MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1: usize = 5;
/// Maximum production facets emitted by failure/coverage lane V1.
pub const MAX_COVERAGE_OUTPUT_FACETS_V1: usize = 4_096;
/// Maximum block-to-facet affinities emitted by failure/coverage lane V1.
pub const MAX_COVERAGE_OUTPUT_AFFINITIES_V1: usize = 32_768;
/// Maximum transparent sentinel labels emitted by failure/coverage lane V1.
pub const MAX_COVERAGE_OUTPUT_SENTINELS_V1: usize = 8_192;

/// Maximum exact typed namespace/native-identity bytes hashed by lane 3.
pub const MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1: u64 = 16 * 1024 * 1024;
/// Maximum adapter-attested scope/kind/value bytes inspected by lane 3.
pub const MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1: u64 = 16 * 1024 * 1024;
/// Maximum canonical adapter attestations inspected across one result.
pub const MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1: usize = 65_536;
/// Maximum distinct namespace-scoped native identity keys.
pub const MAX_PROVIDER_CORRELATION_KEYS_V1: usize = 4_096;
/// Maximum distinct `(correlation key, primary block)` graph nodes.
pub const MAX_PROVIDER_GRAPH_NODES_V1: usize = 8_192;
/// Maximum direct, typed graph edges emitted by lane 3.
pub const MAX_PROVIDER_GRAPH_EDGES_V1: usize = 4_096;
/// Maximum primary blocks joined by one namespace-scoped native identity.
pub const MAX_PROVIDER_RELATION_FANOUT_V1: usize = 64;
/// Maximum emitted graph degree for any one primary block.
pub const MAX_PROVIDER_GRAPH_DEGREE_V1: usize = 64;
/// V1 emits only direct relations; it performs no recursive graph walk.
pub const MAX_PROVIDER_GRAPH_HOP_DEPTH_V1: u8 = 1;
/// Maximum provider-correlation facets emitted by lane 3.
pub const MAX_PROVIDER_OUTPUT_FACETS_V1: usize = 2_048;
/// Maximum block-to-provider-facet affinities emitted by lane 3.
pub const MAX_PROVIDER_OUTPUT_AFFINITIES_V1: usize = 4_096;
