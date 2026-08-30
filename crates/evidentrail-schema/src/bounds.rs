//! Version-one structural limits shared by wire and product contracts.
//!
//! These are hard representation limits, not acquisition policy defaults.
//! Callers may impose smaller limits. The result lifetime is the sole default
//! in this module and remains subject to local policy.

/// Largest integer represented as a JSON number without loss in IEEE-754
/// implementations.
pub const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// Largest encoded size of one wire object.
pub const MAX_WIRE_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// Largest encoded query-plan object.
pub const MAX_QUERY_PLAN_BYTES: usize = 1024 * 1024;

/// Largest encoded approved local-file binding object.
pub const MAX_APPROVED_LOCAL_FILE_BINDING_BYTES: usize = 64 * 1024;

/// Largest canonical absolute root byte path admitted by the Unix local-file
/// V1 representation. This is a product representation bound, not a claim
/// about every supported filesystem's runtime limit.
pub const MAX_UNIX_LOCAL_FILE_ROOT_BYTES: usize = 4 * 1024;

/// Largest one-byte-path component admitted by the Unix local-file V1
/// representation.
pub const MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES: usize = 255;

/// Largest number of root-relative member components in one Unix local-file
/// V1 locator.
pub const MAX_UNIX_LOCAL_FILE_COMPONENTS: usize = 256;

/// Largest reconstructed canonical path admitted by the Unix local-file V1
/// representation, including separators.
pub const MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES: usize = 64 * 1024;

/// Largest encoded expansion request.
pub const MAX_EXPANSION_REQUEST_BYTES: usize = 64 * 1024;

/// Largest authorized payload carried by one event.
pub const MAX_AUTHORIZED_EVENT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Largest authorized source record before an adapter must use an explicitly
/// marked fragment or truncation outcome.
pub const MAX_AUTHORIZED_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// Largest separately preserved source record terminator.
pub const MAX_RECORD_TERMINATOR_BYTES: usize = 64;

/// Largest number of lossless native metadata fields on one record.
pub const MAX_NATIVE_METADATA_FIELDS: usize = 256;

/// Largest aggregate encoded native metadata size on one record.
pub const MAX_NATIVE_METADATA_BYTES: usize = 256 * 1024;

/// Largest one opaque adapter-attested correlation value.
pub const MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1: usize = 4 * 1024;

/// Largest number of adapter-attested correlations on one event. The cap is
/// applied to input occurrences before exact duplicates are removed.
pub const MAX_PROVIDER_ATTESTATIONS_PER_EVENT_V1: usize = 64;

/// Largest number of sorted byte-range replacements in one transformation.
pub const MAX_TRANSFORMATION_OPERATIONS: usize = 256;

/// Largest number of events in one atomic block.
pub const MAX_EVENT_BLOCK_MEMBERS: usize = 4_096;

/// Largest number of receipt entries in one independently verified chunk.
pub const MAX_RECEIPT_CHUNK_ENTRIES: usize = 4_096;

/// Largest number of evidence packets in one Log Brief.
pub const MAX_LOG_BRIEF_EVIDENCE_PACKETS: usize = 512;

/// Largest number of deterministic signals in one Log Brief.
pub const MAX_LOG_BRIEF_SIGNALS: usize = 256;

/// Largest number of bounded next-step proposals in one Log Brief.
pub const MAX_LOG_BRIEF_NEXT_STEPS: usize = 64;

/// Largest number of events returned by one exact expansion.
pub const MAX_EXPANSION_EVENTS: usize = 512;

/// Largest authorized byte count returned by one exact expansion.
pub const MAX_EXPANSION_BYTES: usize = 8 * 1024 * 1024;

/// Largest canonical token count returned by one exact expansion.
pub const MAX_EXPANSION_TOKENS: usize = 131_072;

/// Largest same-side neighborhood requested around an expansion anchor.
pub const MAX_EXPANSION_BEFORE_AFTER: usize = 256;

/// Default local result lifetime. Policy may choose a different lifetime.
pub const DEFAULT_RESULT_TTL_SECS: u64 = 1_800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_bounds_are_frozen_at_the_contract_values() {
        assert_eq!(JSON_SAFE_INTEGER_MAX, (1_u64 << 53) - 1);
        assert_eq!(MAX_WIRE_OBJECT_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_QUERY_PLAN_BYTES, 1024 * 1024);
        assert_eq!(MAX_APPROVED_LOCAL_FILE_BINDING_BYTES, 64 * 1024);
        assert_eq!(MAX_UNIX_LOCAL_FILE_ROOT_BYTES, 4 * 1024);
        assert_eq!(MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES, 255);
        assert_eq!(MAX_UNIX_LOCAL_FILE_COMPONENTS, 256);
        assert_eq!(MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES, 64 * 1024);
        assert_eq!(MAX_EXPANSION_REQUEST_BYTES, 64 * 1024);
        assert_eq!(MAX_AUTHORIZED_EVENT_PAYLOAD_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_AUTHORIZED_RECORD_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_RECORD_TERMINATOR_BYTES, 64);
        assert_eq!(MAX_NATIVE_METADATA_FIELDS, 256);
        assert_eq!(MAX_NATIVE_METADATA_BYTES, 256 * 1024);
        assert_eq!(MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1, 4 * 1024);
        assert_eq!(MAX_PROVIDER_ATTESTATIONS_PER_EVENT_V1, 64);
        assert_eq!(MAX_TRANSFORMATION_OPERATIONS, 256);
        assert_eq!(MAX_EVENT_BLOCK_MEMBERS, 4_096);
        assert_eq!(MAX_RECEIPT_CHUNK_ENTRIES, 4_096);
        assert_eq!(MAX_LOG_BRIEF_EVIDENCE_PACKETS, 512);
        assert_eq!(MAX_LOG_BRIEF_SIGNALS, 256);
        assert_eq!(MAX_LOG_BRIEF_NEXT_STEPS, 64);
        assert_eq!(MAX_EXPANSION_EVENTS, 512);
        assert_eq!(MAX_EXPANSION_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_EXPANSION_TOKENS, 131_072);
        assert_eq!(MAX_EXPANSION_BEFORE_AFTER, 256);
        assert_eq!(DEFAULT_RESULT_TTL_SECS, 1_800);
    }
}
