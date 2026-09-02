use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_select::{AFFINITY_SCALE_V1, OptionalPacketPriorityV1, PacketIdV1};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Maximum intact optional blocks sent in one hosted-ranking request.
pub const MAX_HOSTED_RANKING_CANDIDATES_V1: usize = 32;
/// Maximum escaped question plus candidate bytes eligible for hosted egress.
/// This bounds request memory, provider context consumption, latency, and cost
/// independently of the much larger local-input limit.
pub const MAX_HOSTED_RANKING_ESCAPED_INPUT_BYTES_V1: usize = 40 * 1024;
/// Strict hosted response size bound. Rankings need only a few hundred bytes.
pub const MAX_HOSTED_RANKING_RESPONSE_BYTES_V1: usize = 16 * 1024;
pub const EVIDENCE_RANKING_SCHEMA_VERSION_V1: u16 = 1;

const ACCEPTED_IDS_DOMAIN_V1: &[u8] = b"evidentrail/hosted-ranking/accepted-ids/v1\0";

/// One intact model-visible candidate. Debug output never exposes its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceRankingCandidateV1 {
    block_id: String,
    packet_id: PacketIdV1,
    escaped_untrusted_data: String,
}

impl EvidenceRankingCandidateV1 {
    pub(crate) fn new(
        block_id: String,
        packet_id: PacketIdV1,
        escaped_untrusted_data: String,
    ) -> Self {
        Self {
            block_id,
            packet_id,
            escaped_untrusted_data,
        }
    }

    #[must_use]
    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    /// Canonical reversible `ascii_byte_escape_v1` source representation.
    #[must_use]
    pub fn escaped_untrusted_data(&self) -> &str {
        &self.escaped_untrusted_data
    }
}

impl fmt::Debug for EvidenceRankingCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRankingCandidateV1")
            .field("block_id", &self.block_id)
            .field("escaped_byte_count", &self.escaped_untrusted_data.len())
            .finish()
    }
}

/// Complete input for the one permitted hosted call. It is ephemeral and is
/// never retained by the product.
pub struct EvidenceRankingRequestV1 {
    escaped_question: String,
    candidates: Vec<EvidenceRankingCandidateV1>,
}

impl EvidenceRankingRequestV1 {
    pub(crate) fn new(
        escaped_question: String,
        candidates: Vec<EvidenceRankingCandidateV1>,
    ) -> Self {
        Self {
            escaped_question,
            candidates,
        }
    }

    #[must_use]
    pub fn escaped_question(&self) -> &str {
        &self.escaped_question
    }

    #[must_use]
    pub fn candidates(&self) -> &[EvidenceRankingCandidateV1] {
        &self.candidates
    }

    /// Return an ephemeral copy with candidates in the supplied complete
    /// permutation. This exists for benchmark order-sensitivity evaluation;
    /// aliases and exact escaped bytes remain unchanged.
    #[must_use]
    pub fn reordered_candidates_v1(&self, order: &[usize]) -> Option<Self> {
        if order.len() != self.candidates.len() {
            return None;
        }
        let mut seen = vec![false; order.len()];
        let mut candidates = Vec::with_capacity(order.len());
        for index in order.iter().copied() {
            if index >= self.candidates.len() || seen[index] {
                return None;
            }
            seen[index] = true;
            candidates.push(self.candidates[index].clone());
        }
        Some(Self {
            escaped_question: self.escaped_question.clone(),
            candidates,
        })
    }
}

impl fmt::Debug for EvidenceRankingRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRankingRequestV1")
            .field("question_byte_count", &self.escaped_question.len())
            .field("candidate_count", &self.candidates.len())
            .finish()
    }
}

/// Provider-neutral result from exactly one hosted call.
#[derive(Clone)]
pub struct EvidenceRankerOutputV1 {
    response_json: Vec<u8>,
    provider_digest: [u8; 32],
    configuration_digest: [u8; 32],
    elapsed_nanos: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_microusd: Option<u64>,
}

impl EvidenceRankerOutputV1 {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        response_json: Vec<u8>,
        provider_digest: [u8; 32],
        configuration_digest: [u8; 32],
        elapsed_nanos: u64,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_microusd: Option<u64>,
    ) -> Self {
        Self {
            response_json,
            provider_digest,
            configuration_digest,
            elapsed_nanos,
            input_tokens,
            output_tokens,
            cost_microusd,
        }
    }

    #[must_use]
    pub fn response_json(&self) -> &[u8] {
        &self.response_json
    }
}

impl fmt::Debug for EvidenceRankerOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRankerOutputV1")
            .field("response_byte_count", &self.response_json.len())
            .field("elapsed_nanos", &self.elapsed_nanos)
            .field("input_tokens", &self.input_tokens)
            .field("output_tokens", &self.output_tokens)
            .field("cost_microusd", &self.cost_microusd)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRankerFailureV1 {
    Disabled,
    MissingCredential,
    Timeout,
    RateLimited,
    PolicyDenied,
    ProviderFailure,
}

impl EvidenceRankerFailureV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MissingCredential => "missing_credential",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::PolicyDenied => "policy_denied",
            Self::ProviderFailure => "provider_failure",
        }
    }
}

impl fmt::Debug for EvidenceRankerFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRankerFailureV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EvidenceRankerFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EvidenceRankerFailureV1 {}

/// Application-layer seam. Implementations must make at most one provider
/// call and must not retain the request or response.
pub trait EvidenceRankerV1 {
    fn rank(
        &mut self,
        request: &EvidenceRankingRequestV1,
    ) -> Result<EvidenceRankerOutputV1, EvidenceRankerFailureV1>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RankingEnvelopeV1 {
    schema_version: u16,
    ranked_block_ids: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedEvidenceRankingV1 {
    ranked_packet_ids: Vec<PacketIdV1>,
}

impl ValidatedEvidenceRankingV1 {
    #[must_use]
    pub fn ranked_packet_ids(&self) -> &[PacketIdV1] {
        &self.ranked_packet_ids
    }
}

impl fmt::Debug for ValidatedEvidenceRankingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedEvidenceRankingV1")
            .field("ranked_packet_count", &self.ranked_packet_ids.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RankingValidationErrorV1 {
    ResponseTooLarge,
    Malformed,
    UnsupportedSchema,
    IncompletePermutation,
    DuplicateId,
    ForeignId,
}

impl RankingValidationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ResponseTooLarge => "response_too_large",
            Self::Malformed => "malformed",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::IncompletePermutation => "incomplete_permutation",
            Self::DuplicateId => "duplicate_id",
            Self::ForeignId => "foreign_id",
        }
    }
}

impl fmt::Debug for RankingValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RankingValidationErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for RankingValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RankingValidationErrorV1 {}

/// Strictly parse the sole accepted response and require a complete
/// permutation of submitted IDs.
pub fn validate_evidence_ranking_response_v1(
    response: &[u8],
    candidates: &[EvidenceRankingCandidateV1],
) -> Result<ValidatedEvidenceRankingV1, RankingValidationErrorV1> {
    if response.len() > MAX_HOSTED_RANKING_RESPONSE_BYTES_V1 {
        return Err(RankingValidationErrorV1::ResponseTooLarge);
    }
    let envelope: RankingEnvelopeV1 =
        serde_json::from_slice(response).map_err(|_| RankingValidationErrorV1::Malformed)?;
    if envelope.schema_version != EVIDENCE_RANKING_SCHEMA_VERSION_V1 {
        return Err(RankingValidationErrorV1::UnsupportedSchema);
    }
    if envelope.ranked_block_ids.len() != candidates.len() {
        return Err(RankingValidationErrorV1::IncompletePermutation);
    }
    let lookup = candidates
        .iter()
        .map(|candidate| (candidate.block_id(), candidate.packet_id()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut ranked_packet_ids = Vec::with_capacity(candidates.len());
    for block_id in &envelope.ranked_block_ids {
        if !seen.insert(block_id.as_str()) {
            return Err(RankingValidationErrorV1::DuplicateId);
        }
        let packet_id = lookup
            .get(block_id.as_str())
            .copied()
            .ok_or(RankingValidationErrorV1::ForeignId)?;
        ranked_packet_ids.push(packet_id);
    }
    Ok(ValidatedEvidenceRankingV1 { ranked_packet_ids })
}

/// The three deterministic consumers evaluated by EvidentrailBench.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RankingConsumerV1 {
    ModelOrder,
    ReciprocalRankFusion,
    BoundedFourthAffinity,
}

/// Deterministic application policy controlling whether an explicitly enabled
/// hosted ranker may be contacted after passthrough and feasibility gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostedRankingEscalationPolicyV1 {
    /// Attempt ranking whenever at least two optional candidates are eligible.
    AlwaysEligible,
    /// Attempt ranking only when a model-visible optional candidate was
    /// excluded from the deterministic selection by bounded packing.
    SelectionContended,
}

#[must_use]
pub(crate) fn selection_is_contended_v1(
    model_visible_optional_packet_ids: &[PacketIdV1],
    selected_packet_ids: &BTreeSet<PacketIdV1>,
) -> bool {
    model_visible_optional_packet_ids
        .iter()
        .any(|packet_id| !selected_packet_ids.contains(packet_id))
}

/// Deterministically consume one validated permutation. RRF uses the submitted
/// order as the deterministic rank and a fixed `k=60`.
#[must_use]
pub fn consume_evidence_ranking_v1(
    consumer: RankingConsumerV1,
    deterministic_packet_ids: &[PacketIdV1],
    ranking: &ValidatedEvidenceRankingV1,
) -> Vec<PacketIdV1> {
    match consumer {
        RankingConsumerV1::ModelOrder | RankingConsumerV1::BoundedFourthAffinity => {
            ranking.ranked_packet_ids.clone()
        }
        RankingConsumerV1::ReciprocalRankFusion => {
            let deterministic_positions = deterministic_packet_ids
                .iter()
                .enumerate()
                .map(|(index, id)| (*id, index))
                .collect::<BTreeMap<_, _>>();
            let model_positions = ranking
                .ranked_packet_ids
                .iter()
                .enumerate()
                .map(|(index, id)| (*id, index))
                .collect::<BTreeMap<_, _>>();
            let mut fused = ranking.ranked_packet_ids.clone();
            fused.sort_by_key(|id| {
                let deterministic = deterministic_positions
                    .get(id)
                    .copied()
                    .unwrap_or(usize::MAX);
                let model = model_positions.get(id).copied().unwrap_or(usize::MAX);
                let left = 1_000_000_u64 / (61 + u64::try_from(deterministic).unwrap_or(u64::MAX));
                let right = 1_000_000_u64 / (61 + u64::try_from(model).unwrap_or(u64::MAX));
                (std::cmp::Reverse(left.saturating_add(right)), deterministic)
            });
            fused
        }
    }
}

#[must_use]
pub fn ranking_priorities_v1(ranked_packet_ids: &[PacketIdV1]) -> Vec<OptionalPacketPriorityV1> {
    let count = ranked_packet_ids.len();
    ranked_packet_ids
        .iter()
        .enumerate()
        .map(|(index, packet_id)| {
            let numerator = u64::try_from(count - index).unwrap_or(1);
            let denominator = u64::try_from(count).unwrap_or(1).max(1);
            let affinity = (u64::from(AFFINITY_SCALE_V1) * numerator / denominator) as u32;
            OptionalPacketPriorityV1::new(*packet_id, affinity.max(1))
        })
        .collect()
}

#[derive(Clone, PartialEq, Eq)]
pub struct HostedRankingDiagnosticsV1 {
    application_code: &'static str,
    proposal_changed: Option<bool>,
    provider_digest: Option<[u8; 32]>,
    configuration_digest: Option<[u8; 32]>,
    elapsed_nanos: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_microusd: Option<u64>,
    validation_code: &'static str,
    fallback_reason: Option<&'static str>,
    accepted_block_ids_digest: Option<[u8; 32]>,
}

impl HostedRankingDiagnosticsV1 {
    pub(crate) fn provider_failure(
        application_code: &'static str,
        reason: EvidenceRankerFailureV1,
        elapsed_nanos: u64,
    ) -> Self {
        Self {
            application_code,
            proposal_changed: None,
            provider_digest: None,
            configuration_digest: None,
            elapsed_nanos: Some(elapsed_nanos),
            input_tokens: None,
            output_tokens: None,
            cost_microusd: None,
            validation_code: "not_received",
            fallback_reason: Some(reason.code()),
            accepted_block_ids_digest: None,
        }
    }

    pub(crate) fn not_sent(application_code: &'static str, reason: &'static str) -> Self {
        Self {
            application_code,
            proposal_changed: None,
            provider_digest: None,
            configuration_digest: None,
            elapsed_nanos: None,
            input_tokens: None,
            output_tokens: None,
            cost_microusd: None,
            validation_code: "not_sent",
            fallback_reason: Some(reason),
            accepted_block_ids_digest: None,
        }
    }

    pub(crate) fn invalid(
        application_code: &'static str,
        output: &EvidenceRankerOutputV1,
        reason: RankingValidationErrorV1,
    ) -> Self {
        Self::from_output(
            application_code,
            None,
            output,
            reason.code(),
            Some("invalid_response"),
            None,
        )
    }

    pub(crate) fn accepted(
        application_code: &'static str,
        proposal_changed: bool,
        output: &EvidenceRankerOutputV1,
        ranked_packet_ids: &[PacketIdV1],
    ) -> Self {
        Self::from_output(
            application_code,
            Some(proposal_changed),
            output,
            "accepted",
            None,
            Some(digest_packet_ids_v1(ranked_packet_ids)),
        )
    }

    pub(crate) fn accepted_but_fallback(
        application_code: &'static str,
        output: &EvidenceRankerOutputV1,
        ranked_packet_ids: &[PacketIdV1],
    ) -> Self {
        Self::from_output(
            application_code,
            None,
            output,
            "accepted",
            Some("selection_failure"),
            Some(digest_packet_ids_v1(ranked_packet_ids)),
        )
    }

    fn from_output(
        application_code: &'static str,
        proposal_changed: Option<bool>,
        output: &EvidenceRankerOutputV1,
        validation_code: &'static str,
        fallback_reason: Option<&'static str>,
        accepted_block_ids_digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            application_code,
            proposal_changed,
            provider_digest: Some(output.provider_digest),
            configuration_digest: Some(output.configuration_digest),
            elapsed_nanos: Some(output.elapsed_nanos),
            input_tokens: output.input_tokens,
            output_tokens: output.output_tokens,
            cost_microusd: output.cost_microusd,
            validation_code,
            fallback_reason,
            accepted_block_ids_digest,
        }
    }

    #[must_use]
    pub const fn application_code(&self) -> &'static str {
        self.application_code
    }

    #[must_use]
    pub const fn proposal_changed(&self) -> Option<bool> {
        self.proposal_changed
    }

    #[must_use]
    pub const fn validation_code(&self) -> &'static str {
        self.validation_code
    }

    #[must_use]
    pub const fn provider_digest(&self) -> Option<[u8; 32]> {
        self.provider_digest
    }

    #[must_use]
    pub const fn configuration_digest(&self) -> Option<[u8; 32]> {
        self.configuration_digest
    }

    #[must_use]
    pub const fn elapsed_nanos(&self) -> Option<u64> {
        self.elapsed_nanos
    }

    #[must_use]
    pub const fn input_tokens(&self) -> Option<u64> {
        self.input_tokens
    }

    #[must_use]
    pub const fn output_tokens(&self) -> Option<u64> {
        self.output_tokens
    }

    #[must_use]
    pub const fn cost_microusd(&self) -> Option<u64> {
        self.cost_microusd
    }

    #[must_use]
    pub const fn fallback_reason(&self) -> Option<&'static str> {
        self.fallback_reason
    }

    #[must_use]
    pub const fn accepted_block_ids_digest(&self) -> Option<[u8; 32]> {
        self.accepted_block_ids_digest
    }
}

impl fmt::Debug for HostedRankingDiagnosticsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedRankingDiagnosticsV1")
            .field("application_code", &self.application_code)
            .field("proposal_changed", &self.proposal_changed)
            .field("provider_digest_present", &self.provider_digest.is_some())
            .field(
                "configuration_digest_present",
                &self.configuration_digest.is_some(),
            )
            .field("elapsed_nanos", &self.elapsed_nanos)
            .field("input_tokens", &self.input_tokens)
            .field("output_tokens", &self.output_tokens)
            .field("cost_microusd", &self.cost_microusd)
            .field("validation_code", &self.validation_code)
            .field("fallback_reason", &self.fallback_reason)
            .field(
                "accepted_block_ids_digest_present",
                &self.accepted_block_ids_digest.is_some(),
            )
            .finish()
    }
}

fn digest_packet_ids_v1(packet_ids: &[PacketIdV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTED_IDS_DOMAIN_V1);
    hasher.update(
        u64::try_from(packet_ids.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for packet_id in packet_ids {
        hasher.update(packet_id.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(seed: u8) -> PacketIdV1 {
        PacketIdV1::from_bytes([seed; 32])
    }

    fn candidates() -> Vec<EvidenceRankingCandidateV1> {
        vec![
            EvidenceRankingCandidateV1::new("B1".to_owned(), packet(1), "a".to_owned()),
            EvidenceRankingCandidateV1::new("B2".to_owned(), packet(2), "b".to_owned()),
            EvidenceRankingCandidateV1::new("B3".to_owned(), packet(3), "c".to_owned()),
        ]
    }

    #[test]
    fn contention_requires_a_model_visible_excluded_optional_packet() {
        let candidates = [packet(1), packet(2), packet(3)];
        let all_selected = candidates.into_iter().collect::<BTreeSet<_>>();
        assert!(!selection_is_contended_v1(&candidates, &all_selected));

        let partially_selected = [packet(1), packet(3)].into_iter().collect::<BTreeSet<_>>();
        assert!(selection_is_contended_v1(&candidates, &partially_selected));
        assert!(!selection_is_contended_v1(&[], &BTreeSet::new()));
    }

    #[test]
    fn strict_parser_requires_one_complete_known_permutation() {
        let candidates = candidates();
        let valid = validate_evidence_ranking_response_v1(
            br#"{"schema_version":1,"ranked_block_ids":["B3","B1","B2"]}"#,
            &candidates,
        )
        .unwrap();
        assert_eq!(
            valid.ranked_packet_ids(),
            &[packet(3), packet(1), packet(2)]
        );

        for (response, expected) in [
            (
                br#"{"schema_version":1,"ranked_block_ids":["B1","B1","B2"]}"#.as_slice(),
                RankingValidationErrorV1::DuplicateId,
            ),
            (
                br#"{"schema_version":1,"ranked_block_ids":["B1","B2"]}"#.as_slice(),
                RankingValidationErrorV1::IncompletePermutation,
            ),
            (
                br#"{"schema_version":1,"ranked_block_ids":["B1","B2","FOREIGN"]}"#.as_slice(),
                RankingValidationErrorV1::ForeignId,
            ),
            (
                br#"{"schema_version":2,"ranked_block_ids":["B1","B2","B3"]}"#.as_slice(),
                RankingValidationErrorV1::UnsupportedSchema,
            ),
            (
                br#"{"schema_version":1,"ranked_block_ids":["B1","B2","B3"],"extra":true}"#
                    .as_slice(),
                RankingValidationErrorV1::Malformed,
            ),
        ] {
            assert_eq!(
                validate_evidence_ranking_response_v1(response, &candidates),
                Err(expected)
            );
        }
    }

    #[test]
    fn arbitrary_response_bytes_never_escape_the_closed_validator() {
        let candidates = candidates();
        let mut state = 0x5eed_f00d_cafe_beef_u64;
        for length in 0..=512 {
            let mut response = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                response.push(state as u8);
            }
            let result = validate_evidence_ranking_response_v1(&response, &candidates);
            assert!(result.is_err());
        }

        let oversized = vec![b' '; MAX_HOSTED_RANKING_RESPONSE_BYTES_V1 + 1];
        assert_eq!(
            validate_evidence_ranking_response_v1(&oversized, &candidates),
            Err(RankingValidationErrorV1::ResponseTooLarge)
        );
    }

    #[test]
    fn consumers_and_diagnostics_are_deterministic_and_contentless() {
        let candidates = candidates();
        let ranking = validate_evidence_ranking_response_v1(
            br#"{"schema_version":1,"ranked_block_ids":["B3","B2","B1"]}"#,
            &candidates,
        )
        .unwrap();
        let deterministic = [packet(1), packet(2), packet(3)];
        assert_eq!(
            consume_evidence_ranking_v1(RankingConsumerV1::ModelOrder, &deterministic, &ranking),
            vec![packet(3), packet(2), packet(1)]
        );
        let first = consume_evidence_ranking_v1(
            RankingConsumerV1::ReciprocalRankFusion,
            &deterministic,
            &ranking,
        );
        let second = consume_evidence_ranking_v1(
            RankingConsumerV1::ReciprocalRankFusion,
            &deterministic,
            &ranking,
        );
        assert_eq!(first, second);

        let output = EvidenceRankerOutputV1::new(
            b"SECRET_RESPONSE".to_vec(),
            [1; 32],
            [2; 32],
            3,
            Some(4),
            Some(5),
            Some(6),
        );
        let diagnostics =
            HostedRankingDiagnosticsV1::accepted("apply", true, &output, &deterministic);
        let debug = format!("{diagnostics:?}");
        assert!(!debug.contains("SECRET_RESPONSE"));
        assert!(!debug.contains("B1"));
        assert_eq!(diagnostics.validation_code(), "accepted");
        assert!(diagnostics.accepted_block_ids_digest().is_some());
    }
}
