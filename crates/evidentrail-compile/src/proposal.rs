use std::error::Error as StdError;
use std::fmt;

use evidentrail_candidates::{
    BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1, CANDIDATE_POLICY_NAME_V1,
    CANDIDATE_POLICY_VERSION_V1, COVERAGE_CANDIDATE_POLICY_NAME_V1,
    COVERAGE_CANDIDATE_POLICY_VERSION_V1, MAX_COVERAGE_ANALYSIS_TOKENS_V1,
    MAX_COVERAGE_OUTPUT_AFFINITIES_V1, MAX_COVERAGE_OUTPUT_FACETS_V1,
    MAX_COVERAGE_OUTPUT_SENTINELS_V1, MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1,
    MAX_COVERAGE_SOURCE_LANES_V1, MAX_EMITTED_SIGNALS_V1, MAX_IDENTIFIER_BLOCK_FANOUT_V1,
    MAX_MANDATORY_BLOCKS_V1, MAX_PRIMARY_BLOCKS_V1, MAX_PRIMARY_BYTES_SCANNED_V1,
    MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1, MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1,
    MAX_PROVIDER_CORRELATION_KEYS_V1, MAX_PROVIDER_GRAPH_DEGREE_V1, MAX_PROVIDER_GRAPH_EDGES_V1,
    MAX_PROVIDER_GRAPH_HOP_DEPTH_V1, MAX_PROVIDER_GRAPH_NODES_V1,
    MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1, MAX_PROVIDER_OUTPUT_AFFINITIES_V1,
    MAX_PROVIDER_OUTPUT_FACETS_V1, MAX_PROVIDER_RELATION_FANOUT_V1, MAX_QUERY_TERM_BYTES_V1,
    MAX_QUERY_TERMS_V1, MAX_QUERY_TOKENS_V1, MAX_QUESTION_BYTES_V1,
    MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1, MAX_TIME_COVERAGE_STRATA_V1,
    MAX_VALIDATED_QUERY_IDENTIFIERS_V1, MIN_QUERY_TERM_BYTES_V1,
    PROVIDER_CORRELATION_POLICY_NAME_V1, PROVIDER_CORRELATION_POLICY_VERSION_V1,
};
use evidentrail_core::{
    AcquisitionReceiptId, EventLedger, PlanDigest, PlanId, QuestionDigest, ResultId, RetrievalId,
    SourceIdentityDigest,
};
use evidentrail_evidence::{
    CompiledCostCertificationV1, PinnedTokenizer, Utf8ByteTokenizerV1, compiled_renderer_digest_v1,
};
use evidentrail_schema::{ArtifactDigest, bounds::JSON_SAFE_INTEGER_MAX};
use evidentrail_select::{
    AFFINITY_SCALE_V1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, ComposableCostModelV1,
    IntactPacketV1, MAX_FACET_SATURATION_CARDINALITY_V1, MAX_MANDATORY_PACKETS_V1,
    MAX_PACKET_EVENTS_V1, MAX_SELECTION_EVENTS_V1, MAX_SELECTION_FACETS_V1,
    MAX_SELECTION_PACKETS_V1, MandatoryPacketV1, PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    ProductionFacetKindV1, ProductionFacetV1, SELECTION_OBJECTIVE_POLICY_NAME_V1,
    SELECTION_OBJECTIVE_POLICY_VERSION_V1,
};
use sha2::{Digest, Sha256};

use crate::types::{
    CertifiedThreeLaneSelectionV1, CompiledPacketMetadataV1, ThreeLaneNeedsMoreV1,
    find_packet_metadata_v1,
};

/// Contract version for the producer-side proposal preparation boundary.
pub const PROPOSAL_PREPARATION_CONTRACT_VERSION_V1: u16 = 1;
/// Fixed-width receipt integers are committed least-significant byte first.
pub const PROPOSAL_RECEIPT_INTEGER_ENCODING_V1: &[u8] = b"little_endian_fixed_width_v1";
/// Frozen compiler policy name committed by every V1 proposal receipt.
pub const PROPOSAL_COMPILER_POLICY_NAME_V1: &[u8] =
    b"evidentrail/three-lane-positive-affinity-proposal-compiler";
/// Frozen compiler policy version committed by every V1 proposal receipt.
pub const PROPOSAL_COMPILER_POLICY_VERSION_V1: &[u8] = b"4";

const CANDIDATE_CONFIG_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/candidate-config-digest/v1\0";
const COMPILER_CONFIG_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/proposal-compiler-config-digest/v1\0";
const ADAPTER_IDENTITY_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/adapter-identity-digest/v1\0";
const PREPARATION_INPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/proposal-preparation-input/v1\0";
const PROPOSAL_UNIVERSE_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/proposal-universe-receipt/v1\0";

/// Digest of all three fixed candidate-lane policy identities.
#[must_use]
pub fn proposal_candidate_config_digest_v1() -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_CONFIG_DIGEST_DOMAIN_V1);
    for (name, version) in [
        (CANDIDATE_POLICY_NAME_V1, CANDIDATE_POLICY_VERSION_V1),
        (
            COVERAGE_CANDIDATE_POLICY_NAME_V1,
            COVERAGE_CANDIDATE_POLICY_VERSION_V1,
        ),
        (
            PROVIDER_CORRELATION_POLICY_NAME_V1,
            PROVIDER_CORRELATION_POLICY_VERSION_V1,
        ),
    ] {
        update_field(&mut hasher, name);
        update_field(&mut hasher, version);
    }
    macro_rules! bind_candidate_bound {
        ($bound:ident) => {{
            update_field(&mut hasher, stringify!($bound).as_bytes());
            update_u64(
                &mut hasher,
                u64::try_from($bound).expect("candidate V1 bound fits u64"),
            );
        }};
    }
    bind_candidate_bound!(MAX_COVERAGE_ANALYSIS_TOKENS_V1);
    bind_candidate_bound!(BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1);
    bind_candidate_bound!(MAX_COVERAGE_OUTPUT_AFFINITIES_V1);
    bind_candidate_bound!(MAX_COVERAGE_OUTPUT_FACETS_V1);
    bind_candidate_bound!(MAX_COVERAGE_OUTPUT_SENTINELS_V1);
    bind_candidate_bound!(MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1);
    bind_candidate_bound!(MAX_COVERAGE_SOURCE_LANES_V1);
    bind_candidate_bound!(MAX_EMITTED_SIGNALS_V1);
    bind_candidate_bound!(MAX_IDENTIFIER_BLOCK_FANOUT_V1);
    bind_candidate_bound!(MAX_MANDATORY_BLOCKS_V1);
    bind_candidate_bound!(MAX_PRIMARY_BLOCKS_V1);
    bind_candidate_bound!(MAX_PRIMARY_BYTES_SCANNED_V1);
    bind_candidate_bound!(MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1);
    bind_candidate_bound!(MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1);
    bind_candidate_bound!(MAX_PROVIDER_CORRELATION_KEYS_V1);
    bind_candidate_bound!(MAX_PROVIDER_GRAPH_DEGREE_V1);
    bind_candidate_bound!(MAX_PROVIDER_GRAPH_EDGES_V1);
    bind_candidate_bound!(MAX_PROVIDER_GRAPH_HOP_DEPTH_V1);
    bind_candidate_bound!(MAX_PROVIDER_GRAPH_NODES_V1);
    bind_candidate_bound!(MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1);
    bind_candidate_bound!(MAX_PROVIDER_OUTPUT_AFFINITIES_V1);
    bind_candidate_bound!(MAX_PROVIDER_OUTPUT_FACETS_V1);
    bind_candidate_bound!(MAX_PROVIDER_RELATION_FANOUT_V1);
    bind_candidate_bound!(PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1);
    bind_candidate_bound!(MAX_QUERY_TERM_BYTES_V1);
    bind_candidate_bound!(MAX_QUERY_TERMS_V1);
    bind_candidate_bound!(MAX_QUERY_TOKENS_V1);
    bind_candidate_bound!(MAX_QUESTION_BYTES_V1);
    bind_candidate_bound!(MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1);
    bind_candidate_bound!(MAX_TIME_COVERAGE_STRATA_V1);
    bind_candidate_bound!(MAX_VALIDATED_QUERY_IDENTIFIERS_V1);
    bind_candidate_bound!(MIN_QUERY_TERM_BYTES_V1);
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

/// Digest of the fixed compiler semantics used to form the proposal universe.
#[must_use]
pub fn proposal_compiler_config_digest_v1() -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(COMPILER_CONFIG_DIGEST_DOMAIN_V1);
    update_field(&mut hasher, PROPOSAL_COMPILER_POLICY_NAME_V1);
    update_field(&mut hasher, PROPOSAL_COMPILER_POLICY_VERSION_V1);
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_NAME_V1);
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_VERSION_V1);
    update_field(&mut hasher, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1);
    update_u16(&mut hasher, PROPOSAL_PREPARATION_CONTRACT_VERSION_V1);
    macro_rules! bind_compiler_bound {
        ($bound:ident) => {{
            update_field(&mut hasher, stringify!($bound).as_bytes());
            update_u64(
                &mut hasher,
                u64::try_from($bound).expect("compiler V1 bound fits u64"),
            );
        }};
    }
    bind_compiler_bound!(AFFINITY_SCALE_V1);
    bind_compiler_bound!(MAX_FACET_SATURATION_CARDINALITY_V1);
    bind_compiler_bound!(PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1);
    bind_compiler_bound!(COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1);
    bind_compiler_bound!(MAX_MANDATORY_PACKETS_V1);
    bind_compiler_bound!(MAX_PACKET_EVENTS_V1);
    bind_compiler_bound!(MAX_SELECTION_EVENTS_V1);
    bind_compiler_bound!(MAX_SELECTION_FACETS_V1);
    bind_compiler_bound!(MAX_SELECTION_PACKETS_V1);
    for kind in ProductionFacetKindV1::ALL_V1 {
        update_field(&mut hasher, kind.code().as_bytes());
        update_u64(
            &mut hasher,
            u64::from(kind.saturation_cardinality().count()),
        );
    }
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

/// Frozen input authority available even when a candidate lane cannot produce
/// a complete proposal universe. It deliberately makes no proposal-membership
/// claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProposalPreparationInputReceiptV1 {
    digest: ArtifactDigest,
    result_id: ResultId,
    question_digest: QuestionDigest,
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    source_identity_digest: SourceIdentityDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    adapter_identity_digest: ArtifactDigest,
    candidate_config_digest: ArtifactDigest,
    compiler_config_digest: ArtifactDigest,
    renderer_digest: ArtifactDigest,
    tokenizer_digest: ArtifactDigest,
    tokenizer_bound_contract_digest: ArtifactDigest,
}

impl ProposalPreparationInputReceiptV1 {
    pub(crate) fn new(
        result_id: ResultId,
        question_digest: QuestionDigest,
        ledger: &EventLedger,
        tokenizer: &Utf8ByteTokenizerV1,
    ) -> Self {
        Self::new_with_candidate_config_digest(
            result_id,
            question_digest,
            ledger,
            tokenizer,
            proposal_candidate_config_digest_v1(),
        )
    }

    pub(crate) fn new_with_candidate_config_digest(
        result_id: ResultId,
        question_digest: QuestionDigest,
        ledger: &EventLedger,
        tokenizer: &Utf8ByteTokenizerV1,
        candidate_config_digest: ArtifactDigest,
    ) -> Self {
        let adapter_identity_digest = adapter_identity_digest(ledger);
        let compiler_config_digest = proposal_compiler_config_digest_v1();
        let renderer_digest = compiled_renderer_digest_v1();
        let tokenizer_bound = tokenizer.ascii_render_bound_contract();
        let tokenizer_digest = tokenizer.digest();
        let tokenizer_bound_contract_digest = tokenizer_bound.contract_digest();
        let mut hasher = Sha256::new();
        hasher.update(PREPARATION_INPUT_DIGEST_DOMAIN_V1);
        update_field(&mut hasher, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1);
        update_u16(&mut hasher, PROPOSAL_PREPARATION_CONTRACT_VERSION_V1);
        update_field(&mut hasher, result_id.as_bytes());
        update_field(&mut hasher, question_digest.as_bytes());
        update_field(&mut hasher, ledger.retrieval_id().as_bytes());
        update_field(&mut hasher, ledger.plan_id().as_bytes());
        update_field(&mut hasher, ledger.plan_digest().as_bytes());
        update_field(&mut hasher, ledger.source_identity_digest().as_bytes());
        update_field(&mut hasher, ledger.acquisition_receipt_id().as_bytes());
        update_field(&mut hasher, adapter_identity_digest.as_bytes());
        update_field(&mut hasher, candidate_config_digest.as_bytes());
        update_field(&mut hasher, compiler_config_digest.as_bytes());
        update_field(&mut hasher, renderer_digest.as_bytes());
        update_field(&mut hasher, tokenizer_digest.as_bytes());
        update_field(&mut hasher, tokenizer_bound_contract_digest.as_bytes());
        Self {
            digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            result_id,
            question_digest,
            retrieval_id: ledger.retrieval_id(),
            plan_id: ledger.plan_id(),
            plan_digest: ledger.plan_digest(),
            source_identity_digest: ledger.source_identity_digest(),
            acquisition_receipt_id: ledger.acquisition_receipt_id(),
            adapter_identity_digest,
            candidate_config_digest,
            compiler_config_digest,
            renderer_digest,
            tokenizer_digest,
            tokenizer_bound_contract_digest,
        }
    }

    #[must_use]
    pub const fn digest(self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn retrieval_id(self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn plan_id(self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn plan_digest(self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn source_identity_digest(self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn adapter_identity_digest(self) -> ArtifactDigest {
        self.adapter_identity_digest
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
    pub const fn renderer_digest(self) -> ArtifactDigest {
        self.renderer_digest
    }

    #[must_use]
    pub const fn tokenizer_digest(self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub const fn tokenizer_bound_contract_digest(self) -> ArtifactDigest {
        self.tokenizer_bound_contract_digest
    }

    pub(crate) fn matches(&self, ledger: &EventLedger, tokenizer: &Utf8ByteTokenizerV1) -> bool {
        *self == Self::new(self.result_id, self.question_digest, ledger, tokenizer)
    }

    #[cfg(feature = "benchmark-instrumentation")]
    pub(crate) fn matches_candidate_config(
        &self,
        ledger: &EventLedger,
        tokenizer: &Utf8ByteTokenizerV1,
        candidate_config_digest: ArtifactDigest,
    ) -> bool {
        *self
            == Self::new_with_candidate_config_digest(
                self.result_id,
                self.question_digest,
                ledger,
                tokenizer,
                candidate_config_digest,
            )
    }
}

impl fmt::Debug for ProposalPreparationInputReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalPreparationInputReceiptV1")
            .field(
                "contract_version",
                &PROPOSAL_PREPARATION_CONTRACT_VERSION_V1,
            )
            .field("identities_present", &true)
            .finish()
    }
}

/// Checked, additive accounting over exhaustive primary metadata and the exact
/// positive-affinity selector proposal subset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProposalUniverseAccountingV1 {
    exhaustive_primary_block_count: u64,
    exhaustive_member_event_count: u64,
    exhaustive_member_source_bytes: u64,
    proposal_packet_count: u64,
    proposal_unique_member_event_count: u64,
    proposal_member_source_bytes: u64,
    retained_raw_nonproposal_block_count: u64,
    retained_raw_nonproposal_member_event_count: u64,
    retained_raw_nonproposal_source_bytes: u64,
    proposal_affinity_count: u64,
    mandatory_proposal_count: u64,
    facet_count: u64,
}

pub(crate) struct ProposalUniverseAccountingPartsV1 {
    pub exhaustive_primary_block_count: u64,
    pub exhaustive_member_event_count: u64,
    pub exhaustive_member_source_bytes: u64,
    pub proposal_packet_count: u64,
    pub proposal_unique_member_event_count: u64,
    pub proposal_member_source_bytes: u64,
    pub retained_raw_nonproposal_block_count: u64,
    pub retained_raw_nonproposal_member_event_count: u64,
    pub retained_raw_nonproposal_source_bytes: u64,
    pub proposal_affinity_count: u64,
    pub mandatory_proposal_count: u64,
    pub facet_count: u64,
}

impl ProposalUniverseAccountingV1 {
    pub(crate) fn new(
        parts: ProposalUniverseAccountingPartsV1,
    ) -> Result<Self, ProposalUniverseAccountingErrorV1> {
        let values = [
            parts.exhaustive_primary_block_count,
            parts.exhaustive_member_event_count,
            parts.exhaustive_member_source_bytes,
            parts.proposal_packet_count,
            parts.proposal_unique_member_event_count,
            parts.proposal_member_source_bytes,
            parts.retained_raw_nonproposal_block_count,
            parts.retained_raw_nonproposal_member_event_count,
            parts.retained_raw_nonproposal_source_bytes,
            parts.proposal_affinity_count,
            parts.mandatory_proposal_count,
            parts.facet_count,
        ];
        if values.iter().any(|value| *value > JSON_SAFE_INTEGER_MAX) {
            return Err(ProposalUniverseAccountingErrorV1::AboveJsonSafeInteger);
        }
        if parts
            .proposal_packet_count
            .checked_add(parts.retained_raw_nonproposal_block_count)
            != Some(parts.exhaustive_primary_block_count)
            || parts
                .proposal_unique_member_event_count
                .checked_add(parts.retained_raw_nonproposal_member_event_count)
                != Some(parts.exhaustive_member_event_count)
            || parts
                .proposal_member_source_bytes
                .checked_add(parts.retained_raw_nonproposal_source_bytes)
                != Some(parts.exhaustive_member_source_bytes)
            || parts.mandatory_proposal_count > parts.proposal_packet_count
            || (parts.proposal_packet_count > 0
                && parts.proposal_affinity_count < parts.proposal_packet_count)
        {
            return Err(ProposalUniverseAccountingErrorV1::PartitionInvariant);
        }
        Ok(Self {
            exhaustive_primary_block_count: parts.exhaustive_primary_block_count,
            exhaustive_member_event_count: parts.exhaustive_member_event_count,
            exhaustive_member_source_bytes: parts.exhaustive_member_source_bytes,
            proposal_packet_count: parts.proposal_packet_count,
            proposal_unique_member_event_count: parts.proposal_unique_member_event_count,
            proposal_member_source_bytes: parts.proposal_member_source_bytes,
            retained_raw_nonproposal_block_count: parts.retained_raw_nonproposal_block_count,
            retained_raw_nonproposal_member_event_count: parts
                .retained_raw_nonproposal_member_event_count,
            retained_raw_nonproposal_source_bytes: parts.retained_raw_nonproposal_source_bytes,
            proposal_affinity_count: parts.proposal_affinity_count,
            mandatory_proposal_count: parts.mandatory_proposal_count,
            facet_count: parts.facet_count,
        })
    }

    #[must_use]
    pub const fn exhaustive_primary_block_count(self) -> u64 {
        self.exhaustive_primary_block_count
    }

    #[must_use]
    pub const fn exhaustive_member_event_count(self) -> u64 {
        self.exhaustive_member_event_count
    }

    /// Exact authorized ledger bytes carried by exhaustive block members.
    #[must_use]
    pub const fn exhaustive_member_source_bytes(self) -> u64 {
        self.exhaustive_member_source_bytes
    }

    #[must_use]
    pub const fn proposal_packet_count(self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn proposal_unique_member_event_count(self) -> u64 {
        self.proposal_unique_member_event_count
    }

    /// Exact authorized ledger bytes carried by proposal members.
    #[must_use]
    pub const fn proposal_member_source_bytes(self) -> u64 {
        self.proposal_member_source_bytes
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_block_count(self) -> u64 {
        self.retained_raw_nonproposal_block_count
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_member_event_count(self) -> u64 {
        self.retained_raw_nonproposal_member_event_count
    }

    #[must_use]
    pub const fn retained_raw_nonproposal_source_bytes(self) -> u64 {
        self.retained_raw_nonproposal_source_bytes
    }

    #[must_use]
    pub const fn proposal_affinity_count(self) -> u64 {
        self.proposal_affinity_count
    }

    #[must_use]
    pub const fn mandatory_proposal_count(self) -> u64 {
        self.mandatory_proposal_count
    }

    #[must_use]
    pub const fn facet_count(self) -> u64 {
        self.facet_count
    }
}

impl fmt::Debug for ProposalUniverseAccountingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalUniverseAccountingV1")
            .field(
                "exhaustive_primary_block_count",
                &self.exhaustive_primary_block_count,
            )
            .field(
                "exhaustive_member_event_count",
                &self.exhaustive_member_event_count,
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
            .field("proposal_affinity_count", &self.proposal_affinity_count)
            .field("mandatory_proposal_count", &self.mandatory_proposal_count)
            .field("facet_count", &self.facet_count)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProposalUniverseAccountingErrorV1 {
    ArithmeticOverflow,
    AboveJsonSafeInteger,
    PartitionInvariant,
}

impl ProposalUniverseAccountingErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArithmeticOverflow => "EVIDENTRAIL_COMPILE_PROPOSAL_ACCOUNTING_OVERFLOW",
            Self::AboveJsonSafeInteger => "EVIDENTRAIL_COMPILE_PROPOSAL_ACCOUNTING_ABOVE_JSON_SAFE",
            Self::PartitionInvariant => "EVIDENTRAIL_COMPILE_PROPOSAL_ACCOUNTING_PARTITION",
        }
    }
}

impl fmt::Debug for ProposalUniverseAccountingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalUniverseAccountingErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ProposalUniverseAccountingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProposalUniverseAccountingErrorV1 {}

/// Canonical producer receipt. Its digest commits to every exhaustive block
/// fact and every exact positive-affinity proposal packet, not merely counts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProposalUniverseReceiptV1 {
    digest: ArtifactDigest,
    input: ProposalPreparationInputReceiptV1,
    accounting: ProposalUniverseAccountingV1,
    cost_model: Option<ComposableCostModelV1>,
}

impl ProposalUniverseReceiptV1 {
    pub(crate) fn new(
        input: ProposalPreparationInputReceiptV1,
        accounting: ProposalUniverseAccountingV1,
        facets: &[ProductionFacetV1],
        metadata: &[CompiledPacketMetadataV1],
        proposals: &[IntactPacketV1],
        mandatory: &[MandatoryPacketV1],
        certification: Option<&CompiledCostCertificationV1>,
    ) -> Self {
        let cost_model = certification.map(CompiledCostCertificationV1::cost_model);
        let mut hasher = Sha256::new();
        hasher.update(PROPOSAL_UNIVERSE_RECEIPT_DIGEST_DOMAIN_V1);
        update_field(&mut hasher, PROPOSAL_RECEIPT_INTEGER_ENCODING_V1);
        update_u16(&mut hasher, PROPOSAL_PREPARATION_CONTRACT_VERSION_V1);
        update_field(&mut hasher, input.digest().as_bytes());
        hash_accounting(&mut hasher, accounting);

        let mut canonical_facets = facets.iter().collect::<Vec<_>>();
        canonical_facets.sort_unstable_by_key(|facet| facet.id());
        update_len(&mut hasher, canonical_facets.len());
        for facet in canonical_facets {
            update_field(&mut hasher, facet.id().as_bytes());
            update_field(&mut hasher, facet.kind().code().as_bytes());
            update_u32(&mut hasher, facet.weight().micros());
        }

        let mut canonical_metadata = metadata.iter().collect::<Vec<_>>();
        canonical_metadata.sort_unstable_by_key(|entry| entry.block_id());
        update_len(&mut hasher, canonical_metadata.len());
        for entry in canonical_metadata {
            update_field(&mut hasher, entry.block_id().as_bytes());
            update_field(&mut hasher, entry.packet_id().as_bytes());
            update_len(&mut hasher, entry.ordered_event_ids().len());
            for event_id in entry.ordered_event_ids() {
                update_field(&mut hasher, event_id.as_bytes());
            }
            let mut reasons = entry.mandatory_reasons().to_vec();
            reasons.sort_unstable_by_key(|reason| (reason.facet_id(), reason.identifier_kind()));
            update_len(&mut hasher, reasons.len());
            for reason in reasons {
                update_field(&mut hasher, reason.facet_id().as_bytes());
                update_field(&mut hasher, reason.identifier_kind().code().as_bytes());
            }
        }

        let mut canonical_proposals = proposals.iter().collect::<Vec<_>>();
        canonical_proposals.sort_unstable_by_key(|packet| packet.id());
        update_len(&mut hasher, canonical_proposals.len());
        for packet in canonical_proposals {
            update_field(&mut hasher, packet.id().as_bytes());
            update_len(&mut hasher, packet.event_ids().len());
            for event_id in packet.event_ids() {
                update_field(&mut hasher, event_id.as_bytes());
            }
            let cost = packet.composable_token_upper_bound();
            update_field(&mut hasher, cost.cost_model().artifact_digest().as_bytes());
            update_u64(&mut hasher, cost.upper_bound_tokens());
            update_len(&mut hasher, packet.affinities().len());
            for affinity in packet.affinities() {
                update_field(&mut hasher, affinity.facet_id().as_bytes());
                update_u32(&mut hasher, affinity.affinity().micros());
            }
        }

        let mut canonical_mandatory = mandatory.to_vec();
        canonical_mandatory.sort_unstable_by_key(|entry| {
            (entry.packet_id(), entry.validated_identifier_facet_id())
        });
        update_len(&mut hasher, canonical_mandatory.len());
        for entry in canonical_mandatory {
            update_field(&mut hasher, entry.packet_id().as_bytes());
            update_field(
                &mut hasher,
                entry.validated_identifier_facet_id().as_bytes(),
            );
        }

        match certification {
            Some(certification) => {
                hasher.update([1]);
                update_field(
                    &mut hasher,
                    certification.cost_model().artifact_digest().as_bytes(),
                );
                update_field(
                    &mut hasher,
                    certification
                        .tokenizer_bound()
                        .tokenizer_digest()
                        .as_bytes(),
                );
                update_field(
                    &mut hasher,
                    certification.tokenizer_bound().contract_digest().as_bytes(),
                );
                update_u64(
                    &mut hasher,
                    certification.fixed_overhead().upper_bound_tokens(),
                );
                update_u64(&mut hasher, certification.universe_upper_bound());
            }
            None => hasher.update([0]),
        }

        Self {
            digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            input,
            accounting,
            cost_model,
        }
    }

    #[must_use]
    pub const fn digest(self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn input(self) -> ProposalPreparationInputReceiptV1 {
        self.input
    }

    #[must_use]
    pub const fn accounting(self) -> ProposalUniverseAccountingV1 {
        self.accounting
    }

    #[must_use]
    pub const fn cost_model(self) -> Option<ComposableCostModelV1> {
        self.cost_model
    }
}

impl fmt::Debug for ProposalUniverseReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalUniverseReceiptV1")
            .field("accounting", &self.accounting)
            .field("cost_model_present", &self.cost_model.is_some())
            .finish()
    }
}

/// Budget-independent, producer-certified proposal universe.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedThreeLaneProposalUniverseV1 {
    receipt: ProposalUniverseReceiptV1,
    facets: Vec<ProductionFacetV1>,
    packet_metadata: Vec<CompiledPacketMetadataV1>,
    proposal_packets: Vec<IntactPacketV1>,
    mandatory: Vec<MandatoryPacketV1>,
    certification: Option<CompiledCostCertificationV1>,
}

impl PreparedThreeLaneProposalUniverseV1 {
    pub(crate) fn new(
        receipt: ProposalUniverseReceiptV1,
        facets: Vec<ProductionFacetV1>,
        packet_metadata: Vec<CompiledPacketMetadataV1>,
        proposal_packets: Vec<IntactPacketV1>,
        mandatory: Vec<MandatoryPacketV1>,
        certification: Option<CompiledCostCertificationV1>,
    ) -> Self {
        Self {
            receipt,
            facets,
            packet_metadata,
            proposal_packets,
            mandatory,
            certification,
        }
    }

    #[must_use]
    pub const fn receipt(&self) -> ProposalUniverseReceiptV1 {
        self.receipt
    }

    #[must_use]
    pub fn facets(&self) -> &[ProductionFacetV1] {
        &self.facets
    }

    /// Exhaustive canonical metadata for every primary block, including
    /// retained-raw nonproposals.
    #[must_use]
    pub fn packet_metadata(&self) -> &[CompiledPacketMetadataV1] {
        &self.packet_metadata
    }

    /// Exact positive-affinity packet universe eligible for selection.
    #[must_use]
    pub fn proposal_packets(&self) -> &[IntactPacketV1] {
        &self.proposal_packets
    }

    /// Resolve one exact proposal ID to the exhaustive primary metadata from
    /// which its member set was derived.
    #[must_use]
    pub fn proposal_metadata(
        &self,
        packet_id: evidentrail_select::PacketIdV1,
    ) -> Option<&CompiledPacketMetadataV1> {
        if !self
            .proposal_packets
            .iter()
            .any(|packet| packet.id() == packet_id)
        {
            return None;
        }
        find_packet_metadata_v1(&self.packet_metadata, packet_id)
    }

    #[must_use]
    pub fn mandatory(&self) -> &[MandatoryPacketV1] {
        &self.mandatory
    }

    #[must_use]
    pub const fn certification(&self) -> Option<&CompiledCostCertificationV1> {
        self.certification.as_ref()
    }

    pub(crate) fn into_parts(self) -> PreparedProposalPartsV1 {
        PreparedProposalPartsV1 {
            receipt: self.receipt,
            facets: self.facets,
            packet_metadata: self.packet_metadata,
            certification: self.certification,
        }
    }
}

impl fmt::Debug for PreparedThreeLaneProposalUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedThreeLaneProposalUniverseV1")
            .field("receipt", &self.receipt)
            .field("facet_count", &self.facets.len())
            .field("packet_metadata_count", &self.packet_metadata.len())
            .field("proposal_packet_count", &self.proposal_packets.len())
            .field("mandatory_packet_count", &self.mandatory.len())
            .field("certification_present", &self.certification.is_some())
            .finish()
    }
}

pub(crate) struct PreparedProposalPartsV1 {
    pub receipt: ProposalUniverseReceiptV1,
    pub facets: Vec<ProductionFacetV1>,
    pub packet_metadata: Vec<CompiledPacketMetadataV1>,
    pub certification: Option<CompiledCostCertificationV1>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ThreeLaneProposalPreparationNeedsMoreV1 {
    reason: ThreeLaneNeedsMoreV1,
    input: ProposalPreparationInputReceiptV1,
}

impl ThreeLaneProposalPreparationNeedsMoreV1 {
    pub(crate) const fn new(
        reason: ThreeLaneNeedsMoreV1,
        input: ProposalPreparationInputReceiptV1,
    ) -> Self {
        Self { reason, input }
    }

    #[must_use]
    pub const fn reason(&self) -> ThreeLaneNeedsMoreV1 {
        self.reason
    }

    #[must_use]
    pub const fn input(&self) -> ProposalPreparationInputReceiptV1 {
        self.input
    }
}

impl fmt::Debug for ThreeLaneProposalPreparationNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneProposalPreparationNeedsMoreV1")
            .field("reason", &self.reason)
            .field("input", &self.input)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ThreeLaneProposalPreparationDecisionV1 {
    Prepared(Box<PreparedThreeLaneProposalUniverseV1>),
    NeedsMore(Box<ThreeLaneProposalPreparationNeedsMoreV1>),
}

impl ThreeLaneProposalPreparationDecisionV1 {
    #[must_use]
    pub fn prepared(&self) -> Option<&PreparedThreeLaneProposalUniverseV1> {
        match self {
            Self::Prepared(prepared) => Some(prepared),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<&ThreeLaneProposalPreparationNeedsMoreV1> {
        match self {
            Self::Prepared(_) => None,
            Self::NeedsMore(needs_more) => Some(needs_more),
        }
    }
}

impl fmt::Debug for ThreeLaneProposalPreparationDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepared(prepared) => formatter
                .debug_struct("ThreeLaneProposalPreparationDecisionV1")
                .field("state", &"prepared")
                .field("summary", prepared)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_struct("ThreeLaneProposalPreparationDecisionV1")
                .field("state", &"needs_more")
                .field("summary", needs_more)
                .finish(),
        }
    }
}

/// Budget failure retaining the exact prepared proposal artifact for an honest
/// retry under a different final output budget.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedThreeLaneNeedsMoreV1 {
    reason: ThreeLaneNeedsMoreV1,
    prepared: PreparedThreeLaneProposalUniverseV1,
}

impl PreparedThreeLaneNeedsMoreV1 {
    pub(crate) const fn new(
        reason: ThreeLaneNeedsMoreV1,
        prepared: PreparedThreeLaneProposalUniverseV1,
    ) -> Self {
        Self { reason, prepared }
    }

    #[must_use]
    pub const fn reason(&self) -> ThreeLaneNeedsMoreV1 {
        self.reason
    }

    #[must_use]
    pub const fn receipt(&self) -> ProposalUniverseReceiptV1 {
        self.prepared.receipt()
    }

    #[must_use]
    pub const fn prepared(&self) -> &PreparedThreeLaneProposalUniverseV1 {
        &self.prepared
    }

    #[must_use]
    pub fn into_prepared(self) -> PreparedThreeLaneProposalUniverseV1 {
        self.prepared
    }
}

impl fmt::Debug for PreparedThreeLaneNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedThreeLaneNeedsMoreV1")
            .field("reason", &self.reason)
            .field("receipt", &self.receipt())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PreparedThreeLaneSelectionDecisionV1 {
    Selected(Box<CertifiedThreeLaneSelectionV1>),
    NeedsMore(Box<PreparedThreeLaneNeedsMoreV1>),
}

impl PreparedThreeLaneSelectionDecisionV1 {
    #[must_use]
    pub fn selected(&self) -> Option<&CertifiedThreeLaneSelectionV1> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub fn needs_more(&self) -> Option<&PreparedThreeLaneNeedsMoreV1> {
        match self {
            Self::Selected(_) => None,
            Self::NeedsMore(needs_more) => Some(needs_more),
        }
    }
}

impl fmt::Debug for PreparedThreeLaneSelectionDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(selected) => formatter
                .debug_struct("PreparedThreeLaneSelectionDecisionV1")
                .field("state", &"selected")
                .field("summary", selected)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_struct("PreparedThreeLaneSelectionDecisionV1")
                .field("state", &"needs_more")
                .field("summary", needs_more)
                .finish(),
        }
    }
}

fn adapter_identity_digest(ledger: &EventLedger) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_IDENTITY_DIGEST_DOMAIN_V1);
    update_field(&mut hasher, ledger.adapter().kind().as_bytes());
    update_field(&mut hasher, ledger.adapter().version().as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

fn hash_accounting(hasher: &mut Sha256, accounting: ProposalUniverseAccountingV1) {
    for value in [
        accounting.exhaustive_primary_block_count(),
        accounting.exhaustive_member_event_count(),
        accounting.exhaustive_member_source_bytes(),
        accounting.proposal_packet_count(),
        accounting.proposal_unique_member_event_count(),
        accounting.proposal_member_source_bytes(),
        accounting.retained_raw_nonproposal_block_count(),
        accounting.retained_raw_nonproposal_member_event_count(),
        accounting.retained_raw_nonproposal_source_bytes(),
        accounting.proposal_affinity_count(),
        accounting.mandatory_proposal_count(),
        accounting.facet_count(),
    ] {
        update_u64(hasher, value);
    }
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    update_u64(
        hasher,
        u64::try_from(bytes.len()).expect("bounded receipt field length fits u64"),
    );
    hasher.update(bytes);
}

fn update_len(hasher: &mut Sha256, length: usize) {
    update_u64(
        hasher,
        u64::try_from(length).expect("bounded receipt collection length fits u64"),
    );
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn update_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn update_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}
