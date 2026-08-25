use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::EvidenceTargetV1;
use evidentrail_compile::{PreparedThreeLaneNeedsMoreV1, ThreeLaneNeedsMoreV1};
use evidentrail_core::EvidenceTargetRef;
use evidentrail_evidence::{
    CompiledAgentViewCandidateV1, OwnedRenderedCompiledBriefV1,
    compiled_agent_view_candidate_renderer_digest_v1, unescape_evidence_bytes,
};
use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::TotalTokenBudgetV1;
use sha2::{Digest, Sha256};

use crate::{
    CompactAgentViewCorpusReductionReceiptV1, CompactAgentViewErrorV1,
    CompactAgentViewReaderPreservationReceiptV1, CompactAgentViewV1,
    FrozenReaderSingleShotReceiptV1, ReaderResourceCapsV1, artifact_digest_for_bytes_v1,
    compare_compact_agent_view_reader_receipts_v1,
};

pub const COMPACT_AGENT_VIEW_CHALLENGE_CORPUS_CONTRACT_VERSION_V1: u16 = 1;
pub const COMPACT_AGENT_VIEW_ADMISSION_MEASUREMENT_CONTRACT_VERSION_V1: u16 = 1;
pub const COMPACT_AGENT_VIEW_CHALLENGE_RENDERED_CASE_COUNT_V1: u64 = 4;
pub const COMPACT_AGENT_VIEW_CHALLENGE_NEEDS_MORE_CASE_COUNT_V1: u64 = 1;
pub const MAX_COMPACT_AGENT_VIEW_MEASURED_READER_PAIRS_V1: usize = 16;

const CHALLENGE_CORPUS_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-admission-challenge-corpus/v1\0rendered-cases=4\0needs-more-cases=1\0classes=arbitrary-bytes-structural-injection,duplicate-occurrences,empty-crlf-backslash,deep-stack-trace\0source=typed-owned-compiled-log-brief\0byte-proof=decode-range-and-compare-to-structured-event\0citation-proof=alias-and-occurrence-target-equality\0production-renderer-unchanged=true\0hosted-reader=false";
const CHALLENGE_CASE_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-challenge-case/v1";
const NEEDS_MORE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-needs-more-observation/v1";
const CHALLENGE_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-challenge-corpus-receipt/v1";
const READER_ARM_MEASUREMENT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-reader-arm-measurement/v1";
const READER_PAIR_MEASUREMENT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-reader-pair-measurement/v1";
const ADMISSION_EVIDENCE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-production-admission-evidence/v1";
const CAPS_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-reader-caps/v1";
const BYTE_BINDING_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-challenge-byte-binding/v1";
const PRODUCTION_CANDIDATE_PARITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-production-candidate-parity/v1";

#[must_use]
pub fn compact_agent_view_challenge_corpus_identity_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(CHALLENGE_CORPUS_MANIFEST_V1)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompactAgentViewChallengeClassV1 {
    ArbitraryBytesStructuralInjection,
    DuplicateOccurrences,
    EmptyCrLfBackslash,
    DeepStackTrace,
}

impl CompactAgentViewChallengeClassV1 {
    pub const ALL: [Self; 4] = [
        Self::ArbitraryBytesStructuralInjection,
        Self::DuplicateOccurrences,
        Self::EmptyCrLfBackslash,
        Self::DeepStackTrace,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArbitraryBytesStructuralInjection => "arbitrary_bytes_structural_injection",
            Self::DuplicateOccurrences => "duplicate_occurrences",
            Self::EmptyCrLfBackslash => "empty_crlf_backslash",
            Self::DeepStackTrace => "deep_stack_trace",
        }
    }
}

impl fmt::Debug for CompactAgentViewChallengeClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewChallengeClassV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewChallengeObservationV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    class: CompactAgentViewChallengeClassV1,
    view_artifact_digest: ArtifactDigest,
    audit_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    canonical_render_artifact_digest: ArtifactDigest,
    compact_output_artifact_digest: ArtifactDigest,
    byte_binding_artifact_digest: ArtifactDigest,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    packet_count: u64,
    citation_count: u64,
    event_count: u64,
    decoded_event_byte_count: u64,
}

impl CompactAgentViewChallengeObservationV1 {
    pub fn try_new(
        public_case_artifact_digest: ArtifactDigest,
        class: CompactAgentViewChallengeClassV1,
        canonical: &OwnedRenderedCompiledBriefV1,
        view: &CompactAgentViewV1,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        let canonical_render_artifact_digest =
            artifact_digest_for_bytes_v1(canonical.text().as_bytes());
        if canonical_render_artifact_digest != view.audit().canonical_render_artifact_digest()
            || canonical.brief().evidence().len() != view.audit().packet_audits().len()
            || canonical.brief().evidence().len() != view.citation_handles().len()
            || !view.untrusted_data()
            || !view.byte_exact_event_content()
            || view.canonical_text_parsed_or_postprocessed()
            || view.production_renderer_changed()
            || view.contains_hidden_labels()
        {
            return Err(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation);
        }

        let mut byte_hasher = Sha256::new();
        update_field(&mut byte_hasher, BYTE_BINDING_DOMAIN_V1);
        update_field(&mut byte_hasher, public_case_artifact_digest.as_bytes());
        update_field(&mut byte_hasher, view.artifact_digest().as_bytes());
        let mut event_count = 0_u64;
        let mut decoded_event_byte_count = 0_u64;
        let mut previous_field_end = 0_u64;
        let mut payload_occurrences = BTreeMap::<Vec<u8>, BTreeSet<EventId>>::new();
        let mut has_invalid_utf8 = false;
        let mut has_nul = false;
        let mut has_non_ascii = false;
        let mut has_structural_token = false;
        let mut has_empty = false;
        let mut has_crlf = false;
        let mut has_backslash = false;
        let mut has_stack_header = false;
        let mut has_stack_frame = false;
        let mut has_stack_terminal = false;

        for ((packet, audit), citation) in canonical
            .brief()
            .evidence()
            .iter()
            .zip(view.audit().packet_audits())
            .zip(view.citation_handles())
        {
            if audit.alias() != citation.handle()
                || packet.ordinal().checked_add(1) != usize::try_from(audit.alias()).ok()
                || packet.events().len() != audit.events().len()
            {
                return Err(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation);
            }
            let canonical_targets = packet
                .events()
                .iter()
                .map(|event| EvidenceTargetV1::Event(event.event_id()))
                .collect::<BTreeSet<_>>();
            let citation_targets = citation.targets().iter().copied().collect::<BTreeSet<_>>();
            if canonical_targets != citation_targets {
                return Err(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation);
            }
            for (event, proof) in packet.events().iter().zip(audit.events()) {
                let (field_start, field_end) = proof.field_range();
                let (data_start, data_end) = proof.encoded_data_range();
                if proof.event_id() != event.event_id()
                    || proof.exactness_basis() != event.exactness_basis()
                    || proof.stream() != event.stream()
                    || proof.authorized_byte_count() != checked_u64(event.authorized_bytes().len())?
                    || field_start < previous_field_end
                    || field_start > data_start
                    || data_start > data_end
                    || data_end > field_end
                {
                    return Err(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation);
                }
                let start = usize::try_from(data_start)
                    .map_err(|_| CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)?;
                let end = usize::try_from(data_end)
                    .map_err(|_| CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)?;
                let encoded = std::str::from_utf8(
                    view.bytes()
                        .get(start..end)
                        .ok_or(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation)?,
                )
                .map_err(|_| CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation)?;
                let decoded = unescape_evidence_bytes(encoded)
                    .map_err(|_| CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation)?;
                if decoded != event.authorized_bytes() {
                    return Err(CompactAgentViewAdmissionErrorV1::InvalidChallengeObservation);
                }
                previous_field_end = field_end;
                event_count = event_count
                    .checked_add(1)
                    .ok_or(CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)?;
                decoded_event_byte_count = decoded_event_byte_count
                    .checked_add(checked_u64(decoded.len())?)
                    .ok_or(CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)?;
                has_invalid_utf8 |= std::str::from_utf8(&decoded).is_err();
                has_nul |= decoded.contains(&0);
                has_non_ascii |= decoded.iter().any(|byte| !byte.is_ascii());
                has_structural_token |= contains_bytes(&decoded, b"[E999]")
                    || contains_bytes(&decoded, b"EVIDENTRAIL_AGENT_VIEW_V1");
                has_empty |= decoded.is_empty();
                has_crlf |= contains_bytes(&decoded, b"\r\n");
                has_backslash |= decoded.contains(&b'\\');
                has_stack_header |= contains_bytes(&decoded, b"Traceback");
                has_stack_frame |=
                    contains_bytes(&decoded, b"File \"") || contains_bytes(&decoded, b" at ");
                has_stack_terminal |= contains_bytes(&decoded, b"RuntimeError")
                    || contains_bytes(&decoded, b"Exception")
                    || contains_bytes(&decoded, b"panic");
                payload_occurrences
                    .entry(decoded.clone())
                    .or_default()
                    .insert(event.event_id());
                update_field(&mut byte_hasher, event.event_id().as_bytes());
                update_field(&mut byte_hasher, &decoded);
                update_u64(&mut byte_hasher, field_start);
                update_u64(&mut byte_hasher, field_end);
                update_u64(&mut byte_hasher, data_start);
                update_u64(&mut byte_hasher, data_end);
            }
        }
        let has_duplicate_occurrences = payload_occurrences
            .values()
            .any(|event_ids| event_ids.len() >= 2);
        let class_is_proven = match class {
            CompactAgentViewChallengeClassV1::ArbitraryBytesStructuralInjection => {
                has_invalid_utf8 && has_nul && has_non_ascii && has_structural_token
            }
            CompactAgentViewChallengeClassV1::DuplicateOccurrences => has_duplicate_occurrences,
            CompactAgentViewChallengeClassV1::EmptyCrLfBackslash => {
                has_empty && has_crlf && has_backslash
            }
            CompactAgentViewChallengeClassV1::DeepStackTrace => {
                has_stack_header
                    && has_stack_frame
                    && has_stack_terminal
                    && decoded_event_byte_count >= 128
            }
        };
        if !class_is_proven || event_count == 0 {
            return Err(CompactAgentViewAdmissionErrorV1::ChallengeClassUnproven);
        }
        let packet_count = checked_u64(canonical.brief().evidence().len())?;
        let citation_count = checked_u64(view.citation_handles().len())?;
        let byte_binding_artifact_digest =
            ArtifactDigest::from_bytes(byte_hasher.finalize().into());
        let mut hasher = Sha256::new();
        update_field(&mut hasher, CHALLENGE_CASE_DOMAIN_V1);
        update_field(&mut hasher, public_case_artifact_digest.as_bytes());
        update_field(&mut hasher, class.code().as_bytes());
        update_field(&mut hasher, view.artifact_digest().as_bytes());
        update_field(&mut hasher, view.audit().artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            view.audit().config().artifact_digest().as_bytes(),
        );
        update_field(&mut hasher, canonical_render_artifact_digest.as_bytes());
        update_field(&mut hasher, view.output_artifact_digest().as_bytes());
        update_field(&mut hasher, byte_binding_artifact_digest.as_bytes());
        for value in [
            view.audit().canonical_byte_count(),
            view.audit().compact_byte_count(),
            view.audit().saved_byte_count(),
            packet_count,
            citation_count,
            event_count,
            decoded_event_byte_count,
        ] {
            update_u64(&mut hasher, value);
        }
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            public_case_artifact_digest,
            class,
            view_artifact_digest: view.artifact_digest(),
            audit_artifact_digest: view.audit().artifact_digest(),
            config_artifact_digest: view.audit().config().artifact_digest(),
            canonical_render_artifact_digest,
            compact_output_artifact_digest: view.output_artifact_digest(),
            byte_binding_artifact_digest,
            canonical_byte_count: view.audit().canonical_byte_count(),
            compact_byte_count: view.audit().compact_byte_count(),
            saved_byte_count: view.audit().saved_byte_count(),
            packet_count,
            citation_count,
            event_count,
            decoded_event_byte_count,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn class(self) -> CompactAgentViewChallengeClassV1 {
        self.class
    }

    #[must_use]
    pub const fn view_artifact_digest(self) -> ArtifactDigest {
        self.view_artifact_digest
    }

    #[must_use]
    pub const fn audit_artifact_digest(self) -> ArtifactDigest {
        self.audit_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn canonical_render_artifact_digest(self) -> ArtifactDigest {
        self.canonical_render_artifact_digest
    }

    #[must_use]
    pub const fn compact_output_artifact_digest(self) -> ArtifactDigest {
        self.compact_output_artifact_digest
    }

    #[must_use]
    pub const fn byte_binding_artifact_digest(self) -> ArtifactDigest {
        self.byte_binding_artifact_digest
    }

    #[must_use]
    pub const fn canonical_byte_count(self) -> u64 {
        self.canonical_byte_count
    }

    #[must_use]
    pub const fn compact_byte_count(self) -> u64 {
        self.compact_byte_count
    }

    #[must_use]
    pub const fn saved_byte_count(self) -> u64 {
        self.saved_byte_count
    }

    #[must_use]
    pub const fn packet_count(self) -> u64 {
        self.packet_count
    }

    #[must_use]
    pub const fn citation_count(self) -> u64 {
        self.citation_count
    }

    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn decoded_event_byte_count(self) -> u64 {
        self.decoded_event_byte_count
    }
}

impl fmt::Debug for CompactAgentViewChallengeObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewChallengeObservationV1")
            .field("case_identity_present", &true)
            .field("class", &self.class)
            .field("view_binding_present", &true)
            .field("audit_binding_present", &true)
            .field("canonical_render_binding_present", &true)
            .field("compact_output_binding_present", &true)
            .field("byte_binding_present", &true)
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field("packet_count", &self.packet_count)
            .field("citation_count", &self.citation_count)
            .field("event_count", &self.event_count)
            .field("decoded_event_byte_count", &self.decoded_event_byte_count)
            .field("content_redacted", &true)
            .finish()
    }
}

/// Exact parity proof between the benchmark challenger and the production-owned,
/// default-off controlled-admission candidate renderer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewProductionCandidateParityV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    view_artifact_digest: ArtifactDigest,
    benchmark_audit_artifact_digest: ArtifactDigest,
    production_candidate_audit_artifact_digest: ArtifactDigest,
    production_candidate_renderer_artifact_digest: ArtifactDigest,
    output_artifact_digest: ArtifactDigest,
    output_byte_count: u64,
    citation_count: u64,
    event_count: u64,
}

impl CompactAgentViewProductionCandidateParityV1 {
    pub fn try_new(
        public_case_artifact_digest: ArtifactDigest,
        view: &CompactAgentViewV1,
        production_candidate: &CompiledAgentViewCandidateV1,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        let candidate_audit = production_candidate.audit();
        let view_event_proofs = view
            .audit()
            .packet_audits()
            .iter()
            .flat_map(|packet| packet.events())
            .collect::<Vec<_>>();
        if production_candidate.text().as_bytes() != view.bytes()
            || candidate_audit.source_render_artifact_digest()
                != view.audit().canonical_render_artifact_digest()
            || candidate_audit.output_artifact_digest() != view.output_artifact_digest()
            || candidate_audit.output_byte_count() != view.audit().compact_byte_count()
            || candidate_audit.canonical_byte_count() != view.audit().canonical_byte_count()
            || candidate_audit.saved_byte_count() != view.audit().saved_byte_count()
            || candidate_audit.candidate_renderer_digest()
                != compiled_agent_view_candidate_renderer_digest_v1()
            || production_candidate.citations().len() != view.citation_handles().len()
            || production_candidate.event_proofs().len() != view_event_proofs.len()
            || production_candidate.production_default_changed()
            || !production_candidate.untrusted_data()
            || !production_candidate.byte_exact_event_content()
            || production_candidate.canonical_text_parsed_or_postprocessed()
        {
            return Err(CompactAgentViewAdmissionErrorV1::ProductionCandidateParityMismatch);
        }
        for (candidate, benchmark) in production_candidate
            .citations()
            .iter()
            .zip(view.citation_handles())
        {
            let candidate_targets = candidate
                .reference()
                .targets()
                .iter()
                .map(|target| match target {
                    EvidenceTargetRef::Event(event_id) => EvidenceTargetV1::Event(*event_id),
                    EvidenceTargetRef::Block(block_id) => EvidenceTargetV1::Block(*block_id),
                })
                .collect::<BTreeSet<_>>();
            let benchmark_targets = benchmark.targets().iter().copied().collect::<BTreeSet<_>>();
            if candidate.alias() != benchmark.handle()
                || candidate.marker_range() != (benchmark.marker_start(), benchmark.marker_end())
                || candidate_targets != benchmark_targets
            {
                return Err(CompactAgentViewAdmissionErrorV1::ProductionCandidateParityMismatch);
            }
        }
        for (candidate, benchmark) in production_candidate
            .event_proofs()
            .iter()
            .zip(view_event_proofs)
        {
            if candidate.event_id() != benchmark.event_id()
                || candidate.exactness_basis() != benchmark.exactness_basis()
                || candidate.stream() != benchmark.stream()
                || candidate.field_range() != benchmark.field_range()
                || candidate.encoded_data_range() != benchmark.encoded_data_range()
                || candidate.authorized_byte_count() != benchmark.authorized_byte_count()
            {
                return Err(CompactAgentViewAdmissionErrorV1::ProductionCandidateParityMismatch);
            }
        }
        let output_byte_count = checked_u64(view.bytes().len())?;
        let citation_count = checked_u64(view.citation_handles().len())?;
        let event_count = checked_u64(production_candidate.event_proofs().len())?;
        let mut hasher = Sha256::new();
        update_field(&mut hasher, PRODUCTION_CANDIDATE_PARITY_DOMAIN_V1);
        update_field(&mut hasher, public_case_artifact_digest.as_bytes());
        update_field(&mut hasher, view.artifact_digest().as_bytes());
        update_field(&mut hasher, view.audit().artifact_digest().as_bytes());
        update_field(&mut hasher, candidate_audit.artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            candidate_audit.candidate_renderer_digest().as_bytes(),
        );
        update_field(&mut hasher, view.output_artifact_digest().as_bytes());
        update_u64(&mut hasher, output_byte_count);
        update_u64(&mut hasher, citation_count);
        update_u64(&mut hasher, event_count);
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            public_case_artifact_digest,
            view_artifact_digest: view.artifact_digest(),
            benchmark_audit_artifact_digest: view.audit().artifact_digest(),
            production_candidate_audit_artifact_digest: candidate_audit.artifact_digest(),
            production_candidate_renderer_artifact_digest: candidate_audit
                .candidate_renderer_digest(),
            output_artifact_digest: view.output_artifact_digest(),
            output_byte_count,
            citation_count,
            event_count,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn view_artifact_digest(self) -> ArtifactDigest {
        self.view_artifact_digest
    }

    #[must_use]
    pub const fn benchmark_audit_artifact_digest(self) -> ArtifactDigest {
        self.benchmark_audit_artifact_digest
    }

    #[must_use]
    pub const fn production_candidate_audit_artifact_digest(self) -> ArtifactDigest {
        self.production_candidate_audit_artifact_digest
    }

    #[must_use]
    pub const fn production_candidate_renderer_artifact_digest(self) -> ArtifactDigest {
        self.production_candidate_renderer_artifact_digest
    }

    #[must_use]
    pub const fn output_artifact_digest(self) -> ArtifactDigest {
        self.output_artifact_digest
    }

    #[must_use]
    pub const fn output_byte_count(self) -> u64 {
        self.output_byte_count
    }

    #[must_use]
    pub const fn citation_count(self) -> u64 {
        self.citation_count
    }

    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn exact_text_alias_range_and_count_parity(self) -> bool {
        true
    }
}

impl fmt::Debug for CompactAgentViewProductionCandidateParityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewProductionCandidateParityV1")
            .field("parity_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("view_binding_present", &true)
            .field("benchmark_audit_binding_present", &true)
            .field("production_candidate_audit_binding_present", &true)
            .field("production_candidate_renderer_binding_present", &true)
            .field("output_binding_present", &true)
            .field("output_byte_count", &self.output_byte_count)
            .field("citation_count", &self.citation_count)
            .field("event_count", &self.event_count)
            .field("exact_text_alias_range_and_count_parity", &true)
            .field("production_default_changed", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewNeedsMoreObservationV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    proposal_receipt_artifact_digest: ArtifactDigest,
    budget_tokens: u64,
    reason: ThreeLaneNeedsMoreV1,
}

impl CompactAgentViewNeedsMoreObservationV1 {
    pub fn from_prepared(
        public_case_artifact_digest: ArtifactDigest,
        budget: TotalTokenBudgetV1,
        needs_more: &PreparedThreeLaneNeedsMoreV1,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        let reason = needs_more.reason();
        let proposal_receipt_artifact_digest = needs_more.receipt().digest();
        let mut hasher = Sha256::new();
        update_field(&mut hasher, NEEDS_MORE_DOMAIN_V1);
        update_field(&mut hasher, public_case_artifact_digest.as_bytes());
        update_field(&mut hasher, proposal_receipt_artifact_digest.as_bytes());
        update_u64(&mut hasher, budget.tokens());
        update_field(&mut hasher, reason.code().as_bytes());
        update_field(
            &mut hasher,
            reason.lane().map_or("none", |lane| lane.code()).as_bytes(),
        );
        update_field(
            &mut hasher,
            reason
                .candidate_reason()
                .map_or("none", |candidate| candidate.code())
                .as_bytes(),
        );
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            public_case_artifact_digest,
            proposal_receipt_artifact_digest,
            budget_tokens: budget.tokens(),
            reason,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn proposal_receipt_artifact_digest(self) -> ArtifactDigest {
        self.proposal_receipt_artifact_digest
    }

    #[must_use]
    pub const fn budget_tokens(self) -> u64 {
        self.budget_tokens
    }

    #[must_use]
    pub const fn reason(self) -> ThreeLaneNeedsMoreV1 {
        self.reason
    }

    #[must_use]
    pub const fn compact_view_emitted(self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewNeedsMoreObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewNeedsMoreObservationV1")
            .field("case_identity_present", &true)
            .field("proposal_receipt_binding_present", &true)
            .field("budget_tokens", &self.budget_tokens)
            .field("reason_code", &self.reason.code())
            .field("compact_view_emitted", &false)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewChallengeCorpusReceiptV1 {
    artifact_digest: ArtifactDigest,
    corpus_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    cases: Vec<CompactAgentViewChallengeObservationV1>,
    needs_more: CompactAgentViewNeedsMoreObservationV1,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    citation_count: u64,
    event_count: u64,
    decoded_event_byte_count: u64,
    reduction_micros: u64,
}

impl CompactAgentViewChallengeCorpusReceiptV1 {
    pub fn try_new(
        mut cases: Vec<CompactAgentViewChallengeObservationV1>,
        needs_more: CompactAgentViewNeedsMoreObservationV1,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        if checked_u64(cases.len())? != COMPACT_AGENT_VIEW_CHALLENGE_RENDERED_CASE_COUNT_V1 {
            return Err(CompactAgentViewAdmissionErrorV1::MissingChallengeCoverage);
        }
        cases.sort_unstable_by_key(|case| case.public_case_artifact_digest);
        let config_artifact_digest = cases[0].config_artifact_digest;
        let mut seen_cases = BTreeSet::new();
        let mut seen_classes = BTreeSet::new();
        let mut canonical_byte_count = 0_u64;
        let mut compact_byte_count = 0_u64;
        let mut saved_byte_count = 0_u64;
        let mut citation_count = 0_u64;
        let mut event_count = 0_u64;
        let mut decoded_event_byte_count = 0_u64;
        for case in &cases {
            if !seen_cases.insert(case.public_case_artifact_digest)
                || !seen_classes.insert(case.class)
                || case.config_artifact_digest != config_artifact_digest
                || case.saved_byte_count == 0
            {
                return Err(CompactAgentViewAdmissionErrorV1::MissingChallengeCoverage);
            }
            canonical_byte_count = checked_add(canonical_byte_count, case.canonical_byte_count)?;
            compact_byte_count = checked_add(compact_byte_count, case.compact_byte_count)?;
            saved_byte_count = checked_add(saved_byte_count, case.saved_byte_count)?;
            citation_count = checked_add(citation_count, case.citation_count)?;
            event_count = checked_add(event_count, case.event_count)?;
            decoded_event_byte_count =
                checked_add(decoded_event_byte_count, case.decoded_event_byte_count)?;
        }
        if seen_classes != CompactAgentViewChallengeClassV1::ALL.into_iter().collect()
            || seen_cases.contains(&needs_more.public_case_artifact_digest)
            || needs_more.compact_view_emitted()
        {
            return Err(CompactAgentViewAdmissionErrorV1::MissingChallengeCoverage);
        }
        let reduction_micros = reduction_micros(saved_byte_count, canonical_byte_count)?;
        let corpus_artifact_digest = compact_agent_view_challenge_corpus_identity_v1();
        let mut hasher = Sha256::new();
        update_field(&mut hasher, CHALLENGE_CORPUS_DOMAIN_V1);
        update_field(&mut hasher, corpus_artifact_digest.as_bytes());
        update_field(&mut hasher, config_artifact_digest.as_bytes());
        for case in &cases {
            update_field(&mut hasher, case.artifact_digest.as_bytes());
        }
        update_field(&mut hasher, needs_more.artifact_digest.as_bytes());
        for value in [
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            citation_count,
            event_count,
            decoded_event_byte_count,
            reduction_micros,
        ] {
            update_u64(&mut hasher, value);
        }
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            corpus_artifact_digest,
            config_artifact_digest,
            cases,
            needs_more,
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            citation_count,
            event_count,
            decoded_event_byte_count,
            reduction_micros,
        })
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn corpus_artifact_digest(&self) -> ArtifactDigest {
        self.corpus_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(&self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub fn cases(&self) -> &[CompactAgentViewChallengeObservationV1] {
        &self.cases
    }

    #[must_use]
    pub const fn needs_more(&self) -> CompactAgentViewNeedsMoreObservationV1 {
        self.needs_more
    }

    #[must_use]
    pub const fn canonical_byte_count(&self) -> u64 {
        self.canonical_byte_count
    }

    #[must_use]
    pub const fn compact_byte_count(&self) -> u64 {
        self.compact_byte_count
    }

    #[must_use]
    pub const fn saved_byte_count(&self) -> u64 {
        self.saved_byte_count
    }

    #[must_use]
    pub const fn citation_count(&self) -> u64 {
        self.citation_count
    }

    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn decoded_event_byte_count(&self) -> u64 {
        self.decoded_event_byte_count
    }

    #[must_use]
    pub const fn reduction_micros(&self) -> u64 {
        self.reduction_micros
    }

    #[must_use]
    pub const fn contains_hidden_labels(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewChallengeCorpusReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewChallengeCorpusReceiptV1")
            .field("receipt_identity_present", &true)
            .field("corpus_binding_present", &true)
            .field("config_binding_present", &true)
            .field("rendered_case_count", &self.cases.len())
            .field("needs_more_case_count", &1_u64)
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field("citation_count", &self.citation_count)
            .field("event_count", &self.event_count)
            .field("decoded_event_byte_count", &self.decoded_event_byte_count)
            .field("reduction_micros", &self.reduction_micros)
            .field("contains_hidden_labels", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompactAgentViewMeasuredArmV1 {
    Canonical,
    Compact,
}

impl CompactAgentViewMeasuredArmV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Canonical => "canonical_log_brief",
            Self::Compact => "compact_agent_view",
        }
    }
}

impl fmt::Debug for CompactAgentViewMeasuredArmV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewMeasuredArmV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewReaderArmMeasurementV1 {
    artifact_digest: ArtifactDigest,
    arm: CompactAgentViewMeasuredArmV1,
    receipt_artifact_digest: ArtifactDigest,
    public_input_artifact_digest: ArtifactDigest,
    method_binding_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
    reader_configuration_artifact_digest: ArtifactDigest,
    caps_artifact_digest: ArtifactDigest,
    prompt_artifact_digest: ArtifactDigest,
    answer_artifact_digest: ArtifactDigest,
    observer_measurement_mechanism_artifact_digest: ArtifactDigest,
    observer_raw_report_artifact_digest: ArtifactDigest,
    prompt_canonical_token_count: u64,
    answer_canonical_token_count: u64,
    wall_time_nanos: u64,
    direct_process_peak_rss_bytes: u64,
    observer_raw_report_byte_count: u64,
}

impl CompactAgentViewReaderArmMeasurementV1 {
    fn try_from_receipt(
        arm: CompactAgentViewMeasuredArmV1,
        receipt: &FrozenReaderSingleShotReceiptV1,
        caps_artifact_digest: ArtifactDigest,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        if receipt.wall_time_nanos() == 0
            || receipt.peak_rss_bytes() == 0
            || receipt.observer_raw_report_byte_count() == 0
            || receipt.independently_attested()
            || !receipt.directly_timed_process_only()
            || receipt.child_tree_peak_rss_claimed()
            || receipt.live_peak_rss_enforcement_claimed()
            || receipt.contains_hidden_labels()
        {
            return Err(CompactAgentViewAdmissionErrorV1::MeasurementBindingMismatch);
        }
        let mut hasher = Sha256::new();
        update_field(&mut hasher, READER_ARM_MEASUREMENT_DOMAIN_V1);
        update_field(&mut hasher, arm.code().as_bytes());
        update_field(&mut hasher, receipt.artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            receipt.public_input().artifact_digest().as_bytes(),
        );
        update_field(
            &mut hasher,
            receipt
                .public_input()
                .method_artifact()
                .binding_artifact_digest()
                .as_bytes(),
        );
        update_field(
            &mut hasher,
            receipt
                .target()
                .program()
                .executable_build_artifact_digest()
                .as_bytes(),
        );
        update_field(
            &mut hasher,
            receipt.target().configuration_artifact_digest().as_bytes(),
        );
        update_field(&mut hasher, caps_artifact_digest.as_bytes());
        update_field(&mut hasher, receipt.prompt().artifact_digest().as_bytes());
        update_field(&mut hasher, receipt.answer_artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            receipt
                .observer_measurement_mechanism_artifact_digest()
                .as_bytes(),
        );
        update_field(
            &mut hasher,
            receipt.observer_raw_report_artifact_digest().as_bytes(),
        );
        for value in [
            receipt.prompt().canonical_token_count(),
            receipt.answer_canonical_token_count(),
            receipt.wall_time_nanos(),
            receipt.peak_rss_bytes(),
            receipt.observer_raw_report_byte_count(),
        ] {
            update_u64(&mut hasher, value);
        }
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            arm,
            receipt_artifact_digest: receipt.artifact_digest(),
            public_input_artifact_digest: receipt.public_input().artifact_digest(),
            method_binding_artifact_digest: receipt
                .public_input()
                .method_artifact()
                .binding_artifact_digest(),
            executable_build_artifact_digest: receipt
                .target()
                .program()
                .executable_build_artifact_digest(),
            reader_configuration_artifact_digest: receipt.target().configuration_artifact_digest(),
            caps_artifact_digest,
            prompt_artifact_digest: receipt.prompt().artifact_digest(),
            answer_artifact_digest: receipt.answer_artifact_digest(),
            observer_measurement_mechanism_artifact_digest: receipt
                .observer_measurement_mechanism_artifact_digest(),
            observer_raw_report_artifact_digest: receipt.observer_raw_report_artifact_digest(),
            prompt_canonical_token_count: receipt.prompt().canonical_token_count(),
            answer_canonical_token_count: receipt.answer_canonical_token_count(),
            wall_time_nanos: receipt.wall_time_nanos(),
            direct_process_peak_rss_bytes: receipt.peak_rss_bytes(),
            observer_raw_report_byte_count: receipt.observer_raw_report_byte_count(),
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn arm(self) -> CompactAgentViewMeasuredArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn receipt_artifact_digest(self) -> ArtifactDigest {
        self.receipt_artifact_digest
    }

    #[must_use]
    pub const fn public_input_artifact_digest(self) -> ArtifactDigest {
        self.public_input_artifact_digest
    }

    #[must_use]
    pub const fn method_binding_artifact_digest(self) -> ArtifactDigest {
        self.method_binding_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub const fn reader_configuration_artifact_digest(self) -> ArtifactDigest {
        self.reader_configuration_artifact_digest
    }

    #[must_use]
    pub const fn caps_artifact_digest(self) -> ArtifactDigest {
        self.caps_artifact_digest
    }

    #[must_use]
    pub const fn prompt_artifact_digest(self) -> ArtifactDigest {
        self.prompt_artifact_digest
    }

    #[must_use]
    pub const fn answer_artifact_digest(self) -> ArtifactDigest {
        self.answer_artifact_digest
    }

    #[must_use]
    pub const fn observer_measurement_mechanism_artifact_digest(self) -> ArtifactDigest {
        self.observer_measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub const fn observer_raw_report_artifact_digest(self) -> ArtifactDigest {
        self.observer_raw_report_artifact_digest
    }

    #[must_use]
    pub const fn prompt_canonical_token_count(self) -> u64 {
        self.prompt_canonical_token_count
    }

    #[must_use]
    pub const fn answer_canonical_token_count(self) -> u64 {
        self.answer_canonical_token_count
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn direct_process_peak_rss_bytes(self) -> u64 {
        self.direct_process_peak_rss_bytes
    }

    #[must_use]
    pub const fn observer_raw_report_byte_count(self) -> u64 {
        self.observer_raw_report_byte_count
    }
}

impl fmt::Debug for CompactAgentViewReaderArmMeasurementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewReaderArmMeasurementV1")
            .field("arm", &self.arm)
            .field("receipt_binding_present", &true)
            .field("public_input_binding_present", &true)
            .field("method_binding_present", &true)
            .field("executable_build_binding_present", &true)
            .field("reader_configuration_binding_present", &true)
            .field("caps_binding_present", &true)
            .field("prompt_binding_present", &true)
            .field("answer_binding_present", &true)
            .field("observer_mechanism_binding_present", &true)
            .field("observer_raw_report_binding_present", &true)
            .field(
                "prompt_canonical_token_count",
                &self.prompt_canonical_token_count,
            )
            .field(
                "answer_canonical_token_count",
                &self.answer_canonical_token_count,
            )
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field(
                "direct_process_peak_rss_bytes",
                &self.direct_process_peak_rss_bytes,
            )
            .field(
                "observer_raw_report_byte_count",
                &self.observer_raw_report_byte_count,
            )
            .field("independently_attested", &false)
            .field("child_tree_peak_rss_claimed", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewReaderMeasurementPairV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    view_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    preservation_artifact_digest: ArtifactDigest,
    observer_measurement_mechanism_artifact_digest: ArtifactDigest,
    reader_configuration_artifact_digest: ArtifactDigest,
    caps_artifact_digest: ArtifactDigest,
    canonical: CompactAgentViewReaderArmMeasurementV1,
    compact: CompactAgentViewReaderArmMeasurementV1,
}

impl CompactAgentViewReaderMeasurementPairV1 {
    pub fn try_new(
        preservation: &CompactAgentViewReaderPreservationReceiptV1,
        view: &CompactAgentViewV1,
        canonical_receipt: &FrozenReaderSingleShotReceiptV1,
        compact_receipt: &FrozenReaderSingleShotReceiptV1,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        let regenerated = compare_compact_agent_view_reader_receipts_v1(
            canonical_receipt,
            compact_receipt,
            view,
        )?;
        if &regenerated != preservation
            || canonical_receipt.observer_measurement_mechanism_artifact_digest()
                != compact_receipt.observer_measurement_mechanism_artifact_digest()
            || canonical_receipt
                .target()
                .program()
                .executable_build_artifact_digest()
                != compact_receipt
                    .target()
                    .program()
                    .executable_build_artifact_digest()
        {
            return Err(CompactAgentViewAdmissionErrorV1::MeasurementBindingMismatch);
        }
        let caps_artifact_digest = derive_caps_artifact_digest(canonical_receipt.caps());
        if caps_artifact_digest != derive_caps_artifact_digest(compact_receipt.caps()) {
            return Err(CompactAgentViewAdmissionErrorV1::MeasurementBindingMismatch);
        }
        let canonical = CompactAgentViewReaderArmMeasurementV1::try_from_receipt(
            CompactAgentViewMeasuredArmV1::Canonical,
            canonical_receipt,
            caps_artifact_digest,
        )?;
        let compact = CompactAgentViewReaderArmMeasurementV1::try_from_receipt(
            CompactAgentViewMeasuredArmV1::Compact,
            compact_receipt,
            caps_artifact_digest,
        )?;
        let public_case_artifact_digest = preservation.public_case_artifact_digest();
        let observer_measurement_mechanism_artifact_digest =
            canonical.observer_measurement_mechanism_artifact_digest;
        let reader_configuration_artifact_digest = canonical.reader_configuration_artifact_digest;
        if observer_measurement_mechanism_artifact_digest
            != compact.observer_measurement_mechanism_artifact_digest
            || reader_configuration_artifact_digest != compact.reader_configuration_artifact_digest
            || canonical.answer_artifact_digest != compact.answer_artifact_digest
        {
            return Err(CompactAgentViewAdmissionErrorV1::MeasurementBindingMismatch);
        }
        let mut hasher = Sha256::new();
        update_field(&mut hasher, READER_PAIR_MEASUREMENT_DOMAIN_V1);
        update_field(&mut hasher, public_case_artifact_digest.as_bytes());
        update_field(&mut hasher, view.artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            view.audit().config().artifact_digest().as_bytes(),
        );
        update_field(&mut hasher, preservation.artifact_digest().as_bytes());
        update_field(
            &mut hasher,
            observer_measurement_mechanism_artifact_digest.as_bytes(),
        );
        update_field(&mut hasher, reader_configuration_artifact_digest.as_bytes());
        update_field(&mut hasher, caps_artifact_digest.as_bytes());
        update_field(&mut hasher, canonical.artifact_digest.as_bytes());
        update_field(&mut hasher, compact.artifact_digest.as_bytes());
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            public_case_artifact_digest,
            view_artifact_digest: view.artifact_digest(),
            config_artifact_digest: view.audit().config().artifact_digest(),
            preservation_artifact_digest: preservation.artifact_digest(),
            observer_measurement_mechanism_artifact_digest,
            reader_configuration_artifact_digest,
            caps_artifact_digest,
            canonical,
            compact,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn view_artifact_digest(self) -> ArtifactDigest {
        self.view_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn preservation_artifact_digest(self) -> ArtifactDigest {
        self.preservation_artifact_digest
    }

    #[must_use]
    pub const fn observer_measurement_mechanism_artifact_digest(self) -> ArtifactDigest {
        self.observer_measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub const fn reader_configuration_artifact_digest(self) -> ArtifactDigest {
        self.reader_configuration_artifact_digest
    }

    #[must_use]
    pub const fn caps_artifact_digest(self) -> ArtifactDigest {
        self.caps_artifact_digest
    }

    #[must_use]
    pub const fn canonical(self) -> CompactAgentViewReaderArmMeasurementV1 {
        self.canonical
    }

    #[must_use]
    pub const fn compact(self) -> CompactAgentViewReaderArmMeasurementV1 {
        self.compact
    }

    #[must_use]
    pub const fn performance_ordering_eligible(self) -> bool {
        false
    }

    #[must_use]
    pub const fn measurements_independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewReaderMeasurementPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewReaderMeasurementPairV1")
            .field("pair_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("view_binding_present", &true)
            .field("config_binding_present", &true)
            .field("preservation_binding_present", &true)
            .field("observer_mechanism_binding_present", &true)
            .field("reader_configuration_binding_present", &true)
            .field("caps_binding_present", &true)
            .field("canonical", &self.canonical)
            .field("compact", &self.compact)
            .field("performance_ordering_eligible", &false)
            .field("measurements_independently_attested", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompactAgentViewProductionAdmissionStatusV1 {
    EligibleForBoundedProductionAdmissionReview,
}

impl CompactAgentViewProductionAdmissionStatusV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        "eligible_for_bounded_production_admission_review_not_admitted"
    }
}

impl fmt::Debug for CompactAgentViewProductionAdmissionStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewProductionAdmissionStatusV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewProductionAdmissionEvidenceV1 {
    artifact_digest: ArtifactDigest,
    base_corpus_artifact_digest: ArtifactDigest,
    challenge_corpus_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    observer_measurement_mechanism_artifact_digest: ArtifactDigest,
    production_candidate_parities: Vec<CompactAgentViewProductionCandidateParityV1>,
    measurement_pairs: Vec<CompactAgentViewReaderMeasurementPairV1>,
    total_expected_case_count: u64,
    total_rendered_case_count: u64,
    total_needs_more_case_count: u64,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    canonical_observed_wall_time_nanos: u64,
    compact_observed_wall_time_nanos: u64,
    maximum_canonical_direct_process_peak_rss_bytes: u64,
    maximum_compact_direct_process_peak_rss_bytes: u64,
    status: CompactAgentViewProductionAdmissionStatusV1,
}

impl CompactAgentViewProductionAdmissionEvidenceV1 {
    pub fn try_new(
        base_corpus: &CompactAgentViewCorpusReductionReceiptV1,
        challenge_corpus: &CompactAgentViewChallengeCorpusReceiptV1,
        mut production_candidate_parities: Vec<CompactAgentViewProductionCandidateParityV1>,
        mut measurement_pairs: Vec<CompactAgentViewReaderMeasurementPairV1>,
    ) -> Result<Self, CompactAgentViewAdmissionErrorV1> {
        if base_corpus.expected_case_count() < 6
            || base_corpus.needs_more_case_count() == 0
            || base_corpus.config_artifact_digest() != challenge_corpus.config_artifact_digest()
            || measurement_pairs.is_empty()
            || measurement_pairs.len() > MAX_COMPACT_AGENT_VIEW_MEASURED_READER_PAIRS_V1
        {
            return Err(CompactAgentViewAdmissionErrorV1::AdmissionEvidenceIncomplete);
        }
        measurement_pairs.sort_unstable_by_key(|pair| pair.public_case_artifact_digest);
        production_candidate_parities.sort_unstable_by_key(|parity| {
            (
                parity.public_case_artifact_digest,
                parity.view_artifact_digest,
            )
        });
        let config_artifact_digest = base_corpus.config_artifact_digest();
        let observer_measurement_mechanism_artifact_digest =
            measurement_pairs[0].observer_measurement_mechanism_artifact_digest;
        let mut seen_pair_cases = BTreeSet::new();
        let challenge_views = challenge_corpus
            .cases()
            .iter()
            .map(|case| (case.public_case_artifact_digest, case.view_artifact_digest))
            .collect::<BTreeSet<_>>();
        let base_views = base_corpus
            .cases()
            .iter()
            .map(|case| {
                (
                    case.public_case_artifact_digest(),
                    case.view_artifact_digest(),
                )
            })
            .collect::<BTreeSet<_>>();
        let expected_parity_views = base_views
            .union(&challenge_views)
            .copied()
            .collect::<BTreeSet<_>>();
        let observed_parity_views = production_candidate_parities
            .iter()
            .map(|parity| {
                (
                    parity.public_case_artifact_digest,
                    parity.view_artifact_digest,
                )
            })
            .collect::<BTreeSet<_>>();
        if production_candidate_parities.len() != expected_parity_views.len()
            || observed_parity_views != expected_parity_views
            || production_candidate_parities
                .iter()
                .any(|parity| !parity.exact_text_alias_range_and_count_parity())
        {
            return Err(CompactAgentViewAdmissionErrorV1::AdmissionEvidenceIncomplete);
        }
        let mut canonical_observed_wall_time_nanos = 0_u64;
        let mut compact_observed_wall_time_nanos = 0_u64;
        let mut maximum_canonical_direct_process_peak_rss_bytes = 0_u64;
        let mut maximum_compact_direct_process_peak_rss_bytes = 0_u64;
        for pair in &measurement_pairs {
            if !seen_pair_cases.insert(pair.public_case_artifact_digest)
                || pair.config_artifact_digest != config_artifact_digest
                || pair.observer_measurement_mechanism_artifact_digest
                    != observer_measurement_mechanism_artifact_digest
                || !challenge_views
                    .contains(&(pair.public_case_artifact_digest, pair.view_artifact_digest))
                || pair.performance_ordering_eligible()
                || pair.measurements_independently_attested()
            {
                return Err(CompactAgentViewAdmissionErrorV1::AdmissionEvidenceIncomplete);
            }
            canonical_observed_wall_time_nanos = checked_add(
                canonical_observed_wall_time_nanos,
                pair.canonical.wall_time_nanos,
            )?;
            compact_observed_wall_time_nanos = checked_add(
                compact_observed_wall_time_nanos,
                pair.compact.wall_time_nanos,
            )?;
            maximum_canonical_direct_process_peak_rss_bytes =
                maximum_canonical_direct_process_peak_rss_bytes
                    .max(pair.canonical.direct_process_peak_rss_bytes);
            maximum_compact_direct_process_peak_rss_bytes =
                maximum_compact_direct_process_peak_rss_bytes
                    .max(pair.compact.direct_process_peak_rss_bytes);
        }
        let total_expected_case_count = checked_add(
            base_corpus.expected_case_count(),
            checked_add(
                COMPACT_AGENT_VIEW_CHALLENGE_RENDERED_CASE_COUNT_V1,
                COMPACT_AGENT_VIEW_CHALLENGE_NEEDS_MORE_CASE_COUNT_V1,
            )?,
        )?;
        let total_rendered_case_count = checked_add(
            base_corpus.rendered_case_count(),
            COMPACT_AGENT_VIEW_CHALLENGE_RENDERED_CASE_COUNT_V1,
        )?;
        let total_needs_more_case_count = checked_add(
            base_corpus.needs_more_case_count(),
            COMPACT_AGENT_VIEW_CHALLENGE_NEEDS_MORE_CASE_COUNT_V1,
        )?;
        let canonical_byte_count = checked_add(
            base_corpus.canonical_byte_count(),
            challenge_corpus.canonical_byte_count(),
        )?;
        let compact_byte_count = checked_add(
            base_corpus.compact_byte_count(),
            challenge_corpus.compact_byte_count(),
        )?;
        let saved_byte_count = checked_add(
            base_corpus.saved_byte_count(),
            challenge_corpus.saved_byte_count(),
        )?;
        if compact_byte_count.checked_add(saved_byte_count) != Some(canonical_byte_count) {
            return Err(CompactAgentViewAdmissionErrorV1::AdmissionEvidenceIncomplete);
        }
        let status =
            CompactAgentViewProductionAdmissionStatusV1::EligibleForBoundedProductionAdmissionReview;
        let mut hasher = Sha256::new();
        update_field(&mut hasher, ADMISSION_EVIDENCE_DOMAIN_V1);
        update_field(&mut hasher, base_corpus.artifact_digest().as_bytes());
        update_field(&mut hasher, challenge_corpus.artifact_digest().as_bytes());
        update_field(&mut hasher, config_artifact_digest.as_bytes());
        update_field(
            &mut hasher,
            observer_measurement_mechanism_artifact_digest.as_bytes(),
        );
        for parity in &production_candidate_parities {
            update_field(&mut hasher, parity.artifact_digest.as_bytes());
        }
        for pair in &measurement_pairs {
            update_field(&mut hasher, pair.artifact_digest.as_bytes());
        }
        for value in [
            total_expected_case_count,
            total_rendered_case_count,
            total_needs_more_case_count,
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            canonical_observed_wall_time_nanos,
            compact_observed_wall_time_nanos,
            maximum_canonical_direct_process_peak_rss_bytes,
            maximum_compact_direct_process_peak_rss_bytes,
        ] {
            update_u64(&mut hasher, value);
        }
        update_field(&mut hasher, status.code().as_bytes());
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            base_corpus_artifact_digest: base_corpus.artifact_digest(),
            challenge_corpus_artifact_digest: challenge_corpus.artifact_digest(),
            config_artifact_digest,
            observer_measurement_mechanism_artifact_digest,
            production_candidate_parities,
            measurement_pairs,
            total_expected_case_count,
            total_rendered_case_count,
            total_needs_more_case_count,
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            canonical_observed_wall_time_nanos,
            compact_observed_wall_time_nanos,
            maximum_canonical_direct_process_peak_rss_bytes,
            maximum_compact_direct_process_peak_rss_bytes,
            status,
        })
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn base_corpus_artifact_digest(&self) -> ArtifactDigest {
        self.base_corpus_artifact_digest
    }

    #[must_use]
    pub const fn challenge_corpus_artifact_digest(&self) -> ArtifactDigest {
        self.challenge_corpus_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(&self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn observer_measurement_mechanism_artifact_digest(&self) -> ArtifactDigest {
        self.observer_measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub fn measurement_pairs(&self) -> &[CompactAgentViewReaderMeasurementPairV1] {
        &self.measurement_pairs
    }

    #[must_use]
    pub fn production_candidate_parities(&self) -> &[CompactAgentViewProductionCandidateParityV1] {
        &self.production_candidate_parities
    }

    #[must_use]
    pub const fn total_expected_case_count(&self) -> u64 {
        self.total_expected_case_count
    }

    #[must_use]
    pub const fn total_rendered_case_count(&self) -> u64 {
        self.total_rendered_case_count
    }

    #[must_use]
    pub const fn total_needs_more_case_count(&self) -> u64 {
        self.total_needs_more_case_count
    }

    #[must_use]
    pub const fn canonical_byte_count(&self) -> u64 {
        self.canonical_byte_count
    }

    #[must_use]
    pub const fn compact_byte_count(&self) -> u64 {
        self.compact_byte_count
    }

    #[must_use]
    pub const fn saved_byte_count(&self) -> u64 {
        self.saved_byte_count
    }

    #[must_use]
    pub const fn canonical_observed_wall_time_nanos(&self) -> u64 {
        self.canonical_observed_wall_time_nanos
    }

    #[must_use]
    pub const fn compact_observed_wall_time_nanos(&self) -> u64 {
        self.compact_observed_wall_time_nanos
    }

    #[must_use]
    pub const fn maximum_canonical_direct_process_peak_rss_bytes(&self) -> u64 {
        self.maximum_canonical_direct_process_peak_rss_bytes
    }

    #[must_use]
    pub const fn maximum_compact_direct_process_peak_rss_bytes(&self) -> u64 {
        self.maximum_compact_direct_process_peak_rss_bytes
    }

    #[must_use]
    pub const fn status(&self) -> CompactAgentViewProductionAdmissionStatusV1 {
        self.status
    }

    #[must_use]
    pub const fn production_behavior_changed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn production_admitted(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn hosted_reader_used(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn scalar_performance_or_quality_winner_available(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn measurements_independently_attested(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn direct_process_peak_rss_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn contains_hidden_labels(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewProductionAdmissionEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewProductionAdmissionEvidenceV1")
            .field("receipt_identity_present", &true)
            .field("base_corpus_binding_present", &true)
            .field("challenge_corpus_binding_present", &true)
            .field("config_binding_present", &true)
            .field("observer_mechanism_binding_present", &true)
            .field(
                "production_candidate_parity_count",
                &self.production_candidate_parities.len(),
            )
            .field("measurement_pair_count", &self.measurement_pairs.len())
            .field("total_expected_case_count", &self.total_expected_case_count)
            .field("total_rendered_case_count", &self.total_rendered_case_count)
            .field(
                "total_needs_more_case_count",
                &self.total_needs_more_case_count,
            )
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field(
                "canonical_observed_wall_time_nanos",
                &self.canonical_observed_wall_time_nanos,
            )
            .field(
                "compact_observed_wall_time_nanos",
                &self.compact_observed_wall_time_nanos,
            )
            .field(
                "maximum_canonical_direct_process_peak_rss_bytes",
                &self.maximum_canonical_direct_process_peak_rss_bytes,
            )
            .field(
                "maximum_compact_direct_process_peak_rss_bytes",
                &self.maximum_compact_direct_process_peak_rss_bytes,
            )
            .field("status", &self.status)
            .field("production_behavior_changed", &false)
            .field("production_admitted", &false)
            .field("hosted_reader_used", &false)
            .field("scalar_performance_or_quality_winner_available", &false)
            .field("measurements_independently_attested", &false)
            .field("direct_process_peak_rss_only", &true)
            .field("contains_hidden_labels", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompactAgentViewAdmissionErrorV1 {
    InvalidChallengeObservation,
    ChallengeClassUnproven,
    ProductionCandidateParityMismatch,
    MissingChallengeCoverage,
    MeasurementBindingMismatch,
    AdmissionEvidenceIncomplete,
    ArithmeticOverflow,
    Compact(CompactAgentViewErrorV1),
}

impl CompactAgentViewAdmissionErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidChallengeObservation => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_INVALID_CHALLENGE_OBSERVATION"
            }
            Self::ChallengeClassUnproven => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_CHALLENGE_CLASS_UNPROVEN"
            }
            Self::ProductionCandidateParityMismatch => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_PRODUCTION_CANDIDATE_PARITY_MISMATCH"
            }
            Self::MissingChallengeCoverage => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_MISSING_CHALLENGE_COVERAGE"
            }
            Self::MeasurementBindingMismatch => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_MEASUREMENT_BINDING_MISMATCH"
            }
            Self::AdmissionEvidenceIncomplete => {
                "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_EVIDENCE_INCOMPLETE"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_ARITHMETIC_OVERFLOW",
            Self::Compact(_) => "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_COMPACT_VIEW_FAILURE",
        }
    }
}

impl fmt::Debug for CompactAgentViewAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewAdmissionErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CompactAgentViewAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CompactAgentViewAdmissionErrorV1 {}

impl From<CompactAgentViewErrorV1> for CompactAgentViewAdmissionErrorV1 {
    fn from(error: CompactAgentViewErrorV1) -> Self {
        Self::Compact(error)
    }
}

fn derive_caps_artifact_digest(caps: ReaderResourceCapsV1) -> ArtifactDigest {
    let limits = caps.harness_limits();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, CAPS_DOMAIN_V1);
    for value in [
        limits.stdin_bytes(),
        limits.stdout_bytes(),
        limits.stderr_bytes(),
        limits.wall_nanos(),
        caps.prompt_token_cap(),
        caps.answer_token_cap(),
        caps.peak_rss_byte_cap(),
        caps.reader_call_cap(),
    ] {
        update_u64(&mut hasher, value);
    }
    update_field(&mut hasher, caps.tokenizer_artifact_digest().as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

fn reduction_micros(saved: u64, canonical: u64) -> Result<u64, CompactAgentViewAdmissionErrorV1> {
    if saved == 0 || canonical == 0 {
        return Err(CompactAgentViewAdmissionErrorV1::MissingChallengeCoverage);
    }
    u64::try_from(
        u128::from(saved)
            .checked_mul(1_000_000)
            .ok_or(CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)?
            / u128::from(canonical),
    )
    .map_err(|_| CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn checked_u64(value: usize) -> Result<u64, CompactAgentViewAdmissionErrorV1> {
    u64::try_from(value).map_err(|_| CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactAgentViewAdmissionErrorV1> {
    left.checked_add(right)
        .ok_or(CompactAgentViewAdmissionErrorV1::ArithmeticOverflow)
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded V1 identity field fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
