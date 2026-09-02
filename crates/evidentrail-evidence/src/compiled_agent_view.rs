//! A compact, typed candidate view over an already certified compiled brief.
//!
//! This module deliberately does not change the canonical renderer or the
//! product's default output. It gives evaluation and controlled product
//! admission a production-owned representation to test. The candidate is
//! derived only from the typed owned brief; it never parses, summarizes, or
//! semantically rewrites canonical text.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EvidenceReferenceV1, EvidenceTargetRef, ExactnessBasis, FetchCompleteness,
};
use evidentrail_schema::{ArtifactDigest, PresentationCounts, SourceStream};
use sha2::{Digest, Sha256};

use crate::{
    CompiledCoverageV1, OwnedRenderedCompiledBriefV1, compiled_renderer_digest_v1,
    escape_evidence_bytes, unescape_evidence_bytes,
};

/// Semantic contract version of the controlled-admission candidate view.
pub const COMPILED_AGENT_VIEW_CANDIDATE_CONTRACT_VERSION_V1: u16 = 1;
/// Renderer grammar version of the controlled-admission candidate view.
pub const COMPILED_AGENT_VIEW_CANDIDATE_RENDERER_CONTRACT_VERSION_V1: u16 = 1;

const RENDERER_MANIFEST_V1: &[u8] = b"evidentrail/evidence/compiled-agent-view-candidate-renderer/v1\0source=typed-owned-compiled-log-brief-only\0canonical-text-parsing=false\0status=untrusted-data,acquisition,selection\0scope=acknowledged,persisted\0aliases=exact-result-scoped-E-ordinal\0roles=canonical-closed-codes\0events=one-line-basis-stream-ascii-byte-escape\0coverage=shown,pattern,retained,source-exact,post-policy,policy-omitted\0selector-internals=model-hidden-receipt-bound\0newlines=lf\0default-output-unchanged=true\0admission=candidate-only";
const STRUCTURED_INPUT_DOMAIN_V1: &[u8] =
    b"evidentrail/evidence/compiled-agent-view-candidate-structured-input/v1";
const AUDIT_DOMAIN_V1: &[u8] = b"evidentrail/evidence/compiled-agent-view-candidate-audit/v1";

/// Frozen identity of the candidate renderer grammar.
#[must_use]
pub fn compiled_agent_view_candidate_renderer_digest_v1() -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(RENDERER_MANIFEST_V1).into())
}

/// One exact result-scoped alias and its byte range in the compact view.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledAgentViewCandidateCitationV1 {
    alias: u32,
    reference: EvidenceReferenceV1,
    marker_start: u64,
    marker_end: u64,
}

impl CompiledAgentViewCandidateCitationV1 {
    #[must_use]
    pub const fn alias(&self) -> u32 {
        self.alias
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub const fn marker_range(&self) -> (u64, u64) {
        (self.marker_start, self.marker_end)
    }
}

impl fmt::Debug for CompiledAgentViewCandidateCitationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAgentViewCandidateCitationV1")
            .field("alias", &self.alias)
            .field("target_count", &self.reference.targets().len())
            .field("marker_byte_count", &(self.marker_end - self.marker_start))
            .field("reference_identity_redacted", &true)
            .finish()
    }
}

/// Reversible byte ranges for one exact event field in the candidate output.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledAgentViewCandidateEventProofV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    field_start: u64,
    field_end: u64,
    encoded_data_start: u64,
    encoded_data_end: u64,
    authorized_byte_count: u64,
}

impl CompiledAgentViewCandidateEventProofV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }

    #[must_use]
    pub const fn field_range(&self) -> (u64, u64) {
        (self.field_start, self.field_end)
    }

    #[must_use]
    pub const fn encoded_data_range(&self) -> (u64, u64) {
        (self.encoded_data_start, self.encoded_data_end)
    }

    #[must_use]
    pub const fn authorized_byte_count(&self) -> u64 {
        self.authorized_byte_count
    }
}

impl fmt::Debug for CompiledAgentViewCandidateEventProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAgentViewCandidateEventProofV1")
            .field("exactness_code", &self.exactness_basis.code())
            .field("stream_code", &self.stream.code())
            .field("authorized_byte_count", &self.authorized_byte_count)
            .field("field_byte_count", &(self.field_end - self.field_start))
            .field(
                "encoded_data_byte_count",
                &(self.encoded_data_end - self.encoded_data_start),
            )
            .field("event_identity_redacted", &true)
            .finish()
    }
}

/// Contentless receipt binding the typed source, compact bytes, citations,
/// exact event fields, and model-hidden selector facts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompiledAgentViewCandidateAuditV1 {
    artifact_digest: ArtifactDigest,
    source_renderer_digest: ArtifactDigest,
    source_render_artifact_digest: ArtifactDigest,
    structured_input_artifact_digest: ArtifactDigest,
    output_artifact_digest: ArtifactDigest,
    candidate_renderer_digest: ArtifactDigest,
    canonical_byte_count: u64,
    output_byte_count: u64,
    saved_byte_count: u64,
    packet_count: u64,
    event_count: u64,
}

impl CompiledAgentViewCandidateAuditV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn source_renderer_digest(self) -> ArtifactDigest {
        self.source_renderer_digest
    }

    #[must_use]
    pub const fn source_render_artifact_digest(self) -> ArtifactDigest {
        self.source_render_artifact_digest
    }

    #[must_use]
    pub const fn structured_input_artifact_digest(self) -> ArtifactDigest {
        self.structured_input_artifact_digest
    }

    #[must_use]
    pub const fn output_artifact_digest(self) -> ArtifactDigest {
        self.output_artifact_digest
    }

    #[must_use]
    pub const fn candidate_renderer_digest(self) -> ArtifactDigest {
        self.candidate_renderer_digest
    }

    #[must_use]
    pub const fn canonical_byte_count(self) -> u64 {
        self.canonical_byte_count
    }

    #[must_use]
    pub const fn output_byte_count(self) -> u64 {
        self.output_byte_count
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
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn selector_internals_model_visible(self) -> bool {
        false
    }

    #[must_use]
    pub const fn production_default_changed(self) -> bool {
        false
    }
}

impl fmt::Debug for CompiledAgentViewCandidateAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAgentViewCandidateAuditV1")
            .field("identity_present", &true)
            .field("source_render_binding_present", &true)
            .field("structured_input_binding_present", &true)
            .field("output_binding_present", &true)
            .field("renderer_identity_present", &true)
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("output_byte_count", &self.output_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field("packet_count", &self.packet_count)
            .field("event_count", &self.event_count)
            .field("selector_internals_model_visible", &false)
            .field("production_default_changed", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

/// Compact candidate text plus exact aliases and reversible event-field proof.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledAgentViewCandidateV1 {
    text: String,
    citations: Vec<CompiledAgentViewCandidateCitationV1>,
    event_proofs: Vec<CompiledAgentViewCandidateEventProofV1>,
    audit: CompiledAgentViewCandidateAuditV1,
}

impl CompiledAgentViewCandidateV1 {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn citations(&self) -> &[CompiledAgentViewCandidateCitationV1] {
        &self.citations
    }

    #[must_use]
    pub fn event_proofs(&self) -> &[CompiledAgentViewCandidateEventProofV1] {
        &self.event_proofs
    }

    #[must_use]
    pub const fn audit(&self) -> CompiledAgentViewCandidateAuditV1 {
        self.audit
    }

    #[must_use]
    pub const fn untrusted_data(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn byte_exact_event_content(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn canonical_text_parsed_or_postprocessed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn production_default_changed(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompiledAgentViewCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAgentViewCandidateV1")
            .field("byte_count", &self.text.len())
            .field("citation_count", &self.citations.len())
            .field("event_proof_count", &self.event_proofs.len())
            .field("audit", &self.audit)
            .field("untrusted_data", &true)
            .field("byte_exact_event_content", &true)
            .field("canonical_text_parsed_or_postprocessed", &false)
            .field("production_default_changed", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

/// Render a compact candidate from an already validated, owned compiled brief.
///
/// Success proves a strict byte reduction relative to the canonical render,
/// reversible event payload encoding, exact alias preservation, and a receipt
/// binding every typed source fact. It does not authorize changing the default
/// CLI/MCP representation.
pub fn render_compiled_agent_view_candidate_v1(
    rendered: &OwnedRenderedCompiledBriefV1,
) -> Result<CompiledAgentViewCandidateV1, CompiledAgentViewCandidateErrorV1> {
    let brief = rendered.brief();
    let cost = brief.cost();
    let canonical = rendered.text().as_bytes();
    let canonical_byte_count = checked_u64(canonical.len())?;
    if canonical.is_empty()
        || cost.renderer_digest() != compiled_renderer_digest_v1()
        || cost.total_rendered_bytes() != canonical_byte_count
        || cost.total_rendered_tokens() != canonical_byte_count
        || !cost.is_additive_bound_certified()
        || brief.status().selection().code() != "compiled"
        || !brief.untrusted_data()
        || brief.evidence().is_empty()
    {
        return Err(CompiledAgentViewCandidateErrorV1::StructuredInputMismatch);
    }

    let maximum = canonical
        .len()
        .checked_sub(1)
        .ok_or(CompiledAgentViewCandidateErrorV1::NotSmallerThanCanonical)?;
    let mut text = BoundedCandidateText::new(canonical.len(), maximum);
    text.push("EVIDENTRAIL_AGENT_VIEW_V1\nresult=")?;
    text.push(&brief.result_id().canonical_token())?;
    text.push("\nuntrusted_data=true\nacquisition=")?;
    render_acquisition(&mut text, brief.status().acquisition())?;
    text.push("\nselection=compiled\nscope acknowledged=")?;
    text.push_usize(brief.coverage().acknowledged_records())?;
    let presentation_counts = brief.coverage().presentation_counts();
    text.push(" persisted=")?;
    text.push_usize(presentation_counts.persisted())?;
    text.push("\nevidence\n")?;

    let mut citations = Vec::with_capacity(brief.evidence().len());
    let mut event_proofs = Vec::new();
    let mut seen_event_ids = BTreeSet::new();
    for (packet_index, packet) in brief.evidence().iter().enumerate() {
        if packet.ordinal() != packet_index || packet.events().is_empty() {
            return Err(CompiledAgentViewCandidateErrorV1::StructuredInputMismatch);
        }
        let alias = u32::try_from(
            packet_index
                .checked_add(1)
                .ok_or(CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)?,
        )
        .map_err(|_| CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)?;
        let marker_start = checked_u64(text.len())?;
        text.push("[E")?;
        text.push_u32(alias)?;
        text.push("]")?;
        let marker_end = checked_u64(text.len())?;
        text.push(" roles=")?;
        for (index, kind) in packet.facet_kinds().iter().enumerate() {
            if index != 0 {
                text.push(",")?;
            }
            text.push(kind.code())?;
        }
        text.push("\n")?;

        let packet_event_ids = packet
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<BTreeSet<_>>();
        let canonical_event_ids = packet
            .canonical_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let reference_event_ids = packet
            .reference()
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) => Ok(*event_id),
                EvidenceTargetRef::Block(_) => {
                    Err(CompiledAgentViewCandidateErrorV1::StructuredInputMismatch)
                }
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if packet_event_ids != canonical_event_ids
            || packet_event_ids != reference_event_ids
            || packet.reference().targets().len() != packet_event_ids.len()
            || packet_event_ids
                .iter()
                .any(|event_id| !seen_event_ids.insert(*event_id))
        {
            return Err(CompiledAgentViewCandidateErrorV1::StructuredInputMismatch);
        }

        for (event_index, event) in packet.events().iter().enumerate() {
            let field_start = checked_u64(text.len())?;
            text.push("event")?;
            text.push_usize(
                event_index
                    .checked_add(1)
                    .ok_or(CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)?,
            )?;
            text.push(" basis=")?;
            text.push(event.exactness_basis().code())?;
            text.push(" stream=")?;
            text.push(event.stream().code())?;
            text.push(" data=")?;
            let encoded_data_start = checked_u64(text.len())?;
            text.push(&escape_evidence_bytes(event.authorized_bytes()))?;
            let encoded_data_end = checked_u64(text.len())?;
            text.push("\n")?;
            let field_end = checked_u64(text.len())?;
            let encoded = text
                .as_str()
                .get(checked_usize(encoded_data_start)?..checked_usize(encoded_data_end)?)
                .ok_or(CompiledAgentViewCandidateErrorV1::ReversibleEncodingMismatch)?;
            if unescape_evidence_bytes(encoded)
                .map_err(|_| CompiledAgentViewCandidateErrorV1::ReversibleEncodingMismatch)?
                != event.authorized_bytes()
            {
                return Err(CompiledAgentViewCandidateErrorV1::ReversibleEncodingMismatch);
            }
            event_proofs.push(CompiledAgentViewCandidateEventProofV1 {
                event_id: event.event_id(),
                exactness_basis: event.exactness_basis(),
                stream: event.stream().clone(),
                field_start,
                field_end,
                encoded_data_start,
                encoded_data_end,
                authorized_byte_count: checked_u64(event.authorized_bytes().len())?,
            });
        }
        citations.push(CompiledAgentViewCandidateCitationV1 {
            alias,
            reference: packet.reference().clone(),
            marker_start,
            marker_end,
        });
    }

    if event_proofs
        .windows(2)
        .any(|pair| pair[0].field_end > pair[1].field_start)
    {
        return Err(CompiledAgentViewCandidateErrorV1::ReversibleEncodingMismatch);
    }
    render_coverage(&mut text, presentation_counts, brief.coverage())?;
    if !text.as_str().is_ascii() {
        return Err(CompiledAgentViewCandidateErrorV1::NonCanonicalOutput);
    }

    let output_byte_count = checked_u64(text.len())?;
    let saved_byte_count = canonical_byte_count
        .checked_sub(output_byte_count)
        .filter(|saved| *saved > 0)
        .ok_or(CompiledAgentViewCandidateErrorV1::NotSmallerThanCanonical)?;
    let source_render_artifact_digest = digest(canonical);
    let output_artifact_digest = digest(text.as_str().as_bytes());
    let candidate_renderer_digest = compiled_agent_view_candidate_renderer_digest_v1();
    let structured_input_artifact_digest = derive_structured_input_digest(rendered)?;
    let packet_count = checked_u64(citations.len())?;
    let event_count = checked_u64(event_proofs.len())?;
    let artifact_digest = derive_audit_digest(
        source_render_artifact_digest,
        structured_input_artifact_digest,
        output_artifact_digest,
        candidate_renderer_digest,
        canonical_byte_count,
        output_byte_count,
        saved_byte_count,
        &citations,
        &event_proofs,
    )?;
    let audit = CompiledAgentViewCandidateAuditV1 {
        artifact_digest,
        source_renderer_digest: compiled_renderer_digest_v1(),
        source_render_artifact_digest,
        structured_input_artifact_digest,
        output_artifact_digest,
        candidate_renderer_digest,
        canonical_byte_count,
        output_byte_count,
        saved_byte_count,
        packet_count,
        event_count,
    };
    Ok(CompiledAgentViewCandidateV1 {
        text: text.into_string(),
        citations,
        event_proofs,
        audit,
    })
}

/// Stable contentless failure from candidate validation or rendering.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompiledAgentViewCandidateErrorV1 {
    StructuredInputMismatch,
    OutputTooLarge,
    ReversibleEncodingMismatch,
    NonCanonicalOutput,
    NotSmallerThanCanonical,
    ArithmeticOverflow,
}

impl CompiledAgentViewCandidateErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StructuredInputMismatch => {
                "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_STRUCTURED_INPUT_MISMATCH"
            }
            Self::OutputTooLarge => "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_OUTPUT_TOO_LARGE",
            Self::ReversibleEncodingMismatch => {
                "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_REVERSIBLE_ENCODING_MISMATCH"
            }
            Self::NonCanonicalOutput => {
                "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_NONCANONICAL_OUTPUT"
            }
            Self::NotSmallerThanCanonical => {
                "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_NOT_SMALLER"
            }
            Self::ArithmeticOverflow => {
                "EVIDENTRAIL_EVIDENCE_AGENT_VIEW_CANDIDATE_ARITHMETIC_OVERFLOW"
            }
        }
    }
}

impl fmt::Debug for CompiledAgentViewCandidateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAgentViewCandidateErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CompiledAgentViewCandidateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CompiledAgentViewCandidateErrorV1 {}

struct BoundedCandidateText {
    value: String,
    maximum: usize,
}

impl BoundedCandidateText {
    fn new(capacity: usize, maximum: usize) -> Self {
        Self {
            value: String::with_capacity(capacity.min(maximum)),
            maximum,
        }
    }

    fn push(&mut self, value: &str) -> Result<(), CompiledAgentViewCandidateErrorV1> {
        let next = self
            .value
            .len()
            .checked_add(value.len())
            .ok_or(CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)?;
        if next > self.maximum {
            return Err(CompiledAgentViewCandidateErrorV1::OutputTooLarge);
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_usize(&mut self, value: usize) -> Result<(), CompiledAgentViewCandidateErrorV1> {
        self.push(&value.to_string())
    }

    fn push_u32(&mut self, value: u32) -> Result<(), CompiledAgentViewCandidateErrorV1> {
        self.push(&value.to_string())
    }

    fn len(&self) -> usize {
        self.value.len()
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn into_string(self) -> String {
        self.value
    }
}

fn render_acquisition(
    text: &mut BoundedCandidateText,
    acquisition: &FetchCompleteness,
) -> Result<(), CompiledAgentViewCandidateErrorV1> {
    match acquisition {
        FetchCompleteness::Complete { proof } => {
            text.push("complete(")?;
            text.push(proof.code())?;
            text.push(")")
        }
        FetchCompleteness::Partial { reasons, .. } => {
            text.push("partial(")?;
            for (index, reason) in reasons.iter().enumerate() {
                if index != 0 {
                    text.push(",")?;
                }
                text.push(reason.code())?;
            }
            text.push(")")
        }
        FetchCompleteness::Unknown { reason } => {
            text.push("unknown(")?;
            text.push(reason.code())?;
            text.push(")")
        }
    }
}

fn render_coverage(
    text: &mut BoundedCandidateText,
    counts: PresentationCounts,
    coverage: CompiledCoverageV1,
) -> Result<(), CompiledAgentViewCandidateErrorV1> {
    text.push("coverage shown=")?;
    text.push_usize(counts.shown_verbatim)?;
    text.push(" pattern=")?;
    text.push_usize(counts.pattern_represented)?;
    text.push(" retained=")?;
    text.push_usize(counts.retained_raw)?;
    text.push(" source_exact=")?;
    text.push_usize(coverage.source_exact_records())?;
    text.push(" post_policy=")?;
    text.push_usize(coverage.post_policy_records())?;
    text.push(" policy_omitted=")?;
    text.push_usize(coverage.omitted_by_policy_records())?;
    text.push("\n")
}

fn derive_structured_input_digest(
    rendered: &OwnedRenderedCompiledBriefV1,
) -> Result<ArtifactDigest, CompiledAgentViewCandidateErrorV1> {
    let brief = rendered.brief();
    let coverage = brief.coverage();
    let counts = coverage.presentation_counts();
    let cost = brief.cost();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, STRUCTURED_INPUT_DOMAIN_V1);
    update_field(&mut hasher, brief.result_id().as_bytes());
    update_field(&mut hasher, brief.question_digest().as_bytes());
    update_field(&mut hasher, brief.plan_digest().as_bytes());
    update_i128(&mut hasher, brief.reference_authorized_at().get());
    hash_acquisition(&mut hasher, brief.status().acquisition())?;
    update_field(&mut hasher, brief.status().selection().code().as_bytes());
    update_field(
        &mut hasher,
        selection_strategy_code(brief.selection_strategy()).as_bytes(),
    );
    update_u64(&mut hasher, brief.normalized_gain().numerator());
    update_field(&mut hasher, cost.cost_model().artifact_digest().as_bytes());
    update_u64(&mut hasher, cost.total_token_budget());
    update_u64(&mut hasher, cost.reserved_fixed_overhead());
    update_u64(&mut hasher, cost.mandatory_token_cost());
    update_u64(&mut hasher, cost.selected_packet_cost());
    update_u64(&mut hasher, cost.accounted_token_upper_bound());
    update_u64(&mut hasher, cost.coverage_only_token_limit());
    update_u64(&mut hasher, cost.coverage_only_token_cost());
    update_u64(&mut hasher, cost.total_rendered_tokens());
    update_u64(&mut hasher, cost.total_rendered_bytes());
    update_field(&mut hasher, cost.tokenizer_digest().as_bytes());
    update_field(&mut hasher, cost.renderer_digest().as_bytes());
    update_u64(&mut hasher, u64::from(cost.is_additive_bound_certified()));
    update_u64(&mut hasher, checked_u64(coverage.acknowledged_records())?);
    update_u64(&mut hasher, checked_u64(counts.shown_verbatim)?);
    update_u64(&mut hasher, checked_u64(counts.pattern_represented)?);
    update_u64(&mut hasher, checked_u64(counts.retained_raw)?);
    update_u64(&mut hasher, checked_u64(coverage.source_exact_records())?);
    update_u64(&mut hasher, checked_u64(coverage.post_policy_records())?);
    update_u64(
        &mut hasher,
        checked_u64(coverage.omitted_by_policy_records())?,
    );
    update_u64(&mut hasher, checked_u64(brief.evidence().len())?);
    for packet in brief.evidence() {
        update_u64(&mut hasher, checked_u64(packet.ordinal())?);
        update_field(&mut hasher, packet.packet_id().as_bytes());
        update_field(&mut hasher, packet.reference().id().as_bytes());
        update_u64(
            &mut hasher,
            checked_u64(packet.canonical_event_ids().len())?,
        );
        for event_id in packet.canonical_event_ids() {
            update_field(&mut hasher, event_id.as_bytes());
        }
        update_u64(&mut hasher, checked_u64(packet.events().len())?);
        for event in packet.events() {
            update_field(&mut hasher, event.event_id().as_bytes());
            update_field(&mut hasher, event.exactness_basis().code().as_bytes());
            update_field(&mut hasher, event.stream().code().as_bytes());
            update_field(&mut hasher, event.authorized_bytes());
        }
        update_u64(&mut hasher, checked_u64(packet.affinities().len())?);
        for affinity in packet.affinities() {
            update_field(&mut hasher, affinity.facet_id().as_bytes());
            update_u64(&mut hasher, u64::from(affinity.affinity().micros()));
        }
        update_u64(&mut hasher, checked_u64(packet.facet_kinds().len())?);
        for kind in packet.facet_kinds() {
            update_field(&mut hasher, kind.code().as_bytes());
        }
        let forcing = packet.forcing_constraint();
        update_field(&mut hasher, forcing.code().as_bytes());
        if let Some(facet_id) = forcing.mandatory_facet_id() {
            update_field(&mut hasher, facet_id.as_bytes());
        } else {
            update_field(&mut hasher, &[]);
        }
        update_u64(&mut hasher, packet.marginal_gain().numerator());
        let composable = packet.composable_token_upper_bound();
        update_field(
            &mut hasher,
            composable.cost_model().artifact_digest().as_bytes(),
        );
        update_u64(&mut hasher, composable.upper_bound_tokens());
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_audit_digest(
    source_render_artifact_digest: ArtifactDigest,
    structured_input_artifact_digest: ArtifactDigest,
    output_artifact_digest: ArtifactDigest,
    candidate_renderer_digest: ArtifactDigest,
    canonical_byte_count: u64,
    output_byte_count: u64,
    saved_byte_count: u64,
    citations: &[CompiledAgentViewCandidateCitationV1],
    event_proofs: &[CompiledAgentViewCandidateEventProofV1],
) -> Result<ArtifactDigest, CompiledAgentViewCandidateErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, AUDIT_DOMAIN_V1);
    update_field(&mut hasher, compiled_renderer_digest_v1().as_bytes());
    update_field(&mut hasher, source_render_artifact_digest.as_bytes());
    update_field(&mut hasher, structured_input_artifact_digest.as_bytes());
    update_field(&mut hasher, output_artifact_digest.as_bytes());
    update_field(&mut hasher, candidate_renderer_digest.as_bytes());
    update_u64(&mut hasher, canonical_byte_count);
    update_u64(&mut hasher, output_byte_count);
    update_u64(&mut hasher, saved_byte_count);
    update_u64(&mut hasher, checked_u64(citations.len())?);
    for citation in citations {
        update_u64(&mut hasher, u64::from(citation.alias));
        update_field(&mut hasher, citation.reference.id().as_bytes());
        update_u64(&mut hasher, citation.marker_start);
        update_u64(&mut hasher, citation.marker_end);
    }
    update_u64(&mut hasher, checked_u64(event_proofs.len())?);
    for proof in event_proofs {
        update_field(&mut hasher, proof.event_id.as_bytes());
        update_field(&mut hasher, proof.exactness_basis.code().as_bytes());
        update_field(&mut hasher, proof.stream.code().as_bytes());
        update_u64(&mut hasher, proof.field_start);
        update_u64(&mut hasher, proof.field_end);
        update_u64(&mut hasher, proof.encoded_data_start);
        update_u64(&mut hasher, proof.encoded_data_end);
        update_u64(&mut hasher, proof.authorized_byte_count);
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn hash_acquisition(
    hasher: &mut Sha256,
    acquisition: &FetchCompleteness,
) -> Result<(), CompiledAgentViewCandidateErrorV1> {
    update_field(hasher, acquisition.code().as_bytes());
    match acquisition {
        FetchCompleteness::Complete { proof } => update_field(hasher, proof.code().as_bytes()),
        FetchCompleteness::Partial {
            reasons,
            continuation,
        } => {
            update_u64(hasher, checked_u64(reasons.len())?);
            for reason in reasons.iter() {
                update_field(hasher, reason.code().as_bytes());
            }
            match continuation {
                Some(cursor) => {
                    update_u64(hasher, 1);
                    update_field(hasher, cursor.as_bytes());
                }
                None => update_u64(hasher, 0),
            }
        }
        FetchCompleteness::Unknown { reason } => update_field(hasher, reason.code().as_bytes()),
    }
    Ok(())
}

const fn selection_strategy_code(
    strategy: evidentrail_select::SelectionStrategyV1,
) -> &'static str {
    match strategy {
        evidentrail_select::SelectionStrategyV1::MandatoryOnly => "mandatory_only",
        evidentrail_select::SelectionStrategyV1::DensityGreedy => "density_greedy",
        evidentrail_select::SelectionStrategyV1::BestSingle => "best_single",
        evidentrail_select::SelectionStrategyV1::ExternalOrderBudgetPack => {
            "external_order_budget_pack"
        }
    }
}

fn digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(bytes).into())
}

fn checked_u64(value: usize) -> Result<u64, CompiledAgentViewCandidateErrorV1> {
    u64::try_from(value).map_err(|_| CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)
}

fn checked_usize(value: u64) -> Result<usize, CompiledAgentViewCandidateErrorV1> {
    usize::try_from(value).map_err(|_| CompiledAgentViewCandidateErrorV1::ArithmeticOverflow)
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded compiled-agent-view field fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn update_i128(hasher: &mut Sha256, value: i128) {
    hasher.update(value.to_le_bytes());
}
