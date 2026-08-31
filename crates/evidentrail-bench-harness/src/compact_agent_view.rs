use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    EvidenceTargetV1, MethodDescriptor, ReversibleEncodingIdentityV1, ascii_byte_escape_v1_identity,
};
use evidentrail_core::{EventId, ExactnessBasis, FetchCompleteness};
use evidentrail_evidence::{
    CompiledCostAccountingV1, OwnedRenderedCompiledBriefV1, compiled_renderer_digest_v1,
    escape_evidence_bytes, unescape_evidence_bytes,
};
use evidentrail_schema::{ArtifactDigest, PresentationCounts, SourceStream};
use evidentrail_select::{
    ComposablePacketCostV1, FacetAffinityV1, ObjectiveGainV1, PacketIdV1, ProductionFacetKindV1,
    SelectionConstraintV1, SelectionStrategyV1,
};
use sha2::{Digest, Sha256};

use crate::{
    FrozenReaderSingleShotReceiptV1, MAX_READER_METHOD_ARTIFACT_BYTES_V1, ReaderCitationHandleV1,
    ReaderErrorV1, ReaderMethodArtifactV1, artifact_digest_for_bytes_v1,
    log_brief_compiled_method_descriptor_v1,
};

pub const COMPACT_AGENT_VIEW_CONTRACT_VERSION_V1: u16 = 1;
pub const COMPACT_AGENT_VIEW_RENDERER_CONTRACT_VERSION_V1: u16 = 1;

const RENDERER_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-renderer/v1\0source=typed-owned-compiled-log-brief-only\0canonical-text-parsing=false\0status=untrusted-data,acquisition,selection\0scope=acknowledged,persisted\0aliases=exact-result-scoped-E-ordinal\0roles=canonical-closed-codes\0events=one-line-basis-stream-ascii-byte-escape\0coverage=shown,pattern,retained,source-exact,post-policy,policy-omitted\0selector-forcing=separate-audit-only\0marginal-gain=separate-audit-only\0composable-cost=separate-audit-only\0newlines=lf";
const CONFIG_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-config/v1\0roles-visible=true\0basis-visible=always\0stream-visible=always\0event-index=one-based-within-packet\0result-token-visible=true\0max-output=reader-method-artifact-v1\0production-renderer-unchanged=true\0evaluation-only=true";
const STRUCTURED_INPUT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-structured-input/v1";
const PACKET_AUDIT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-packet-audit/v1";
const AUDIT_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-audit-receipt/v1";
const VIEW_RECEIPT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/compact-agent-view-receipt/v1";
const CORPUS_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-corpus-reduction/v1";
const READER_PRESERVATION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-reader-preservation/v1";
const ADMISSION_PROPOSAL_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/compact-agent-view-admission-proposal/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewConfigV1 {
    artifact_digest: ArtifactDigest,
    renderer_artifact_digest: ArtifactDigest,
    encoding: ReversibleEncodingIdentityV1,
    maximum_output_bytes: u64,
}

impl CompactAgentViewConfigV1 {
    #[must_use]
    pub fn v1() -> Self {
        let renderer_artifact_digest = compact_agent_view_renderer_artifact_digest_v1();
        let encoding = ascii_byte_escape_v1_identity();
        let mut hasher = Sha256::new();
        update_field(&mut hasher, CONFIG_MANIFEST_V1);
        update_field(&mut hasher, renderer_artifact_digest.as_bytes());
        update_field(&mut hasher, encoding.artifact_digest().as_bytes());
        update_u64(&mut hasher, encoding.contract_version());
        update_u64(&mut hasher, MAX_READER_METHOD_ARTIFACT_BYTES_V1);
        Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            renderer_artifact_digest,
            encoding,
            maximum_output_bytes: MAX_READER_METHOD_ARTIFACT_BYTES_V1,
        }
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn renderer_artifact_digest(self) -> ArtifactDigest {
        self.renderer_artifact_digest
    }

    #[must_use]
    pub const fn encoding(self) -> ReversibleEncodingIdentityV1 {
        self.encoding
    }

    #[must_use]
    pub const fn maximum_output_bytes(self) -> u64 {
        self.maximum_output_bytes
    }
}

impl fmt::Debug for CompactAgentViewConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewConfigV1")
            .field("contract_version", &COMPACT_AGENT_VIEW_CONTRACT_VERSION_V1)
            .field("configuration_identity_present", &true)
            .field("renderer_identity_present", &true)
            .field("encoding", &self.encoding)
            .field("maximum_output_bytes", &self.maximum_output_bytes)
            .field("production_renderer_changed", &false)
            .field("evaluation_only", &true)
            .finish()
    }
}

#[must_use]
pub fn compact_agent_view_renderer_artifact_digest_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(RENDERER_MANIFEST_V1)
}

#[must_use]
pub const fn compact_agent_view_method_descriptor_v1() -> MethodDescriptor {
    MethodDescriptor::new("evidentrail-log-brief-compiled-compact-agent-view", "1")
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewEventProofV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    field_start: u64,
    field_end: u64,
    encoded_data_start: u64,
    encoded_data_end: u64,
    authorized_byte_count: u64,
}

impl CompactAgentViewEventProofV1 {
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

impl fmt::Debug for CompactAgentViewEventProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewEventProofV1")
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

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewPacketAuditV1 {
    artifact_digest: ArtifactDigest,
    alias: u32,
    packet_id: PacketIdV1,
    canonical_event_ids: Vec<EventId>,
    events: Vec<CompactAgentViewEventProofV1>,
    affinities: Vec<FacetAffinityV1>,
    facet_kinds: Vec<ProductionFacetKindV1>,
    marginal_gain: ObjectiveGainV1,
    forcing_constraint: SelectionConstraintV1,
    composable_token_upper_bound: ComposablePacketCostV1,
}

impl CompactAgentViewPacketAuditV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn alias(&self) -> u32 {
        self.alias
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub fn canonical_event_ids(&self) -> &[EventId] {
        &self.canonical_event_ids
    }

    #[must_use]
    pub fn events(&self) -> &[CompactAgentViewEventProofV1] {
        &self.events
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }

    #[must_use]
    pub fn facet_kinds(&self) -> &[ProductionFacetKindV1] {
        &self.facet_kinds
    }

    #[must_use]
    pub const fn marginal_gain(&self) -> ObjectiveGainV1 {
        self.marginal_gain
    }

    #[must_use]
    pub const fn forcing_constraint(&self) -> SelectionConstraintV1 {
        self.forcing_constraint
    }

    #[must_use]
    pub const fn composable_token_upper_bound(&self) -> ComposablePacketCostV1 {
        self.composable_token_upper_bound
    }
}

impl fmt::Debug for CompactAgentViewPacketAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewPacketAuditV1")
            .field("packet_identity_present", &true)
            .field("alias", &self.alias)
            .field("event_count", &self.events.len())
            .field("affinity_count", &self.affinities.len())
            .field("facet_kind_count", &self.facet_kinds.len())
            .field("selector_internals_bound", &true)
            .field("event_identities_redacted", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewAuditReceiptV1 {
    artifact_digest: ArtifactDigest,
    source_provenance_artifact_digest: ArtifactDigest,
    canonical_render_artifact_digest: ArtifactDigest,
    structured_input_artifact_digest: ArtifactDigest,
    compact_output_artifact_digest: ArtifactDigest,
    config: CompactAgentViewConfigV1,
    selection_strategy: SelectionStrategyV1,
    normalized_gain: ObjectiveGainV1,
    cost: CompiledCostAccountingV1,
    packet_audits: Vec<CompactAgentViewPacketAuditV1>,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
}

impl CompactAgentViewAuditReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn source_provenance_artifact_digest(&self) -> ArtifactDigest {
        self.source_provenance_artifact_digest
    }

    #[must_use]
    pub const fn canonical_render_artifact_digest(&self) -> ArtifactDigest {
        self.canonical_render_artifact_digest
    }

    #[must_use]
    pub const fn structured_input_artifact_digest(&self) -> ArtifactDigest {
        self.structured_input_artifact_digest
    }

    #[must_use]
    pub const fn compact_output_artifact_digest(&self) -> ArtifactDigest {
        self.compact_output_artifact_digest
    }

    #[must_use]
    pub const fn config(&self) -> CompactAgentViewConfigV1 {
        self.config
    }

    #[must_use]
    pub const fn selection_strategy(&self) -> SelectionStrategyV1 {
        self.selection_strategy
    }

    #[must_use]
    pub const fn normalized_gain(&self) -> ObjectiveGainV1 {
        self.normalized_gain
    }

    #[must_use]
    pub const fn cost(&self) -> CompiledCostAccountingV1 {
        self.cost
    }

    #[must_use]
    pub fn packet_audits(&self) -> &[CompactAgentViewPacketAuditV1] {
        &self.packet_audits
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
    pub const fn selector_internals_model_visible(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewAuditReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewAuditReceiptV1")
            .field("receipt_identity_present", &true)
            .field("source_provenance_binding_present", &true)
            .field("canonical_render_binding_present", &true)
            .field("structured_input_binding_present", &true)
            .field("compact_output_binding_present", &true)
            .field("config", &self.config)
            .field("packet_audit_count", &self.packet_audits.len())
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field("selector_internals_bound", &true)
            .field("selector_internals_model_visible", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewV1 {
    artifact_digest: ArtifactDigest,
    output_artifact_digest: ArtifactDigest,
    bytes: Box<[u8]>,
    citation_handles: Vec<ReaderCitationHandleV1>,
    audit: CompactAgentViewAuditReceiptV1,
}

impl CompactAgentViewV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn output_artifact_digest(&self) -> ArtifactDigest {
        self.output_artifact_digest
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn citation_handles(&self) -> &[ReaderCitationHandleV1] {
        &self.citation_handles
    }

    #[must_use]
    pub const fn audit(&self) -> &CompactAgentViewAuditReceiptV1 {
        &self.audit
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
    pub const fn production_renderer_changed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_hidden_labels(&self) -> bool {
        false
    }

    pub fn reader_method_artifact(
        &self,
        public_case_artifact_digest: ArtifactDigest,
    ) -> Result<ReaderMethodArtifactV1, CompactAgentViewErrorV1> {
        ReaderMethodArtifactV1::try_new(
            public_case_artifact_digest,
            compact_agent_view_method_descriptor_v1(),
            self.audit.artifact_digest(),
            self.output_artifact_digest,
            self.bytes.to_vec(),
            self.citation_handles.clone(),
        )
        .map_err(CompactAgentViewErrorV1::Reader)
    }
}

impl fmt::Debug for CompactAgentViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewV1")
            .field("view_identity_present", &true)
            .field("output_identity_present", &true)
            .field("byte_count", &self.bytes.len())
            .field("citation_handle_count", &self.citation_handles.len())
            .field("audit", &self.audit)
            .field("untrusted_data", &true)
            .field("byte_exact_event_content", &true)
            .field("canonical_text_parsed_or_postprocessed", &false)
            .field("production_renderer_changed", &false)
            .field("contains_hidden_labels", &false)
            .field("content_redacted", &true)
            .finish()
    }
}

pub fn freeze_compact_compiled_agent_view_v1(
    source_provenance_artifact_digest: ArtifactDigest,
    rendered: &OwnedRenderedCompiledBriefV1,
) -> Result<CompactAgentViewV1, CompactAgentViewErrorV1> {
    let config = CompactAgentViewConfigV1::v1();
    let brief = rendered.brief();
    let cost = brief.cost();
    let canonical_bytes = rendered.text().as_bytes();
    let canonical_byte_count = checked_u64(canonical_bytes.len())?;
    if canonical_bytes.is_empty()
        || canonical_byte_count > MAX_READER_METHOD_ARTIFACT_BYTES_V1
        || cost.renderer_digest() != compiled_renderer_digest_v1()
        || cost.total_rendered_bytes() != canonical_byte_count
        || cost.total_rendered_tokens() != canonical_byte_count
        || !cost.is_additive_bound_certified()
        || brief.status().selection().code() != "compiled"
        || !brief.untrusted_data()
        || brief.evidence().is_empty()
    {
        return Err(CompactAgentViewErrorV1::StructuredInputMismatch);
    }

    let mut text = BoundedCompactText::new(canonical_bytes.len(), config.maximum_output_bytes())?;
    text.push("EVIDENTRAIL_AGENT_VIEW_V1\nresult=")?;
    text.push(&brief.result_id().canonical_token())?;
    text.push("\nuntrusted_data=true\nacquisition=")?;
    render_acquisition(&mut text, brief.status().acquisition())?;
    text.push("\nselection=compiled\nscope acknowledged=")?;
    text.push_usize(brief.coverage().acknowledged_records())?;
    let counts = brief.coverage().presentation_counts();
    text.push(" persisted=")?;
    text.push_usize(counts.persisted())?;
    text.push("\nevidence\n")?;

    let mut seen_event_ids = BTreeSet::new();
    let mut packet_audits = Vec::with_capacity(brief.evidence().len());
    let mut citation_handles = Vec::with_capacity(brief.evidence().len());
    for (packet_index, packet) in brief.evidence().iter().enumerate() {
        if packet.ordinal() != packet_index || packet.events().is_empty() {
            return Err(CompactAgentViewErrorV1::StructuredInputMismatch);
        }
        let alias = u32::try_from(packet_index + 1)
            .map_err(|_| CompactAgentViewErrorV1::ArithmeticOverflow)?;
        let marker_start = checked_u64(text.len())?;
        text.push("[E")?;
        text.push_u32(alias)?;
        text.push("] roles=")?;
        for (index, kind) in packet.facet_kinds().iter().enumerate() {
            if index != 0 {
                text.push(",")?;
            }
            text.push(kind.code())?;
        }
        let marker_end = marker_start
            .checked_add(checked_u64(format!("[E{alias}]").len())?)
            .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?;
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
        if packet_event_ids != canonical_event_ids
            || packet_event_ids
                .iter()
                .any(|event_id| !seen_event_ids.insert(*event_id))
        {
            return Err(CompactAgentViewErrorV1::StructuredInputMismatch);
        }

        let mut event_proofs = Vec::with_capacity(packet.events().len());
        for (event_index, event) in packet.events().iter().enumerate() {
            let field_start = checked_u64(text.len())?;
            text.push("event")?;
            text.push_usize(event_index + 1)?;
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
            let start = checked_usize(encoded_data_start)?;
            let end = checked_usize(encoded_data_end)?;
            let encoded = text
                .as_str()
                .get(start..end)
                .ok_or(CompactAgentViewErrorV1::ReversibleEncodingMismatch)?;
            if unescape_evidence_bytes(encoded)
                .map_err(|_| CompactAgentViewErrorV1::ReversibleEncodingMismatch)?
                != event.authorized_bytes()
            {
                return Err(CompactAgentViewErrorV1::ReversibleEncodingMismatch);
            }
            event_proofs.push(CompactAgentViewEventProofV1 {
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
        if event_proofs
            .windows(2)
            .any(|pair| pair[0].field_end > pair[1].field_start)
        {
            return Err(CompactAgentViewErrorV1::ReversibleEncodingMismatch);
        }

        let targets = packet
            .events()
            .iter()
            .map(|event| EvidenceTargetV1::Event(event.event_id()))
            .collect::<Vec<_>>();
        citation_handles.push(
            ReaderCitationHandleV1::try_new(alias, targets, marker_start, marker_end)
                .map_err(CompactAgentViewErrorV1::Reader)?,
        );
        let packet_audit = build_packet_audit(alias, packet, event_proofs)?;
        packet_audits.push(packet_audit);
    }

    render_coverage(
        &mut text,
        brief.coverage().presentation_counts(),
        brief.coverage(),
    )?;
    if !text.as_str().is_ascii() {
        return Err(CompactAgentViewErrorV1::NonCanonicalOutput);
    }
    let compact_byte_count = checked_u64(text.len())?;
    let saved_byte_count = canonical_byte_count
        .checked_sub(compact_byte_count)
        .filter(|saved| *saved > 0)
        .ok_or(CompactAgentViewErrorV1::NotSmallerThanCanonical)?;
    let bytes = text.into_bytes().into_boxed_slice();
    let canonical_render_artifact_digest = artifact_digest_for_bytes_v1(canonical_bytes);
    let compact_output_artifact_digest = artifact_digest_for_bytes_v1(&bytes);
    let structured_input_artifact_digest = derive_structured_input_digest(
        source_provenance_artifact_digest,
        canonical_render_artifact_digest,
        rendered,
        &packet_audits,
    )?;
    let audit_artifact_digest = derive_audit_receipt_digest(
        source_provenance_artifact_digest,
        canonical_render_artifact_digest,
        structured_input_artifact_digest,
        compact_output_artifact_digest,
        config,
        canonical_byte_count,
        compact_byte_count,
        saved_byte_count,
        &packet_audits,
    )?;
    let audit = CompactAgentViewAuditReceiptV1 {
        artifact_digest: audit_artifact_digest,
        source_provenance_artifact_digest,
        canonical_render_artifact_digest,
        structured_input_artifact_digest,
        compact_output_artifact_digest,
        config,
        selection_strategy: brief.selection_strategy(),
        normalized_gain: brief.normalized_gain(),
        cost,
        packet_audits,
        canonical_byte_count,
        compact_byte_count,
        saved_byte_count,
    };
    let artifact_digest = derive_view_receipt_digest(
        audit.artifact_digest(),
        compact_output_artifact_digest,
        &citation_handles,
    )?;
    Ok(CompactAgentViewV1 {
        artifact_digest,
        output_artifact_digest: compact_output_artifact_digest,
        bytes,
        citation_handles,
        audit,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewCaseReductionV1 {
    public_case_artifact_digest: ArtifactDigest,
    view_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
}

impl CompactAgentViewCaseReductionV1 {
    #[must_use]
    pub fn from_view(
        public_case_artifact_digest: ArtifactDigest,
        view: &CompactAgentViewV1,
    ) -> Self {
        Self {
            public_case_artifact_digest,
            view_artifact_digest: view.artifact_digest(),
            config_artifact_digest: view.audit().config().artifact_digest(),
            canonical_byte_count: view.audit().canonical_byte_count(),
            compact_byte_count: view.audit().compact_byte_count(),
            saved_byte_count: view.audit().saved_byte_count(),
        }
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
}

impl fmt::Debug for CompactAgentViewCaseReductionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewCaseReductionV1")
            .field("case_identity_present", &true)
            .field("view_identity_present", &true)
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewCorpusReductionReceiptV1 {
    artifact_digest: ArtifactDigest,
    corpus_artifact_digest: ArtifactDigest,
    budget_schedule_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    expected_case_count: u64,
    rendered_case_count: u64,
    needs_more_case_count: u64,
    cases: Vec<CompactAgentViewCaseReductionV1>,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    minimum_case_saved_bytes: u64,
    reduction_micros: u64,
}

impl CompactAgentViewCorpusReductionReceiptV1 {
    pub fn try_new(
        corpus_artifact_digest: ArtifactDigest,
        budget_schedule_artifact_digest: ArtifactDigest,
        expected_case_count: u64,
        needs_more_case_count: u64,
        mut cases: Vec<CompactAgentViewCaseReductionV1>,
    ) -> Result<Self, CompactAgentViewErrorV1> {
        if expected_case_count == 0 || cases.is_empty() {
            return Err(CompactAgentViewErrorV1::InvalidCorpusMeasurement);
        }
        let rendered_case_count = checked_u64(cases.len())?;
        if rendered_case_count
            .checked_add(needs_more_case_count)
            .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?
            != expected_case_count
        {
            return Err(CompactAgentViewErrorV1::InvalidCorpusMeasurement);
        }
        cases.sort_unstable_by_key(|case| case.public_case_artifact_digest);
        let config_artifact_digest = cases[0].config_artifact_digest;
        let mut seen_cases = BTreeSet::new();
        let mut canonical_byte_count = 0_u64;
        let mut compact_byte_count = 0_u64;
        let mut saved_byte_count = 0_u64;
        let mut minimum_case_saved_bytes = u64::MAX;
        for case in &cases {
            if !seen_cases.insert(case.public_case_artifact_digest)
                || case.config_artifact_digest != config_artifact_digest
                || case.saved_byte_count == 0
                || case.compact_byte_count.checked_add(case.saved_byte_count)
                    != Some(case.canonical_byte_count)
            {
                return Err(CompactAgentViewErrorV1::InvalidCorpusMeasurement);
            }
            canonical_byte_count = canonical_byte_count
                .checked_add(case.canonical_byte_count)
                .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?;
            compact_byte_count = compact_byte_count
                .checked_add(case.compact_byte_count)
                .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?;
            saved_byte_count = saved_byte_count
                .checked_add(case.saved_byte_count)
                .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?;
            minimum_case_saved_bytes = minimum_case_saved_bytes.min(case.saved_byte_count);
        }
        let reduction_micros = u64::try_from(
            u128::from(saved_byte_count)
                .checked_mul(1_000_000)
                .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?
                / u128::from(canonical_byte_count),
        )
        .map_err(|_| CompactAgentViewErrorV1::ArithmeticOverflow)?;
        let artifact_digest = derive_corpus_receipt_digest(
            corpus_artifact_digest,
            budget_schedule_artifact_digest,
            config_artifact_digest,
            expected_case_count,
            needs_more_case_count,
            &cases,
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            minimum_case_saved_bytes,
            reduction_micros,
        )?;
        Ok(Self {
            artifact_digest,
            corpus_artifact_digest,
            budget_schedule_artifact_digest,
            config_artifact_digest,
            expected_case_count,
            rendered_case_count,
            needs_more_case_count,
            cases,
            canonical_byte_count,
            compact_byte_count,
            saved_byte_count,
            minimum_case_saved_bytes,
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
    pub const fn budget_schedule_artifact_digest(&self) -> ArtifactDigest {
        self.budget_schedule_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(&self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn expected_case_count(&self) -> u64 {
        self.expected_case_count
    }

    #[must_use]
    pub const fn rendered_case_count(&self) -> u64 {
        self.rendered_case_count
    }

    #[must_use]
    pub const fn needs_more_case_count(&self) -> u64 {
        self.needs_more_case_count
    }

    #[must_use]
    pub fn cases(&self) -> &[CompactAgentViewCaseReductionV1] {
        &self.cases
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
    pub const fn minimum_case_saved_bytes(&self) -> u64 {
        self.minimum_case_saved_bytes
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

impl fmt::Debug for CompactAgentViewCorpusReductionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewCorpusReductionReceiptV1")
            .field("receipt_identity_present", &true)
            .field("corpus_binding_present", &true)
            .field("budget_schedule_binding_present", &true)
            .field("config_binding_present", &true)
            .field("expected_case_count", &self.expected_case_count)
            .field("rendered_case_count", &self.rendered_case_count)
            .field("needs_more_case_count", &self.needs_more_case_count)
            .field("canonical_byte_count", &self.canonical_byte_count)
            .field("compact_byte_count", &self.compact_byte_count)
            .field("saved_byte_count", &self.saved_byte_count)
            .field("minimum_case_saved_bytes", &self.minimum_case_saved_bytes)
            .field("reduction_micros", &self.reduction_micros)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompactAgentViewReaderPreservationReceiptV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    compact_view_artifact_digest: ArtifactDigest,
    reader_configuration_artifact_digest: ArtifactDigest,
    answer_artifact_digest: ArtifactDigest,
    cited_handles: Vec<u32>,
}

impl CompactAgentViewReaderPreservationReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn compact_view_artifact_digest(&self) -> ArtifactDigest {
        self.compact_view_artifact_digest
    }

    #[must_use]
    pub const fn reader_configuration_artifact_digest(&self) -> ArtifactDigest {
        self.reader_configuration_artifact_digest
    }

    #[must_use]
    pub const fn answer_artifact_digest(&self) -> ArtifactDigest {
        self.answer_artifact_digest
    }

    #[must_use]
    pub fn cited_handles(&self) -> &[u32] {
        &self.cited_handles
    }

    #[must_use]
    pub const fn answers_preserved(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn citation_semantics_preserved(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn hosted_reader_claimed(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewReaderPreservationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewReaderPreservationReceiptV1")
            .field("receipt_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("compact_view_binding_present", &true)
            .field("reader_configuration_binding_present", &true)
            .field("answer_binding_present", &true)
            .field("cited_handle_count", &self.cited_handles.len())
            .field("answers_preserved", &true)
            .field("citation_semantics_preserved", &true)
            .field("hosted_reader_claimed", &false)
            .finish()
    }
}

pub fn compare_compact_agent_view_reader_receipts_v1(
    canonical: &FrozenReaderSingleShotReceiptV1,
    compact: &FrozenReaderSingleShotReceiptV1,
    view: &CompactAgentViewV1,
) -> Result<CompactAgentViewReaderPreservationReceiptV1, CompactAgentViewErrorV1> {
    let canonical_input = canonical.public_input();
    let compact_input = compact.public_input();
    if canonical_input.public_case_artifact_digest() != compact_input.public_case_artifact_digest()
        || canonical_input.question_digest() != compact_input.question_digest()
        || canonical_input.context_artifact_digest() != compact_input.context_artifact_digest()
        || canonical_input.method_artifact().method() != log_brief_compiled_method_descriptor_v1()
        || compact_input.method_artifact().method() != compact_agent_view_method_descriptor_v1()
        || canonical_input.method_artifact().artifact_digest()
            != view.audit().canonical_render_artifact_digest()
        || canonical_input
            .method_artifact()
            .source_provenance_artifact_digest()
            != view.audit().source_provenance_artifact_digest()
        || compact_input.method_artifact().artifact_digest() != view.output_artifact_digest()
        || compact_input
            .method_artifact()
            .source_provenance_artifact_digest()
            != view.audit().artifact_digest()
        || canonical.target().configuration_artifact_digest()
            != compact.target().configuration_artifact_digest()
        || canonical.caps() != compact.caps()
        || canonical.answer_artifact_digest() != compact.answer_artifact_digest()
        || canonical.answer_bytes() != compact.answer_bytes()
        || canonical.answer().citation_handles() != compact.answer().citation_handles()
        || !same_citation_semantics(
            canonical_input.method_artifact().citation_handles(),
            compact_input.method_artifact().citation_handles(),
        )
    {
        return Err(CompactAgentViewErrorV1::ReaderPreservationMismatch);
    }
    let cited_handles = canonical.answer().citation_handles().to_vec();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, READER_PRESERVATION_DOMAIN_V1);
    update_field(
        &mut hasher,
        canonical_input.public_case_artifact_digest().as_bytes(),
    );
    update_field(&mut hasher, canonical.artifact_digest().as_bytes());
    update_field(&mut hasher, compact.artifact_digest().as_bytes());
    update_field(&mut hasher, view.artifact_digest().as_bytes());
    update_field(
        &mut hasher,
        canonical
            .target()
            .configuration_artifact_digest()
            .as_bytes(),
    );
    update_field(&mut hasher, canonical.answer_artifact_digest().as_bytes());
    update_u64(&mut hasher, checked_u64(cited_handles.len())?);
    for handle in &cited_handles {
        update_u64(&mut hasher, u64::from(*handle));
    }
    Ok(CompactAgentViewReaderPreservationReceiptV1 {
        artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        public_case_artifact_digest: canonical_input.public_case_artifact_digest(),
        compact_view_artifact_digest: view.artifact_digest(),
        reader_configuration_artifact_digest: canonical.target().configuration_artifact_digest(),
        answer_artifact_digest: canonical.answer_artifact_digest(),
        cited_handles,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompactAgentViewAdmissionStatusV1 {
    EligibleForControlledAdmissionReview,
}

impl CompactAgentViewAdmissionStatusV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        "eligible_for_controlled_admission_review_not_admitted"
    }
}

impl fmt::Debug for CompactAgentViewAdmissionStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewAdmissionStatusV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactAgentViewAdmissionProposalV1 {
    artifact_digest: ArtifactDigest,
    preservation_receipt_artifact_digest: ArtifactDigest,
    corpus_reduction_receipt_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    status: CompactAgentViewAdmissionStatusV1,
}

impl CompactAgentViewAdmissionProposalV1 {
    pub fn try_new(
        preservation: &CompactAgentViewReaderPreservationReceiptV1,
        corpus: &CompactAgentViewCorpusReductionReceiptV1,
    ) -> Result<Self, CompactAgentViewErrorV1> {
        if corpus.rendered_case_count() == 0
            || corpus.saved_byte_count() == 0
            || corpus.minimum_case_saved_bytes() == 0
            || !preservation.answers_preserved()
            || !preservation.citation_semantics_preserved()
        {
            return Err(CompactAgentViewErrorV1::AdmissionEvidenceIncomplete);
        }
        let status = CompactAgentViewAdmissionStatusV1::EligibleForControlledAdmissionReview;
        let mut hasher = Sha256::new();
        update_field(&mut hasher, ADMISSION_PROPOSAL_DOMAIN_V1);
        update_field(&mut hasher, preservation.artifact_digest().as_bytes());
        update_field(&mut hasher, corpus.artifact_digest().as_bytes());
        update_field(&mut hasher, corpus.config_artifact_digest().as_bytes());
        update_field(&mut hasher, status.code().as_bytes());
        Ok(Self {
            artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
            preservation_receipt_artifact_digest: preservation.artifact_digest(),
            corpus_reduction_receipt_artifact_digest: corpus.artifact_digest(),
            config_artifact_digest: corpus.config_artifact_digest(),
            status,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn preservation_receipt_artifact_digest(self) -> ArtifactDigest {
        self.preservation_receipt_artifact_digest
    }

    #[must_use]
    pub const fn corpus_reduction_receipt_artifact_digest(self) -> ArtifactDigest {
        self.corpus_reduction_receipt_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn status(self) -> CompactAgentViewAdmissionStatusV1 {
        self.status
    }

    #[must_use]
    pub const fn production_change_authorized(self) -> bool {
        false
    }

    #[must_use]
    pub const fn hosted_reader_validated(self) -> bool {
        false
    }
}

impl fmt::Debug for CompactAgentViewAdmissionProposalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewAdmissionProposalV1")
            .field("proposal_identity_present", &true)
            .field("preservation_binding_present", &true)
            .field("corpus_reduction_binding_present", &true)
            .field("config_binding_present", &true)
            .field("status", &self.status)
            .field("production_change_authorized", &false)
            .field("hosted_reader_validated", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompactAgentViewErrorV1 {
    StructuredInputMismatch,
    OutputTooLarge,
    ReversibleEncodingMismatch,
    NonCanonicalOutput,
    NotSmallerThanCanonical,
    InvalidCorpusMeasurement,
    ReaderPreservationMismatch,
    AdmissionEvidenceIncomplete,
    ArithmeticOverflow,
    Reader(ReaderErrorV1),
}

impl CompactAgentViewErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StructuredInputMismatch => {
                "EVIDENTRAIL_BENCH_COMPACT_VIEW_STRUCTURED_INPUT_MISMATCH"
            }
            Self::OutputTooLarge => "EVIDENTRAIL_BENCH_COMPACT_VIEW_OUTPUT_TOO_LARGE",
            Self::ReversibleEncodingMismatch => {
                "EVIDENTRAIL_BENCH_COMPACT_VIEW_REVERSIBLE_ENCODING_MISMATCH"
            }
            Self::NonCanonicalOutput => "EVIDENTRAIL_BENCH_COMPACT_VIEW_NONCANONICAL_OUTPUT",
            Self::NotSmallerThanCanonical => "EVIDENTRAIL_BENCH_COMPACT_VIEW_NOT_SMALLER",
            Self::InvalidCorpusMeasurement => {
                "EVIDENTRAIL_BENCH_COMPACT_VIEW_INVALID_CORPUS_MEASUREMENT"
            }
            Self::ReaderPreservationMismatch => {
                "EVIDENTRAIL_BENCH_COMPACT_VIEW_READER_PRESERVATION_MISMATCH"
            }
            Self::AdmissionEvidenceIncomplete => {
                "EVIDENTRAIL_BENCH_COMPACT_VIEW_ADMISSION_EVIDENCE_INCOMPLETE"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_COMPACT_VIEW_ARITHMETIC_OVERFLOW",
            Self::Reader(_) => "EVIDENTRAIL_BENCH_COMPACT_VIEW_READER_FAILURE",
        }
    }
}

impl fmt::Debug for CompactAgentViewErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactAgentViewErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CompactAgentViewErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CompactAgentViewErrorV1 {}

struct BoundedCompactText {
    value: String,
    maximum: usize,
}

impl BoundedCompactText {
    fn new(capacity: usize, maximum: u64) -> Result<Self, CompactAgentViewErrorV1> {
        let maximum = checked_usize(maximum)?;
        Ok(Self {
            value: String::with_capacity(capacity.min(maximum)),
            maximum,
        })
    }

    fn push(&mut self, value: &str) -> Result<(), CompactAgentViewErrorV1> {
        let next = self
            .value
            .len()
            .checked_add(value.len())
            .ok_or(CompactAgentViewErrorV1::ArithmeticOverflow)?;
        if next > self.maximum {
            return Err(CompactAgentViewErrorV1::OutputTooLarge);
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_usize(&mut self, value: usize) -> Result<(), CompactAgentViewErrorV1> {
        self.push(&value.to_string())
    }

    fn push_u32(&mut self, value: u32) -> Result<(), CompactAgentViewErrorV1> {
        self.push(&value.to_string())
    }

    fn len(&self) -> usize {
        self.value.len()
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn into_bytes(self) -> Vec<u8> {
        self.value.into_bytes()
    }
}

fn render_acquisition(
    text: &mut BoundedCompactText,
    acquisition: &FetchCompleteness,
) -> Result<(), CompactAgentViewErrorV1> {
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
    text: &mut BoundedCompactText,
    counts: PresentationCounts,
    coverage: evidentrail_evidence::CompiledCoverageV1,
) -> Result<(), CompactAgentViewErrorV1> {
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

fn build_packet_audit(
    alias: u32,
    packet: &evidentrail_evidence::OwnedCompiledEvidencePacketV1,
    events: Vec<CompactAgentViewEventProofV1>,
) -> Result<CompactAgentViewPacketAuditV1, CompactAgentViewErrorV1> {
    let canonical_event_ids = packet.canonical_event_ids().to_vec();
    let affinities = packet.affinities().to_vec();
    let facet_kinds = packet.facet_kinds().to_vec();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PACKET_AUDIT_DOMAIN_V1);
    update_u64(&mut hasher, u64::from(alias));
    update_field(&mut hasher, packet.packet_id().as_bytes());
    update_u64(&mut hasher, checked_u64(canonical_event_ids.len())?);
    for event_id in &canonical_event_ids {
        update_field(&mut hasher, event_id.as_bytes());
    }
    update_u64(&mut hasher, checked_u64(packet.events().len())?);
    for event in packet.events() {
        update_field(&mut hasher, event.event_id().as_bytes());
        update_field(&mut hasher, event.exactness_basis().code().as_bytes());
        update_field(&mut hasher, event.stream().code().as_bytes());
        update_field(&mut hasher, event.authorized_bytes());
    }
    update_u64(&mut hasher, checked_u64(affinities.len())?);
    for affinity in &affinities {
        update_field(&mut hasher, affinity.facet_id().as_bytes());
        update_u64(&mut hasher, u64::from(affinity.affinity().micros()));
    }
    update_u64(&mut hasher, checked_u64(facet_kinds.len())?);
    for kind in &facet_kinds {
        update_field(&mut hasher, kind.code().as_bytes());
    }
    let forcing_constraint = packet.forcing_constraint();
    update_field(&mut hasher, forcing_constraint.code().as_bytes());
    if let Some(facet_id) = forcing_constraint.mandatory_facet_id() {
        update_field(&mut hasher, facet_id.as_bytes());
    } else {
        update_field(&mut hasher, &[]);
    }
    let marginal_gain = packet.marginal_gain();
    update_u64(&mut hasher, marginal_gain.numerator());
    let composable_token_upper_bound = packet.composable_token_upper_bound();
    update_field(
        &mut hasher,
        composable_token_upper_bound
            .cost_model()
            .artifact_digest()
            .as_bytes(),
    );
    update_u64(
        &mut hasher,
        composable_token_upper_bound.upper_bound_tokens(),
    );
    update_u64(&mut hasher, checked_u64(events.len())?);
    for event in &events {
        update_u64(&mut hasher, event.field_start);
        update_u64(&mut hasher, event.field_end);
        update_u64(&mut hasher, event.encoded_data_start);
        update_u64(&mut hasher, event.encoded_data_end);
    }
    Ok(CompactAgentViewPacketAuditV1 {
        artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        alias,
        packet_id: packet.packet_id(),
        canonical_event_ids,
        events,
        affinities,
        facet_kinds,
        marginal_gain,
        forcing_constraint,
        composable_token_upper_bound,
    })
}

fn derive_structured_input_digest(
    source_provenance_artifact_digest: ArtifactDigest,
    canonical_render_artifact_digest: ArtifactDigest,
    rendered: &OwnedRenderedCompiledBriefV1,
    packets: &[CompactAgentViewPacketAuditV1],
) -> Result<ArtifactDigest, CompactAgentViewErrorV1> {
    let brief = rendered.brief();
    let cost = brief.cost();
    let coverage = brief.coverage();
    let counts = coverage.presentation_counts();
    let mut hasher = Sha256::new();
    update_field(&mut hasher, STRUCTURED_INPUT_DOMAIN_V1);
    update_field(&mut hasher, source_provenance_artifact_digest.as_bytes());
    update_field(&mut hasher, canonical_render_artifact_digest.as_bytes());
    update_field(&mut hasher, brief.result_id().as_bytes());
    update_field(&mut hasher, brief.question_digest().as_bytes());
    update_field(&mut hasher, brief.plan_digest().as_bytes());
    update_field(
        &mut hasher,
        selection_strategy_code(brief.selection_strategy()).as_bytes(),
    );
    update_u64(&mut hasher, brief.normalized_gain().numerator());
    hash_acquisition(&mut hasher, brief.status().acquisition())?;
    hash_cost(&mut hasher, cost);
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
    update_u64(&mut hasher, checked_u64(packets.len())?);
    for packet in packets {
        update_field(&mut hasher, packet.artifact_digest().as_bytes());
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_audit_receipt_digest(
    source_provenance_artifact_digest: ArtifactDigest,
    canonical_render_artifact_digest: ArtifactDigest,
    structured_input_artifact_digest: ArtifactDigest,
    compact_output_artifact_digest: ArtifactDigest,
    config: CompactAgentViewConfigV1,
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    packets: &[CompactAgentViewPacketAuditV1],
) -> Result<ArtifactDigest, CompactAgentViewErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, AUDIT_RECEIPT_DOMAIN_V1);
    update_field(&mut hasher, source_provenance_artifact_digest.as_bytes());
    update_field(&mut hasher, canonical_render_artifact_digest.as_bytes());
    update_field(&mut hasher, structured_input_artifact_digest.as_bytes());
    update_field(&mut hasher, compact_output_artifact_digest.as_bytes());
    update_field(&mut hasher, config.artifact_digest().as_bytes());
    update_u64(&mut hasher, canonical_byte_count);
    update_u64(&mut hasher, compact_byte_count);
    update_u64(&mut hasher, saved_byte_count);
    update_u64(&mut hasher, checked_u64(packets.len())?);
    for packet in packets {
        update_field(&mut hasher, packet.artifact_digest().as_bytes());
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_view_receipt_digest(
    audit_artifact_digest: ArtifactDigest,
    output_artifact_digest: ArtifactDigest,
    citations: &[ReaderCitationHandleV1],
) -> Result<ArtifactDigest, CompactAgentViewErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, VIEW_RECEIPT_DOMAIN_V1);
    update_field(&mut hasher, audit_artifact_digest.as_bytes());
    update_field(&mut hasher, output_artifact_digest.as_bytes());
    update_u64(&mut hasher, checked_u64(citations.len())?);
    for citation in citations {
        update_u64(&mut hasher, u64::from(citation.handle()));
        update_u64(&mut hasher, citation.marker_start());
        update_u64(&mut hasher, citation.marker_end());
        update_u64(&mut hasher, checked_u64(citation.targets().len())?);
        for target in citation.targets() {
            match target {
                EvidenceTargetV1::Event(event_id) => {
                    update_field(&mut hasher, b"event");
                    update_field(&mut hasher, event_id.as_bytes());
                }
                EvidenceTargetV1::Block(block_id) => {
                    update_field(&mut hasher, b"block");
                    update_field(&mut hasher, block_id.as_bytes());
                }
            }
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_corpus_receipt_digest(
    corpus_artifact_digest: ArtifactDigest,
    budget_schedule_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    expected_case_count: u64,
    needs_more_case_count: u64,
    cases: &[CompactAgentViewCaseReductionV1],
    canonical_byte_count: u64,
    compact_byte_count: u64,
    saved_byte_count: u64,
    minimum_case_saved_bytes: u64,
    reduction_micros: u64,
) -> Result<ArtifactDigest, CompactAgentViewErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, CORPUS_RECEIPT_DOMAIN_V1);
    update_field(&mut hasher, corpus_artifact_digest.as_bytes());
    update_field(&mut hasher, budget_schedule_artifact_digest.as_bytes());
    update_field(&mut hasher, config_artifact_digest.as_bytes());
    update_u64(&mut hasher, expected_case_count);
    update_u64(&mut hasher, needs_more_case_count);
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in cases {
        update_field(&mut hasher, case.public_case_artifact_digest.as_bytes());
        update_field(&mut hasher, case.view_artifact_digest.as_bytes());
        update_u64(&mut hasher, case.canonical_byte_count);
        update_u64(&mut hasher, case.compact_byte_count);
        update_u64(&mut hasher, case.saved_byte_count);
    }
    update_u64(&mut hasher, canonical_byte_count);
    update_u64(&mut hasher, compact_byte_count);
    update_u64(&mut hasher, saved_byte_count);
    update_u64(&mut hasher, minimum_case_saved_bytes);
    update_u64(&mut hasher, reduction_micros);
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn same_citation_semantics(
    canonical: &[ReaderCitationHandleV1],
    compact: &[ReaderCitationHandleV1],
) -> bool {
    canonical.len() == compact.len()
        && canonical.iter().zip(compact).all(|(left, right)| {
            left.handle() == right.handle() && left.targets() == right.targets()
        })
}

fn hash_acquisition(
    hasher: &mut Sha256,
    acquisition: &FetchCompleteness,
) -> Result<(), CompactAgentViewErrorV1> {
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
            if let Some(continuation) = continuation {
                update_field(hasher, continuation.as_bytes());
            } else {
                update_field(hasher, &[]);
            }
        }
        FetchCompleteness::Unknown { reason } => update_field(hasher, reason.code().as_bytes()),
    }
    Ok(())
}

fn hash_cost(hasher: &mut Sha256, cost: CompiledCostAccountingV1) {
    update_field(hasher, cost.cost_model().artifact_digest().as_bytes());
    update_u64(hasher, cost.total_token_budget());
    update_u64(hasher, cost.reserved_fixed_overhead());
    update_u64(hasher, cost.mandatory_token_cost());
    update_u64(hasher, cost.selected_packet_cost());
    update_u64(hasher, cost.accounted_token_upper_bound());
    update_u64(hasher, cost.coverage_only_token_limit());
    update_u64(hasher, cost.coverage_only_token_cost());
    update_u64(hasher, cost.total_rendered_tokens());
    update_u64(hasher, cost.total_rendered_bytes());
    update_field(hasher, cost.tokenizer_digest().as_bytes());
    update_field(hasher, cost.renderer_digest().as_bytes());
    update_u64(
        hasher,
        if cost.is_additive_bound_certified() {
            1
        } else {
            0
        },
    );
}

const fn selection_strategy_code(strategy: SelectionStrategyV1) -> &'static str {
    match strategy {
        SelectionStrategyV1::MandatoryOnly => "mandatory_only",
        SelectionStrategyV1::DensityGreedy => "density_greedy",
        SelectionStrategyV1::BestSingle => "best_single",
    }
}

fn checked_u64(value: usize) -> Result<u64, CompactAgentViewErrorV1> {
    u64::try_from(value).map_err(|_| CompactAgentViewErrorV1::ArithmeticOverflow)
}

fn checked_usize(value: u64) -> Result<usize, CompactAgentViewErrorV1> {
    usize::try_from(value).map_err(|_| CompactAgentViewErrorV1::ArithmeticOverflow)
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded compact-agent-view field fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
