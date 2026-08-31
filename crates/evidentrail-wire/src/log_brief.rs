use evidentrail_core::{EventLedger, ExactnessBasis, ResultStatusV1};
use evidentrail_evidence::{
    OwnedRenderedCompiledBriefV1, OwnedRenderedPassthroughBriefV1, compiled_renderer_digest_v1,
    utf8_byte_tokenizer_digest_v1,
};
use evidentrail_schema::{
    ArtifactDigest, PlanDigest, QuestionDigest, ResultId, UnixTimestampNanos,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::codec::{BinaryWireV1, parse_hash_token, parse_result_id, parse_timestamp};
use crate::{WireErrorV1, decode_artifact};

pub const LOG_BRIEF_CONTRACT_V1: &str = "evidentrail.log_brief";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    (contract == LOG_BRIEF_CONTRACT_V1).then(|| schemars::schema_for!(LogBriefWire))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogBriefVariantV1 {
    Passthrough,
    Compiled,
    NeedsMore,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LogBriefArtifactV1 {
    variant: LogBriefVariantV1,
    canonical_bytes: Vec<u8>,
}
impl LogBriefArtifactV1 {
    #[must_use]
    pub const fn variant(&self) -> LogBriefVariantV1 {
        self.variant
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct LogBriefWire {
    contract: String,
    contract_version: u16,
    variant: String,
    structured: StructuredWire,
    rendered_text: String,
    rendered_byte_count: u64,
    rendered_token_count: u64,
    renderer_digest: String,
    tokenizer_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StructuredWire {
    result_id: String,
    question_digest: String,
    plan_digest: String,
    reference_authorized_at_unix_nanos: String,
    untrusted_data: bool,
    acquisition_state: String,
    selection_state: String,
    needs_more_reason: Option<String>,
    acquisition_receipt_id: String,
    presentation_receipt_id: String,
    acknowledged_records: u64,
    source_exact_records: u64,
    post_policy_records: u64,
    omitted_by_policy_records: u64,
    shown_verbatim: u64,
    pattern_represented: u64,
    retained_raw: u64,
    total_token_limit: u64,
    accounted_token_upper_bound: u64,
    evidence: Vec<PacketWire>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PacketWire {
    ordinal: u64,
    evidence_reference_id: String,
    reference_result_id: String,
    allowed_relations: Vec<String>,
    issued_at_unix_nanos: String,
    expires_at_unix_nanos: String,
    event_ids: Vec<String>,
    events: Vec<EventWire>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EventWire {
    event_id: String,
    exactness: String,
    stream: String,
    authorized_bytes: BinaryWireV1,
}

pub fn encode_passthrough_log_brief_v1(
    value: &OwnedRenderedPassthroughBriefV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    let brief = value.brief();
    let budget = brief.budget();
    let coverage = brief.coverage();
    let packets = brief
        .evidence()
        .iter()
        .map(|event| {
            let r = event.reference();
            Ok(PacketWire {
                ordinal: event.ordinal() as u64,
                evidence_reference_id: r.id().to_string(),
                reference_result_id: r.result_id().canonical_token(),
                allowed_relations: r
                    .allowed_relations()
                    .iter()
                    .map(|v| v.code().into())
                    .collect(),
                issued_at_unix_nanos: r.issued_at().get().to_string(),
                expires_at_unix_nanos: r.expires_at().get().to_string(),
                event_ids: vec![event.event_id().to_string()],
                events: vec![EventWire {
                    event_id: event.event_id().to_string(),
                    exactness: exactness(event.exactness_basis()),
                    stream: event.stream().code().into(),
                    authorized_bytes: BinaryWireV1::encode(event.authorized_bytes())?,
                }],
            })
        })
        .collect::<Result<Vec<_>, WireErrorV1>>()?;
    let structured = StructuredWire {
        result_id: brief.result_id().canonical_token(),
        question_digest: brief.question_digest().to_string(),
        plan_digest: brief.plan_digest().to_string(),
        reference_authorized_at_unix_nanos: brief.reference_authorized_at().get().to_string(),
        untrusted_data: true,
        acquisition_state: brief.status().acquisition().code().into(),
        selection_state: brief.status().selection().code().into(),
        needs_more_reason: None,
        acquisition_receipt_id: coverage.acquisition_receipt_id().to_string(),
        presentation_receipt_id: coverage.presentation_receipt_id().to_string(),
        acknowledged_records: coverage.acknowledged_records() as u64,
        source_exact_records: coverage.source_exact_records() as u64,
        post_policy_records: coverage.post_policy_records() as u64,
        omitted_by_policy_records: coverage.omitted_by_policy_records() as u64,
        shown_verbatim: coverage.presentation_counts().shown_verbatim as u64,
        pattern_represented: coverage.presentation_counts().pattern_represented as u64,
        retained_raw: coverage.presentation_counts().retained_raw as u64,
        total_token_limit: budget.total_token_limit(),
        accounted_token_upper_bound: budget.total_rendered_tokens(),
        evidence: packets,
    };
    encode_wire(
        "passthrough",
        structured,
        value.text(),
        budget.total_rendered_tokens(),
        budget.renderer_digest(),
        budget.tokenizer_digest(),
    )
}

pub fn encode_compiled_log_brief_v1(
    value: &OwnedRenderedCompiledBriefV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    let brief = value.brief();
    let cost = brief.cost();
    let coverage = brief.coverage();
    let packets = brief
        .evidence()
        .iter()
        .map(|packet| {
            let r = packet.reference();
            Ok(PacketWire {
                ordinal: packet.ordinal() as u64,
                evidence_reference_id: r.id().to_string(),
                reference_result_id: r.result_id().canonical_token(),
                allowed_relations: r
                    .allowed_relations()
                    .iter()
                    .map(|v| v.code().into())
                    .collect(),
                issued_at_unix_nanos: r.issued_at().get().to_string(),
                expires_at_unix_nanos: r.expires_at().get().to_string(),
                event_ids: packet
                    .canonical_event_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                events: packet
                    .events()
                    .iter()
                    .map(|event| {
                        Ok(EventWire {
                            event_id: event.event_id().to_string(),
                            exactness: exactness(event.exactness_basis()),
                            stream: event.stream().code().into(),
                            authorized_bytes: BinaryWireV1::encode(event.authorized_bytes())?,
                        })
                    })
                    .collect::<Result<_, WireErrorV1>>()?,
            })
        })
        .collect::<Result<Vec<_>, WireErrorV1>>()?;
    let pc = coverage.presentation_counts();
    let structured = StructuredWire {
        result_id: brief.result_id().canonical_token(),
        question_digest: brief.question_digest().to_string(),
        plan_digest: brief.plan_digest().to_string(),
        reference_authorized_at_unix_nanos: brief.reference_authorized_at().get().to_string(),
        untrusted_data: true,
        acquisition_state: brief.status().acquisition().code().into(),
        selection_state: brief.status().selection().code().into(),
        needs_more_reason: None,
        acquisition_receipt_id: coverage.acquisition_receipt_id().to_string(),
        presentation_receipt_id: coverage.presentation_receipt_id().to_string(),
        acknowledged_records: coverage.acknowledged_records() as u64,
        source_exact_records: coverage.source_exact_records() as u64,
        post_policy_records: coverage.post_policy_records() as u64,
        omitted_by_policy_records: coverage.omitted_by_policy_records() as u64,
        shown_verbatim: pc.shown_verbatim as u64,
        pattern_represented: pc.pattern_represented as u64,
        retained_raw: pc.retained_raw as u64,
        total_token_limit: cost.total_token_budget(),
        accounted_token_upper_bound: cost.accounted_token_upper_bound(),
        evidence: packets,
    };
    encode_wire(
        "compiled",
        structured,
        value.text(),
        cost.total_rendered_tokens(),
        cost.renderer_digest(),
        cost.tokenizer_digest(),
    )
}

pub fn encode_needs_more_log_brief_v1(
    ledger: &EventLedger,
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    authorized_at: UnixTimestampNanos,
    status: &ResultStatusV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    if status.selection().code() != "needs_more" {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    let reason = status
        .selection()
        .needs_more_reason()
        .ok_or(WireErrorV1::SemanticallyInvalid)?;
    let receipt = status.selection().presentation_receipt();
    let acq = ledger.acquisition_receipt().counts();
    let pc = receipt.counts();
    let text = format!(
        "Log Brief V1\nselection: needs_more\nreason: {}\n",
        reason.code()
    );
    let structured = StructuredWire {
        result_id: result_id.canonical_token(),
        question_digest: question_digest.to_string(),
        plan_digest: plan_digest.to_string(),
        reference_authorized_at_unix_nanos: authorized_at.get().to_string(),
        untrusted_data: true,
        acquisition_state: status.acquisition().code().into(),
        selection_state: "needs_more".into(),
        needs_more_reason: Some(reason.code().into()),
        acquisition_receipt_id: ledger.acquisition_receipt_id().to_string(),
        presentation_receipt_id: receipt.id().to_string(),
        acknowledged_records: ledger.acquisition_receipt().acknowledged_count() as u64,
        source_exact_records: acq.source_exact as u64,
        post_policy_records: acq.post_policy as u64,
        omitted_by_policy_records: acq.omitted_by_policy as u64,
        shown_verbatim: pc.shown_verbatim as u64,
        pattern_represented: pc.pattern_represented as u64,
        retained_raw: pc.retained_raw as u64,
        total_token_limit: text.len() as u64,
        accounted_token_upper_bound: text.len() as u64,
        evidence: Vec::new(),
    };
    encode_wire(
        "needs_more",
        structured,
        &text,
        text.len() as u64,
        compiled_renderer_digest_v1(),
        utf8_byte_tokenizer_digest_v1(),
    )
}

fn encode_wire(
    variant: &str,
    structured: StructuredWire,
    text: &str,
    tokens: u64,
    renderer: ArtifactDigest,
    tokenizer: ArtifactDigest,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    let wire = LogBriefWire {
        contract: LOG_BRIEF_CONTRACT_V1.into(),
        contract_version: 1,
        variant: variant.into(),
        structured,
        rendered_text: text.into(),
        rendered_byte_count: text.len() as u64,
        rendered_token_count: tokens,
        renderer_digest: renderer.to_string(),
        tokenizer_digest: tokenizer.to_string(),
    };
    let bytes = canonical_json(&wire).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_log_brief_v1(&bytes)
}
pub fn decode_log_brief_v1(bytes: &[u8]) -> Result<LogBriefArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != LOG_BRIEF_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: LogBriefWire = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    let variant = match wire.variant.as_str() {
        "passthrough" => LogBriefVariantV1::Passthrough,
        "compiled" => LogBriefVariantV1::Compiled,
        "needs_more" => LogBriefVariantV1::NeedsMore,
        _ => return Err(WireErrorV1::SemanticallyInvalid),
    };
    if wire.rendered_byte_count != wire.rendered_text.len() as u64
        || !wire.structured.untrusted_data
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    parse_result_id(&wire.structured.result_id)?;
    parse_hash_token(&wire.structured.question_digest, "question_sha256_")?;
    parse_hash_token(&wire.structured.plan_digest, "plan_sha256_")?;
    parse_timestamp(&wire.structured.reference_authorized_at_unix_nanos)?;
    parse_hash_token(&wire.structured.acquisition_receipt_id, "acqrcpt_")?;
    parse_hash_token(&wire.structured.presentation_receipt_id, "prcpt_")?;
    parse_hash_token(&wire.renderer_digest, "artifact_sha256_")?;
    parse_hash_token(&wire.tokenizer_digest, "artifact_sha256_")?;
    for packet in &wire.structured.evidence {
        parse_hash_token(&packet.evidence_reference_id, "eref_")?;
        parse_result_id(&packet.reference_result_id)?;
        parse_timestamp(&packet.issued_at_unix_nanos)?;
        parse_timestamp(&packet.expires_at_unix_nanos)?;
        for event in &packet.events {
            parse_hash_token(&event.event_id, "evt_")?;
            event.authorized_bytes.decode()?;
        }
    }
    Ok(LogBriefArtifactV1 {
        variant,
        canonical_bytes: bytes.to_vec(),
    })
}
pub fn verify_passthrough_log_brief_v1(
    bytes: &[u8],
    expected: &OwnedRenderedPassthroughBriefV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    verify_exact(
        bytes,
        encode_passthrough_log_brief_v1(expected)?,
        LogBriefVariantV1::Passthrough,
    )
}
pub fn verify_compiled_log_brief_v1(
    bytes: &[u8],
    expected: &OwnedRenderedCompiledBriefV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    verify_exact(
        bytes,
        encode_compiled_log_brief_v1(expected)?,
        LogBriefVariantV1::Compiled,
    )
}
fn verify_exact(
    bytes: &[u8],
    expected: LogBriefArtifactV1,
    variant: LogBriefVariantV1,
) -> Result<LogBriefArtifactV1, WireErrorV1> {
    let decoded = decode_log_brief_v1(bytes)?;
    if decoded.variant != variant || decoded != expected {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(decoded)
}
fn exactness(v: ExactnessBasis) -> String {
    v.code().into()
}
