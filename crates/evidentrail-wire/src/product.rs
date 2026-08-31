use evidentrail_core::{
    EventLedger, EvidenceReferenceId, EvidenceReferenceV1, EvidenceTargetRef, ExpandedEventV1,
    ExpansionLimitV1, ExpansionRelationV1, ExpansionRequestV1, ExpansionResponseV1, ResultStatusV1,
    ResultStoreError, UnixTimestampNanos, expand_retained_result_v1,
};
use evidentrail_schema::{BlockId, EventId, ExactnessBasis, PolicyDigest, TransformationReceiptId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::codec::{BinaryWireV1, parse_hash_token, parse_result_id, parse_timestamp};
use crate::{WireErrorV1, decode_artifact};

pub const EVIDENCE_REFERENCE_CONTRACT_V1: &str = "evidentrail.evidence_reference";
pub const EXPANSION_REQUEST_CONTRACT_V1: &str = "evidentrail.expansion_request";
pub const EXPANSION_RESPONSE_CONTRACT_V1: &str = "evidentrail.expansion_response";
pub const RESULT_STATUS_CONTRACT_V1: &str = "evidentrail.result_status";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    match contract {
        EVIDENCE_REFERENCE_CONTRACT_V1 => Some(schemars::schema_for!(EvidenceReferenceWireV1)),
        RESULT_STATUS_CONTRACT_V1 => Some(schemars::schema_for!(ResultStatusWireV1)),
        EXPANSION_REQUEST_CONTRACT_V1 => Some(schemars::schema_for!(ExpansionRequestWireV1)),
        EXPANSION_RESPONSE_CONTRACT_V1 => Some(schemars::schema_for!(ExpansionResponseWireV1)),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceReferenceArtifactV1 {
    reference: EvidenceReferenceV1,
    canonical_bytes: Vec<u8>,
}
impl EvidenceReferenceArtifactV1 {
    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EvidenceReferenceWireV1 {
    contract: String,
    contract_version: u16,
    evidence_reference_id: String,
    result_id: String,
    targets: Vec<TargetWireV1>,
    allowed_relations: Vec<String>,
    issued_at_unix_nanos: String,
    expires_at_unix_nanos: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TargetWireV1 {
    Event { event_id: String },
    Block { block_id: String },
}

pub fn encode_evidence_reference_v1(
    reference: &EvidenceReferenceV1,
) -> Result<EvidenceReferenceArtifactV1, WireErrorV1> {
    let wire = reference_to_wire(reference);
    let bytes = canonical_json(&wire).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_evidence_reference_v1(&bytes)
}

pub fn decode_evidence_reference_v1(
    bytes: &[u8],
) -> Result<EvidenceReferenceArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != EVIDENCE_REFERENCE_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: EvidenceReferenceWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    if wire.contract != EVIDENCE_REFERENCE_CONTRACT_V1 || wire.contract_version != 1 {
        return Err(WireErrorV1::UnsupportedVersion);
    }
    let declared =
        EvidenceReferenceId::from_bytes(parse_hash_token(&wire.evidence_reference_id, "eref_")?);
    let result_id = parse_result_id(&wire.result_id)?;
    let targets = wire
        .targets
        .into_iter()
        .map(|target| match target {
            TargetWireV1::Event { event_id } => Ok(EvidenceTargetRef::Event(EventId::from_bytes(
                parse_hash_token(&event_id, "evt_")?,
            ))),
            TargetWireV1::Block { block_id } => Ok(EvidenceTargetRef::Block(BlockId::from_bytes(
                parse_hash_token(&block_id, "blk_")?,
            ))),
        })
        .collect::<Result<Vec<_>, WireErrorV1>>()?;
    let relations = wire
        .allowed_relations
        .into_iter()
        .map(|code| relation_from_code(&code))
        .collect::<Result<Vec<_>, _>>()?;
    let reference = EvidenceReferenceV1::verify_declared(
        declared,
        result_id,
        targets,
        relations,
        parse_timestamp(&wire.issued_at_unix_nanos)?,
        parse_timestamp(&wire.expires_at_unix_nanos)?,
    )
    .map_err(|_| WireErrorV1::IdentityMismatch)?;
    Ok(EvidenceReferenceArtifactV1 {
        reference,
        canonical_bytes: bytes.to_vec(),
    })
}

pub fn verify_evidence_reference_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
    expected_result_id: evidentrail_schema::ResultId,
    now: UnixTimestampNanos,
) -> Result<EvidenceReferenceArtifactV1, WireErrorV1> {
    let artifact = decode_evidence_reference_v1(bytes)?;
    if artifact.reference.result_id() != expected_result_id {
        return Err(WireErrorV1::CrossContext);
    }
    if artifact
        .reference
        .targets()
        .iter()
        .any(|target| match target {
            EvidenceTargetRef::Event(id) => !ledger.contains(*id),
            EvidenceTargetRef::Block(_) => true,
        })
    {
        return Err(WireErrorV1::CrossContext);
    }
    artifact
        .reference
        .authorize(expected_result_id, ExpansionRelationV1::Exact, now)
        .map_err(|_| WireErrorV1::CrossContext)?;
    Ok(artifact)
}

fn reference_to_wire(reference: &EvidenceReferenceV1) -> EvidenceReferenceWireV1 {
    EvidenceReferenceWireV1 {
        contract: EVIDENCE_REFERENCE_CONTRACT_V1.into(),
        contract_version: 1,
        evidence_reference_id: reference.id().to_string(),
        result_id: reference.result_id().canonical_token(),
        targets: reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(id) => TargetWireV1::Event {
                    event_id: id.to_string(),
                },
                EvidenceTargetRef::Block(id) => TargetWireV1::Block {
                    block_id: id.to_string(),
                },
            })
            .collect(),
        allowed_relations: reference
            .allowed_relations()
            .iter()
            .map(|value| value.code().to_owned())
            .collect(),
        issued_at_unix_nanos: reference.issued_at().get().to_string(),
        expires_at_unix_nanos: reference.expires_at().get().to_string(),
    }
}

fn relation_from_code(code: &str) -> Result<ExpansionRelationV1, WireErrorV1> {
    match code {
        "exact" => Ok(ExpansionRelationV1::Exact),
        "same_lane_before_after" => Ok(ExpansionRelationV1::SameLaneBeforeAfter),
        "global_before_after" => Ok(ExpansionRelationV1::GlobalBeforeAfter),
        "pattern_members" => Ok(ExpansionRelationV1::PatternMembers),
        "same_attested_trace" => Ok(ExpansionRelationV1::SameAttestedTrace),
        "around_onset" => Ok(ExpansionRelationV1::AroundOnset),
        _ => Err(WireErrorV1::SemanticallyInvalid),
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExpansionRequestWireV1 {
    contract: String,
    contract_version: u16,
    result_id: String,
    evidence_reference_id: String,
    relation: String,
    max_events: u64,
    max_bytes: u64,
    before: u64,
    after: u64,
}

pub fn encode_expansion_request_v1(request: ExpansionRequestV1) -> Result<Vec<u8>, WireErrorV1> {
    let limit = request.limit();
    canonical_json(&ExpansionRequestWireV1 {
        contract: EXPANSION_REQUEST_CONTRACT_V1.into(),
        contract_version: 1,
        result_id: request.result_id().canonical_token(),
        evidence_reference_id: request.reference_id().to_string(),
        relation: request.relation().code().into(),
        max_events: limit.max_events() as u64,
        max_bytes: limit.max_bytes() as u64,
        before: limit.before() as u64,
        after: limit.after() as u64,
    })
    .map_err(|_| WireErrorV1::CanonicalizationFailed)
}

pub fn decode_expansion_request_v1(bytes: &[u8]) -> Result<ExpansionRequestV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != EXPANSION_REQUEST_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: ExpansionRequestWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    let limit = ExpansionLimitV1::new(
        usize::try_from(wire.max_events).map_err(|_| WireErrorV1::SemanticallyInvalid)?,
        usize::try_from(wire.max_bytes).map_err(|_| WireErrorV1::SemanticallyInvalid)?,
        usize::try_from(wire.before).map_err(|_| WireErrorV1::SemanticallyInvalid)?,
        usize::try_from(wire.after).map_err(|_| WireErrorV1::SemanticallyInvalid)?,
    )
    .map_err(|_| WireErrorV1::SemanticallyInvalid)?;
    Ok(ExpansionRequestV1::new(
        parse_result_id(&wire.result_id)?,
        EvidenceReferenceId::from_bytes(parse_hash_token(&wire.evidence_reference_id, "eref_")?),
        relation_from_code(&wire.relation)?,
        limit,
    ))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExpansionResponseWireV1 {
    contract: String,
    contract_version: u16,
    result_id: String,
    evidence_reference_id: String,
    relation: String,
    events: Vec<ExpandedEventWireV1>,
    returned_bytes: u64,
    truncated: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExpandedEventWireV1 {
    event_id: String,
    exactness: ExactnessWireV1,
    acquisition_sequence: u64,
    lane_sequence: u64,
    record_state: String,
    exact_bytes: BinaryWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ExactnessWireV1 {
    SourceExact,
    PostPolicy {
        policy_digest: String,
        transformation_receipt_id: String,
    },
}

pub fn encode_expansion_response_v1(
    response: &ExpansionResponseV1,
) -> Result<Vec<u8>, WireErrorV1> {
    canonical_json(&response_to_wire(response)?).map_err(|_| WireErrorV1::CanonicalizationFailed)
}

pub fn verify_expansion_response_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
    reference: &EvidenceReferenceV1,
    request: ExpansionRequestV1,
    now: UnixTimestampNanos,
) -> Result<ExpansionResponseV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != EXPANSION_RESPONSE_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let declared: ExpansionResponseWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    let expected =
        expand_retained_result_v1(ledger, reference, request, now).map_err(map_store_error)?;
    if declared != response_to_wire(&expected)? {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(expected)
}

fn response_to_wire(
    response: &ExpansionResponseV1,
) -> Result<ExpansionResponseWireV1, WireErrorV1> {
    Ok(ExpansionResponseWireV1 {
        contract: EXPANSION_RESPONSE_CONTRACT_V1.into(),
        contract_version: 1,
        result_id: response.result_id().canonical_token(),
        evidence_reference_id: response.reference_id().to_string(),
        relation: response.relation().code().into(),
        events: response
            .events()
            .iter()
            .map(event_to_wire)
            .collect::<Result<_, _>>()?,
        returned_bytes: u64::try_from(response.returned_bytes())
            .map_err(|_| WireErrorV1::SemanticallyInvalid)?,
        truncated: response.truncated(),
    })
}
fn event_to_wire(event: &ExpandedEventV1) -> Result<ExpandedEventWireV1, WireErrorV1> {
    Ok(ExpandedEventWireV1 {
        event_id: event.event_id().to_string(),
        exactness: match event.exactness_basis() {
            ExactnessBasis::SourceExact => ExactnessWireV1::SourceExact,
            ExactnessBasis::PostPolicy {
                policy_digest,
                transformation_receipt_id,
            } => ExactnessWireV1::PostPolicy {
                policy_digest: policy_digest.to_string(),
                transformation_receipt_id: transformation_receipt_id.to_string(),
            },
        },
        acquisition_sequence: event.acquisition_sequence().get(),
        lane_sequence: event.lane_sequence().get(),
        record_state: event.record_state().code().into(),
        exact_bytes: BinaryWireV1::encode(event.exact_bytes())?,
    })
}
fn map_store_error(error: ResultStoreError) -> WireErrorV1 {
    match error {
        ResultStoreError::InvalidExpansionLimit => WireErrorV1::SemanticallyInvalid,
        ResultStoreError::ReferenceUnavailable => WireErrorV1::CrossContext,
        ResultStoreError::InsufficientExpansionBudget => WireErrorV1::CrossContext,
        _ => WireErrorV1::SemanticallyInvalid,
    }
}

#[allow(dead_code)]
fn _identity_types(_: PolicyDigest, _: TransformationReceiptId) {}

#[derive(Clone, PartialEq, Eq)]
pub struct ResultStatusArtifactV1 {
    canonical_bytes: Vec<u8>,
}
impl ResultStatusArtifactV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResultStatusWireV1 {
    contract: String,
    contract_version: u16,
    acquisition: AcquisitionStatusWireV1,
    selection: SelectionStatusWireV1,
    presentation_receipt_id: String,
    persisted_event_count: u64,
    shown_verbatim: u64,
    pattern_represented: u64,
    retained_raw: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum AcquisitionStatusWireV1 {
    Complete,
    Partial { reasons: Vec<String> },
    Unknown { reason: String },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum SelectionStatusWireV1 {
    Passthrough,
    Compiled,
    NeedsMore { reason: String },
}

pub fn encode_result_status_v1(
    status: &ResultStatusV1,
) -> Result<ResultStatusArtifactV1, WireErrorV1> {
    let receipt = status.selection().presentation_receipt();
    let counts = receipt.counts();
    let acquisition = match status.acquisition() {
        evidentrail_core::FetchCompleteness::Complete { .. } => AcquisitionStatusWireV1::Complete,
        evidentrail_core::FetchCompleteness::Partial { reasons, .. } => {
            AcquisitionStatusWireV1::Partial {
                reasons: reasons.iter().map(|v| v.code().into()).collect(),
            }
        }
        evidentrail_core::FetchCompleteness::Unknown { reason } => {
            AcquisitionStatusWireV1::Unknown {
                reason: reason.code().into(),
            }
        }
    };
    let selection = match status.selection().code() {
        "passthrough" => SelectionStatusWireV1::Passthrough,
        "compiled" => SelectionStatusWireV1::Compiled,
        "needs_more" => SelectionStatusWireV1::NeedsMore {
            reason: status
                .selection()
                .needs_more_reason()
                .ok_or(WireErrorV1::SemanticallyInvalid)?
                .code()
                .into(),
        },
        _ => return Err(WireErrorV1::SemanticallyInvalid),
    };
    let wire = ResultStatusWireV1 {
        contract: RESULT_STATUS_CONTRACT_V1.into(),
        contract_version: 1,
        acquisition,
        selection,
        presentation_receipt_id: receipt.id().to_string(),
        persisted_event_count: receipt.persisted_count() as u64,
        shown_verbatim: counts.shown_verbatim as u64,
        pattern_represented: counts.pattern_represented as u64,
        retained_raw: counts.retained_raw as u64,
    };
    let bytes = canonical_json(&wire).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_result_status_v1(&bytes)
}
pub fn decode_result_status_v1(bytes: &[u8]) -> Result<ResultStatusArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != RESULT_STATUS_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: ResultStatusWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    parse_hash_token(&wire.presentation_receipt_id, "prcpt_")?;
    if wire
        .shown_verbatim
        .checked_add(wire.pattern_represented)
        .and_then(|v| v.checked_add(wire.retained_raw))
        != Some(wire.persisted_event_count)
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    if let AcquisitionStatusWireV1::Partial { reasons } = &wire.acquisition {
        if reasons.is_empty() {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
    }
    Ok(ResultStatusArtifactV1 {
        canonical_bytes: bytes.to_vec(),
    })
}
pub fn verify_result_status_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
    status: &ResultStatusV1,
) -> Result<ResultStatusArtifactV1, WireErrorV1> {
    if status.selection().presentation_receipt().retrieval_id() != ledger.retrieval_id() {
        return Err(WireErrorV1::CrossContext);
    }
    let decoded = decode_result_status_v1(bytes)?;
    let expected = encode_result_status_v1(status)?;
    if decoded != expected {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(decoded)
}
