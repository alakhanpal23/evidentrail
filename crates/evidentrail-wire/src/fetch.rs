use evidentrail_core::{
    CapKind, CompletenessProof, EventLedger, FetchCompleteness, FetchErrorCode, FetchPartialReason,
};
use evidentrail_schema::FetchCompletion;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::codec::{BinaryWireV1, parse_hash_token, parse_timestamp};
use crate::{WireErrorV1, decode_artifact};

pub const FETCH_COMPLETION_CONTRACT_V1: &str = "evidentrail.fetch_completion";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    (contract == FETCH_COMPLETION_CONTRACT_V1).then(|| schemars::schema_for!(FetchCompletionWireV1))
}

#[derive(Clone, PartialEq, Eq)]
pub struct FetchCompletionArtifactV1 {
    canonical_bytes: Vec<u8>,
}
impl FetchCompletionArtifactV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FetchCompletionWireV1 {
    contract: String,
    contract_version: u16,
    retrieval_id: String,
    plan_id: String,
    plan_digest: String,
    adapter_kind: String,
    adapter_version: String,
    started_at_unix_nanos: String,
    ended_at_unix_nanos: String,
    acknowledged_records: u64,
    acknowledged_payload_bytes: u64,
    acknowledged_source_bytes: u64,
    members_attempted: u64,
    members_completed: u64,
    pages_attempted: u64,
    pages_completed: u64,
    first_cursor: Option<BinaryWireV1>,
    final_cursor: Option<BinaryWireV1>,
    high_water_marks: Vec<HighWaterWireV1>,
    cap_usage: Vec<CapWireV1>,
    adapter_outcome: String,
    error_codes: Vec<CodeWireV1>,
    completeness: CompletenessWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HighWaterWireV1 {
    member: BinaryWireV1,
    cursor: BinaryWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CapWireV1 {
    kind: CodeWireV1,
    used: u64,
    limit: u64,
    reached: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CodeWireV1 {
    code: String,
    version: Option<u16>,
    other_code: Option<u16>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum CompletenessWireV1 {
    Complete {
        proof: CodeWireV1,
    },
    Partial {
        reasons: Vec<CodeWireV1>,
        continuation: Option<BinaryWireV1>,
    },
    Unknown {
        reason: String,
    },
}

pub fn encode_fetch_completion_v1(
    completion: &FetchCompletion,
) -> Result<FetchCompletionArtifactV1, WireErrorV1> {
    let bytes =
        canonical_json(&to_wire(completion)?).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_fetch_completion_v1(&bytes)
}
pub fn decode_fetch_completion_v1(bytes: &[u8]) -> Result<FetchCompletionArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != FETCH_COMPLETION_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: FetchCompletionWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    parse_hash_token(&wire.retrieval_id, "ret_")?;
    parse_hash_token(&wire.plan_id, "plan_")?;
    parse_hash_token(&wire.plan_digest, "plan_sha256_")?;
    parse_timestamp(&wire.started_at_unix_nanos)?;
    parse_timestamp(&wire.ended_at_unix_nanos)?;
    if wire.adapter_kind.is_empty()
        || wire.adapter_version.is_empty()
        || wire.acknowledged_payload_bytes > wire.acknowledged_source_bytes
        || wire.members_completed > wire.members_attempted
        || wire.pages_completed > wire.pages_attempted
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    if let Some(value) = &wire.first_cursor {
        value.decode()?;
    }
    if let Some(value) = &wire.final_cursor {
        value.decode()?;
    }
    for value in &wire.high_water_marks {
        value.member.decode()?;
        value.cursor.decode()?;
    }
    if let CompletenessWireV1::Partial {
        reasons,
        continuation,
    } = &wire.completeness
    {
        if reasons.is_empty() {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
        if let Some(value) = continuation {
            value.decode()?;
        }
    }
    Ok(FetchCompletionArtifactV1 {
        canonical_bytes: bytes.to_vec(),
    })
}
pub fn verify_fetch_completion_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
) -> Result<FetchCompletionArtifactV1, WireErrorV1> {
    let decoded = decode_fetch_completion_v1(bytes)?;
    let expected = encode_fetch_completion_v1(ledger.fetch_completion())?;
    if decoded != expected {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(decoded)
}

fn to_wire(value: &FetchCompletion) -> Result<FetchCompletionWireV1, WireErrorV1> {
    let identity = value.identity();
    let timing = value.timing();
    let ack = value.acknowledged();
    let members = value.member_counts();
    let pages = value.page_counts();
    let boundaries = value.boundaries();
    Ok(FetchCompletionWireV1 {
        contract: FETCH_COMPLETION_CONTRACT_V1.into(),
        contract_version: 1,
        retrieval_id: identity.retrieval_id().to_string(),
        plan_id: identity.plan_id().to_string(),
        plan_digest: identity.plan_digest().to_string(),
        adapter_kind: identity.adapter().kind().into(),
        adapter_version: identity.adapter().version().into(),
        started_at_unix_nanos: timing.started_at().get().to_string(),
        ended_at_unix_nanos: timing.ended_at().get().to_string(),
        acknowledged_records: ack.records(),
        acknowledged_payload_bytes: ack.payload_bytes(),
        acknowledged_source_bytes: ack.source_bytes(),
        members_attempted: members.attempted(),
        members_completed: members.completed(),
        pages_attempted: pages.attempted(),
        pages_completed: pages.completed(),
        first_cursor: boundaries
            .first_cursor()
            .map(|v| BinaryWireV1::encode(v.as_bytes()))
            .transpose()?,
        final_cursor: boundaries
            .final_cursor()
            .map(|v| BinaryWireV1::encode(v.as_bytes()))
            .transpose()?,
        high_water_marks: boundaries
            .high_water_marks()
            .iter()
            .map(|v| {
                Ok(HighWaterWireV1 {
                    member: BinaryWireV1::encode(v.member().as_bytes())?,
                    cursor: BinaryWireV1::encode(v.cursor().as_bytes())?,
                })
            })
            .collect::<Result<_, WireErrorV1>>()?,
        cap_usage: value
            .cap_usage()
            .iter()
            .map(|v| CapWireV1 {
                kind: cap_code(v.kind()),
                used: v.used(),
                limit: v.limit(),
                reached: v.reached(),
            })
            .collect(),
        adapter_outcome: value.adapter_outcome().code().into(),
        error_codes: value
            .error_codes()
            .iter()
            .copied()
            .map(error_code)
            .collect(),
        completeness: match value.completeness() {
            FetchCompleteness::Complete { proof } => CompletenessWireV1::Complete {
                proof: proof_code(*proof),
            },
            FetchCompleteness::Partial {
                reasons,
                continuation,
            } => CompletenessWireV1::Partial {
                reasons: reasons.iter().map(partial_code).collect(),
                continuation: continuation
                    .as_ref()
                    .map(|v| BinaryWireV1::encode(v.as_bytes()))
                    .transpose()?,
            },
            FetchCompleteness::Unknown { reason } => CompletenessWireV1::Unknown {
                reason: reason.code().into(),
            },
        },
    })
}
fn simple(code: &str) -> CodeWireV1 {
    CodeWireV1 {
        code: code.into(),
        version: None,
        other_code: None,
    }
}
fn versioned(code: &str, version: u16, other_code: u16) -> CodeWireV1 {
    CodeWireV1 {
        code: code.into(),
        version: Some(version),
        other_code: Some(other_code),
    }
}
fn cap_code(v: CapKind) -> CodeWireV1 {
    match v {
        CapKind::OtherVersioned { version, code } => versioned(v.code(), version, code),
        _ => simple(v.code()),
    }
}
fn error_code(v: FetchErrorCode) -> CodeWireV1 {
    match v {
        FetchErrorCode::OtherVersioned { version, code } => versioned(v.code(), version, code),
        _ => simple(v.code()),
    }
}
fn proof_code(v: CompletenessProof) -> CodeWireV1 {
    match v {
        CompletenessProof::OtherVersioned { version, code } => versioned(v.code(), version, code),
        _ => simple(v.code()),
    }
}
fn partial_code(v: FetchPartialReason) -> CodeWireV1 {
    match v {
        FetchPartialReason::OtherVersioned { version, code } => versioned(v.code(), version, code),
        _ => simple(v.code()),
    }
}
