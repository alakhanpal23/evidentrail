use evidentrail_core::{
    BlockId, BlockIndex, Event, EventId, EventLedger, TransformationReceiptId,
    TransformationReceiptV1,
};
use evidentrail_schema::{ExactnessBasis, NativeMetadataValue, RecordState, SourceStream};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::codec::{BinaryWireV1, parse_hash_token, parse_timestamp};
use crate::{WireErrorV1, decode_artifact};

pub const TRANSFORMATION_RECEIPT_CONTRACT_V1: &str = "evidentrail.transformation_receipt";
pub const EVENT_RECORD_CONTRACT_V1: &str = "evidentrail.event_record";
pub const EVENT_BLOCK_RECORD_CONTRACT_V1: &str = "evidentrail.event_block_record";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    match contract {
        TRANSFORMATION_RECEIPT_CONTRACT_V1 => {
            Some(schemars::schema_for!(TransformationReceiptWireV1))
        }
        EVENT_RECORD_CONTRACT_V1 => Some(schemars::schema_for!(EventRecordWireV1)),
        EVENT_BLOCK_RECORD_CONTRACT_V1 => Some(schemars::schema_for!(EventBlockRecordWireV1)),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransformationReceiptArtifactV1 {
    receipt_id: TransformationReceiptId,
    resulting_event_id: EventId,
    canonical_bytes: Vec<u8>,
}
impl TransformationReceiptArtifactV1 {
    #[must_use]
    pub const fn receipt_id(&self) -> TransformationReceiptId {
        self.receipt_id
    }
    #[must_use]
    pub const fn resulting_event_id(&self) -> EventId {
        self.resulting_event_id
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TransformationReceiptWireV1 {
    contract: String,
    contract_version: u16,
    transformation_receipt_id: String,
    policy_digest: String,
    operations: Vec<ReplacementWireV1>,
    input_length: u64,
    output_length: u64,
    output_content_hash: String,
    output_payload_length: u64,
    output_terminator_length: Option<u64>,
    resulting_event_id: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReplacementWireV1 {
    start: u64,
    end: u64,
    replacement: BinaryWireV1,
}

pub fn encode_transformation_receipt_v1(
    ledger: &EventLedger,
    id: TransformationReceiptId,
) -> Result<TransformationReceiptArtifactV1, WireErrorV1> {
    let receipt = ledger
        .transformation_receipt(id)
        .ok_or(WireErrorV1::CrossContext)?;
    let bytes = canonical_json(&transformation_to_wire(receipt)?)
        .map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_transformation_receipt_v1(&bytes)
}

pub fn decode_transformation_receipt_v1(
    bytes: &[u8],
) -> Result<TransformationReceiptArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != TRANSFORMATION_RECEIPT_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: TransformationReceiptWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    if wire.operations.len() > evidentrail_schema::bounds::MAX_TRANSFORMATION_OPERATIONS {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    let mut prior_end = 0_u64;
    let mut replacement_bytes = 0_u64;
    for operation in &wire.operations {
        if operation.start > operation.end
            || operation.start < prior_end
            || operation.end > wire.input_length
        {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
        replacement_bytes = replacement_bytes
            .checked_add(operation.replacement.decode()?.len() as u64)
            .ok_or(WireErrorV1::SemanticallyInvalid)?;
        prior_end = operation.end;
    }
    let removed = wire
        .operations
        .iter()
        .try_fold(0_u64, |total, op| total.checked_add(op.end - op.start))
        .ok_or(WireErrorV1::SemanticallyInvalid)?;
    if wire
        .input_length
        .checked_sub(removed)
        .and_then(|value| value.checked_add(replacement_bytes))
        != Some(wire.output_length)
        || wire
            .output_payload_length
            .checked_add(wire.output_terminator_length.unwrap_or(0))
            != Some(wire.output_length)
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    parse_hash_token(&wire.policy_digest, "policy_sha256_")?;
    parse_hash_token(&wire.output_content_hash, "sha256_")?;
    let receipt_id = TransformationReceiptId::from_bytes(parse_hash_token(
        &wire.transformation_receipt_id,
        "txrcpt_",
    )?);
    let resulting_event_id =
        EventId::from_bytes(parse_hash_token(&wire.resulting_event_id, "evt_")?);
    Ok(TransformationReceiptArtifactV1 {
        receipt_id,
        resulting_event_id,
        canonical_bytes: bytes.to_vec(),
    })
}

pub fn verify_transformation_receipt_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
) -> Result<TransformationReceiptArtifactV1, WireErrorV1> {
    let artifact = decode_transformation_receipt_v1(bytes)?;
    let expected = encode_transformation_receipt_v1(ledger, artifact.receipt_id)?;
    if expected.canonical_bytes != bytes
        || expected.resulting_event_id != artifact.resulting_event_id
    {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(artifact)
}

fn transformation_to_wire(
    receipt: &TransformationReceiptV1,
) -> Result<TransformationReceiptWireV1, WireErrorV1> {
    Ok(TransformationReceiptWireV1 {
        contract: TRANSFORMATION_RECEIPT_CONTRACT_V1.into(),
        contract_version: 1,
        transformation_receipt_id: receipt.id().to_string(),
        policy_digest: receipt.policy_digest().to_string(),
        operations: receipt
            .operations()
            .iter()
            .map(|operation| {
                Ok(ReplacementWireV1 {
                    start: operation.start(),
                    end: operation.end(),
                    replacement: BinaryWireV1::encode(operation.replacement())?,
                })
            })
            .collect::<Result<_, WireErrorV1>>()?,
        input_length: receipt.input_length(),
        output_length: receipt.output_length(),
        output_content_hash: receipt.output_content_hash().to_string(),
        output_payload_length: receipt.output_payload_length(),
        output_terminator_length: receipt.output_terminator_length(),
        resulting_event_id: receipt.resulting_event_id().to_string(),
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct EventRecordArtifactV1 {
    event_id: EventId,
    canonical_bytes: Vec<u8>,
}
impl EventRecordArtifactV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EventRecordWireV1 {
    contract: String,
    contract_version: u16,
    retrieval_id: String,
    plan_id: String,
    plan_digest: String,
    source_identity_digest: String,
    adapter_kind: String,
    adapter_version: String,
    event_id: String,
    source_record_id: String,
    content_hash: String,
    exactness: ExactnessWireV1,
    ordinal: u64,
    acquisition_sequence: u64,
    lane_member: BinaryWireV1,
    stream: VersionedCodeWireV1,
    lane_sequence: u64,
    payload: BinaryWireV1,
    terminator: Option<BinaryWireV1>,
    native_event_id: Option<BinaryWireV1>,
    cursor: Option<BinaryWireV1>,
    record_state: RecordStateWireV1,
    timestamps: TimestampsWireV1,
    metadata: Option<Vec<MetadataFieldWireV1>>,
    provider_attestations: Vec<AttestationWireV1>,
    format_hint: Option<VersionedCodeWireV1>,
    encoding_hint: Option<VersionedCodeWireV1>,
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VersionedCodeWireV1 {
    code: String,
    version: Option<u16>,
    other_code: Option<u16>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordStateWireV1 {
    code: String,
    reason: Option<VersionedCodeWireV1>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TimestampsWireV1 {
    source_raw: Option<BinaryWireV1>,
    source_parsed_unix_nanos: Option<String>,
    provider_observed_unix_nanos: Option<String>,
    adapter_emitted_unix_nanos: Option<String>,
    adapter_monotonic_nanos: Option<u64>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct MetadataFieldWireV1 {
    name: BinaryWireV1,
    value: MetadataValueWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum MetadataValueWireV1 {
    Null,
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    FloatBits(u64),
    Text(String),
    Bytes(BinaryWireV1),
    Sequence(Vec<MetadataValueWireV1>),
    Map(Vec<MetadataFieldWireV1>),
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AttestationWireV1 {
    scope_digest: String,
    relation_kind: String,
    origin: String,
    value: BinaryWireV1,
}

pub fn encode_event_record_v1(
    ledger: &EventLedger,
    event_id: EventId,
) -> Result<EventRecordArtifactV1, WireErrorV1> {
    let event = ledger
        .event(event_id)
        .map_err(|_| WireErrorV1::CrossContext)?;
    let wire = event_to_wire(ledger, event)?;
    let bytes = canonical_json(&wire).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_event_record_v1(&bytes)
}

pub fn decode_event_record_v1(bytes: &[u8]) -> Result<EventRecordArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != EVENT_RECORD_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: EventRecordWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    validate_event_wire(&wire)?;
    Ok(EventRecordArtifactV1 {
        event_id: EventId::from_bytes(parse_hash_token(&wire.event_id, "evt_")?),
        canonical_bytes: bytes.to_vec(),
    })
}

pub fn verify_event_record_v1_against(
    bytes: &[u8],
    ledger: &EventLedger,
) -> Result<EventRecordArtifactV1, WireErrorV1> {
    let artifact = decode_event_record_v1(bytes)?;
    let expected = encode_event_record_v1(ledger, artifact.event_id)?;
    if expected.canonical_bytes != bytes {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(artifact)
}

fn validate_event_wire(wire: &EventRecordWireV1) -> Result<(), WireErrorV1> {
    parse_hash_token(&wire.retrieval_id, "ret_")?;
    parse_hash_token(&wire.plan_id, "plan_")?;
    parse_hash_token(&wire.plan_digest, "plan_sha256_")?;
    parse_hash_token(&wire.source_identity_digest, "source_sha256_")?;
    parse_hash_token(&wire.event_id, "evt_")?;
    parse_hash_token(&wire.source_record_id, "srec_")?;
    parse_hash_token(&wire.content_hash, "sha256_")?;
    if wire.adapter_kind.is_empty() || wire.adapter_version.is_empty() {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    wire.lane_member.decode()?;
    wire.payload.decode()?;
    if let Some(value) = &wire.terminator {
        if value.decode()?.len() > evidentrail_schema::bounds::MAX_RECORD_TERMINATOR_BYTES {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
    }
    if let Some(value) = &wire.native_event_id {
        value.decode()?;
    }
    if let Some(value) = &wire.cursor {
        value.decode()?;
    }
    if let ExactnessWireV1::PostPolicy {
        policy_digest,
        transformation_receipt_id,
    } = &wire.exactness
    {
        parse_hash_token(policy_digest, "policy_sha256_")?;
        parse_hash_token(transformation_receipt_id, "txrcpt_")?;
    }
    for value in [
        &wire.timestamps.source_parsed_unix_nanos,
        &wire.timestamps.provider_observed_unix_nanos,
        &wire.timestamps.adapter_emitted_unix_nanos,
    ]
    .into_iter()
    .flatten()
    {
        parse_timestamp(value)?;
    }
    if let Some(value) = &wire.timestamps.source_raw {
        value.decode()?;
    }
    if let Some(fields) = &wire.metadata {
        for field in fields {
            field.name.decode()?;
            validate_metadata(&field.value)?;
        }
    }
    for attestation in &wire.provider_attestations {
        parse_hash_token(&attestation.scope_digest, "provider_scope_sha256_").or_else(|_| {
            if attestation.scope_digest.len() == 64 {
                parse_hash_token(
                    &format!("provider_scope_sha256_{}", attestation.scope_digest),
                    "provider_scope_sha256_",
                )
            } else {
                Err(WireErrorV1::SemanticallyInvalid)
            }
        })?;
        attestation.value.decode()?;
    }
    Ok(())
}
fn validate_metadata(value: &MetadataValueWireV1) -> Result<(), WireErrorV1> {
    match value {
        MetadataValueWireV1::Bytes(value) => {
            value.decode()?;
        }
        MetadataValueWireV1::Sequence(values) => {
            for value in values {
                validate_metadata(value)?;
            }
        }
        MetadataValueWireV1::Map(fields) => {
            for field in fields {
                field.name.decode()?;
                validate_metadata(&field.value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn event_to_wire(ledger: &EventLedger, event: &Event) -> Result<EventRecordWireV1, WireErrorV1> {
    let timestamps = event.timestamps();
    Ok(EventRecordWireV1 {
        contract: EVENT_RECORD_CONTRACT_V1.into(),
        contract_version: 1,
        retrieval_id: ledger.retrieval_id().to_string(),
        plan_id: ledger.plan_id().to_string(),
        plan_digest: ledger.plan_digest().to_string(),
        source_identity_digest: ledger.source_identity_digest().to_string(),
        adapter_kind: ledger.adapter().kind().into(),
        adapter_version: ledger.adapter().version().into(),
        event_id: event.id().to_string(),
        source_record_id: event.source_record_id().to_string(),
        content_hash: event.content_hash().to_string(),
        exactness: exactness_to_wire(event.exactness_basis()),
        ordinal: event.ordinal(),
        acquisition_sequence: event.acquisition_sequence().get(),
        lane_member: BinaryWireV1::encode(event.lane().member().as_bytes())?,
        stream: stream_to_wire(event.lane().stream()),
        lane_sequence: event.lane_sequence().get(),
        payload: BinaryWireV1::encode(event.payload())?,
        terminator: event.terminator().map(BinaryWireV1::encode).transpose()?,
        native_event_id: event
            .native_event_id()
            .map(|value| BinaryWireV1::encode(value.as_bytes()))
            .transpose()?,
        cursor: event
            .cursor()
            .map(|value| BinaryWireV1::encode(value.as_bytes()))
            .transpose()?,
        record_state: state_to_wire(event.record_state()),
        timestamps: TimestampsWireV1 {
            source_raw: timestamps
                .source()
                .map(|value| BinaryWireV1::encode(value.raw().as_bytes()))
                .transpose()?,
            source_parsed_unix_nanos: timestamps
                .source()
                .and_then(|value| value.parsed())
                .map(|value| value.get().to_string()),
            provider_observed_unix_nanos: timestamps
                .provider_observed_at()
                .map(|value| value.get().to_string()),
            adapter_emitted_unix_nanos: timestamps
                .adapter_emitted_at()
                .map(|value| value.get().to_string()),
            adapter_monotonic_nanos: timestamps.adapter_monotonic_time().map(|value| value.get()),
        },
        metadata: event
            .metadata()
            .map(|value| {
                value
                    .fields()
                    .iter()
                    .map(metadata_field_to_wire)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
        provider_attestations: event
            .provider_attestations()
            .entries()
            .iter()
            .map(|value| {
                Ok(AttestationWireV1 {
                    scope_digest: hex(value.scope_digest().as_bytes()),
                    relation_kind: value.relation_kind().code().into(),
                    origin: value.origin().code().into(),
                    value: BinaryWireV1::encode(value.value().as_bytes())?,
                })
            })
            .collect::<Result<_, WireErrorV1>>()?,
        format_hint: event
            .hints()
            .format()
            .map(|value| simple_code(value.code())),
        encoding_hint: event
            .hints()
            .encoding()
            .map(|value| simple_code(value.code())),
    })
}
fn exactness_to_wire(value: ExactnessBasis) -> ExactnessWireV1 {
    match value {
        ExactnessBasis::SourceExact => ExactnessWireV1::SourceExact,
        ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        } => ExactnessWireV1::PostPolicy {
            policy_digest: policy_digest.to_string(),
            transformation_receipt_id: transformation_receipt_id.to_string(),
        },
    }
}
fn stream_to_wire(value: &SourceStream) -> VersionedCodeWireV1 {
    match value {
        SourceStream::OtherVersioned { version, code } => VersionedCodeWireV1 {
            code: value.code().into(),
            version: Some(*version),
            other_code: Some(*code),
        },
        _ => simple_code(value.code()),
    }
}
fn simple_code(code: &str) -> VersionedCodeWireV1 {
    VersionedCodeWireV1 {
        code: code.into(),
        version: None,
        other_code: None,
    }
}
fn state_to_wire(value: RecordState) -> RecordStateWireV1 {
    match value {
        RecordState::Complete => RecordStateWireV1 {
            code: value.code().into(),
            reason: None,
        },
        RecordState::SourceTruncated { reason } | RecordState::AdapterFragment { reason } => {
            RecordStateWireV1 {
                code: value.code().into(),
                reason: Some(simple_code(reason.code())),
            }
        }
    }
}
fn metadata_field_to_wire(
    value: &evidentrail_schema::NativeMetadataField,
) -> Result<MetadataFieldWireV1, WireErrorV1> {
    Ok(MetadataFieldWireV1 {
        name: BinaryWireV1::encode(value.name())?,
        value: metadata_to_wire(value.value())?,
    })
}
fn metadata_to_wire(value: &NativeMetadataValue) -> Result<MetadataValueWireV1, WireErrorV1> {
    Ok(match value {
        NativeMetadataValue::Null => MetadataValueWireV1::Null,
        NativeMetadataValue::Boolean(value) => MetadataValueWireV1::Boolean(*value),
        NativeMetadataValue::Signed(value) => MetadataValueWireV1::Signed(*value),
        NativeMetadataValue::Unsigned(value) => MetadataValueWireV1::Unsigned(*value),
        NativeMetadataValue::FloatBits(value) => MetadataValueWireV1::FloatBits(*value),
        NativeMetadataValue::Text(value) => MetadataValueWireV1::Text(value.clone()),
        NativeMetadataValue::Bytes(value) => {
            MetadataValueWireV1::Bytes(BinaryWireV1::encode(value)?)
        }
        NativeMetadataValue::Sequence(values) => MetadataValueWireV1::Sequence(
            values
                .iter()
                .map(metadata_to_wire)
                .collect::<Result<_, _>>()?,
        ),
        NativeMetadataValue::Map(fields) => MetadataValueWireV1::Map(
            fields
                .iter()
                .map(metadata_field_to_wire)
                .collect::<Result<_, _>>()?,
        ),
    })
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

#[derive(Clone, PartialEq, Eq)]
pub struct EventBlockRecordArtifactV1 {
    block_id: BlockId,
    canonical_bytes: Vec<u8>,
}
impl EventBlockRecordArtifactV1 {
    #[must_use]
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EventBlockRecordWireV1 {
    contract: String,
    contract_version: u16,
    retrieval_id: String,
    block_id: String,
    ordinal: u64,
    lane_member: BinaryWireV1,
    stream: VersionedCodeWireV1,
    ordered_event_ids: Vec<String>,
    lane_sequences: Vec<u64>,
    framing_policy: BinaryWireV1,
    framing_policy_version: BinaryWireV1,
    state: String,
    confidence: String,
}

pub fn encode_event_block_record_v1(
    index: &BlockIndex<'_>,
    block_id: BlockId,
) -> Result<EventBlockRecordArtifactV1, WireErrorV1> {
    let block = index
        .block(block_id)
        .map_err(|_| WireErrorV1::CrossContext)?;
    let wire = EventBlockRecordWireV1 {
        contract: EVENT_BLOCK_RECORD_CONTRACT_V1.into(),
        contract_version: 1,
        retrieval_id: index.retrieval_id().to_string(),
        block_id: block.id().to_string(),
        ordinal: block.ordinal(),
        lane_member: BinaryWireV1::encode(block.lane().member().as_bytes())?,
        stream: stream_to_wire(block.lane().stream()),
        ordered_event_ids: block.member_ids().iter().map(ToString::to_string).collect(),
        lane_sequences: block
            .member_lane_sequences()
            .iter()
            .map(|value| value.get())
            .collect(),
        framing_policy: BinaryWireV1::encode(block.framing_policy().policy())?,
        framing_policy_version: BinaryWireV1::encode(block.framing_policy().version())?,
        state: block.state().code().into(),
        confidence: block.confidence().code().into(),
    };
    let bytes = canonical_json(&wire).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode_event_block_record_v1(&bytes)
}

pub fn decode_event_block_record_v1(
    bytes: &[u8],
) -> Result<EventBlockRecordArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != EVENT_BLOCK_RECORD_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: EventBlockRecordWireV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    if wire.ordered_event_ids.is_empty()
        || wire.ordered_event_ids.len() > evidentrail_schema::bounds::MAX_EVENT_BLOCK_MEMBERS
        || wire.ordered_event_ids.len() != wire.lane_sequences.len()
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    parse_hash_token(&wire.retrieval_id, "ret_")?;
    let block_id = BlockId::from_bytes(parse_hash_token(&wire.block_id, "blk_")?);
    wire.lane_member.decode()?;
    wire.framing_policy.decode()?;
    wire.framing_policy_version.decode()?;
    let mut prior = None;
    for (id, sequence) in wire.ordered_event_ids.iter().zip(&wire.lane_sequences) {
        parse_hash_token(id, "evt_")?;
        if prior.is_some_and(|value| value + 1 != *sequence) {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
        prior = Some(*sequence);
    }
    Ok(EventBlockRecordArtifactV1 {
        block_id,
        canonical_bytes: bytes.to_vec(),
    })
}

pub fn verify_event_block_record_v1_against(
    bytes: &[u8],
    index: &BlockIndex<'_>,
) -> Result<EventBlockRecordArtifactV1, WireErrorV1> {
    let artifact = decode_event_block_record_v1(bytes)?;
    let expected = encode_event_block_record_v1(index, artifact.block_id)?;
    if expected.canonical_bytes != bytes {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(artifact)
}
