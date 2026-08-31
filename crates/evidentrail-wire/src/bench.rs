use evidentrail_bench::{
    CandidateResourceCap, EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::codec::parse_hash_token;
use crate::{WireErrorV1, decode_artifact};

pub const BENCH_CASE_MANIFEST_CONTRACT_V1: &str = "evidentrail.bench.case_manifest";
pub const BENCH_ANNOTATION_MANIFEST_CONTRACT_V1: &str = "evidentrail.bench.annotation_manifest";
pub const BENCH_RUN_MANIFEST_CONTRACT_V1: &str = "evidentrail.bench.run_manifest";
pub const BENCH_HIDDEN_EVALUATION_MANIFEST_CONTRACT_V1: &str =
    "evidentrail.bench.hidden_evaluation_manifest";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    match contract {
        BENCH_CASE_MANIFEST_CONTRACT_V1 => Some(schemars::schema_for!(CaseWire)),
        BENCH_ANNOTATION_MANIFEST_CONTRACT_V1 => Some(schemars::schema_for!(AnnotationWire)),
        BENCH_RUN_MANIFEST_CONTRACT_V1 => Some(schemars::schema_for!(RunWire)),
        BENCH_HIDDEN_EVALUATION_MANIFEST_CONTRACT_V1 => Some(schemars::schema_for!(HiddenWire)),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BenchArtifactV1 {
    canonical_bytes: Vec<u8>,
}
impl BenchArtifactV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BudgetWire {
    unique_candidate_event_count: u64,
    unique_candidate_source_bytes: u64,
    canonical_candidate_tokens: u64,
    wall_time_nanos: u64,
    peak_memory_bytes: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CaseWire {
    contract: String,
    contract_version: u16,
    source_artifact_digests: Vec<String>,
    question_digest: String,
    plan_digest: String,
    split_artifact_digests: Vec<String>,
    leakage_artifact_digests: Vec<String>,
    budget_points: Vec<BudgetWire>,
    expected_acquisition_class: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TargetWire {
    Event { event_id: String },
    Block { block_id: String },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RequirementWire {
    weight_micros: u64,
    alternatives: Vec<Vec<TargetWire>>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AnnotationWire {
    contract: String,
    contract_version: u16,
    public_case_artifact_digest: String,
    diagnostic_requirements: Vec<RequirementWire>,
    precursor_targets: Option<Vec<TargetWire>>,
    symptom_targets: Option<Vec<TargetWire>>,
    supporting_targets: Option<Vec<TargetWire>>,
    distractor_targets: Option<Vec<TargetWire>>,
    unsafe_targets: Option<Vec<TargetWire>>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RunWire {
    contract: String,
    contract_version: u16,
    system_artifact_digest: String,
    build_artifact_digest: String,
    dataset_artifact_digest: String,
    seed: u64,
    budget: BudgetWire,
    public_case_artifact_digests: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    public_case_artifact_digest: String,
    annotation_artifact_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HiddenWire {
    contract: String,
    contract_version: u16,
    public_run_manifest_artifact_digest: String,
    annotation_set_artifact_digest: String,
    scoring_spec_artifact_digest: String,
    case_bindings: Vec<BindingWire>,
}

pub fn encode_bench_case_manifest_v1(
    value: &EvidentrailBenchCaseSpecV1,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let wire = CaseWire {
        contract: BENCH_CASE_MANIFEST_CONTRACT_V1.into(),
        contract_version: 1,
        source_artifact_digests: value
            .source_artifact_digests()
            .iter()
            .map(ToString::to_string)
            .collect(),
        question_digest: value.question_digest().to_string(),
        plan_digest: value.plan_digest().to_string(),
        split_artifact_digests: value
            .split_artifact_digests()
            .iter()
            .map(ToString::to_string)
            .collect(),
        leakage_artifact_digests: value
            .leakage_artifact_digests()
            .iter()
            .map(ToString::to_string)
            .collect(),
        budget_points: value.budget_points().iter().copied().map(budget).collect(),
        expected_acquisition_class: value.expected_acquisition_class().code().into(),
    };
    encode_decode(&wire, decode_bench_case_manifest_v1)
}
pub fn decode_bench_case_manifest_v1(bytes: &[u8]) -> Result<BenchArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != BENCH_CASE_MANIFEST_CONTRACT_V1 {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let wire: CaseWire = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    for digest in wire
        .source_artifact_digests
        .iter()
        .chain(&wire.split_artifact_digests)
        .chain(&wire.leakage_artifact_digests)
    {
        parse_hash_token(digest, "artifact_sha256_")?;
    }
    parse_hash_token(&wire.question_digest, "question_sha256_")?;
    parse_hash_token(&wire.plan_digest, "plan_sha256_")?;
    Ok(BenchArtifactV1 {
        canonical_bytes: bytes.to_vec(),
    })
}
pub fn encode_bench_annotation_manifest_v1(
    value: &EvidentrailBenchAnnotationSpecV1,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let map = |values: Option<&[EvidenceTargetV1]>| {
        values.map(|v| v.iter().copied().map(target).collect())
    };
    let wire = AnnotationWire {
        contract: BENCH_ANNOTATION_MANIFEST_CONTRACT_V1.into(),
        contract_version: 1,
        public_case_artifact_digest: value.public_case_artifact_digest().to_string(),
        diagnostic_requirements: value
            .diagnostic_requirements()
            .iter()
            .map(|r| RequirementWire {
                weight_micros: r.weight_micros(),
                alternatives: r
                    .alternatives()
                    .iter()
                    .map(|a| a.iter().copied().map(target).collect())
                    .collect(),
            })
            .collect(),
        precursor_targets: map(value.precursor_targets()),
        symptom_targets: map(value.symptom_targets()),
        supporting_targets: map(value.supporting_targets()),
        distractor_targets: map(value.distractor_targets()),
        unsafe_targets: map(value.unsafe_targets()),
    };
    encode_decode(&wire, decode_bench_annotation_manifest_v1)
}
pub fn decode_bench_annotation_manifest_v1(bytes: &[u8]) -> Result<BenchArtifactV1, WireErrorV1> {
    let artifact = decode_typed::<AnnotationWire>(bytes, BENCH_ANNOTATION_MANIFEST_CONTRACT_V1)?;
    let wire: AnnotationWire = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    parse_hash_token(&wire.public_case_artifact_digest, "artifact_sha256_")?;
    for requirement in &wire.diagnostic_requirements {
        for alternative in &requirement.alternatives {
            for target in alternative {
                validate_target(target)?;
            }
        }
    }
    for targets in [
        wire.precursor_targets.as_deref(),
        wire.symptom_targets.as_deref(),
        wire.supporting_targets.as_deref(),
        wire.distractor_targets.as_deref(),
        wire.unsafe_targets.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for target in targets {
            validate_target(target)?;
        }
    }
    Ok(artifact)
}
pub fn encode_bench_run_manifest_v1(
    value: &EvidentrailBenchRunManifestV1,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let id = value.identity();
    let wire = RunWire {
        contract: BENCH_RUN_MANIFEST_CONTRACT_V1.into(),
        contract_version: 1,
        system_artifact_digest: id.system_artifact_digest().to_string(),
        build_artifact_digest: id.build_artifact_digest().to_string(),
        dataset_artifact_digest: id.dataset_artifact_digest().to_string(),
        seed: id.seed(),
        budget: budget(id.budget().cap()),
        public_case_artifact_digests: value
            .public_case_artifact_digests()
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    encode_decode(&wire, decode_bench_run_manifest_v1)
}
pub fn decode_bench_run_manifest_v1(bytes: &[u8]) -> Result<BenchArtifactV1, WireErrorV1> {
    let artifact = decode_typed::<RunWire>(bytes, BENCH_RUN_MANIFEST_CONTRACT_V1)?;
    let wire: RunWire = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    for digest in [
        &wire.system_artifact_digest,
        &wire.build_artifact_digest,
        &wire.dataset_artifact_digest,
    ]
    .into_iter()
    .chain(&wire.public_case_artifact_digests)
    {
        parse_hash_token(digest, "artifact_sha256_")?;
    }
    Ok(artifact)
}
pub fn encode_bench_hidden_evaluation_manifest_v1(
    value: &EvidentrailBenchHiddenEvaluationManifestV1,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let wire = HiddenWire {
        contract: BENCH_HIDDEN_EVALUATION_MANIFEST_CONTRACT_V1.into(),
        contract_version: 1,
        public_run_manifest_artifact_digest: value
            .public_run_manifest_artifact_digest()
            .to_string(),
        annotation_set_artifact_digest: value.annotation_set_artifact_digest().to_string(),
        scoring_spec_artifact_digest: value.scoring_spec_artifact_digest().to_string(),
        case_bindings: value
            .case_bindings()
            .iter()
            .map(|v| BindingWire {
                public_case_artifact_digest: v.public_case_artifact_digest().to_string(),
                annotation_artifact_digest: v.annotation_artifact_digest().to_string(),
            })
            .collect(),
    };
    encode_decode(&wire, decode_bench_hidden_evaluation_manifest_v1)
}
pub fn decode_bench_hidden_evaluation_manifest_v1(
    bytes: &[u8],
) -> Result<BenchArtifactV1, WireErrorV1> {
    let artifact = decode_typed::<HiddenWire>(bytes, BENCH_HIDDEN_EVALUATION_MANIFEST_CONTRACT_V1)?;
    let wire: HiddenWire = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    for digest in [
        &wire.public_run_manifest_artifact_digest,
        &wire.annotation_set_artifact_digest,
        &wire.scoring_spec_artifact_digest,
    ] {
        parse_hash_token(digest, "artifact_sha256_")?;
    }
    for binding in &wire.case_bindings {
        parse_hash_token(&binding.public_case_artifact_digest, "artifact_sha256_")?;
        parse_hash_token(&binding.annotation_artifact_digest, "artifact_sha256_")?;
    }
    Ok(artifact)
}

pub fn verify_bench_case_manifest_v1_against(
    artifact: &BenchArtifactV1,
    value: &EvidentrailBenchCaseSpecV1,
) -> Result<(), WireErrorV1> {
    verify_exact(artifact, encode_bench_case_manifest_v1(value)?)
}

pub fn verify_bench_annotation_manifest_v1_against(
    artifact: &BenchArtifactV1,
    value: &EvidentrailBenchAnnotationSpecV1,
) -> Result<(), WireErrorV1> {
    verify_exact(artifact, encode_bench_annotation_manifest_v1(value)?)
}

pub fn verify_bench_run_manifest_v1_against(
    artifact: &BenchArtifactV1,
    value: &EvidentrailBenchRunManifestV1,
) -> Result<(), WireErrorV1> {
    verify_exact(artifact, encode_bench_run_manifest_v1(value)?)
}

pub fn verify_bench_hidden_evaluation_manifest_v1_against(
    artifact: &BenchArtifactV1,
    value: &EvidentrailBenchHiddenEvaluationManifestV1,
) -> Result<(), WireErrorV1> {
    verify_exact(artifact, encode_bench_hidden_evaluation_manifest_v1(value)?)
}

fn verify_exact(artifact: &BenchArtifactV1, expected: BenchArtifactV1) -> Result<(), WireErrorV1> {
    if artifact.canonical_bytes == expected.canonical_bytes {
        Ok(())
    } else {
        Err(WireErrorV1::CrossContext)
    }
}

fn validate_target(target: &TargetWire) -> Result<(), WireErrorV1> {
    match target {
        TargetWire::Event { event_id } => parse_hash_token(event_id, "evt_").map(|_| ()),
        TargetWire::Block { block_id } => parse_hash_token(block_id, "blk_").map(|_| ()),
    }
}

fn encode_decode<T: Serialize>(
    value: &T,
    decode: fn(&[u8]) -> Result<BenchArtifactV1, WireErrorV1>,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let bytes = canonical_json(value).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    decode(&bytes)
}
fn decode_typed<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
    contract: &str,
) -> Result<BenchArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(bytes)?;
    if artifact.descriptor().name() != contract {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let _: T = serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    Ok(BenchArtifactV1 {
        canonical_bytes: bytes.to_vec(),
    })
}
fn budget(v: CandidateResourceCap) -> BudgetWire {
    BudgetWire {
        unique_candidate_event_count: v.unique_candidate_event_count(),
        unique_candidate_source_bytes: v.unique_candidate_source_bytes(),
        canonical_candidate_tokens: v.canonical_candidate_tokens(),
        wall_time_nanos: v.wall_time_nanos(),
        peak_memory_bytes: v.peak_memory_bytes(),
    }
}
fn target(v: EvidenceTargetV1) -> TargetWire {
    match v {
        EvidenceTargetV1::Event(id) => TargetWire::Event {
            event_id: id.to_string(),
        },
        EvidenceTargetV1::Block(id) => TargetWire::Block {
            block_id: id.to_string(),
        },
    }
}
