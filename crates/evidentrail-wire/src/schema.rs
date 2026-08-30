use serde_json::{Map, Value, json};

use crate::canonical::canonical_json;
use crate::{ContractDescriptorV1, WireErrorV1, contract_registry_v1};

/// Deterministically generated Draft 2020-12 structural schemas.
pub fn schema_documents_v1() -> Result<Vec<(&'static str, Vec<u8>)>, WireErrorV1> {
    contract_registry_v1()
        .into_iter()
        .map(|descriptor| {
            let sample = sample_for(descriptor)?;
            let mut schema = generated_schema(descriptor.name())
                .and_then(|schema| serde_json::to_value(schema).ok())
                .unwrap_or_else(|| infer_schema(&sample, None));
            constrain_schema(&mut schema, None);
            let object = schema
                .as_object_mut()
                .ok_or(WireErrorV1::CanonicalizationFailed)?;
            object.insert("$id".into(), Value::String(descriptor.schema_path().into()));
            object.insert(
                "$schema".into(),
                Value::String("https://json-schema.org/draft/2020-12/schema".into()),
            );
            object.insert("title".into(), Value::String(descriptor.name().into()));
            let properties = object
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .ok_or(WireErrorV1::CanonicalizationFailed)?;
            properties
                .get_mut("contract")
                .and_then(Value::as_object_mut)
                .ok_or(WireErrorV1::CanonicalizationFailed)?
                .insert("const".into(), Value::String(descriptor.name().into()));
            properties
                .get_mut("contract_version")
                .and_then(Value::as_object_mut)
                .ok_or(WireErrorV1::CanonicalizationFailed)?
                .insert("const".into(), Value::from(1_u64));
            canonical_json(&schema)
                .map(|bytes| (descriptor.schema_path(), bytes))
                .map_err(|_| WireErrorV1::CanonicalizationFailed)
        })
        .collect()
}

fn generated_schema(_contract: &str) -> Option<schemars::Schema> {
    #[cfg(feature = "ledger")]
    if let Some(schema) = crate::ledger::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    #[cfg(feature = "ledger")]
    if let Some(schema) = crate::fetch::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    #[cfg(feature = "ledger")]
    if let Some(schema) = crate::receipts::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    #[cfg(feature = "product")]
    if let Some(schema) = crate::product::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    #[cfg(feature = "product")]
    if let Some(schema) = crate::log_brief::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    #[cfg(feature = "bench")]
    if let Some(schema) = crate::bench::schema_for_contract_v1(_contract) {
        return Some(schema);
    }
    None
}

fn constrain_schema(schema: &mut Value, field_name: Option<&str>) {
    match schema {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("array") {
                let maximum = if field_name == Some("operations") {
                    evidentrail_schema::bounds::MAX_TRANSFORMATION_OPERATIONS
                } else {
                    evidentrail_schema::bounds::MAX_RECEIPT_CHUNK_ENTRIES
                };
                object.insert("maxItems".into(), Value::from(maximum as u64));
            }
            if object.get("type").and_then(Value::as_str) == Some("integer") {
                object.insert("maximum".into(), Value::from(9_007_199_254_740_991_u64));
            }
            if object.get("type").and_then(Value::as_str) == Some("string") {
                if let Some(pattern) = field_name.and_then(pattern_for_field) {
                    object.insert("pattern".into(), Value::String(pattern.into()));
                }
                if field_name == Some("encoding") {
                    object.insert("const".into(), Value::String("base64url-nopad".into()));
                }
            }
            for (name, child) in object {
                let child_field = if name == "properties" {
                    None
                } else {
                    field_name
                };
                if name == "properties" {
                    if let Value::Object(properties) = child {
                        for (property_name, property_schema) in properties {
                            constrain_schema(property_schema, Some(property_name));
                        }
                    }
                } else if name == "items" {
                    constrain_schema(child, field_name);
                } else if matches!(name.as_str(), "anyOf" | "oneOf" | "allOf" | "$defs") {
                    constrain_schema(child, child_field);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                constrain_schema(value, field_name);
            }
        }
        _ => {}
    }
}

fn pattern_for_field(field: &str) -> Option<&'static str> {
    match field {
        "retrieval_id" => Some("^ret_[0-9a-f]{64}$"),
        "plan_id" => Some("^plan_[0-9a-f]{64}$"),
        "plan_digest" => Some("^plan_sha256_[0-9a-f]{64}$"),
        "source_identity_digest" => Some("^source_sha256_[0-9a-f]{64}$"),
        "source_record_id" => Some("^srec_[0-9a-f]{64}$"),
        "event_id" | "resulting_event_id" => Some("^evt_[0-9a-f]{64}$"),
        "block_id" => Some("^blk_[0-9a-f]{64}$"),
        "content_hash" | "output_content_hash" => Some("^sha256_[0-9a-f]{64}$"),
        "policy_digest" => Some("^policy_sha256_[0-9a-f]{64}$"),
        "transformation_receipt_id" => Some("^txrcpt_[0-9a-f]{64}$"),
        "question_digest" => Some("^question_sha256_[0-9a-f]{64}$"),
        "evidence_reference_id" => Some("^eref_[0-9a-f]{64}$"),
        "acquisition_receipt_id" => Some("^acqrcpt_[0-9a-f]{64}$"),
        "presentation_receipt_id" => Some("^prcpt_[0-9a-f]{64}$"),
        "pattern_id" => Some("^pat_[0-9a-f]{64}$"),
        "result_id" => Some("^result_[0-9a-f]{64}$"),
        "renderer_digest" | "tokenizer_digest" => Some("^artifact_sha256_[0-9a-f]{64}$"),
        name if name.ends_with("artifact_digest") => Some("^artifact_sha256_[0-9a-f]{64}$"),
        name if name.ends_with("unix_nanos") || name.ends_with("_ns") => {
            Some("^-?(0|[1-9][0-9]*)$")
        }
        "data" => Some("^[A-Za-z0-9_-]*$"),
        _ => None,
    }
}

/// One immutable canonical dispatch fixture per registry entry.
pub fn golden_documents_v1() -> Result<Vec<(String, Vec<u8>)>, WireErrorV1> {
    contract_registry_v1()
        .into_iter()
        .map(|descriptor| {
            let value = sample_for(descriptor)?;
            let filename = format!(
                "crates/evidentrail-wire/tests/fixtures/golden/{}.json",
                descriptor.name().replace('.', "_")
            );
            canonical_json(&value)
                .map(|bytes| (filename, bytes))
                .map_err(|_| WireErrorV1::CanonicalizationFailed)
        })
        .collect()
}

fn sample_for(descriptor: ContractDescriptorV1) -> Result<Value, WireErrorV1> {
    let bytes: Option<&'static [u8]> = match descriptor.name() {
        "evidentrail.approved_local_file_binding" => Some(include_bytes!(
            "../tests/fixtures/approved_local_file_binding_v1/golden.json"
        )),
        "evidentrail.local_file_query_plan" => Some(include_bytes!(
            "../tests/fixtures/local_file_plan_v1/golden.json"
        )),
        _ => None,
    };
    match bytes {
        Some(bytes) => serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed),
        None => Ok(contract_sample(descriptor.name())),
    }
}

fn contract_sample(contract: &str) -> Value {
    let z = |prefix: &str| format!("{}{}", prefix, "0".repeat(64));
    let b = || json!({"byte_length":0,"data":"","encoding":"base64url-nopad"});
    match contract {
        "evidentrail.transformation_receipt" => {
            json!({"contract":contract,"contract_version":1,"input_length":0,"operations":[],"output_content_hash":z("sha256_"),"output_length":0,"output_payload_length":0,"output_terminator_length":null,"policy_digest":z("policy_sha256_"),"resulting_event_id":z("evt_"),"transformation_receipt_id":z("txrcpt_")})
        }
        "evidentrail.event_record" => {
            json!({"acquisition_sequence":0,"adapter_kind":"fixture","adapter_version":"1","content_hash":z("sha256_"),"contract":contract,"contract_version":1,"cursor":null,"encoding_hint":null,"event_id":z("evt_"),"exactness":{"kind":"source_exact"},"format_hint":null,"lane_member":b(),"lane_sequence":0,"metadata":null,"native_event_id":null,"ordinal":0,"payload":b(),"plan_digest":z("plan_sha256_"),"plan_id":z("plan_"),"provider_attestations":[],"record_state":{"code":"complete","reason":null},"retrieval_id":z("ret_"),"source_identity_digest":z("source_sha256_"),"source_record_id":z("srec_"),"stream":{"code":"stdout","other_code":null,"version":null},"terminator":null,"timestamps":{"adapter_emitted_unix_nanos":null,"adapter_monotonic_nanos":null,"provider_observed_unix_nanos":null,"source_parsed_unix_nanos":null,"source_raw":null}})
        }
        "evidentrail.event_block_record" => {
            json!({"block_id":z("blk_"),"confidence":"certain","contract":contract,"contract_version":1,"framing_policy":b(),"framing_policy_version":b(),"lane_member":b(),"lane_sequences":[0],"ordered_event_ids":[z("evt_")],"ordinal":0,"retrieval_id":z("ret_"),"state":"fallback_singleton","stream":{"code":"stdout","other_code":null,"version":null}})
        }
        "evidentrail.fetch_completion" => {
            json!({"acknowledged_payload_bytes":0,"acknowledged_records":0,"acknowledged_source_bytes":0,"adapter_kind":"fixture","adapter_outcome":"finished","adapter_version":"1","cap_usage":[],"completeness":{"proof":{"code":"in_memory_fixture_exhausted","other_code":null,"version":null},"state":"complete"},"contract":contract,"contract_version":1,"ended_at_unix_nanos":"0","error_codes":[],"final_cursor":null,"first_cursor":null,"high_water_marks":[],"members_attempted":0,"members_completed":0,"pages_attempted":0,"pages_completed":0,"plan_digest":z("plan_sha256_"),"plan_id":z("plan_"),"retrieval_id":z("ret_"),"started_at_unix_nanos":"0"})
        }
        "evidentrail.acquisition_receipt" => receipt_manifest(contract, &z("acqrcpt_"), &z("ret_")),
        "evidentrail.presentation_receipt" => receipt_manifest(contract, &z("prcpt_"), &z("ret_")),
        "evidentrail.acquisition_receipt_chunk" => {
            json!({"chunk_index":0,"contract":contract,"contract_version":1,"entries":[],"entry_offset":0,"receipt_id":z("acqrcpt_"),"retrieval_id":z("ret_")})
        }
        "evidentrail.presentation_receipt_chunk" => {
            json!({"chunk_index":0,"contract":contract,"contract_version":1,"entries":[],"entry_offset":0,"receipt_id":z("prcpt_"),"retrieval_id":z("ret_")})
        }
        "evidentrail.evidence_reference" => {
            json!({"allowed_relations":["exact"],"contract":contract,"contract_version":1,"evidence_reference_id":z("eref_"),"expires_at_unix_nanos":"1","issued_at_unix_nanos":"0","result_id":z("result_"),"targets":[{"event_id":z("evt_"),"kind":"event"}]})
        }
        "evidentrail.result_status" => {
            json!({"acquisition":{"state":"complete"},"contract":contract,"contract_version":1,"pattern_represented":0,"persisted_event_count":0,"presentation_receipt_id":z("prcpt_"),"retained_raw":0,"selection":{"state":"needs_more","reason":"question_unsupported"},"shown_verbatim":0})
        }
        "evidentrail.expansion_request" => {
            json!({"after":0,"before":0,"contract":contract,"contract_version":1,"evidence_reference_id":z("eref_"),"max_bytes":1,"max_events":1,"relation":"exact","result_id":z("result_")})
        }
        "evidentrail.expansion_response" => {
            json!({"contract":contract,"contract_version":1,"events":[],"evidence_reference_id":z("eref_"),"relation":"exact","result_id":z("result_"),"returned_bytes":0,"truncated":false})
        }
        "evidentrail.log_brief" => {
            json!({"contract":contract,"contract_version":1,"rendered_byte_count":0,"rendered_text":"","rendered_token_count":0,"renderer_digest":z("artifact_sha256_"),"structured":{"accounted_token_upper_bound":0,"acknowledged_records":0,"acquisition_receipt_id":z("acqrcpt_"),"acquisition_state":"complete","evidence":[],"needs_more_reason":"question_unsupported","omitted_by_policy_records":0,"pattern_represented":0,"plan_digest":z("plan_sha256_"),"post_policy_records":0,"presentation_receipt_id":z("prcpt_"),"question_digest":z("question_sha256_"),"reference_authorized_at_unix_nanos":"0","result_id":z("result_"),"retained_raw":0,"selection_state":"needs_more","shown_verbatim":0,"source_exact_records":0,"total_token_limit":0,"untrusted_data":true},"tokenizer_digest":z("artifact_sha256_"),"variant":"needs_more"})
        }
        "evidentrail.bench.case_manifest" => {
            json!({"budget_points":[budget_sample()],"contract":contract,"contract_version":1,"expected_acquisition_class":"complete","leakage_artifact_digests":[z("artifact_sha256_")],"plan_digest":z("plan_sha256_"),"question_digest":z("question_sha256_"),"source_artifact_digests":[z("artifact_sha256_")],"split_artifact_digests":[z("artifact_sha256_")]})
        }
        "evidentrail.bench.annotation_manifest" => {
            json!({"contract":contract,"contract_version":1,"diagnostic_requirements":[{"alternatives":[[{"event_id":z("evt_"),"kind":"event"}]],"weight_micros":1}],"distractor_targets":null,"precursor_targets":null,"public_case_artifact_digest":z("artifact_sha256_"),"supporting_targets":null,"symptom_targets":null,"unsafe_targets":null})
        }
        "evidentrail.bench.run_manifest" => {
            json!({"budget":budget_sample(),"build_artifact_digest":z("artifact_sha256_"),"contract":contract,"contract_version":1,"dataset_artifact_digest":z("artifact_sha256_"),"public_case_artifact_digests":[z("artifact_sha256_")],"seed":0,"system_artifact_digest":z("artifact_sha256_")})
        }
        "evidentrail.bench.hidden_evaluation_manifest" => {
            json!({"annotation_set_artifact_digest":z("artifact_sha256_"),"case_bindings":[{"annotation_artifact_digest":z("artifact_sha256_"),"public_case_artifact_digest":z("artifact_sha256_")}],"contract":contract,"contract_version":1,"public_run_manifest_artifact_digest":z("artifact_sha256_"),"scoring_spec_artifact_digest":z("artifact_sha256_")})
        }
        _ => json!({"contract":contract,"contract_version":1}),
    }
}

fn receipt_manifest(contract: &str, receipt: &str, retrieval: &str) -> Value {
    json!({"chunk_count":0,"chunk_digests":[],"contract":contract,"contract_version":1,"entry_count":0,"receipt_id":receipt,"retrieval_id":retrieval})
}
fn budget_sample() -> Value {
    json!({"canonical_candidate_tokens":0,"peak_memory_bytes":0,"unique_candidate_event_count":0,"unique_candidate_source_bytes":0,"wall_time_nanos":0})
}

fn infer_schema(value: &Value, field_name: Option<&str>) -> Value {
    match value {
        Value::Object(fields) => {
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (name, value) in fields {
                let mut child = infer_schema(value, Some(name));
                if name == "contract" || name == "encoding" || name == "contract_version" {
                    child
                        .as_object_mut()
                        .expect("scalar schema")
                        .insert("const".into(), value.clone());
                }
                properties.insert(name.clone(), child);
                required.push(Value::String(name.clone()));
            }
            json!({"additionalProperties":false,"properties":properties,"required":required,"type":"object"})
        }
        Value::Array(values) => {
            json!({"items":values.first().map(|value|infer_schema(value,None)).unwrap_or_else(||json!({})),"maxItems":4096,"type":"array"})
        }
        Value::String(text) => {
            let mut schema = json!({"type":"string"});
            if let Some(pattern) = string_pattern(text, field_name) {
                schema
                    .as_object_mut()
                    .expect("string schema")
                    .insert("pattern".into(), Value::String(pattern));
            }
            schema
        }
        Value::Number(_) => {
            json!({"maximum":9_007_199_254_740_991_u64,"minimum":0,"type":"integer"})
        }
        Value::Bool(_) => json!({"type":"boolean"}),
        Value::Null => json!({"type":"null"}),
    }
}

fn string_pattern(text: &str, field_name: Option<&str>) -> Option<String> {
    if field_name.is_some_and(|name| name.ends_with("unix_nanos") || name.ends_with("_ns")) {
        return Some("^-?(0|[1-9][0-9]*)$".into());
    }
    if field_name == Some("data") {
        return Some("^[A-Za-z0-9_-]*$".into());
    }
    const PREFIXES: &[&str] = &[
        "ret_",
        "plan_",
        "plan_sha256_",
        "source_sha256_",
        "srec_",
        "evt_",
        "blk_",
        "sha256_",
        "policy_sha256_",
        "txrcpt_",
        "question_sha256_",
        "eref_",
        "artifact_sha256_",
        "acqrcpt_",
        "prcpt_",
        "pat_",
        "bind_",
        "binding_sha256_",
        "repo_sha256_",
        "internal_path_policy_sha256_",
        "local_file_certification_profile_sha256_",
    ];
    PREFIXES
        .iter()
        .filter(|prefix| text.starts_with(**prefix))
        .max_by_key(|prefix| prefix.len())
        .map(|prefix| format!("^{prefix}[0-9a-f]{{64}}$"))
}
