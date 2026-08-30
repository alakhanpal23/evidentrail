use std::collections::BTreeSet;

use evidentrail_wire::{
    WireErrorV1, contract_registry_v1, decode_artifact, golden_documents_v1, migration_registry_v1,
    schema_documents_v1,
};

#[test]
fn registry_is_unique_sorted_versioned_and_schema_backed() {
    let registry = contract_registry_v1();
    assert!(!registry.is_empty());
    assert!(
        registry
            .windows(2)
            .all(|pair| pair[0].name() < pair[1].name())
    );
    assert!(registry.iter().all(|entry| entry.supported_version() == 1));
    assert!(registry.iter().all(|entry| entry.maximum_bytes() > 0));
    let schema_paths = schema_documents_v1()
        .unwrap()
        .into_iter()
        .map(|(path, _)| path)
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_paths.len(), registry.len());
    assert!(
        registry
            .iter()
            .all(|entry| schema_paths.contains(entry.schema_path()))
    );
    assert!(migration_registry_v1().is_empty());
}

#[test]
fn generated_schemas_validate_goldens_and_reject_unknown_fields() {
    let schemas = schema_documents_v1().unwrap();
    let goldens = golden_documents_v1().unwrap();
    assert_eq!(schemas.len(), goldens.len());
    for ((schema_path, schema_bytes), (_, golden_bytes)) in schemas.iter().zip(&goldens) {
        let schema: serde_json::Value = serde_json::from_slice(schema_bytes).unwrap();
        let golden: serde_json::Value = serde_json::from_slice(golden_bytes).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            validator.is_valid(&golden),
            "schema/golden mismatch: {schema_path}"
        );
        let mut adversarial = golden.clone();
        adversarial
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(!validator.is_valid(&adversarial));
    }
}

#[test]
fn dispatch_is_bounded_canonical_and_contentless() {
    for (_, golden) in golden_documents_v1().unwrap() {
        let artifact = decode_artifact(&golden).unwrap();
        assert_eq!(artifact.canonical_bytes(), golden);
    }
    assert_eq!(decode_artifact(b""), Err(WireErrorV1::EmptyDocument));
    assert_eq!(
        decode_artifact(br#"{"contract":"evidentrail.unknown","contract_version":1}"#),
        Err(WireErrorV1::UnsupportedContract)
    );
    let known = contract_registry_v1()[0].name();
    let duplicate =
        format!(r#"{{"contract":"{known}","contract":"{known}","contract_version":1}}"#);
    assert_eq!(
        decode_artifact(duplicate.as_bytes()),
        Err(WireErrorV1::Malformed)
    );
    let noncanonical = format!("{{ \"contract\":\"{known}\",\"contract_version\":1}}");
    assert_eq!(
        decode_artifact(noncanonical.as_bytes()),
        Err(WireErrorV1::NonCanonical)
    );
    let debug = format!("{:?}", WireErrorV1::Malformed);
    assert!(!debug.contains("contract"));
    assert!(!debug.contains("/private/"));
}
