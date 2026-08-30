#![cfg(unix)]

use std::fs;

use evidentrail_cli::{
    DurablePublishingMcpRetentionBackendV2, McpRetentionBackendV1, McpRetentionModeV1,
    StdinBriefOutcomeV1, compile_explicit_stdin_v1,
};
use evidentrail_core::{ExpansionRelationV1, UnixTimestampNanos};
use evidentrail_product::DurableProductV2;
use evidentrail_store::{
    AliasExpansionRequestV1, DurableResultRepositoryV2, EvidenceAliasV1, ExpansionLimitV1,
    ProcessKeyAuthorityV2,
};

fn unique_root(suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "evidentrail-cli-durable-mcp-{}-{suffix}",
        std::process::id()
    ))
}

fn assert_public_outcomes_equal(memory: &StdinBriefOutcomeV1, durable: &StdinBriefOutcomeV1) {
    match (memory, durable) {
        (StdinBriefOutcomeV1::Rendered(memory), StdinBriefOutcomeV1::Rendered(durable)) => {
            assert_eq!(durable.mode(), memory.mode());
            assert_eq!(durable.result_id(), memory.result_id());
            assert_eq!(durable.expires_at(), memory.expires_at());
            assert_eq!(durable.text().as_bytes(), memory.text().as_bytes());
            assert_eq!(durable.source_record_count(), memory.source_record_count());
            assert_eq!(durable.source_byte_count(), memory.source_byte_count());
            assert_eq!(
                durable.evidence_alias_count(),
                memory.evidence_alias_count()
            );
        }
        (StdinBriefOutcomeV1::NeedsMore(memory), StdinBriefOutcomeV1::NeedsMore(durable)) => {
            assert_eq!(durable.result_id(), memory.result_id());
            assert_eq!(durable.reason(), memory.reason());
            assert_eq!(durable.source_record_count(), memory.source_record_count());
            assert_eq!(durable.source_byte_count(), memory.source_byte_count());
        }
        _ => panic!("memory and durable decisions diverged"),
    }
}

fn compiled_fixture() -> (Vec<u8>, Vec<u8>) {
    const REQUEST_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    let mut input = Vec::new();
    for index in 0..200 {
        match index {
            97 => input.extend_from_slice(
                format!("ERROR request_id={REQUEST_ID} database timeout\n").as_bytes(),
            ),
            98 => input.extend_from_slice(b"Traceback (most recent call last):\n"),
            99 => input.extend_from_slice(b"  File \"db.py\", line 7, in execute\n"),
            100 => input.extend_from_slice(b"TimeoutError: synthetic database timeout\n"),
            _ => {
                input.extend_from_slice(format!("INFO heartbeat sequence={index} ").as_bytes());
                input.extend(std::iter::repeat_n(b'x', 620));
                input.push(b'\n');
            }
        }
    }
    let question = format!("why did request {REQUEST_ID} fail with database timeout?");
    (input, question.into_bytes())
}

#[test]
fn durable_backend_preserves_public_bytes_and_expands_without_source_access() {
    let root = unique_root("parity");
    let _ = fs::remove_dir_all(&root);
    let input = b"ERROR request=R9 timeout\nretry request=R9 failed\n";
    let question = b"why did request R9 fail?";
    let budget = 100_000;
    let seed = [0x51; 32];
    let now = UnixTimestampNanos::new(10_000);

    let memory = compile_explicit_stdin_v1(input, question, budget, seed, now).unwrap();
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(8).unwrap()).unwrap();
    let mut backend =
        DurablePublishingMcpRetentionBackendV2::new(DurableProductV2::new(repository));
    assert_eq!(backend.mode(), McpRetentionModeV1::DurablePublishedV2);
    let durable = backend
        .compile_logs(input, question, budget, seed, now)
        .unwrap()
        .expect("durable backend owns compilation");
    assert_public_outcomes_equal(&memory, &durable);
    assert_eq!(backend.retained_result_count(), 1);

    let result_id = durable.result_id();
    drop(durable);
    let expansion = backend
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(8, 4096, 0, 0).unwrap(),
            ),
            UnixTimestampNanos::new(now.get() + 1),
        )
        .unwrap();
    assert!(!expansion.events().is_empty());
    assert!(
        expansion
            .events()
            .iter()
            .any(|event| event.authorized_bytes().starts_with(b"ERROR"))
    );
    backend.product().repository().destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_repository_publication_never_installs_an_expansion_capability() {
    let root = unique_root("fail-closed");
    let _ = fs::remove_dir_all(&root);
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(8).unwrap()).unwrap();
    let mut backend =
        DurablePublishingMcpRetentionBackendV2::new(DurableProductV2::new(repository));
    fs::remove_dir_all(&root).unwrap();

    assert!(
        backend
            .compile_logs(
                b"ERROR unavailable\n",
                b"why?",
                100_000,
                [0x52; 32],
                UnixTimestampNanos::new(20_000),
            )
            .is_err()
    );
    assert_eq!(backend.retained_result_count(), 0);
}

#[test]
fn compiled_and_needs_more_decisions_are_identical_across_retention_modes() {
    let root = unique_root("decisions");
    let _ = fs::remove_dir_all(&root);
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(8).unwrap()).unwrap();
    let mut backend =
        DurablePublishingMcpRetentionBackendV2::new(DurableProductV2::new(repository));
    let now = UnixTimestampNanos::new(30_000);
    let (input, question) = compiled_fixture();
    let memory = compile_explicit_stdin_v1(&input, &question, 20_000, [0x53; 32], now).unwrap();
    let durable = backend
        .compile_logs(&input, &question, 20_000, [0x53; 32], now)
        .unwrap()
        .unwrap();
    assert_public_outcomes_equal(&memory, &durable);
    assert!(matches!(
        durable,
        StdinBriefOutcomeV1::Rendered(ref rendered)
            if rendered.mode() == evidentrail_cli::StdinBriefModeV1::Compiled
    ));
    let compiled_result_id = durable.result_id();
    assert_eq!(backend.retained_result_count(), 1);

    let needs_more_now = UnixTimestampNanos::new(now.get() + 1);
    let memory_needs_more = compile_explicit_stdin_v1(
        b"request_id=REQ-7 database timeout\n",
        b"why REQ-7?",
        1,
        [0x54; 32],
        needs_more_now,
    )
    .unwrap();
    let durable_needs_more = backend
        .compile_logs(
            b"request_id=REQ-7 database timeout\n",
            b"why REQ-7?",
            1,
            [0x54; 32],
            needs_more_now,
        )
        .unwrap()
        .unwrap();
    assert_public_outcomes_equal(&memory_needs_more, &durable_needs_more);
    assert!(matches!(
        durable_needs_more,
        StdinBriefOutcomeV1::NeedsMore(_)
    ));
    assert_eq!(backend.retained_result_count(), 1);

    backend
        .product()
        .repository()
        .destroy(compiled_result_id)
        .unwrap();
    fs::remove_dir_all(root).unwrap();
}
