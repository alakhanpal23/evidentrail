#![cfg(unix)]

use std::fs::{self, DirBuilder};
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use evidentrail_cli::{
    AuthenticatedPublishingMcpRetentionBackendV1, AuthenticatedRecoveredMcpRetentionBackendV1,
    AuthenticatedStdinPublicationErrorV1, MCP_PROTOCOL_VERSION_V1, McpRetentionBackendErrorV1,
    McpRetentionBackendV1, StdinBriefOutcomeV1, compile_explicit_stdin_retained_v1,
    run_mcp_stdio_with_backend_v1,
};
use evidentrail_core::{ExpansionRelationV1, UnixTimestampNanos};
use evidentrail_product::AuthenticatedEncryptedRetentionV1;
use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    EntropySourceFailureV1, EntropySourceV1, ExpectedCoreResultManifestContextV1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, AuthenticatedFilesystemRestartCoordinatorV1,
    AuthenticatedFilesystemRestartErrorV1, CreatingKeyContextV1, DEFAULT_RESULT_TTL_NANOS,
    EphemeralKeyProviderV1, EvidenceAliasV1, ExpansionLimitV1, FilesystemBundleFaultPointV1,
    FilesystemSealedBundleStoreV1, KeyProviderV1, MemoryEncryptedCoreResultRepositoryV1,
    sealed_bundle_filename_v1,
};
use serde_json::{Value, json};

static SYNTHETIC_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

struct CountingEntropy {
    next: u8,
}

impl CountingEntropy {
    const fn new() -> Self {
        Self { next: 1 }
    }
}

impl EntropySourceV1 for CountingEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
        destination.fill(self.next);
        self.next = self
            .next
            .checked_add(1)
            .ok_or(EntropySourceFailureV1::Unavailable)?;
        Ok(())
    }
}

type TestProvider = EphemeralKeyProviderV1<CountingEntropy>;

struct SyntheticRootV1 {
    path: PathBuf,
}

impl SyntheticRootV1 {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let ordinal = SYNTHETIC_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "evidentrail-synthetic-cli-authenticated-mcp-{}-{ordinal}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn store(&self) -> FilesystemSealedBundleStoreV1 {
        FilesystemSealedBundleStoreV1::open_existing_root(&self.path).unwrap()
    }
}

impl Drop for SyntheticRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct PublishedFixtureV1 {
    root: SyntheticRootV1,
    provider: Arc<TestProvider>,
    expected: ExpectedCoreResultManifestContextV1,
    result_id: ResultId,
    now: UnixTimestampNanos,
}

impl PublishedFixtureV1 {
    fn publish(log_bytes: Vec<u8>, seed: u8) -> Self {
        let root = SyntheticRootV1::new();
        let now = wall_clock_now_v1();
        let mut session = compile_explicit_stdin_retained_v1(
            &log_bytes,
            b"why did the synthetic request fail?",
            100_000,
            [seed; 32],
            now,
        )
        .unwrap();
        let StdinBriefOutcomeV1::Rendered(rendered) = session.outcome() else {
            panic!("bounded single-record fixture must render");
        };
        assert_eq!(rendered.evidence_alias_count(), 1);
        let result_id = rendered.result_id();
        let created = i64::try_from(now.get()).unwrap();
        let expires = i64::try_from(now.get() + DEFAULT_RESULT_TTL_NANOS).unwrap();
        let key_context = CreatingKeyContextV1::new(result_id, created, expires).unwrap();
        let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 8).unwrap());
        let repository =
            MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 8).unwrap();
        let mut retention = AuthenticatedEncryptedRetentionV1::new(repository);
        let publisher = AuthenticatedFilesystemRestartCoordinatorV1::new(
            root.store(),
            Arc::clone(&provider),
            8,
        )
        .unwrap();
        let publication = session
            .publish_authenticated_restart_v1(&mut retention, &key_context, &publisher, now)
            .unwrap();
        let expected = publication.expected_context();
        assert_eq!(publication.result_id(), result_id);

        // These were the only product/session owners. The fixture retains only
        // ciphertext-root authority and the independently supplied context.
        drop(session);
        drop(retention);
        drop(publisher);
        drop(log_bytes);

        Self {
            root,
            provider,
            expected,
            result_id,
            now,
        }
    }

    fn recover_backend(&self) -> AuthenticatedRecoveredMcpRetentionBackendV1<TestProvider> {
        AuthenticatedRecoveredMcpRetentionBackendV1::recover(
            self.root.store(),
            Arc::clone(&self.provider),
            self.expected,
            UnixTimestampNanos::new(self.now.get() + 1),
        )
        .unwrap()
    }
}

fn wall_clock_now_v1() -> UnixTimestampNanos {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    UnixTimestampNanos::new(i128::try_from(nanos).unwrap())
}

fn result_id_text_v1(result_id: ResultId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in result_id.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn modern_meta_v1() -> Value {
    json!({
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "restart-test", "version": "1"},
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION_V1,
    })
}

fn request_v1(id: u64, method: &str, params: Value) -> Value {
    json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params})
}

fn run_requests_v1(
    backend: impl McpRetentionBackendV1 + 'static,
    requests: impl IntoIterator<Item = Value>,
) -> Vec<Value> {
    let mut input = Vec::new();
    for request in requests {
        serde_json::to_writer(&mut input, &request).unwrap();
        input.push(b'\n');
    }
    let mut output = Vec::new();
    run_mcp_stdio_with_backend_v1(Cursor::new(input), &mut output, backend).unwrap();
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn expand_params_v1(result_id: &str, alias: &str, relation: &str) -> Value {
    json!({
        "_meta": modern_meta_v1(),
        "arguments": {
            "alias": alias,
            "max_bytes": 4096,
            "max_events": 4,
            "relation": relation,
            "result_id": result_id,
        },
        "name": "evidentrail_expand",
    })
}

#[test]
fn authenticated_restart_serves_only_advertised_exact_aliases_over_modern_mcp() {
    let exact_bytes = b"ERROR injected ## fake-heading\0\xff".to_vec();
    let expected_base64 = STANDARD.encode(&exact_bytes);
    let fixture = PublishedFixtureV1::publish(exact_bytes, 0x31);
    let result_id = result_id_text_v1(fixture.result_id);
    let wrong_result_id = "11".repeat(32);
    let low_cap = json!({
        "_meta": modern_meta_v1(),
        "arguments": {
            "alias": "E1",
            "max_bytes": 1,
            "max_events": 1,
            "relation": "exact",
            "result_id": result_id,
        },
        "name": "evidentrail_expand",
    });
    let prefixed_result = format!("result_{result_id}");
    let backend = fixture.recover_backend();
    let backend_debug = format!("{backend:?}");
    assert!(!backend_debug.contains("fake-heading"));
    assert!(!backend_debug.contains(&result_id));
    let responses = run_requests_v1(
        backend,
        [
            request_v1(1, "server/discover", json!({"_meta": modern_meta_v1()})),
            request_v1(2, "tools/list", json!({"_meta": modern_meta_v1()})),
            request_v1(
                3,
                "tools/call",
                json!({"_meta": modern_meta_v1(), "arguments": {}, "name": "evidentrail_logs"}),
            ),
            request_v1(4, "tools/call", expand_params_v1(&result_id, "E1", "exact")),
            request_v1(5, "tools/call", expand_params_v1(&result_id, "E2", "exact")),
            request_v1(
                6,
                "tools/call",
                expand_params_v1(&result_id, "xE1", "exact"),
            ),
            request_v1(
                7,
                "tools/call",
                expand_params_v1(&result_id, "E1", "same_lane_before_after"),
            ),
            request_v1(8, "tools/call", low_cap),
            request_v1(
                9,
                "tools/call",
                expand_params_v1(&wrong_result_id, "E1", "exact"),
            ),
            request_v1(
                10,
                "tools/call",
                expand_params_v1(&prefixed_result, "E1", "exact"),
            ),
        ],
    );
    assert_eq!(responses.len(), 10);
    assert!(
        responses[0]["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("exact-only")
    );
    assert!(
        !responses[0]["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("memory-only")
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "evidentrail_expand");
    assert_eq!(
        tools[0]["inputSchema"]["properties"]["relation"]["const"],
        "exact"
    );
    let event_schema = &tools[0]["outputSchema"]["properties"]["events"]["items"];
    assert!(
        event_schema["properties"]
            .get("acquisition_sequence")
            .is_none()
    );
    assert!(event_schema["properties"].get("lane_sequence").is_none());
    assert!(event_schema["properties"].get("record_state").is_none());
    assert_eq!(
        responses[2]["result"]["content"][0]["text"],
        "EVIDENTRAIL_MCP_RETENTION_READ_ONLY"
    );

    let expanded = &responses[3]["result"]["structuredContent"];
    assert_eq!(responses[3]["result"]["isError"], false);
    assert_eq!(expanded["alias"], "E1");
    assert_eq!(expanded["relation"], "exact");
    assert_eq!(expanded["result_id"], result_id);
    assert_eq!(expanded["events"][0]["bytes_base64"], expected_base64);
    assert!(expanded["events"][0].get("acquisition_sequence").is_none());
    assert!(expanded["events"][0].get("lane_sequence").is_none());
    assert!(expanded["events"][0].get("record_state").is_none());

    assert_eq!(
        responses[4]["result"]["content"][0]["text"],
        "EVIDENTRAIL_STORE_REFERENCE_UNAVAILABLE"
    );
    assert_eq!(
        responses[5]["result"]["content"][0]["text"],
        "EVIDENTRAIL_MCP_EVIDENCE_ALIAS_INVALID"
    );
    assert_eq!(
        responses[6]["result"]["content"][0]["text"],
        "EVIDENTRAIL_STORE_REFERENCE_UNAVAILABLE"
    );
    assert_eq!(
        responses[7]["result"]["content"][0]["text"],
        "EVIDENTRAIL_STORE_INSUFFICIENT_EXPANSION_BUDGET"
    );
    assert_eq!(
        responses[8]["result"]["content"][0]["text"],
        "EVIDENTRAIL_MCP_RESULT_UNAVAILABLE"
    );
    assert_eq!(
        responses[9]["result"]["content"][0]["text"],
        "EVIDENTRAIL_MCP_RESULT_ID_INVALID"
    );
}

#[test]
fn authenticated_restart_supports_legacy_exact_expansion_without_compile_tool() {
    let exact_bytes = b"legacy\0\xff\n".to_vec();
    let expected_base64 = STANDARD.encode(&exact_bytes);
    let fixture = PublishedFixtureV1::publish(exact_bytes, 0x41);
    let result_id = result_id_text_v1(fixture.result_id);
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    });
    let responses = run_requests_v1(
        fixture.recover_backend(),
        [
            request_v1(
                1,
                "initialize",
                json!({
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-restart", "version": "1"},
                    "protocolVersion": "2025-11-25",
                }),
            ),
            notification,
            request_v1(2, "tools/list", json!({})),
            request_v1(
                3,
                "tools/call",
                json!({
                    "arguments": {
                        "alias": "E1",
                        "max_bytes": 4096,
                        "max_events": 1,
                        "relation": "exact",
                        "result_id": result_id,
                    },
                    "name": "evidentrail_expand",
                }),
            ),
        ],
    );
    assert_eq!(responses.len(), 3);
    assert!(
        responses[0]["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("exact-only")
    );
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(
        responses[1]["result"]["tools"][0]["name"],
        "evidentrail_expand"
    );
    assert_eq!(
        responses[2]["result"]["structuredContent"]["events"][0]["bytes_base64"],
        expected_base64
    );
    assert!(responses[2]["result"].get("resultType").is_none());
}

#[test]
fn expired_or_tampered_authenticated_results_never_become_mcp_backends() {
    let fixture = PublishedFixtureV1::publish(b"expiry-and-tamper\0\xff\n".to_vec(), 0x51);
    let expiry = UnixTimestampNanos::new(i128::from(fixture.expected.expires_unix_nanos()));
    assert_eq!(
        AuthenticatedRecoveredMcpRetentionBackendV1::recover(
            fixture.root.store(),
            Arc::clone(&fixture.provider),
            fixture.expected,
            expiry,
        )
        .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::OutsideValidity)
    );

    let final_path = fixture
        .root
        .path()
        .join(sealed_bundle_filename_v1(fixture.result_id));
    let mut ciphertext_bundle = fs::read(&final_path).unwrap();
    let final_byte = ciphertext_bundle.last_mut().unwrap();
    *final_byte ^= 0x80;
    fs::write(&final_path, ciphertext_bundle).unwrap();
    let tampered = AuthenticatedRecoveredMcpRetentionBackendV1::recover(
        fixture.root.store(),
        Arc::clone(&fixture.provider),
        fixture.expected,
        UnixTimestampNanos::new(fixture.now.get() + 2),
    )
    .err()
    .unwrap();
    assert_eq!(
        tampered,
        AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined
    );
    let debug = format!("{tampered:?}");
    assert!(!debug.contains("expiry-and-tamper"));
    assert!(!debug.contains(&result_id_text_v1(fixture.result_id)));
}

#[test]
fn needs_more_cannot_publish_a_fake_restartable_alias_manifest() {
    let root = SyntheticRootV1::new();
    let now = wall_clock_now_v1();
    let mut session = compile_explicit_stdin_retained_v1(
        b"too large for one unit\n",
        b"why?",
        1,
        [0x61; 32],
        now,
    )
    .unwrap();
    let StdinBriefOutcomeV1::NeedsMore(needs_more) = session.outcome() else {
        panic!("one-unit budget must return needs_more");
    };
    let key_context = CreatingKeyContextV1::new(
        needs_more.result_id(),
        i64::try_from(now.get()).unwrap(),
        i64::try_from(now.get() + DEFAULT_RESULT_TTL_NANOS).unwrap(),
    )
    .unwrap();
    let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 2).unwrap());
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 2).unwrap();
    let mut retention = AuthenticatedEncryptedRetentionV1::new(repository);
    let coordinator =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 2).unwrap();
    assert_eq!(
        session
            .publish_authenticated_restart_v1(&mut retention, &key_context, &coordinator, now)
            .err(),
        Some(AuthenticatedStdinPublicationErrorV1::NeedsMoreNotPublishable)
    );
    assert_eq!(retention.result_count(), 0);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn publishing_backend_matches_memory_bytes_and_exposes_only_published_exact_aliases() {
    let root = SyntheticRootV1::new();
    let now = wall_clock_now_v1();
    let log_bytes = b"ERROR request=REQ-PUBLISH arbitrary=\0\xff\n".to_vec();
    let question = b"why did the request fail?";
    let seed = [0x71; 32];
    let memory =
        compile_explicit_stdin_retained_v1(&log_bytes, question, 100_000, seed, now).unwrap();
    let durable =
        compile_explicit_stdin_retained_v1(&log_bytes, question, 100_000, seed, now).unwrap();
    let StdinBriefOutcomeV1::Rendered(memory_rendered) = memory.outcome() else {
        panic!("fixture must render");
    };
    let StdinBriefOutcomeV1::Rendered(durable_rendered) = durable.outcome() else {
        panic!("fixture must render");
    };
    assert_eq!(
        memory_rendered.text().as_bytes(),
        durable_rendered.text().as_bytes()
    );
    assert_eq!(memory_rendered.result_id(), durable_rendered.result_id());
    assert_eq!(memory_rendered.evidence_alias_count(), 1);
    let result_id = durable_rendered.result_id();

    let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 8).unwrap());
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 8).unwrap();
    let retention = AuthenticatedEncryptedRetentionV1::new(repository);
    let coordinator =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 8)
            .unwrap();
    let mut backend = AuthenticatedPublishingMcpRetentionBackendV1::new(retention, coordinator);
    assert_eq!(backend.retained_result_count(), 0);
    backend.retain_rendered_session(durable).unwrap();
    assert_eq!(backend.retained_result_count(), 1);
    assert!(
        root.path()
            .join(sealed_bundle_filename_v1(result_id))
            .is_file()
    );

    drop(log_bytes);
    let request = AliasExpansionRequestV1::new(
        result_id,
        EvidenceAliasV1::new(result_id, 1).unwrap(),
        ExpansionRelationV1::Exact,
        ExpansionLimitV1::new(4, 4096, 0, 0).unwrap(),
    );
    let expanded = backend
        .expand_alias(request, UnixTimestampNanos::new(now.get() + 1))
        .unwrap();
    assert_eq!(expanded.events().len(), 1);
    assert_eq!(
        expanded.events()[0].authorized_bytes(),
        b"ERROR request=REQ-PUBLISH arbitrary=\0\xff\n"
    );
    assert_eq!(expanded.relation(), ExpansionRelationV1::Exact);
    assert!(!expanded.truncated());
    assert!(expanded.events()[0].acquisition_sequence().is_none());
}

#[test]
fn publishing_backend_failure_destroys_authority_and_never_installs_a_handle() {
    let root = SyntheticRootV1::new();
    let now = wall_clock_now_v1();
    let session = compile_explicit_stdin_retained_v1(
        b"publication must fail\n",
        b"why?",
        100_000,
        [0x72; 32],
        now,
    )
    .unwrap();
    let result_id = session.outcome().result_id();
    let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 8).unwrap());
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 8).unwrap();
    let retention = AuthenticatedEncryptedRetentionV1::new(repository);
    let filesystem = root.store();
    filesystem
        .fail_next_for_test(FilesystemBundleFaultPointV1::BeforeAtomicPublish)
        .unwrap();
    let coordinator =
        AuthenticatedFilesystemRestartCoordinatorV1::new(filesystem, Arc::clone(&provider), 8)
            .unwrap();
    let mut backend = AuthenticatedPublishingMcpRetentionBackendV1::new(retention, coordinator);
    assert_eq!(
        backend.retain_rendered_session(session),
        Err(McpRetentionBackendErrorV1::PublicationFailed)
    );
    assert_eq!(backend.retained_result_count(), 0);
    let request = AliasExpansionRequestV1::new(
        result_id,
        EvidenceAliasV1::new(result_id, 1).unwrap(),
        ExpansionRelationV1::Exact,
        ExpansionLimitV1::new(1, 4096, 0, 0).unwrap(),
    );
    assert_eq!(
        backend
            .expand_alias(request, UnixTimestampNanos::new(now.get() + 1))
            .err(),
        Some(McpRetentionBackendErrorV1::ResultUnavailable)
    );
    assert!(
        provider
            .list_managed_records()
            .unwrap()
            .iter()
            .all(|record| record.result_id() != result_id)
    );
}

#[test]
fn publishing_mcp_returns_no_result_before_the_publication_gate() {
    let root = SyntheticRootV1::new();
    let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 8).unwrap());
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 8).unwrap();
    let retention = AuthenticatedEncryptedRetentionV1::new(repository);
    let coordinator =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 8)
            .unwrap();
    let backend = AuthenticatedPublishingMcpRetentionBackendV1::new(retention, coordinator);
    let responses = run_requests_v1(
        backend,
        [
            request_v1(1, "tools/list", json!({"_meta": modern_meta_v1()})),
            request_v1(
                2,
                "tools/call",
                json!({
                    "_meta": modern_meta_v1(),
                    "arguments": {
                        "logs_base64": STANDARD.encode(b"published MCP source removed later\n"),
                        "question": "why?",
                        "token_budget": 100_000,
                    },
                    "name": "evidentrail_logs",
                }),
            ),
        ],
    );
    let tools = responses[0]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "evidentrail_logs");
    assert_eq!(
        tools[1]["inputSchema"]["properties"]["relation"]["const"],
        "exact"
    );
    assert_eq!(responses[1]["result"]["isError"], false);
    assert!(responses[1]["result"]["structuredContent"]["retained"] == true);
    assert_eq!(
        fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("r_"))
            .count(),
        1
    );

    let failed_root = SyntheticRootV1::new();
    let failed_provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 8).unwrap());
    let failed_repository =
        MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&failed_provider), 8).unwrap();
    let failed_retention = AuthenticatedEncryptedRetentionV1::new(failed_repository);
    let filesystem = failed_root.store();
    filesystem
        .fail_next_for_test(FilesystemBundleFaultPointV1::BeforeAtomicPublish)
        .unwrap();
    let failed_coordinator = AuthenticatedFilesystemRestartCoordinatorV1::new(
        filesystem,
        Arc::clone(&failed_provider),
        8,
    )
    .unwrap();
    let failed_backend =
        AuthenticatedPublishingMcpRetentionBackendV1::new(failed_retention, failed_coordinator);
    let failed = run_requests_v1(
        failed_backend,
        [request_v1(
            3,
            "tools/call",
            json!({
                "_meta": modern_meta_v1(),
                "arguments": {
                    "logs_base64": STANDARD.encode(b"never visible\n"),
                    "question": "why?",
                    "token_budget": 100_000,
                },
                "name": "evidentrail_logs",
            }),
        )],
    );
    assert_eq!(failed[0]["result"]["isError"], true);
    assert_eq!(
        failed[0]["result"]["content"][0]["text"],
        McpRetentionBackendErrorV1::PublicationFailed.code()
    );
    assert!(failed[0]["result"].get("structuredContent").is_none());
    assert!(failed_provider.list_managed_records().unwrap().is_empty());
}
