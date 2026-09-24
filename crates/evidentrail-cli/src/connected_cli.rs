//! macOS connected-source registration, bounded synchronization, and query.
//! Registration never claims that a source has been backfilled.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    AuthorizedCorpus, CliFailure, ConnectedLogPack, OpenAiIncidentReasoner, select_connected_logs,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use evidentrail_corpus::{
    ConnectedSourceDescriptorV1, CorpusKeychainErrorV1, EncryptedHistoryStore,
    MacOsConnectedCredentialKeychainV1, MacOsCorpusKeychainV1, SyncAttempt, SyncObservation,
};
use evidentrail_ingest::{
    AwsCloudWatchTransportV1, CloudWatchCapsV1, CloudWatchHistorySourceV1, CloudWatchPlanV1,
    DatadogAccessIdentityV1, DatadogHistorySourceV1, DatadogSiteV1, DatadogStorageTierV1,
    HistoryPageSourceV1, HistoryPartitionV1, HistorySyncErrorV1, HistorySyncLimitsV1,
    HistorySyncStatusV1, reconcile_history_range_v1, reconcile_history_v1, synchronize_history_v1,
};
use rustix::fs::{CWD, FlockOperation, Mode, OFlags, flock, openat};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CloudWatchDescriptor {
    schema_version: u8,
    provider: String,
    account: String,
    region: String,
    log_group: String,
    profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_arn: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DatadogDescriptor {
    schema_version: u8,
    provider: String,
    site: String,
    tier: String,
    connection_id: String,
    org_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_ids: Option<Vec<String>>,
}

enum SourceBinding {
    CloudWatch(CloudWatchDescriptor),
    Datadog(DatadogDescriptor),
}

fn parse_binding(descriptor: &[u8]) -> Result<SourceBinding, CliFailure> {
    let value: serde_json::Value = serde_json::from_slice(descriptor)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
    match value.get("provider").and_then(serde_json::Value::as_str) {
        Some("cloudwatch") => {
            let binding: CloudWatchDescriptor = serde_json::from_value(value)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
            validate_binding(&binding)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
            Ok(SourceBinding::CloudWatch(binding))
        }
        Some("datadog") => {
            let binding: DatadogDescriptor = serde_json::from_value(value)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
            validate_datadog_binding(&binding)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
            Ok(SourceBinding::Datadog(binding))
        }
        _ => Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE",
        )),
    }
}

pub fn run(args: Vec<OsString>) -> Result<ExitCode, CliFailure> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_COMMAND_REQUIRED"))?;
    if command == "connect-cloudwatch" {
        connect_cloudwatch(parse_cloudwatch_args(args)?)
    } else if command == "connect-datadog" {
        connect_datadog(parse_datadog_args(args)?)
    } else if command == "rotate-datadog" {
        rotate_datadog(parse_datadog_rotation_args(args)?, false)
    } else if command == "recover-datadog" {
        rotate_datadog(parse_datadog_rotation_args(args)?, true)
    } else if command == "list" {
        if args.next().is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        }
        list_sources()
    } else if command == "sync" {
        if args.next().is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        }
        sync_sources()
    } else if command == "watch" {
        watch_sources(parse_watch_interval(args)?)
    } else if command == "service" {
        crate::connected_service::run(args)
    } else if command == "disconnect" {
        let option = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_SOURCE_ID_REQUIRED"))?;
        if option != "--source-id" {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        }
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_SOURCE_ID_REQUIRED"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_SOURCE_ID_INVALID"))?;
        if args.next().is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        }
        disconnect_source(parse_source_digest(&value)?)
    } else {
        Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_COMMAND"))
    }
}

fn parse_source_digest(value: &str) -> Result<[u8; 32], CliFailure> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_SOURCE_ID_INVALID"));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_SOURCE_ID_INVALID"))?;
    }
    Ok(digest)
}

pub(crate) fn source_id_for_mcp(source_digest: &[u8; 32]) -> String {
    hex(source_digest)
}

const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;
const MAX_SYNC_PAGES: usize = 256;
const MAX_HISTORICAL_PAGES_PER_PASS: usize = 8;
const DEFAULT_WATCH_INTERVAL_SECS: u64 = 60;
const MAX_WATCH_INTERVAL_SECS: u64 = 3600;

fn parse_watch_interval(mut args: impl Iterator<Item = OsString>) -> Result<Duration, CliFailure> {
    let Some(option) = args.next() else {
        return Ok(Duration::from_secs(DEFAULT_WATCH_INTERVAL_SECS));
    };
    if option != "--interval-seconds" {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
    }
    let value = args
        .next()
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_WATCH_INTERVAL_INVALID"))?
        .into_string()
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_WATCH_INTERVAL_INVALID"))?;
    if args.next().is_some() {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
    }
    let seconds = value
        .parse::<u64>()
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_WATCH_INTERVAL_INVALID"))?;
    if !(5..=MAX_WATCH_INTERVAL_SECS).contains(&seconds) {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_SOURCES_WATCH_INTERVAL_INVALID",
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn watch_sources(interval: Duration) -> Result<ExitCode, CliFailure> {
    let mut consecutive_errors = 0u32;
    loop {
        let outcome = sync_cycle();
        let (next_errors, delay) = watch_cycle_delay(interval, consecutive_errors, &outcome);
        if let Err(error) = outcome {
            if error.code != "EVIDENTRAIL_SOURCES_BUSY" {
                serde_json::to_writer(
                    io::stderr().lock(),
                    &json!({
                        "status": "sync_cycle_error",
                        "code": error.code,
                        "consecutive_errors": next_errors,
                    }),
                )
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
                writeln!(io::stderr().lock())
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
            }
        }
        consecutive_errors = next_errors;
        // Every pass releases the catalog lock. A supervisor restarts the
        // process after a crash; persistent checkpoints make replay safe.
        thread::sleep(delay);
    }
}

fn watch_cycle_delay(
    interval: Duration,
    consecutive_errors: u32,
    outcome: &Result<bool, CliFailure>,
) -> (u32, Duration) {
    let next_errors = match outcome {
        Ok(false)
        | Err(CliFailure {
            code: "EVIDENTRAIL_SOURCES_BUSY",
            ..
        }) => 0,
        Ok(true) | Err(_) => consecutive_errors.saturating_add(1),
    };
    (next_errors, watch_delay(interval, next_errors))
}

fn watch_delay(interval: Duration, consecutive_errors: u32) -> Duration {
    let multiplier = 1u64 << consecutive_errors.min(6);
    Duration::from_secs(interval.as_secs().saturating_mul(multiplier).min(3600))
}

struct ConnectedQueryOptions {
    task: String,
    max_raw_bytes: usize,
}

pub(crate) struct ConnectedQueryResult {
    pub body: Vec<u8>,
    pub metadata: serde_json::Value,
    pub selected_refs: Vec<([u8; 32], Vec<u8>)>,
    _catalog_guard: File,
}

pub(crate) struct ConnectedQueryError {
    pub code: &'static str,
    pub metadata: Option<serde_json::Value>,
}

pub fn run_logs(args: Vec<OsString>) -> Result<ExitCode, CliFailure> {
    let options = parse_logs_args(args.into_iter())?;
    let result = match query_connected_logs(&options.task, options.max_raw_bytes) {
        Ok(result) => result,
        Err(error) => {
            if let Some(metadata) = error.metadata {
                write_metadata(&metadata)?;
            }
            return Err(CliFailure::runtime(error.code));
        }
    };
    write_metadata(&result.metadata)?;
    io::stdout()
        .lock()
        .write_all(&result.body)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn write_metadata(metadata: &serde_json::Value) -> Result<(), CliFailure> {
    serde_json::to_writer(io::stderr().lock(), metadata)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))?;
    writeln!(io::stderr().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))
}

pub(crate) fn query_connected_logs(
    task: &str,
    max_raw_bytes: usize,
) -> Result<ConnectedQueryResult, ConnectedQueryError> {
    let query_started = Instant::now();
    if task.trim().is_empty()
        || task.len() > 4096
        || max_raw_bytes == 0
        || max_raw_bytes > 256 * 1024
    {
        return Err(ConnectedQueryError {
            code: "EVIDENTRAIL_LOGS_ARGUMENTS_INVALID",
            metadata: None,
        });
    }
    let query_error = |failure: CliFailure| ConnectedQueryError {
        code: failure.code,
        metadata: None,
    };
    let catalog_guard = connected_catalog_lock().map_err(query_error)?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    let entries = authority
        .list_bound(&tenant)
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    if entries.is_empty() {
        return Err(ConnectedQueryError {
            code: "EVIDENTRAIL_LOGS_NO_CONNECTED_SOURCE",
            metadata: None,
        });
    }
    let interrupted_rotations = interrupted_datadog_rotations(&entries).map_err(query_error)?;
    let high_water = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE")))?
        .as_millis() as i64;
    let mut stores = Vec::new();
    let mut selected_descriptors = Vec::new();
    let mut selected_key_digests = Vec::new();
    let mut source_states = Vec::new();
    let mut datadog_tiers = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in entries {
        let binding = parse_binding(&entry.descriptor).map_err(query_error)?;
        if let SourceBinding::Datadog(datadog) = &binding {
            datadog_tiers
                .entry(datadog.connection_id.clone())
                .or_default()
                .insert(datadog.tier.clone());
        }
        let source_id = hex(&entry.source_digest);
        if matches!(&binding, SourceBinding::Datadog(datadog) if interrupted_rotations.contains(&datadog.connection_id))
        {
            source_states.push(json!({
                "source_id": source_id,
                "state": "excluded_rotation_interrupted"
            }));
            continue;
        }
        if matches!(&binding, SourceBinding::Datadog(datadog) if datadog.schema_version == 1) {
            source_states.push(json!({
                "source_id": source_id,
                "state": "excluded_reconnect_required"
            }));
            continue;
        }
        let path = corpus_path(&entry.source_digest, false).map_err(query_error)?;
        if !corpus_file_exists_safe(&path).map_err(query_error)? {
            source_states.push(json!({
                "source_id": source_id,
                "state": "excluded_corpus_missing"
            }));
            continue;
        }
        let key = authority
            .load(&tenant, &entry.source_digest)
            .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
        let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
            .map_err(|_| {
                query_error(CliFailure::runtime(
                    "EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED",
                ))
            })?;
        let progress = sync_binding(
            &binding,
            &tenant,
            &entry.source_digest,
            &mut store,
            high_water,
        );
        match progress {
            Ok(progress) => {
                source_states.push(json!({
                    "source_id": source_id,
                    "state": progress.status,
                    "reconciliation": progress.reconciliation,
                    "historical_reconciliation": progress.historical_reconciliation,
                    "historical_cursor_millis": store.read_historical_reconciliation_cursor().map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED")))?,
                    "historical_last_cycle_end_millis": store.read_historical_reconciliation_last_cycle_end().map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED")))?,
                    "scanned_through_millis": store.read_checkpoint().map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED")))?.map(|value| value.completed_through_millis),
                    "high_water_millis": high_water,
                }));
                selected_descriptors.push((entry.source_digest, entry.descriptor));
                selected_key_digests.push(corpus_key_generation(&key));
                stores.push((entry.source_digest, store));
            }
            Err(error) => {
                source_states.push(json!({
                    "source_id": source_id,
                    "state": "excluded_sync_error",
                    "error": error,
                }));
            }
        }
    }
    for (connection_id, tiers) in datadog_tiers {
        for tier in ["indexes", "online-archives", "flex"] {
            if !tiers.contains(tier) {
                source_states.push(json!({
                    "provider": "datadog",
                    "connection_id": connection_id,
                    "tier": tier,
                    "state": "tier_not_connected",
                }));
            }
        }
    }
    if stores.is_empty() {
        return Err(ConnectedQueryError {
            code: "EVIDENTRAIL_LOGS_NO_AUTHORIZED_SOURCE",
            metadata: Some(json!({"sources": source_states, "coverage": "no_authorized_source"})),
        });
    }
    let snapshots = stores
        .iter()
        .map(|(_, store)| store.read_snapshot())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            query_error(CliFailure::runtime(
                "EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED",
            ))
        })?;
    let authorized = stores
        .iter()
        .zip(&snapshots)
        .map(|((source_digest, _), snapshot)| AuthorizedCorpus {
            source_digest: *source_digest,
            store: snapshot,
        })
        .collect::<Vec<_>>();
    // WAL snapshots keep the candidate and original-record view stable while
    // the watcher is free to append newer records. Nothing is returned until
    // the sources are revalidated under the catalog lock below.
    drop(catalog_guard);
    let mut selector = OpenAiIncidentReasoner::from_compact_environment()
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    let pack = select_connected_logs(&authorized, task, max_raw_bytes, &mut selector)
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    let body = render_connected_logs(&pack).map_err(query_error)?;
    let catalog_guard =
        wait_for_connected_catalog_lock(Duration::from_secs(60)).map_err(query_error)?;
    verify_query_sources(
        &authority,
        &tenant,
        &selected_descriptors,
        &selected_key_digests,
        &snapshots,
    )
    .map_err(query_error)?;
    let selected_refs = pack
        .selected
        .iter()
        .flat_map(|entry| {
            std::iter::once((entry.source_digest, entry.first_native_id.clone())).chain(
                entry
                    .last_native_id
                    .iter()
                    .cloned()
                    .map(|id| (entry.source_digest, id)),
            )
        })
        .collect();
    let partial_source = source_states
        .iter()
        .any(|state| state["state"] != "scanned_to_high_water")
        || source_states
            .iter()
            .any(|state| state["reconciliation"] != "recent_lookback_scanned")
        || source_states.iter().any(|state| {
            !matches!(
                state["historical_reconciliation"].as_str(),
                Some("cycle_complete" | "recent_cycle_complete" | "not_applicable")
            )
        });
    let metadata = json!({
        "sources": source_states,
        "coverage": if partial_source { "partial" } else { "unverified_provider_consistency" },
        "candidate_count": pack.candidate_count,
        "prefinal_pruned_groups": pack.prefinal_pruned_groups,
        "graph_candidate_count": pack.graph_candidate_count,
        "fallback_candidate_count": pack.fallback_candidate_count,
        "service_candidates_added": pack.service_candidates_added,
        "service_directory_pages": pack.service_directory_pages,
        "service_directory_truncated": pack.service_directory_truncated,
        "candidate_pool_truncated": pack.candidate_pool_truncated,
        "output_budget_truncated": pack.output_budget_truncated,
        "selection_calls": pack.selection_calls,
        "selection_elapsed_ms": pack.selection_elapsed_ms,
        "query_elapsed_ms": query_started.elapsed().as_millis(),
        "selected_groups": pack.selected.len(),
        "total_groups": pack.total_groups,
        "raw_byte_budget": max_raw_bytes,
    });
    Ok(ConnectedQueryResult {
        body,
        metadata,
        selected_refs,
        _catalog_guard: catalog_guard,
    })
}

fn verify_query_sources(
    authority: &MacOsCorpusKeychainV1,
    tenant: &[u8; 32],
    selected_descriptors: &[([u8; 32], Vec<u8>)],
    selected_key_digests: &[[u8; 32]],
    snapshots: &[evidentrail_corpus::CorpusReadSnapshot<'_>],
) -> Result<(), CliFailure> {
    let current = authority
        .list_bound(tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let interrupted_rotations = interrupted_datadog_rotations(&current)?;
    if selected_descriptors.len() != snapshots.len() {
        return Err(CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"));
    }
    verify_query_generations(
        selected_descriptors,
        selected_key_digests,
        &current,
        |source_digest| {
            let current_key = authority
                .load(tenant, source_digest)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?;
            Ok(corpus_key_generation(&current_key))
        },
    )?;
    for ((source_digest, descriptor), snapshot) in selected_descriptors.iter().zip(snapshots) {
        match parse_binding(descriptor)? {
            SourceBinding::CloudWatch(cloudwatch) => {
                let caller_arn = cloudwatch
                    .caller_arn
                    .as_deref()
                    .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?;
                let source_plan = plan(&cloudwatch)?;
                let transport = AwsCloudWatchTransportV1::connect(
                    source_plan.clone(),
                    &cloudwatch.account,
                    Some(caller_arn),
                    cloudwatch.profile.as_deref(),
                )
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
                    .as_millis() as i64;
                source
                    .fetch_page(
                        HistoryPartitionV1 {
                            start_millis: now.saturating_sub(1000),
                            end_millis: now,
                        },
                        None,
                    )
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
            }
            SourceBinding::Datadog(datadog) => {
                if interrupted_rotations.contains(&datadog.connection_id) {
                    return Err(CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"));
                }
                let credentials = MacOsConnectedCredentialKeychainV1::production();
                let secret = credentials
                    .load(tenant, source_digest)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                let (mut api_key, mut application_key) = decode_datadog_secret(&secret)?;
                let source = DatadogHistorySourceV1::connect(
                    datadog_site(&datadog.site)
                        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?,
                    datadog_tier(&datadog.tier)
                        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?,
                    std::mem::take(&mut *api_key),
                    std::mem::take(&mut *application_key),
                )
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                let identity = source
                    .current_access_identity()
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                check_datadog_identity(&datadog, &identity)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?;
                let scope = source
                    .current_access_scope_digest(&identity)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_UNAVAILABLE"))?;
                snapshot
                    .bind_provider_access_scope(&scope)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"))?;
            }
        }
    }
    Ok(())
}

fn corpus_key_generation(key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"evidentrail/query-corpus-key-generation/v1\0");
    hash.update(key);
    hash.finalize().into()
}

fn verify_query_generations(
    selected: &[([u8; 32], Vec<u8>)],
    expected_keys: &[[u8; 32]],
    current: &[ConnectedSourceDescriptorV1],
    mut current_key_generation: impl FnMut(&[u8; 32]) -> Result<[u8; 32], CliFailure>,
) -> Result<(), CliFailure> {
    if selected.len() != expected_keys.len() {
        return Err(CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"));
    }
    let current = current
        .iter()
        .map(|entry| (entry.source_digest, entry.descriptor.as_slice()))
        .collect::<BTreeMap<_, _>>();
    for ((source_digest, descriptor), expected_key) in selected.iter().zip(expected_keys) {
        if current.get(source_digest).copied() != Some(descriptor.as_slice())
            || current_key_generation(source_digest)? != *expected_key
        {
            return Err(CliFailure::runtime("EVIDENTRAIL_LOGS_SOURCE_CHANGED"));
        }
    }
    Ok(())
}

/// Recheck a registered source against its live provider credentials before
/// resolving any neighboring bytes from its encrypted local corpus.
pub(crate) fn expand_connected_logs(
    source_digest: &[u8; 32],
    native_id: &[u8],
    before: usize,
    after: usize,
    max_raw_bytes: usize,
) -> Result<(Vec<u8>, serde_json::Value), ConnectedQueryError> {
    let failure = |code| ConnectedQueryError {
        code,
        metadata: None,
    };
    let map_failure = |error: CliFailure| failure(error.code);
    let _guard = connected_catalog_lock().map_err(map_failure)?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| failure(error.code()))?;
    let entries = authority
        .list_bound(&tenant)
        .map_err(|error| failure(error.code()))?;
    let interrupted_rotations = interrupted_datadog_rotations(&entries).map_err(map_failure)?;
    let entry = entries
        .into_iter()
        .find(|entry| &entry.source_digest == source_digest)
        .ok_or_else(|| failure("EVIDENTRAIL_CONNECTED_EXPAND_SOURCE_REVOKED"))?;
    let binding = parse_binding(&entry.descriptor).map_err(map_failure)?;
    if matches!(&binding, SourceBinding::Datadog(datadog) if interrupted_rotations.contains(&datadog.connection_id))
    {
        return Err(failure("EVIDENTRAIL_DATADOG_ROTATION_INTERRUPTED"));
    }
    if matches!(&binding, SourceBinding::Datadog(datadog) if datadog.schema_version == 1) {
        return Err(failure("EVIDENTRAIL_DATADOG_RECONNECT_REQUIRED"));
    }
    let path = corpus_path(source_digest, false).map_err(map_failure)?;
    if !corpus_file_exists_safe(&path).map_err(map_failure)? {
        return Err(failure("EVIDENTRAIL_CONNECTED_EXPAND_CORPUS_MISSING"));
    }
    let key = authority
        .load(&tenant, source_digest)
        .map_err(|error| failure(error.code()))?;
    let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, source_digest)
        .map_err(|_| failure("EVIDENTRAIL_CONNECTED_EXPAND_CORPUS_FAILURE"))?;
    let high_water = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failure("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    let progress = sync_binding(&binding, &tenant, source_digest, &mut store, high_water)
        .map_err(|_| failure("EVIDENTRAIL_CONNECTED_EXPAND_SOURCE_UNAVAILABLE"))?;
    let nearby = store
        .read_nearby(native_id, before, after, max_raw_bytes)
        .map_err(|_| failure("EVIDENTRAIL_CONNECTED_EXPAND_CORPUS_FAILURE"))?
        .ok_or_else(|| failure("EVIDENTRAIL_CONNECTED_EXPAND_ANCHOR_MISSING"))?;
    let mut body = Vec::new();
    for record in &nearby.records {
        if crate::sensitive_log::contains_sensitive_data(&String::from_utf8_lossy(&record.bytes)) {
            return Err(failure("EVIDENTRAIL_CONNECTED_EXPAND_SENSITIVE_RECORD"));
        }
        let mut row = json!({
            "source_id": hex(source_digest),
            "native_id": URL_SAFE_NO_PAD.encode(&record.native_id),
            "event_timestamp_millis": record.event_timestamp_millis,
        });
        if let Ok(raw) = std::str::from_utf8(&record.bytes) {
            row["raw"] = json!(raw);
        } else {
            row["raw_base64"] = json!(URL_SAFE_NO_PAD.encode(&record.bytes));
        }
        serde_json::to_writer(&mut body, &row)
            .map_err(|_| failure("EVIDENTRAIL_CONNECTED_EXPAND_OUTPUT_FAILURE"))?;
        body.push(b'\n');
    }
    Ok((
        body,
        json!({
            "source_id": hex(source_digest),
            "anchor_native_id": URL_SAFE_NO_PAD.encode(native_id),
            "before_truncated": nearby.before_truncated,
            "after_truncated": nearby.after_truncated,
            "sync_state": progress.status,
            "reconciliation": progress.reconciliation,
            "historical_reconciliation": progress.historical_reconciliation,
        "coverage": if progress.status == "scanned_to_high_water"
            && progress.reconciliation == "recent_lookback_scanned"
            && progress.historical_replay_complete() {
            "unverified_provider_consistency"
        } else {
            "partial"
        },
        }),
    ))
}

fn parse_logs_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<ConnectedQueryOptions, CliFailure> {
    let mut task = None;
    let mut task_file = None;
    let mut max_raw_bytes = None;
    while let Some(option) = args.next() {
        let target = if option == "--task" {
            &mut task
        } else if option == "--task-file" {
            &mut task_file
        } else if option == "--max-raw-bytes" {
            &mut max_raw_bytes
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_LOGS_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_LOGS_MISSING_VALUE"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_LOGS_INVALID_VALUE"))?;
        if target.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_LOGS_DUPLICATE_OPTION"));
        }
    }
    if task.is_some() == task_file.is_some() {
        return Err(CliFailure::usage("EVIDENTRAIL_LOGS_TASK_REQUIRED"));
    }
    let task = if let Some(path) = task_file {
        let file = File::open(path)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_LOGS_TASK_FILE_UNAVAILABLE"))?;
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_TASK_FILE_READ_FAILED"))?;
        String::from_utf8(bytes).map_err(|_| CliFailure::usage("EVIDENTRAIL_LOGS_TASK_INVALID"))?
    } else {
        task.expect("one task source")
    };
    if task.trim().is_empty() || task.len() > 4096 {
        return Err(CliFailure::usage("EVIDENTRAIL_LOGS_TASK_INVALID"));
    }
    let max_raw_bytes = if let Some(value) = max_raw_bytes {
        value
            .parse::<usize>()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_LOGS_BUDGET_INVALID"))?
    } else {
        32 * 1024
    };
    if max_raw_bytes == 0 || max_raw_bytes > 256 * 1024 {
        return Err(CliFailure::usage("EVIDENTRAIL_LOGS_BUDGET_INVALID"));
    }
    Ok(ConnectedQueryOptions {
        task,
        max_raw_bytes,
    })
}

fn render_connected_logs(pack: &ConnectedLogPack) -> Result<Vec<u8>, CliFailure> {
    let mut output = Vec::new();
    for entry in &pack.selected {
        let source_id = hex(&entry.source_digest);
        for (position, native_id, raw) in [
            (
                "first",
                entry.first_native_id.as_slice(),
                entry.first_raw.as_slice(),
            ),
            (
                "last",
                entry.last_native_id.as_deref().unwrap_or_default(),
                entry.last_raw.as_deref().unwrap_or_default(),
            ),
        ] {
            if position == "last" && entry.last_native_id.is_none() {
                continue;
            }
            let mut row = json!({
                "source_id": source_id,
                "native_id": URL_SAFE_NO_PAD.encode(native_id),
                "position": position,
                "repeat_count": entry.repeat_count,
            });
            if let Ok(original) = std::str::from_utf8(raw) {
                row["raw"] = json!(original);
            } else {
                row["raw_base64"] = json!(URL_SAFE_NO_PAD.encode(raw));
            }
            serde_json::to_writer(&mut output, &row)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_OUTPUT_FAILED"))?;
            output.push(b'\n');
        }
    }
    Ok(output)
}

fn sync_sources() -> Result<ExitCode, CliFailure> {
    sync_cycle().map(|had_error| ExitCode::from(u8::from(had_error)))
}

fn sync_cycle() -> Result<bool, CliFailure> {
    let _catalog_guard = connected_catalog_lock()?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let high_water = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    let mut outcomes = Vec::new();
    let mut had_error = false;
    let mut datadog_tiers = BTreeMap::<String, BTreeSet<String>>::new();
    let entries = authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let interrupted_rotations = interrupted_datadog_rotations(&entries)?;
    for entry in entries {
        let binding = parse_binding(&entry.descriptor)?;
        if let SourceBinding::Datadog(datadog) = &binding {
            datadog_tiers
                .entry(datadog.connection_id.clone())
                .or_default()
                .insert(datadog.tier.clone());
        }
        if matches!(&binding, SourceBinding::Datadog(datadog) if interrupted_rotations.contains(&datadog.connection_id))
        {
            had_error = true;
            outcomes.push(json!({
                "source_id": hex(&entry.source_digest),
                "status": "rotation_interrupted",
                "coverage": "incomplete"
            }));
            continue;
        }
        if matches!(&binding, SourceBinding::Datadog(datadog) if datadog.schema_version == 1) {
            had_error = true;
            outcomes.push(json!({
                "source_id": hex(&entry.source_digest),
                "status": "reconnect_required",
                "coverage": "incomplete"
            }));
            continue;
        }
        let path = corpus_path(&entry.source_digest, false)?;
        if !corpus_file_exists_safe(&path)? {
            had_error = true;
            outcomes.push(json!({
                "source_id": hex(&entry.source_digest),
                "status": "corpus_missing",
                "coverage": "incomplete"
            }));
            continue;
        }
        let key = authority
            .load(&tenant, &entry.source_digest)
            .map_err(|error| CliFailure::runtime(error.code()))?;
        let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
        let sync_result = sync_binding(
            &binding,
            &tenant,
            &entry.source_digest,
            &mut store,
            high_water,
        );
        let checkpoint = store
            .read_checkpoint()
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
        let record_count = store
            .record_count()
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
        let coverage = match &sync_result {
            Ok(progress)
                if progress.status == "scanned_to_high_water"
                    && progress.reconciliation == "recent_lookback_scanned"
                    && progress.historical_replay_complete() =>
            {
                "unverified_provider_consistency"
            }
            Ok(_) => "partial",
            Err(_) => "incomplete",
        };
        let status = match sync_result {
            Ok(progress) => json!({
                "status": progress.status,
                "pages": progress.pages,
                "reconciliation": progress.reconciliation,
                "historical_reconciliation": progress.historical_reconciliation,
            }),
            Err(error) => {
                had_error = true;
                json!({
                    "status": "sync_error",
                    "error": error,
                })
            }
        };
        outcomes.push(json!({
            "source_id": hex(&entry.source_digest),
            "provider": match binding { SourceBinding::CloudWatch(_) => "cloudwatch", SourceBinding::Datadog(_) => "datadog" },
            "record_count": record_count,
            "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
            "high_water_millis": high_water,
            "coverage": coverage,
            "result": status,
        }));
    }
    for (connection_id, tiers) in datadog_tiers {
        for tier in ["indexes", "online-archives", "flex"] {
            if !tiers.contains(tier) {
                had_error = true;
                outcomes.push(json!({
                    "provider": "datadog",
                    "connection_id": connection_id,
                    "tier": tier,
                    "status": "tier_not_connected",
                    "coverage": "incomplete",
                }));
            }
        }
    }
    serde_json::to_writer(io::stdout().lock(), &outcomes)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(had_error)
}

struct BoundedSyncProgress {
    status: &'static str,
    pages: usize,
    reconciliation: &'static str,
    historical_reconciliation: &'static str,
}

impl BoundedSyncProgress {
    fn historical_replay_complete(&self) -> bool {
        matches!(
            self.historical_reconciliation,
            "cycle_complete" | "recent_cycle_complete" | "not_applicable"
        )
    }
}

fn sync_binding(
    binding: &SourceBinding,
    tenant: &[u8; 32],
    source_digest: &[u8; 32],
    store: &mut EncryptedHistoryStore,
    high_water: i64,
) -> Result<BoundedSyncProgress, String> {
    let result = sync_binding_inner(binding, tenant, source_digest, store, high_water);
    let completed_at_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "ClockFailure".to_owned())?
        .as_millis() as i64;
    match result {
        Ok(progress) => {
            store
                .record_sync_observation(SyncObservation {
                    completed_at_millis,
                    high_water_millis: high_water,
                    scanned_to_high_water: progress.status == "scanned_to_high_water",
                    reconciled_lookback: progress.reconciliation == "recent_lookback_scanned",
                })
                .map_err(|error| format!("{error:?}"))?;
            Ok(progress)
        }
        Err(error) => {
            store
                .record_failed_sync_attempt(SyncAttempt {
                    completed_at_millis,
                    high_water_millis: high_water,
                    succeeded: false,
                })
                .map_err(|storage_error| format!("{storage_error:?}"))?;
            Err(error)
        }
    }
}

fn sync_binding_inner(
    binding: &SourceBinding,
    tenant: &[u8; 32],
    source_digest: &[u8; 32],
    store: &mut EncryptedHistoryStore,
    high_water: i64,
) -> Result<BoundedSyncProgress, String> {
    match binding {
        SourceBinding::CloudWatch(cloudwatch) => {
            let caller_arn = cloudwatch
                .caller_arn
                .as_deref()
                .ok_or_else(|| "EVIDENTRAIL_SOURCES_CLOUDWATCH_RECONNECT_REQUIRED".to_owned())?;
            let source_plan = plan(cloudwatch).map_err(|error| error.code.to_owned())?;
            let transport = AwsCloudWatchTransportV1::connect(
                source_plan.clone(),
                &cloudwatch.account,
                Some(caller_arn),
                cloudwatch.profile.as_deref(),
            )
            .map_err(|error| error.code().to_owned())?;
            let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
                .map_err(|_| "InvalidConfiguration".to_owned())?;
            bounded_sync(&mut source, store, high_water).map_err(|error| format!("{error:?}"))
        }
        SourceBinding::Datadog(datadog) => {
            let authority = MacOsConnectedCredentialKeychainV1::production();
            let secret = authority
                .load(tenant, source_digest)
                .map_err(|error| error.code().to_owned())?;
            let (mut api_key, mut application_key) =
                decode_datadog_secret(&secret).map_err(|error| error.code.to_owned())?;
            let mut source = DatadogHistorySourceV1::connect(
                datadog_site(&datadog.site).ok_or("InvalidConfiguration")?,
                datadog_tier(&datadog.tier).ok_or("InvalidConfiguration")?,
                std::mem::take(&mut *api_key),
                std::mem::take(&mut *application_key),
            )
            .map_err(|error| format!("{error:?}"))?;
            let current_identity = source
                .current_access_identity()
                .map_err(|error| format!("{error:?}"))?;
            check_datadog_identity(datadog, &current_identity)?;
            let access_scope_digest = source
                .current_access_scope_digest(&current_identity)
                .map_err(|error| format!("{error:?}"))?;
            store
                .bind_provider_access_scope(&access_scope_digest)
                .map_err(|_| "AccessScopeChangedOrUnbound".to_owned())?;
            bounded_sync(&mut source, store, high_water).map_err(|error| format!("{error:?}"))
        }
    }
}

fn bounded_sync(
    source: &mut impl HistoryPageSourceV1,
    store: &mut EncryptedHistoryStore,
    high_water: i64,
) -> Result<BoundedSyncProgress, HistorySyncErrorV1> {
    let mut partition_millis = 365 * DAY_MILLIS;
    let mut pages = 0;
    let mut reached = false;
    while pages < MAX_SYNC_PAGES {
        let receipt = synchronize_history_v1(
            source,
            store,
            high_water,
            HistorySyncLimitsV1 {
                partition_millis,
                max_partitions: 1,
                max_pages_per_partition: (MAX_SYNC_PAGES - pages).min(32),
                max_records_per_page: 10_000,
                max_record_bytes: 8 * 1024 * 1024,
            },
        )?;
        pages += receipt.committed_pages;
        match receipt.status {
            HistorySyncStatusV1::ScannedToHighWater => {
                reached = true;
                break;
            }
            HistorySyncStatusV1::PartialPageLimit => {
                if partition_millis <= 1 {
                    break;
                }
                partition_millis = (partition_millis / 2).max(1);
            }
            HistorySyncStatusV1::Backfilling => {}
            HistorySyncStatusV1::ReconciledLookback => {
                return Err(HistorySyncErrorV1::InvalidConfiguration);
            }
        }
    }
    if !reached {
        return Ok(BoundedSyncProgress {
            status: "backfilling",
            pages,
            reconciliation: "not_run",
            historical_reconciliation: "not_run_backfill",
        });
    }
    let remaining = MAX_SYNC_PAGES - pages;
    if remaining == 0 {
        return Ok(BoundedSyncProgress {
            status: "scanned_to_high_water",
            pages,
            reconciliation: "not_run_budget_exhausted",
            historical_reconciliation: "not_run_budget_exhausted",
        });
    }
    let reconciliation = reconcile_history_v1(
        source,
        store,
        7 * DAY_MILLIS,
        HistorySyncLimitsV1 {
            partition_millis: 7 * DAY_MILLIS,
            max_partitions: 1,
            max_pages_per_partition: remaining,
            max_records_per_page: 10_000,
            max_record_bytes: 8 * 1024 * 1024,
        },
    )?;
    pages += reconciliation.committed_pages;
    let reconciliation_status = match reconciliation.status {
        HistorySyncStatusV1::ReconciledLookback => "recent_lookback_scanned",
        HistorySyncStatusV1::Backfilling | HistorySyncStatusV1::PartialPageLimit => "partial",
        HistorySyncStatusV1::ScannedToHighWater => "partial",
    };
    let historical_reconciliation = if reconciliation_status != "recent_lookback_scanned" {
        "not_run_recent_partial"
    } else if pages == MAX_SYNC_PAGES {
        "not_run_budget_exhausted"
    } else {
        sweep_older_history(source, store, high_water, &mut pages)?
    };
    Ok(BoundedSyncProgress {
        status: "scanned_to_high_water",
        pages,
        reconciliation: reconciliation_status,
        historical_reconciliation,
    })
}

fn sweep_older_history(
    source: &mut impl HistoryPageSourceV1,
    store: &mut EncryptedHistoryStore,
    high_water: i64,
    pages: &mut usize,
) -> Result<&'static str, HistorySyncErrorV1> {
    let older_end = high_water.saturating_sub(7 * DAY_MILLIS);
    if older_end <= 0 {
        return Ok("not_applicable");
    }
    let mut cursor = store
        .read_historical_reconciliation_cursor()
        .map_err(|_| HistorySyncErrorV1::Store)?;
    if cursor == 0
        && store
            .read_historical_reconciliation_last_cycle_end()
            .map_err(|_| HistorySyncErrorV1::Store)?
            .is_some_and(|last_end| older_end.saturating_sub(last_end) < DAY_MILLIS)
    {
        return Ok("recent_cycle_complete");
    }
    if cursor >= older_end {
        return Err(HistorySyncErrorV1::InvalidConfiguration);
    }
    let mut partition_millis = store
        .read_historical_reconciliation_partition_millis()
        .map_err(|_| HistorySyncErrorV1::Store)?;
    let sweep_page_limit = (*pages + MAX_HISTORICAL_PAGES_PER_PASS).min(MAX_SYNC_PAGES);
    while *pages < sweep_page_limit {
        let receipt = reconcile_history_range_v1(
            source,
            store,
            cursor,
            older_end,
            HistorySyncLimitsV1 {
                partition_millis,
                max_partitions: 1,
                max_pages_per_partition: (sweep_page_limit - *pages).min(32),
                max_records_per_page: 10_000,
                max_record_bytes: 8 * 1024 * 1024,
            },
        )?;
        *pages += receipt.committed_pages;
        if receipt.completed_through_millis > cursor {
            store
                .record_historical_reconciliation_progress(
                    cursor,
                    receipt.completed_through_millis,
                    older_end,
                )
                .map_err(|_| HistorySyncErrorV1::Store)?;
            cursor = receipt.completed_through_millis;
        }
        if cursor == older_end {
            return Ok("cycle_complete");
        }
        if receipt.status == HistorySyncStatusV1::PartialPageLimit {
            if partition_millis == 1 {
                return Ok("partial_page_limit");
            }
            partition_millis = (partition_millis / 2).max(1);
            store
                .record_historical_reconciliation_partition_hint(cursor, partition_millis)
                .map_err(|_| HistorySyncErrorV1::Store)?;
        }
    }
    Ok("progress_partial")
}

fn parse_cloudwatch_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<CloudWatchDescriptor, CliFailure> {
    let mut account = None;
    let mut region = None;
    let mut log_group = None;
    let mut profile = None;
    while let Some(option) = args.next() {
        let target = if option == "--account" {
            &mut account
        } else if option == "--region" {
            &mut region
        } else if option == "--log-group" {
            &mut log_group
        } else if option == "--profile" {
            &mut profile
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_MISSING_VALUE"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_VALUE"))?;
        if target.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_DUPLICATE_OPTION"));
        }
    }
    let binding = CloudWatchDescriptor {
        schema_version: 1,
        provider: "cloudwatch".to_owned(),
        account: account
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_ACCOUNT_REQUIRED"))?,
        region: region.ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_REGION_REQUIRED"))?,
        log_group: log_group
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_LOG_GROUP_REQUIRED"))?,
        profile,
        caller_arn: None,
    };
    validate_binding(&binding)?;
    Ok(binding)
}

fn validate_binding(binding: &CloudWatchDescriptor) -> Result<(), CliFailure> {
    if binding.schema_version != 1
        || binding.provider != "cloudwatch"
        || binding.account.len() != 12
        || !binding.account.bytes().all(|byte| byte.is_ascii_digit())
        || binding.region.is_empty()
        || binding.region.len() > 64
        || !binding
            .region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || binding.log_group.is_empty()
        || binding.log_group.len()
            > if binding.log_group.starts_with("arn:") {
                2048
            } else {
                512
            }
        || binding.log_group.chars().any(char::is_control)
        || binding.profile.as_ref().is_some_and(|profile| {
            profile.is_empty()
                || profile.len() > 128
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"));
    }
    Ok(())
}

fn datadog_site(value: &str) -> Option<DatadogSiteV1> {
    Some(match value {
        "us1" => DatadogSiteV1::Us1,
        "us3" => DatadogSiteV1::Us3,
        "us5" => DatadogSiteV1::Us5,
        "eu1" => DatadogSiteV1::Eu1,
        "ap1" => DatadogSiteV1::Ap1,
        "ap2" => DatadogSiteV1::Ap2,
        "uk1" => DatadogSiteV1::Uk1,
        "us1-fed" => DatadogSiteV1::Us1Fed,
        "us2-fed" => DatadogSiteV1::Us2Fed,
        _ => return None,
    })
}

fn datadog_tier(value: &str) -> Option<DatadogStorageTierV1> {
    Some(match value {
        "indexes" => DatadogStorageTierV1::Indexes,
        "online-archives" => DatadogStorageTierV1::OnlineArchives,
        "flex" => DatadogStorageTierV1::Flex,
        _ => return None,
    })
}

fn valid_datadog_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn check_datadog_identity(
    binding: &DatadogDescriptor,
    current: &DatadogAccessIdentityV1,
) -> Result<(), String> {
    if binding.schema_version != 2 {
        return Err("LegacyBindingRequiresReconnect".to_owned());
    }
    if binding.org_id != current.org_id
        || binding.user_id.as_deref() != Some(current.user_id.as_str())
        || binding.role_ids.as_ref() != Some(&current.role_ids)
    {
        return Err("AccessIdentityChanged".to_owned());
    }
    Ok(())
}

fn validate_datadog_binding(binding: &DatadogDescriptor) -> Result<(), CliFailure> {
    if !matches!(binding.schema_version, 1 | 2)
        || binding.provider != "datadog"
        || datadog_site(&binding.site).is_none()
        || datadog_tier(&binding.tier).is_none()
        || binding.connection_id.len() != 32
        || !binding
            .connection_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !valid_datadog_id(&binding.org_id)
        || (binding.schema_version == 2
            && (!binding.user_id.as_deref().is_some_and(valid_datadog_id)
                || !binding.role_ids.as_ref().is_some_and(|roles| {
                    !roles.is_empty()
                        && roles.len() <= 128
                        && roles.iter().all(|role| valid_datadog_id(role))
                        && roles.windows(2).all(|pair| pair[0] < pair[1])
                })))
    {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"));
    }
    Ok(())
}

fn encode_datadog_secret(
    api_key: &str,
    application_key: &str,
) -> Result<Zeroizing<Vec<u8>>, CliFailure> {
    if api_key.is_empty()
        || application_key.is_empty()
        || api_key.len() > 1024
        || application_key.len() > 1024
        || !api_key.bytes().all(|byte| byte.is_ascii_graphic())
        || !application_key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CliFailure::usage("EVIDENTRAIL_DATADOG_CREDENTIAL_INVALID"));
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(
        4 + api_key.len() + application_key.len(),
    ));
    secret.extend_from_slice(&(api_key.len() as u16).to_be_bytes());
    secret.extend_from_slice(&(application_key.len() as u16).to_be_bytes());
    secret.extend_from_slice(api_key.as_bytes());
    secret.extend_from_slice(application_key.as_bytes());
    Ok(secret)
}

fn decode_datadog_secret(
    secret: &[u8],
) -> Result<(Zeroizing<String>, Zeroizing<String>), CliFailure> {
    if secret.len() < 6 {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_CREDENTIAL_CORRUPT",
        ));
    }
    let api_length = u16::from_be_bytes([secret[0], secret[1]]) as usize;
    let app_length = u16::from_be_bytes([secret[2], secret[3]]) as usize;
    if api_length == 0
        || app_length == 0
        || api_length > 1024
        || app_length > 1024
        || secret.len() != 4 + api_length + app_length
    {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_CREDENTIAL_CORRUPT",
        ));
    }
    let api_key = std::str::from_utf8(&secret[4..4 + api_length])
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_CREDENTIAL_CORRUPT"))?;
    let application_key = std::str::from_utf8(&secret[4 + api_length..])
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_CREDENTIAL_CORRUPT"))?;
    if !api_key.bytes().all(|byte| byte.is_ascii_graphic())
        || !application_key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_CREDENTIAL_CORRUPT",
        ));
    }
    Ok((
        Zeroizing::new(api_key.to_owned()),
        Zeroizing::new(application_key.to_owned()),
    ))
}

struct DatadogConnectOptions {
    site: String,
    api_key_env: String,
    application_key_env: String,
}

struct DatadogRotateOptions {
    connection_id: String,
    api_key_env: String,
    application_key_env: String,
}

fn parse_datadog_rotation_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<DatadogRotateOptions, CliFailure> {
    let mut connection_id = None;
    let mut api_key_env = None;
    let mut application_key_env = None;
    while let Some(option) = args.next() {
        let target = if option == "--connection-id" {
            &mut connection_id
        } else if option == "--api-key-env" {
            &mut api_key_env
        } else if option == "--application-key-env" {
            &mut application_key_env
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_MISSING_VALUE"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_VALUE"))?;
        if target.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_DUPLICATE_OPTION"));
        }
    }
    let options = DatadogRotateOptions {
        connection_id: connection_id
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_DATADOG_CONNECTION_ID_REQUIRED"))?,
        api_key_env: api_key_env.unwrap_or_else(|| "DD_API_KEY".to_owned()),
        application_key_env: application_key_env.unwrap_or_else(|| "DD_APP_KEY".to_owned()),
    };
    if options.connection_id.len() != 32
        || !options
            .connection_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !valid_env_name(&options.api_key_env)
        || !valid_env_name(&options.application_key_env)
        || options.api_key_env == options.application_key_env
    {
        return Err(CliFailure::usage("EVIDENTRAIL_DATADOG_OPTIONS_INVALID"));
    }
    Ok(options)
}

fn parse_datadog_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<DatadogConnectOptions, CliFailure> {
    let mut site = None;
    let mut api_key_env = None;
    let mut application_key_env = None;
    while let Some(option) = args.next() {
        let target = if option == "--site" {
            &mut site
        } else if option == "--api-key-env" {
            &mut api_key_env
        } else if option == "--application-key-env" {
            &mut application_key_env
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_MISSING_VALUE"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_VALUE"))?;
        if target.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_DUPLICATE_OPTION"));
        }
    }
    let options = DatadogConnectOptions {
        site: site.ok_or_else(|| CliFailure::usage("EVIDENTRAIL_DATADOG_SITE_REQUIRED"))?,
        api_key_env: api_key_env.unwrap_or_else(|| "DD_API_KEY".to_owned()),
        application_key_env: application_key_env.unwrap_or_else(|| "DD_APP_KEY".to_owned()),
    };
    if datadog_site(&options.site).is_none()
        || !valid_env_name(&options.api_key_env)
        || !valid_env_name(&options.application_key_env)
        || options.api_key_env == options.application_key_env
    {
        return Err(CliFailure::usage("EVIDENTRAIL_DATADOG_OPTIONS_INVALID"));
    }
    Ok(options)
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !value.as_bytes()[0].is_ascii_digit()
}

fn connect_datadog(options: DatadogConnectOptions) -> Result<ExitCode, CliFailure> {
    let api_key = Zeroizing::new(
        env::var(&options.api_key_env)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_DATADOG_API_KEY_UNAVAILABLE"))?,
    );
    let application_key = Zeroizing::new(
        env::var(&options.application_key_env)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_DATADOG_APP_KEY_UNAVAILABLE"))?,
    );
    let secret = encode_datadog_secret(&api_key, &application_key)?;
    let site = datadog_site(&options.site)
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_DATADOG_OPTIONS_INVALID"))?;
    let identity_source = DatadogHistorySourceV1::connect(
        site,
        DatadogStorageTierV1::Indexes,
        api_key.to_string(),
        application_key.to_string(),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_IDENTITY_FAILED"))?;
    let identity = identity_source
        .current_access_identity()
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_IDENTITY_FAILED"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    let mut probes = Vec::new();
    for (name, tier) in [
        ("indexes", DatadogStorageTierV1::Indexes),
        ("online-archives", DatadogStorageTierV1::OnlineArchives),
        ("flex", DatadogStorageTierV1::Flex),
    ] {
        let probe = DatadogHistorySourceV1::connect(
            site,
            tier,
            api_key.to_string(),
            application_key.to_string(),
        )
        .and_then(|mut source| {
            source.current_access_scope_digest(&identity)?;
            source.fetch_page(
                HistoryPartitionV1 {
                    start_millis: now.saturating_sub(1000),
                    end_millis: now,
                },
                None,
            )
        });
        probes.push((
            name,
            probe.map(|_| ()).map_err(|error| format!("{error:?}")),
        ));
    }
    if !probes.iter().any(|(_, result)| result.is_ok()) {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_READ_VERIFICATION_FAILED",
        ));
    }
    let _catalog_guard = connected_catalog_lock()?;
    let corpus_authority = MacOsCorpusKeychainV1::production();
    let credential_authority = MacOsConnectedCredentialKeychainV1::production();
    let tenant = corpus_authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let mut random_id = [0u8; 16];
    getrandom::fill(&mut random_id)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_CONNECTION_ID_FAILED"))?;
    let connection_id = hex(&random_id);
    let mut registered = Vec::new();
    let mut outcomes = Vec::new();
    for (tier, probe) in probes {
        if let Err(error) = probe {
            outcomes.push(json!({"tier": tier, "status": "not_connected", "error": error}));
            continue;
        }
        let binding = DatadogDescriptor {
            schema_version: 2,
            provider: "datadog".to_owned(),
            site: options.site.clone(),
            tier: tier.to_owned(),
            connection_id: connection_id.clone(),
            org_id: identity.org_id.clone(),
            user_id: Some(identity.user_id.clone()),
            role_ids: Some(identity.role_ids.clone()),
        };
        let result = register_datadog_tier(
            &corpus_authority,
            &credential_authority,
            &tenant,
            &binding,
            &secret,
        );
        match result {
            Ok((source_digest, path)) => {
                registered.push((source_digest, path));
                outcomes.push(json!({
                    "tier": tier,
                    "source_id": hex(&source_digest),
                    "status": "registered_backfill_pending",
                }));
            }
            Err(error) => {
                rollback_datadog_registration(
                    &corpus_authority,
                    &credential_authority,
                    &tenant,
                    &registered,
                )?;
                return Err(error);
            }
        }
    }
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({
            "provider": "datadog",
            "site": options.site,
            "connection_id": connection_id,
            "org_id": identity.org_id,
            "tiers": outcomes,
            "coverage": "partial_until_backfill_and_provider_consistency_verified",
        }),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn rotate_datadog(options: DatadogRotateOptions, recovering: bool) -> Result<ExitCode, CliFailure> {
    let api_key = Zeroizing::new(
        env::var(&options.api_key_env)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_DATADOG_API_KEY_UNAVAILABLE"))?,
    );
    let application_key = Zeroizing::new(
        env::var(&options.application_key_env)
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_DATADOG_APP_KEY_UNAVAILABLE"))?,
    );
    let secret = encode_datadog_secret(&api_key, &application_key)?;
    let _catalog_guard = connected_catalog_lock()?;
    let corpus_authority = MacOsCorpusKeychainV1::production();
    let credential_authority = MacOsConnectedCredentialKeychainV1::production();
    let tenant = corpus_authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let mut bound = Vec::new();
    for entry in corpus_authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        if let SourceBinding::Datadog(binding) = parse_binding(&entry.descriptor)? {
            if binding.connection_id == options.connection_id {
                bound.push((entry.source_digest, binding));
            }
        }
    }
    let (_, first) = bound
        .first()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_DATADOG_CONNECTION_NOT_FOUND"))?;
    let interrupted = bound.iter().try_fold(false, |found, (source, _)| {
        rotation_artifact_present(&corpus_path(source, false)?).map(|present| found || present)
    })?;
    if interrupted && !recovering {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_ROTATION_INTERRUPTED",
        ));
    }
    if recovering && !interrupted {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_RECOVERY_NOT_NEEDED",
        ));
    }
    let site = datadog_site(&first.site)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
    let expected_org = first.org_id.clone();
    let mut tiers = BTreeSet::new();
    for (_, binding) in &bound {
        if binding.site != first.site
            || binding.org_id != expected_org
            || !tiers.insert(binding.tier.as_str())
        {
            return Err(CliFailure::runtime(
                "EVIDENTRAIL_DATADOG_CONNECTION_SCOPE_MISMATCH",
            ));
        }
    }
    let identity = DatadogHistorySourceV1::connect(
        site,
        DatadogStorageTierV1::Indexes,
        api_key.to_string(),
        application_key.to_string(),
    )
    .and_then(|source| source.current_access_identity())
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_IDENTITY_FAILED"))?;
    if identity.org_id != expected_org {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_ROTATION_ORG_CHANGED",
        ));
    }
    for (_, binding) in &bound {
        check_datadog_identity(binding, &identity)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_SCOPE_CHANGED"))?;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    for (_, binding) in &bound {
        let tier = datadog_tier(&binding.tier)
            .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        let mut source = DatadogHistorySourceV1::connect(
            site,
            tier,
            api_key.to_string(),
            application_key.to_string(),
        )
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_READ_FAILED"))?;
        source
            .current_access_scope_digest(&identity)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_SCOPE_FAILED"))?;
        source
            .fetch_page(
                HistoryPartitionV1 {
                    start_millis: now.saturating_sub(1000),
                    end_millis: now,
                },
                None,
            )
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_READ_FAILED"))?;
    }
    let old = bound
        .iter()
        .map(|(source_digest, _)| {
            credential_authority
                .load(&tenant, source_digest)
                .map(|previous| (*source_digest, previous))
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STORE_FAILED"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // New credentials can have narrower restriction queries in the same org.
    // Move old encrypted corpora out of the active paths before changing any
    // key. A failed, fully rolled-back update can restore them without loss.
    let paths = old
        .iter()
        .map(|(source, _)| corpus_path(source, false))
        .collect::<Result<Vec<_>, _>>()?;
    let staged = stage_rotation_corpora(&paths)?;
    let replacement = replace_datadog_secrets_with_rollback(&old, &secret, |source, value| {
        credential_authority
            .replace(&tenant, source, value)
            .map_err(|_| ())
    });
    if recovering && replacement.is_err() {
        // The prior interrupted rotation may already have left different
        // credentials on different tiers. Keep all staged files as a gate;
        // restoring these active paths would risk serving an old scope.
        return Err(CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"));
    }
    if replacement == Err("EVIDENTRAIL_DATADOG_ROTATION_STORE_FAILED") {
        restore_rotation_corpora(&staged)?;
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_ROTATION_STORE_FAILED",
        ));
    }
    if replacement.is_err() {
        purge_staged_rotation_corpora(&staged)?;
        return Err(CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"));
    }
    let mut rebuild_failed = false;
    for (source, _) in &old {
        rebuild_failed |= corpus_path(source, true)
            .and_then(|path| recreate_empty_corpus(&path, &corpus_authority, &tenant, source))
            .is_err();
    }
    if rebuild_failed {
        if !recovering {
            purge_staged_rotation_corpora(&staged)?;
        }
        return Err(CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"));
    }
    if recovering {
        purge_rotation_artifacts(&paths)?;
    } else {
        purge_staged_rotation_corpora(&staged)?;
    }
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({
            "provider": "datadog",
            "connection_id": options.connection_id,
            "status": if recovering { "rotation_recovered_backfill_pending" } else { "credentials_rotated_backfill_pending" },
            "source_ids": old.iter().map(|(source, _)| hex(source)).collect::<Vec<_>>(),
        }),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn recreate_empty_corpus(
    path: &Path,
    authority: &MacOsCorpusKeychainV1,
    tenant: &[u8; 32],
    source: &[u8; 32],
) -> Result<(), CliFailure> {
    if corpus_file_exists_safe(path)? {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_ROTATION_REBUILD_FAILED",
        ));
    }
    let key = authority
        .load(tenant, source)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_REBUILD_FAILED"))?;
    let reserved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_REBUILD_FAILED"))?;
    drop(reserved);
    if EncryptedHistoryStore::open(path, &key, tenant, source).is_err() {
        let _ = remove_corpus_files(path, "EVIDENTRAIL_DATADOG_ROTATION_REBUILD_FAILED");
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_DATADOG_ROTATION_REBUILD_FAILED",
        ));
    }
    Ok(())
}

struct StagedRotationFile {
    original: PathBuf,
    staged: PathBuf,
}

fn rotation_artifact_present(path: &Path) -> Result<bool, CliFailure> {
    Ok(!rotation_artifact_paths(path)?.is_empty())
}

fn rotation_artifact_paths(path: &Path) -> Result<Vec<PathBuf>, CliFailure> {
    let parent = path
        .parent()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED"))?;
    let prefix = format!(
        "{}.rotation-",
        path.file_name()
            .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED"))?
            .to_string_lossy()
    );
    let files = match fs::read_dir(parent) {
        Ok(files) => files,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err(CliFailure::runtime(
                "EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED",
            ));
        }
    };
    let mut artifacts = Vec::new();
    for file in files {
        let file =
            file.map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED"))?;
        if file.file_name().to_string_lossy().starts_with(&prefix) {
            artifacts.push(file.path());
        }
    }
    Ok(artifacts)
}

fn purge_rotation_artifacts(paths: &[PathBuf]) -> Result<(), CliFailure> {
    for path in paths {
        for artifact in rotation_artifact_paths(path)? {
            fs::remove_file(artifact)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"))?;
        }
    }
    Ok(())
}

fn interrupted_datadog_rotations(
    entries: &[ConnectedSourceDescriptorV1],
) -> Result<BTreeSet<String>, CliFailure> {
    interrupted_datadog_rotations_at(entries, |source| corpus_path(source, false))
}

fn interrupted_datadog_rotations_at(
    entries: &[ConnectedSourceDescriptorV1],
    mut path_for: impl FnMut(&[u8; 32]) -> Result<PathBuf, CliFailure>,
) -> Result<BTreeSet<String>, CliFailure> {
    let mut interrupted = BTreeSet::new();
    for entry in entries {
        if let SourceBinding::Datadog(binding) = parse_binding(&entry.descriptor)? {
            let path = path_for(&entry.source_digest)?;
            if rotation_artifact_present(&path)? {
                interrupted.insert(binding.connection_id);
            }
        }
    }
    Ok(interrupted)
}

fn stage_rotation_corpora(paths: &[PathBuf]) -> Result<Vec<StagedRotationFile>, CliFailure> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED"))?;
    let nonce = hex(&nonce);
    let mut staged = Vec::new();
    for path in paths {
        let result = (|| {
            let name = path
                .file_name()
                .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED"))?;
            let name = name.to_string_lossy();
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let original = path.with_file_name(format!("{name}{suffix}"));
                let staged_path = path.with_file_name(format!("{name}.rotation-{nonce}{suffix}"));
                let metadata = match fs::symlink_metadata(&original) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        return Err(CliFailure::runtime(
                            "EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED",
                        ));
                    }
                };
                let staged_absent = matches!(
                    staged_path.symlink_metadata(),
                    Err(error) if error.kind() == io::ErrorKind::NotFound
                );
                if !metadata.file_type().is_file() || !staged_absent {
                    return Err(CliFailure::runtime(
                        "EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED",
                    ));
                }
                fs::rename(&original, &staged_path).map_err(|_| {
                    CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_STAGE_FAILED")
                })?;
                staged.push(StagedRotationFile {
                    original,
                    staged: staged_path,
                });
            }
            Ok(())
        })();
        if let Err(error) = result {
            restore_rotation_corpora(&staged)?;
            return Err(error);
        }
    }
    Ok(staged)
}

fn restore_rotation_corpora(staged: &[StagedRotationFile]) -> Result<(), CliFailure> {
    let mut failed = false;
    for file in staged.iter().rev() {
        if file.original.symlink_metadata().is_ok()
            || fs::rename(&file.staged, &file.original).is_err()
        {
            failed = true;
        }
    }
    if failed {
        Err(CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"))
    } else {
        Ok(())
    }
}

fn purge_staged_rotation_corpora(staged: &[StagedRotationFile]) -> Result<(), CliFailure> {
    let mut failed = false;
    for file in staged {
        failed |= fs::remove_file(&file.staged).is_err();
    }
    if failed {
        Err(CliFailure::runtime("EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"))
    } else {
        Ok(())
    }
}

fn replace_datadog_secrets_with_rollback(
    old: &[([u8; 32], Zeroizing<Vec<u8>>)],
    new: &[u8],
    mut replace: impl FnMut(&[u8; 32], &[u8]) -> Result<(), ()>,
) -> Result<(), &'static str> {
    for index in 0..old.len() {
        if replace(&old[index].0, new).is_err() {
            let mut rollback_failed = false;
            for (source, previous) in old[..=index].iter().rev() {
                rollback_failed |= replace(source, previous).is_err();
            }
            return Err(if rollback_failed {
                "EVIDENTRAIL_DATADOG_ROTATION_PARTIAL"
            } else {
                "EVIDENTRAIL_DATADOG_ROTATION_STORE_FAILED"
            });
        }
    }
    Ok(())
}

fn register_datadog_tier(
    corpus_authority: &MacOsCorpusKeychainV1,
    credential_authority: &MacOsConnectedCredentialKeychainV1,
    tenant: &[u8; 32],
    binding: &DatadogDescriptor,
    secret: &[u8],
) -> Result<([u8; 32], PathBuf), CliFailure> {
    validate_datadog_binding(binding)?;
    let descriptor = serde_json::to_vec(binding)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
    let source_digest = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let path = corpus_path(&source_digest, true)?;
    credential_authority
        .create(tenant, &source_digest, secret)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    if let Err(error) = register_corpus(corpus_authority, tenant, &descriptor, &path) {
        credential_authority
            .destroy(tenant, &source_digest)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROLLBACK_FAILED"))?;
        return Err(error);
    }
    Ok((source_digest, path))
}

fn rollback_datadog_registration(
    corpus_authority: &MacOsCorpusKeychainV1,
    credential_authority: &MacOsConnectedCredentialKeychainV1,
    tenant: &[u8; 32],
    registered: &[([u8; 32], PathBuf)],
) -> Result<(), CliFailure> {
    for (source_digest, path) in registered {
        remove_corpus_files(path, "EVIDENTRAIL_DATADOG_ROLLBACK_FAILED")?;
        corpus_authority
            .destroy(tenant, source_digest)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROLLBACK_FAILED"))?;
        credential_authority
            .destroy(tenant, source_digest)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_DATADOG_ROLLBACK_FAILED"))?;
    }
    Ok(())
}

fn remove_corpus_files(path: &Path, error_code: &'static str) -> Result<(), CliFailure> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(CliFailure::runtime(error_code)),
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| CliFailure::runtime(error_code))?
        .to_string_lossy();
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = path.with_file_name(format!("{file_name}{suffix}"));
        match fs::remove_file(sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CliFailure::runtime(error_code)),
        }
    }
    Ok(())
}

fn plan(binding: &CloudWatchDescriptor) -> Result<CloudWatchPlanV1, CliFailure> {
    let caps = CloudWatchCapsV1::new(10_000, 16 * 1024 * 1024, 1, 8 * 1024 * 1024)
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))?;
    CloudWatchPlanV1::new(
        binding.account.as_bytes().to_vec(),
        binding.region.as_bytes().to_vec(),
        binding.log_group.as_bytes().to_vec(),
        Vec::<Vec<u8>>::new(),
        None,
        None,
        None,
        caps,
    )
    .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))
}

fn connect_cloudwatch(mut binding: CloudWatchDescriptor) -> Result<ExitCode, CliFailure> {
    let source_plan = plan(&binding)?;
    let transport = AwsCloudWatchTransportV1::connect(
        source_plan.clone(),
        &binding.account,
        None,
        binding.profile.as_deref(),
    )
    .map_err(|error| CliFailure::runtime(error.code()))?;
    binding.caller_arn = Some(transport.caller_arn().to_owned());
    let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    // A narrow internal permission probe; it is not a product query window.
    source
        .fetch_page(
            HistoryPartitionV1 {
                start_millis: now.saturating_sub(1000),
                end_millis: now,
            },
            None,
        )
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_READ_VERIFICATION_FAILED"))?;

    let _catalog_guard = connected_catalog_lock()?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let descriptor = serde_json::to_vec(&binding)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
    let source_digest = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let path = corpus_path(&source_digest, true)?;
    register_corpus(&authority, &tenant, &descriptor, &path)?;
    let response = json!({
        "source_id": hex(&source_digest),
        "provider": "cloudwatch",
        "account": binding.account,
        "region": binding.region,
        "log_group": binding.log_group,
        "status": "registered_backfill_pending"
    });
    serde_json::to_writer(io::stdout().lock(), &response)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn register_corpus(
    authority: &MacOsCorpusKeychainV1,
    tenant: &[u8; 32],
    descriptor: &[u8],
    path: &Path,
) -> Result<(), CliFailure> {
    let (source_digest, key) = authority
        .create_bound(tenant, descriptor)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let reserved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    if reserved.is_err() {
        let _ = authority.destroy(tenant, &source_digest);
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_CORPUS_CREATE_FAILED",
        ));
    }
    drop(reserved);
    if EncryptedHistoryStore::open(path, &key, tenant, &source_digest).is_err() {
        let _ = fs::remove_file(path);
        let _ = authority.destroy(tenant, &source_digest);
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_CORPUS_CREATE_FAILED",
        ));
    }
    Ok(())
}

fn list_sources() -> Result<ExitCode, CliFailure> {
    let _catalog_guard = connected_catalog_lock()?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    let mut listed = Vec::new();
    let entries = authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let interrupted_rotations = interrupted_datadog_rotations(&entries)?;
    for entry in entries {
        let binding = parse_binding(&entry.descriptor)?;
        let path = corpus_path(&entry.source_digest, false)?;
        let status = if matches!(&binding, SourceBinding::Datadog(datadog) if interrupted_rotations.contains(&datadog.connection_id))
        {
            json!({"state": "rotation_interrupted", "coverage": "incomplete"})
        } else if matches!(&binding, SourceBinding::Datadog(datadog) if datadog.schema_version == 1)
        {
            json!({"state": "reconnect_required", "coverage": "incomplete"})
        } else if corpus_file_exists_safe(&path)? {
            let key = authority
                .load(&tenant, &entry.source_digest)
                .map_err(|error| CliFailure::runtime(error.code()))?;
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let record_count = store
                .record_count()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let unbound_datadog = matches!(&binding, SourceBinding::Datadog(_))
                && record_count > 0
                && !store
                    .provider_access_scope_bound()
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let checkpoint = store
                .read_checkpoint()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let observation = store
                .read_sync_observation()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let attempt = store
                .read_sync_attempt()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let historical_cursor = store
                .read_historical_reconciliation_cursor()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let historical_last_cycle_end =
                store
                    .read_historical_reconciliation_last_cycle_end()
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let historical_recent = observation.is_some_and(|value| {
                let older_end = value.high_water_millis.saturating_sub(7 * DAY_MILLIS);
                older_end <= 0
                    || (historical_cursor == 0
                        && historical_last_cycle_end
                            .is_some_and(|last| older_end.saturating_sub(last) < DAY_MILLIS))
            });
            let last_attempt_failed = attempt.is_some_and(|value| !value.succeeded);
            json!({
                "state": if unbound_datadog { "reconnect_required" } else if last_attempt_failed { "last_sync_failed" } else if observation.is_some() { "sync_observed" } else { "registered_incomplete" },
                "record_count": record_count,
                "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
                "last_sync_completed_at_millis": observation.map(|value| value.completed_at_millis),
                "last_sync_high_water_millis": observation.map(|value| value.high_water_millis),
                "last_sync_age_millis": observation.map(|value| now_millis.saturating_sub(value.completed_at_millis)),
                "last_sync_scanned_to_high_water": observation.map(|value| value.scanned_to_high_water),
                "last_sync_reconciled_lookback": observation.map(|value| value.reconciled_lookback),
                "historical_reconciliation_cursor_millis": historical_cursor,
                "historical_last_cycle_end_millis": historical_last_cycle_end,
                "last_attempt_completed_at_millis": attempt.map(|value| value.completed_at_millis),
                "last_attempt_high_water_millis": attempt.map(|value| value.high_water_millis),
                "last_attempt_age_millis": attempt.map(|value| now_millis.saturating_sub(value.completed_at_millis)),
                "last_attempt_succeeded": attempt.map(|value| value.succeeded),
                "coverage": if unbound_datadog || last_attempt_failed {
                    "incomplete"
                } else if historical_recent && observation.is_some_and(|value| value.scanned_to_high_water && value.reconciled_lookback) {
                    "unverified_provider_consistency_at_last_sync"
                } else {
                    "partial"
                },
            })
        } else {
            json!({"state": "corpus_missing"})
        };
        let summary = match binding {
            SourceBinding::CloudWatch(binding) => json!({
                "source_id": hex(&entry.source_digest),
                "provider": "cloudwatch",
                "account": binding.account,
                "region": binding.region,
                "log_group": binding.log_group,
                "status": status,
            }),
            SourceBinding::Datadog(binding) => json!({
                "source_id": hex(&entry.source_digest),
                "provider": "datadog",
                "site": binding.site,
                "tier": binding.tier,
                "connection_id": binding.connection_id,
                "org_id": binding.org_id,
                "status": status,
            }),
        };
        listed.push(summary);
    }
    serde_json::to_writer(io::stdout().lock(), &listed)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn disconnect_source(requested_source: [u8; 32]) -> Result<ExitCode, CliFailure> {
    let _catalog_guard = connected_catalog_lock()?;
    let corpus_authority = MacOsCorpusKeychainV1::production();
    let credential_authority = MacOsConnectedCredentialKeychainV1::production();
    let tenant = corpus_authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let source_ids = revoke_registered_sources(
        requested_source,
        &tenant,
        &corpus_authority,
        &credential_authority,
        |digest| corpus_path(digest, false),
    )?;
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({"status": "disconnected", "source_ids": source_ids}),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn revoke_registered_sources(
    requested_source: [u8; 32],
    tenant: &[u8; 32],
    corpus_authority: &MacOsCorpusKeychainV1,
    credential_authority: &MacOsConnectedCredentialKeychainV1,
    path_for_source: impl Fn(&[u8; 32]) -> Result<PathBuf, CliFailure>,
) -> Result<Vec<String>, CliFailure> {
    let entries = corpus_authority
        .list_bound(tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let bindings = entries
        .iter()
        .map(|entry| parse_binding(&entry.descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = revocation_indices(requested_source, &entries, &bindings)?;
    let mut paths = Vec::with_capacity(selected.len());
    for index in &selected {
        let entry = &entries[*index];
        let path = path_for_source(&entry.source_digest)?;
        corpus_file_exists_safe(&path)?;
        paths.push(path);
    }
    // Remove provider credentials before deleting any corpus. A partial
    // failure then excludes the affected Datadog source from future queries.
    for index in &selected {
        if matches!(&bindings[*index], SourceBinding::Datadog(_)) {
            match credential_authority.destroy(tenant, &entries[*index].source_digest) {
                Ok(()) | Err(CorpusKeychainErrorV1::NotFound) => {}
                Err(_) => return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_REVOKE_FAILED")),
            }
        }
    }
    for path in &paths {
        remove_corpus_files(path, "EVIDENTRAIL_SOURCES_REVOKE_FAILED")?;
        for artifact in rotation_artifact_paths(path)? {
            fs::remove_file(artifact)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_REVOKE_FAILED"))?;
        }
    }
    for index in &selected {
        match corpus_authority.destroy(tenant, &entries[*index].source_digest) {
            Ok(()) | Err(CorpusKeychainErrorV1::NotFound) => {}
            Err(_) => return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_REVOKE_FAILED")),
        }
    }
    let source_ids = selected
        .iter()
        .map(|index| hex(&entries[*index].source_digest))
        .collect::<Vec<_>>();
    Ok(source_ids)
}

fn revocation_indices(
    requested_source: [u8; 32],
    entries: &[ConnectedSourceDescriptorV1],
    bindings: &[SourceBinding],
) -> Result<Vec<usize>, CliFailure> {
    if entries.len() != bindings.len() {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE",
        ));
    }
    let requested_index = entries
        .iter()
        .position(|entry| entry.source_digest == requested_source)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_NOT_FOUND"))?;
    let selected = match &bindings[requested_index] {
        SourceBinding::CloudWatch(_) => vec![requested_index],
        SourceBinding::Datadog(target) => bindings
            .iter()
            .enumerate()
            .filter_map(|(index, binding)| match binding {
                SourceBinding::Datadog(candidate)
                    if candidate.connection_id == target.connection_id
                        && candidate.site == target.site
                        && candidate.org_id == target.org_id =>
                {
                    Some(index)
                }
                _ => None,
            })
            .collect(),
    };
    Ok(selected)
}

fn corpus_path(source_digest: &[u8; 32], create_dirs: bool) -> Result<PathBuf, CliFailure> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"))?;
    if !home.is_absolute() {
        return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"));
    }
    let home = fs::canonicalize(home)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"))?;
    let data = home.join("Library/Application Support/Evidentrail");
    let corpus = data.join("corpus");
    if create_dirs {
        ensure_private_directory(&data)?;
        ensure_private_directory(&corpus)?;
    } else {
        check_private_directory_if_present(&data)?;
        check_private_directory_if_present(&corpus)?;
    }
    Ok(corpus.join(format!("{}.db", hex(source_digest))))
}

pub(crate) fn connected_catalog_lock() -> Result<File, CliFailure> {
    let corpus = corpus_path(&[0u8; 32], true)?;
    let lock_path = corpus
        .parent()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"))?
        .join(".connections.lock");
    acquire_connected_lock(&lock_path)
}

fn wait_for_connected_catalog_lock(max_wait: Duration) -> Result<File, CliFailure> {
    let started = Instant::now();
    loop {
        match connected_catalog_lock() {
            Ok(guard) => return Ok(guard),
            Err(error) if error.code == "EVIDENTRAIL_SOURCES_BUSY" => {
                let remaining = max_wait.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                thread::sleep(remaining.min(Duration::from_millis(250)));
            }
            Err(error) => return Err(error),
        }
    }
}

fn acquire_connected_lock(lock_path: &Path) -> Result<File, CliFailure> {
    let handle = openat(
        CWD,
        lock_path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_LOCK_UNAVAILABLE"))?;
    let file = File::from(handle);
    let metadata = file
        .metadata()
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_LOCK_UNAVAILABLE"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_LOCK_UNSAFE"));
    }
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_BUSY"))?;
    Ok(file)
}

fn corpus_file_exists_safe(path: &Path) -> Result<bool, CliFailure> {
    match path.symlink_metadata() {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Ok(_) | Err(_) => Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_UNSAFE")),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), CliFailure> {
    if !path.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"))?;
    }
    check_private_directory(path)
}

fn check_private_directory_if_present(path: &Path) -> Result<(), CliFailure> {
    match path.symlink_metadata() {
        Ok(_) => check_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE")),
    }
}

fn check_private_directory(path: &Path) -> Result<(), CliFailure> {
    let meta = path
        .symlink_metadata()
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidentrail_ingest::{HistoryPageV1, HistoryRecordV1};

    #[test]
    fn watch_interval_is_bounded_and_errors_back_off() {
        assert_eq!(
            parse_watch_interval(Vec::<OsString>::new().into_iter()).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            parse_watch_interval(
                [OsString::from("--interval-seconds"), OsString::from("5")].into_iter()
            )
            .unwrap(),
            Duration::from_secs(5)
        );
        for invalid in ["0", "4", "3601", "-1", "abc"] {
            assert!(
                parse_watch_interval(
                    [
                        OsString::from("--interval-seconds"),
                        OsString::from(invalid)
                    ]
                    .into_iter()
                )
                .is_err()
            );
        }
        assert_eq!(
            watch_delay(Duration::from_secs(5), 0),
            Duration::from_secs(5)
        );
        assert_eq!(
            watch_delay(Duration::from_secs(5), 3),
            Duration::from_secs(40)
        );
        assert_eq!(
            watch_delay(Duration::from_secs(60), 100),
            Duration::from_secs(3600)
        );
        assert_eq!(
            watch_cycle_delay(
                Duration::from_secs(60),
                5,
                &Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_BUSY")),
            ),
            (0, Duration::from_secs(60))
        );
        assert_eq!(
            watch_cycle_delay(
                Duration::from_secs(60),
                5,
                &Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_PROVIDER_FAILED")),
            ),
            (6, Duration::from_secs(3600))
        );
    }

    #[test]
    fn cloudwatch_registration_requires_complete_unfiltered_binding() {
        let args = [
            "--account",
            "123456789012",
            "--region",
            "us-west-2",
            "--log-group",
            "/aws/api",
        ]
        .into_iter()
        .map(OsString::from);
        let binding = parse_cloudwatch_args(args).unwrap();
        assert_eq!(binding.profile, None);
        assert_eq!(binding.log_group, "/aws/api");
        assert!(plan(&binding).unwrap().log_streams().is_empty());
        let mut invalid = binding;
        invalid.account = "wrong".to_owned();
        assert!(validate_binding(&invalid).is_err());
        invalid.account = "123456789012".to_owned();
        invalid.log_group = format!(
            "arn:aws:logs:us-west-2:123456789012:log-group:{}:*",
            "a".repeat(512)
        );
        assert!(invalid.log_group.len() > 512);
        assert!(validate_binding(&invalid).is_ok());
        invalid.log_group = "a".repeat(513);
        assert!(validate_binding(&invalid).is_err());
        assert!(
            parse_cloudwatch_args(["--account", "123"].into_iter().map(OsString::from)).is_err()
        );
    }

    #[test]
    fn datadog_binding_and_secret_never_mix() {
        let options = parse_datadog_args(
            ["--site", "eu1", "--api-key-env", "TEST_DD_API_KEY"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(options.application_key_env, "DD_APP_KEY");
        let connection_id = "a".repeat(32);
        let rotation = parse_datadog_rotation_args(
            [
                "--connection-id",
                connection_id.as_str(),
                "--api-key-env",
                "NEW_DD_API_KEY",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();
        assert_eq!(rotation.connection_id, "a".repeat(32));
        assert_eq!(rotation.api_key_env, "NEW_DD_API_KEY");
        assert_eq!(rotation.application_key_env, "DD_APP_KEY");
        assert!(
            parse_datadog_rotation_args(
                ["--connection-id", "wrong"].into_iter().map(OsString::from)
            )
            .is_err()
        );
        assert!(parse_datadog_args(["--site", "invalid"].into_iter().map(OsString::from)).is_err());
        assert!(
            parse_datadog_args(
                ["--site", "eu1", "--api-key-env", "BAD=VALUE"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        let binding = DatadogDescriptor {
            schema_version: 1,
            provider: "datadog".to_owned(),
            site: "eu1".to_owned(),
            tier: "online-archives".to_owned(),
            connection_id: "a".repeat(32),
            org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
            user_id: None,
            role_ids: None,
        };
        let descriptor = serde_json::to_vec(&binding).unwrap();
        assert!(matches!(
            parse_binding(&descriptor),
            Ok(SourceBinding::Datadog(_))
        ));
        let identity = DatadogAccessIdentityV1 {
            org_id: binding.org_id.clone(),
            user_id: "b1234567-1234-1234-1234-123456789abc".to_owned(),
            role_ids: vec!["c1234567-1234-1234-1234-123456789abc".to_owned()],
        };
        assert_eq!(
            check_datadog_identity(&binding, &identity),
            Err("LegacyBindingRequiresReconnect".to_owned())
        );
        let pinned = DatadogDescriptor {
            schema_version: 2,
            user_id: Some(identity.user_id.clone()),
            role_ids: Some(identity.role_ids.clone()),
            ..binding.clone()
        };
        assert!(validate_datadog_binding(&pinned).is_ok());
        assert_eq!(check_datadog_identity(&pinned, &identity), Ok(()));
        let narrowed = DatadogAccessIdentityV1 {
            role_ids: vec!["d1234567-1234-1234-1234-123456789abc".to_owned()],
            ..identity
        };
        assert_eq!(
            check_datadog_identity(&pinned, &narrowed),
            Err("AccessIdentityChanged".to_owned())
        );
        assert!(!String::from_utf8_lossy(&descriptor).contains("private-api"));
        let secret = encode_datadog_secret("private-api", "private-app").unwrap();
        let (api_key, app_key) = decode_datadog_secret(&secret).unwrap();
        assert_eq!(&**api_key, "private-api");
        assert_eq!(&**app_key, "private-app");
        let mut malformed = secret.clone();
        malformed[0] = 0xff;
        assert!(decode_datadog_secret(&malformed).is_err());
        let mut with_secret = serde_json::to_value(&binding).unwrap();
        with_secret["api_key"] = json!("private-api");
        assert!(parse_binding(&serde_json::to_vec(&with_secret).unwrap()).is_err());
    }

    #[test]
    fn datadog_rotation_restores_all_tiers_after_a_failed_update() {
        let old = vec![
            ([1; 32], Zeroizing::new(b"old-indexes".to_vec())),
            ([2; 32], Zeroizing::new(b"old-flex".to_vec())),
        ];
        let mut stored = BTreeMap::from([
            ([1; 32], b"old-indexes".to_vec()),
            ([2; 32], b"old-flex".to_vec()),
        ]);
        let mut failed_once = false;
        let result = replace_datadog_secrets_with_rollback(&old, b"new-secret", |source, value| {
            if *source == [2; 32] && value == b"new-secret" && !failed_once {
                failed_once = true;
                return Err(());
            }
            stored.insert(*source, value.to_vec());
            Ok(())
        });
        assert_eq!(result, Err("EVIDENTRAIL_DATADOG_ROTATION_STORE_FAILED"));
        assert_eq!(stored[&[1; 32]], b"old-indexes");
        assert_eq!(stored[&[2; 32]], b"old-flex");
    }

    #[test]
    fn rotation_stages_and_restores_encrypted_corpus_files() {
        let base = env::temp_dir().join(format!(
            "evidentrail-rotation-stage-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let path = base.join("source.db");
        let wal = base.join("source.db-wal");
        fs::write(&path, b"encrypted database").unwrap();
        fs::write(&wal, b"encrypted wal").unwrap();
        let staged = stage_rotation_corpora(&[path.clone()]).unwrap();
        assert_eq!(staged.len(), 2);
        assert!(!path.exists());
        assert!(!wal.exists());
        restore_rotation_corpora(&staged).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"encrypted database");
        assert_eq!(fs::read(&wal).unwrap(), b"encrypted wal");
        let staged = stage_rotation_corpora(&[path.clone()]).unwrap();
        purge_staged_rotation_corpora(&staged).unwrap();
        assert!(!path.exists());
        assert!(!wal.exists());
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn interrupted_rotation_excludes_every_tier_in_the_connection() {
        let base = env::temp_dir().join(format!(
            "evidentrail-rotation-gate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let entries = [
            ([1; 32], "indexes", "a".repeat(32)),
            ([2; 32], "flex", "a".repeat(32)),
            ([3; 32], "indexes", "b".repeat(32)),
        ]
        .into_iter()
        .map(
            |(source_digest, tier, connection_id)| ConnectedSourceDescriptorV1 {
                source_digest,
                descriptor: serde_json::to_vec(&DatadogDescriptor {
                    schema_version: 1,
                    provider: "datadog".to_owned(),
                    site: "us1".to_owned(),
                    tier: tier.to_owned(),
                    connection_id,
                    org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
                    user_id: None,
                    role_ids: None,
                })
                .unwrap(),
            },
        )
        .collect::<Vec<_>>();
        let path_for = |source: &[u8; 32]| Ok(base.join(format!("{}.db", hex(source))));
        fs::write(path_for(&[1; 32]).unwrap(), b"old corpus").unwrap();
        fs::write(path_for(&[2; 32]).unwrap(), b"other old corpus").unwrap();
        let staged = stage_rotation_corpora(&[path_for(&[1; 32]).unwrap()]).unwrap();
        assert_eq!(
            rotation_artifact_paths(&path_for(&[1; 32]).unwrap())
                .unwrap()
                .len(),
            1
        );
        let interrupted = interrupted_datadog_rotations_at(&entries, path_for).unwrap();
        assert_eq!(interrupted, BTreeSet::from(["a".repeat(32)]));
        assert!(!interrupted.contains(&"b".repeat(32)));
        purge_staged_rotation_corpora(&staged).unwrap();
        fs::remove_file(path_for(&[2; 32]).unwrap()).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn recovery_keeps_gate_until_old_artifacts_are_purged() {
        let base = env::temp_dir().join(format!(
            "evidentrail-rotation-recovery-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let paths = [base.join("first.db"), base.join("second.db")];
        fs::write(&paths[0], b"old first").unwrap();
        let first_staged = stage_rotation_corpora(&paths[..1]).unwrap();
        fs::write(&paths[1], b"old second").unwrap();
        let second_staged = stage_rotation_corpora(&paths[1..]).unwrap();
        fs::write(&paths[0], b"new first").unwrap();
        fs::write(&paths[1], b"new second").unwrap();
        assert!(
            paths
                .iter()
                .all(|path| rotation_artifact_present(path).unwrap())
        );
        purge_rotation_artifacts(&paths).unwrap();
        assert!(
            paths
                .iter()
                .all(|path| !rotation_artifact_present(path).unwrap())
        );
        assert_eq!(fs::read(&paths[0]).unwrap(), b"new first");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"new second");
        assert!(first_staged.iter().all(|file| !file.staged.exists()));
        assert!(second_staged.iter().all(|file| !file.staged.exists()));
        fs::remove_file(&paths[0]).unwrap();
        fs::remove_file(&paths[1]).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn rotation_rebuild_discards_prior_records_and_checkpoints() {
        let suffix = format!(
            "rotate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let authority = MacOsCorpusKeychainV1::isolated_for_tests(&suffix).unwrap();
        let tenant = [21; 32];
        let binding = DatadogDescriptor {
            schema_version: 1,
            provider: "datadog".to_owned(),
            site: "us1".to_owned(),
            tier: "indexes".to_owned(),
            connection_id: "a".repeat(32),
            org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
            user_id: None,
            role_ids: None,
        };
        let descriptor = serde_json::to_vec(&binding).unwrap();
        let source = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
        let path = env::temp_dir().join(format!("evidentrail-{suffix}.db"));
        register_corpus(&authority, &tenant, &descriptor, &path).unwrap();
        let key = authority.load(&tenant, &source).unwrap();
        let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        store
            .commit_page_checked(&[HistoryRecordV1 {
                native_id: b"old-record".to_vec(),
                event_timestamp_millis: 1,
                bytes: b"old data".to_vec(),
            }])
            .unwrap();
        assert_eq!(store.record_count().unwrap(), 1);
        drop(store);
        remove_corpus_files(&path, "EVIDENTRAIL_TEST_CLEANUP_FAILED").unwrap();
        recreate_empty_corpus(&path, &authority, &tenant, &source).unwrap();
        let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        assert_eq!(store.record_count().unwrap(), 0);
        assert_eq!(store.read_checkpoint().unwrap(), None);
        drop(store);
        remove_corpus_files(&path, "EVIDENTRAIL_TEST_CLEANUP_FAILED").unwrap();
        authority.destroy(&tenant, &source).unwrap();
    }

    #[test]
    fn connected_corpus_rejects_symlink_and_shared_permissions() {
        use std::os::unix::fs::symlink;

        let base = env::temp_dir().join(format!(
            "evidentrail-corpus-path-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let file = base.join("corpus.db");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)
            .unwrap();
        assert_eq!(corpus_file_exists_safe(&file), Ok(true));
        let link = base.join("symlink.db");
        symlink(&file, &link).unwrap();
        assert!(corpus_file_exists_safe(&link).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(corpus_file_exists_safe(&file).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(file).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn connected_lock_excludes_concurrent_mutation_and_symlinks() {
        use std::os::unix::fs::symlink;

        let base = env::temp_dir().join(format!(
            "evidentrail-connected-lock-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let path = base.join("catalog.lock");
        let guard = acquire_connected_lock(&path).unwrap();
        assert_eq!(
            acquire_connected_lock(&path).err().unwrap().code,
            "EVIDENTRAIL_SOURCES_BUSY"
        );
        drop(guard);
        let guard = acquire_connected_lock(&path).unwrap();
        drop(guard);
        let link = base.join("link.lock");
        symlink(&path, &link).unwrap();
        assert!(acquire_connected_lock(&link).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn query_generation_rejects_revocation_and_same_descriptor_reconnect() {
        let source_digest = [7; 32];
        let descriptor = b"cloudwatch-source".to_vec();
        let old_key = corpus_key_generation(&[11; 32]);
        let new_key = corpus_key_generation(&[12; 32]);
        let selected = vec![(source_digest, descriptor.clone())];
        let registered = vec![ConnectedSourceDescriptorV1 {
            source_digest,
            descriptor: descriptor.clone(),
        }];
        let check = |current: &[ConnectedSourceDescriptorV1], key| {
            verify_query_generations(&selected, &[old_key], current, |_| Ok(key))
        };
        assert!(check(&registered, old_key).is_ok());
        assert_eq!(
            check(&[], old_key).unwrap_err().code,
            "EVIDENTRAIL_LOGS_SOURCE_CHANGED"
        );
        assert_eq!(
            check(
                &[ConnectedSourceDescriptorV1 {
                    source_digest,
                    descriptor: b"changed-source".to_vec(),
                }],
                old_key,
            )
            .unwrap_err()
            .code,
            "EVIDENTRAIL_LOGS_SOURCE_CHANGED"
        );
        assert_eq!(
            check(&registered, new_key).unwrap_err().code,
            "EVIDENTRAIL_LOGS_SOURCE_CHANGED"
        );
    }

    #[test]
    fn revocation_selects_one_cloudwatch_source_or_one_datadog_connection() {
        let entries = [1u8, 2, 3, 4]
            .into_iter()
            .map(|byte| ConnectedSourceDescriptorV1 {
                source_digest: [byte; 32],
                descriptor: Vec::new(),
            })
            .collect::<Vec<_>>();
        let datadog = |tier: &str, connection_id: &str| {
            SourceBinding::Datadog(DatadogDescriptor {
                schema_version: 1,
                provider: "datadog".to_owned(),
                site: "us1".to_owned(),
                tier: tier.to_owned(),
                connection_id: connection_id.to_owned(),
                org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
                user_id: None,
                role_ids: None,
            })
        };
        let bindings = vec![
            SourceBinding::CloudWatch(CloudWatchDescriptor {
                schema_version: 1,
                provider: "cloudwatch".to_owned(),
                account: "123456789012".to_owned(),
                region: "us-west-2".to_owned(),
                log_group: "/aws/test".to_owned(),
                profile: None,
                caller_arn: None,
            }),
            datadog("indexes", "a"),
            datadog("flex", "a"),
            datadog("indexes", "b"),
        ];
        assert_eq!(
            revocation_indices([1; 32], &entries, &bindings).unwrap(),
            [0]
        );
        assert_eq!(
            revocation_indices([2; 32], &entries, &bindings).unwrap(),
            [1, 2]
        );
        assert_eq!(
            revocation_indices([4; 32], &entries, &bindings).unwrap(),
            [3]
        );
        assert!(revocation_indices([5; 32], &entries, &bindings).is_err());
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn disconnect_removes_all_datadog_tiers_but_preserves_other_sources() {
        let suffix = format!(
            "revoke-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let corpus_authority = MacOsCorpusKeychainV1::isolated_for_tests(&suffix).unwrap();
        let credential_authority =
            MacOsConnectedCredentialKeychainV1::isolated_for_tests(&suffix).unwrap();
        let base = env::temp_dir().join(format!("evidentrail-{suffix}"));
        fs::create_dir(&base).unwrap();
        let tenant = [17; 32];
        let mut connected = Vec::new();
        for tier in ["indexes", "flex"] {
            let binding = DatadogDescriptor {
                schema_version: 1,
                provider: "datadog".to_owned(),
                site: "us1".to_owned(),
                tier: tier.to_owned(),
                connection_id: "a".repeat(32),
                org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
                user_id: None,
                role_ids: None,
            };
            let descriptor = serde_json::to_vec(&binding).unwrap();
            let source_digest =
                MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
            let path = base.join(format!("{}.db", hex(&source_digest)));
            credential_authority
                .create(&tenant, &source_digest, b"api:app")
                .unwrap();
            register_corpus(&corpus_authority, &tenant, &descriptor, &path).unwrap();
            connected.push((source_digest, path));
        }
        let cloudwatch = CloudWatchDescriptor {
            schema_version: 1,
            provider: "cloudwatch".to_owned(),
            account: "123456789012".to_owned(),
            region: "us-west-2".to_owned(),
            log_group: "/aws/other".to_owned(),
            profile: None,
            caller_arn: None,
        };
        let descriptor = serde_json::to_vec(&cloudwatch).unwrap();
        let other = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
        let other_path = base.join(format!("{}.db", hex(&other)));
        register_corpus(&corpus_authority, &tenant, &descriptor, &other_path).unwrap();

        let removed = revoke_registered_sources(
            connected[0].0,
            &tenant,
            &corpus_authority,
            &credential_authority,
            |digest| Ok(base.join(format!("{}.db", hex(digest)))),
        )
        .unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(corpus_authority.list_bound(&tenant).unwrap().len(), 1);
        for (source_digest, path) in connected {
            assert!(!path.exists());
            assert!(corpus_authority.load(&tenant, &source_digest).is_err());
            assert!(credential_authority.load(&tenant, &source_digest).is_err());
        }
        assert!(other_path.exists());
        remove_corpus_files(&other_path, "EVIDENTRAIL_TEST_CLEANUP_FAILED").unwrap();
        corpus_authority.destroy(&tenant, &other).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn connected_logs_require_task_and_render_exact_source_bytes() {
        assert!(parse_logs_args(Vec::<OsString>::new().into_iter()).is_err());
        assert!(parse_logs_args(["--task", "  "].into_iter().map(OsString::from)).is_err());
        let parsed = parse_logs_args(
            ["--task", "reservation failure", "--max-raw-bytes", "1024"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(parsed.task, "reservation failure");
        assert_eq!(parsed.max_raw_bytes, 1024);
        let pack = ConnectedLogPack {
            source_record_counts: vec![([2; 32], 2)],
            total_groups: 1,
            candidate_count: 1,
            prefinal_pruned_groups: 0,
            graph_candidate_count: 0,
            fallback_candidate_count: 0,
            service_candidates_added: 0,
            service_directory_pages: 0,
            service_directory_truncated: false,
            candidate_pool_truncated: false,
            output_budget_truncated: false,
            selection_calls: 1,
            selection_elapsed_ms: 0,
            selected: vec![crate::ConnectedLogEntry {
                source_digest: [2; 32],
                first_native_id: b"event-1".to_vec(),
                first_raw: b"error\nline".to_vec(),
                last_native_id: Some(b"event-2".to_vec()),
                last_raw: Some(vec![0xff, 0x00]),
                repeat_count: 2,
            }],
        };
        let body = render_connected_logs(&pack).unwrap();
        let lines = body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_slice(lines[0]).unwrap();
        let last: serde_json::Value = serde_json::from_slice(lines[1]).unwrap();
        assert_eq!(first["raw"], "error\nline");
        assert_eq!(first["repeat_count"], 2);
        assert_eq!(last["raw_base64"], URL_SAFE_NO_PAD.encode([0xff, 0x00]));
        assert_eq!(last["native_id"], URL_SAFE_NO_PAD.encode(b"event-2"));
    }

    #[test]
    fn bounded_sync_scans_then_reconciles_without_duplicate_records() {
        struct ReplaySource;
        impl HistoryPageSourceV1 for ReplaySource {
            fn fetch_page(
                &mut self,
                _: HistoryPartitionV1,
                _: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                Ok(HistoryPageV1 {
                    records: vec![HistoryRecordV1 {
                        native_id: b"one".to_vec(),
                        event_timestamp_millis: 5,
                        bytes: b"[checkout] ERROR: reservation failed".to_vec(),
                    }],
                    next_token: None,
                })
            }
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "evidentrail-sync-{}-{suffix}.db",
            std::process::id()
        ));
        let mut store = EncryptedHistoryStore::open(&path, &[9; 32], &[1; 32], &[2; 32]).unwrap();
        let progress = bounded_sync(&mut ReplaySource, &mut store, 10).unwrap();
        assert_eq!(progress.status, "scanned_to_high_water");
        assert_eq!(progress.reconciliation, "recent_lookback_scanned");
        assert_eq!(progress.historical_reconciliation, "not_applicable");
        assert_eq!(progress.pages, 2);
        assert_eq!(store.record_count().unwrap(), 1);
        assert_eq!(
            store
                .read_checkpoint()
                .unwrap()
                .unwrap()
                .completed_through_millis,
            10
        );
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn historical_sweep_resumes_after_restart_and_finds_older_late_record() {
        struct LateSource;
        impl HistoryPageSourceV1 for LateSource {
            fn fetch_page(
                &mut self,
                partition: HistoryPartitionV1,
                _: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                let late_at = 500 * DAY_MILLIS;
                Ok(HistoryPageV1 {
                    records: (partition.start_millis <= late_at && partition.end_millis >= late_at)
                        .then(|| HistoryRecordV1 {
                            native_id: b"older-late".to_vec(),
                            event_timestamp_millis: late_at,
                            bytes: b"[database] ERROR: old late arrival".to_vec(),
                        })
                        .into_iter()
                        .collect(),
                    next_token: None,
                })
            }
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "evidentrail-history-sweep-{}-{suffix}.db",
            std::process::id()
        ));
        let high_water = 3 * 365 * DAY_MILLIS;
        {
            let mut store =
                EncryptedHistoryStore::open(&path, &[10; 32], &[1; 32], &[2; 32]).unwrap();
            store
                .complete_partition_checked(evidentrail_ingest::HistoryCheckpointV1 {
                    completed_through_millis: high_water,
                })
                .unwrap();
            let mut pages = MAX_SYNC_PAGES - 1;
            let state =
                sweep_older_history(&mut LateSource, &mut store, high_water, &mut pages).unwrap();
            assert_eq!(state, "progress_partial");
            assert_eq!(
                store.read_historical_reconciliation_cursor().unwrap(),
                365 * DAY_MILLIS
            );
            assert_eq!(store.record_count().unwrap(), 0);
        }
        {
            let mut store =
                EncryptedHistoryStore::open(&path, &[10; 32], &[1; 32], &[2; 32]).unwrap();
            let mut pages = 0;
            let state =
                sweep_older_history(&mut LateSource, &mut store, high_water, &mut pages).unwrap();
            assert_eq!(state, "cycle_complete");
            assert_eq!(store.read_historical_reconciliation_cursor().unwrap(), 0);
            assert_eq!(
                store.get_record(b"older-late").unwrap().unwrap().bytes,
                b"[database] ERROR: old late arrival"
            );
            assert_eq!(
                store
                    .read_checkpoint()
                    .unwrap()
                    .unwrap()
                    .completed_through_millis,
                high_water
            );
            let mut repeated_pages = 0;
            assert_eq!(
                sweep_older_history(&mut LateSource, &mut store, high_water, &mut repeated_pages)
                    .unwrap(),
                "recent_cycle_complete"
            );
            assert_eq!(repeated_pages, 0);
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn historical_sweep_remembers_smaller_partition_after_page_cap() {
        struct EndlessPages;
        impl HistoryPageSourceV1 for EndlessPages {
            fn fetch_page(
                &mut self,
                _: HistoryPartitionV1,
                token: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                let next = token
                    .map(|value| {
                        std::str::from_utf8(value)
                            .unwrap()
                            .parse::<usize>()
                            .unwrap()
                    })
                    .unwrap_or(0)
                    + 1;
                Ok(HistoryPageV1 {
                    records: vec![],
                    next_token: Some(next.to_string().into_bytes()),
                })
            }
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "evidentrail-sweep-cap-{}-{suffix}.db",
            std::process::id()
        ));
        let high_water = 2 * 365 * DAY_MILLIS;
        {
            let mut store =
                EncryptedHistoryStore::open(&path, &[11; 32], &[1; 32], &[2; 32]).unwrap();
            store
                .complete_partition_checked(evidentrail_ingest::HistoryCheckpointV1 {
                    completed_through_millis: high_water,
                })
                .unwrap();
            let mut pages = MAX_SYNC_PAGES - 1;
            assert_eq!(
                sweep_older_history(&mut EndlessPages, &mut store, high_water, &mut pages).unwrap(),
                "progress_partial"
            );
            assert_eq!(store.read_historical_reconciliation_cursor().unwrap(), 0);
        }
        {
            let store = EncryptedHistoryStore::open(&path, &[11; 32], &[1; 32], &[2; 32]).unwrap();
            assert_eq!(
                store
                    .read_historical_reconciliation_partition_millis()
                    .unwrap(),
                365 * DAY_MILLIS / 2
            );
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn historical_sweep_caps_provider_pages_per_pass() {
        struct EmptySource;
        impl HistoryPageSourceV1 for EmptySource {
            fn fetch_page(
                &mut self,
                _: HistoryPartitionV1,
                _: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                Ok(HistoryPageV1 {
                    records: vec![],
                    next_token: None,
                })
            }
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "evidentrail-sweep-budget-{}-{suffix}.db",
            std::process::id()
        ));
        let mut store = EncryptedHistoryStore::open(&path, &[12; 32], &[1; 32], &[2; 32]).unwrap();
        let high_water = 20 * 365 * DAY_MILLIS;
        store
            .complete_partition_checked(evidentrail_ingest::HistoryCheckpointV1 {
                completed_through_millis: high_water,
            })
            .unwrap();
        let mut pages = 0;
        assert_eq!(
            sweep_older_history(&mut EmptySource, &mut store, high_water, &mut pages).unwrap(),
            "progress_partial"
        );
        assert_eq!(pages, MAX_HISTORICAL_PAGES_PER_PASS);
        assert_eq!(
            store.read_historical_reconciliation_cursor().unwrap(),
            8 * 365 * DAY_MILLIS
        );
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn bounded_sync_never_claims_completion_when_pagination_budget_is_exhausted() {
        struct EndlessPages;
        impl HistoryPageSourceV1 for EndlessPages {
            fn fetch_page(
                &mut self,
                _: HistoryPartitionV1,
                token: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                let ordinal = token
                    .map(|value| std::str::from_utf8(value).unwrap().parse::<u32>().unwrap())
                    .unwrap_or(0);
                Ok(HistoryPageV1 {
                    records: vec![],
                    next_token: Some((ordinal + 1).to_string().into_bytes()),
                })
            }
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "evidentrail-cap-{}-{suffix}.db",
            std::process::id()
        ));
        let mut store = EncryptedHistoryStore::open(&path, &[8; 32], &[1; 32], &[2; 32]).unwrap();
        let progress = bounded_sync(&mut EndlessPages, &mut store, 10).unwrap();
        assert_eq!(progress.status, "backfilling");
        assert_eq!(progress.pages, MAX_SYNC_PAGES);
        assert_eq!(progress.reconciliation, "not_run");
        assert_eq!(store.read_checkpoint().unwrap(), None);
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn registered_source_reopens_same_encrypted_corpus() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let authority = MacOsCorpusKeychainV1::isolated_for_tests(&format!(
            "cli-{}-{suffix}",
            std::process::id()
        ))
        .unwrap();
        let tenant = [3; 32];
        let binding = CloudWatchDescriptor {
            schema_version: 1,
            provider: "cloudwatch".to_owned(),
            account: "123456789012".to_owned(),
            region: "us-west-2".to_owned(),
            log_group: "/aws/test".to_owned(),
            profile: None,
            caller_arn: None,
        };
        let descriptor = serde_json::to_vec(&binding).unwrap();
        let digest = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
        let path = env::temp_dir().join(format!(
            "evidentrail-registered-{}-{suffix}.db",
            std::process::id()
        ));
        register_corpus(&authority, &tenant, &descriptor, &path).unwrap();
        assert_eq!(authority.list_bound(&tenant).unwrap().len(), 1);
        let key = authority.load(&tenant, &digest).unwrap();
        let store = EncryptedHistoryStore::open(&path, &key, &tenant, &digest).unwrap();
        assert_eq!(store.record_count().unwrap(), 0);
        assert_eq!(store.read_checkpoint().unwrap(), None);
        drop(store);
        assert_eq!(
            register_corpus(&authority, &tenant, &descriptor, &path)
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CORPUS_KEY_ALREADY_EXISTS"
        );
        authority.destroy(&tenant, &digest).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn same_descriptor_reconnect_cannot_publish_old_snapshot() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let authority = MacOsCorpusKeychainV1::isolated_for_tests(&format!(
            "query-reconnect-{}-{suffix}",
            std::process::id()
        ))
        .unwrap();
        let tenant = [3; 32];
        let descriptor = br#"{"provider":"cloudwatch","source":"same"}"#.to_vec();
        let source_digest =
            MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
        let path = env::temp_dir().join(format!(
            "evidentrail-query-reconnect-{}-{suffix}.db",
            std::process::id()
        ));
        register_corpus(&authority, &tenant, &descriptor, &path).unwrap();
        let old_key = authority.load(&tenant, &source_digest).unwrap();
        let mut old_store =
            EncryptedHistoryStore::open(&path, &old_key, &tenant, &source_digest).unwrap();
        old_store
            .commit_page_checked(&[evidentrail_ingest::HistoryRecordV1 {
                native_id: b"old".to_vec(),
                event_timestamp_millis: 1,
                bytes: b"old source line".to_vec(),
            }])
            .unwrap();
        let snapshot = old_store.read_snapshot().unwrap();
        assert_eq!(snapshot.record_count().unwrap(), 1);
        let selected = vec![(source_digest, descriptor.clone())];
        let selected_key = corpus_key_generation(&old_key);

        remove_corpus_files(&path, "EVIDENTRAIL_TEST_CLEANUP_FAILED").unwrap();
        authority.destroy(&tenant, &source_digest).unwrap();
        register_corpus(&authority, &tenant, &descriptor, &path).unwrap();
        let current = authority.list_bound(&tenant).unwrap();
        assert_eq!(current[0].descriptor, descriptor);
        assert_eq!(current[0].source_digest, source_digest);
        assert_eq!(
            verify_query_generations(&selected, &[selected_key], &current, |digest| {
                let key = authority.load(&tenant, digest).unwrap();
                Ok(corpus_key_generation(&key))
            })
            .unwrap_err()
            .code,
            "EVIDENTRAIL_LOGS_SOURCE_CHANGED"
        );
        drop(snapshot);
        drop(old_store);
        remove_corpus_files(&path, "EVIDENTRAIL_TEST_CLEANUP_FAILED").unwrap();
        authority.destroy(&tenant, &source_digest).unwrap();
    }
}
