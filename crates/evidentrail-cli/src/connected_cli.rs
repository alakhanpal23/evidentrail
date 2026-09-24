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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    DatadogHistorySourceV1, DatadogSiteV1, DatadogStorageTierV1, HistoryPageSourceV1,
    HistoryPartitionV1, HistorySyncErrorV1, HistorySyncLimitsV1, HistorySyncStatusV1,
    reconcile_history_v1, synchronize_history_v1,
};
use rustix::fs::{CWD, FlockOperation, Mode, OFlags, flock, openat};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
        match sync_cycle() {
            Ok(false) => consecutive_errors = 0,
            Ok(true) => consecutive_errors = consecutive_errors.saturating_add(1),
            Err(error) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                serde_json::to_writer(
                    io::stderr().lock(),
                    &json!({
                        "status": "sync_cycle_error",
                        "code": error.code,
                        "consecutive_errors": consecutive_errors,
                    }),
                )
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
                writeln!(io::stderr().lock())
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
            }
        }
        // Every pass releases the catalog lock. A supervisor restarts the
        // process after a crash; persistent checkpoints make replay safe.
        thread::sleep(watch_delay(interval, consecutive_errors));
    }
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
    if entries.is_empty() || entries.len() > 32 {
        return Err(ConnectedQueryError {
            code: "EVIDENTRAIL_LOGS_SOURCE_COUNT_UNSUPPORTED",
            metadata: None,
        });
    }
    let high_water = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE")))?
        .as_millis() as i64;
    let mut stores = Vec::new();
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
                    "scanned_through_millis": store.read_checkpoint().map_err(|_| query_error(CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED")))?.map(|value| value.completed_through_millis),
                    "high_water_millis": high_water,
                }));
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
    let authorized = stores
        .iter()
        .map(|(source_digest, store)| AuthorizedCorpus {
            source_digest: *source_digest,
            store,
        })
        .collect::<Vec<_>>();
    let mut selector = OpenAiIncidentReasoner::from_compact_environment()
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    let pack = select_connected_logs(&authorized, task, max_raw_bytes, &mut selector)
        .map_err(|error| query_error(CliFailure::runtime(error.code())))?;
    let body = render_connected_logs(&pack).map_err(query_error)?;
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
            .any(|state| state["reconciliation"] != "recent_lookback_scanned");
    let metadata = json!({
        "sources": source_states,
        "coverage": if partial_source { "partial" } else { "unverified_provider_consistency" },
        "candidate_count": pack.candidate_count,
        "graph_candidate_count": pack.graph_candidate_count,
        "fallback_candidate_count": pack.fallback_candidate_count,
        "service_candidates_added": pack.service_candidates_added,
        "service_directory_pages": pack.service_directory_pages,
        "service_directory_truncated": pack.service_directory_truncated,
        "candidate_pool_truncated": pack.candidate_pool_truncated,
        "output_budget_truncated": pack.output_budget_truncated,
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
    let entry = authority
        .list_bound(&tenant)
        .map_err(|error| failure(error.code()))?
        .into_iter()
        .find(|entry| &entry.source_digest == source_digest)
        .ok_or_else(|| failure("EVIDENTRAIL_CONNECTED_EXPAND_SOURCE_REVOKED"))?;
    let binding = parse_binding(&entry.descriptor).map_err(map_failure)?;
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
        if crate::incident_analysis::contains_sensitive_data(&String::from_utf8_lossy(
            &record.bytes,
        )) {
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
        "coverage": if progress.status == "scanned_to_high_water"
            && progress.reconciliation == "recent_lookback_scanned" {
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
    for entry in authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        let binding = parse_binding(&entry.descriptor)?;
        if let SourceBinding::Datadog(datadog) = &binding {
            datadog_tiers
                .entry(datadog.connection_id.clone())
                .or_default()
                .insert(datadog.tier.clone());
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
                    && progress.reconciliation == "recent_lookback_scanned" =>
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
            let source_plan = plan(cloudwatch).map_err(|error| error.code.to_owned())?;
            let transport = AwsCloudWatchTransportV1::connect(
                source_plan.clone(),
                &cloudwatch.account,
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
            let current_org = source
                .current_org_id()
                .map_err(|error| format!("{error:?}"))?;
            if current_org != datadog.org_id {
                return Err("AuthenticationChanged".to_owned());
            }
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
        });
    }
    let remaining = MAX_SYNC_PAGES - pages;
    if remaining == 0 {
        return Ok(BoundedSyncProgress {
            status: "scanned_to_high_water",
            pages,
            reconciliation: "not_run_budget_exhausted",
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
    Ok(BoundedSyncProgress {
        status: "scanned_to_high_water",
        pages,
        reconciliation: reconciliation_status,
    })
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
        || binding.log_group.len() > 512
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

fn validate_datadog_binding(binding: &DatadogDescriptor) -> Result<(), CliFailure> {
    if binding.schema_version != 1
        || binding.provider != "datadog"
        || datadog_site(&binding.site).is_none()
        || datadog_tier(&binding.tier).is_none()
        || binding.connection_id.len() != 32
        || !binding
            .connection_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || binding.org_id.len() != 36
        || !binding.org_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
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
    let org_id = identity_source
        .current_org_id()
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
            schema_version: 1,
            provider: "datadog".to_owned(),
            site: options.site.clone(),
            tier: tier.to_owned(),
            connection_id: connection_id.clone(),
            org_id: org_id.clone(),
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
        "org_id": org_id,
            "tiers": outcomes,
            "coverage": "partial_until_backfill_and_provider_consistency_verified",
        }),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
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

fn connect_cloudwatch(binding: CloudWatchDescriptor) -> Result<ExitCode, CliFailure> {
    let source_plan = plan(&binding)?;
    let transport = AwsCloudWatchTransportV1::connect(
        source_plan.clone(),
        &binding.account,
        binding.profile.as_deref(),
    )
    .map_err(|error| CliFailure::runtime(error.code()))?;
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
    for entry in authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        let binding = parse_binding(&entry.descriptor)?;
        let path = corpus_path(&entry.source_digest, false)?;
        let status = if corpus_file_exists_safe(&path)? {
            let key = authority
                .load(&tenant, &entry.source_digest)
                .map_err(|error| CliFailure::runtime(error.code()))?;
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
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
            let last_attempt_failed = attempt.is_some_and(|value| !value.succeeded);
            json!({
                "state": if last_attempt_failed { "last_sync_failed" } else if observation.is_some() { "sync_observed" } else { "registered_incomplete" },
                "record_count": store.record_count().map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?,
                "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
                "last_sync_completed_at_millis": observation.map(|value| value.completed_at_millis),
                "last_sync_high_water_millis": observation.map(|value| value.high_water_millis),
                "last_sync_age_millis": observation.map(|value| now_millis.saturating_sub(value.completed_at_millis)),
                "last_sync_scanned_to_high_water": observation.map(|value| value.scanned_to_high_water),
                "last_sync_reconciled_lookback": observation.map(|value| value.reconciled_lookback),
                "last_attempt_completed_at_millis": attempt.map(|value| value.completed_at_millis),
                "last_attempt_high_water_millis": attempt.map(|value| value.high_water_millis),
                "last_attempt_age_millis": attempt.map(|value| now_millis.saturating_sub(value.completed_at_millis)),
                "last_attempt_succeeded": attempt.map(|value| value.succeeded),
                "coverage": if last_attempt_failed {
                    "incomplete"
                } else if observation.is_some_and(|value| value.scanned_to_high_water && value.reconciled_lookback) {
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
        };
        let descriptor = serde_json::to_vec(&binding).unwrap();
        assert!(matches!(
            parse_binding(&descriptor),
            Ok(SourceBinding::Datadog(_))
        ));
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
            graph_candidate_count: 0,
            fallback_candidate_count: 0,
            service_candidates_added: 0,
            service_directory_pages: 0,
            service_directory_truncated: false,
            candidate_pool_truncated: false,
            output_budget_truncated: false,
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
}
