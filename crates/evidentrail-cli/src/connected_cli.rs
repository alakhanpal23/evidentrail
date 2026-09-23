//! macOS connection registration. Synchronization and query are separate
//! release gates; registration never claims that a source has been backfilled.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use evidentrail_cli::{
    AuthorizedCorpus, ConnectedLogPack, OpenAiIncidentReasoner, select_connected_logs,
};
use evidentrail_corpus::{EncryptedHistoryStore, MacOsCorpusKeychainV1};
use evidentrail_ingest::{
    AwsCloudWatchTransportV1, CloudWatchCapsV1, CloudWatchHistorySourceV1, CloudWatchPlanV1,
    HistoryPageSourceV1, HistoryPartitionV1, HistorySyncErrorV1, HistorySyncLimitsV1,
    HistorySyncStatusV1, reconcile_history_v1, synchronize_history_v1,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::CliFailure;

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

pub(super) fn run(args: Vec<OsString>) -> Result<ExitCode, CliFailure> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_COMMAND_REQUIRED"))?;
    if command == "connect-cloudwatch" {
        connect_cloudwatch(parse_cloudwatch_args(args)?)
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
    } else {
        Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_COMMAND"))
    }
}

const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;
const MAX_SYNC_PAGES: usize = 256;

struct ConnectedQueryOptions {
    task: String,
    max_raw_bytes: usize,
}

pub(super) fn run_logs(args: Vec<OsString>) -> Result<ExitCode, CliFailure> {
    let options = parse_logs_args(args.into_iter())?;
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let entries = authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    if entries.is_empty() || entries.len() > 32 {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_LOGS_SOURCE_COUNT_UNSUPPORTED",
        ));
    }
    let high_water = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    let mut stores = Vec::new();
    let mut source_states = Vec::new();
    for entry in entries {
        let binding: CloudWatchDescriptor = serde_json::from_slice(&entry.descriptor)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        validate_binding(&binding)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        let source_id = hex(&entry.source_digest);
        let path = corpus_path(&entry.source_digest, false)?;
        if !path.is_file() {
            source_states.push(json!({
                "source_id": source_id,
                "state": "excluded_corpus_missing"
            }));
            continue;
        }
        let key = authority
            .load(&tenant, &entry.source_digest)
            .map_err(|error| CliFailure::runtime(error.code()))?;
        let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
        let source_plan = plan(&binding)?;
        let progress = AwsCloudWatchTransportV1::connect(
            source_plan.clone(),
            &binding.account,
            binding.profile.as_deref(),
        )
        .map_err(|error| format!("{error:?}"))
        .and_then(|transport| {
            let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
                .map_err(|_| "InvalidConfiguration".to_owned())?;
            bounded_sync(&mut source, &mut store, high_water).map_err(|error| format!("{error:?}"))
        });
        match progress {
            Ok(progress) => {
                source_states.push(json!({
                    "source_id": source_id,
                    "state": progress.status,
                    "reconciliation": progress.reconciliation,
                    "scanned_through_millis": store.read_checkpoint().map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?.map(|value| value.completed_through_millis),
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
    if stores.is_empty() {
        serde_json::to_writer(
            io::stderr().lock(),
            &json!({"sources": source_states, "coverage": "no_authorized_source"}),
        )
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))?;
        writeln!(io::stderr().lock())
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))?;
        return Err(CliFailure::runtime("EVIDENTRAIL_LOGS_NO_AUTHORIZED_SOURCE"));
    }
    let authorized = stores
        .iter()
        .map(|(source_digest, store)| AuthorizedCorpus {
            source_digest: *source_digest,
            store,
        })
        .collect::<Vec<_>>();
    let mut selector = OpenAiIncidentReasoner::from_compact_environment()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let pack = select_connected_logs(
        &authorized,
        &options.task,
        options.max_raw_bytes,
        &mut selector,
    )
    .map_err(|error| CliFailure::runtime(error.code()))?;
    let body = render_connected_logs(&pack)?;
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
        "candidate_pool_truncated": pack.candidate_pool_truncated,
        "output_budget_truncated": pack.output_budget_truncated,
        "selected_groups": pack.selected.len(),
        "total_groups": pack.total_groups,
        "raw_byte_budget": options.max_raw_bytes,
    });
    serde_json::to_writer(io::stderr().lock(), &metadata)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))?;
    writeln!(io::stderr().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_METADATA_WRITE_FAILED"))?;
    io::stdout()
        .lock()
        .write_all(&body)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_LOGS_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
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
    for entry in authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        let binding: CloudWatchDescriptor = serde_json::from_slice(&entry.descriptor)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        validate_binding(&binding)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        let path = corpus_path(&entry.source_digest, false)?;
        if !path.is_file() {
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
        let source_plan = plan(&binding)?;
        let sync_result = AwsCloudWatchTransportV1::connect(
            source_plan.clone(),
            &binding.account,
            binding.profile.as_deref(),
        )
        .map_err(|error| format!("{error:?}"))
        .and_then(|transport| {
            let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
                .map_err(|_| "InvalidConfiguration".to_owned())?;
            bounded_sync(&mut source, &mut store, high_water).map_err(|error| format!("{error:?}"))
        });
        let checkpoint = store
            .read_checkpoint()
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
        let record_count = store
            .record_count()
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
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
            "provider": "cloudwatch",
            "record_count": record_count,
            "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
            "high_water_millis": high_water,
            "coverage": "unverified_provider_consistency",
            "result": status,
        }));
    }
    serde_json::to_writer(io::stdout().lock(), &outcomes)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::from(u8::from(had_error)))
}

struct BoundedSyncProgress {
    status: &'static str,
    pages: usize,
    reconciliation: &'static str,
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
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let mut listed = Vec::new();
    for entry in authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        let binding: CloudWatchDescriptor = serde_json::from_slice(&entry.descriptor)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        validate_binding(&binding)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        let path = corpus_path(&entry.source_digest, false)?;
        let status = if path.is_file() {
            let key = authority
                .load(&tenant, &entry.source_digest)
                .map_err(|error| CliFailure::runtime(error.code()))?;
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let checkpoint = store
                .read_checkpoint()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            json!({
                "state": "registered_incomplete",
                "record_count": store.record_count().map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?,
                "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
            })
        } else {
            json!({"state": "corpus_missing"})
        };
        listed.push(json!({
            "source_id": hex(&entry.source_digest),
            "provider": binding.provider,
            "account": binding.account,
            "region": binding.region,
            "log_group": binding.log_group,
            "status": status,
        }));
    }
    serde_json::to_writer(io::stdout().lock(), &listed)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
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
            candidate_pool_truncated: false,
            output_budget_truncated: false,
            selected: vec![evidentrail_cli::ConnectedLogEntry {
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
