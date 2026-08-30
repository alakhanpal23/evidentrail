//! Non-certifying local performance probe for the real Evidentrail product arms.
//!
//! This example deliberately uses `ProcessKeyAuthorityV2` for the durable arm.
//! It is useful for engineering measurements of encryption and filesystem
//! synchronization, but its output is not production qualification evidence.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use evidentrail_bench_harness::{
    execute_real_durable_product_arm_v2, execute_real_memory_product_arm_v2,
};
use evidentrail_cli::{
    DurablePublishingMcpRetentionBackendV2, McpRetentionBackendV1, StdinBriefOutcomeV1,
};
use evidentrail_core::{EventId, ExpansionRelationV1, ResultId, UnixTimestampNanos};
use evidentrail_product::DurableProductV2;
use evidentrail_schema::ExactnessBasis;
use evidentrail_snapshot_format::{BuildContextDigestsV1, LifecycleDigestV1, OperationIdV1};
use evidentrail_store::{
    AliasExpansionRequestV1, BatchCommitInputV2, DataCommitInputV2, DurableEventInputV2,
    DurableResultRepositoryV2, EvidenceAliasV1, ExpansionLimitV1, KeyAuthorityV2,
    MAX_DURABLE_BATCH_EVENTS_V2, ProcessKeyAuthorityV2, SealInputV2,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const QUESTION: &[u8] = b"what failed and which exact evidence supports the diagnosis?";
const TOKEN_BUDGET: u64 = 100_000;
const FIXED_NOW: UnixTimestampNanos = UnixTimestampNanos::new(1_800_000_000_000_000_000);
const RESULT_RANDOMNESS: [u8; 32] = [0x7d; 32];

#[derive(Clone, Copy)]
enum Mode {
    Memory,
    Durable,
    Repository,
}

#[derive(Serialize)]
struct ProbeReport {
    schema_version: u16,
    qualification_eligible: bool,
    authority: &'static str,
    mode: &'static str,
    corpus: &'static str,
    source_records: u64,
    source_bytes: u64,
    elapsed_nanos: u64,
    throughput_records_per_second: f64,
    throughput_mib_per_second: f64,
    stored_bytes: u64,
    rendered: bool,
    evidence_aliases: u64,
    public_artifact_commitment: String,
    authorized_basis_commitment: String,
    expansion: Option<ExpansionReport>,
}

#[derive(Serialize)]
struct ExpansionReport {
    alias: &'static str,
    latency_nanos: u64,
    returned_events: usize,
    returned_bytes: usize,
    exact: bool,
}

#[derive(Serialize)]
struct RepositoryProbeReport {
    schema_version: u16,
    qualification_eligible: bool,
    component_only: bool,
    authority: &'static str,
    source_records: u64,
    source_bytes: u64,
    lifecycle_elapsed_nanos: u64,
    throughput_records_per_second: f64,
    throughput_mib_per_second: f64,
    stored_bytes: u64,
    storage_to_source_ratio: f64,
    expansion_samples: usize,
    expansion_latency_median_nanos: u64,
    expansion_latency_p95_nanos: u64,
    expansion_returned_bytes: usize,
    expansion_exact: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let mode = match arguments.next().as_deref() {
        Some("memory") => Mode::Memory,
        Some("durable") => Mode::Durable,
        Some("repository") => Mode::Repository,
        _ => {
            return Err(
                "usage: local_product_performance <memory|durable|repository> <records N|file PATH>"
                    .into(),
            );
        }
    };
    let corpus_kind = arguments.next().ok_or("missing corpus kind")?;
    let corpus_value = arguments.next().ok_or("missing corpus value")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    if matches!(mode, Mode::Repository) {
        if corpus_kind != "records" {
            return Err("repository mode requires records N".into());
        }
        let report = run_repository(corpus_value.parse::<u64>()?)?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let (corpus, input) = match corpus_kind.as_str() {
        "records" => {
            let records = corpus_value.parse::<u64>()?;
            ("generated_provider_shaped", generated_fixture(records)?)
        }
        "file" => ("private_local_log", fs::read(corpus_value)?),
        _ => return Err("corpus kind must be records or file".into()),
    };

    let report = match mode {
        Mode::Memory => run_memory(corpus, &input)?,
        Mode::Durable => run_durable(corpus, &input)?,
        Mode::Repository => unreachable!("repository mode returned above"),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn run_repository(records: u64) -> Result<RepositoryProbeReport, Box<dyn Error>> {
    if records == 0 || records > 1_000_000 {
        return Err("repository record count must be in 1..=1,000,000".into());
    }
    let root = PrivateRepositoryRoot::new()?;
    let repository = DurableResultRepositoryV2::open(root.path(), ProcessKeyAuthorityV2::new(1)?)?;
    let result_id = ResultId::from_bytes([0x91; 32]);
    let started = Instant::now();
    repository.begin(
        result_id,
        100,
        10_000_000_000,
        operation(0x10, 0),
        b"local component performance probe",
    )?;

    let mut source_bytes = 0_u64;
    let mut target_event_id = None;
    let mut target_bytes = Vec::new();
    let mut first = 0_u64;
    let batch_size = u64::try_from(MAX_DURABLE_BATCH_EVENTS_V2)?;
    while first < records {
        let end = records.min(first.checked_add(batch_size).ok_or("batch overflow")?);
        let mut events = Vec::with_capacity(usize::try_from(end - first)?);
        for ordinal in first..end {
            let bytes = repository_fixture_record(ordinal);
            source_bytes = source_bytes
                .checked_add(u64::try_from(bytes.len())?)
                .ok_or("source byte count overflow")?;
            let event_id = repository_event_id(ordinal);
            if ordinal == records / 2 {
                target_event_id = Some(event_id);
                target_bytes.clone_from(&bytes);
            }
            events.push(DurableEventInputV2::new(
                event_id,
                ExactnessBasis::SourceExact,
                bytes,
            )?);
        }
        let batch_ordinal = first / batch_size;
        let batch = BatchCommitInputV2::new(
            batch_ordinal,
            operation(0x20, batch_ordinal),
            events,
            Vec::new(),
            Vec::new(),
        )?;
        repository
            .commit_batch(result_id, &batch)
            .map_err(|error| contextual_error("commit_batch", error))?;
        first = end;
    }
    repository
        .commit_data(
            result_id,
            DataCommitInputV2 {
                operation: operation(0x30, 0),
                question_configuration: lifecycle_digest(1),
                acquisition_receipt: lifecycle_digest(2),
                transformation_receipts: lifecycle_digest(3),
                fetch_completion: lifecycle_digest(4),
                source_identity: lifecycle_digest(5),
                build_context: repository_build_context(),
            },
        )
        .map_err(|error| contextual_error("commit_data", error))?;
    repository
        .seal(
            result_id,
            &SealInputV2 {
                operation: operation(0x40, 0),
                log_brief: b"component-only-probe".to_vec(),
                references: b"component-only-probe".to_vec(),
                presentation_receipt: b"component-only-probe".to_vec(),
                status: b"component-only-probe".to_vec(),
                alias_manifest: b"component-only-probe".to_vec(),
            },
        )
        .map_err(|error| contextual_error("seal", error))?;
    repository
        .publish(result_id, operation(0x50, 0))
        .map_err(|error| contextual_error("publish", error))?;
    let lifecycle_elapsed_nanos = elapsed_nanos(started)?;
    let stored_bytes = directory_bytes(root.path())?;

    let target_event_id = target_event_id.ok_or("expansion target missing")?;
    let mut expansion_latencies = Vec::with_capacity(200);
    let mut expansion_returned_bytes = 0;
    let mut expansion_exact = true;
    for _ in 0..200 {
        let expansion_started = Instant::now();
        let expanded = repository.expand(result_id, &[target_event_id], 1, 1024 * 1024, 200)?;
        expansion_latencies.push(elapsed_nanos(expansion_started)?);
        let event = expanded.events().first().ok_or("expanded event missing")?;
        expansion_returned_bytes = event.authorized_bytes().len();
        expansion_exact &= event.event_id() == target_event_id
            && event.exactness_basis().is_source_exact()
            && event.authorized_bytes() == target_bytes;
    }
    expansion_latencies.sort_unstable();
    let expansion_latency_median_nanos = expansion_latencies[expansion_latencies.len() / 2];
    let expansion_latency_p95_nanos =
        expansion_latencies[(expansion_latencies.len() * 95).div_ceil(100) - 1];
    repository.destroy(result_id)?;
    drop(repository);
    root.cleanup()?;

    let seconds = lifecycle_elapsed_nanos as f64 / 1_000_000_000.0;
    Ok(RepositoryProbeReport {
        schema_version: 1,
        qualification_eligible: false,
        component_only: true,
        authority: "process_conformance_only",
        source_records: records,
        source_bytes,
        lifecycle_elapsed_nanos,
        throughput_records_per_second: records as f64 / seconds,
        throughput_mib_per_second: source_bytes as f64 / (1024.0 * 1024.0) / seconds,
        stored_bytes,
        storage_to_source_ratio: stored_bytes as f64 / source_bytes as f64,
        expansion_samples: expansion_latencies.len(),
        expansion_latency_median_nanos,
        expansion_latency_p95_nanos,
        expansion_returned_bytes,
        expansion_exact,
    })
}

fn repository_fixture_record(ordinal: u64) -> Vec<u8> {
    format!(
        "2026-08-30T12:00:00Z INFO service=api ordinal={ordinal} request=req-{} status=ok\n",
        ordinal % 997
    )
    .into_bytes()
}

fn repository_event_id(ordinal: u64) -> EventId {
    let mut digest = Sha256::new();
    digest.update(b"evidentrail/local-component-performance/event/v1");
    digest.update(ordinal.to_be_bytes());
    EventId::from_bytes(digest.finalize().into())
}

fn operation(prefix: u8, ordinal: u64) -> OperationIdV1 {
    let mut bytes = [0_u8; 16];
    bytes[0] = prefix;
    bytes[8..].copy_from_slice(&ordinal.to_be_bytes());
    OperationIdV1::from_bytes(bytes)
}

fn lifecycle_digest(byte: u8) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes([byte; 32])
}

fn contextual_error(
    stage: &'static str,
    error: evidentrail_store::DurableRepositoryErrorV2,
) -> std::io::Error {
    std::io::Error::other(format!("{stage}: {}", error.code()))
}

fn repository_build_context() -> BuildContextDigestsV1 {
    BuildContextDigestsV1::new(
        lifecycle_digest(11),
        lifecycle_digest(12),
        lifecycle_digest(13),
        lifecycle_digest(14),
        lifecycle_digest(15),
    )
}

fn generated_fixture(records: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let capacity = usize::try_from(records)?
        .checked_mul(112)
        .ok_or("fixture capacity overflow")?;
    let mut input = Vec::with_capacity(capacity);
    for ordinal in 0..records {
        if ordinal % 10_000 == 9_997 {
            input.extend_from_slice(
                format!(
                    "2026-08-30T12:00:00Z ERROR service=api request=req-{ordinal} database timeout after 5000ms\n"
                )
                .as_bytes(),
            );
        } else {
            input.extend_from_slice(
                format!(
                    "2026-08-30T12:00:00Z INFO service=api ordinal={ordinal} request=req-{} status=ok latency_ms={}\n",
                    ordinal % 997,
                    ordinal % 41
                )
                .as_bytes(),
            );
        }
    }
    Ok(input)
}

fn run_memory(corpus: &'static str, input: &[u8]) -> Result<ProbeReport, Box<dyn Error>> {
    let started = Instant::now();
    let (session, observation) = execute_real_memory_product_arm_v2(
        input,
        QUESTION,
        TOKEN_BUDGET,
        RESULT_RANDOMNESS,
        FIXED_NOW,
    )?;
    let compile_elapsed_nanos = elapsed_nanos(started)?;
    let evidence_aliases = alias_count(session.outcome());
    let expansion = if evidence_aliases == 0 {
        None
    } else {
        let result_id = session.outcome().result_id();
        let request = expansion_request(result_id)?;
        let expansion_started = Instant::now();
        let response = session.expand_alias(request, after_creation())?;
        Some(ExpansionReport {
            alias: "E1",
            latency_nanos: elapsed_nanos(expansion_started)?,
            returned_events: response.events().len(),
            returned_bytes: response
                .events()
                .iter()
                .map(|event| event.exact_bytes().len())
                .sum(),
            exact: response
                .events()
                .iter()
                .all(|event| event.exactness_basis().is_source_exact()),
        })
    };
    Ok(report(
        "memory",
        "none",
        corpus,
        input,
        compile_elapsed_nanos,
        0,
        observation,
        evidence_aliases,
        expansion,
    ))
}

fn run_durable(corpus: &'static str, input: &[u8]) -> Result<ProbeReport, Box<dyn Error>> {
    let root = PrivateRepositoryRoot::new()?;
    let repository = DurableResultRepositoryV2::open(root.path(), ProcessKeyAuthorityV2::new(4)?)?;
    let mut backend =
        DurablePublishingMcpRetentionBackendV2::new(DurableProductV2::new(repository));
    let started = Instant::now();
    let observation = execute_real_durable_product_arm_v2(
        &mut backend,
        input,
        QUESTION,
        TOKEN_BUDGET,
        RESULT_RANDOMNESS,
        FIXED_NOW,
    )
    .map_err(|_| "durable product arm failed")?;
    let compile_elapsed_nanos = elapsed_nanos(started)?;
    let stored_bytes = directory_bytes(root.path())?;
    let evidence_aliases = observation.evidence_alias_count;
    let result_id = if evidence_aliases == 0 {
        None
    } else {
        Some(result_id_from_backend_observation(&backend)?)
    };
    let expansion = if evidence_aliases == 0 {
        None
    } else {
        let result_id = result_id.ok_or("published result identity missing")?;
        let request = expansion_request(result_id)?;
        let expansion_started = Instant::now();
        let response = backend.expand_alias(request, after_creation())?;
        Some(ExpansionReport {
            alias: "E1",
            latency_nanos: elapsed_nanos(expansion_started)?,
            returned_events: response.events().len(),
            returned_bytes: response.returned_bytes(),
            exact: response
                .events()
                .iter()
                .all(|event| event.exactness_basis().is_source_exact()),
        })
    };
    if let Some(result_id) = result_id {
        backend.product().repository().destroy(result_id)?;
    }
    drop(backend);
    root.cleanup()?;
    Ok(report(
        "durable",
        "process_conformance_only",
        corpus,
        input,
        compile_elapsed_nanos,
        stored_bytes,
        observation,
        evidence_aliases,
        expansion,
    ))
}

#[allow(clippy::too_many_arguments)]
fn report(
    mode: &'static str,
    authority: &'static str,
    corpus: &'static str,
    input: &[u8],
    elapsed_nanos: u64,
    stored_bytes: u64,
    observation: evidentrail_bench_harness::RealMemoryProductObservationV2,
    evidence_aliases: u64,
    expansion: Option<ExpansionReport>,
) -> ProbeReport {
    let elapsed_seconds = elapsed_nanos as f64 / 1_000_000_000.0;
    ProbeReport {
        schema_version: 1,
        qualification_eligible: false,
        authority,
        mode,
        corpus,
        source_records: observation.source_record_count,
        source_bytes: observation.source_byte_count,
        elapsed_nanos,
        throughput_records_per_second: observation.source_record_count as f64 / elapsed_seconds,
        throughput_mib_per_second: input.len() as f64 / (1024.0 * 1024.0) / elapsed_seconds,
        stored_bytes,
        rendered: observation.rendered,
        evidence_aliases,
        public_artifact_commitment: hex(&observation.public_artifact_commitment),
        authorized_basis_commitment: hex(&observation.authorized_basis_commitment),
        expansion,
    }
}

fn alias_count(outcome: &StdinBriefOutcomeV1) -> u64 {
    match outcome {
        StdinBriefOutcomeV1::Rendered(rendered) => rendered.evidence_alias_count(),
        StdinBriefOutcomeV1::NeedsMore(_) => 0,
    }
}

fn result_id_from_backend_observation(
    backend: &DurablePublishingMcpRetentionBackendV2<ProcessKeyAuthorityV2>,
) -> Result<evidentrail_schema::ResultId, Box<dyn Error>> {
    let records = backend.product().repository().authority().list()?;
    let record = records
        .first()
        .ok_or("published authority record missing")?;
    Ok(record.result_id())
}

fn expansion_request(
    result_id: evidentrail_schema::ResultId,
) -> Result<AliasExpansionRequestV1, Box<dyn Error>> {
    Ok(AliasExpansionRequestV1::new(
        result_id,
        EvidenceAliasV1::new(result_id, 1)?,
        ExpansionRelationV1::Exact,
        ExpansionLimitV1::new(512, 8 * 1024 * 1024, 0, 0)?,
    ))
}

fn after_creation() -> UnixTimestampNanos {
    UnixTimestampNanos::new(FIXED_NOW.get() + 1)
}

struct PrivateRepositoryRoot {
    path: PathBuf,
    armed: bool,
}

impl PrivateRepositoryRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(Self {
            path: env::temp_dir().join(format!(
                "evidentrail-local-product-performance-{}-{unique}",
                std::process::id()
            )),
            armed: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(mut self) -> Result<(), Box<dyn Error>> {
        if self.path.exists() {
            fs::remove_dir_all(&self.path)?;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for PrivateRepositoryRoot {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn directory_bytes(path: &Path) -> Result<u64, Box<dyn Error>> {
    let mut bytes = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err("benchmark repository contains a symbolic link".into());
        }
        if metadata.is_dir() {
            bytes = bytes
                .checked_add(directory_bytes(&entry.path())?)
                .ok_or("repository byte count overflow")?;
        } else if metadata.is_file() {
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or("repository byte count overflow")?;
        }
    }
    Ok(bytes)
}

fn elapsed_nanos(started: Instant) -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(started.elapsed().as_nanos())?)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
