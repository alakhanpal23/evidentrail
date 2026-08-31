//! Non-certifying, real-path resource probe for Streaming Product V3.
//!
//! Peak RSS is intentionally measured by the parent process (`/usr/bin/time`
//! or an equivalent host observer). This program emits deterministic product,
//! storage, and exact-read measurements as JSON.

use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use evidentrail_cli::{StdinBriefOutcomeV1, compile_explicit_stream_profiled_v3};
use evidentrail_core::UnixTimestampNanos;
use evidentrail_store::{
    DurablePackedPerformanceReceiptV3, DurableRetainedEventStoreV3, PackedMemoryEventStoreV3,
    ProcessKeyAuthorityV2, RetainedEventStoreV3,
};
use serde::Serialize;

const QUESTION: &[u8] = b"which request failed and what evidence identifies the cause?";
const TOKEN_BUDGET: u64 = 100_000;
const NOW: UnixTimestampNanos = UnixTimestampNanos::new(1_800_000_000_000_000_000);
const SEED: [u8; 32] = [0x93; 32];

#[derive(Serialize)]
struct Report {
    schema_version: u16,
    qualification_eligible: bool,
    mode: &'static str,
    records: u64,
    source_bytes: u64,
    elapsed_nanos: u64,
    records_per_second: f64,
    retained_or_stored_bytes: u64,
    storage_amplification: f64,
    rendered: bool,
    aliases: u64,
    exact_read_verified: bool,
    expansion_samples: usize,
    expansion_median_nanos: u64,
    expansion_p95_nanos: u64,
    expansion_nanos: Vec<u64>,
    product_performance: ProductPerformanceReport,
    store_performance: Option<StorePerformanceReport>,
}

#[derive(Serialize)]
struct ProductPerformanceReport {
    total_elapsed_nanos: u64,
    atomic_framing_nanos: u64,
    global_analysis_nanos: u64,
    projection_nanos: u64,
    v1_compilation_nanos: u64,
    seal_and_publication_nanos: u64,
}

#[derive(Serialize)]
struct StorePerformanceReport {
    total_elapsed_nanos: u64,
    page_construction_nanos: u64,
    frame_encryption_nanos: u64,
    nonce_reservation_nanos: u64,
    file_write_nanos: u64,
    file_full_sync_nanos: u64,
    rename_nanos: u64,
    directory_sync_nanos: u64,
    nonce_acknowledgement_nanos: u64,
    checkpoint_construction_nanos: u64,
    index_construction_nanos: u64,
    page_scan_nanos: u64,
    frame_decryption_nanos: u64,
    object_count: u64,
    page_count: u64,
    index_shard_count: u64,
    sync_count: u64,
    encrypted_byte_count: u64,
    decrypted_byte_count: u64,
    written_byte_count: u64,
}

struct EmitInput<'a> {
    mode: &'static str,
    records: u64,
    elapsed_nanos: u64,
    retained_or_stored_bytes: u64,
    outcome: &'a StdinBriefOutcomeV1,
    exact_read_verified: bool,
    expansion_latencies: Vec<u64>,
    product_performance: evidentrail_product::StreamingPerformanceReceiptV3,
    store_performance: Option<DurablePackedPerformanceReceiptV3>,
}

struct GeneratedRecords {
    records: u64,
    ordinal: u64,
    current: Vec<u8>,
    offset: usize,
}

impl GeneratedRecords {
    fn new(records: u64) -> Self {
        Self {
            records,
            ordinal: 0,
            current: Vec::new(),
            offset: 0,
        }
    }

    fn fill_record(&mut self) {
        if self.ordinal >= self.records {
            return;
        }
        self.current = if self.ordinal % 10_000 == 9_997 {
            format!(
                "2026-08-30T12:00:00Z ERROR service=api request=req-{} database timeout after 5000ms cause=pool_exhausted\n",
                self.ordinal
            )
            .into_bytes()
        } else {
            format!(
                "2026-08-30T12:00:00Z INFO service=api ordinal={} request=req-{} status=ok latency_ms={}\n",
                self.ordinal,
                self.ordinal % 997,
                self.ordinal % 41
            )
            .into_bytes()
        };
        self.ordinal += 1;
        self.offset = 0;
    }
}

impl Read for GeneratedRecords {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.current.len() {
            self.fill_record();
            if self.current.is_empty() || self.offset == self.current.len() {
                return Ok(0);
            }
        }
        let count = output.len().min(self.current.len() - self.offset);
        output[..count].copy_from_slice(&self.current[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("usage: v3_resource_probe <memory|durable> <records>")?;
    let records = args.next().ok_or("missing records")?.parse::<u64>()?;
    if args.next().is_some() || records == 0 || records > 1_000_000 {
        return Err("records must be in 1..=1,000,000".into());
    }
    match mode.as_str() {
        "memory" => run_memory(records),
        "durable" => run_durable(records),
        _ => Err("mode must be memory or durable".into()),
    }
}

fn run_memory(records: u64) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let session = compile_explicit_stream_profiled_v3(
        GeneratedRecords::new(records),
        QUESTION,
        TOKEN_BUDGET,
        SEED,
        NOW,
        PackedMemoryEventStoreV3::new(),
    )?;
    let elapsed = nanos(started)?;
    let product_performance = session
        .product()
        .last_performance_receipt()
        .ok_or("product performance receipt missing")?;
    let (outcome, backend) = session.into_parts();
    let retained = backend.retained_plaintext_bytes() as u64;
    let locator = middle_locator(&backend, records)?;
    let (exact, latencies) = expansion_observations(&backend, locator.event_id())?;
    emit(EmitInput {
        mode: "memory",
        records,
        elapsed_nanos: elapsed,
        retained_or_stored_bytes: retained,
        outcome: &outcome,
        exact_read_verified: !exact.is_empty(),
        expansion_latencies: latencies,
        product_performance,
        store_performance: None,
    })
}

fn run_durable(records: u64) -> Result<(), Box<dyn Error>> {
    let root = temporary_root()?;
    let backend = DurableRetainedEventStoreV3::open(&root, ProcessKeyAuthorityV2::new(2)?)?;
    backend.enable_performance_instrumentation();
    let started = Instant::now();
    let session = compile_explicit_stream_profiled_v3(
        GeneratedRecords::new(records),
        QUESTION,
        TOKEN_BUDGET,
        SEED,
        NOW,
        backend,
    )?;
    let elapsed = nanos(started)?;
    let product_performance = session
        .product()
        .last_performance_receipt()
        .ok_or("product performance receipt missing")?;
    let (outcome, backend) = session.into_parts();
    let locator = middle_locator(&backend, records)?;
    let (exact, latencies) = expansion_observations(&backend, locator.event_id())?;
    let exact_verified = !exact.is_empty();
    let stored = directory_bytes(&root)?;
    let store_performance = backend.performance_receipt();
    drop(backend);
    fs::remove_dir_all(&root)?;
    emit(EmitInput {
        mode: "durable",
        records,
        elapsed_nanos: elapsed,
        retained_or_stored_bytes: stored,
        outcome: &outcome,
        exact_read_verified: exact_verified,
        expansion_latencies: latencies,
        product_performance,
        store_performance: Some(store_performance),
    })
}

fn expansion_observations<B: RetainedEventStoreV3>(
    backend: &B,
    event_id: evidentrail_schema::EventId,
) -> Result<(Vec<u8>, Vec<u64>), Box<dyn Error>> {
    let mut exact = Vec::new();
    for _ in 0..10 {
        exact = backend.read_exact(event_id)?.to_vec();
    }
    let mut latencies = Vec::with_capacity(200);
    for _ in 0..200 {
        let started = Instant::now();
        exact = backend.read_exact(event_id)?.to_vec();
        latencies.push(nanos(started)?);
    }
    latencies.sort_unstable();
    Ok((exact, latencies))
}

fn middle_locator<B: RetainedEventStoreV3>(
    backend: &B,
    records: u64,
) -> Result<evidentrail_store::RetainedEventLocatorV3, Box<dyn Error>> {
    let wanted = records / 2;
    let mut found = None;
    backend.acquisition_scan(&mut |view| {
        if view.locator().acquisition_ordinal() == wanted {
            found = Some(view.locator());
        }
        Ok(())
    })?;
    found.ok_or_else(|| "middle event missing".into())
}

fn emit(input: EmitInput<'_>) -> Result<(), Box<dyn Error>> {
    let (source_bytes, aliases, rendered) = match input.outcome {
        StdinBriefOutcomeV1::Rendered(value) => (
            value.source_byte_count(),
            value.evidence_alias_count(),
            true,
        ),
        StdinBriefOutcomeV1::NeedsMore(value) => (value.source_byte_count(), 0, false),
    };
    let report = Report {
        schema_version: 1,
        qualification_eligible: false,
        mode: input.mode,
        records: input.records,
        source_bytes,
        elapsed_nanos: input.elapsed_nanos,
        records_per_second: input.records as f64 / (input.elapsed_nanos as f64 / 1_000_000_000.0),
        retained_or_stored_bytes: input.retained_or_stored_bytes,
        storage_amplification: input.retained_or_stored_bytes as f64 / source_bytes as f64,
        rendered,
        aliases,
        exact_read_verified: input.exact_read_verified,
        expansion_samples: input.expansion_latencies.len(),
        expansion_median_nanos: input.expansion_latencies[input.expansion_latencies.len() / 2],
        expansion_p95_nanos: input.expansion_latencies
            [(input.expansion_latencies.len() * 95).div_ceil(100) - 1],
        expansion_nanos: input.expansion_latencies,
        product_performance: ProductPerformanceReport {
            total_elapsed_nanos: input.product_performance.total_elapsed_nanos(),
            atomic_framing_nanos: input.product_performance.atomic_framing_nanos,
            global_analysis_nanos: input.product_performance.global_analysis_nanos,
            projection_nanos: input.product_performance.projection_nanos,
            v1_compilation_nanos: input.product_performance.v1_compilation_nanos,
            seal_and_publication_nanos: input.product_performance.seal_and_publication_nanos,
        },
        store_performance: input.store_performance.map(StorePerformanceReport::from),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

impl From<DurablePackedPerformanceReceiptV3> for StorePerformanceReport {
    fn from(receipt: DurablePackedPerformanceReceiptV3) -> Self {
        Self {
            total_elapsed_nanos: receipt.total_elapsed_nanos(),
            page_construction_nanos: receipt.page_construction_nanos,
            frame_encryption_nanos: receipt.frame_encryption_nanos,
            nonce_reservation_nanos: receipt.nonce_reservation_nanos,
            file_write_nanos: receipt.file_write_nanos,
            file_full_sync_nanos: receipt.file_full_sync_nanos,
            rename_nanos: receipt.rename_nanos,
            directory_sync_nanos: receipt.directory_sync_nanos,
            nonce_acknowledgement_nanos: receipt.nonce_acknowledgement_nanos,
            checkpoint_construction_nanos: receipt.checkpoint_construction_nanos,
            index_construction_nanos: receipt.index_construction_nanos,
            page_scan_nanos: receipt.page_scan_nanos,
            frame_decryption_nanos: receipt.frame_decryption_nanos,
            object_count: receipt.object_count,
            page_count: receipt.page_count,
            index_shard_count: receipt.index_shard_count,
            sync_count: receipt.sync_count,
            encrypted_byte_count: receipt.encrypted_byte_count,
            decrypted_byte_count: receipt.decrypted_byte_count,
            written_byte_count: receipt.written_byte_count,
        }
    }
}

fn nanos(started: Instant) -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(started.elapsed().as_nanos())?)
}

fn temporary_root() -> Result<PathBuf, Box<dyn Error>> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "evidentrail-v3-resource-probe-{}-{stamp}",
        std::process::id()
    )))
}

fn directory_bytes(path: &Path) -> io::Result<u64> {
    let mut bytes = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            bytes = bytes.saturating_add(directory_bytes(&entry.path())?);
        } else {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(bytes)
}
