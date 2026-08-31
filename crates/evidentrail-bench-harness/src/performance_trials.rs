//! M1 paired performance, fidelity, and random-access benchmark protocol.
//!
//! The module owns measurement policy only. Product arms are injected by the
//! caller, which keeps benchmark code out of production selection and lets the
//! same protocol measure memory-only and durable repositories.

use std::error::Error as StdError;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const M1_WARMUP_OBSERVATIONS_V1: usize = 5;
pub const M1_MEASURED_OBSERVATIONS_V1: usize = 30;
pub const DEFAULT_BOOTSTRAP_RESAMPLES_V1: usize = 10_000;
pub const BOOTSTRAP_CONFIDENCE_LEVEL_V1: f64 = 0.95;

const FIXTURE_DOMAIN_V1: &[u8] = b"evidentrail/m1/provider-shaped-fixture/v1";
const BASELINE_DOMAIN_V1: &[u8] = b"evidentrail/m1/frozen-memory-baseline/v1";
const MIN_BOOTSTRAP_RESAMPLES_V1: usize = 2_000;
const THROUGHPUT_RATIO_FLOOR_V1: f64 = 0.90;
const LATENCY_REGRESSION_CEILING_V1: f64 = 0.10;
const TEN_K_LATENCY_OVERHEAD_NANOS_V1: f64 = 20_000_000.0;
const RSS_REGRESSION_CEILING_V1: f64 = 0.15;
const EXPANSION_SCALE_REGRESSION_CEILING_V1: f64 = 0.10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkScaleV1 {
    TenThousand,
    OneHundredThousand,
    OneMillion,
}

impl BenchmarkScaleV1 {
    #[must_use]
    pub const fn record_count(self) -> u64 {
        match self {
            Self::TenThousand => 10_000,
            Self::OneHundredThousand => 100_000,
            Self::OneMillion => 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderShapeV1 {
    LocalFile,
    CloudWatch,
    Kubernetes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkCacheStateV1 {
    Cold,
    Warm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessExpectationV1 {
    Complete,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkArmV1 {
    MemoryOnly,
    Durable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkPhaseV1 {
    Warmup,
    Measured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M1TrialOrderV1 {
    MemoryThenDurable,
    DurableThenMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticObservationV1 {
    /// Commitment to status, Log Brief, references, and semantic receipts.
    pub public_artifact_commitment: [u8; 32],
    /// Commitment independently recomputed from all authorized-basis bytes.
    pub authorized_basis_commitment: [u8; 32],
    pub authorized_basis_exact: bool,
    pub reconciliation_failures: u64,
    pub protected_blocks_retained: u64,
    pub protected_blocks_required: u64,
    pub required_evidence_retained: u64,
    pub required_evidence_total: u64,
    pub correct_citations: u64,
    pub total_citations: u64,
    pub diagnosis_outcomes_correct: u64,
    pub diagnosis_outcomes_total: u64,
    pub fix_outcomes_correct: u64,
    pub fix_outcomes_total: u64,
    pub honest_abstentions: u64,
    pub required_abstentions: u64,
}

impl SemanticObservationV1 {
    fn is_exact_and_reconciled(self) -> bool {
        self.authorized_basis_exact
            && self.reconciliation_failures == 0
            && self.protected_blocks_retained == self.protected_blocks_required
            && self.required_evidence_retained == self.required_evidence_total
            && self.correct_citations == self.total_citations
            && self.diagnosis_outcomes_correct == self.diagnosis_outcomes_total
            && self.fix_outcomes_correct == self.fix_outcomes_total
            && self.honest_abstentions == self.required_abstentions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpansionMeasurementV1 {
    pub total_result_records: u64,
    pub returned_frame_count: u64,
    pub returned_plaintext_bytes: u64,
    pub latency_nanos: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmMeasurementV1 {
    pub elapsed_nanos: u64,
    pub record_count: u64,
    pub authorized_source_bytes: u64,
    pub peak_rss_bytes: u64,
    /// Zero for memory-only arms; complete repository bytes for durable arms.
    pub stored_bytes: u64,
    pub completeness: CompletenessExpectationV1,
    pub semantic: SemanticObservationV1,
    pub expansion: Option<ExpansionMeasurementV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenMemoryBaselineV1 {
    pub fixture_commitment: [u8; 32],
    pub build_context_commitment: [u8; 32],
    pub semantic: SemanticObservationV1,
    pub baseline_commitment: [u8; 32],
}

#[must_use]
pub fn freeze_memory_baseline_v1(
    fixture_commitment: [u8; 32],
    build_context_commitment: [u8; 32],
    semantic: SemanticObservationV1,
) -> Option<FrozenMemoryBaselineV1> {
    if !semantic.is_exact_and_reconciled() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(BASELINE_DOMAIN_V1);
    hasher.update(fixture_commitment);
    hasher.update(build_context_commitment);
    hash_semantic_v1(&mut hasher, semantic);
    let baseline_commitment = hasher.finalize().into();
    Some(FrozenMemoryBaselineV1 {
        fixture_commitment,
        build_context_commitment,
        semantic,
        baseline_commitment,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M1PairedRunConfigV1 {
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub fixture_seed: u64,
    pub randomization_seed: u64,
    pub warmup_observations: usize,
    pub measured_observations: usize,
    pub bootstrap_resamples: usize,
    pub durable_rss_hard_cap_bytes: u64,
    pub baseline: FrozenMemoryBaselineV1,
}

impl M1PairedRunConfigV1 {
    pub fn validate(self) -> Result<Self, M1PerformanceErrorV1> {
        if self.warmup_observations < M1_WARMUP_OBSERVATIONS_V1 {
            return Err(M1PerformanceErrorV1::InsufficientWarmups);
        }
        if self.measured_observations < M1_MEASURED_OBSERVATIONS_V1 {
            return Err(M1PerformanceErrorV1::InsufficientMeasuredObservations);
        }
        if self.bootstrap_resamples < MIN_BOOTSTRAP_RESAMPLES_V1 {
            return Err(M1PerformanceErrorV1::InsufficientBootstrapResamples);
        }
        if self.durable_rss_hard_cap_bytes == 0 {
            return Err(M1PerformanceErrorV1::InvalidHardCap);
        }
        if self.baseline.fixture_commitment
            != provider_fixture_commitment_v1(self.provider, self.scale, self.fixture_seed)
        {
            return Err(M1PerformanceErrorV1::BaselineFixtureMismatch);
        }
        let Some(recomputed_baseline) = freeze_memory_baseline_v1(
            self.baseline.fixture_commitment,
            self.baseline.build_context_commitment,
            self.baseline.semantic,
        ) else {
            return Err(M1PerformanceErrorV1::SemanticRegression);
        };
        if recomputed_baseline.baseline_commitment != self.baseline.baseline_commitment {
            return Err(M1PerformanceErrorV1::SemanticRegression);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct M1TrialRequestV1 {
    pub phase: BenchmarkPhaseV1,
    pub arm: BenchmarkArmV1,
    pub pair_index: usize,
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub fixture_seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkExecutionFailureV1 {
    ArmFailed,
    ObservationUnavailable,
}

impl fmt::Display for BenchmarkExecutionFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArmFailed => "EVIDENTRAIL_BENCHMARK_ARM_FAILED",
            Self::ObservationUnavailable => "EVIDENTRAIL_BENCHMARK_OBSERVATION_UNAVAILABLE",
        })
    }
}

impl StdError for BenchmarkExecutionFailureV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M1PerformanceErrorV1 {
    InsufficientWarmups,
    InsufficientMeasuredObservations,
    InsufficientBootstrapResamples,
    InvalidHardCap,
    BaselineFixtureMismatch,
    InvalidMeasurement,
    SemanticRegression,
    Execution(BenchmarkExecutionFailureV1),
}

impl fmt::Display for M1PerformanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InsufficientWarmups => "EVIDENTRAIL_M1_INSUFFICIENT_WARMUPS",
            Self::InsufficientMeasuredObservations => "EVIDENTRAIL_M1_INSUFFICIENT_OBSERVATIONS",
            Self::InsufficientBootstrapResamples => {
                "EVIDENTRAIL_M1_INSUFFICIENT_BOOTSTRAP_RESAMPLES"
            }
            Self::InvalidHardCap => "EVIDENTRAIL_M1_INVALID_HARD_CAP",
            Self::BaselineFixtureMismatch => "EVIDENTRAIL_M1_BASELINE_FIXTURE_MISMATCH",
            Self::InvalidMeasurement => "EVIDENTRAIL_M1_INVALID_MEASUREMENT",
            Self::SemanticRegression => "EVIDENTRAIL_M1_SEMANTIC_REGRESSION",
            Self::Execution(error) => return error.fmt(formatter),
        })
    }
}

impl StdError for M1PerformanceErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M1TrialObservationV1 {
    pub pair_index: usize,
    pub order: M1TrialOrderV1,
    pub memory: ArmMeasurementV1,
    pub durable: ArmMeasurementV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M1PairedRunV1 {
    pub config: M1PairedRunConfigV1,
    pub observations: Vec<M1TrialObservationV1>,
}

pub fn run_m1_paired_trials_v1<F>(
    config: M1PairedRunConfigV1,
    mut execute: F,
) -> Result<M1PairedRunV1, M1PerformanceErrorV1>
where
    F: FnMut(M1TrialRequestV1) -> Result<ArmMeasurementV1, BenchmarkExecutionFailureV1>,
{
    let config = config.validate()?;
    let mut random = XorShift64::new(config.randomization_seed);
    let warmup_orders = balanced_random_orders_v1(config.warmup_observations, &mut random);
    for (pair_index, order) in warmup_orders.into_iter().enumerate() {
        execute_pair_v1(
            &config,
            BenchmarkPhaseV1::Warmup,
            pair_index,
            order,
            &mut execute,
        )?;
    }

    let measured_orders = balanced_random_orders_v1(config.measured_observations, &mut random);
    let mut observations = Vec::with_capacity(config.measured_observations);
    for (pair_index, order) in measured_orders.into_iter().enumerate() {
        let (memory, durable) = execute_pair_v1(
            &config,
            BenchmarkPhaseV1::Measured,
            pair_index,
            order,
            &mut execute,
        )?;
        observations.push(M1TrialObservationV1 {
            pair_index,
            order,
            memory,
            durable,
        });
    }
    Ok(M1PairedRunV1 {
        config,
        observations,
    })
}

fn execute_pair_v1<F>(
    config: &M1PairedRunConfigV1,
    phase: BenchmarkPhaseV1,
    pair_index: usize,
    order: M1TrialOrderV1,
    execute: &mut F,
) -> Result<(ArmMeasurementV1, ArmMeasurementV1), M1PerformanceErrorV1>
where
    F: FnMut(M1TrialRequestV1) -> Result<ArmMeasurementV1, BenchmarkExecutionFailureV1>,
{
    let invoke = |arm, execute: &mut F| {
        execute(M1TrialRequestV1 {
            phase,
            arm,
            pair_index,
            scale: config.scale,
            provider: config.provider,
            cache_state: config.cache_state,
            fixture_seed: config.fixture_seed,
        })
        .map_err(M1PerformanceErrorV1::Execution)
    };
    let (memory, durable) = match order {
        M1TrialOrderV1::MemoryThenDurable => (
            invoke(BenchmarkArmV1::MemoryOnly, execute)?,
            invoke(BenchmarkArmV1::Durable, execute)?,
        ),
        M1TrialOrderV1::DurableThenMemory => (
            invoke(BenchmarkArmV1::Durable, execute)?,
            invoke(BenchmarkArmV1::MemoryOnly, execute)?,
        ),
    };
    let (memory, durable) = match order {
        M1TrialOrderV1::MemoryThenDurable => (memory, durable),
        M1TrialOrderV1::DurableThenMemory => (durable, memory),
    };
    validate_measurement_v1(config, memory, BenchmarkArmV1::MemoryOnly)?;
    validate_measurement_v1(config, durable, BenchmarkArmV1::Durable)?;
    if memory.authorized_source_bytes != durable.authorized_source_bytes
        || memory
            .expansion
            .map(|value| (value.returned_frame_count, value.returned_plaintext_bytes))
            != durable
                .expansion
                .map(|value| (value.returned_frame_count, value.returned_plaintext_bytes))
    {
        return Err(M1PerformanceErrorV1::InvalidMeasurement);
    }
    Ok((memory, durable))
}

fn validate_measurement_v1(
    config: &M1PairedRunConfigV1,
    measurement: ArmMeasurementV1,
    arm: BenchmarkArmV1,
) -> Result<(), M1PerformanceErrorV1> {
    if measurement.elapsed_nanos == 0
        || measurement.record_count != config.scale.record_count()
        || measurement.authorized_source_bytes == 0
        || measurement.peak_rss_bytes == 0
        || (arm == BenchmarkArmV1::MemoryOnly && measurement.stored_bytes != 0)
        || (arm == BenchmarkArmV1::Durable && measurement.stored_bytes == 0)
        || measurement.completeness
            != ProviderFixtureStreamV1::new(config.provider, 0, config.fixture_seed)
                .completeness_expectation()
    {
        return Err(M1PerformanceErrorV1::InvalidMeasurement);
    }
    if measurement.semantic != config.baseline.semantic
        || !measurement.semantic.is_exact_and_reconciled()
    {
        return Err(M1PerformanceErrorV1::SemanticRegression);
    }
    if let Some(expansion) = measurement.expansion {
        if expansion.total_result_records != measurement.record_count
            || expansion.returned_frame_count == 0
            || expansion.returned_plaintext_bytes == 0
            || expansion.latency_nanos == 0
        {
            return Err(M1PerformanceErrorV1::InvalidMeasurement);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceIntervalV1 {
    pub point: f64,
    pub lower: f64,
    pub upper: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct StorageOverheadV1 {
    pub median_ratio: f64,
    pub p95_ratio: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDispositionV1 {
    Pass,
    Fail,
    NotApplicable,
    NotMeasured,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct M1GateReportV1 {
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub measured_observations: usize,
    pub sampling_gate: GateDispositionV1,
    pub semantic_exactness: GateDispositionV1,
    pub throughput_ratio: ConfidenceIntervalV1,
    pub throughput_gate: GateDispositionV1,
    pub latency_regression: ConfidenceIntervalV1,
    pub latency_gate: GateDispositionV1,
    pub rss_regression: ConfidenceIntervalV1,
    pub rss_gate: GateDispositionV1,
    pub storage_overhead: StorageOverheadV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M1SliceIdentityV1 {
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct M1PerformanceSuiteReportV1 {
    pub confidence_level: f64,
    pub reports: Vec<M1GateReportV1>,
    pub expansion_scale_independence: GateDispositionV1,
    pub expansion_scale_ratio: Option<ConfidenceIntervalV1>,
    pub worst_throughput_slice: Option<M1SliceIdentityV1>,
    pub worst_latency_slice: Option<M1SliceIdentityV1>,
    pub worst_rss_slice: Option<M1SliceIdentityV1>,
    pub overall: GateDispositionV1,
}

#[must_use]
pub fn evaluate_m1_performance_suite_v1(runs: &[M1PairedRunV1]) -> M1PerformanceSuiteReportV1 {
    let mut reports = Vec::with_capacity(runs.len());
    for run in runs {
        reports.push(evaluate_run_v1(run));
    }
    let expansion_scale_ratio = expansion_scale_ratio_v1(runs);
    let expansion_scale_independence =
        expansion_scale_ratio.map_or(GateDispositionV1::NotMeasured, |interval| {
            if interval.upper <= 1.0 + EXPANSION_SCALE_REGRESSION_CEILING_V1 {
                GateDispositionV1::Pass
            } else {
                GateDispositionV1::Fail
            }
        });
    let required_reports_present = required_matrix_present_v1(&reports);
    let report_gates_pass = reports.iter().all(|report| {
        report.sampling_gate == GateDispositionV1::Pass
            && report.semantic_exactness == GateDispositionV1::Pass
            && matches!(
                report.throughput_gate,
                GateDispositionV1::Pass | GateDispositionV1::NotApplicable
            )
            && report.latency_gate == GateDispositionV1::Pass
            && report.rss_gate == GateDispositionV1::Pass
    });
    let overall = if required_reports_present
        && report_gates_pass
        && expansion_scale_independence == GateDispositionV1::Pass
    {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    };
    let worst_throughput_slice = reports
        .iter()
        .filter(|report| report.throughput_gate != GateDispositionV1::NotApplicable)
        .min_by(|left, right| {
            left.throughput_ratio
                .lower
                .total_cmp(&right.throughput_ratio.lower)
        })
        .map(slice_identity_v1);
    let worst_latency_slice = reports
        .iter()
        .max_by(|left, right| {
            normalized_latency_regression_v1(left)
                .total_cmp(&normalized_latency_regression_v1(right))
        })
        .map(slice_identity_v1);
    let worst_rss_slice = reports
        .iter()
        .max_by(|left, right| {
            left.rss_regression
                .upper
                .total_cmp(&right.rss_regression.upper)
        })
        .map(slice_identity_v1);
    M1PerformanceSuiteReportV1 {
        confidence_level: BOOTSTRAP_CONFIDENCE_LEVEL_V1,
        reports,
        expansion_scale_independence,
        expansion_scale_ratio,
        worst_throughput_slice,
        worst_latency_slice,
        worst_rss_slice,
        overall,
    }
}

fn evaluate_run_v1(run: &M1PairedRunV1) -> M1GateReportV1 {
    if !run_structure_valid_v1(run) {
        return failed_run_report_v1(run);
    }
    let elapsed_ratios: Vec<f64> = run
        .observations
        .iter()
        .map(|observation| {
            observation.memory.elapsed_nanos as f64 / observation.durable.elapsed_nanos as f64
        })
        .collect();
    let memory_elapsed: Vec<f64> = run
        .observations
        .iter()
        .map(|observation| observation.memory.elapsed_nanos as f64)
        .collect();
    let durable_elapsed: Vec<f64> = run
        .observations
        .iter()
        .map(|observation| observation.durable.elapsed_nanos as f64)
        .collect();
    let rss_regressions: Vec<f64> = run
        .observations
        .iter()
        .map(|observation| {
            observation.durable.peak_rss_bytes as f64 / observation.memory.peak_rss_bytes as f64
                - 1.0
        })
        .collect();
    let storage_ratios: Vec<f64> = run
        .observations
        .iter()
        .map(|observation| {
            observation.durable.stored_bytes as f64
                / observation.durable.authorized_source_bytes as f64
        })
        .collect();

    let throughput_ratio = bootstrap_mean_ci_v1(
        &elapsed_ratios,
        run.config.bootstrap_resamples,
        run.config.randomization_seed ^ 0x5452_5054,
    );
    let latency_regression = bootstrap_p95_comparison_ci_v1(
        &memory_elapsed,
        &durable_elapsed,
        run.config.bootstrap_resamples,
        run.config.randomization_seed ^ 0x4c41_5445,
        run.config.scale == BenchmarkScaleV1::TenThousand,
    );
    let rss_regression = bootstrap_mean_ci_v1(
        &rss_regressions,
        run.config.bootstrap_resamples,
        run.config.randomization_seed ^ 0x5253_5321,
    );

    let throughput_gate = if run.config.scale == BenchmarkScaleV1::TenThousand {
        GateDispositionV1::NotApplicable
    } else if throughput_ratio.lower >= THROUGHPUT_RATIO_FLOOR_V1 {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    };
    let latency_ceiling = if run.config.scale == BenchmarkScaleV1::TenThousand {
        TEN_K_LATENCY_OVERHEAD_NANOS_V1
    } else {
        LATENCY_REGRESSION_CEILING_V1
    };
    let latency_gate = if latency_regression.upper <= latency_ceiling {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    };
    let under_hard_cap = run.observations.iter().all(|observation| {
        observation.durable.peak_rss_bytes <= run.config.durable_rss_hard_cap_bytes
    });
    let rss_gate = if under_hard_cap && rss_regression.upper <= RSS_REGRESSION_CEILING_V1 {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    };
    let semantic_exactness = if run.observations.iter().all(|observation| {
        observation.memory.semantic == run.config.baseline.semantic
            && observation.durable.semantic == run.config.baseline.semantic
            && observation.memory.semantic.is_exact_and_reconciled()
    }) {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    };

    M1GateReportV1 {
        scale: run.config.scale,
        provider: run.config.provider,
        cache_state: run.config.cache_state,
        measured_observations: run.observations.len(),
        sampling_gate: GateDispositionV1::Pass,
        semantic_exactness,
        throughput_ratio,
        throughput_gate,
        latency_regression,
        latency_gate,
        rss_regression,
        rss_gate,
        storage_overhead: StorageOverheadV1 {
            median_ratio: percentile_v1(storage_ratios.clone(), 0.50),
            p95_ratio: percentile_v1(storage_ratios, 0.95),
        },
    }
}

fn run_structure_valid_v1(run: &M1PairedRunV1) -> bool {
    if run.config.validate().is_err()
        || run.observations.len() != run.config.measured_observations
        || run.observations.len() < M1_MEASURED_OBSERVATIONS_V1
    {
        return false;
    }
    let mut random = XorShift64::new(run.config.randomization_seed);
    let _ = balanced_random_orders_v1(run.config.warmup_observations, &mut random);
    let expected_orders = balanced_random_orders_v1(run.config.measured_observations, &mut random);
    run.observations
        .iter()
        .zip(expected_orders)
        .enumerate()
        .all(|(index, (observation, expected_order))| {
            observation.pair_index == index
                && observation.order == expected_order
                && validate_measurement_v1(
                    &run.config,
                    observation.memory,
                    BenchmarkArmV1::MemoryOnly,
                )
                .is_ok()
                && validate_measurement_v1(
                    &run.config,
                    observation.durable,
                    BenchmarkArmV1::Durable,
                )
                .is_ok()
                && observation.memory.authorized_source_bytes
                    == observation.durable.authorized_source_bytes
                && observation
                    .memory
                    .expansion
                    .map(|value| (value.returned_frame_count, value.returned_plaintext_bytes))
                    == observation
                        .durable
                        .expansion
                        .map(|value| (value.returned_frame_count, value.returned_plaintext_bytes))
        })
}

fn failed_run_report_v1(run: &M1PairedRunV1) -> M1GateReportV1 {
    let zero = ConfidenceIntervalV1 {
        point: 0.0,
        lower: 0.0,
        upper: 0.0,
    };
    M1GateReportV1 {
        scale: run.config.scale,
        provider: run.config.provider,
        cache_state: run.config.cache_state,
        measured_observations: run.observations.len(),
        sampling_gate: GateDispositionV1::Fail,
        semantic_exactness: GateDispositionV1::Fail,
        throughput_ratio: zero,
        throughput_gate: GateDispositionV1::Fail,
        latency_regression: zero,
        latency_gate: GateDispositionV1::Fail,
        rss_regression: zero,
        rss_gate: GateDispositionV1::Fail,
        storage_overhead: StorageOverheadV1 {
            median_ratio: 0.0,
            p95_ratio: 0.0,
        },
    }
}

fn required_matrix_present_v1(reports: &[M1GateReportV1]) -> bool {
    [
        ProviderShapeV1::LocalFile,
        ProviderShapeV1::CloudWatch,
        ProviderShapeV1::Kubernetes,
    ]
    .into_iter()
    .all(|provider| {
        [
            BenchmarkScaleV1::TenThousand,
            BenchmarkScaleV1::OneHundredThousand,
            BenchmarkScaleV1::OneMillion,
        ]
        .into_iter()
        .all(|scale| {
            [BenchmarkCacheStateV1::Cold, BenchmarkCacheStateV1::Warm]
                .into_iter()
                .all(|cache| {
                    reports.iter().any(|report| {
                        report.provider == provider
                            && report.scale == scale
                            && report.cache_state == cache
                    })
                })
        })
    })
}

fn expansion_scale_ratio_v1(runs: &[M1PairedRunV1]) -> Option<ConfidenceIntervalV1> {
    let mut best: Option<(&M1PairedRunV1, &M1PairedRunV1)> = None;
    for small in runs {
        for large in runs {
            if large.config.scale.record_count() < small.config.scale.record_count() * 10
                || small.config.provider != large.config.provider
                || small.config.cache_state != large.config.cache_state
            {
                continue;
            }
            let Some(small_key) = expansion_shape_v1(small) else {
                continue;
            };
            let Some(large_key) = expansion_shape_v1(large) else {
                continue;
            };
            if small_key != large_key {
                continue;
            }
            if best.is_none_or(|(old_small, old_large)| {
                large.config.scale.record_count() / small.config.scale.record_count()
                    > old_large.config.scale.record_count() / old_small.config.scale.record_count()
            }) {
                best = Some((small, large));
            }
        }
    }
    let (small, large) = best?;
    let small_latencies: Vec<f64> = small
        .observations
        .iter()
        .map(|item| {
            item.durable
                .expansion
                .map(|value| value.latency_nanos as f64)
        })
        .collect::<Option<_>>()?;
    let large_latencies: Vec<f64> = large
        .observations
        .iter()
        .map(|item| {
            item.durable
                .expansion
                .map(|value| value.latency_nanos as f64)
        })
        .collect::<Option<_>>()?;
    Some(bootstrap_independent_p95_ratio_ci_v1(
        &small_latencies,
        &large_latencies,
        small
            .config
            .bootstrap_resamples
            .min(large.config.bootstrap_resamples),
        small.config.randomization_seed ^ large.config.randomization_seed ^ 0x4558_5044,
    ))
}

fn expansion_shape_v1(run: &M1PairedRunV1) -> Option<(u64, u64)> {
    let first = run.observations.first()?.durable.expansion?;
    run.observations
        .iter()
        .all(|item| {
            item.durable.expansion.is_some_and(|value| {
                value.returned_frame_count == first.returned_frame_count
                    && value.returned_plaintext_bytes == first.returned_plaintext_bytes
            })
        })
        .then_some((first.returned_frame_count, first.returned_plaintext_bytes))
}

fn bootstrap_mean_ci_v1(values: &[f64], resamples: usize, seed: u64) -> ConfidenceIntervalV1 {
    let point = mean_v1(values);
    let mut random = XorShift64::new(seed);
    let mut distribution = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut total = 0.0;
        for _ in values {
            total += values[random.index(values.len())];
        }
        distribution.push(total / values.len() as f64);
    }
    interval_v1(point, distribution)
}

fn bootstrap_p95_comparison_ci_v1(
    baseline: &[f64],
    candidate: &[f64],
    resamples: usize,
    seed: u64,
    absolute: bool,
) -> ConfidenceIntervalV1 {
    let compare = |left: &[f64], right: &[f64]| {
        let baseline_p95 = percentile_v1(left.to_vec(), 0.95);
        let candidate_p95 = percentile_v1(right.to_vec(), 0.95);
        if absolute {
            candidate_p95 - baseline_p95
        } else {
            candidate_p95 / baseline_p95 - 1.0
        }
    };
    let point = compare(baseline, candidate);
    let mut random = XorShift64::new(seed);
    let mut distribution = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut left = Vec::with_capacity(baseline.len());
        let mut right = Vec::with_capacity(candidate.len());
        for _ in baseline {
            let index = random.index(baseline.len());
            left.push(baseline[index]);
            right.push(candidate[index]);
        }
        distribution.push(compare(&left, &right));
    }
    interval_v1(point, distribution)
}

fn bootstrap_independent_p95_ratio_ci_v1(
    baseline: &[f64],
    candidate: &[f64],
    resamples: usize,
    seed: u64,
) -> ConfidenceIntervalV1 {
    let ratio = |left: &[f64], right: &[f64]| {
        percentile_v1(right.to_vec(), 0.95) / percentile_v1(left.to_vec(), 0.95)
    };
    let point = ratio(baseline, candidate);
    let mut random = XorShift64::new(seed);
    let mut distribution = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let left: Vec<f64> = (0..baseline.len())
            .map(|_| baseline[random.index(baseline.len())])
            .collect();
        let right: Vec<f64> = (0..candidate.len())
            .map(|_| candidate[random.index(candidate.len())])
            .collect();
        distribution.push(ratio(&left, &right));
    }
    interval_v1(point, distribution)
}

fn interval_v1(point: f64, distribution: Vec<f64>) -> ConfidenceIntervalV1 {
    ConfidenceIntervalV1 {
        point,
        lower: percentile_v1(distribution.clone(), 0.025),
        upper: percentile_v1(distribution, 0.975),
    }
}

fn percentile_v1(mut values: Vec<f64>, quantile: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    let index = ((values.len() - 1) as f64 * quantile).ceil() as usize;
    values[index]
}

fn mean_v1(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn balanced_random_orders_v1(count: usize, random: &mut XorShift64) -> Vec<M1TrialOrderV1> {
    let mut orders = Vec::with_capacity(count);
    for index in 0..count {
        orders.push(if index % 2 == 0 {
            M1TrialOrderV1::MemoryThenDurable
        } else {
            M1TrialOrderV1::DurableThenMemory
        });
    }
    for index in (1..orders.len()).rev() {
        let swap = random.index(index + 1);
        orders.swap(index, swap);
    }
    orders
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderFixtureRecordV1 {
    pub acquisition_ordinal: u64,
    pub native_identity: Vec<u8>,
    pub source_member: Vec<u8>,
    pub canonical_order_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub terminator: Vec<u8>,
}

pub struct ProviderFixtureStreamV1 {
    provider: ProviderShapeV1,
    next: u64,
    end: u64,
    seed: u64,
}

impl ProviderFixtureStreamV1 {
    #[must_use]
    pub const fn new(provider: ProviderShapeV1, record_count: u64, seed: u64) -> Self {
        Self {
            provider,
            next: 0,
            end: record_count,
            seed,
        }
    }

    #[must_use]
    pub const fn completeness_expectation(&self) -> CompletenessExpectationV1 {
        match self.provider {
            ProviderShapeV1::LocalFile => CompletenessExpectationV1::Complete,
            ProviderShapeV1::CloudWatch | ProviderShapeV1::Kubernetes => {
                CompletenessExpectationV1::Unknown
            }
        }
    }
}

impl Iterator for ProviderFixtureStreamV1 {
    type Item = ProviderFixtureRecordV1;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        let ordinal = self.next;
        self.next += 1;
        Some(provider_record_v1(self.provider, ordinal, self.seed))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.end - self.next).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ProviderFixtureStreamV1 {}

#[must_use]
pub fn provider_fixture_commitment_v1(
    provider: ProviderShapeV1,
    scale: BenchmarkScaleV1,
    seed: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FIXTURE_DOMAIN_V1);
    hasher.update([provider_code_v1(provider)]);
    hasher.update(scale.record_count().to_be_bytes());
    hasher.update(seed.to_be_bytes());
    hasher.finalize().into()
}

fn provider_record_v1(
    provider: ProviderShapeV1,
    ordinal: u64,
    seed: u64,
) -> ProviderFixtureRecordV1 {
    let lane = (ordinal.wrapping_mul(17).wrapping_add(seed) % 31) as u16;
    // Reverse timestamps inside every synthetic provider page. Acquisition
    // order is therefore preserved separately and cannot accidentally serve
    // as the canonical provider order in a benchmark arm.
    let page_reversed_ordinal = (ordinal / 128)
        .wrapping_mul(128)
        .wrapping_add(127 - (ordinal % 128));
    let timestamp = 1_700_000_000_000_000_000u64
        .wrapping_add(page_reversed_ordinal.wrapping_mul(1_000_003))
        .wrapping_add(seed & 0xffff);
    let (native_identity, source_member, canonical_order_key) = match provider {
        ProviderShapeV1::LocalFile => (
            format!("inode:77:record:{ordinal}").into_bytes(),
            b"fixture.log".to_vec(),
            ordinal.to_be_bytes().to_vec(),
        ),
        ProviderShapeV1::CloudWatch => (
            format!("acct-{seed:016x}/us-west-2/group-{lane}/stream-{lane}/event-{ordinal}")
                .into_bytes(),
            format!("group-{lane}/stream-{lane}").into_bytes(),
            format!(
                "{timestamp:020}/{:020}/acct-{seed:016x}/us-west-2/group-{lane}/stream-{lane}/event-{ordinal}",
                timestamp.wrapping_add(41)
            )
            .into_bytes(),
        ),
        ProviderShapeV1::Kubernetes => {
            let restart = (ordinal / 200_000) as u16;
            (
                format!(
                    "cluster-{seed:016x}/ns-a/pod-{lane}/container-app/id-{lane}/restart-{restart}/current/stdout/{timestamp}/{ordinal}"
                )
                .into_bytes(),
                format!("pod-{lane}/container-app/restart-{restart}").into_bytes(),
                format!(
                    "{timestamp:020}/pod-{lane}/container-app/{restart:05}/stdout/{ordinal:020}"
                )
                .into_bytes(),
            )
        }
    };
    let (payload, terminator) = hostile_payload_v1(ordinal, lane);
    ProviderFixtureRecordV1 {
        acquisition_ordinal: ordinal,
        native_identity,
        source_member,
        canonical_order_key,
        payload,
        terminator,
    }
}

fn hostile_payload_v1(ordinal: u64, lane: u16) -> (Vec<u8>, Vec<u8>) {
    match ordinal % 4096 {
        0 => (vec![0xff, 0xfe, b'X', 0, b'Y'], b"\r\n".to_vec()),
        1 => (Vec::new(), b"\n".to_vec()),
        2 | 3 => (
            b"duplicate-payload-distinct-native-identity".to_vec(),
            b"\n".to_vec(),
        ),
        4 => (b"embedded\0nul\0payload".to_vec(), Vec::new()),
        5 => (b"incomplete-final-record".to_vec(), Vec::new()),
        _ => (
            format!(
                "ts={} lane={lane} request=req-{} status=ok",
                ordinal * 13,
                ordinal % 997
            )
            .into_bytes(),
            b"\n".to_vec(),
        ),
    }
}

fn provider_code_v1(provider: ProviderShapeV1) -> u8 {
    match provider {
        ProviderShapeV1::LocalFile => 1,
        ProviderShapeV1::CloudWatch => 2,
        ProviderShapeV1::Kubernetes => 3,
    }
}

fn slice_identity_v1(report: &M1GateReportV1) -> M1SliceIdentityV1 {
    M1SliceIdentityV1 {
        scale: report.scale,
        provider: report.provider,
        cache_state: report.cache_state,
    }
}

fn normalized_latency_regression_v1(report: &M1GateReportV1) -> f64 {
    if report.scale == BenchmarkScaleV1::TenThousand {
        report.latency_regression.upper / TEN_K_LATENCY_OVERHEAD_NANOS_V1
    } else {
        report.latency_regression.upper / LATENCY_REGRESSION_CEILING_V1
    }
}

fn hash_semantic_v1(hasher: &mut Sha256, semantic: SemanticObservationV1) {
    hasher.update(semantic.public_artifact_commitment);
    hasher.update(semantic.authorized_basis_commitment);
    hasher.update([u8::from(semantic.authorized_basis_exact)]);
    for value in [
        semantic.reconciliation_failures,
        semantic.protected_blocks_retained,
        semantic.protected_blocks_required,
        semantic.required_evidence_retained,
        semantic.required_evidence_total,
        semantic.correct_citations,
        semantic.total_citations,
        semantic.diagnosis_outcomes_correct,
        semantic.diagnosis_outcomes_total,
        semantic.fix_outcomes_correct,
        semantic.fix_outcomes_total,
        semantic.honest_abstentions,
        semantic.required_abstentions,
    ] {
        hasher.update(value.to_be_bytes());
    }
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        (self.next() % length as u64) as usize
    }
}
