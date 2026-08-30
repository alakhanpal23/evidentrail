//! Dedicated-host qualification policy and paired BCa statistics.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    BenchmarkCacheStateV1, BenchmarkScaleV1, GateDispositionV1, M1TrialOrderV1, ProviderShapeV1,
    SemanticObservationV1,
};

pub const THROUGHPUT_WARMUPS_V2: usize = 5;
pub const THROUGHPUT_MEASURED_PAIRS_V2: usize = 30;
pub const LATENCY_WARMUPS_V2: usize = 10;
pub const LATENCY_MEASURED_PAIRS_V2: usize = 200;
pub const QUALIFICATION_BCA_RESAMPLES_V2: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationMetricV2 {
    Throughput,
    Latency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityQualificationV2 {
    ExternalTrustedRoot,
    ProcessConformanceOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheQualificationV2 {
    WarmProcess,
    CleanBootPerArm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationThermalStateV2 {
    Nominal,
    Fair,
    Serious,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationEnvironmentV2 {
    pub manifest_commitment: [u8; 32],
    pub host_identity_commitment: [u8; 32],
    pub os_build_commitment: [u8; 32],
    pub hardware_commitment: [u8; 32],
    pub filesystem_commitment: [u8; 32],
    pub executable_commitment: [u8; 32],
    pub dedicated_reference_host: bool,
    pub thermal_monitoring_available: bool,
    pub authority: AuthorityQualificationV2,
    pub cache_qualification: CacheQualificationV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationProtocolV2 {
    pub metric: QualificationMetricV2,
    pub warmups: usize,
    pub measured_pairs: usize,
    pub bca_resamples: usize,
    pub randomization_seed: u64,
}

impl QualificationProtocolV2 {
    #[must_use]
    pub const fn throughput(seed: u64) -> Self {
        Self {
            metric: QualificationMetricV2::Throughput,
            warmups: THROUGHPUT_WARMUPS_V2,
            measured_pairs: THROUGHPUT_MEASURED_PAIRS_V2,
            bca_resamples: QUALIFICATION_BCA_RESAMPLES_V2,
            randomization_seed: seed,
        }
    }
    #[must_use]
    pub const fn latency(seed: u64) -> Self {
        Self {
            metric: QualificationMetricV2::Latency,
            warmups: LATENCY_WARMUPS_V2,
            measured_pairs: LATENCY_MEASURED_PAIRS_V2,
            bca_resamples: QUALIFICATION_BCA_RESAMPLES_V2,
            randomization_seed: seed,
        }
    }
    fn valid(self) -> bool {
        let (warmups, pairs) = match self.metric {
            QualificationMetricV2::Throughput => {
                (THROUGHPUT_WARMUPS_V2, THROUGHPUT_MEASURED_PAIRS_V2)
            }
            QualificationMetricV2::Latency => (LATENCY_WARMUPS_V2, LATENCY_MEASURED_PAIRS_V2),
        };
        self.warmups >= warmups
            && self.measured_pairs >= pairs
            && self.bca_resamples >= QUALIFICATION_BCA_RESAMPLES_V2
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationArmObservationV2 {
    pub elapsed_nanos: u64,
    pub peak_rss_bytes: u64,
    pub stored_bytes: u64,
    pub fixture_commitment: [u8; 32],
    pub boot_identity_commitment: [u8; 32],
    pub returned_frame_count: u64,
    pub returned_plaintext_bytes: u64,
    pub expansion_latency_nanos: u64,
    pub thermal_state: QualificationThermalStateV2,
    pub frequency_throttled: bool,
    pub semantic: SemanticObservationV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationPairV2 {
    pub index: usize,
    pub order: M1TrialOrderV1,
    pub memory: QualificationArmObservationV2,
    pub durable: QualificationArmObservationV2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationRunV2 {
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub protocol: QualificationProtocolV2,
    pub environment: QualificationEnvironmentV2,
    pub semantic_baseline: SemanticObservationV1,
    pub durable_rss_hard_cap_bytes: u64,
    pub pairs: Vec<QualificationPairV2>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct BcaOneSidedBoundV2 {
    pub point: f64,
    pub bound: f64,
    pub confidence: f64,
    pub lower: bool,
    pub bias_correction: f64,
    pub acceleration: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QualificationRunReportV2 {
    pub scale: BenchmarkScaleV1,
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub metric: QualificationMetricV2,
    pub sampling_gate: GateDispositionV1,
    pub environment_gate: GateDispositionV1,
    pub thermal_gate: GateDispositionV1,
    pub semantic_gate: GateDispositionV1,
    pub throughput_lower_bound: Option<BcaOneSidedBoundV2>,
    pub latency_upper_bound: Option<BcaOneSidedBoundV2>,
    pub rss_upper_bound: BcaOneSidedBoundV2,
    pub performance_gate: GateDispositionV1,
    pub rss_gate: GateDispositionV1,
    pub overall: GateDispositionV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExpansionScalingReportV2 {
    pub provider: ProviderShapeV1,
    pub cache_state: BenchmarkCacheStateV1,
    pub returned_frame_count: u64,
    pub returned_plaintext_bytes: u64,
    pub total_record_ratio: f64,
    pub p95_latency_ratio_upper_bound: BcaOneSidedBoundV2,
    pub log_log_slope_point: f64,
    pub log_log_slope_upper_bound: f64,
    pub gate: GateDispositionV1,
}

#[must_use]
pub fn evaluate_qualification_run_v2(run: &QualificationRunV2) -> QualificationRunReportV2 {
    let sampling = run.protocol.valid()
        && run.pairs.len() == run.protocol.measured_pairs
        && schedule_matches(run);
    let environment = run.environment.dedicated_reference_host
        && run.environment.thermal_monitoring_available
        && run.environment.authority == AuthorityQualificationV2::ExternalTrustedRoot
        && matches!(
            (run.cache_state, run.environment.cache_qualification),
            (
                BenchmarkCacheStateV1::Cold,
                CacheQualificationV2::CleanBootPerArm
            ) | (
                BenchmarkCacheStateV1::Warm,
                CacheQualificationV2::WarmProcess
            )
        )
        && (run.cache_state != BenchmarkCacheStateV1::Cold || unique_boots(&run.pairs));
    let thermal = run.pairs.iter().all(|pair| {
        [pair.memory, pair.durable].into_iter().all(|arm| {
            arm.thermal_state == QualificationThermalStateV2::Nominal && !arm.frequency_throttled
        })
    });
    let semantic = run.pairs.iter().all(|pair| {
        pair.memory.semantic == run.semantic_baseline
            && pair.durable.semantic == run.semantic_baseline
            && pair.memory.fixture_commitment == pair.durable.fixture_commitment
            && pair.memory.returned_frame_count == pair.durable.returned_frame_count
            && pair.memory.returned_plaintext_bytes == pair.durable.returned_plaintext_bytes
            && pair.memory.elapsed_nanos > 0
            && pair.durable.elapsed_nanos > 0
            && pair.memory.peak_rss_bytes > 0
            && pair.durable.peak_rss_bytes > 0
            && pair.memory.stored_bytes == 0
            && pair.durable.stored_bytes > 0
    });
    let elapsed: Vec<_> = run
        .pairs
        .iter()
        .map(|pair| {
            (
                pair.memory.elapsed_nanos as f64,
                pair.durable.elapsed_nanos as f64,
            )
        })
        .collect();
    let rss: Vec<_> = run
        .pairs
        .iter()
        .map(|pair| {
            (
                pair.memory.peak_rss_bytes as f64,
                pair.durable.peak_rss_bytes as f64,
            )
        })
        .collect();
    let rss_bound = bca_bound(
        &rss,
        run.protocol.bca_resamples,
        run.protocol.randomization_seed ^ 0x5253_5302,
        false,
        mean_ratio,
    );
    let (throughput, latency, performance) = match run.protocol.metric {
        QualificationMetricV2::Throughput => {
            let bound = bca_bound(
                &elapsed,
                run.protocol.bca_resamples,
                run.protocol.randomization_seed ^ 0x5450_5402,
                true,
                mean_inverse_ratio,
            );
            (Some(bound), None, bound.bound >= 0.90)
        }
        QualificationMetricV2::Latency => {
            let absolute = run.scale == BenchmarkScaleV1::TenThousand;
            let statistic = if absolute {
                p95_difference as fn(&[(f64, f64)]) -> f64
            } else {
                p95_ratio
            };
            let bound = bca_bound(
                &elapsed,
                run.protocol.bca_resamples,
                run.protocol.randomization_seed ^ 0x4c41_5402,
                false,
                statistic,
            );
            (
                None,
                Some(bound),
                bound.bound <= if absolute { 20_000_000.0 } else { 1.10 },
            )
        }
    };
    let rss_ok = rss_bound.bound <= 1.15
        && run
            .pairs
            .iter()
            .all(|pair| pair.durable.peak_rss_bytes <= run.durable_rss_hard_cap_bytes);
    let base = sampling && environment && thermal && semantic;
    QualificationRunReportV2 {
        scale: run.scale,
        provider: run.provider,
        cache_state: run.cache_state,
        metric: run.protocol.metric,
        sampling_gate: gate(sampling),
        environment_gate: gate(environment),
        thermal_gate: gate(thermal),
        semantic_gate: gate(semantic),
        throughput_lower_bound: throughput,
        latency_upper_bound: latency,
        rss_upper_bound: rss_bound,
        performance_gate: gate(performance),
        rss_gate: gate(rss_ok),
        overall: gate(base && performance && rss_ok),
    }
}

#[must_use]
pub fn qualification_trial_orders_v2(protocol: QualificationProtocolV2) -> Vec<M1TrialOrderV1> {
    let mut random = Random::new(protocol.randomization_seed);
    let _ = orders(protocol.warmups, &mut random);
    orders(protocol.measured_pairs, &mut random)
}

#[must_use]
pub fn evaluate_expansion_scaling_v2(
    runs: &[QualificationRunV2],
) -> Option<ExpansionScalingReportV2> {
    let small = runs.iter().min_by_key(|run| run.scale.record_count())?;
    let large = runs.iter().max_by_key(|run| run.scale.record_count())?;
    let record_ratio = large.scale.record_count() as f64 / small.scale.record_count() as f64;
    if record_ratio < 10.0
        || small.provider != large.provider
        || small.cache_state != large.cache_state
        || small.protocol.metric != QualificationMetricV2::Latency
        || large.protocol.metric != QualificationMetricV2::Latency
        || small.pairs.len() != large.pairs.len()
    {
        return None;
    }
    let first = small.pairs.first()?.durable;
    if first.returned_frame_count == 0
        || first.returned_plaintext_bytes == 0
        || small.pairs.iter().chain(&large.pairs).any(|pair| {
            pair.durable.returned_frame_count != first.returned_frame_count
                || pair.durable.returned_plaintext_bytes != first.returned_plaintext_bytes
                || pair.durable.expansion_latency_nanos == 0
        })
    {
        return None;
    }
    let values: Vec<_> = small
        .pairs
        .iter()
        .zip(&large.pairs)
        .map(|(small, large)| {
            (
                small.durable.expansion_latency_nanos as f64,
                large.durable.expansion_latency_nanos as f64,
            )
        })
        .collect();
    let bound = bca_bound(
        &values,
        small
            .protocol
            .bca_resamples
            .min(large.protocol.bca_resamples),
        small.protocol.randomization_seed ^ large.protocol.randomization_seed ^ 0x4558_5002,
        false,
        p95_ratio,
    );
    Some(ExpansionScalingReportV2 {
        provider: small.provider,
        cache_state: small.cache_state,
        returned_frame_count: first.returned_frame_count,
        returned_plaintext_bytes: first.returned_plaintext_bytes,
        total_record_ratio: record_ratio,
        log_log_slope_point: bound.point.ln() / record_ratio.ln(),
        log_log_slope_upper_bound: bound.bound.ln() / record_ratio.ln(),
        gate: gate(bound.bound <= 1.10),
        p95_latency_ratio_upper_bound: bound,
    })
}

fn gate(value: bool) -> GateDispositionV1 {
    if value {
        GateDispositionV1::Pass
    } else {
        GateDispositionV1::Fail
    }
}

fn schedule_matches(run: &QualificationRunV2) -> bool {
    run.pairs
        .iter()
        .zip(qualification_trial_orders_v2(run.protocol))
        .enumerate()
        .all(|(index, (pair, order))| pair.index == index && pair.order == order)
}

fn unique_boots(pairs: &[QualificationPairV2]) -> bool {
    let mut values = BTreeSet::new();
    pairs.iter().all(|pair| {
        pair.memory.boot_identity_commitment != pair.durable.boot_identity_commitment
            && values.insert(pair.memory.boot_identity_commitment)
            && values.insert(pair.durable.boot_identity_commitment)
    })
}

fn mean_ratio(values: &[(f64, f64)]) -> f64 {
    values
        .iter()
        .map(|(memory, durable)| durable / memory)
        .sum::<f64>()
        / values.len() as f64
}
fn mean_inverse_ratio(values: &[(f64, f64)]) -> f64 {
    values
        .iter()
        .map(|(memory, durable)| memory / durable)
        .sum::<f64>()
        / values.len() as f64
}
fn p95_ratio(values: &[(f64, f64)]) -> f64 {
    let (memory, durable): (Vec<_>, Vec<_>) = values.iter().copied().unzip();
    percentile(durable, 0.95) / percentile(memory, 0.95)
}
fn p95_difference(values: &[(f64, f64)]) -> f64 {
    let (memory, durable): (Vec<_>, Vec<_>) = values.iter().copied().unzip();
    percentile(durable, 0.95) - percentile(memory, 0.95)
}

fn bca_bound(
    values: &[(f64, f64)],
    resamples: usize,
    seed: u64,
    lower: bool,
    statistic: fn(&[(f64, f64)]) -> f64,
) -> BcaOneSidedBoundV2 {
    if values.len() < 2 {
        return BcaOneSidedBoundV2 {
            point: 0.0,
            bound: if lower { 0.0 } else { f64::MAX },
            confidence: 0.95,
            lower,
            bias_correction: 0.0,
            acceleration: 0.0,
        };
    }
    let point = statistic(values);
    let mut random = Random::new(seed);
    let mut sample = Vec::with_capacity(values.len());
    let mut distribution = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        sample.clear();
        sample.extend((0..values.len()).map(|_| values[random.index(values.len())]));
        distribution.push(statistic(&sample));
    }
    let below = distribution.iter().filter(|value| **value < point).count();
    let z0 = inverse_normal(((below as f64) + 0.5) / ((resamples as f64) + 1.0));
    let jackknife: Vec<_> = (0..values.len())
        .map(|omitted| {
            let sample: Vec<_> = values
                .iter()
                .enumerate()
                .filter_map(|(index, value)| (index != omitted).then_some(*value))
                .collect();
            statistic(&sample)
        })
        .collect();
    let mean = jackknife.iter().sum::<f64>() / jackknife.len() as f64;
    let numerator = jackknife
        .iter()
        .map(|value| (mean - value).powi(3))
        .sum::<f64>();
    let denominator = 6.0
        * jackknife
            .iter()
            .map(|value| (mean - value).powi(2))
            .sum::<f64>()
            .powf(1.5);
    let acceleration = if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    };
    let z = inverse_normal(if lower { 0.05 } else { 0.95 });
    let adjusted = normal_cdf(z0 + (z0 + z) / (1.0 - acceleration * (z0 + z)));
    BcaOneSidedBoundV2 {
        point,
        bound: percentile(distribution, adjusted.clamp(0.0, 1.0)),
        confidence: 0.95,
        lower,
        bias_correction: z0,
        acceleration,
    }
}

fn percentile(mut values: Vec<f64>, quantile: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    values[((values.len() - 1) as f64 * quantile).round() as usize]
}

fn normal_cdf(value: f64) -> f64 {
    let x = value / 2.0_f64.sqrt();
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let poly = ((((1.061_405_429 * t - 1.453_152_027) * t + 1.421_413_741) * t - 0.284_496_736)
        * t
        + 0.254_829_592)
        * t;
    0.5 * (1.0 + sign * (1.0 - poly * (-x * x).exp()))
}

fn inverse_normal(p: f64) -> f64 {
    let p = p.clamp(1e-12, 1.0 - 1e-12);
    const C: [f64; 6] = [
        -0.00778489400243,
        -0.322396458041,
        -2.40075827716,
        -2.54973253934,
        4.37466414146,
        2.9381639827,
    ];
    const D: [f64; 4] = [
        0.00778469570904,
        0.32246712907,
        2.44513413714,
        3.75440866191,
    ];
    if p < 0.02425 {
        let q = (-2.0 * p.ln()).sqrt();
        return (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0);
    }
    if p > 0.97575 {
        return -inverse_normal(1.0 - p);
    }
    const A: [f64; 6] = [
        -39.6968302867,
        220.946098425,
        -275.928510447,
        138.357751867,
        -30.6647980661,
        2.50662827746,
    ];
    const B: [f64; 5] = [
        -54.4760987982,
        161.585836858,
        -155.69897986,
        66.8013118877,
        -13.2806815529,
    ];
    let q = p - 0.5;
    let r = q * q;
    (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
        / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
}

fn orders(count: usize, random: &mut Random) -> Vec<M1TrialOrderV1> {
    let mut values: Vec<_> = (0..count)
        .map(|index| {
            if index % 2 == 0 {
                M1TrialOrderV1::MemoryThenDurable
            } else {
                M1TrialOrderV1::DurableThenMemory
            }
        })
        .collect();
    for index in (1..values.len()).rev() {
        let swap = random.index(index + 1);
        values.swap(index, swap);
    }
    values
}

struct Random(u64);
impl Random {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x6a09_e667_f3bc_c909
        } else {
            seed
        })
    }
    fn index(&mut self, length: usize) -> usize {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        (value % length as u64) as usize
    }
}
