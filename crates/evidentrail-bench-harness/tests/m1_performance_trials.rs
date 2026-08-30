use evidentrail_bench_harness::{
    ArmMeasurementV1, BenchmarkArmV1, BenchmarkCacheStateV1, BenchmarkPhaseV1, BenchmarkScaleV1,
    CompletenessExpectationV1, ExpansionMeasurementV1, GateDispositionV1,
    M1_MEASURED_OBSERVATIONS_V1, M1PairedRunConfigV1, M1PairedRunV1, M1PerformanceErrorV1,
    M1TrialOrderV1, ProviderFixtureStreamV1, ProviderShapeV1, SemanticObservationV1,
    evaluate_m1_performance_suite_v1, freeze_memory_baseline_v1, provider_fixture_commitment_v1,
    run_m1_paired_trials_v1,
};

fn semantic() -> SemanticObservationV1 {
    SemanticObservationV1 {
        public_artifact_commitment: [0x11; 32],
        authorized_basis_commitment: [0x22; 32],
        authorized_basis_exact: true,
        reconciliation_failures: 0,
        protected_blocks_retained: 3,
        protected_blocks_required: 3,
        required_evidence_retained: 7,
        required_evidence_total: 7,
        correct_citations: 4,
        total_citations: 4,
        diagnosis_outcomes_correct: 2,
        diagnosis_outcomes_total: 2,
        fix_outcomes_correct: 2,
        fix_outcomes_total: 2,
        honest_abstentions: 1,
        required_abstentions: 1,
    }
}

fn config(
    scale: BenchmarkScaleV1,
    provider: ProviderShapeV1,
    cache_state: BenchmarkCacheStateV1,
) -> M1PairedRunConfigV1 {
    let fixture_commitment = provider_fixture_commitment_v1(provider, scale, 73);
    let baseline = freeze_memory_baseline_v1(fixture_commitment, [0x33; 32], semantic()).unwrap();
    M1PairedRunConfigV1 {
        scale,
        provider,
        cache_state,
        fixture_seed: 73,
        randomization_seed: 991,
        warmup_observations: 5,
        measured_observations: M1_MEASURED_OBSERVATIONS_V1,
        bootstrap_resamples: 2_000,
        durable_rss_hard_cap_bytes: 200_000_000,
        baseline,
    }
}

fn measurement(
    arm: BenchmarkArmV1,
    scale: BenchmarkScaleV1,
    elapsed_nanos: u64,
    expansion_latency_nanos: u64,
) -> ArmMeasurementV1 {
    ArmMeasurementV1 {
        elapsed_nanos,
        record_count: scale.record_count(),
        authorized_source_bytes: 1_000_000,
        peak_rss_bytes: match arm {
            BenchmarkArmV1::MemoryOnly => 100_000_000,
            BenchmarkArmV1::Durable => 105_000_000,
        },
        stored_bytes: match arm {
            BenchmarkArmV1::MemoryOnly => 0,
            BenchmarkArmV1::Durable => 1_200_000,
        },
        completeness: CompletenessExpectationV1::Complete,
        semantic: semantic(),
        expansion: Some(ExpansionMeasurementV1 {
            total_result_records: scale.record_count(),
            returned_frame_count: 2,
            returned_plaintext_bytes: 4_096,
            latency_nanos: expansion_latency_nanos,
        }),
    }
}

#[test]
fn runner_preregisters_warmups_balances_order_and_rejects_semantic_drift() {
    let config = config(
        BenchmarkScaleV1::TenThousand,
        ProviderShapeV1::LocalFile,
        BenchmarkCacheStateV1::Cold,
    );
    let mut requests = Vec::new();
    let run = run_m1_paired_trials_v1(config, |request| {
        requests.push((request.phase, request.arm));
        let elapsed = match request.arm {
            BenchmarkArmV1::MemoryOnly => 100_000_000,
            BenchmarkArmV1::Durable => 110_000_000,
        };
        let mut observed = measurement(request.arm, request.scale, elapsed, 1_000_000);
        observed.completeness = CompletenessExpectationV1::Complete;
        Ok(observed)
    })
    .unwrap();

    assert_eq!(requests.len(), (5 + 30) * 2);
    assert_eq!(
        requests
            .iter()
            .filter(|(phase, _)| *phase == BenchmarkPhaseV1::Warmup)
            .count(),
        10
    );
    assert_eq!(run.observations.len(), 30);
    assert_eq!(
        run.observations
            .iter()
            .filter(|trial| trial.order == M1TrialOrderV1::MemoryThenDurable)
            .count(),
        15
    );

    let error = run_m1_paired_trials_v1(config, |request| {
        let mut observed = measurement(request.arm, request.scale, 100_000_000, 1_000_000);
        if request.arm == BenchmarkArmV1::Durable {
            observed.semantic.public_artifact_commitment[0] ^= 1;
        }
        observed.completeness = CompletenessExpectationV1::Complete;
        Ok(observed)
    })
    .unwrap_err();
    assert_eq!(error, M1PerformanceErrorV1::SemanticRegression);
}

#[test]
fn provider_streams_bind_identity_order_completeness_and_hostile_bytes() {
    let local = ProviderFixtureStreamV1::new(ProviderShapeV1::LocalFile, 6, 9).collect::<Vec<_>>();
    assert_eq!(local[0].payload, [0xff, 0xfe, b'X', 0, b'Y']);
    assert_eq!(local[0].terminator, b"\r\n");
    assert!(local[1].payload.is_empty());
    assert_eq!(local[2].payload, local[3].payload);
    assert_ne!(local[2].native_identity, local[3].native_identity);
    assert!(local[4].payload.contains(&0));
    assert!(local[5].terminator.is_empty());

    assert_eq!(
        ProviderFixtureStreamV1::new(ProviderShapeV1::LocalFile, 1, 9).completeness_expectation(),
        CompletenessExpectationV1::Complete
    );
    for provider in [ProviderShapeV1::CloudWatch, ProviderShapeV1::Kubernetes] {
        let mut stream = ProviderFixtureStreamV1::new(provider, 2, 9);
        assert_eq!(
            stream.completeness_expectation(),
            CompletenessExpectationV1::Unknown
        );
        let first = stream.next().unwrap();
        let second = stream.next().unwrap();
        assert_ne!(first.native_identity, second.native_identity);
        assert_ne!(first.acquisition_ordinal, second.acquisition_ordinal);
        assert!(!first.canonical_order_key.is_empty());
        assert!(first.canonical_order_key > second.canonical_order_key);
    }
    assert_ne!(
        provider_fixture_commitment_v1(
            ProviderShapeV1::CloudWatch,
            BenchmarkScaleV1::TenThousand,
            1
        ),
        provider_fixture_commitment_v1(
            ProviderShapeV1::CloudWatch,
            BenchmarkScaleV1::TenThousand,
            2
        )
    );
}

fn fake_run(
    scale: BenchmarkScaleV1,
    provider: ProviderShapeV1,
    cache_state: BenchmarkCacheStateV1,
) -> M1PairedRunV1 {
    let config = config(scale, provider, cache_state);
    let (memory_elapsed, durable_elapsed) = match scale {
        BenchmarkScaleV1::TenThousand => (100_000_000, 110_000_000),
        BenchmarkScaleV1::OneHundredThousand | BenchmarkScaleV1::OneMillion => {
            (100_000_000, 105_000_000)
        }
    };
    let expansion_latency = if scale == BenchmarkScaleV1::OneMillion {
        1_050_000
    } else {
        1_000_000
    };
    run_m1_paired_trials_v1(config, |request| {
        let elapsed = match request.arm {
            BenchmarkArmV1::MemoryOnly => memory_elapsed,
            BenchmarkArmV1::Durable => durable_elapsed,
        };
        let mut value = measurement(request.arm, scale, elapsed, expansion_latency);
        value.completeness = match provider {
            ProviderShapeV1::LocalFile => CompletenessExpectationV1::Complete,
            ProviderShapeV1::CloudWatch | ProviderShapeV1::Kubernetes => {
                CompletenessExpectationV1::Unknown
            }
        };
        Ok(value)
    })
    .unwrap()
}

fn complete_matrix() -> Vec<M1PairedRunV1> {
    let mut runs = Vec::new();
    for provider in [
        ProviderShapeV1::LocalFile,
        ProviderShapeV1::CloudWatch,
        ProviderShapeV1::Kubernetes,
    ] {
        for scale in [
            BenchmarkScaleV1::TenThousand,
            BenchmarkScaleV1::OneHundredThousand,
            BenchmarkScaleV1::OneMillion,
        ] {
            for cache in [BenchmarkCacheStateV1::Cold, BenchmarkCacheStateV1::Warm] {
                runs.push(fake_run(scale, provider, cache));
            }
        }
    }
    runs
}

#[test]
fn suite_enforces_confidence_gates_full_matrix_worst_slices_and_random_access() {
    let mut runs = complete_matrix();
    let report = evaluate_m1_performance_suite_v1(&runs);
    assert_eq!(report.overall, GateDispositionV1::Pass);
    assert_eq!(report.expansion_scale_independence, GateDispositionV1::Pass);
    assert!(report.expansion_scale_ratio.unwrap().upper <= 1.10);
    assert!(report.worst_throughput_slice.is_some());
    assert!(report.worst_latency_slice.is_some());
    assert!(report.worst_rss_slice.is_some());
    assert_eq!(report.reports.len(), 18);
    assert!(report.reports.iter().all(|slice| {
        slice.sampling_gate == GateDispositionV1::Pass
            && slice.semantic_exactness == GateDispositionV1::Pass
            && slice.latency_gate == GateDispositionV1::Pass
            && slice.rss_gate == GateDispositionV1::Pass
    }));

    runs[0].observations.pop();
    let underpowered = evaluate_m1_performance_suite_v1(&runs);
    assert_eq!(underpowered.overall, GateDispositionV1::Fail);
    assert_eq!(
        underpowered.reports[0].sampling_gate,
        GateDispositionV1::Fail
    );

    let mut regressed = complete_matrix();
    for observation in &mut regressed[2].observations {
        observation.durable.elapsed_nanos = 125_000_000;
    }
    let failed = evaluate_m1_performance_suite_v1(&regressed);
    assert_eq!(failed.overall, GateDispositionV1::Fail);
    assert_eq!(failed.reports[2].throughput_gate, GateDispositionV1::Fail);
    assert_eq!(failed.reports[2].latency_gate, GateDispositionV1::Fail);

    let json = serde_json::to_vec_pretty(&report).unwrap();
    assert!(json.starts_with(b"{"));
    assert!(!json.windows(3).any(|window| window == b"NaN"));
}

#[test]
fn malformed_baseline_commitment_and_short_protocol_are_rejected() {
    let mut invalid = config(
        BenchmarkScaleV1::TenThousand,
        ProviderShapeV1::LocalFile,
        BenchmarkCacheStateV1::Warm,
    );
    invalid.baseline.baseline_commitment[0] ^= 1;
    assert_eq!(
        invalid.validate().unwrap_err(),
        M1PerformanceErrorV1::SemanticRegression
    );

    let mut short = config(
        BenchmarkScaleV1::TenThousand,
        ProviderShapeV1::LocalFile,
        BenchmarkCacheStateV1::Warm,
    );
    short.measured_observations = 29;
    assert_eq!(
        short.validate().unwrap_err(),
        M1PerformanceErrorV1::InsufficientMeasuredObservations
    );

    let cloudwatch = config(
        BenchmarkScaleV1::TenThousand,
        ProviderShapeV1::CloudWatch,
        BenchmarkCacheStateV1::Warm,
    );
    let incorrect_complete = run_m1_paired_trials_v1(cloudwatch, |request| {
        Ok(measurement(
            request.arm,
            request.scale,
            100_000_000,
            1_000_000,
        ))
    })
    .unwrap_err();
    assert_eq!(incorrect_complete, M1PerformanceErrorV1::InvalidMeasurement);

    let empty = evaluate_m1_performance_suite_v1(&[]);
    assert_eq!(empty.overall, GateDispositionV1::Fail);
    assert_eq!(
        empty.expansion_scale_independence,
        GateDispositionV1::NotMeasured
    );
}
