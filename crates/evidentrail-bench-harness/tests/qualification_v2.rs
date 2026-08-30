use evidentrail_bench_harness::{
    AuthorityQualificationV2, BenchmarkCacheStateV1, BenchmarkScaleV1, CacheQualificationV2,
    GateDispositionV1, ProviderShapeV1, QualificationArmObservationV2, QualificationEnvironmentV2,
    QualificationPairV2, QualificationProtocolV2, QualificationRunV2, QualificationThermalStateV2,
    SemanticObservationV1, evaluate_expansion_scaling_v2, evaluate_qualification_run_v2,
    qualification_trial_orders_v2,
};

fn semantic() -> SemanticObservationV1 {
    SemanticObservationV1 {
        public_artifact_commitment: [1; 32],
        authorized_basis_commitment: [2; 32],
        authorized_basis_exact: true,
        reconciliation_failures: 0,
        protected_blocks_retained: 1,
        protected_blocks_required: 1,
        required_evidence_retained: 1,
        required_evidence_total: 1,
        correct_citations: 1,
        total_citations: 1,
        diagnosis_outcomes_correct: 1,
        diagnosis_outcomes_total: 1,
        fix_outcomes_correct: 1,
        fix_outcomes_total: 1,
        honest_abstentions: 0,
        required_abstentions: 0,
    }
}

fn environment(authority: AuthorityQualificationV2) -> QualificationEnvironmentV2 {
    QualificationEnvironmentV2 {
        manifest_commitment: [3; 32],
        host_identity_commitment: [4; 32],
        os_build_commitment: [5; 32],
        hardware_commitment: [6; 32],
        filesystem_commitment: [7; 32],
        executable_commitment: [8; 32],
        dedicated_reference_host: true,
        thermal_monitoring_available: true,
        authority,
        cache_qualification: CacheQualificationV2::WarmProcess,
    }
}

fn arm(index: usize, durable: bool, elapsed: u64) -> QualificationArmObservationV2 {
    let mut boot = [0u8; 32];
    boot[0] = (index * 2 + usize::from(durable)) as u8;
    QualificationArmObservationV2 {
        elapsed_nanos: elapsed,
        peak_rss_bytes: if durable { 105_000_000 } else { 100_000_000 },
        stored_bytes: if durable { 1_200_000 } else { 0 },
        fixture_commitment: [9; 32],
        boot_identity_commitment: boot,
        returned_frame_count: 2,
        returned_plaintext_bytes: 4096,
        expansion_latency_nanos: 1_000_000,
        thermal_state: QualificationThermalStateV2::Nominal,
        frequency_throttled: false,
        semantic: semantic(),
    }
}

fn run(protocol: QualificationProtocolV2, scale: BenchmarkScaleV1) -> QualificationRunV2 {
    let pairs = qualification_trial_orders_v2(protocol)
        .into_iter()
        .enumerate()
        .map(|(index, order)| QualificationPairV2 {
            index,
            order,
            memory: arm(index, false, 100_000_000),
            durable: arm(
                index,
                true,
                if scale == BenchmarkScaleV1::TenThousand {
                    110_000_000
                } else {
                    105_000_000
                },
            ),
        })
        .collect();
    QualificationRunV2 {
        scale,
        provider: ProviderShapeV1::LocalFile,
        cache_state: BenchmarkCacheStateV1::Warm,
        protocol,
        environment: environment(AuthorityQualificationV2::ExternalTrustedRoot),
        semantic_baseline: semantic(),
        durable_rss_hard_cap_bytes: 120_000_000,
        pairs,
    }
}

#[test]
fn throughput_uses_one_sided_paired_bca_and_rejects_process_authority() {
    let mut run = run(
        QualificationProtocolV2::throughput(71),
        BenchmarkScaleV1::OneMillion,
    );
    let report = evaluate_qualification_run_v2(&run);
    assert_eq!(report.overall, GateDispositionV1::Pass);
    let bound = report.throughput_lower_bound.unwrap();
    assert!(bound.lower && bound.bound >= 0.90);
    assert_eq!(bound.confidence, 0.95);
    assert!(report.rss_upper_bound.bound <= 1.15);

    run.environment.authority = AuthorityQualificationV2::ProcessConformanceOnly;
    let ineligible = evaluate_qualification_run_v2(&run);
    assert_eq!(ineligible.environment_gate, GateDispositionV1::Fail);
    assert_eq!(ineligible.overall, GateDispositionV1::Fail);
}

#[test]
fn latency_requires_two_hundred_pairs_and_thermal_validity() {
    let mut run = run(
        QualificationProtocolV2::latency(91),
        BenchmarkScaleV1::TenThousand,
    );
    let report = evaluate_qualification_run_v2(&run);
    assert_eq!(run.pairs.len(), 200);
    assert_eq!(report.overall, GateDispositionV1::Pass);
    let bound = report.latency_upper_bound.unwrap();
    assert!(!bound.lower && bound.bound <= 20_000_000.0);

    run.pairs[17].durable.thermal_state = QualificationThermalStateV2::Serious;
    let invalid = evaluate_qualification_run_v2(&run);
    assert_eq!(invalid.thermal_gate, GateDispositionV1::Fail);
    assert_eq!(invalid.overall, GateDispositionV1::Fail);
}

#[test]
fn expansion_scaling_bounds_total_size_slope_at_equal_frame_shape() {
    let small = run(
        QualificationProtocolV2::latency(101),
        BenchmarkScaleV1::TenThousand,
    );
    let mut large = run(
        QualificationProtocolV2::latency(101),
        BenchmarkScaleV1::OneMillion,
    );
    for pair in &mut large.pairs {
        pair.durable.expansion_latency_nanos = 1_050_000;
    }
    let report = evaluate_expansion_scaling_v2(&[small, large]).unwrap();
    assert_eq!(report.gate, GateDispositionV1::Pass);
    assert_eq!(report.total_record_ratio, 100.0);
    assert!(report.p95_latency_ratio_upper_bound.bound <= 1.10);
    assert!(report.log_log_slope_upper_bound < 0.025);
}
