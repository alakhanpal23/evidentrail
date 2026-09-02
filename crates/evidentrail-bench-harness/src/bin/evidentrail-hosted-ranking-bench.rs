use std::env;
use std::process::ExitCode;

use evidentrail_bench_harness::{
    HostedRankingBenchmarkPhaseV1, HostedRankingLatencyCharacterizationReportV1,
    HostedRankingQualificationReportV1, OpenAiHostedDiagnosisReaderV1,
    run_hosted_ranking_latency_challenger_v1, run_hosted_ranking_latency_characterization_v1,
    run_hosted_ranking_measurement_pilot_v2, run_hosted_ranking_qualification_phase_v1,
    run_hosted_ranking_qualification_phase_with_reader_v1,
};
use evidentrail_cli::OpenAiEvidenceRankerV1;
use serde::Serialize;

#[derive(Serialize)]
struct RunReportV1 {
    schema_version: u16,
    mode: &'static str,
    scored_skipped_reason: Option<&'static str>,
    pilot: HostedRankingQualificationReportV1,
    scored: Option<HostedRankingQualificationReportV1>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CommandReportV1 {
    Qualification(Box<RunReportV1>),
    Characterization(Box<HostedRankingLatencyCharacterizationReportV1>),
}

fn main() -> ExitCode {
    match run() {
        Ok((report, success)) => {
            let encoded = serde_json::to_string(&report)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_owned());
            println!("{encoded}");
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(code) => {
            eprintln!("EVIDENTRAIL_HOSTED_BENCH_ERROR {code}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(CommandReportV1, bool), &'static str> {
    if env::var_os("EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Err("synthetic_authorization_not_enabled");
    }
    if env::var_os("EVIDENTRAIL_HOSTED_RANKING_SHADOW").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Err("shadow_mode_not_enabled");
    }
    // Mode is deliberately mandatory: a truncated command must never default
    // to an 18-call paid pilot.
    let mode = env::args()
        .nth(1)
        .ok_or("usage_measure_pilot_qualify_characterize_or_challenge_latency")?;
    if mode != "measure"
        && mode != "pilot"
        && mode != "qualify"
        && mode != "characterize"
        && mode != "challenge-latency"
    {
        return Err("usage_measure_pilot_qualify_characterize_or_challenge_latency");
    }
    if mode == "measure" {
        let mut ranker = OpenAiEvidenceRankerV1::for_evaluation_measurement_v2();
        let pilot =
            run_hosted_ranking_measurement_pilot_v2(&mut ranker).map_err(|error| error.code())?;
        let success = pilot.measurement_completed();
        return Ok((
            CommandReportV1::Qualification(Box::new(RunReportV1 {
                schema_version: 1,
                mode: "measure",
                scored_skipped_reason: Some("measurement_only_no_admission"),
                pilot,
                scored: None,
            })),
            success,
        ));
    }
    if mode == "characterize" {
        let mut ranker = OpenAiEvidenceRankerV1::for_nonqualifying_latency_characterization_v1();
        let report = run_hosted_ranking_latency_characterization_v1(&mut ranker)
            .map_err(|error| error.code())?;
        let completed = report.completed();
        return Ok((
            CommandReportV1::Characterization(Box::new(report)),
            completed,
        ));
    }
    if mode == "challenge-latency" {
        let mut ranker = OpenAiEvidenceRankerV1::for_nonqualifying_latency_challenger_v1();
        let report =
            run_hosted_ranking_latency_challenger_v1(&mut ranker).map_err(|error| error.code())?;
        let completed = report.completed() && report.observed_within_production_deadline();
        return Ok((
            CommandReportV1::Characterization(Box::new(report)),
            completed,
        ));
    }
    let mut ranker = OpenAiEvidenceRankerV1::from_environment();
    let pilot = run_hosted_ranking_qualification_phase_v1(
        HostedRankingBenchmarkPhaseV1::Pilot,
        &mut ranker,
    )
    .map_err(|error| error.code())?;
    if mode == "pilot" {
        let success = pilot.operational_pilot_passed();
        return Ok((
            CommandReportV1::Qualification(Box::new(RunReportV1 {
                schema_version: 1,
                mode: "pilot",
                scored_skipped_reason: Some("pilot_only"),
                pilot,
                scored: None,
            })),
            success,
        ));
    }
    if !pilot.operational_pilot_passed() {
        return Ok((
            CommandReportV1::Qualification(Box::new(RunReportV1 {
                schema_version: 1,
                mode: "qualify",
                scored_skipped_reason: Some("pilot_operational_gate_failed"),
                pilot,
                scored: None,
            })),
            false,
        ));
    }
    let mut reader = OpenAiHostedDiagnosisReaderV1::from_environment();
    let scored = run_hosted_ranking_qualification_phase_with_reader_v1(
        HostedRankingBenchmarkPhaseV1::Scored,
        &mut ranker,
        &mut reader,
    )
    .map_err(|error| error.code())?;
    let success = scored.qualification_passed();
    Ok((
        CommandReportV1::Qualification(Box::new(RunReportV1 {
            schema_version: 1,
            mode: "qualify",
            scored_skipped_reason: None,
            pilot,
            scored: Some(scored),
        })),
        success,
    ))
}
