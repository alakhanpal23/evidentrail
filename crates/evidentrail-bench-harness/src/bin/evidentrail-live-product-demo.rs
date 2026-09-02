use std::path::PathBuf;
use std::process::ExitCode;

use evidentrail_bench_harness::{
    OpenAiHostedDiagnosisReaderV1, hosted_product_demo_configuration_digest_v1,
    run_live_product_demo_v1,
};
use evidentrail_cli::HOSTED_RANKING_LATENCY_CHALLENGER_MODEL_V1;

fn main() -> ExitCode {
    if std::env::var_os("EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return fail_v1("synthetic_authorization_not_enabled");
    }
    let current = match std::env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(path) => path,
        Err(_) => return fail_v1("current_executable"),
    };
    let Some(directory) = current.parent() else {
        return fail_v1("current_executable_parent");
    };
    let helper = directory.join(helper_name_v1());
    let working_directory = match std::env::current_dir().and_then(|path| path.canonicalize()) {
        Ok(path) => path,
        Err(_) => return fail_v1("working_directory"),
    };
    let mut reader = OpenAiHostedDiagnosisReaderV1::for_product_demo_v1();
    match run_live_product_demo_v1(
        &mut reader,
        hosted_product_demo_configuration_digest_v1(),
        HOSTED_RANKING_LATENCY_CHALLENGER_MODEL_V1,
        &helper,
        &working_directory,
    ) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(encoded) => {
                let success = report.live_value_indication_supported();
                println!("{encoded}");
                if success {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(_) => fail_v1("serialization"),
        },
        Err(error) => fail_v1(error.code()),
    }
}

fn helper_name_v1() -> PathBuf {
    PathBuf::from(if cfg!(windows) {
        "evidentrail-bench-harness-helper.exe"
    } else {
        "evidentrail-bench-harness-helper"
    })
}

fn fail_v1(code: &str) -> ExitCode {
    eprintln!("EVIDENTRAIL_LIVE_PRODUCT_DEMO_ERROR {code}");
    ExitCode::from(2)
}
