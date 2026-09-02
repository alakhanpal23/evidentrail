use std::path::PathBuf;
use std::process::ExitCode;

use evidentrail_bench_harness::run_executable_value_report_v1;

fn main() -> ExitCode {
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
    match run_executable_value_report_v1(&helper, &working_directory) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
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
    eprintln!("EVIDENTRAIL_EXECUTABLE_VALUE_ERROR {code}");
    ExitCode::from(2)
}
