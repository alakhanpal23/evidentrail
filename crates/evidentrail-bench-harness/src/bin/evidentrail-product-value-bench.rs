use std::process::ExitCode;

use evidentrail_bench_harness::build_product_value_report_v1;

fn main() -> ExitCode {
    match build_product_value_report_v1() {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("EVIDENTRAIL_PRODUCT_VALUE_ERROR serialization");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("EVIDENTRAIL_PRODUCT_VALUE_ERROR {}", error.code());
            ExitCode::from(2)
        }
    }
}
