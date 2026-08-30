use std::env;
use std::fs;
use std::path::Path;

use evidentrail_wire::{golden_documents_v1, schema_documents_v1};

fn main() {
    let mode = env::args().nth(1).unwrap_or_default();
    let documents = schema_documents_v1()
        .expect("EVIDENTRAIL_WIRE_SCHEMA_GENERATION_FAILED")
        .into_iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .chain(golden_documents_v1().expect("EVIDENTRAIL_WIRE_GOLDEN_GENERATION_FAILED"))
        .collect::<Vec<_>>();
    let result = match mode.as_str() {
        "--write" => write_documents(&documents),
        "--check" => check_documents(&documents),
        _ => Err("EVIDENTRAIL_WIRE_SCHEMA_USAGE"),
    };
    if let Err(code) = result {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

fn write_documents(documents: &[(String, Vec<u8>)]) -> Result<(), &'static str> {
    for (path, bytes) in documents {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|_| "EVIDENTRAIL_WIRE_SCHEMA_WRITE_FAILED")?;
        }
        fs::write(path, bytes).map_err(|_| "EVIDENTRAIL_WIRE_SCHEMA_WRITE_FAILED")?;
    }
    Ok(())
}

fn check_documents(documents: &[(String, Vec<u8>)]) -> Result<(), &'static str> {
    for (path, expected) in documents {
        let actual = fs::read(path).map_err(|_| "EVIDENTRAIL_WIRE_SCHEMA_CHECK_FAILED")?;
        if actual != *expected {
            return Err("EVIDENTRAIL_WIRE_SCHEMA_CHECK_FAILED");
        }
    }
    Ok(())
}
