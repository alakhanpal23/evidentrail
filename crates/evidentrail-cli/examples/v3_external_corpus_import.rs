use std::error::Error;
use std::fs::File;
use std::path::Path;

use evidentrail_cli::import_external_adjudicated_corpus_v3;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let manifest = arguments
        .next()
        .ok_or("usage: v3_external_corpus_import <manifest.jsonl> <artifact-root>")?;
    let artifact_root = arguments.next().ok_or("missing artifact root")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let report =
        import_external_adjudicated_corpus_v3(File::open(manifest)?, Path::new(&artifact_root))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.certification_eligible {
        std::process::exit(2);
    }
    Ok(())
}
