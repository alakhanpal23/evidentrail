use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_MANIFEST_LINE_BYTES_V3: usize = 1024 * 1024;
const MAX_CITATION_BYTES_V3: u64 = 16 * 1024 * 1024;
const MIN_CERTIFICATION_CASES_V3: usize = 50;
const MIN_CERTIFICATION_ORGANIZATIONS_V3: usize = 5;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCaseV3 {
    schema_version: u16,
    case_id: String,
    organization_id: String,
    project_id: String,
    family_id: String,
    split: String,
    question: String,
    artifact: CorpusArtifactV3,
    adjudication: CorpusAdjudicationV3,
    requirements: Vec<CorpusRequirementV3>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusArtifactV3 {
    relative_path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusAdjudicationV3 {
    annotator_ids: [String; 2],
    adjudicator_id: String,
    independently_adjudicated: bool,
    consent_or_license_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusRequirementV3 {
    requirement_id: String,
    alternatives: Vec<Vec<CorpusCitationV3>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCitationV3 {
    start_byte: u64,
    end_byte: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalCorpusImportReportV3 {
    pub schema_version: u16,
    pub case_count: usize,
    pub organization_count: usize,
    pub requirement_count: usize,
    pub citation_count: usize,
    pub certification_eligible: bool,
    pub qualification_blockers: Vec<String>,
    pub corpus_digest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalCorpusImportErrorV3 {
    line: usize,
    code: &'static str,
}

impl ExternalCorpusImportErrorV3 {
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ExternalCorpusImportErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at manifest line {}", self.code, self.line)
    }
}

impl StdError for ExternalCorpusImportErrorV3 {}

/// Verify and import an independently adjudicated JSONL corpus manifest.
///
/// Source artifacts remain external. Every artifact and citation is read by
/// an exact byte range and checked against its declared SHA-256 digest; paths
/// cannot escape the canonical artifact root or traverse symlinks outside it.
pub fn import_external_adjudicated_corpus_v3(
    manifest: impl Read,
    artifact_root: &Path,
) -> Result<ExternalCorpusImportReportV3, ExternalCorpusImportErrorV3> {
    let canonical_root = artifact_root
        .canonicalize()
        .map_err(|_| error(0, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_ROOT"))?;
    let mut cases = BTreeSet::new();
    let mut organizations = BTreeSet::new();
    let mut family_splits = BTreeMap::<(String, String, String), String>::new();
    let mut requirement_count = 0usize;
    let mut citation_count = 0usize;
    let mut corpus = Sha256::new();
    corpus.update(b"evidentrail/external-adjudicated-corpus/v3\0");
    for (offset, line) in BufReader::new(manifest).split(b'\n').enumerate() {
        let line_number = offset + 1;
        let line = line.map_err(|_| error(line_number, "EVIDENTRAIL_CORPUS_V3_MANIFEST_READ"))?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_MANIFEST_LINE_BYTES_V3 {
            return Err(error(
                line_number,
                "EVIDENTRAIL_CORPUS_V3_MANIFEST_LINE_CAP",
            ));
        }
        let case: CorpusCaseV3 = serde_json::from_slice(&line)
            .map_err(|_| error(line_number, "EVIDENTRAIL_CORPUS_V3_MANIFEST_SCHEMA"))?;
        validate_case_v3(&case, line_number)?;
        if !cases.insert(case.case_id.clone()) {
            return Err(error(line_number, "EVIDENTRAIL_CORPUS_V3_DUPLICATE_CASE"));
        }
        organizations.insert(case.organization_id.clone());
        let family = (
            case.organization_id.clone(),
            case.project_id.clone(),
            case.family_id.clone(),
        );
        if family_splits
            .insert(family, case.split.clone())
            .is_some_and(|split| split != case.split)
        {
            return Err(error(
                line_number,
                "EVIDENTRAIL_CORPUS_V3_FAMILY_SPLIT_LEAKAGE",
            ));
        }
        let relative = Path::new(&case.artifact.relative_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(error(
                line_number,
                "EVIDENTRAIL_CORPUS_V3_UNSAFE_ARTIFACT_PATH",
            ));
        }
        let artifact = canonical_root
            .join(relative)
            .canonicalize()
            .map_err(|_| error(line_number, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_MISSING"))?;
        if !artifact.starts_with(&canonical_root) || !artifact.is_file() {
            return Err(error(
                line_number,
                "EVIDENTRAIL_CORPUS_V3_UNSAFE_ARTIFACT_PATH",
            ));
        }
        let artifact_digest = hash_file_v3(&artifact, line_number)?;
        if artifact_digest != parse_digest_v3(&case.artifact.sha256, line_number)? {
            return Err(error(line_number, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_DIGEST"));
        }
        let artifact_len = artifact
            .metadata()
            .map_err(|_| error(line_number, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?
            .len();
        let mut file = File::open(&artifact)
            .map_err(|_| error(line_number, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?;
        for requirement in &case.requirements {
            requirement_count += 1;
            for alternative in &requirement.alternatives {
                for citation in alternative {
                    citation_count += 1;
                    verify_citation_v3(&mut file, artifact_len, citation, line_number)?;
                }
            }
        }
        corpus.update((line.len() as u64).to_be_bytes());
        corpus.update(Sha256::digest(&line));
        corpus.update(artifact_digest);
    }
    if cases.is_empty() {
        return Err(error(0, "EVIDENTRAIL_CORPUS_V3_EMPTY"));
    }
    let mut blockers = Vec::new();
    if cases.len() < MIN_CERTIFICATION_CASES_V3 {
        blockers.push(format!(
            "requires at least {MIN_CERTIFICATION_CASES_V3} independently adjudicated incidents"
        ));
    }
    if organizations.len() < MIN_CERTIFICATION_ORGANIZATIONS_V3 {
        blockers.push(format!(
            "requires at least {MIN_CERTIFICATION_ORGANIZATIONS_V3} organizations"
        ));
    }
    Ok(ExternalCorpusImportReportV3 {
        schema_version: 3,
        case_count: cases.len(),
        organization_count: organizations.len(),
        requirement_count,
        citation_count,
        certification_eligible: blockers.is_empty(),
        qualification_blockers: blockers,
        corpus_digest_sha256: hex_v3(&corpus.finalize()),
    })
}

fn validate_case_v3(case: &CorpusCaseV3, line: usize) -> Result<(), ExternalCorpusImportErrorV3> {
    let nonempty = [
        &case.case_id,
        &case.organization_id,
        &case.project_id,
        &case.family_id,
        &case.split,
        &case.question,
        &case.adjudication.annotator_ids[0],
        &case.adjudication.annotator_ids[1],
        &case.adjudication.adjudicator_id,
        &case.adjudication.consent_or_license_id,
    ];
    if case.schema_version != 3 || nonempty.iter().any(|value| value.trim().is_empty()) {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_INVALID_CASE"));
    }
    if !case.adjudication.independently_adjudicated
        || case.adjudication.annotator_ids[0] == case.adjudication.annotator_ids[1]
        || case
            .adjudication
            .annotator_ids
            .contains(&case.adjudication.adjudicator_id)
    {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_ADJUDICATION"));
    }
    if case.requirements.is_empty()
        || case.requirements.iter().any(|requirement| {
            requirement.requirement_id.trim().is_empty()
                || requirement.alternatives.is_empty()
                || requirement
                    .alternatives
                    .iter()
                    .any(|alternative| alternative.is_empty())
        })
    {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_REQUIREMENTS"));
    }
    Ok(())
}

fn verify_citation_v3(
    file: &mut File,
    artifact_len: u64,
    citation: &CorpusCitationV3,
    line: usize,
) -> Result<(), ExternalCorpusImportErrorV3> {
    let length = citation
        .end_byte
        .checked_sub(citation.start_byte)
        .ok_or_else(|| error(line, "EVIDENTRAIL_CORPUS_V3_CITATION_RANGE"))?;
    if length == 0 || length > MAX_CITATION_BYTES_V3 || citation.end_byte > artifact_len {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_CITATION_RANGE"));
    }
    file.seek(SeekFrom::Start(citation.start_byte))
        .map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?;
    let mut bounded = file.take(length);
    let mut hasher = Sha256::new();
    std::io::copy(&mut bounded, &mut HashWriterV3(&mut hasher))
        .map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?;
    if hasher.finalize().as_slice() != parse_digest_v3(&citation.sha256, line)? {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_CITATION_DIGEST"));
    }
    Ok(())
}

struct HashWriterV3<'a>(&'a mut Sha256);

impl std::io::Write for HashWriterV3<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hash_file_v3(path: &Path, line: usize) -> Result<[u8; 32], ExternalCorpusImportErrorV3> {
    let mut file =
        File::open(path).map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut HashWriterV3(&mut hasher))
        .map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_ARTIFACT_READ"))?;
    Ok(hasher.finalize().into())
}

fn parse_digest_v3(value: &str, line: usize) -> Result<[u8; 32], ExternalCorpusImportErrorV3> {
    if value.len() != 64 {
        return Err(error(line, "EVIDENTRAIL_CORPUS_V3_DIGEST_ENCODING"));
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_DIGEST_ENCODING"))?;
        output[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| error(line, "EVIDENTRAIL_CORPUS_V3_DIGEST_ENCODING"))?;
    }
    Ok(output)
}

fn hex_v3(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn error(line: usize, code: &'static str) -> ExternalCorpusImportErrorV3 {
    ExternalCorpusImportErrorV3 { line, code }
}
