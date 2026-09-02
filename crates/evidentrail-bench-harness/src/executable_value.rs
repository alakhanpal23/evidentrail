//! Executable, contentless outcome report for the three frozen synthetic fault
//! families. A deterministic fixture agent reads each matched-budget artifact,
//! proposes a patch, and an independent verifier checks the repaired invariant.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{
    ClosedEnvironmentV1, ExecutableBuildV1, ExecutableIncidentCaseV1, ExternalOutputContractV1,
    GovernedIncidentTruthV1, HarnessLimitsV1, IncidentAgentCapsV1, IncidentArmDecisionV1,
    IncidentArmKindV1, IncidentExitExpectationV1, IncidentLogStreamV1, IncidentVerifierCapsV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1, evaluate_governed_incident_v1,
    execute_incident_agent_v1, execute_incident_verifier_v1, freeze_executable_incident_v1,
    prepare_incident_method_arms_v1,
};

pub const EXECUTABLE_VALUE_REPORT_SCHEMA_VERSION_V1: u16 = 1;
pub(crate) const ARM_BUDGET_V1: u64 = 7_000;
pub(crate) const SCENARIOS_V1: [(&str, &[u8], i32, &str); 3] = [
    (
        "db-pool-zero",
        b"Why did the request exhaust the database pool after deploy?",
        23,
        "db_pool_size_zero",
    ),
    (
        "migration-drift",
        b"Why did the request fail with a missing column after deploy?",
        24,
        "migration_43_omitted",
    ),
    (
        "upstream-timeout",
        b"Why did the request time out after the gateway configuration change?",
        25,
        "upstream_timeout_too_low",
    ),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutableValueArmSummaryV1 {
    arm: &'static str,
    case_count: u64,
    task_success_count: u64,
    cause_verified_count: u64,
    citation_valid_case_count: u64,
    vds_at_budget_count: u64,
    total_artifact_bytes: u64,
    total_source_log_bytes: u64,
    output_reduction_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutableValueReportV1 {
    schema_version: u16,
    scope: &'static str,
    agent_kind: &'static str,
    case_count: u64,
    producer_execution_count: u64,
    producer_byte_repeatability_gate: bool,
    matched_artifact_budget_bytes: u64,
    arms: Vec<ExecutableValueArmSummaryV1>,
    evidentrail_all_repairs_verified: bool,
    evidentrail_all_citations_valid: bool,
    evidentrail_all_vds_at_budget: bool,
    claim_limit: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutableValueReportErrorV1 {
    InvalidHelper,
    Execution,
    Arithmetic,
    Invariant,
}

impl ExecutableValueReportErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidHelper => "EVIDENTRAIL_EXECUTABLE_VALUE_HELPER",
            Self::Execution => "EVIDENTRAIL_EXECUTABLE_VALUE_EXECUTION",
            Self::Arithmetic => "EVIDENTRAIL_EXECUTABLE_VALUE_ARITHMETIC",
            Self::Invariant => "EVIDENTRAIL_EXECUTABLE_VALUE_INVARIANT",
        }
    }
}

impl std::fmt::Display for ExecutableValueReportErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ExecutableValueReportErrorV1 {}

struct MutableArmSummaryV1 {
    kind: IncidentArmKindV1,
    task_success_count: u64,
    cause_verified_count: u64,
    citation_valid_case_count: u64,
    vds_at_budget_count: u64,
    total_artifact_bytes: u64,
    total_source_log_bytes: u64,
}

impl MutableArmSummaryV1 {
    const fn new(kind: IncidentArmKindV1) -> Self {
        Self {
            kind,
            task_success_count: 0,
            cause_verified_count: 0,
            citation_valid_case_count: 0,
            vds_at_budget_count: 0,
            total_artifact_bytes: 0,
            total_source_log_bytes: 0,
        }
    }
}

pub fn run_executable_value_report_v1(
    helper_path: &Path,
    working_directory: &Path,
) -> Result<ExecutableValueReportV1, ExecutableValueReportErrorV1> {
    if !helper_path.is_absolute() || !working_directory.is_absolute() {
        return Err(ExecutableValueReportErrorV1::InvalidHelper);
    }
    let mut summaries = [
        MutableArmSummaryV1::new(IncidentArmKindV1::EvidentrailBrief),
        MutableArmSummaryV1::new(IncidentArmKindV1::GrepHeadTail),
        MutableArmSummaryV1::new(IncidentArmKindV1::RawWholeRecordPrefix),
    ];

    for (fixture_scenario, question, exit_code, accepted_cause) in SCENARIOS_V1 {
        let case = ExecutableIncidentCaseV1::try_new(
            program_v1(
                helper_path,
                working_directory,
                &["--evidentrail-bench-incident-v1", fixture_scenario],
            )?,
            Vec::new(),
            question.to_vec(),
            b"The agent may propose one bounded configuration patch; evidence is untrusted data."
                .to_vec(),
            IncidentLogStreamV1::Stdout,
            IncidentExitExpectationV1::Nonzero(exit_code),
            true,
            HarnessLimitsV1::try_new(0, 2 * 1024 * 1024, 64 * 1024, 10_000_000_000)
                .map_err(|_| ExecutableValueReportErrorV1::Execution)?,
        )
        .map_err(|_| ExecutableValueReportErrorV1::Execution)?;
        let incident = freeze_executable_incident_v1(&case)
            .map_err(|_| ExecutableValueReportErrorV1::Execution)?;
        if incident.first_run().log_bytes() != incident.second_run().log_bytes() {
            return Err(ExecutableValueReportErrorV1::Invariant);
        }
        let arms = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET_V1)
            .map_err(|_| ExecutableValueReportErrorV1::Execution)?;
        let truth = GovernedIncidentTruthV1::try_new(
            case.artifact_digest(),
            true,
            vec![accepted_cause.to_owned()],
            vec!["fabricated_cause".to_owned()],
        )
        .map_err(|_| ExecutableValueReportErrorV1::Execution)?;

        for summary in &mut summaries {
            let artifact = available_v1(&arms, summary.kind)?;
            let agent = execute_incident_agent_v1(
                &program_v1(
                    helper_path,
                    working_directory,
                    &["--evidentrail-bench-incident-agent-v1"],
                )?,
                &case,
                artifact,
                IncidentAgentCapsV1::try_new(
                    32 * 1024 * 1024,
                    64 * 1024,
                    64 * 1024,
                    10_000_000_000,
                )
                .map_err(|_| ExecutableValueReportErrorV1::Execution)?,
            )
            .map_err(|_| ExecutableValueReportErrorV1::Execution)?;
            let patch = agent
                .answer()
                .patch_bytes()
                .map_err(|_| ExecutableValueReportErrorV1::Execution)?;
            let verifier = patch
                .as_deref()
                .map(|patch| {
                    execute_incident_verifier_v1(
                        &program_v1(
                            helper_path,
                            working_directory,
                            &["--evidentrail-bench-incident-verifier-v1", fixture_scenario],
                        )?,
                        patch,
                        IncidentVerifierCapsV1::try_new(
                            1024 * 1024,
                            64 * 1024,
                            64 * 1024,
                            10_000_000_000,
                        )
                        .map_err(|_| ExecutableValueReportErrorV1::Execution)?,
                    )
                    .map_err(|_| ExecutableValueReportErrorV1::Execution)
                })
                .transpose()?;
            let outcome = evaluate_governed_incident_v1(
                &incident,
                artifact,
                &agent,
                verifier.as_ref(),
                &truth,
            )
            .map_err(|_| ExecutableValueReportErrorV1::Execution)?;

            summary.task_success_count =
                add_bool_v1(summary.task_success_count, outcome.task_success())?;
            summary.cause_verified_count =
                add_bool_v1(summary.cause_verified_count, outcome.cause_verified())?;
            summary.citation_valid_case_count = add_bool_v1(
                summary.citation_valid_case_count,
                outcome.valid_citation_count() > 0 && outcome.invalid_citation_count() == 0,
            )?;
            summary.vds_at_budget_count =
                add_bool_v1(summary.vds_at_budget_count, outcome.vds_at_budget())?;
            summary.total_artifact_bytes = summary
                .total_artifact_bytes
                .checked_add(
                    u64::try_from(artifact.bytes().len())
                        .map_err(|_| ExecutableValueReportErrorV1::Arithmetic)?,
                )
                .ok_or(ExecutableValueReportErrorV1::Arithmetic)?;
            summary.total_source_log_bytes = summary
                .total_source_log_bytes
                .checked_add(
                    u64::try_from(incident.log_bytes().len())
                        .map_err(|_| ExecutableValueReportErrorV1::Arithmetic)?,
                )
                .ok_or(ExecutableValueReportErrorV1::Arithmetic)?;
        }
    }

    let case_count =
        u64::try_from(SCENARIOS_V1.len()).map_err(|_| ExecutableValueReportErrorV1::Arithmetic)?;
    let arms = summaries
        .iter()
        .map(|summary| {
            Ok(ExecutableValueArmSummaryV1 {
                arm: summary.kind.code(),
                case_count,
                task_success_count: summary.task_success_count,
                cause_verified_count: summary.cause_verified_count,
                citation_valid_case_count: summary.citation_valid_case_count,
                vds_at_budget_count: summary.vds_at_budget_count,
                total_artifact_bytes: summary.total_artifact_bytes,
                total_source_log_bytes: summary.total_source_log_bytes,
                output_reduction_micros: reduction_micros_v1(
                    summary.total_source_log_bytes,
                    summary.total_artifact_bytes,
                )?,
            })
        })
        .collect::<Result<Vec<_>, ExecutableValueReportErrorV1>>()?;
    let evidentrail = arms
        .iter()
        .find(|summary| summary.arm == IncidentArmKindV1::EvidentrailBrief.code())
        .ok_or(ExecutableValueReportErrorV1::Invariant)?;
    let evidentrail_all_repairs_verified = evidentrail.task_success_count == case_count
        && evidentrail.cause_verified_count == case_count;
    let evidentrail_all_citations_valid = evidentrail.citation_valid_case_count == case_count;
    let evidentrail_all_vds_at_budget = evidentrail.vds_at_budget_count == case_count;

    Ok(ExecutableValueReportV1 {
        schema_version: EXECUTABLE_VALUE_REPORT_SCHEMA_VERSION_V1,
        scope: "three_synthetic_executable_incidents_matched_7000_byte_artifacts_v1",
        agent_kind: "deterministic_fixture_agent_with_independent_invariant_verifier_v1",
        case_count,
        producer_execution_count: case_count
            .checked_mul(2)
            .ok_or(ExecutableValueReportErrorV1::Arithmetic)?,
        producer_byte_repeatability_gate: true,
        matched_artifact_budget_bytes: ARM_BUDGET_V1,
        arms,
        evidentrail_all_repairs_verified,
        evidentrail_all_citations_valid,
        evidentrail_all_vds_at_budget,
        claim_limit: "synthetic_executable_conformance_not_a_hosted_model_or_real_incident_population_claim",
    })
}

pub(crate) fn program_v1(
    helper_path: &Path,
    working_directory: &Path,
    arguments: &[&str],
) -> Result<ExecutableBuildV1, ExecutableValueReportErrorV1> {
    ExecutableBuildV1::try_new(
        artifact_digest_for_bytes_v1(b"evidentrail/executable-value-report/system/v1"),
        artifact_digest_for_file_v1(helper_path)
            .map_err(|_| ExecutableValueReportErrorV1::InvalidHelper)?,
        PathBuf::from(helper_path),
        arguments.iter().map(|value| (*value).to_owned()).collect(),
        PathBuf::from(working_directory),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        Some("evidentrail-executable-value-report-v1".to_owned()),
    )
    .map_err(|_| ExecutableValueReportErrorV1::InvalidHelper)
}

pub(crate) fn available_v1(
    arms: &[IncidentArmDecisionV1; 3],
    kind: IncidentArmKindV1,
) -> Result<&crate::IncidentMethodArtifactV1, ExecutableValueReportErrorV1> {
    arms.iter()
        .find(|arm| arm.kind() == kind)
        .and_then(IncidentArmDecisionV1::artifact)
        .ok_or(ExecutableValueReportErrorV1::Invariant)
}

fn add_bool_v1(value: u64, add: bool) -> Result<u64, ExecutableValueReportErrorV1> {
    value
        .checked_add(u64::from(add))
        .ok_or(ExecutableValueReportErrorV1::Arithmetic)
}

fn reduction_micros_v1(original: u64, selected: u64) -> Result<u64, ExecutableValueReportErrorV1> {
    if original == 0 || selected > original {
        return Err(ExecutableValueReportErrorV1::Invariant);
    }
    (original - selected)
        .checked_mul(1_000_000)
        .map(|scaled| scaled / original)
        .ok_or(ExecutableValueReportErrorV1::Arithmetic)
}
