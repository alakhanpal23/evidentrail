//! Contentless, reproducible product-value summary over the frozen hermetic
//! incident corpus. This is deliberately separate from hosted qualification:
//! it establishes the deterministic product's matched-budget value, while the
//! live ranker must establish its own incremental value.

use evidentrail_bench::{
    HERMETIC_INCIDENT_CASE_COUNT_V1, HermeticIncidentArmV1,
    freeze_hermetic_incident_public_corpus_v1, govern_hermetic_incident_outcome_corpus_v1,
    synthetic_hermetic_incident_annotations_v1,
};
use serde::Serialize;

pub const PRODUCT_VALUE_REPORT_SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductValueArmSummaryV1 {
    arm: &'static str,
    required_evidence_recall_micros: u64,
    perfect_case_count: u64,
    case_count: u64,
    worst_case_recall_micros: u64,
    selected_source_bytes: u64,
    source_byte_reduction_micros: u64,
    recall_delta_vs_raw_micros: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductValueGateSummaryV1 {
    all_arms_use_full_selected_source_byte_budget: bool,
    deterministic_matches_exact_oracle_recall: bool,
    deterministic_beats_every_cheap_baseline_recall: bool,
    deterministic_perfect_on_every_case: bool,
    hosted_incremental_value_established: bool,
    real_incident_external_validity_established: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductValueReportV1 {
    schema_version: u16,
    scope: &'static str,
    corpus_digest_hex: String,
    public_corpus_digest_hex: String,
    case_count: u64,
    diagnosis_expected_count: u64,
    abstention_expected_count: u64,
    total_authorized_source_bytes: u64,
    matched_budget_basis: &'static str,
    headline: &'static str,
    arms: Vec<ProductValueArmSummaryV1>,
    exact_oracle_required_evidence_recall_micros: u64,
    gates: ProductValueGateSummaryV1,
    claim_limit: &'static str,
    hosted_next_gate: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductValueReportErrorV1 {
    Corpus,
    Arithmetic,
    Invariant,
}

impl ProductValueReportErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Corpus => "EVIDENTRAIL_PRODUCT_VALUE_CORPUS",
            Self::Arithmetic => "EVIDENTRAIL_PRODUCT_VALUE_ARITHMETIC",
            Self::Invariant => "EVIDENTRAIL_PRODUCT_VALUE_INVARIANT",
        }
    }
}

impl std::fmt::Display for ProductValueReportErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProductValueReportErrorV1 {}

/// Build a report containing identities and aggregate measurements only. No
/// questions, log bytes, evidence IDs, or hidden annotations are serialized.
pub fn build_product_value_report_v1() -> Result<ProductValueReportV1, ProductValueReportErrorV1> {
    let public = freeze_hermetic_incident_public_corpus_v1()
        .map_err(|_| ProductValueReportErrorV1::Corpus)?;
    let annotations = synthetic_hermetic_incident_annotations_v1(&public)
        .map_err(|_| ProductValueReportErrorV1::Corpus)?;
    let governed = govern_hermetic_incident_outcome_corpus_v1(&public, annotations)
        .map_err(|_| ProductValueReportErrorV1::Corpus)?;

    let case_count = u64::try_from(HERMETIC_INCIDENT_CASE_COUNT_V1)
        .map_err(|_| ProductValueReportErrorV1::Arithmetic)?;
    let total_authorized_source_bytes = public.cases().iter().try_fold(0_u64, |total, case| {
        let case_bytes = case
            .ledger()
            .events()
            .iter()
            .try_fold(0_u64, |sum, event| {
                sum.checked_add(
                    u64::try_from(event.raw().len())
                        .map_err(|_| ProductValueReportErrorV1::Arithmetic)?,
                )
                .ok_or(ProductValueReportErrorV1::Arithmetic)
            })?;
        total
            .checked_add(case_bytes)
            .ok_or(ProductValueReportErrorV1::Arithmetic)
    })?;

    let raw_summary = governed.arm_summary(HermeticIncidentArmV1::RawChronological);
    let (raw_satisfied, raw_total) = raw_summary.exact_ratio();
    let raw_recall = ratio_micros_v1(raw_satisfied, raw_total)?;
    let mut arms = Vec::with_capacity(HermeticIncidentArmV1::ALL.len());
    for arm in HermeticIncidentArmV1::ALL {
        let summary = governed.arm_summary(arm);
        let (satisfied, total) = summary.exact_ratio();
        let recall = ratio_micros_v1(satisfied, total)?;
        let selected_source_bytes = governed.cases().iter().try_fold(0_u64, |sum, case| {
            sum.checked_add(case.outcome(arm).selected_unique_source_bytes())
                .ok_or(ProductValueReportErrorV1::Arithmetic)
        })?;
        let worst_case_recall_micros = governed
            .cases()
            .iter()
            .map(|case| {
                let (case_satisfied, case_total) = case.outcome(arm).recall().exact_ratio();
                ratio_micros_v1(case_satisfied, case_total)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min()
            .unwrap_or(0);
        arms.push(ProductValueArmSummaryV1 {
            arm: arm.code(),
            required_evidence_recall_micros: recall,
            perfect_case_count: summary.perfect_case_count(),
            case_count,
            worst_case_recall_micros,
            selected_source_bytes,
            source_byte_reduction_micros: reduction_micros_v1(
                total_authorized_source_bytes,
                selected_source_bytes,
            )?,
            recall_delta_vs_raw_micros: i64::try_from(recall)
                .and_then(|value| i64::try_from(raw_recall).map(|raw| value - raw))
                .map_err(|_| ProductValueReportErrorV1::Arithmetic)?,
        });
    }

    let (oracle_satisfied, oracle_total) =
        governed
            .cases()
            .iter()
            .try_fold((0_u64, 0_u64), |(satisfied, total), case| {
                let (case_satisfied, case_total) = case.exact_oracle_recall().exact_ratio();
                Ok::<_, ProductValueReportErrorV1>((
                    satisfied
                        .checked_add(case_satisfied)
                        .ok_or(ProductValueReportErrorV1::Arithmetic)?,
                    total
                        .checked_add(case_total)
                        .ok_or(ProductValueReportErrorV1::Arithmetic)?,
                ))
            })?;
    let oracle_recall = ratio_micros_v1(oracle_satisfied, oracle_total)?;
    let deterministic = arms
        .iter()
        .find(|summary| summary.arm == HermeticIncidentArmV1::FullThreeLane.code())
        .ok_or(ProductValueReportErrorV1::Invariant)?;
    let cheap = arms
        .iter()
        .filter(|summary| summary.arm != HermeticIncidentArmV1::FullThreeLane.code())
        .collect::<Vec<_>>();
    let all_arms_use_full_selected_source_byte_budget = public.cases().iter().all(|case| {
        let full_bytes = case
            .outcome(HermeticIncidentArmV1::FullThreeLane)
            .selected_unique_source_bytes();
        case.matched_source_byte_budget() == full_bytes
            && HermeticIncidentArmV1::ALL
                .iter()
                .filter(|arm| **arm != HermeticIncidentArmV1::FullThreeLane)
                .all(|arm| case.outcome(*arm).selected_unique_source_bytes() <= full_bytes)
    });
    let deterministic_matches_exact_oracle_recall =
        deterministic.required_evidence_recall_micros == oracle_recall;
    let deterministic_beats_every_cheap_baseline_recall = cheap.iter().all(|summary| {
        deterministic.required_evidence_recall_micros > summary.required_evidence_recall_micros
    });
    let deterministic_perfect_on_every_case = deterministic.perfect_case_count == case_count;

    Ok(ProductValueReportV1 {
        schema_version: PRODUCT_VALUE_REPORT_SCHEMA_VERSION_V1,
        scope: "frozen_synthetic_hermetic_matched_budget_conformance_v1",
        corpus_digest_hex: hex_v1(governed.digest().as_bytes()),
        public_corpus_digest_hex: hex_v1(public.digest().as_bytes()),
        case_count,
        diagnosis_expected_count: governed.diagnosis_expected_count(),
        abstention_expected_count: governed.abstention_expected_count(),
        total_authorized_source_bytes,
        matched_budget_basis: "full_selected_unique_authorized_source_bytes_per_case",
        headline: "deterministic_evidentrail_preserves_more_required_evidence_than_every_frozen_cheap_baseline_at_matched_source_byte_budgets",
        arms,
        exact_oracle_required_evidence_recall_micros: oracle_recall,
        gates: ProductValueGateSummaryV1 {
            all_arms_use_full_selected_source_byte_budget,
            deterministic_matches_exact_oracle_recall,
            deterministic_beats_every_cheap_baseline_recall,
            deterministic_perfect_on_every_case,
            hosted_incremental_value_established: false,
            real_incident_external_validity_established: false,
        },
        claim_limit: "synthetic_conformance_only_not_a_population_or_real_incident_outcome_claim",
        hosted_next_gate: "hosted_ranking_must_show_positive_paired_recall_lower_bound_and_noninferior_verified_diagnosis_before_admission",
    })
}

fn ratio_micros_v1(numerator: u64, denominator: u64) -> Result<u64, ProductValueReportErrorV1> {
    if denominator == 0 || numerator > denominator {
        return Err(ProductValueReportErrorV1::Invariant);
    }
    numerator
        .checked_mul(1_000_000)
        .map(|scaled| scaled / denominator)
        .ok_or(ProductValueReportErrorV1::Arithmetic)
}

fn reduction_micros_v1(original: u64, selected: u64) -> Result<u64, ProductValueReportErrorV1> {
    if original == 0 || selected > original {
        return Err(ProductValueReportErrorV1::Invariant);
    }
    ratio_micros_v1(original - selected, original)
}

fn hex_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_makes_the_matched_budget_value_and_limits_explicit() {
        let report = build_product_value_report_v1().unwrap();
        assert_eq!(report.case_count, 8);
        assert_eq!(report.arms.len(), 5);
        let exact = report
            .arms
            .iter()
            .map(|arm| {
                (
                    arm.arm,
                    arm.required_evidence_recall_micros,
                    arm.perfect_case_count,
                    arm.worst_case_recall_micros,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            exact,
            vec![
                ("production_full_three_lane_v1", 1_000_000, 8, 1_000_000),
                ("raw_chronological_v1", 237_500, 0, 0),
                ("grep_head_tail_v1", 525_000, 3, 0),
                ("quota_hybrid_v1", 612_500, 3, 300_000),
                ("bm25f_whole_event_v1", 237_500, 1, 0),
            ]
        );
        assert!(report.gates.all_arms_use_full_selected_source_byte_budget);
        assert!(report.gates.deterministic_matches_exact_oracle_recall);
        assert!(report.gates.deterministic_beats_every_cheap_baseline_recall);
        assert!(report.gates.deterministic_perfect_on_every_case);
        assert!(!report.gates.hosted_incremental_value_established);
        assert!(!report.gates.real_incident_external_validity_established);

        let encoded = serde_json::to_string(&report).unwrap();
        for forbidden in [
            "secret=",
            "traceback",
            "kubectl",
            "cause_code=",
            "ranked_block_ids",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
