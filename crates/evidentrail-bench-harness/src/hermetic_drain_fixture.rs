use std::error::Error as StdError;
use std::fmt;

use serde::Serialize;

use crate::legacy_drain_normalizer::parse_pinned_ascii_line;
use crate::{
    MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_INPUT_BYTES_V1, MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1,
};

#[derive(Serialize)]
struct FixtureOutputV1 {
    groups: Vec<FixtureGroupV1>,
    original_count: u64,
    template_count: u64,
    line_compression: f64,
}

#[derive(Serialize)]
struct FixtureGroupV1 {
    id: u64,
    first_index: u64,
    count: u64,
    template: &'static str,
    samples: Vec<FixtureSampleV1>,
    slots: Vec<FixtureSlotV1>,
}

#[derive(Serialize)]
struct FixtureSampleV1 {
    index: u64,
    text: String,
    level: Option<String>,
    timestamp: Option<String>,
}

#[derive(Serialize)]
struct FixtureSlotV1;

/// Produce fixture-only full-membership JSON from the exact public stdin.
///
/// This deliberately does not emulate grouping quality. It emits one bounded
/// synthetic group whose samples are derived through the same frozen pinned
/// line-normalization contract that the strict verifier independently checks.
/// The helper's system/revision/method identities prevent this artifact from
/// being mistaken for an observed pinned `legacy-drain` result.
#[doc(hidden)]
pub fn hermetic_legacy_drain_full_membership_fixture_json_v1(
    input: &[u8],
) -> Result<Vec<u8>, HermeticDrainFixtureErrorV1> {
    let input_len = u64::try_from(input.len()).map_err(|_| HermeticDrainFixtureErrorV1::Limit)?;
    if input_len > MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_INPUT_BYTES_V1 {
        return Err(HermeticDrainFixtureErrorV1::Limit);
    }
    let input = std::str::from_utf8(input).map_err(|_| HermeticDrainFixtureErrorV1::Input)?;
    if !input.is_ascii() {
        return Err(HermeticDrainFixtureErrorV1::Input);
    }

    let mut samples = Vec::new();
    for payload in source_payloads(input) {
        if payload.trim().is_empty() {
            continue;
        }
        let normalized =
            parse_pinned_ascii_line(payload).map_err(|_| HermeticDrainFixtureErrorV1::Input)?;
        let index = u64::try_from(samples.len()).map_err(|_| HermeticDrainFixtureErrorV1::Limit)?;
        samples.push(FixtureSampleV1 {
            index,
            text: normalized.message,
            level: normalized.level,
            timestamp: normalized.timestamp,
        });
    }
    let original_count =
        u64::try_from(samples.len()).map_err(|_| HermeticDrainFixtureErrorV1::Limit)?;
    if original_count == 0 || original_count > MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1 {
        return Err(HermeticDrainFixtureErrorV1::Limit);
    }
    let output = FixtureOutputV1 {
        groups: vec![FixtureGroupV1 {
            id: 0,
            first_index: 0,
            count: original_count,
            template: "hermetic-full-membership-fixture",
            samples,
            slots: Vec::new(),
        }],
        original_count,
        template_count: 1,
        line_compression: original_count as f64,
    };
    let mut encoded =
        serde_json::to_vec(&output).map_err(|_| HermeticDrainFixtureErrorV1::Encode)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn source_payloads(input: &str) -> impl Iterator<Item = &str> {
    input.split_inclusive('\n').map(|record| {
        record
            .strip_suffix('\n')
            .unwrap_or(record)
            .strip_suffix('\r')
            .unwrap_or_else(|| record.strip_suffix('\n').unwrap_or(record))
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HermeticDrainFixtureErrorV1 {
    Input,
    Limit,
    Encode,
}

impl HermeticDrainFixtureErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "EVIDENTRAIL_BENCH_HERMETIC_DRAIN_FIXTURE_INPUT",
            Self::Limit => "EVIDENTRAIL_BENCH_HERMETIC_DRAIN_FIXTURE_LIMIT",
            Self::Encode => "EVIDENTRAIL_BENCH_HERMETIC_DRAIN_FIXTURE_ENCODE",
        }
    }
}

impl fmt::Debug for HermeticDrainFixtureErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticDrainFixtureErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for HermeticDrainFixtureErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for HermeticDrainFixtureErrorV1 {}
