use std::io::{self, Read};

use evidentrail_cli::{StdinBriefOutcomeV1, compile_explicit_stream_v3};
use evidentrail_core::UnixTimestampNanos;
use evidentrail_store::PackedMemoryEventStoreV3;

const RECORDS: u64 = 1_000_000;
const START_ID: &str = "11111111-1111-4111-8111-111111111111";
const MIDDLE_ID: &str = "22222222-2222-4222-8222-222222222222";
const END_ID: &str = "33333333-3333-4333-8333-333333333333";

struct IncidentStream {
    ordinal: u64,
    current: Vec<u8>,
    offset: usize,
}

impl IncidentStream {
    fn new() -> Self {
        Self {
            ordinal: 0,
            current: Vec::new(),
            offset: 0,
        }
    }

    fn fill(&mut self) {
        if self.ordinal == RECORDS {
            return;
        }
        let ordinal = self.ordinal;
        self.current = match ordinal {
            0 => evidence(ordinal, START_ID, "deploy_started_with_pool_size_zero"),
            value if value == RECORDS / 2 => {
                evidence(ordinal, MIDDLE_ID, "first_pool_exhaustion_observed")
            }
            value if value == RECORDS - 1 => {
                evidence(ordinal, END_ID, "rollback_restored_pool_size_sixteen")
            }
            _ => format!("2026-08-30T12:00:00Z INFO service=api ordinal={ordinal} status=ok\n")
                .into_bytes(),
        };
        self.ordinal += 1;
        self.offset = 0;
    }
}

impl Read for IncidentStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.current.len() {
            self.fill();
            if self.current.is_empty() || self.offset == self.current.len() {
                return Ok(0);
            }
        }
        let count = output.len().min(self.current.len() - self.offset);
        output[..count].copy_from_slice(&self.current[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn evidence(ordinal: u64, request: &str, fact: &str) -> Vec<u8> {
    format!(
        "2026-08-30T12:00:00Z ERROR service=api ordinal={ordinal} request={request} evidence={fact}\n"
    )
    .into_bytes()
}

/// Resource-heavy gate run explicitly by the V3 validation workflow.
#[test]
#[ignore = "runs the one-million-record certification corpus"]
fn required_evidence_survives_beginning_middle_and_end_partition_boundaries() {
    let question =
        format!("why did the deployment fail? correlate requests {START_ID} {MIDDLE_ID} {END_ID}");
    let session = compile_explicit_stream_v3(
        IncidentStream::new(),
        question.as_bytes(),
        100_000,
        [0x81; 32],
        UnixTimestampNanos::new(1_800_000_000_000_000_000),
        PackedMemoryEventStoreV3::new(),
    )
    .unwrap();
    let StdinBriefOutcomeV1::Rendered(rendered) = session.outcome() else {
        panic!("the complete labeled corpus must render")
    };
    assert_eq!(rendered.source_record_count(), RECORDS);
    for required in [
        START_ID,
        MIDDLE_ID,
        END_ID,
        "deploy_started_with_pool_size_zero",
        "first_pool_exhaustion_observed",
        "rollback_restored_pool_size_sixteen",
    ] {
        assert!(
            rendered.text().contains(required),
            "required evidence missing: {required}"
        );
    }
}
