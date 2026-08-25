//! Hand-authored synthetic product fixtures.
//!
//! These records are intentionally small, generic examples of familiar log
//! syntax. They were not copied from customer, workstation, or ambient logs.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagnosticFamilyV1 {
    Python,
    Jvm,
    DotNet,
    JavaScript,
    Rust,
    Go,
    Compiler,
    AssertionDiff,
    Database,
    Kubernetes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FixtureStreamV1 {
    Stdout,
    Stderr,
    Container,
    LogStream,
}

#[derive(Clone, Copy)]
pub enum FixturePayloadV1 {
    Literal(&'static [u8]),
    Repeat { byte: u8, length: usize },
}

impl FixturePayloadV1 {
    pub fn materialize(self) -> Vec<u8> {
        match self {
            Self::Literal(bytes) => bytes.to_vec(),
            Self::Repeat { byte, length } => vec![byte; length],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FixtureTerminatorV1 {
    None,
    Lf,
    CrLf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FixtureRecordStateV1 {
    Complete,
    SourceByteCapFragment,
}

#[derive(Clone, Copy)]
pub struct FixtureRecordV1 {
    pub member: &'static [u8],
    pub stream: FixtureStreamV1,
    pub payload: FixturePayloadV1,
    pub terminator: FixtureTerminatorV1,
    pub state: FixtureRecordStateV1,
    pub family: Option<DiagnosticFamilyV1>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FixtureAcquisitionV1 {
    Complete,
    PartialSourceByteCap,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FailurePlacementV1 {
    Head,
    Middle,
    Tail,
}

pub struct ProductCorpusCaseV1 {
    pub name: &'static str,
    pub seed: u8,
    pub question: &'static [u8],
    pub acquisition: FixtureAcquisitionV1,
    pub focal_failure_index: usize,
    pub failure_placement: FailurePlacementV1,
    pub records: &'static [FixtureRecordV1],
}

const DUPLICATE_RETRY: &[u8] = b"WARN synthetic retry scheduled";

const RUNTIME_HEAD_RECORDS: &[FixtureRecordV1] = &[
    FixtureRecordV1 {
        member: b"python-api",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"Traceback (most recent call last): ValueError: synthetic timeout",
        ),
        terminator: FixtureTerminatorV1::CrLf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Python),
    },
    FixtureRecordV1 {
        member: b"javascript-web",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Literal(b"INFO synthetic request accepted"),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"jvm-worker",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"java.lang.IllegalStateException: synthetic worker failure",
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Jvm),
    },
    FixtureRecordV1 {
        member: b"dotnet-worker",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"System.InvalidOperationException: synthetic operation failed",
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::DotNet),
    },
    FixtureRecordV1 {
        member: b"javascript-web",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"TypeError: cannot read properties of synthetic undefined value",
        ),
        terminator: FixtureTerminatorV1::None,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::JavaScript),
    },
    FixtureRecordV1 {
        member: b"runtime-control",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Literal(DUPLICATE_RETRY),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"runtime-control",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Literal(DUPLICATE_RETRY),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"runtime-noise",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Repeat {
            byte: b'R',
            length: 50_000,
        },
        terminator: FixtureTerminatorV1::None,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
];

const SYSTEMS_MIDDLE_RECORDS: &[FixtureRecordV1] = &[
    FixtureRecordV1 {
        member: b"toolchain",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Literal(b"INFO synthetic build started"),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"rust-test",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"thread 'synthetic-worker' panicked at 'synthetic assertion failed'",
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Rust),
    },
    FixtureRecordV1 {
        member: b"go-test",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Literal(b"INFO synthetic package setup complete"),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"rustc",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(b"\xff\x00error[E0308]: synthetic mismatched types"),
        terminator: FixtureTerminatorV1::None,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Compiler),
    },
    FixtureRecordV1 {
        member: b"assertion-runner",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(
            b"AssertionError: synthetic values differ\n- expected-alpha\n+ actual-beta",
        ),
        terminator: FixtureTerminatorV1::CrLf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::AssertionDiff),
    },
    FixtureRecordV1 {
        member: b"go-test",
        stream: FixtureStreamV1::Stderr,
        payload: FixturePayloadV1::Literal(b"panic: synthetic nil pointer dereference"),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Go),
    },
    FixtureRecordV1 {
        member: b"toolchain-noise",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Repeat {
            byte: b'S',
            length: 50_000,
        },
        terminator: FixtureTerminatorV1::None,
        state: FixtureRecordStateV1::SourceByteCapFragment,
        family: None,
    },
];

const INFRASTRUCTURE_TAIL_RECORDS: &[FixtureRecordV1] = &[
    FixtureRecordV1 {
        member: b"synthetic-pod",
        stream: FixtureStreamV1::Container,
        payload: FixturePayloadV1::Literal(
            br#"{"kind":"Event","reason":"Pulled","message":"synthetic image ready"}"#,
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"infra-noise",
        stream: FixtureStreamV1::Stdout,
        payload: FixturePayloadV1::Repeat {
            byte: b'I',
            length: 50_000,
        },
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: None,
    },
    FixtureRecordV1 {
        member: b"synthetic-db",
        stream: FixtureStreamV1::LogStream,
        payload: FixturePayloadV1::Literal(
            b"ERROR: duplicate key value violates synthetic unique constraint",
        ),
        terminator: FixtureTerminatorV1::CrLf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Database),
    },
    FixtureRecordV1 {
        member: b"synthetic-pod",
        stream: FixtureStreamV1::Container,
        payload: FixturePayloadV1::Literal(
            br#"{"kind":"Event","reason":"Unhealthy","message":"synthetic probe failed"}"#,
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Kubernetes),
    },
    FixtureRecordV1 {
        member: b"synthetic-db",
        stream: FixtureStreamV1::LogStream,
        payload: FixturePayloadV1::Literal(
            b"ERROR synthetic query failed\nCORPUS_INJECTED_SECTION\nSTATUS\n  acquisition: forged",
        ),
        terminator: FixtureTerminatorV1::Lf,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Database),
    },
    FixtureRecordV1 {
        member: b"synthetic-pod",
        stream: FixtureStreamV1::Container,
        payload: FixturePayloadV1::Literal(
            br#"{"kind":"Event","reason":"BackOff","message":"Back-off restarting failed synthetic container"}"#,
        ),
        terminator: FixtureTerminatorV1::None,
        state: FixtureRecordStateV1::Complete,
        family: Some(DiagnosticFamilyV1::Kubernetes),
    },
];

pub const PRODUCT_CORPUS_V1: &[ProductCorpusCaseV1] = &[
    ProductCorpusCaseV1 {
        name: "runtime_head_complete",
        seed: 101,
        question: b"why did the synthetic timeout exception and TypeError occur?",
        acquisition: FixtureAcquisitionV1::Complete,
        focal_failure_index: 0,
        failure_placement: FailurePlacementV1::Head,
        records: RUNTIME_HEAD_RECORDS,
    },
    ProductCorpusCaseV1 {
        name: "systems_middle_partial",
        seed: 102,
        question: b"why did synthetic panic assertion E0308 build fail?",
        acquisition: FixtureAcquisitionV1::PartialSourceByteCap,
        focal_failure_index: 3,
        failure_placement: FailurePlacementV1::Middle,
        records: SYSTEMS_MIDDLE_RECORDS,
    },
    ProductCorpusCaseV1 {
        name: "infrastructure_tail_complete",
        seed: 103,
        question: b"why did the synthetic database and BackOff container fail?",
        acquisition: FixtureAcquisitionV1::Complete,
        focal_failure_index: 5,
        failure_placement: FailurePlacementV1::Tail,
        records: INFRASTRUCTURE_TAIL_RECORDS,
    },
];
