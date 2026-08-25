use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventId, EventLedger};

use crate::{MetricError, candidate_cost};

/// Runtime-dependent candidate measurements supplied by the benchmark harness.
///
/// This crate does not tokenize, time, or profile a method. All three values
/// are therefore mandatory inputs; an absent measurement is never represented
/// by an implicit zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasuredCandidateResources {
    canonical_candidate_tokens: u64,
    wall_time_nanos: u64,
    peak_memory_bytes: u64,
}

impl MeasuredCandidateResources {
    pub fn try_new<Tokens, WallTime, PeakMemory>(
        canonical_candidate_tokens: Tokens,
        wall_time_nanos: WallTime,
        peak_memory_bytes: PeakMemory,
    ) -> Result<Self, CandidateResourceError>
    where
        Tokens: TryInto<u64>,
        WallTime: TryInto<u64>,
        PeakMemory: TryInto<u64>,
    {
        Ok(Self {
            canonical_candidate_tokens: canonical_candidate_tokens
                .try_into()
                .map_err(|_| CandidateResourceError::CanonicalTokenCountOverflow)?,
            wall_time_nanos: wall_time_nanos
                .try_into()
                .map_err(|_| CandidateResourceError::WallTimeNanosOverflow)?,
            peak_memory_bytes: peak_memory_bytes
                .try_into()
                .map_err(|_| CandidateResourceError::PeakMemoryBytesOverflow)?,
        })
    }

    #[must_use]
    pub const fn canonical_candidate_tokens(self) -> u64 {
        self.canonical_candidate_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_memory_bytes(self) -> u64 {
        self.peak_memory_bytes
    }
}

/// Frozen five-dimensional candidate-evaluation cost vector.
///
/// Candidate count and source bytes are inherent costs computed from unique
/// event identities in the supplied ledger. The remaining dimensions are
/// explicit benchmark-harness measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateResourceEnvelope {
    unique_candidate_event_count: u64,
    unique_candidate_source_bytes: u64,
    canonical_candidate_tokens: u64,
    wall_time_nanos: u64,
    peak_memory_bytes: u64,
}

impl CandidateResourceEnvelope {
    #[must_use]
    pub const fn unique_candidate_event_count(self) -> u64 {
        self.unique_candidate_event_count
    }

    #[must_use]
    pub const fn unique_candidate_source_bytes(self) -> u64 {
        self.unique_candidate_source_bytes
    }

    #[must_use]
    pub const fn canonical_candidate_tokens(self) -> u64 {
        self.canonical_candidate_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_memory_bytes(self) -> u64 {
        self.peak_memory_bytes
    }

    /// Cost-only Pareto comparison. Equal vectors do not dominate.
    #[must_use]
    pub const fn pareto_dominates(self, other: Self) -> bool {
        cost_pareto_dominates(self, other)
    }
}

/// Compute inherent candidate costs and combine them with required measurements.
pub fn candidate_resource_envelope(
    ledger: &EventLedger,
    candidate_event_ids: &[EventId],
    measured: MeasuredCandidateResources,
) -> Result<CandidateResourceEnvelope, CandidateResourceError> {
    let inherent = candidate_cost(ledger, candidate_event_ids).map_err(|error| match error {
        MetricError::UnknownCandidateEvent { count } => {
            CandidateResourceError::UnknownCandidateEvent { count }
        }
        MetricError::CandidateByteCostOverflow => {
            CandidateResourceError::UniqueCandidateSourceBytesOverflow
        }
        _ => CandidateResourceError::CandidateCostInvariantViolation,
    })?;
    let unique_candidate_event_count = u64::try_from(inherent.event_count())
        .map_err(|_| CandidateResourceError::CandidateEventCountOverflow)?;
    let unique_candidate_source_bytes = u64::try_from(inherent.unique_source_bytes())
        .map_err(|_| CandidateResourceError::UniqueCandidateSourceBytesOverflow)?;

    Ok(CandidateResourceEnvelope {
        unique_candidate_event_count,
        unique_candidate_source_bytes,
        canonical_candidate_tokens: measured.canonical_candidate_tokens,
        wall_time_nanos: measured.wall_time_nanos,
        peak_memory_bytes: measured.peak_memory_bytes,
    })
}

/// One dimension of the frozen candidate-evaluation vector.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateResourceDimension {
    UniqueCandidateEventCount,
    UniqueCandidateSourceBytes,
    CanonicalCandidateTokens,
    WallTimeNanos,
    PeakMemoryBytes,
}

impl CandidateResourceDimension {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UniqueCandidateEventCount => "unique_candidate_event_count",
            Self::UniqueCandidateSourceBytes => "unique_candidate_source_bytes",
            Self::CanonicalCandidateTokens => "canonical_candidate_tokens",
            Self::WallTimeNanos => "wall_time_nanos",
            Self::PeakMemoryBytes => "peak_memory_bytes",
        }
    }
}

impl fmt::Debug for CandidateResourceDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateResourceDimension")
            .field("code", &self.code())
            .finish()
    }
}

/// Frozen inclusive maxima for all five candidate-evaluation dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateResourceCap {
    unique_candidate_event_count: u64,
    unique_candidate_source_bytes: u64,
    canonical_candidate_tokens: u64,
    wall_time_nanos: u64,
    peak_memory_bytes: u64,
}

impl CandidateResourceCap {
    pub fn try_new<EventCount, SourceBytes, Tokens, WallTime, PeakMemory>(
        unique_candidate_event_count: EventCount,
        unique_candidate_source_bytes: SourceBytes,
        canonical_candidate_tokens: Tokens,
        wall_time_nanos: WallTime,
        peak_memory_bytes: PeakMemory,
    ) -> Result<Self, CandidateResourceError>
    where
        EventCount: TryInto<u64>,
        SourceBytes: TryInto<u64>,
        Tokens: TryInto<u64>,
        WallTime: TryInto<u64>,
        PeakMemory: TryInto<u64>,
    {
        Ok(Self {
            unique_candidate_event_count: unique_candidate_event_count
                .try_into()
                .map_err(|_| CandidateResourceError::CandidateEventCountOverflow)?,
            unique_candidate_source_bytes: unique_candidate_source_bytes
                .try_into()
                .map_err(|_| CandidateResourceError::UniqueCandidateSourceBytesOverflow)?,
            canonical_candidate_tokens: canonical_candidate_tokens
                .try_into()
                .map_err(|_| CandidateResourceError::CanonicalTokenCountOverflow)?,
            wall_time_nanos: wall_time_nanos
                .try_into()
                .map_err(|_| CandidateResourceError::WallTimeNanosOverflow)?,
            peak_memory_bytes: peak_memory_bytes
                .try_into()
                .map_err(|_| CandidateResourceError::PeakMemoryBytesOverflow)?,
        })
    }

    #[must_use]
    pub const fn unique_candidate_event_count(self) -> u64 {
        self.unique_candidate_event_count
    }

    #[must_use]
    pub const fn unique_candidate_source_bytes(self) -> u64 {
        self.unique_candidate_source_bytes
    }

    #[must_use]
    pub const fn canonical_candidate_tokens(self) -> u64 {
        self.canonical_candidate_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_memory_bytes(self) -> u64 {
        self.peak_memory_bytes
    }

    /// Check every dimension and return all exceeded dimensions in fixed order.
    pub fn check(self, cost: CandidateResourceEnvelope) -> Result<(), CandidateCapViolations> {
        let mut dimensions = Vec::new();
        if cost.unique_candidate_event_count > self.unique_candidate_event_count {
            dimensions.push(CandidateResourceDimension::UniqueCandidateEventCount);
        }
        if cost.unique_candidate_source_bytes > self.unique_candidate_source_bytes {
            dimensions.push(CandidateResourceDimension::UniqueCandidateSourceBytes);
        }
        if cost.canonical_candidate_tokens > self.canonical_candidate_tokens {
            dimensions.push(CandidateResourceDimension::CanonicalCandidateTokens);
        }
        if cost.wall_time_nanos > self.wall_time_nanos {
            dimensions.push(CandidateResourceDimension::WallTimeNanos);
        }
        if cost.peak_memory_bytes > self.peak_memory_bytes {
            dimensions.push(CandidateResourceDimension::PeakMemoryBytes);
        }

        if dimensions.is_empty() {
            Ok(())
        } else {
            Err(CandidateCapViolations { dimensions })
        }
    }
}

/// Non-empty typed list of resource-cap violations.
#[derive(Clone, PartialEq, Eq)]
pub struct CandidateCapViolations {
    dimensions: Vec<CandidateResourceDimension>,
}

impl CandidateCapViolations {
    #[must_use]
    pub fn dimensions(&self) -> &[CandidateResourceDimension] {
        &self.dimensions
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.dimensions.len()
    }

    #[must_use]
    pub fn contains(&self, dimension: CandidateResourceDimension) -> bool {
        self.dimensions.contains(&dimension)
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        "EVIDENTRAIL_BENCH_CANDIDATE_RESOURCE_CAP_VIOLATED"
    }
}

impl fmt::Debug for CandidateCapViolations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dimension_codes = self
            .dimensions
            .iter()
            .map(|dimension| dimension.code())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("CandidateCapViolations")
            .field("dimension_codes", &dimension_codes)
            .finish()
    }
}

impl fmt::Display for CandidateCapViolations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CandidateCapViolations {}

/// Contentless construction/evaluation failures for candidate resources.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateResourceError {
    UnknownCandidateEvent { count: usize },
    CandidateEventCountOverflow,
    UniqueCandidateSourceBytesOverflow,
    CanonicalTokenCountOverflow,
    WallTimeNanosOverflow,
    PeakMemoryBytesOverflow,
    CandidateCostInvariantViolation,
}

impl CandidateResourceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownCandidateEvent { .. } => "EVIDENTRAIL_BENCH_RESOURCE_UNKNOWN_CANDIDATE_EVENT",
            Self::CandidateEventCountOverflow => {
                "EVIDENTRAIL_BENCH_RESOURCE_CANDIDATE_EVENT_COUNT_OVERFLOW"
            }
            Self::UniqueCandidateSourceBytesOverflow => {
                "EVIDENTRAIL_BENCH_RESOURCE_UNIQUE_CANDIDATE_SOURCE_BYTES_OVERFLOW"
            }
            Self::CanonicalTokenCountOverflow => {
                "EVIDENTRAIL_BENCH_RESOURCE_CANONICAL_TOKEN_COUNT_OVERFLOW"
            }
            Self::WallTimeNanosOverflow => "EVIDENTRAIL_BENCH_RESOURCE_WALL_TIME_NANOS_OVERFLOW",
            Self::PeakMemoryBytesOverflow => "EVIDENTRAIL_BENCH_RESOURCE_PEAK_MEMORY_BYTES_OVERFLOW",
            Self::CandidateCostInvariantViolation => {
                "EVIDENTRAIL_BENCH_RESOURCE_CANDIDATE_COST_INVARIANT_VIOLATION"
            }
        }
    }
}

impl fmt::Debug for CandidateResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateResourceError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CandidateResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CandidateResourceError {}

/// Return true only when `left` is no worse in every cost dimension and
/// strictly cheaper in at least one. This utility deliberately has no scalar
/// weighting or quality/effectiveness input.
#[must_use]
pub const fn cost_pareto_dominates(
    left: CandidateResourceEnvelope,
    right: CandidateResourceEnvelope,
) -> bool {
    lower_is_better_pareto_dominates(
        [
            left.unique_candidate_event_count,
            left.unique_candidate_source_bytes,
            left.canonical_candidate_tokens,
            left.wall_time_nanos,
            left.peak_memory_bytes,
        ],
        [
            right.unique_candidate_event_count,
            right.unique_candidate_source_bytes,
            right.canonical_candidate_tokens,
            right.wall_time_nanos,
            right.peak_memory_bytes,
        ],
    )
}

/// Shared lower-is-better Pareto primitive. Equal vectors do not dominate.
pub(crate) const fn lower_is_better_pareto_dominates<const DIMENSIONS: usize>(
    left: [u64; DIMENSIONS],
    right: [u64; DIMENSIONS],
) -> bool {
    let mut index = 0;
    let mut any_less = false;
    while index < DIMENSIONS {
        if left[index] > right[index] {
            return false;
        }
        if left[index] < right[index] {
            any_less = true;
        }
        index += 1;
    }
    any_less
}
