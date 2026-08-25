use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, Instant};

use crate::Cancellation;

/// Monotonic time source used at cooperative I/O boundaries.
///
/// The instant has no wall-clock meaning. Tests can supply a deterministic
/// clock without sleeping, while production uses [`SystemMonotonicClock`].
pub trait MonotonicClock {
    type Instant: Copy + Ord;

    fn now(&self) -> Self::Instant;

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant>;
}

/// Production monotonic clock backed by [`Instant`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemMonotonicClock;

impl MonotonicClock for SystemMonotonicClock {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant> {
        instant.checked_add(Duration::from_millis(wall_time_millis))
    }
}

/// Fixed non-sliding deadline captured once at execution entry.
///
/// This type does not make a synchronous read or sink call preemptible. The
/// adapter must call [`Self::checkpoint`] before and after every such call and
/// stop before beginning the next one after a terminal result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CooperativeDeadline<I> {
    deadline: I,
    wall_time_millis: u64,
}

impl<I> CooperativeDeadline<I>
where
    I: Copy + Ord,
{
    pub fn start<C>(clock: &C, wall_time_millis: u64) -> Result<Self, DeadlineConstructionError>
    where
        C: MonotonicClock<Instant = I>,
    {
        if wall_time_millis == 0 {
            return Err(DeadlineConstructionError::ZeroWallTime);
        }
        let started_at = clock.now();
        let deadline = clock
            .checked_add_millis(started_at, wall_time_millis)
            .ok_or(DeadlineConstructionError::InstantOverflow)?;
        Ok(Self {
            deadline,
            wall_time_millis,
        })
    }

    /// Observe cancellation and elapsed time at one cooperative boundary.
    ///
    /// Cancellation has deterministic precedence when both conditions are
    /// visible at the same checkpoint. Deadline equality is terminal: the
    /// deadline is an exclusive upper bound.
    #[must_use]
    pub fn checkpoint<C, X>(&self, clock: &C, cancellation: &X) -> CooperativeStopReason
    where
        C: MonotonicClock<Instant = I>,
        X: Cancellation + ?Sized,
    {
        if cancellation.is_cancelled() {
            CooperativeStopReason::Cancelled
        } else if clock.now() >= self.deadline {
            CooperativeStopReason::WallTimeCap
        } else {
            CooperativeStopReason::Continue
        }
    }

    #[must_use]
    pub const fn wall_time_millis(self) -> u64 {
        self.wall_time_millis
    }
}

impl<I> fmt::Debug for CooperativeDeadline<I> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeDeadline")
            .field("deadline_present", &true)
            .field("wall_time_present", &true)
            .finish()
    }
}

/// Result of a cooperative cancellation/deadline checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CooperativeStopReason {
    Continue,
    Cancelled,
    WallTimeCap,
}

impl CooperativeStopReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Cancelled => "cancelled",
            Self::WallTimeCap => "wall_time_cap",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Continue)
    }
}

/// Invalid fixed-deadline construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeadlineConstructionError {
    ZeroWallTime,
    InstantOverflow,
}

impl DeadlineConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroWallTime => "EVIDENTRAIL_INGEST_DEADLINE_ZERO_WALL_TIME",
            Self::InstantOverflow => "EVIDENTRAIL_INGEST_DEADLINE_INSTANT_OVERFLOW",
        }
    }
}

impl fmt::Debug for DeadlineConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadlineConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for DeadlineConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for DeadlineConstructionError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct FakeClock {
        now: Cell<u64>,
    }

    impl FakeClock {
        fn new(now: u64) -> Self {
            Self {
                now: Cell::new(now),
            }
        }

        fn set(&self, now: u64) {
            self.now.set(now);
        }
    }

    impl MonotonicClock for FakeClock {
        type Instant = u64;

        fn now(&self) -> Self::Instant {
            self.now.get()
        }

        fn checked_add_millis(
            &self,
            instant: Self::Instant,
            wall_time_millis: u64,
        ) -> Option<Self::Instant> {
            instant.checked_add(wall_time_millis)
        }
    }

    struct FixedCancellation(bool);

    impl Cancellation for FixedCancellation {
        fn is_cancelled(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn deadline_is_fixed_non_sliding_and_exclusive() {
        let clock = FakeClock::new(100);
        let deadline = CooperativeDeadline::start(&clock, 25).unwrap();
        assert_eq!(deadline.wall_time_millis(), 25);
        assert_eq!(
            deadline.checkpoint(&clock, &FixedCancellation(false)),
            CooperativeStopReason::Continue
        );

        clock.set(124);
        assert_eq!(
            deadline.checkpoint(&clock, &FixedCancellation(false)),
            CooperativeStopReason::Continue
        );
        clock.set(125);
        assert_eq!(
            deadline.checkpoint(&clock, &FixedCancellation(false)),
            CooperativeStopReason::WallTimeCap
        );
        clock.set(126);
        assert_eq!(
            deadline.checkpoint(&clock, &FixedCancellation(false)),
            CooperativeStopReason::WallTimeCap
        );
    }

    #[test]
    fn cancellation_has_stable_precedence_at_a_checkpoint() {
        let clock = FakeClock::new(10);
        let deadline = CooperativeDeadline::start(&clock, 1).unwrap();
        clock.set(11);
        assert_eq!(
            deadline.checkpoint(&clock, &FixedCancellation(true)),
            CooperativeStopReason::Cancelled
        );
    }

    #[test]
    fn invalid_deadlines_fail_before_execution() {
        let clock = FakeClock::new(u64::MAX);
        assert_eq!(
            CooperativeDeadline::start(&clock, 0),
            Err(DeadlineConstructionError::ZeroWallTime)
        );
        assert_eq!(
            CooperativeDeadline::start(&clock, 1),
            Err(DeadlineConstructionError::InstantOverflow)
        );
    }

    #[test]
    fn diagnostics_do_not_expose_monotonic_instants_or_caps() {
        let clock = FakeClock::new(7_777_777);
        let deadline = CooperativeDeadline::start(&clock, 8_888_888).unwrap();
        let debug = format!("{deadline:?}");
        assert_eq!(
            debug,
            "CooperativeDeadline { deadline_present: true, wall_time_present: true }"
        );
        assert!(!debug.contains("7777777"));
        assert!(!debug.contains("8888888"));

        let error = CooperativeDeadline::start(&clock, 0).unwrap_err();
        assert_eq!(error.to_string(), error.code());
    }
}
