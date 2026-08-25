use std::error::Error as StdError;
use std::fmt;

/// A contentless failure detected before a terminal fetch fact can be made.
///
/// Once source acquisition starts, operational termination is returned as a
/// checked `FetchCompletion` instead of an error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IngestError {
    InvalidLimit,
    InvalidFetchCompletion,
    InvalidReplayFixture,
}

impl IngestError {
    /// Stable contentless diagnostic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimit => "EVIDENTRAIL_INGEST_INVALID_LIMIT",
            Self::InvalidFetchCompletion => "EVIDENTRAIL_INGEST_INVALID_FETCH_COMPLETION",
            Self::InvalidReplayFixture => "EVIDENTRAIL_INGEST_INVALID_REPLAY_FIXTURE",
        }
    }
}

impl fmt::Debug for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngestError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for IngestError {}
