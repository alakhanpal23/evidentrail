use std::fmt;

/// Why a provider retrieval did not return a provably complete bounded result.
#[derive(Clone, PartialEq, Eq)]
pub enum PartialReason {
    RowCap,
    ProviderCap,
    SourceByteCap,
    ExpandedByteCap,
    PageCap,
    WallTimeCap,
    RecordCountCap,
    BackpressureLimit,
    SourceChanged,
    SourceDisappeared,
    RecordTruncated,
    ProviderTruncation,
    SourceReadError,
    PaginationIncomplete,
    Timeout,
    PermissionLimited,
    AuthenticationChanged,
    RetentionBoundary,
    Sampled,
    Cancelled,
    ChildExitFailure,
    ChildKilled,
    NetworkFailure,
    MalformedProviderFraming,
    DecompressionLimit,
    SinkFailure,
    OtherVersioned { version: u16, code: u16 },
}

impl PartialReason {
    /// Stable contentless reason code suitable for diagnostics.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RowCap => "row_cap",
            Self::ProviderCap => "provider_cap",
            Self::SourceByteCap => "source_byte_cap",
            Self::ExpandedByteCap => "expanded_byte_cap",
            Self::PageCap => "page_cap",
            Self::WallTimeCap => "wall_time_cap",
            Self::RecordCountCap => "record_count_cap",
            Self::BackpressureLimit => "backpressure_limit",
            Self::SourceChanged => "source_changed",
            Self::SourceDisappeared => "source_disappeared",
            Self::RecordTruncated => "record_truncated",
            Self::ProviderTruncation => "provider_truncation",
            Self::SourceReadError => "source_read_error",
            Self::PaginationIncomplete => "pagination_incomplete",
            Self::Timeout => "timeout",
            Self::PermissionLimited => "permission_limited",
            Self::AuthenticationChanged => "authentication_changed",
            Self::RetentionBoundary => "retention_boundary",
            Self::Sampled => "sampled",
            Self::Cancelled => "cancelled",
            Self::ChildExitFailure => "child_exit_failure",
            Self::ChildKilled => "child_killed",
            Self::NetworkFailure => "network_failure",
            Self::MalformedProviderFraming => "malformed_provider_framing",
            Self::DecompressionLimit => "decompression_limit",
            Self::SinkFailure => "sink_failure",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for PartialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartialReason")
            .field("code", &self.code())
            .finish()
    }
}

/// A structurally non-empty collection of partial-acquisition reasons.
///
/// The first reason is stored separately, so no public or internal constructor
/// can accidentally create an empty partial status.
#[derive(Clone, PartialEq, Eq)]
pub struct PartialReasons {
    first: PartialReason,
    additional: Vec<PartialReason>,
}

impl PartialReasons {
    #[must_use]
    pub fn new(first: PartialReason) -> Self {
        Self {
            first,
            additional: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_additional(
        first: PartialReason,
        additional: impl IntoIterator<Item = PartialReason>,
    ) -> Self {
        Self {
            first,
            additional: additional.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn first(&self) -> &PartialReason {
        &self.first
    }

    pub fn iter(&self) -> impl Iterator<Item = &PartialReason> {
        std::iter::once(&self.first).chain(self.additional.iter())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.additional.len()
    }

    /// A PartialReasons value is non-empty by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for PartialReasons {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let codes = self.iter().map(PartialReason::code).collect::<Vec<_>>();
        formatter
            .debug_struct("PartialReasons")
            .field("count", &self.len())
            .field("codes", &codes)
            .finish()
    }
}

/// Why provider-side completeness could not be established.
///
/// These variants deliberately carry no free-form provider text. Their stable
/// codes may be emitted in contentless diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnknownCompletenessReason {
    ProviderDoesNotReport,
    AdapterCannotVerify,
    RetrievalBoundaryIndeterminate,
    ProviderHasNoCompletenessProof,
    RetentionUnobservable,
    HighWaterMarkUnverifiable,
    EventuallyConsistentWindow,
    LiveStreamOpenEnded,
    AdapterCapabilityLimit,
}

impl UnknownCompletenessReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderDoesNotReport => "provider_does_not_report",
            Self::AdapterCannotVerify => "adapter_cannot_verify",
            Self::RetrievalBoundaryIndeterminate => "retrieval_boundary_indeterminate",
            Self::ProviderHasNoCompletenessProof => "provider_has_no_completeness_proof",
            Self::RetentionUnobservable => "retention_unobservable",
            Self::HighWaterMarkUnverifiable => "high_water_mark_unverifiable",
            Self::EventuallyConsistentWindow => "eventually_consistent_window",
            Self::LiveStreamOpenEnded => "live_stream_open_ended",
            Self::AdapterCapabilityLimit => "adapter_capability_limit",
        }
    }
}

impl fmt::Debug for UnknownCompletenessReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnknownCompletenessReason")
            .field("code", &self.code())
            .finish()
    }
}

/// Provider-side completeness is separate from Evidentrail's accounting of records
/// it actually received. A valid coverage receipt cannot turn `Partial` or
/// `Unknown` into `Complete`.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderCompleteness {
    Complete,
    Partial {
        reasons: PartialReasons,
        detail: Option<String>,
        continuation: Option<Vec<u8>>,
    },
    Unknown {
        reason: UnknownCompletenessReason,
    },
}

impl ProviderCompleteness {
    #[must_use]
    pub fn partial(reason: PartialReason) -> Self {
        Self::Partial {
            reasons: PartialReasons::new(reason),
            detail: None,
            continuation: None,
        }
    }

    #[must_use]
    pub fn partial_with_context(
        reason: PartialReason,
        detail: Option<String>,
        continuation: Option<Vec<u8>>,
    ) -> Self {
        Self::Partial {
            reasons: PartialReasons::new(reason),
            detail,
            continuation,
        }
    }

    #[must_use]
    pub fn partial_with_reasons(
        first_reason: PartialReason,
        additional_reasons: impl IntoIterator<Item = PartialReason>,
        detail: Option<String>,
        continuation: Option<Vec<u8>>,
    ) -> Self {
        Self::Partial {
            reasons: PartialReasons::with_additional(first_reason, additional_reasons),
            detail,
            continuation,
        }
    }

    #[must_use]
    pub const fn unknown(reason: UnknownCompletenessReason) -> Self {
        Self::Unknown { reason }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }
}

impl fmt::Debug for ProviderCompleteness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("ProviderCompleteness");
        match self {
            Self::Complete => {
                summary.field("status", &"complete");
            }
            Self::Partial {
                reasons,
                detail,
                continuation,
            } => {
                summary
                    .field("status", &"partial")
                    .field("reasons", reasons)
                    .field("detail_present", &detail.is_some())
                    .field("continuation_present", &continuation.is_some());
            }
            Self::Unknown { reason } => {
                summary
                    .field("status", &"unknown")
                    .field("reason_code", &reason.code());
            }
        }
        summary.finish()
    }
}
