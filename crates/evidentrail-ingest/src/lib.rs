//! Shared ingestion seams and deterministic in-memory replay for Evidentrail.
//!
//! Production local-file acquisition lives in `evidentrail-local-file`, where a
//! registry-authorized, descriptor-retaining preflight token is required. The
//! historical path-based file adapter is intentionally not compiled or
//! exported from this crate.

mod adapter;
mod batch;
mod cloudwatch;
#[cfg(feature = "cloudwatch-sdk")]
mod cloudwatch_sdk;
mod datadog;
mod deadline;
mod error;
mod full_history;
mod kubernetes;
mod replay;

pub use adapter::{Cancellation, CancellationToken, ExecutionContext, SourceAdapter};
pub use batch::{
    BatchConstructionErrorV1, BatchOperationIdV1, BatchSinkErrorCodeV1, BatchSinkErrorV1,
    EnvelopeBatchAcknowledgementsV1, EnvelopeBatchSinkV1, EnvelopeBatchV1,
    MAX_ENVELOPES_PER_BATCH_V1, SingleEnvelopeBatchSinkV1, SingleEnvelopeSourceAdapterV1,
    SourceBatchAdapterV1,
};
pub use cloudwatch::{
    CLOUDWATCH_ADAPTER_KIND_V1, CLOUDWATCH_ADAPTER_VERSION_V1, CloudWatchAdapterV1,
    CloudWatchCapsV1, CloudWatchEventV1, CloudWatchFilterRequestV1, CloudWatchHistorySourceV1,
    CloudWatchPageV1, CloudWatchPlanErrorV1, CloudWatchPlanV1, CloudWatchTransportErrorV1,
    CloudWatchTransportV1,
};
#[cfg(feature = "cloudwatch-sdk")]
pub use cloudwatch_sdk::AwsCloudWatchTransportV1;
pub use datadog::{DatadogHistorySourceV1, DatadogSiteV1, DatadogStorageTierV1};
pub use deadline::{
    CooperativeDeadline, CooperativeStopReason, DeadlineConstructionError, MonotonicClock,
    SystemMonotonicClock,
};
pub use error::IngestError;
pub use full_history::{
    HistoryCheckpointV1, HistoryPageSourceV1, HistoryPageStoreV1, HistoryPageV1,
    HistoryPartitionV1, HistoryRecordV1, HistorySyncErrorV1, HistorySyncLimitsV1,
    HistorySyncReceiptV1, HistorySyncStatusV1, reconcile_history_range_v1, reconcile_history_v1,
    synchronize_history_v1,
};
pub use kubernetes::{
    KUBERNETES_ADAPTER_KIND_V1, KUBERNETES_ADAPTER_VERSION_V1, KubernetesAdapterV1,
    KubernetesCapsV1, KubernetesContainerInstanceKindV1, KubernetesContainerInstanceV1,
    KubernetesContainerObservationV1, KubernetesLogRecordV1, KubernetesLogRequestV1,
    KubernetesLogResponseV1, KubernetesLogStreamV1, KubernetesPlanErrorV1, KubernetesPlanV1,
    KubernetesTransportErrorV1, KubernetesTransportV1,
};
pub use replay::InMemoryReplayAdapter;

pub use evidentrail_core::EnvelopeSink;
pub use evidentrail_schema::bounds::MAX_AUTHORIZED_RECORD_BYTES;
pub use evidentrail_schema::{FetchCompletion, RawEnvelopeV1};
