//! Shared V3 streaming compiler orchestration.
//!
//! Acquisition is owned by a `RetainedEventStoreV3`; semantic compilation is
//! always performed by the existing deterministic V1 framer/candidate/selector
//! implementation. Inputs that fit one V3 analysis partition are passed to it
//! unchanged. Larger inputs are reduced at atomic-block boundaries using two
//! bounded deterministic passes with global query frequencies, identifier
//! fanout, failure signals, and acquisition strata.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::time::Instant;

use evidentrail_candidates::{
    MAX_IDENTIFIER_BLOCK_FANOUT_V1, MAX_MANDATORY_BLOCKS_V1, MAX_PRIMARY_BLOCKS_V1,
    preprocess_query_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    EvidenceTargetRef, FetchCompletion, FetchIdentity, LaneKey, LaneSequence, LedgerBuilder,
    PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, ResultId,
    SourceIdentityDigest, UnixTimestampNanos,
};
use evidentrail_framing::{MAX_RECONSTRUCTED_BLOCK_LINES_V1, frame_source_lanes_v1};
use evidentrail_store::{
    RetainedEventStoreErrorV3, RetainedEventStoreV3, RetainedEventViewV3, RetainedPublishedAliasV3,
    RetainedStoreManifestV3,
};
use sha2::{Digest, Sha256};

use crate::{DeterministicProductDecisionV1, MemoryProductV1, ProductError};

pub const MAX_ANALYSIS_PARTITION_BLOCKS_V3: usize = 4_096;
pub const MAX_ANALYSIS_PARTITION_BYTES_V3: u64 = 32 * 1024 * 1024;
pub const MAX_ANALYSIS_PARTITIONS_V3: usize = 4_096;
const REDUCER_WORKING_BYTES_V3: u64 = 7 * 1024 * 1024;
const GLOBAL_STRATA_V3: usize = 8;
const BUILD_CONTEXT_DOMAIN_V3: &[u8] = b"evidentrail/product/streaming-build-context/v3\0";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamingProductErrorV3 {
    Store(RetainedEventStoreErrorV3),
    Product,
    Framing,
    PartitionCapacity,
    Projection,
}

impl StreamingProductErrorV3 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Store(error) => error.code(),
            Self::Product => "EVIDENTRAIL_PRODUCT_V3_COMPILATION_FAILURE",
            Self::Framing => "EVIDENTRAIL_PRODUCT_V3_FRAMING_FAILURE",
            Self::PartitionCapacity => "EVIDENTRAIL_PRODUCT_V3_PARTITION_CAPACITY",
            Self::Projection => "EVIDENTRAIL_PRODUCT_V3_PROJECTION_FAILURE",
        }
    }
}

impl fmt::Debug for StreamingProductErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingProductErrorV3")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for StreamingProductErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for StreamingProductErrorV3 {}

impl From<RetainedEventStoreErrorV3> for StreamingProductErrorV3 {
    fn from(error: RetainedEventStoreErrorV3) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisPlanV3 {
    partition_count: usize,
    source_block_count: usize,
    projected_block_count: usize,
    projected_event_count: usize,
    single_partition_v1_path: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamingPerformanceReceiptV3 {
    pub atomic_framing_nanos: u64,
    pub global_analysis_nanos: u64,
    pub projection_nanos: u64,
    pub v1_compilation_nanos: u64,
    pub seal_and_publication_nanos: u64,
}

impl StreamingPerformanceReceiptV3 {
    #[must_use]
    pub const fn total_elapsed_nanos(self) -> u64 {
        self.atomic_framing_nanos
            .saturating_add(self.global_analysis_nanos)
            .saturating_add(self.projection_nanos)
            .saturating_add(self.v1_compilation_nanos)
            .saturating_add(self.seal_and_publication_nanos)
    }
}

/// Identity and completion facts needed to reconstruct a bounded V1 analysis
/// ledger from authenticated packed events.
#[derive(Clone)]
pub struct StreamingAnalysisContextV3 {
    fetch_identity: FetchIdentity,
    source_identity_digest: SourceIdentityDigest,
    lanes: Vec<StreamingLaneContextV3>,
    completion: FetchCompletion,
}

#[derive(Clone)]
pub struct StreamingLaneContextV3 {
    lane: LaneKey,
    envelope_identity: RawEnvelopeIdentityV1,
}

impl StreamingLaneContextV3 {
    #[must_use]
    pub fn new(lane: LaneKey, envelope_identity: RawEnvelopeIdentityV1) -> Self {
        Self {
            lane,
            envelope_identity,
        }
    }
}

impl StreamingAnalysisContextV3 {
    #[must_use]
    pub fn new(
        fetch_identity: FetchIdentity,
        envelope_identity: RawEnvelopeIdentityV1,
        source_identity_digest: SourceIdentityDigest,
        lane: LaneKey,
        completion: FetchCompletion,
    ) -> Self {
        Self {
            fetch_identity,
            source_identity_digest,
            lanes: vec![StreamingLaneContextV3::new(lane, envelope_identity)],
            completion,
        }
    }

    #[must_use]
    pub fn new_multi_lane(
        fetch_identity: FetchIdentity,
        source_identity_digest: SourceIdentityDigest,
        lanes: Vec<StreamingLaneContextV3>,
        completion: FetchCompletion,
    ) -> Self {
        Self {
            fetch_identity,
            source_identity_digest,
            lanes,
            completion,
        }
    }

    fn lane(&self, ordinal: u64) -> Result<&StreamingLaneContextV3, StreamingProductErrorV3> {
        usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| self.lanes.get(ordinal))
            .ok_or(StreamingProductErrorV3::Projection)
    }
}

impl AnalysisPlanV3 {
    #[must_use]
    pub const fn partition_count(self) -> usize {
        self.partition_count
    }

    #[must_use]
    pub const fn source_block_count(self) -> usize {
        self.source_block_count
    }

    #[must_use]
    pub const fn projected_block_count(self) -> usize {
        self.projected_block_count
    }

    #[must_use]
    pub const fn projected_event_count(self) -> usize {
        self.projected_event_count
    }

    #[must_use]
    pub const fn single_partition_v1_path(self) -> bool {
        self.single_partition_v1_path
    }
}

/// One compiler path over any conforming V3 retained-event backend.
pub struct StreamingProductV3<B> {
    backend: B,
    last_analysis_plan: Option<AnalysisPlanV3>,
    performance_enabled: bool,
    last_performance_receipt: Option<StreamingPerformanceReceiptV3>,
}

impl<B: RetainedEventStoreV3> StreamingProductV3<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            last_analysis_plan: None,
            performance_enabled: false,
            last_performance_receipt: None,
        }
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }

    #[must_use]
    pub const fn last_analysis_plan(&self) -> Option<AnalysisPlanV3> {
        self.last_analysis_plan
    }

    /// Enables contentless engineering instrumentation for subsequent
    /// compilation. It is disabled by default and is non-certifying.
    pub fn enable_performance_instrumentation(&mut self) {
        self.performance_enabled = true;
    }

    #[must_use]
    pub const fn last_performance_receipt(&self) -> Option<StreamingPerformanceReceiptV3> {
        self.last_performance_receipt
    }

    pub fn compile_ledger(
        &mut self,
        result_id: ResultId,
        question: &[u8],
        ledger: EventLedger,
        manifest: RetainedStoreManifestV3,
        now: UnixTimestampNanos,
        total_token_budget: u64,
    ) -> Result<DeterministicProductDecisionV1, StreamingProductErrorV3> {
        let blocks = frame_source_lanes_v1(&ledger)
            .map_err(|_| StreamingProductErrorV3::Framing)?
            .len();
        let plan = AnalysisPlanV3 {
            partition_count: 1,
            source_block_count: blocks,
            projected_block_count: blocks,
            projected_event_count: ledger.len(),
            single_partition_v1_path: true,
        };
        let analysis_ledger = ledger;
        self.last_analysis_plan = Some(plan);
        let published_event_ids = analysis_ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>();
        let mut compiler = MemoryProductV1::new();
        let decision = compiler
            .create_deterministic_result_v1(
                result_id,
                question,
                analysis_ledger,
                now,
                total_token_budget,
            )
            .map_err(map_product_error)?;
        match &decision {
            DeterministicProductDecisionV1::NeedsMore(_) => {
                // A needs-more result has no aliases and no expandable store.
                self.backend.destroy_authority_first()?;
            }
            DeterministicProductDecisionV1::Passthrough(rendered) => {
                let aliases = retained_aliases(rendered.references(), &published_event_ids);
                self.backend.seal_and_publish_aliases(manifest, &aliases)?;
            }
            DeterministicProductDecisionV1::Compiled(rendered) => {
                let aliases = retained_aliases(rendered.references(), &published_event_ids);
                self.backend.seal_and_publish_aliases(manifest, &aliases)?;
            }
        }
        Ok(decision)
    }

    /// Compile from the packed backend without ever constructing a full-input
    /// ledger. At most one analysis partition (or the reducer's bounded
    /// projection) is materialized through the existing V1 compiler.
    pub fn compile_store(
        &mut self,
        result_id: ResultId,
        question: &[u8],
        context: &StreamingAnalysisContextV3,
        manifest: RetainedStoreManifestV3,
        now: UnixTimestampNanos,
        total_token_budget: u64,
    ) -> Result<DeterministicProductDecisionV1, StreamingProductErrorV3> {
        let mut performance = StreamingPerformanceReceiptV3::default();
        let (analysis_ledger, plan) = prepare_store_analysis_v3(
            &self.backend,
            question,
            context,
            self.performance_enabled.then_some(&mut performance),
        )?;
        self.last_analysis_plan = Some(plan);
        let published_event_ids = analysis_ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>();
        let mut compiler = MemoryProductV1::new();
        let compilation_started = self.performance_enabled.then(Instant::now);
        let decision = compiler
            .create_deterministic_result_v1(
                result_id,
                question,
                analysis_ledger,
                now,
                total_token_budget,
            )
            .map_err(map_product_error)?;
        finish_performance_phase(&mut performance.v1_compilation_nanos, compilation_started);
        let publication_started = self.performance_enabled.then(Instant::now);
        match &decision {
            DeterministicProductDecisionV1::NeedsMore(_) => {
                self.backend.destroy_authority_first()?;
            }
            DeterministicProductDecisionV1::Passthrough(rendered) => {
                let aliases = retained_aliases(rendered.references(), &published_event_ids);
                self.backend.seal_and_publish_aliases(manifest, &aliases)?;
            }
            DeterministicProductDecisionV1::Compiled(rendered) => {
                let aliases = retained_aliases(rendered.references(), &published_event_ids);
                self.backend.seal_and_publish_aliases(manifest, &aliases)?;
            }
        }
        finish_performance_phase(
            &mut performance.seal_and_publication_nanos,
            publication_started,
        );
        self.last_performance_receipt = self.performance_enabled.then_some(performance);
        Ok(decision)
    }
}

fn map_product_error(_error: ProductError) -> StreamingProductErrorV3 {
    StreamingProductErrorV3::Product
}

fn retained_aliases<'a>(
    references: impl Iterator<Item = &'a evidentrail_core::EvidenceReferenceV1>,
    block_fallback: &[evidentrail_core::EventId],
) -> Vec<RetainedPublishedAliasV3> {
    references
        .map(|reference| {
            let mut saw_block = false;
            let mut ids = reference
                .targets()
                .iter()
                .filter_map(|target| match target {
                    EvidenceTargetRef::Event(event_id) => Some(*event_id),
                    EvidenceTargetRef::Block(_) => {
                        saw_block = true;
                        None
                    }
                })
                .collect::<Vec<_>>();
            if saw_block {
                ids = block_fallback.to_vec();
            }
            RetainedPublishedAliasV3::new(reference.clone(), ids)
        })
        .collect()
}

#[must_use]
pub fn streaming_product_build_context_v3() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BUILD_CONTEXT_DOMAIN_V3);
    hasher.update((MAX_ANALYSIS_PARTITION_BLOCKS_V3 as u64).to_be_bytes());
    hasher.update(MAX_ANALYSIS_PARTITION_BYTES_V3.to_be_bytes());
    hasher.update((MAX_ANALYSIS_PARTITIONS_V3 as u64).to_be_bytes());
    hasher.update(b"evidentrail-compile/three-lane/v1");
    hasher.update(b"evidentrail-evidence/log-brief/v1");
    hasher.finalize().into()
}

fn prepare_store_analysis_v3<B: RetainedEventStoreV3>(
    backend: &B,
    question: &[u8],
    context: &StreamingAnalysisContextV3,
    mut performance: Option<&mut StreamingPerformanceReceiptV3>,
) -> Result<(EventLedger, AnalysisPlanV3), StreamingProductErrorV3> {
    let atomic_started = performance.as_ref().map(|_| Instant::now());
    let query = preprocess_query_v1(question).map_err(|_| StreamingProductErrorV3::Projection)?;
    let blocks = discover_atomic_blocks_v3(backend, context)?;
    if let Some(receipt) = performance.as_mut() {
        finish_performance_phase(&mut receipt.atomic_framing_nanos, atomic_started);
    }
    let global_started = performance.as_ref().map(|_| Instant::now());
    if blocks.is_empty() {
        return Err(StreamingProductErrorV3::PartitionCapacity);
    }
    let mut partition_count = 1usize;
    let mut partition_blocks = 0usize;
    let mut partition_bytes = 0u64;
    for block in &blocks {
        if partition_blocks > 0
            && (partition_blocks == MAX_ANALYSIS_PARTITION_BLOCKS_V3
                || partition_bytes.saturating_add(block.exact_bytes)
                    > MAX_ANALYSIS_PARTITION_BYTES_V3)
        {
            partition_count = partition_count
                .checked_add(1)
                .ok_or(StreamingProductErrorV3::PartitionCapacity)?;
            partition_blocks = 0;
            partition_bytes = 0;
        }
        partition_blocks += 1;
        partition_bytes = partition_bytes.saturating_add(block.exact_bytes);
    }
    if partition_count > MAX_ANALYSIS_PARTITIONS_V3 {
        return Err(StreamingProductErrorV3::PartitionCapacity);
    }

    let event_count = usize::try_from(
        blocks
            .iter()
            .map(|block| block.acquisition_ordinals.len() as u64)
            .sum::<u64>(),
    )
    .map_err(|_| StreamingProductErrorV3::PartitionCapacity)?;
    let mut event_to_block = vec![usize::MAX; event_count];
    for (block_index, block) in blocks.iter().enumerate() {
        for ordinal in &block.acquisition_ordinals {
            let position = usize::try_from(*ordinal)
                .map_err(|_| StreamingProductErrorV3::PartitionCapacity)?;
            let owner = event_to_block
                .get_mut(position)
                .ok_or(StreamingProductErrorV3::PartitionCapacity)?;
            if *owner != usize::MAX {
                return Err(StreamingProductErrorV3::Projection);
            }
            *owner = block_index;
        }
    }
    if event_to_block.contains(&usize::MAX) {
        return Err(StreamingProductErrorV3::Projection);
    }

    let mut term_blocks = vec![BTreeSet::<usize>::new(); query.terms().len()];
    let mut identifier_matches = vec![BTreeSet::<usize>::new(); query.identifiers().len()];
    let mut failure_blocks = vec![false; blocks.len()];
    let retained_fanout = MAX_IDENTIFIER_BLOCK_FANOUT_V1
        .saturating_add(1)
        .max(MAX_PRIMARY_BLOCKS_V1);
    backend.acquisition_scan(&mut |view| {
        let locator = view.locator();
        let block = *event_to_block
            .get(locator.acquisition_ordinal() as usize)
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        for (position, term) in query.terms().iter().enumerate() {
            if contains_ascii_token(view.exact_bytes(), term.canonical_token()) {
                term_blocks[position].insert(block);
            }
        }
        for (position, identifier) in query.identifiers().iter().enumerate() {
            if identifier_matches[position].len() < retained_fanout
                && contains_ascii_token(view.exact_bytes(), identifier.canonical_token())
            {
                identifier_matches[position].insert(block);
            }
        }
        failure_blocks[block] |= has_failure_signal(view.exact_bytes());
        Ok(())
    })?;

    let single_partition = partition_count == 1;
    let selected_blocks = if single_partition {
        (0..blocks.len()).collect::<BTreeSet<_>>()
    } else {
        let mut mandatory = BTreeSet::new();
        for matches in &identifier_matches {
            if matches.len() <= MAX_IDENTIFIER_BLOCK_FANOUT_V1 {
                mandatory.extend(matches.iter().copied());
            } else {
                mandatory.extend(matches.iter().take(MAX_PRIMARY_BLOCKS_V1).copied());
            }
        }
        if mandatory.len() > MAX_MANDATORY_BLOCKS_V1 {
            mandatory = mandatory.into_iter().take(MAX_PRIMARY_BLOCKS_V1).collect();
        }
        let document_count = blocks.len() as u64;
        let mut ranked = (0..blocks.len())
            .map(|block| {
                let mut score = if mandatory.contains(&block) {
                    u64::MAX / 2
                } else {
                    0
                };
                for matching in &term_blocks {
                    if matching.contains(&block) {
                        score = score.saturating_add(
                            document_count
                                .saturating_sub(matching.len() as u64)
                                .saturating_add(1),
                        );
                    }
                }
                if failure_blocks[block] {
                    score = score.saturating_add(document_count.max(1).saturating_mul(2));
                }
                (score, block)
            })
            .collect::<Vec<_>>();
        ranked.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
        });
        let mut selected = mandatory;
        selected.extend(stratified_blocks(blocks.len()));
        let mut selected_bytes = selected.iter().fold(0u64, |total, block| {
            total.saturating_add(blocks[*block].exact_bytes)
        });
        for (_, block) in ranked {
            if selected.len() >= MAX_PRIMARY_BLOCKS_V1 {
                break;
            }
            if selected.contains(&block) {
                continue;
            }
            let next = selected_bytes.saturating_add(blocks[block].exact_bytes);
            if next <= REDUCER_WORKING_BYTES_V3 {
                selected.insert(block);
                selected_bytes = next;
            }
        }
        selected
    };
    let selected = selected_blocks
        .iter()
        .flat_map(|block| blocks[*block].acquisition_ordinals.iter().copied())
        .collect::<BTreeSet<_>>();

    if let Some(receipt) = performance.as_mut() {
        finish_performance_phase(&mut receipt.global_analysis_nanos, global_started);
    }
    let projection_started = performance.as_ref().map(|_| Instant::now());

    let mut builder = if single_partition {
        LedgerBuilder::new(
            context.fetch_identity.clone(),
            context.source_identity_digest,
            SourceExactAnalysisPolicyV3,
        )
    } else {
        LedgerBuilder::new_analysis_projection_v3(
            context.fetch_identity.clone(),
            context.source_identity_digest,
            SourceExactAnalysisPolicyV3,
        )
    };
    let mut selected_records = 0u64;
    let mut selected_payload_bytes = 0u64;
    let mut selected_source_bytes = 0u64;
    backend.acquisition_scan(&mut |view: RetainedEventViewV3<'_>| {
        let locator = view.locator();
        if !selected.contains(&locator.acquisition_ordinal()) {
            return Ok(());
        }
        let record = if locator.terminator_len() == 0 {
            RecordBytes::whole(view.payload().to_vec())
        } else {
            RecordBytes::framed(view.payload().to_vec(), view.terminator().to_vec())
        };
        let acknowledgement = builder
            .accept(RawEnvelopeV1::new(
                context
                    .lane(locator.lane_ordinal())
                    .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?
                    .envelope_identity
                    .clone(),
                EnvelopeOrdering::new(
                    evidentrail_core::AcquisitionSequence::new(locator.acquisition_ordinal()),
                    context
                        .lane(locator.lane_ordinal())
                        .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?
                        .lane
                        .clone(),
                    LaneSequence::new(locator.lane_sequence()),
                ),
                record,
                RecordState::Complete,
            ))
            .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        if acknowledgement.outcome().persisted_event_id() != Some(locator.event_id()) {
            return Err(RetainedEventStoreErrorV3::CorruptIndex);
        }
        selected_records = selected_records.saturating_add(1);
        selected_payload_bytes =
            selected_payload_bytes.saturating_add(u64::from(locator.payload_len()));
        selected_source_bytes =
            selected_source_bytes.saturating_add(u64::from(locator.exact_len()));
        Ok(())
    })?;
    let completion = FetchCompletion::new(
        context.fetch_identity.clone(),
        context.completion.timing(),
        AcknowledgedCounts::new(
            selected_records,
            selected_payload_bytes,
            selected_source_bytes,
        ),
        context.completion.member_counts(),
        context.completion.page_counts(),
        context.completion.boundaries().clone(),
        context.completion.cap_usage().iter().copied(),
        context.completion.adapter_outcome(),
        context.completion.error_codes().iter().copied(),
        context.completion.completeness().clone(),
    )
    .map_err(|_| StreamingProductErrorV3::Projection)?;
    let ledger = builder
        .seal(completion)
        .map_err(|_| StreamingProductErrorV3::Projection)?
        .with_analysis_completion_v3(context.completion.clone())
        .map_err(|_| StreamingProductErrorV3::Projection)?;
    let projected_blocks = frame_source_lanes_v1(&ledger)
        .map_err(|_| StreamingProductErrorV3::Framing)?
        .len();
    if let Some(receipt) = performance.as_mut() {
        finish_performance_phase(&mut receipt.projection_nanos, projection_started);
    }
    Ok((
        ledger,
        AnalysisPlanV3 {
            partition_count,
            source_block_count: blocks.len(),
            projected_block_count: projected_blocks,
            projected_event_count: selected.len(),
            single_partition_v1_path: single_partition,
        },
    ))
}

fn finish_performance_phase(output: &mut u64, started: Option<Instant>) {
    if let Some(started) = started {
        *output = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    }
}

#[derive(Clone)]
struct BufferedEventV3 {
    locator: evidentrail_store::RetainedEventLocatorV3,
    exact_bytes: Vec<u8>,
}

struct AtomicBlockV3 {
    acquisition_ordinals: Vec<u64>,
    exact_bytes: u64,
}

fn discover_atomic_blocks_v3<B: RetainedEventStoreV3>(
    backend: &B,
    context: &StreamingAnalysisContextV3,
) -> Result<Vec<AtomicBlockV3>, StreamingProductErrorV3> {
    let mut blocks = Vec::new();
    let mut buffer = Vec::<BufferedEventV3>::new();
    let mut buffer_bytes = 0u64;
    let mut lane = None;
    backend.lane_scan(&mut |view| {
        let locator = view.locator();
        if lane.is_some_and(|lane| lane != locator.lane_ordinal()) {
            flush_atomic_buffer_v3(&mut buffer, &mut buffer_bytes, true, context, &mut blocks)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        }
        lane = Some(locator.lane_ordinal());
        if locator.exact_len() as usize > evidentrail_framing::MAX_RECONSTRUCTED_BLOCK_BYTES_V1 {
            flush_atomic_buffer_v3(&mut buffer, &mut buffer_bytes, true, context, &mut blocks)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            blocks.push(AtomicBlockV3 {
                acquisition_ordinals: vec![locator.acquisition_ordinal()],
                exact_bytes: u64::from(locator.exact_len()),
            });
            return Ok(());
        }
        buffer_bytes = buffer_bytes.saturating_add(u64::from(locator.exact_len()));
        buffer.push(BufferedEventV3 {
            locator,
            exact_bytes: view.exact_bytes().to_vec(),
        });
        if buffer.len() >= MAX_ANALYSIS_PARTITION_BLOCKS_V3 + MAX_RECONSTRUCTED_BLOCK_LINES_V1 + 2
            || buffer_bytes
                > MAX_ANALYSIS_PARTITION_BYTES_V3
                    + 2 * evidentrail_framing::MAX_RECONSTRUCTED_BLOCK_BYTES_V1 as u64
        {
            flush_atomic_buffer_v3(&mut buffer, &mut buffer_bytes, false, context, &mut blocks)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        }
        Ok(())
    })?;
    flush_atomic_buffer_v3(&mut buffer, &mut buffer_bytes, true, context, &mut blocks)?;
    Ok(blocks)
}

fn flush_atomic_buffer_v3(
    buffer: &mut Vec<BufferedEventV3>,
    buffer_bytes: &mut u64,
    finalize: bool,
    context: &StreamingAnalysisContextV3,
    output: &mut Vec<AtomicBlockV3>,
) -> Result<(), StreamingProductErrorV3> {
    if buffer.is_empty() {
        return Ok(());
    }
    let ledger = buffered_ledger_v3(buffer, context)?;
    let framed = frame_source_lanes_v1(&ledger).map_err(|_| StreamingProductErrorV3::Framing)?;
    let emit = if finalize {
        framed.blocks().len()
    } else {
        framed.blocks().len().saturating_sub(1)
    };
    for block in &framed.blocks()[..emit] {
        let mut acquisitions = Vec::with_capacity(block.len());
        let mut exact_bytes = 0u64;
        for position in block.member_positions() {
            let event = buffer
                .get(*position)
                .ok_or(StreamingProductErrorV3::Projection)?;
            acquisitions.push(event.locator.acquisition_ordinal());
            exact_bytes = exact_bytes.saturating_add(u64::from(event.locator.exact_len()));
        }
        output.push(AtomicBlockV3 {
            acquisition_ordinals: acquisitions,
            exact_bytes,
        });
    }
    let keep_from = if emit == framed.blocks().len() {
        buffer.len()
    } else {
        *framed.blocks()[emit]
            .member_positions()
            .first()
            .ok_or(StreamingProductErrorV3::Projection)?
    };
    buffer.drain(..keep_from);
    *buffer_bytes = buffer.iter().fold(0u64, |total, event| {
        total.saturating_add(u64::from(event.locator.exact_len()))
    });
    Ok(())
}

fn buffered_ledger_v3(
    buffer: &[BufferedEventV3],
    context: &StreamingAnalysisContextV3,
) -> Result<EventLedger, StreamingProductErrorV3> {
    let mut builder = LedgerBuilder::new_analysis_projection_v3(
        context.fetch_identity.clone(),
        context.source_identity_digest,
        SourceExactAnalysisPolicyV3,
    );
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;
    for event in buffer {
        let locator = event.locator;
        let lane = context.lane(locator.lane_ordinal())?;
        let payload_len = locator.payload_len() as usize;
        let record = if locator.terminator_len() == 0 {
            RecordBytes::whole(event.exact_bytes[..payload_len].to_vec())
        } else {
            RecordBytes::framed(
                event.exact_bytes[..payload_len].to_vec(),
                event.exact_bytes[payload_len..].to_vec(),
            )
        };
        let acknowledgement = builder
            .accept(RawEnvelopeV1::new(
                lane.envelope_identity.clone(),
                EnvelopeOrdering::new(
                    evidentrail_core::AcquisitionSequence::new(locator.acquisition_ordinal()),
                    lane.lane.clone(),
                    LaneSequence::new(locator.lane_sequence()),
                ),
                record,
                RecordState::Complete,
            ))
            .map_err(|_| StreamingProductErrorV3::Projection)?;
        if acknowledgement.outcome().persisted_event_id() != Some(locator.event_id()) {
            return Err(StreamingProductErrorV3::Projection);
        }
        payload_bytes = payload_bytes.saturating_add(u64::from(locator.payload_len()));
        source_bytes = source_bytes.saturating_add(u64::from(locator.exact_len()));
    }
    let completion =
        projected_completion_v3(context, buffer.len() as u64, payload_bytes, source_bytes)?;
    builder
        .seal(completion)
        .map_err(|_| StreamingProductErrorV3::Projection)?
        .with_analysis_completion_v3(context.completion.clone())
        .map_err(|_| StreamingProductErrorV3::Projection)
}

fn projected_completion_v3(
    context: &StreamingAnalysisContextV3,
    records: u64,
    payload_bytes: u64,
    source_bytes: u64,
) -> Result<FetchCompletion, StreamingProductErrorV3> {
    FetchCompletion::new(
        context.fetch_identity.clone(),
        context.completion.timing(),
        AcknowledgedCounts::new(records, payload_bytes, source_bytes),
        context.completion.member_counts(),
        context.completion.page_counts(),
        context.completion.boundaries().clone(),
        context.completion.cap_usage().iter().copied(),
        context.completion.adapter_outcome(),
        context.completion.error_codes().iter().copied(),
        context.completion.completeness().clone(),
    )
    .map_err(|_| StreamingProductErrorV3::Projection)
}

#[derive(Clone, Copy)]
struct SourceExactAnalysisPolicyV3;

impl DeterministicPolicy for SourceExactAnalysisPolicyV3 {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn stratified_blocks(block_count: usize) -> Vec<usize> {
    if block_count == 0 {
        return Vec::new();
    }
    (0..GLOBAL_STRATA_V3)
        .map(|stratum| {
            ((2 * stratum + 1) * block_count / (2 * GLOBAL_STRATA_V3)).min(block_count - 1)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn contains_ascii_token(raw: &[u8], needle: &[u8]) -> bool {
    raw.split(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-' && *byte != b'_')
        .any(|token| token.eq_ignore_ascii_case(needle))
}

fn has_failure_signal(raw: &[u8]) -> bool {
    [
        b"error".as_slice(),
        b"exception",
        b"failed",
        b"fatal",
        b"panic",
        b"traceback",
    ]
    .iter()
    .any(|needle| contains_ascii_token(raw, needle))
}
