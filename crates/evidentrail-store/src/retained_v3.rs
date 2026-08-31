//! Packed retained-event storage contract for the streaming V3 product.
//!
//! The contract keeps acquisition ordering separate from publication. A store
//! is never expandable before a successful `seal_and_publish`, and destruction
//! revokes authority before releasing backing bytes. The memory implementation
//! uses one byte arena, fixed-width metadata, and sorted locator arrays; it
//! performs no filesystem I/O.

use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::EvidenceReferenceV1;
use evidentrail_schema::{EventId, ResultId};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAX_STREAM_RECORDS_V3: u64 = 1_000_000;
pub const MAX_STREAM_SOURCE_BYTES_V3: u64 = 1024 * 1024 * 1024;
pub const MAX_EVENTS_PER_PAGE_V3: usize = 4_096;
pub const TARGET_PAGE_PLAINTEXT_BYTES_V3: usize = 1024 * 1024;
pub const CHECKPOINT_RECORD_INTERVAL_V3: u64 = 65_536;
pub const CHECKPOINT_BYTE_INTERVAL_V3: u64 = 64 * 1024 * 1024;

const MANIFEST_DOMAIN_V3: &[u8] = b"evidentrail/retained-event-store/manifest/v3\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RetainedEventStoreStateV3 {
    Empty,
    Open,
    DataCommitted,
    Sealed,
    Published,
    Destroyed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RetainedEventStoreErrorV3 {
    InvalidState,
    InvalidInput,
    DuplicateEvent,
    CapacityExceeded,
    CorruptIndex,
    NotFound,
    NotPublished,
    AuthorityUnavailable,
    AuthorityLocked,
    ObsoleteFormat,
    IoFailure,
    FaultInjected,
}

impl RetainedEventStoreErrorV3 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidState => "EVIDENTRAIL_STORE_V3_INVALID_STATE",
            Self::InvalidInput => "EVIDENTRAIL_STORE_V3_INVALID_INPUT",
            Self::DuplicateEvent => "EVIDENTRAIL_STORE_V3_DUPLICATE_EVENT",
            Self::CapacityExceeded => "EVIDENTRAIL_STORE_V3_CAPACITY_EXCEEDED",
            Self::CorruptIndex => "EVIDENTRAIL_STORE_V3_CORRUPT_INDEX",
            Self::NotFound => "EVIDENTRAIL_STORE_V3_NOT_FOUND",
            Self::NotPublished => "EVIDENTRAIL_STORE_V3_NOT_PUBLISHED",
            Self::AuthorityUnavailable => "EVIDENTRAIL_STORE_V3_AUTHORITY_UNAVAILABLE",
            Self::AuthorityLocked => "EVIDENTRAIL_STORE_V3_AUTHORITY_LOCKED",
            Self::ObsoleteFormat => "EVIDENTRAIL_STORE_V3_OBSOLETE_FORMAT",
            Self::IoFailure => "EVIDENTRAIL_STORE_V3_IO_FAILURE",
            Self::FaultInjected => "EVIDENTRAIL_STORE_V3_FAULT_INJECTED",
        }
    }
}

impl fmt::Debug for RetainedEventStoreErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedEventStoreErrorV3")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for RetainedEventStoreErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RetainedEventStoreErrorV3 {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetainedStoreBeginV3 {
    pub result_id: ResultId,
    pub namespace: [u8; 32],
    pub created_unix_nanos: i128,
    pub expires_unix_nanos: i128,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetainedEventInputV3<'a> {
    pub event_id: EventId,
    pub acquisition_ordinal: u64,
    /// Stable index of the source lane in the acquisition descriptor.
    pub lane_ordinal: u64,
    /// Monotonic sequence within `lane_ordinal`.
    pub lane_sequence: u64,
    pub payload_len: u32,
    pub terminator_len: u8,
    pub exact_bytes: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetainedAcquisitionFinishV3 {
    pub record_count: u64,
    pub payload_byte_count: u64,
    pub source_byte_count: u64,
    pub input_digest: [u8; 32],
    pub completion_digest: [u8; 32],
}

impl fmt::Debug for RetainedAcquisitionFinishV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedAcquisitionFinishV3")
            .field("record_count", &self.record_count)
            .field("payload_byte_count", &self.payload_byte_count)
            .field("source_byte_count", &self.source_byte_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetainedStoreManifestV3 {
    digest: [u8; 32],
    result_id: ResultId,
    namespace: [u8; 32],
    record_count: u64,
    payload_byte_count: u64,
    source_byte_count: u64,
    input_digest: [u8; 32],
    completion_digest: [u8; 32],
}

impl fmt::Debug for RetainedStoreManifestV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedStoreManifestV3")
            .field("record_count", &self.record_count)
            .field("source_byte_count", &self.source_byte_count)
            .finish_non_exhaustive()
    }
}

impl RetainedStoreManifestV3 {
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    #[must_use]
    pub const fn namespace(self) -> [u8; 32] {
        self.namespace
    }

    #[must_use]
    pub const fn payload_byte_count(self) -> u64 {
        self.payload_byte_count
    }

    #[must_use]
    pub const fn source_byte_count(self) -> u64 {
        self.source_byte_count
    }

    #[must_use]
    pub const fn input_digest(self) -> [u8; 32] {
        self.input_digest
    }

    #[must_use]
    pub const fn completion_digest(self) -> [u8; 32] {
        self.completion_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedEventLocatorV3 {
    pub(crate) event_id: EventId,
    pub(crate) acquisition_ordinal: u64,
    pub(crate) lane_ordinal: u64,
    pub(crate) lane_sequence: u64,
    pub(crate) offset: u64,
    pub(crate) exact_len: u32,
    pub(crate) payload_len: u32,
    pub(crate) terminator_len: u8,
}

/// A borrowed event exposed only for the duration of a deterministic scan.
///
/// Backends may reuse a decrypted page buffer after the callback returns, so
/// callers that retain bytes must copy only their bounded working set.
#[derive(Clone, Copy)]
pub struct RetainedEventViewV3<'a> {
    locator: RetainedEventLocatorV3,
    exact_bytes: &'a [u8],
}

impl<'a> RetainedEventViewV3<'a> {
    #[must_use]
    pub const fn new(locator: RetainedEventLocatorV3, exact_bytes: &'a [u8]) -> Self {
        Self {
            locator,
            exact_bytes,
        }
    }

    #[must_use]
    pub const fn locator(self) -> RetainedEventLocatorV3 {
        self.locator
    }

    #[must_use]
    pub const fn exact_bytes(self) -> &'a [u8] {
        self.exact_bytes
    }

    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.exact_bytes[..self.locator.payload_len as usize]
    }

    #[must_use]
    pub fn terminator(self) -> &'a [u8] {
        &self.exact_bytes[self.locator.payload_len as usize..]
    }
}

impl fmt::Debug for RetainedEventViewV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedEventViewV3")
            .field("locator", &self.locator)
            .field("exact_byte_count", &self.exact_bytes.len())
            .finish()
    }
}

impl RetainedEventLocatorV3 {
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn acquisition_ordinal(self) -> u64 {
        self.acquisition_ordinal
    }

    #[must_use]
    pub const fn lane_ordinal(self) -> u64 {
        self.lane_ordinal
    }

    #[must_use]
    pub const fn lane_sequence(self) -> u64 {
        self.lane_sequence
    }

    #[must_use]
    pub const fn exact_len(self) -> u32 {
        self.exact_len
    }

    #[must_use]
    pub const fn payload_len(self) -> u32 {
        self.payload_len
    }

    #[must_use]
    pub const fn terminator_len(self) -> u8 {
        self.terminator_len
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RetainedPublishedAliasV3 {
    reference: EvidenceReferenceV1,
    ordered_event_ids: Vec<EventId>,
}

impl RetainedPublishedAliasV3 {
    #[must_use]
    pub fn new(reference: EvidenceReferenceV1, ordered_event_ids: Vec<EventId>) -> Self {
        Self {
            reference,
            ordered_event_ids,
        }
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub fn ordered_event_ids(&self) -> &[EventId] {
        &self.ordered_event_ids
    }
}

impl fmt::Debug for RetainedPublishedAliasV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedPublishedAliasV3")
            .field("event_count", &self.ordered_event_ids.len())
            .finish_non_exhaustive()
    }
}

/// Storage seam shared by memory and durable V3 product orchestration.
pub trait RetainedEventStoreV3 {
    fn begin(&mut self, input: RetainedStoreBeginV3) -> Result<(), RetainedEventStoreErrorV3>;
    fn append(&mut self, input: RetainedEventInputV3<'_>) -> Result<(), RetainedEventStoreErrorV3>;
    fn finish_acquisition(
        &mut self,
        finish: RetainedAcquisitionFinishV3,
    ) -> Result<RetainedStoreManifestV3, RetainedEventStoreErrorV3>;
    fn acquisition_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3>;
    fn lane_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3>;
    fn read_exact(
        &self,
        event_id: EventId,
    ) -> Result<Zeroizing<Vec<u8>>, RetainedEventStoreErrorV3>;
    fn seal_and_publish(
        &mut self,
        manifest: RetainedStoreManifestV3,
        published_aliases: &[EventId],
    ) -> Result<(), RetainedEventStoreErrorV3>;
    fn seal_and_publish_aliases(
        &mut self,
        manifest: RetainedStoreManifestV3,
        aliases: &[RetainedPublishedAliasV3],
    ) -> Result<(), RetainedEventStoreErrorV3> {
        let event_ids = aliases
            .iter()
            .flat_map(|alias| alias.ordered_event_ids.iter().copied())
            .collect::<Vec<_>>();
        self.seal_and_publish(manifest, &event_ids)
    }
    fn recover(&mut self) -> Result<RetainedEventStoreStateV3, RetainedEventStoreErrorV3>;
    fn destroy_authority_first(&mut self) -> Result<(), RetainedEventStoreErrorV3>;
    fn state(&self) -> RetainedEventStoreStateV3;
}

/// Plaintext-in-process packed backend. No method opens or writes a file.
pub struct PackedMemoryEventStoreV3 {
    state: RetainedEventStoreStateV3,
    begin: Option<RetainedStoreBeginV3>,
    manifest: Option<RetainedStoreManifestV3>,
    arena: Zeroizing<Vec<u8>>,
    acquisition: Vec<RetainedEventLocatorV3>,
    by_event: Vec<(EventId, usize)>,
    by_lane: Vec<usize>,
    published_aliases: Vec<EventId>,
}

impl Default for PackedMemoryEventStoreV3 {
    fn default() -> Self {
        Self {
            state: RetainedEventStoreStateV3::Empty,
            begin: None,
            manifest: None,
            arena: Zeroizing::new(Vec::new()),
            acquisition: Vec::new(),
            by_event: Vec::new(),
            by_lane: Vec::new(),
            published_aliases: Vec::new(),
        }
    }
}

impl PackedMemoryEventStoreV3 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn retained_plaintext_bytes(&self) -> usize {
        self.arena.len()
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.acquisition.len()
    }

    #[must_use]
    pub fn manifest(&self) -> Option<RetainedStoreManifestV3> {
        self.manifest
    }

    fn locate(
        &self,
        event_id: EventId,
    ) -> Result<RetainedEventLocatorV3, RetainedEventStoreErrorV3> {
        let position = self
            .by_event
            .binary_search_by_key(&event_id, |entry| entry.0)
            .map_err(|_| RetainedEventStoreErrorV3::NotFound)?;
        let acquisition_position = self.by_event[position].1;
        self.acquisition
            .get(acquisition_position)
            .copied()
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)
    }
}

impl RetainedEventStoreV3 for PackedMemoryEventStoreV3 {
    fn begin(&mut self, input: RetainedStoreBeginV3) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Empty
            || input.namespace.iter().all(|byte| *byte == 0)
            || input.expires_unix_nanos <= input.created_unix_nanos
        {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        self.begin = Some(input);
        self.state = RetainedEventStoreStateV3::Open;
        Ok(())
    }

    fn append(&mut self, input: RetainedEventInputV3<'_>) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Open
            || input.acquisition_ordinal != self.acquisition.len() as u64
            || usize::try_from(input.payload_len).ok().is_none()
            || usize::from(input.terminator_len) > input.exact_bytes.len()
            || usize::try_from(input.payload_len)
                .ok()
                .and_then(|payload| payload.checked_add(usize::from(input.terminator_len)))
                != Some(input.exact_bytes.len())
            || self.acquisition.len() as u64 >= MAX_STREAM_RECORDS_V3
        {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
        // Duplicate EventIds are rejected once, deterministically, when the
        // sorted locator index is built by `finish_acquisition`. Scanning all
        // prior locators here would make million-record acquisition O(n^2).
        let next_len = self
            .arena
            .len()
            .checked_add(input.exact_bytes.len())
            .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
        if next_len as u64 > MAX_STREAM_SOURCE_BYTES_V3 {
            return Err(RetainedEventStoreErrorV3::CapacityExceeded);
        }
        let offset = u64::try_from(self.arena.len())
            .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?;
        let exact_len = u32::try_from(input.exact_bytes.len())
            .map_err(|_| RetainedEventStoreErrorV3::CapacityExceeded)?;
        self.arena.extend_from_slice(input.exact_bytes);
        self.acquisition.push(RetainedEventLocatorV3 {
            event_id: input.event_id,
            acquisition_ordinal: input.acquisition_ordinal,
            lane_ordinal: input.lane_ordinal,
            lane_sequence: input.lane_sequence,
            offset,
            exact_len,
            payload_len: input.payload_len,
            terminator_len: input.terminator_len,
        });
        Ok(())
    }

    fn finish_acquisition(
        &mut self,
        finish: RetainedAcquisitionFinishV3,
    ) -> Result<RetainedStoreManifestV3, RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Open
            || finish.record_count != self.acquisition.len() as u64
            || finish.source_byte_count != self.arena.len() as u64
            || finish.record_count == 0
            || finish.record_count > MAX_STREAM_RECORDS_V3
            || finish.source_byte_count > MAX_STREAM_SOURCE_BYTES_V3
        {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
        let begin = self.begin.ok_or(RetainedEventStoreErrorV3::InvalidState)?;
        let payload_total = self
            .acquisition
            .iter()
            .try_fold(0_u64, |total, locator| {
                total.checked_add(u64::from(locator.payload_len))
            })
            .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
        if payload_total != finish.payload_byte_count {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
        self.by_event = self
            .acquisition
            .iter()
            .enumerate()
            .map(|(position, locator)| (locator.event_id, position))
            .collect();
        self.by_event.sort_unstable_by_key(|entry| entry.0);
        if self.by_event.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(RetainedEventStoreErrorV3::DuplicateEvent);
        }
        self.by_lane = (0..self.acquisition.len()).collect();
        self.by_lane.sort_unstable_by_key(|position| {
            let locator = self.acquisition[*position];
            (
                locator.lane_ordinal,
                locator.lane_sequence,
                locator.acquisition_ordinal,
            )
        });
        validate_lane_order_v3(&self.acquisition, &self.by_lane)?;
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_DOMAIN_V3);
        hasher.update(begin.result_id.as_bytes());
        hasher.update(begin.namespace);
        hasher.update(finish.record_count.to_be_bytes());
        hasher.update(finish.payload_byte_count.to_be_bytes());
        hasher.update(finish.source_byte_count.to_be_bytes());
        hasher.update(finish.input_digest);
        hasher.update(finish.completion_digest);
        for locator in &self.acquisition {
            hasher.update(locator.event_id.as_bytes());
            hasher.update(locator.acquisition_ordinal.to_be_bytes());
            hasher.update(locator.lane_ordinal.to_be_bytes());
            hasher.update(locator.lane_sequence.to_be_bytes());
            hasher.update(locator.offset.to_be_bytes());
            hasher.update(locator.exact_len.to_be_bytes());
            hasher.update(locator.payload_len.to_be_bytes());
            hasher.update([locator.terminator_len]);
        }
        let manifest = RetainedStoreManifestV3 {
            digest: hasher.finalize().into(),
            result_id: begin.result_id,
            namespace: begin.namespace,
            record_count: finish.record_count,
            payload_byte_count: finish.payload_byte_count,
            source_byte_count: finish.source_byte_count,
            input_digest: finish.input_digest,
            completion_digest: finish.completion_digest,
        };
        self.manifest = Some(manifest);
        self.state = RetainedEventStoreStateV3::DataCommitted;
        Ok(manifest)
    }

    fn acquisition_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state < RetainedEventStoreStateV3::DataCommitted {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        for locator in &self.acquisition {
            let start = usize::try_from(locator.offset)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            let end = start
                .checked_add(locator.exact_len as usize)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let exact_bytes = self
                .arena
                .get(start..end)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            visitor(RetainedEventViewV3::new(*locator, exact_bytes))?;
        }
        Ok(())
    }

    fn lane_scan(
        &self,
        visitor: &mut dyn FnMut(RetainedEventViewV3<'_>) -> Result<(), RetainedEventStoreErrorV3>,
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state < RetainedEventStoreStateV3::DataCommitted {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        for position in &self.by_lane {
            let locator = self
                .acquisition
                .get(*position)
                .copied()
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let start = usize::try_from(locator.offset)
                .map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
            let end = start
                .checked_add(locator.exact_len as usize)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            let exact_bytes = self
                .arena
                .get(start..end)
                .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
            visitor(RetainedEventViewV3::new(locator, exact_bytes))?;
        }
        Ok(())
    }

    fn read_exact(
        &self,
        event_id: EventId,
    ) -> Result<Zeroizing<Vec<u8>>, RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::Published {
            return Err(RetainedEventStoreErrorV3::NotPublished);
        }
        let locator = self.locate(event_id)?;
        let start =
            usize::try_from(locator.offset).map_err(|_| RetainedEventStoreErrorV3::CorruptIndex)?;
        let end = start
            .checked_add(locator.exact_len as usize)
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        let bytes = self
            .arena
            .get(start..end)
            .ok_or(RetainedEventStoreErrorV3::CorruptIndex)?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn seal_and_publish(
        &mut self,
        manifest: RetainedStoreManifestV3,
        published_aliases: &[EventId],
    ) -> Result<(), RetainedEventStoreErrorV3> {
        if self.state != RetainedEventStoreStateV3::DataCommitted
            || self.manifest != Some(manifest)
            || published_aliases
                .iter()
                .any(|event_id| self.locate(*event_id).is_err())
        {
            return Err(RetainedEventStoreErrorV3::InvalidState);
        }
        let mut aliases = published_aliases.to_vec();
        aliases.sort_unstable();
        aliases.dedup();
        self.published_aliases = aliases;
        self.state = RetainedEventStoreStateV3::Sealed;
        self.state = RetainedEventStoreStateV3::Published;
        Ok(())
    }

    fn recover(&mut self) -> Result<RetainedEventStoreStateV3, RetainedEventStoreErrorV3> {
        Ok(self.state)
    }

    fn destroy_authority_first(&mut self) -> Result<(), RetainedEventStoreErrorV3> {
        self.state = RetainedEventStoreStateV3::Destroyed;
        self.published_aliases.clear();
        self.by_lane.clear();
        self.by_event.clear();
        self.acquisition.clear();
        self.arena.clear();
        self.manifest = None;
        self.begin = None;
        Ok(())
    }

    fn state(&self) -> RetainedEventStoreStateV3 {
        self.state
    }
}

pub(crate) fn make_manifest_v3(
    begin: RetainedStoreBeginV3,
    finish: RetainedAcquisitionFinishV3,
    acquisition: &[RetainedEventLocatorV3],
) -> Result<RetainedStoreManifestV3, RetainedEventStoreErrorV3> {
    let payload_total = acquisition
        .iter()
        .try_fold(0_u64, |total, locator| {
            total.checked_add(u64::from(locator.payload_len))
        })
        .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
    let source_total = acquisition
        .iter()
        .try_fold(0_u64, |total, locator| {
            total.checked_add(u64::from(locator.exact_len))
        })
        .ok_or(RetainedEventStoreErrorV3::CapacityExceeded)?;
    if payload_total != finish.payload_byte_count
        || source_total != finish.source_byte_count
        || finish.record_count != acquisition.len() as u64
        || finish.record_count > MAX_STREAM_RECORDS_V3
        || finish.source_byte_count > MAX_STREAM_SOURCE_BYTES_V3
    {
        return Err(RetainedEventStoreErrorV3::InvalidInput);
    }
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN_V3);
    hasher.update(begin.result_id.as_bytes());
    hasher.update(begin.namespace);
    hasher.update(finish.record_count.to_be_bytes());
    hasher.update(finish.payload_byte_count.to_be_bytes());
    hasher.update(finish.source_byte_count.to_be_bytes());
    hasher.update(finish.input_digest);
    hasher.update(finish.completion_digest);
    for locator in acquisition {
        hasher.update(locator.event_id.as_bytes());
        hasher.update(locator.acquisition_ordinal.to_be_bytes());
        hasher.update(locator.lane_ordinal.to_be_bytes());
        hasher.update(locator.lane_sequence.to_be_bytes());
        hasher.update(locator.offset.to_be_bytes());
        hasher.update(locator.exact_len.to_be_bytes());
        hasher.update(locator.payload_len.to_be_bytes());
        hasher.update([locator.terminator_len]);
    }
    Ok(RetainedStoreManifestV3 {
        digest: hasher.finalize().into(),
        result_id: begin.result_id,
        namespace: begin.namespace,
        record_count: finish.record_count,
        payload_byte_count: finish.payload_byte_count,
        source_byte_count: finish.source_byte_count,
        input_digest: finish.input_digest,
        completion_digest: finish.completion_digest,
    })
}

pub(crate) fn validate_lane_order_v3(
    acquisition: &[RetainedEventLocatorV3],
    by_lane: &[usize],
) -> Result<(), RetainedEventStoreErrorV3> {
    for pair in by_lane.windows(2) {
        let previous = acquisition[pair[0]];
        let next = acquisition[pair[1]];
        if previous.lane_ordinal == next.lane_ordinal
            && (previous.lane_sequence.checked_add(1) != Some(next.lane_sequence)
                || previous.acquisition_ordinal >= next.acquisition_ordinal)
        {
            return Err(RetainedEventStoreErrorV3::InvalidInput);
        }
    }
    Ok(())
}
