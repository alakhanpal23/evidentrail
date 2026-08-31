use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    BlockConfidence, BlockId, BlockState, EventId, FramingPolicy, LaneKey, LaneSequence,
    RetrievalId, SourceStream,
};
use sha2::{Digest, Sha256};

use crate::hash::block_id;
use crate::ledger::{Event, EventLedger};

/// A proposed primary block membership. Reconciliation, rather than this
/// transport type, establishes whether the proposal is valid.
#[derive(Clone, PartialEq, Eq)]
pub struct BlockAssignment {
    lane: LaneKey,
    member_ids: Vec<EventId>,
    member_lane_sequences: Vec<LaneSequence>,
    framing_policy: FramingPolicy,
    state: BlockState,
    confidence: BlockConfidence,
}

impl BlockAssignment {
    #[must_use]
    pub fn new_same_lane_v1(
        lane: LaneKey,
        members: impl IntoIterator<Item = (EventId, LaneSequence)>,
        framing_policy: FramingPolicy,
        state: BlockState,
        confidence: BlockConfidence,
    ) -> Self {
        let (member_ids, member_lane_sequences) = members.into_iter().unzip();
        Self {
            lane,
            member_ids,
            member_lane_sequences,
            framing_policy,
            state,
            confidence,
        }
    }

    #[must_use]
    pub const fn lane(&self) -> &LaneKey {
        &self.lane
    }

    #[must_use]
    pub fn member_ids(&self) -> &[EventId] {
        &self.member_ids
    }

    #[must_use]
    pub fn member_lane_sequences(&self) -> &[LaneSequence] {
        &self.member_lane_sequences
    }

    #[must_use]
    pub fn framing_policy(&self) -> &FramingPolicy {
        &self.framing_policy
    }

    #[must_use]
    pub fn state(&self) -> BlockState {
        self.state
    }

    #[must_use]
    pub fn confidence(&self) -> BlockConfidence {
        self.confidence
    }
}

impl fmt::Debug for BlockAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockAssignment")
            .field("member_count", &self.member_ids.len())
            .field("lane", &self.lane)
            .field("framing_policy", &self.framing_policy)
            .field("state", &self.state)
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// One immutable atomic block sealed against a single retrieval ledger.
#[derive(Clone, PartialEq, Eq)]
pub struct EventBlock {
    id: BlockId,
    ordinal: u64,
    lane: LaneKey,
    member_ids: Vec<EventId>,
    member_lane_sequences: Vec<LaneSequence>,
    member_positions: Vec<usize>,
    framing_policy: FramingPolicy,
    state: BlockState,
    confidence: BlockConfidence,
}

impl EventBlock {
    #[must_use]
    pub fn id(&self) -> BlockId {
        self.id
    }

    #[must_use]
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn lane(&self) -> &LaneKey {
        &self.lane
    }

    #[must_use]
    pub fn member_ids(&self) -> &[EventId] {
        &self.member_ids
    }

    #[must_use]
    pub fn member_lane_sequences(&self) -> &[LaneSequence] {
        &self.member_lane_sequences
    }

    #[must_use]
    pub fn member_positions(&self) -> &[usize] {
        &self.member_positions
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.member_ids.len()
    }

    /// Reconciled blocks are non-empty by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub fn framing_policy(&self) -> &FramingPolicy {
        &self.framing_policy
    }

    #[must_use]
    pub fn state(&self) -> BlockState {
        self.state
    }

    #[must_use]
    pub fn confidence(&self) -> BlockConfidence {
        self.confidence
    }
}

impl fmt::Debug for EventBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventBlock")
            .field("ordinal", &self.ordinal)
            .field("member_count", &self.member_ids.len())
            .field("lane", &self.lane)
            .field("framing_policy", &self.framing_policy)
            .field("state", &self.state)
            .field("confidence", &self.confidence)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub enum BlockReconciliationError {
    EmptyAssignment {
        assignment_index: usize,
    },
    ForeignMember {
        assignment_index: usize,
        member_index: usize,
        event_id: EventId,
    },
    MemberLaneMismatch {
        assignment_index: usize,
        member_index: usize,
    },
    MemberLaneSequenceMismatch {
        assignment_index: usize,
        member_index: usize,
    },
    DuplicateMember {
        assignment_index: usize,
        member_index: usize,
        event_id: EventId,
    },
    ReversedMembers {
        assignment_index: usize,
        previous_member_index: usize,
        member_index: usize,
    },
    ReversedLaneSequence {
        assignment_index: usize,
        previous_member_index: usize,
        member_index: usize,
    },
    NonContiguousLaneSequence {
        assignment_index: usize,
        previous_member_index: usize,
        member_index: usize,
    },
    DuplicateAssignment {
        first_assignment_index: usize,
        duplicate_assignment_index: usize,
        block_id: BlockId,
    },
    OverlappingMember {
        first_assignment_index: usize,
        second_assignment_index: usize,
        event_id: EventId,
    },
    MissingEvents(Vec<EventId>),
    BlockIdCollision(BlockId),
    BlockCountOverflow,
}

impl BlockReconciliationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyAssignment { .. } => "EVIDENTRAIL_BLOCK_EMPTY_ASSIGNMENT",
            Self::ForeignMember { .. } => "EVIDENTRAIL_BLOCK_FOREIGN_MEMBER",
            Self::MemberLaneMismatch { .. } => "EVIDENTRAIL_BLOCK_MEMBER_LANE_MISMATCH",
            Self::MemberLaneSequenceMismatch { .. } => {
                "EVIDENTRAIL_BLOCK_MEMBER_LANE_SEQUENCE_MISMATCH"
            }
            Self::DuplicateMember { .. } => "EVIDENTRAIL_BLOCK_DUPLICATE_MEMBER",
            Self::ReversedMembers { .. } => "EVIDENTRAIL_BLOCK_REVERSED_MEMBERS",
            Self::ReversedLaneSequence { .. } => "EVIDENTRAIL_BLOCK_REVERSED_LANE_SEQUENCE",
            Self::NonContiguousLaneSequence { .. } => {
                "EVIDENTRAIL_BLOCK_NONCONTIGUOUS_LANE_SEQUENCE"
            }
            Self::DuplicateAssignment { .. } => "EVIDENTRAIL_BLOCK_DUPLICATE_ASSIGNMENT",
            Self::OverlappingMember { .. } => "EVIDENTRAIL_BLOCK_OVERLAPPING_MEMBER",
            Self::MissingEvents(_) => "EVIDENTRAIL_BLOCK_MISSING_EVENTS",
            Self::BlockIdCollision(_) => "EVIDENTRAIL_BLOCK_ID_COLLISION",
            Self::BlockCountOverflow => "EVIDENTRAIL_BLOCK_COUNT_OVERFLOW",
        }
    }

    #[must_use]
    pub fn affected_event_count(&self) -> usize {
        match self {
            Self::EmptyAssignment { .. }
            | Self::DuplicateAssignment { .. }
            | Self::BlockIdCollision(_)
            | Self::BlockCountOverflow => 0,
            Self::MissingEvents(events) => events.len(),
            Self::ForeignMember { .. }
            | Self::MemberLaneMismatch { .. }
            | Self::MemberLaneSequenceMismatch { .. }
            | Self::DuplicateMember { .. }
            | Self::ReversedMembers { .. }
            | Self::ReversedLaneSequence { .. }
            | Self::NonContiguousLaneSequence { .. }
            | Self::OverlappingMember { .. } => 1,
        }
    }
}

impl fmt::Debug for BlockReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("BlockReconciliationError");
        summary
            .field("code", &self.code())
            .field("affected_event_count", &self.affected_event_count());
        match self {
            Self::EmptyAssignment { assignment_index }
            | Self::ForeignMember {
                assignment_index, ..
            }
            | Self::MemberLaneMismatch {
                assignment_index, ..
            }
            | Self::MemberLaneSequenceMismatch {
                assignment_index, ..
            }
            | Self::DuplicateMember {
                assignment_index, ..
            }
            | Self::ReversedMembers {
                assignment_index, ..
            }
            | Self::ReversedLaneSequence {
                assignment_index, ..
            }
            | Self::NonContiguousLaneSequence {
                assignment_index, ..
            } => {
                summary.field("assignment_index", assignment_index);
            }
            Self::DuplicateAssignment {
                first_assignment_index,
                duplicate_assignment_index,
                ..
            } => {
                summary
                    .field("first_assignment_index", first_assignment_index)
                    .field("duplicate_assignment_index", duplicate_assignment_index);
            }
            Self::OverlappingMember {
                first_assignment_index,
                second_assignment_index,
                ..
            } => {
                summary
                    .field("first_assignment_index", first_assignment_index)
                    .field("second_assignment_index", second_assignment_index);
            }
            Self::MissingEvents(_) | Self::BlockIdCollision(_) | Self::BlockCountOverflow => {}
        }
        summary.finish()
    }
}

impl fmt::Display for BlockReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (affected_event_count={})",
            self.code(),
            self.affected_event_count()
        )
    }
}

impl StdError for BlockReconciliationError {}

#[derive(PartialEq, Eq)]
pub enum BlockLookupError {
    UnknownBlock(BlockId),
    UnknownEvent(EventId),
}

impl BlockLookupError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownBlock(_) => "EVIDENTRAIL_BLOCK_UNKNOWN_BLOCK",
            Self::UnknownEvent(_) => "EVIDENTRAIL_BLOCK_UNKNOWN_EVENT",
        }
    }
}

impl fmt::Debug for BlockLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockLookupError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for BlockLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for BlockLookupError {}

struct CandidateBlock {
    id: BlockId,
    lane: LaneKey,
    member_ids: Vec<EventId>,
    member_lane_sequences: Vec<LaneSequence>,
    member_positions: Vec<usize>,
    framing_policy: FramingPolicy,
    state: BlockState,
    confidence: BlockConfidence,
}

struct SeenBlockIdentity {
    assignment_index: usize,
    lane: LaneKey,
    member_ids: Vec<EventId>,
    member_lane_sequences: Vec<LaneSequence>,
    framing_policy: FramingPolicy,
}

/// A reconciled, immutable primary block partition over one event ledger.
pub struct BlockIndex<'ledger> {
    ledger: &'ledger EventLedger,
    blocks: Vec<EventBlock>,
    block_positions: BTreeMap<BlockId, usize>,
    event_block_positions: BTreeMap<EventId, usize>,
}

impl<'ledger> BlockIndex<'ledger> {
    pub fn reconcile<I>(
        ledger: &'ledger EventLedger,
        assignments: I,
    ) -> Result<Self, BlockReconciliationError>
    where
        I: IntoIterator<Item = BlockAssignment>,
    {
        let assignments = assignments.into_iter().collect::<Vec<_>>();
        let mut owners = vec![None; ledger.len()];
        let mut seen_ids: BTreeMap<BlockId, SeenBlockIdentity> = BTreeMap::new();
        let mut candidates = Vec::with_capacity(assignments.len());

        for (assignment_index, assignment) in assignments.into_iter().enumerate() {
            if assignment.member_ids.is_empty() {
                return Err(BlockReconciliationError::EmptyAssignment { assignment_index });
            }

            debug_assert_eq!(
                assignment.member_ids.len(),
                assignment.member_lane_sequences.len()
            );

            let mut positions = Vec::with_capacity(assignment.member_ids.len());
            let mut seen_member_positions = BTreeSet::new();
            for (member_index, event_id) in assignment.member_ids.iter().copied().enumerate() {
                if let Some(previous_sequence) = member_index
                    .checked_sub(1)
                    .map(|index| assignment.member_lane_sequences[index])
                {
                    let sequence = assignment.member_lane_sequences[member_index];
                    if sequence <= previous_sequence {
                        return Err(BlockReconciliationError::ReversedLaneSequence {
                            assignment_index,
                            previous_member_index: member_index - 1,
                            member_index,
                        });
                    }
                    if previous_sequence.get().checked_add(1) != Some(sequence.get()) {
                        return Err(BlockReconciliationError::NonContiguousLaneSequence {
                            assignment_index,
                            previous_member_index: member_index - 1,
                            member_index,
                        });
                    }
                }
                let position =
                    ledger
                        .position(event_id)
                        .ok_or(BlockReconciliationError::ForeignMember {
                            assignment_index,
                            member_index,
                            event_id,
                        })?;
                if !seen_member_positions.insert(position) {
                    return Err(BlockReconciliationError::DuplicateMember {
                        assignment_index,
                        member_index,
                        event_id,
                    });
                }
                let event = &ledger.events()[position];
                if event.lane() != &assignment.lane {
                    return Err(BlockReconciliationError::MemberLaneMismatch {
                        assignment_index,
                        member_index,
                    });
                }
                if event.lane_sequence() != assignment.member_lane_sequences[member_index] {
                    return Err(BlockReconciliationError::MemberLaneSequenceMismatch {
                        assignment_index,
                        member_index,
                    });
                }
                if let Some(previous_position) = positions.last().copied() {
                    if position < previous_position {
                        return Err(BlockReconciliationError::ReversedMembers {
                            assignment_index,
                            previous_member_index: member_index - 1,
                            member_index,
                        });
                    }
                }
                positions.push(position);
            }

            let id = same_lane_block_id_v1(
                ledger.retrieval_id(),
                &assignment.lane,
                &assignment.member_ids,
                &assignment.member_lane_sequences,
                &assignment.framing_policy,
            );
            if let Some(seen) = seen_ids.get(&id) {
                if seen.lane == assignment.lane
                    && seen.member_ids == assignment.member_ids
                    && seen.member_lane_sequences == assignment.member_lane_sequences
                    && seen.framing_policy == assignment.framing_policy
                {
                    return Err(BlockReconciliationError::DuplicateAssignment {
                        first_assignment_index: seen.assignment_index,
                        duplicate_assignment_index: assignment_index,
                        block_id: id,
                    });
                }
                return Err(BlockReconciliationError::BlockIdCollision(id));
            }

            for (member_index, position) in positions.iter().copied().enumerate() {
                if let Some(first_assignment_index) = owners[position] {
                    return Err(BlockReconciliationError::OverlappingMember {
                        first_assignment_index,
                        second_assignment_index: assignment_index,
                        event_id: assignment.member_ids[member_index],
                    });
                }
            }
            for position in &positions {
                owners[*position] = Some(assignment_index);
            }

            seen_ids.insert(
                id,
                SeenBlockIdentity {
                    assignment_index,
                    lane: assignment.lane.clone(),
                    member_ids: assignment.member_ids.clone(),
                    member_lane_sequences: assignment.member_lane_sequences.clone(),
                    framing_policy: assignment.framing_policy.clone(),
                },
            );
            candidates.push(CandidateBlock {
                id,
                lane: assignment.lane,
                member_ids: assignment.member_ids,
                member_lane_sequences: assignment.member_lane_sequences,
                member_positions: positions,
                framing_policy: assignment.framing_policy,
                state: assignment.state,
                confidence: assignment.confidence,
            });
        }

        let missing = ledger
            .events()
            .iter()
            .enumerate()
            .filter(|(position, _)| owners[*position].is_none())
            .map(|(_, event)| event.id())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(BlockReconciliationError::MissingEvents(missing));
        }

        candidates.sort_by_key(|candidate| candidate.member_positions[0]);
        let mut blocks = Vec::with_capacity(candidates.len());
        let mut block_positions = BTreeMap::new();
        let mut event_block_positions = BTreeMap::new();
        for candidate in candidates {
            let ordinal = u64::try_from(blocks.len())
                .map_err(|_| BlockReconciliationError::BlockCountOverflow)?;
            let block_position = blocks.len();
            for event_id in &candidate.member_ids {
                event_block_positions.insert(*event_id, block_position);
            }
            block_positions.insert(candidate.id, block_position);
            blocks.push(EventBlock {
                id: candidate.id,
                ordinal,
                lane: candidate.lane,
                member_ids: candidate.member_ids,
                member_lane_sequences: candidate.member_lane_sequences,
                member_positions: candidate.member_positions,
                framing_policy: candidate.framing_policy,
                state: candidate.state,
                confidence: candidate.confidence,
            });
        }

        Ok(Self {
            ledger,
            blocks,
            block_positions,
            event_block_positions,
        })
    }

    #[must_use]
    pub fn retrieval_id(&self) -> RetrievalId {
        self.ledger.retrieval_id()
    }

    #[must_use]
    pub fn blocks(&self) -> &[EventBlock] {
        &self.blocks
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn block(&self, block_id: BlockId) -> Result<&EventBlock, BlockLookupError> {
        let position = self
            .block_positions
            .get(&block_id)
            .copied()
            .ok_or(BlockLookupError::UnknownBlock(block_id))?;
        Ok(&self.blocks[position])
    }

    pub fn block_for_event(&self, event_id: EventId) -> Result<&EventBlock, BlockLookupError> {
        let position = self
            .event_block_positions
            .get(&event_id)
            .copied()
            .ok_or(BlockLookupError::UnknownEvent(event_id))?;
        Ok(&self.blocks[position])
    }

    pub fn expand_block(&self, block_id: BlockId) -> Result<BlockExpansion<'_>, BlockLookupError> {
        let block = self.block(block_id)?;
        Ok(self.expansion(block))
    }

    pub fn expand_event(&self, event_id: EventId) -> Result<BlockExpansion<'_>, BlockLookupError> {
        let block = self.block_for_event(event_id)?;
        Ok(self.expansion(block))
    }

    fn expansion<'index>(&'index self, block: &'index EventBlock) -> BlockExpansion<'index> {
        let events = block
            .member_positions
            .iter()
            .map(|position| &self.ledger.events()[*position])
            .collect::<Vec<_>>();
        debug_assert_eq!(
            events.iter().map(|event| event.id()).collect::<Vec<_>>(),
            block.member_ids
        );
        BlockExpansion { block, events }
    }
}

impl fmt::Debug for BlockIndex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockIndex")
            .field("block_count", &self.blocks.len())
            .field("event_count", &self.event_block_positions.len())
            .finish()
    }
}

/// Exact, read-only expansion of one atomic block.
#[derive(Clone)]
pub struct BlockExpansion<'index> {
    block: &'index EventBlock,
    events: Vec<&'index Event>,
}

impl<'index> BlockExpansion<'index> {
    #[must_use]
    pub fn block(&self) -> &'index EventBlock {
        self.block
    }

    #[must_use]
    pub fn events(&self) -> &[&'index Event] {
        &self.events
    }

    pub fn raw_events(&self) -> impl ExactSizeIterator<Item = &'index [u8]> + '_ {
        self.events.iter().map(|event| event.raw())
    }

    /// Reconstruct exact member bytes in source order without inserting or
    /// normalizing separators.
    #[must_use]
    pub fn exact_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in &self.events {
            bytes.extend_from_slice(event.raw());
        }
        bytes
    }
}

fn same_lane_block_id_v1(
    retrieval_id: RetrievalId,
    lane: &LaneKey,
    member_ids: &[EventId],
    member_lane_sequences: &[LaneSequence],
    framing_policy: &FramingPolicy,
) -> BlockId {
    let membership_id = block_id(retrieval_id, member_ids, framing_policy);
    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, b"evidentrail/event-block/same-lane/v1");
    update_hash_field(&mut hasher, membership_id.as_bytes());
    update_hash_field(&mut hasher, lane.member().as_bytes());
    update_hash_field(&mut hasher, lane.stream().code().as_bytes());
    if let SourceStream::OtherVersioned { version, code } = lane.stream() {
        update_hash_field(&mut hasher, &version.to_le_bytes());
        update_hash_field(&mut hasher, &code.to_le_bytes());
    }
    for lane_sequence in member_lane_sequences {
        update_hash_field(&mut hasher, &lane_sequence.get().to_le_bytes());
    }
    BlockId::from_bytes(hasher.finalize().into())
}

fn update_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("field lengths fit into u64");
    hasher.update(length.to_le_bytes());
    hasher.update(value);
}

impl fmt::Debug for BlockExpansion<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockExpansion")
            .field("member_count", &self.events.len())
            .field(
                "raw_bytes",
                &self.events.iter().fold(0usize, |total, event| {
                    total.saturating_add(event.raw().len())
                }),
            )
            .finish()
    }
}
