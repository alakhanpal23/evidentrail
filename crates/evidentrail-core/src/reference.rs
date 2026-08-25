use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{BlockId, EventId, EvidenceReferenceId, ResultId, UnixTimestampNanos};

use crate::hash::{domain_hasher, finish_evidence_reference, update_field};

pub const MAX_EVIDENCE_REFERENCE_TARGETS: usize = 4_096;

/// One immutable ledger target carried by an evidence reference.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceTargetRef {
    Event(EventId),
    Block(BlockId),
}

impl EvidenceTargetRef {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Event(_) => "event",
            Self::Block(_) => "block",
        }
    }

    fn hash_bytes(self) -> [u8; 32] {
        match self {
            Self::Event(id) => *id.as_bytes(),
            Self::Block(id) => *id.as_bytes(),
        }
    }
}

impl fmt::Debug for EvidenceTargetRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceTargetRef")
            .field("kind", &self.code())
            .finish()
    }
}

/// Read-only expansion capabilities explicitly granted to one reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExpansionRelationV1 {
    Exact,
    SameLaneBeforeAfter,
    GlobalBeforeAfter,
    PatternMembers,
    SameAttestedTrace,
    AroundOnset,
}

impl ExpansionRelationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::SameLaneBeforeAfter => "same_lane_before_after",
            Self::GlobalBeforeAfter => "global_before_after",
            Self::PatternMembers => "pattern_members",
            Self::SameAttestedTrace => "same_attested_trace",
            Self::AroundOnset => "around_onset",
        }
    }
}

/// Result-scoped, expiring capability description for read-only expansion.
///
/// This value is not an authentication secret and cannot authorize store access
/// by itself. The result store must also match it against its sealed manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceReferenceV1 {
    id: EvidenceReferenceId,
    result_id: ResultId,
    targets: Vec<EvidenceTargetRef>,
    allowed_relations: Vec<ExpansionRelationV1>,
    issued_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
}

impl EvidenceReferenceV1 {
    pub const CONTRACT_VERSION: u16 = 1;

    pub fn issue(
        result_id: ResultId,
        targets: impl IntoIterator<Item = EvidenceTargetRef>,
        allowed_relations: impl IntoIterator<Item = ExpansionRelationV1>,
        issued_at: UnixTimestampNanos,
        expires_at: UnixTimestampNanos,
    ) -> Result<Self, EvidenceReferenceConstructionError> {
        let (targets, allowed_relations) = validate_material(
            targets.into_iter().collect(),
            allowed_relations.into_iter().collect(),
            issued_at,
            expires_at,
        )?;
        let id = evidence_reference_id(
            result_id,
            &targets,
            &allowed_relations,
            issued_at,
            expires_at,
        );
        Ok(Self {
            id,
            result_id,
            targets,
            allowed_relations,
            issued_at,
            expires_at,
        })
    }

    /// Validate an untrusted declared wire identity against all canonical
    /// semantic material before constructing a reference.
    pub fn verify_declared(
        declared_id: EvidenceReferenceId,
        result_id: ResultId,
        targets: impl IntoIterator<Item = EvidenceTargetRef>,
        allowed_relations: impl IntoIterator<Item = ExpansionRelationV1>,
        issued_at: UnixTimestampNanos,
        expires_at: UnixTimestampNanos,
    ) -> Result<Self, EvidenceReferenceConstructionError> {
        let reference = Self::issue(result_id, targets, allowed_relations, issued_at, expires_at)?;
        if reference.id != declared_id {
            return Err(EvidenceReferenceConstructionError::DeclaredIdMismatch);
        }
        Ok(reference)
    }

    #[must_use]
    pub const fn id(&self) -> EvidenceReferenceId {
        self.id
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub fn targets(&self) -> &[EvidenceTargetRef] {
        &self.targets
    }

    #[must_use]
    pub fn allowed_relations(&self) -> &[ExpansionRelationV1] {
        &self.allowed_relations
    }

    #[must_use]
    pub const fn issued_at(&self) -> UnixTimestampNanos {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    /// Collapse expiry, cross-result, and disallowed-relation failures to one
    /// public unavailable result so the reference is not an oracle.
    pub fn authorize(
        &self,
        expected_result_id: ResultId,
        relation: ExpansionRelationV1,
        now: UnixTimestampNanos,
    ) -> Result<(), EvidenceReferenceUnavailable> {
        if self.result_id != expected_result_id
            || now < self.issued_at
            || now >= self.expires_at
            || self.allowed_relations.binary_search(&relation).is_err()
        {
            return Err(EvidenceReferenceUnavailable);
        }
        Ok(())
    }
}

impl fmt::Debug for EvidenceReferenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceReferenceV1")
            .field("target_count", &self.targets.len())
            .field("allowed_relation_count", &self.allowed_relations.len())
            .field("expiry_present", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EvidenceReferenceConstructionError {
    EmptyTargets,
    TooManyTargets,
    DuplicateTarget,
    EmptyRelations,
    DuplicateRelation,
    ExactRelationRequired,
    InvalidLifetime,
    DeclaredIdMismatch,
}

impl EvidenceReferenceConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyTargets => "EVIDENTRAIL_EVIDENCE_REFERENCE_EMPTY_TARGETS",
            Self::TooManyTargets => "EVIDENTRAIL_EVIDENCE_REFERENCE_TOO_MANY_TARGETS",
            Self::DuplicateTarget => "EVIDENTRAIL_EVIDENCE_REFERENCE_DUPLICATE_TARGET",
            Self::EmptyRelations => "EVIDENTRAIL_EVIDENCE_REFERENCE_EMPTY_RELATIONS",
            Self::DuplicateRelation => "EVIDENTRAIL_EVIDENCE_REFERENCE_DUPLICATE_RELATION",
            Self::ExactRelationRequired => "EVIDENTRAIL_EVIDENCE_REFERENCE_EXACT_RELATION_REQUIRED",
            Self::InvalidLifetime => "EVIDENTRAIL_EVIDENCE_REFERENCE_INVALID_LIFETIME",
            Self::DeclaredIdMismatch => "EVIDENTRAIL_EVIDENCE_REFERENCE_DECLARED_ID_MISMATCH",
        }
    }
}

impl fmt::Debug for EvidenceReferenceConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceReferenceConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EvidenceReferenceConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EvidenceReferenceConstructionError {}

/// Deliberately indistinguishable public expansion denial.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EvidenceReferenceUnavailable;

impl EvidenceReferenceUnavailable {
    pub const CODE: &'static str = "EVIDENTRAIL_EVIDENCE_REFERENCE_UNAVAILABLE";
}

impl fmt::Debug for EvidenceReferenceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceReferenceUnavailable")
    }
}

impl fmt::Display for EvidenceReferenceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl StdError for EvidenceReferenceUnavailable {}

fn validate_material(
    targets: Vec<EvidenceTargetRef>,
    relations: Vec<ExpansionRelationV1>,
    issued_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
) -> Result<(Vec<EvidenceTargetRef>, Vec<ExpansionRelationV1>), EvidenceReferenceConstructionError>
{
    if targets.is_empty() {
        return Err(EvidenceReferenceConstructionError::EmptyTargets);
    }
    if targets.len() > MAX_EVIDENCE_REFERENCE_TARGETS {
        return Err(EvidenceReferenceConstructionError::TooManyTargets);
    }
    let unique_targets = targets.iter().copied().collect::<BTreeSet<_>>();
    if unique_targets.len() != targets.len() {
        return Err(EvidenceReferenceConstructionError::DuplicateTarget);
    }

    if relations.is_empty() {
        return Err(EvidenceReferenceConstructionError::EmptyRelations);
    }
    let relation_count = relations.len();
    let allowed_relations = relations.into_iter().collect::<BTreeSet<_>>();
    if allowed_relations.len() != relation_count {
        return Err(EvidenceReferenceConstructionError::DuplicateRelation);
    }
    if !allowed_relations.contains(&ExpansionRelationV1::Exact) {
        return Err(EvidenceReferenceConstructionError::ExactRelationRequired);
    }
    if issued_at >= expires_at {
        return Err(EvidenceReferenceConstructionError::InvalidLifetime);
    }

    Ok((targets, allowed_relations.into_iter().collect()))
}

fn evidence_reference_id(
    result_id: ResultId,
    targets: &[EvidenceTargetRef],
    allowed_relations: &[ExpansionRelationV1],
    issued_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
) -> EvidenceReferenceId {
    let mut hasher = domain_hasher(b"evidentrail/evidence-reference/v1");
    update_field(
        &mut hasher,
        &EvidenceReferenceV1::CONTRACT_VERSION.to_le_bytes(),
    );
    update_field(&mut hasher, result_id.as_bytes());
    update_field(&mut hasher, &issued_at.get().to_le_bytes());
    update_field(&mut hasher, &expires_at.get().to_le_bytes());
    update_field(
        &mut hasher,
        &u64::try_from(targets.len())
            .expect("reference target bounds fit u64")
            .to_le_bytes(),
    );
    for target in targets {
        update_field(&mut hasher, target.code().as_bytes());
        update_field(&mut hasher, &target.hash_bytes());
    }
    update_field(
        &mut hasher,
        &u64::try_from(allowed_relations.len())
            .expect("relation count fits u64")
            .to_le_bytes(),
    );
    for relation in allowed_relations {
        update_field(&mut hasher, relation.code().as_bytes());
    }
    finish_evidence_reference(hasher)
}
