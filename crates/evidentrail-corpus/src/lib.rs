//! Per-source, SQLCipher-encrypted history storage.
//!
//! The caller owns key acquisition and source authorization. This store
//! provides durable page deduplication and checkpoints; it does not by itself
//! establish provider completeness or make a connected product.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use evidentrail_ingest::{
    HistoryCheckpointV1, HistoryPageStoreV1, HistoryRecordV1, HistorySyncErrorV1,
};
use evidentrail_log_model::{explicit_peer_service, parse_event};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const PARSER_INDEX_VERSION: i64 = 2;
const GRAPH_INDEX_VERSION: i64 = 2;
const TERM_INDEX_VERSION: i64 = 1;
const MAX_RAW_RECORD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    InvalidKey,
    EncryptionUnavailable,
    ScopeMismatch,
    ConflictingRecord,
    InvalidCheckpoint,
    InvalidPageBudget,
    RecordExceedsPageBudget,
    RecordTooLarge,
    IndexVersionMismatch,
    Storage,
}

impl CorpusError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidKey => "EVIDENTRAIL_CORPUS_INVALID_KEY",
            Self::EncryptionUnavailable => "EVIDENTRAIL_CORPUS_ENCRYPTION_UNAVAILABLE",
            Self::ScopeMismatch => "EVIDENTRAIL_CORPUS_SCOPE_MISMATCH",
            Self::ConflictingRecord => "EVIDENTRAIL_CORPUS_CONFLICTING_RECORD",
            Self::InvalidCheckpoint => "EVIDENTRAIL_CORPUS_INVALID_CHECKPOINT",
            Self::InvalidPageBudget => "EVIDENTRAIL_CORPUS_INVALID_PAGE_BUDGET",
            Self::RecordExceedsPageBudget => "EVIDENTRAIL_CORPUS_RECORD_EXCEEDS_PAGE_BUDGET",
            Self::RecordTooLarge => "EVIDENTRAIL_CORPUS_RECORD_TOO_LARGE",
            Self::IndexVersionMismatch => "EVIDENTRAIL_CORPUS_INDEX_VERSION_MISMATCH",
            Self::Storage => "EVIDENTRAIL_CORPUS_STORAGE_FAILURE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHistoryRecord {
    pub native_id: Vec<u8>,
    pub event_timestamp_millis: i64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSample {
    pub prefix: Vec<u8>,
    pub original_byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusCursor {
    pub event_timestamp_millis: i64,
    pub native_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusPage {
    pub records: Vec<StoredHistoryRecord>,
    /// `None` means the end was reached at the moment of this read.
    pub next_cursor: Option<CorpusCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusGroupCard {
    pub group_id: i64,
    pub service: String,
    pub role: String,
    pub repeat_count: u64,
    pub first_timestamp_millis: i64,
    pub last_timestamp_millis: i64,
    pub first_native_id: Vec<u8>,
    pub last_native_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateGroupPage {
    pub groups: Vec<CorpusGroupCard>,
    pub total_groups: u64,
    /// True when lexical matches exceeded the requested candidate budget.
    pub candidate_pool_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEdgeCard {
    pub source_service: String,
    pub target_service: String,
    pub evidence_count: u64,
    pub first_timestamp_millis: i64,
    pub last_timestamp_millis: i64,
    pub first_native_id: Vec<u8>,
    pub last_native_id: Vec<u8>,
    pub evidence_kind: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeEvidencePage {
    pub native_ids: Vec<Vec<u8>>,
    pub next_cursor: Option<Vec<u8>>,
}

pub struct EncryptedHistoryStore {
    connection: Connection,
}

impl EncryptedHistoryStore {
    /// One database file is bound permanently to one tenant and one source.
    /// `key` must come from a production key authority; zero keys are refused.
    pub fn open(
        path: &Path,
        key: &[u8; 32],
        tenant_digest: &[u8; 32],
        source_digest: &[u8; 32],
    ) -> Result<Self, CorpusError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(CorpusError::InvalidKey);
        }
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(CorpusError::Storage);
        }
        let connection = Connection::open(path).map_err(|_| CorpusError::Storage)?;
        let mut pragma = Zeroizing::new(String::from("PRAGMA key = \"x'"));
        for byte in key {
            write!(&mut *pragma, "{byte:02x}").map_err(|_| CorpusError::Storage)?;
        }
        pragma.push_str("'\";");
        connection
            .execute_batch(&pragma)
            .map_err(|_| CorpusError::Storage)?;
        drop(pragma);
        let cipher_version = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        if cipher_version.as_deref().is_none_or(str::is_empty) {
            return Err(CorpusError::EncryptionUnavailable);
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| CorpusError::Storage)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA secure_delete=ON;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS corpus_scope (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     tenant_digest BLOB NOT NULL,
                     source_digest BLOB NOT NULL,
                     completed_through_millis INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS history_records (
                     native_id BLOB PRIMARY KEY,
                     event_timestamp_millis INTEGER NOT NULL,
                     raw BLOB NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS history_records_time
                     ON history_records(event_timestamp_millis, native_id);
                 CREATE TABLE IF NOT EXISTS log_groups (
                     group_id INTEGER PRIMARY KEY,
                     service TEXT NOT NULL,
                     role TEXT NOT NULL,
                     fingerprint_digest BLOB NOT NULL,
                     repeat_count INTEGER NOT NULL,
                     first_timestamp_millis INTEGER NOT NULL,
                     first_native_id BLOB NOT NULL,
                     last_timestamp_millis INTEGER NOT NULL,
                     last_native_id BLOB NOT NULL,
                     UNIQUE(service, role, fingerprint_digest)
                 );
                 CREATE TABLE IF NOT EXISTS group_members (
                     native_id BLOB PRIMARY KEY REFERENCES history_records(native_id),
                     group_id INTEGER NOT NULL REFERENCES log_groups(group_id)
                 );
                 CREATE INDEX IF NOT EXISTS group_members_group ON group_members(group_id);
                 CREATE TABLE IF NOT EXISTS group_terms (
                     term_digest BLOB NOT NULL,
                     group_id INTEGER NOT NULL REFERENCES log_groups(group_id),
                     PRIMARY KEY(term_digest, group_id)
                 );
                 CREATE TABLE IF NOT EXISTS term_metadata (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     index_version INTEGER NOT NULL,
                     backfill_complete INTEGER NOT NULL CHECK (backfill_complete IN (0, 1))
                 );
                 CREATE TABLE IF NOT EXISTS service_edges (
                     source_service TEXT NOT NULL,
                     target_service TEXT NOT NULL,
                     evidence_count INTEGER NOT NULL,
                     first_timestamp_millis INTEGER NOT NULL,
                     first_native_id BLOB NOT NULL,
                     last_timestamp_millis INTEGER NOT NULL,
                     last_native_id BLOB NOT NULL,
                     PRIMARY KEY(source_service, target_service)
                 );
                 CREATE INDEX IF NOT EXISTS service_edges_target
                     ON service_edges(target_service, source_service);
                 CREATE TABLE IF NOT EXISTS edge_evidence (
                     native_id BLOB PRIMARY KEY REFERENCES history_records(native_id),
                     source_service TEXT NOT NULL,
                     target_service TEXT NOT NULL,
                     FOREIGN KEY(source_service, target_service)
                         REFERENCES service_edges(source_service, target_service)
                 );
                 CREATE INDEX IF NOT EXISTS edge_evidence_edge
                     ON edge_evidence(source_service, target_service);
                 CREATE TABLE IF NOT EXISTS graph_metadata (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     extractor_version INTEGER NOT NULL,
                     graph_version INTEGER NOT NULL,
                     backfill_complete INTEGER NOT NULL CHECK (backfill_complete IN (0, 1))
                 );",
            )
            .map_err(|_| CorpusError::Storage)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO corpus_scope(singleton, tenant_digest, source_digest)
                 VALUES (1, ?1, ?2)",
                params![tenant_digest.as_slice(), source_digest.as_slice()],
            )
            .map_err(|_| CorpusError::Storage)?;
        let bound = connection
            .query_row(
                "SELECT tenant_digest, source_digest FROM corpus_scope WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(|_| CorpusError::Storage)?;
        if bound.0 != tenant_digest || bound.1 != source_digest {
            return Err(CorpusError::ScopeMismatch);
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS index_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    parser_version INTEGER NOT NULL
                 );",
            )
            .map_err(|_| CorpusError::Storage)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO index_metadata(singleton, parser_version) VALUES (1, ?1)",
                [PARSER_INDEX_VERSION],
            )
            .map_err(|_| CorpusError::Storage)?;
        let version: i64 = connection
            .query_row(
                "SELECT parser_version FROM index_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if !matches!(version, 1 | PARSER_INDEX_VERSION) {
            return Err(CorpusError::IndexVersionMismatch);
        }
        connection
            .execute(
                "INSERT OR IGNORE INTO graph_metadata(
                    singleton, extractor_version, graph_version, backfill_complete
                 ) VALUES (1, ?1, 0, 0)",
                [GRAPH_INDEX_VERSION],
            )
            .map_err(|_| CorpusError::Storage)?;
        let graph_extractor_version: i64 = connection
            .query_row(
                "SELECT extractor_version FROM graph_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if !matches!(graph_extractor_version, 1 | GRAPH_INDEX_VERSION) {
            return Err(CorpusError::IndexVersionMismatch);
        }
        connection
            .execute(
                "INSERT OR IGNORE INTO term_metadata(singleton, index_version, backfill_complete)
                 VALUES (1, ?1, 0)",
                [TERM_INDEX_VERSION],
            )
            .map_err(|_| CorpusError::Storage)?;
        let term_version: i64 = connection
            .query_row(
                "SELECT index_version FROM term_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if term_version != TERM_INDEX_VERSION {
            return Err(CorpusError::IndexVersionMismatch);
        }
        if version == 1 {
            // Reset derived state atomically. A crash during the subsequent
            // bounded backfill leaves version 2 with missing memberships,
            // which `index_unindexed_records` resumes on the next open.
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 DELETE FROM group_members;
                 DELETE FROM group_terms;
                 DELETE FROM log_groups;
                 DELETE FROM edge_evidence;
                 DELETE FROM service_edges;
                 UPDATE index_metadata SET parser_version = 2 WHERE singleton = 1;
                 UPDATE graph_metadata SET extractor_version = 2,
                     graph_version = 0, backfill_complete = 0 WHERE singleton = 1;
                 UPDATE term_metadata SET backfill_complete = 0 WHERE singleton = 1;
                 COMMIT;",
                )
                .map_err(|_| CorpusError::Storage)?;
        } else if graph_extractor_version == 1 {
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 DELETE FROM edge_evidence;
                 DELETE FROM service_edges;
                 UPDATE graph_metadata SET extractor_version = 2,
                     graph_version = 0, backfill_complete = 0 WHERE singleton = 1;
                 COMMIT;",
                )
                .map_err(|_| CorpusError::Storage)?;
        }
        let mut store = Self { connection };
        store.index_unindexed_records()?;
        store.backfill_graph_if_needed()?;
        store.backfill_terms_if_needed()?;
        Ok(store)
    }

    fn backfill_terms_if_needed(&mut self) -> Result<(), CorpusError> {
        let ready: i64 = self
            .connection
            .query_row(
                "SELECT backfill_complete FROM term_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if ready == 1 {
            return Ok(());
        }
        let mut cursor = 0;
        loop {
            let cards = self.read_group_cards(cursor, 256)?;
            if cards.is_empty() {
                break;
            }
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| CorpusError::Storage)?;
            for card in &cards {
                let raw: Vec<u8> = transaction
                    .query_row(
                        "SELECT raw FROM history_records WHERE native_id = ?1",
                        [&card.first_native_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| CorpusError::Storage)?;
                let parsed = parse_event(0, &String::from_utf8_lossy(&raw));
                index_group_terms(
                    &transaction,
                    card.group_id,
                    &parsed.service,
                    parsed.role,
                    &parsed.fingerprint,
                )?;
            }
            transaction.commit().map_err(|_| CorpusError::Storage)?;
            cursor = cards.last().expect("nonempty page").group_id;
        }
        self.connection
            .execute(
                "UPDATE term_metadata SET backfill_complete = 1 WHERE singleton = 1",
                [],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    fn backfill_graph_if_needed(&mut self) -> Result<(), CorpusError> {
        let ready: i64 = self
            .connection
            .query_row(
                "SELECT backfill_complete FROM graph_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if ready == 1 {
            return Ok(());
        }
        let mut cursor = None::<CorpusCursor>;
        loop {
            let page = self.read_page(cursor.as_ref(), 64, MAX_RAW_RECORD_BYTES)?;
            if page.records.is_empty() {
                break;
            }
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| CorpusError::Storage)?;
            for record in &page.records {
                index_new_edge(
                    &transaction,
                    &HistoryRecordV1 {
                        native_id: record.native_id.clone(),
                        event_timestamp_millis: record.event_timestamp_millis,
                        bytes: record.bytes.clone(),
                    },
                )?;
            }
            transaction.commit().map_err(|_| CorpusError::Storage)?;
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        self.connection
            .execute(
                "UPDATE graph_metadata SET backfill_complete = 1 WHERE singleton = 1",
                [],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    fn index_unindexed_records(&mut self) -> Result<(), CorpusError> {
        let (records, members) = self.index_membership_counts()?;
        if records == members {
            return Ok(());
        }
        let mut cursor = None::<CorpusCursor>;
        loop {
            let page = self.read_page(cursor.as_ref(), 64, MAX_RAW_RECORD_BYTES)?;
            if page.records.is_empty() {
                break;
            }
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| CorpusError::Storage)?;
            for record in &page.records {
                let indexed = transaction
                    .query_row(
                        "SELECT 1 FROM group_members WHERE native_id = ?1",
                        [&record.native_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|_| CorpusError::Storage)?
                    .is_some();
                if !indexed {
                    index_new_record(
                        &transaction,
                        &HistoryRecordV1 {
                            native_id: record.native_id.clone(),
                            event_timestamp_millis: record.event_timestamp_millis,
                            bytes: record.bytes.clone(),
                        },
                    )?;
                }
            }
            transaction.commit().map_err(|_| CorpusError::Storage)?;
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let (records, members) = self.index_membership_counts()?;
        if records != members {
            return Err(CorpusError::Storage);
        }
        Ok(())
    }

    fn index_membership_counts(&self) -> Result<(i64, i64), CorpusError> {
        self.connection
            .query_row(
                "SELECT (SELECT count(*) FROM history_records),
                        (SELECT count(*) FROM group_members)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| CorpusError::Storage)
    }

    pub fn read_checkpoint(&self) -> Result<Option<HistoryCheckpointV1>, CorpusError> {
        let value = self
            .connection
            .query_row(
                "SELECT completed_through_millis FROM corpus_scope WHERE singleton = 1",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(value.map(|completed_through_millis| HistoryCheckpointV1 {
            completed_through_millis,
        }))
    }

    pub fn commit_page_checked(&mut self, records: &[HistoryRecordV1]) -> Result<(), CorpusError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CorpusError::Storage)?;
        for record in records {
            if record.native_id.is_empty() || record.event_timestamp_millis < 0 {
                return Err(CorpusError::Storage);
            }
            if record.bytes.len() > MAX_RAW_RECORD_BYTES {
                return Err(CorpusError::RecordTooLarge);
            }
            let prior = transaction
                .query_row(
                    "SELECT event_timestamp_millis, raw FROM history_records WHERE native_id = ?1",
                    [&record.native_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|_| CorpusError::Storage)?;
            match prior {
                Some((timestamp, bytes))
                    if timestamp != record.event_timestamp_millis || bytes != record.bytes =>
                {
                    return Err(CorpusError::ConflictingRecord);
                }
                Some(_) => {}
                None => {
                    transaction
                        .execute(
                            "INSERT INTO history_records(native_id, event_timestamp_millis, raw)
                             VALUES (?1, ?2, ?3)",
                            params![
                                record.native_id,
                                record.event_timestamp_millis,
                                record.bytes
                            ],
                        )
                        .map_err(|_| CorpusError::Storage)?;
                    index_new_record(&transaction, record)?;
                    index_new_edge(&transaction, record)?;
                }
            }
        }
        transaction.commit().map_err(|_| CorpusError::Storage)
    }

    pub fn complete_partition_checked(
        &mut self,
        checkpoint: HistoryCheckpointV1,
    ) -> Result<(), CorpusError> {
        let current = self
            .read_checkpoint()?
            .map_or(0, |old| old.completed_through_millis);
        if checkpoint.completed_through_millis <= current {
            return Err(CorpusError::InvalidCheckpoint);
        }
        self.connection
            .execute(
                "UPDATE corpus_scope SET completed_through_millis = ?1 WHERE singleton = 1",
                [checkpoint.completed_through_millis],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    pub fn record_count(&self) -> Result<u64, CorpusError> {
        self.connection
            .query_row("SELECT count(*) FROM history_records", [], |row| row.get(0))
            .map_err(|_| CorpusError::Storage)
    }

    pub fn group_count(&self) -> Result<u64, CorpusError> {
        self.connection
            .query_row("SELECT count(*) FROM log_groups", [], |row| row.get(0))
            .map_err(|_| CorpusError::Storage)
    }

    pub fn graph_version(&self) -> Result<u64, CorpusError> {
        self.connection
            .query_row(
                "SELECT graph_version FROM graph_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)
    }

    /// Page through observed service relationships. Every edge is backed by
    /// original record IDs in `edge_evidence`; no causal claim is encoded.
    pub fn read_edge_cards(
        &self,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<Vec<ServiceEdgeCard>, CorpusError> {
        if limit == 0 || limit > 256 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let (after_source, after_target) = after.map_or((None, None), |(source, target)| {
            (Some(source), Some(target))
        });
        let mut statement = self
            .connection
            .prepare(
                "SELECT source_service, target_service, evidence_count,
                        first_timestamp_millis, last_timestamp_millis,
                        first_native_id, last_native_id
                 FROM service_edges
                 WHERE (?1 IS NULL OR source_service > ?1
                    OR (source_service = ?1 AND target_service > ?2))
                 ORDER BY source_service, target_service LIMIT ?3",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(params![after_source, after_target, limit as i64], |row| {
                Ok(ServiceEdgeCard {
                    source_service: row.get(0)?,
                    target_service: row.get(1)?,
                    evidence_count: row.get(2)?,
                    first_timestamp_millis: row.get(3)?,
                    last_timestamp_millis: row.get(4)?,
                    first_native_id: row.get(5)?,
                    last_native_id: row.get(6)?,
                    evidence_kind: "explicit_log_field",
                })
            })
            .map_err(|_| CorpusError::Storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)
    }

    /// Enumerate the original record IDs that support one observed edge.
    pub fn read_edge_evidence(
        &self,
        source_service: &str,
        target_service: &str,
        after_native_id: Option<&[u8]>,
        limit: usize,
    ) -> Result<EdgeEvidencePage, CorpusError> {
        if limit == 0 || limit > 256 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT native_id FROM edge_evidence
                 WHERE source_service = ?1 AND target_service = ?2
                   AND (?3 IS NULL OR native_id > ?3)
                 ORDER BY native_id LIMIT ?4",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(
                params![
                    source_service,
                    target_service,
                    after_native_id,
                    limit as i64 + 1
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        let mut native_ids = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)?;
        let has_more = native_ids.len() > limit;
        if has_more {
            native_ids.pop();
        }
        let next_cursor = if has_more {
            native_ids.last().cloned()
        } else {
            None
        };
        Ok(EdgeEvidencePage {
            native_ids,
            next_cursor,
        })
    }

    /// Stable, bounded group-card scan. Cards contain no generated log text;
    /// callers resolve the native IDs through `get_record` when needed.
    pub fn read_group_cards(
        &self,
        after_group_id: i64,
        limit: usize,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        if after_group_id < 0 || limit == 0 || limit > 256 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT group_id, service, role, repeat_count,
                        first_timestamp_millis, last_timestamp_millis,
                        first_native_id, last_native_id
                 FROM log_groups WHERE group_id > ?1 ORDER BY group_id LIMIT ?2",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(params![after_group_id, limit as i64], |row| {
                Ok(CorpusGroupCard {
                    group_id: row.get(0)?,
                    service: row.get(1)?,
                    role: row.get(2)?,
                    repeat_count: row.get(3)?,
                    first_timestamp_millis: row.get(4)?,
                    last_timestamp_millis: row.get(5)?,
                    first_native_id: row.get(6)?,
                    last_native_id: row.get(7)?,
                })
            })
            .map_err(|_| CorpusError::Storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)
    }

    /// Search the complete indexed group corpus with a bounded lexical candidate pool.
    /// An empty result does not prove that no relevant logs exist; callers must
    /// surface retrieval uncertainty and may page through all group cards.
    pub fn search_candidate_groups(
        &self,
        task: &str,
        limit: usize,
    ) -> Result<CandidateGroupPage, CorpusError> {
        if limit == 0 || limit > 256 || task.len() > 8192 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let total_groups = self.group_count()?;
        let terms = search_terms(task, 32);
        if terms.is_empty() {
            return Ok(CandidateGroupPage {
                groups: Vec::new(),
                total_groups,
                candidate_pool_truncated: false,
            });
        }
        let placeholders = vec!["?"; terms.len()].join(",");
        let sql = format!(
            "SELECT g.group_id, g.service, g.role, g.repeat_count,
                    g.first_timestamp_millis, g.last_timestamp_millis,
                    g.first_native_id, g.last_native_id
             FROM group_terms t JOIN log_groups g ON g.group_id = t.group_id
             WHERE t.term_digest IN ({placeholders})
             GROUP BY g.group_id
             ORDER BY COUNT(*) DESC,
                CASE g.role WHEN 'critical' THEN 0 WHEN 'error' THEN 1
                    WHEN 'warning' THEN 2 WHEN 'change' THEN 3 ELSE 4 END,
                g.last_timestamp_millis DESC, g.group_id DESC
             LIMIT {}",
            limit + 1
        );
        let digests = terms
            .iter()
            .map(|term| Sha256::digest(term.as_bytes()).to_vec())
            .collect::<Vec<_>>();
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(&digests), |row| {
                Ok(CorpusGroupCard {
                    group_id: row.get(0)?,
                    service: row.get(1)?,
                    role: row.get(2)?,
                    repeat_count: row.get(3)?,
                    first_timestamp_millis: row.get(4)?,
                    last_timestamp_millis: row.get(5)?,
                    first_native_id: row.get(6)?,
                    last_native_id: row.get(7)?,
                })
            })
            .map_err(|_| CorpusError::Storage)?;
        let mut groups = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)?;
        let candidate_pool_truncated = groups.len() > limit;
        groups.truncate(limit);
        Ok(CandidateGroupPage {
            groups,
            total_groups,
            candidate_pool_truncated,
        })
    }

    pub fn get_record(&self, native_id: &[u8]) -> Result<Option<StoredHistoryRecord>, CorpusError> {
        self.connection
            .query_row(
                "SELECT native_id, event_timestamp_millis, raw
                 FROM history_records WHERE native_id = ?1",
                [native_id],
                |row| {
                    Ok(StoredHistoryRecord {
                        native_id: row.get(0)?,
                        event_timestamp_millis: row.get(1)?,
                        bytes: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| CorpusError::Storage)
    }

    /// Read only a bounded prefix for ranking; callers must resolve the full
    /// original record by native ID before including it in a log pack.
    pub fn read_record_sample(
        &self,
        native_id: &[u8],
        max_bytes: usize,
    ) -> Result<Option<RecordSample>, CorpusError> {
        if max_bytes == 0 || max_bytes > 4096 {
            return Err(CorpusError::InvalidPageBudget);
        }
        self.connection
            .query_row(
                "SELECT substr(raw, 1, ?2), length(raw) FROM history_records WHERE native_id = ?1",
                params![native_id, max_bytes as i64],
                |row| {
                    Ok(RecordSample {
                        prefix: row.get(0)?,
                        original_byte_len: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|_| CorpusError::Storage)
    }

    /// Read a bounded page in stable `(event timestamp, native ID)` order.
    /// The cursor names the last returned record; replaying it is harmless.
    pub fn read_page(
        &self,
        after: Option<&CorpusCursor>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<CorpusPage, CorpusError> {
        if max_records == 0
            || max_records > 256
            || max_bytes == 0
            || max_bytes > MAX_RAW_RECORD_BYTES
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        let timestamp = after.map(|cursor| cursor.event_timestamp_millis);
        let native_id = after.map(|cursor| cursor.native_id.as_slice());
        let mut statement = self
            .connection
            .prepare(
                "SELECT native_id, event_timestamp_millis, raw FROM history_records
                 WHERE (?1 IS NULL OR event_timestamp_millis > ?1
                    OR (event_timestamp_millis = ?1 AND native_id > ?2))
                 ORDER BY event_timestamp_millis, native_id LIMIT ?3",
            )
            .map_err(|_| CorpusError::Storage)?;
        let mut rows = statement
            .query(params![
                timestamp,
                native_id,
                i64::try_from(max_records + 1).map_err(|_| CorpusError::Storage)?
            ])
            .map_err(|_| CorpusError::Storage)?;
        let mut records = Vec::new();
        let mut total_bytes = 0usize;
        let mut has_more = false;
        while let Some(row) = rows.next().map_err(|_| CorpusError::Storage)? {
            if records.len() == max_records {
                has_more = true;
                break;
            }
            let record = StoredHistoryRecord {
                native_id: row.get(0).map_err(|_| CorpusError::Storage)?,
                event_timestamp_millis: row.get(1).map_err(|_| CorpusError::Storage)?,
                bytes: row.get(2).map_err(|_| CorpusError::Storage)?,
            };
            let next_total = total_bytes.saturating_add(record.bytes.len());
            if next_total > max_bytes {
                if records.is_empty() {
                    return Err(CorpusError::RecordExceedsPageBudget);
                }
                has_more = true;
                break;
            }
            total_bytes = next_total;
            records.push(record);
        }
        let next_cursor = if has_more {
            records.last().map(|last| CorpusCursor {
                event_timestamp_millis: last.event_timestamp_millis,
                native_id: last.native_id.clone(),
            })
        } else {
            None
        };
        Ok(CorpusPage {
            records,
            next_cursor,
        })
    }
}

fn index_new_record(
    transaction: &Transaction<'_>,
    record: &HistoryRecordV1,
) -> Result<(), CorpusError> {
    // The parser is advisory metadata. Invalid UTF-8 is lossily interpreted
    // here, while the authoritative bytes remain untouched in history_records.
    let text = String::from_utf8_lossy(&record.bytes);
    let parsed = parse_event(0, &text);
    let digest = Sha256::digest(parsed.fingerprint.as_bytes());
    let prior = transaction
        .query_row(
            "SELECT group_id, repeat_count, first_timestamp_millis, first_native_id,
                    last_timestamp_millis, last_native_id
             FROM log_groups
             WHERE service = ?1 AND role = ?2 AND fingerprint_digest = ?3",
            params![&parsed.service, parsed.role, digest.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| CorpusError::Storage)?;
    let group_id = if let Some((id, count, first_time, first_id, last_time, last_id)) = prior {
        let next_count = count.checked_add(1).ok_or(CorpusError::Storage)?;
        let current_key = (record.event_timestamp_millis, record.native_id.as_slice());
        let first_key = (first_time, first_id.as_slice());
        let last_key = (last_time, last_id.as_slice());
        let (next_first_time, next_first_id) = if current_key < first_key {
            (record.event_timestamp_millis, record.native_id.as_slice())
        } else {
            (first_time, first_id.as_slice())
        };
        let (next_last_time, next_last_id) = if current_key > last_key {
            (record.event_timestamp_millis, record.native_id.as_slice())
        } else {
            (last_time, last_id.as_slice())
        };
        transaction
            .execute(
                "UPDATE log_groups SET repeat_count = ?1,
                    first_timestamp_millis = ?2, first_native_id = ?3,
                    last_timestamp_millis = ?4, last_native_id = ?5
                 WHERE group_id = ?6",
                params![
                    next_count,
                    next_first_time,
                    next_first_id,
                    next_last_time,
                    next_last_id,
                    id
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
        id
    } else {
        transaction
            .execute(
                "INSERT INTO log_groups(
                    service, role, fingerprint_digest, repeat_count,
                    first_timestamp_millis, first_native_id,
                    last_timestamp_millis, last_native_id
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?4, ?5)",
                params![
                    &parsed.service,
                    parsed.role,
                    digest.as_slice(),
                    record.event_timestamp_millis,
                    &record.native_id
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction.last_insert_rowid()
    };
    index_group_terms(
        transaction,
        group_id,
        &parsed.service,
        parsed.role,
        &parsed.fingerprint,
    )?;
    transaction
        .execute(
            "INSERT INTO group_members(native_id, group_id) VALUES (?1, ?2)",
            params![&record.native_id, group_id],
        )
        .map_err(|_| CorpusError::Storage)?;
    Ok(())
}

fn search_terms(text: &str, cap: usize) -> BTreeSet<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| term.len() >= 3 && term.len() <= 64)
        .map(str::to_ascii_lowercase)
        .filter(|term| {
            !matches!(
                term.as_str(),
                "the"
                    | "and"
                    | "for"
                    | "with"
                    | "from"
                    | "that"
                    | "this"
                    | "then"
                    | "into"
                    | "what"
                    | "when"
                    | "where"
                    | "why"
                    | "how"
                    | "logs"
                    | "log"
                    | "find"
                    | "show"
            )
        })
        .take(cap)
        .collect()
}

fn index_group_terms(
    transaction: &Transaction<'_>,
    group_id: i64,
    service: &str,
    role: &str,
    fingerprint: &str,
) -> Result<(), CorpusError> {
    for term in search_terms(&format!("{service} {role} {fingerprint}"), 64) {
        let digest = Sha256::digest(term.as_bytes());
        transaction
            .execute(
                "INSERT OR IGNORE INTO group_terms(term_digest, group_id) VALUES (?1, ?2)",
                params![digest.as_slice(), group_id],
            )
            .map_err(|_| CorpusError::Storage)?;
    }
    Ok(())
}

fn index_new_edge(
    transaction: &Transaction<'_>,
    record: &HistoryRecordV1,
) -> Result<(), CorpusError> {
    let already_indexed = transaction
        .query_row(
            "SELECT 1 FROM edge_evidence WHERE native_id = ?1",
            [&record.native_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| CorpusError::Storage)?
        .is_some();
    if already_indexed {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&record.bytes);
    let Some(target) = explicit_peer_service(&text) else {
        return Ok(());
    };
    let source = parse_event(0, &text).service;
    if source == "unknown" || source == target {
        return Ok(());
    }
    let prior = transaction
        .query_row(
            "SELECT evidence_count, first_timestamp_millis, first_native_id,
                    last_timestamp_millis, last_native_id
             FROM service_edges WHERE source_service = ?1 AND target_service = ?2",
            params![&source, &target],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| CorpusError::Storage)?;
    if let Some((count, first_time, first_id, last_time, last_id)) = prior {
        let next_count = count.checked_add(1).ok_or(CorpusError::Storage)?;
        let current_key = (record.event_timestamp_millis, record.native_id.as_slice());
        let first_key = (first_time, first_id.as_slice());
        let last_key = (last_time, last_id.as_slice());
        let (next_first_time, next_first_id) = if current_key < first_key {
            (record.event_timestamp_millis, record.native_id.as_slice())
        } else {
            (first_time, first_id.as_slice())
        };
        let (next_last_time, next_last_id) = if current_key > last_key {
            (record.event_timestamp_millis, record.native_id.as_slice())
        } else {
            (last_time, last_id.as_slice())
        };
        transaction
            .execute(
                "UPDATE service_edges SET evidence_count = ?1,
                    first_timestamp_millis = ?2, first_native_id = ?3,
                    last_timestamp_millis = ?4, last_native_id = ?5
                 WHERE source_service = ?6 AND target_service = ?7",
                params![
                    next_count,
                    next_first_time,
                    next_first_id,
                    next_last_time,
                    next_last_id,
                    &source,
                    &target
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
    } else {
        transaction
            .execute(
                "INSERT INTO service_edges(
                    source_service, target_service, evidence_count,
                    first_timestamp_millis, first_native_id,
                    last_timestamp_millis, last_native_id
                 ) VALUES (?1, ?2, 1, ?3, ?4, ?3, ?4)",
                params![
                    &source,
                    &target,
                    record.event_timestamp_millis,
                    &record.native_id
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
    }
    transaction
        .execute(
            "INSERT INTO edge_evidence(native_id, source_service, target_service)
             VALUES (?1, ?2, ?3)",
            params![&record.native_id, &source, &target],
        )
        .map_err(|_| CorpusError::Storage)?;
    transaction
        .execute(
            "UPDATE graph_metadata SET graph_version = graph_version + 1 WHERE singleton = 1",
            [],
        )
        .map_err(|_| CorpusError::Storage)?;
    Ok(())
}

impl HistoryPageStoreV1 for EncryptedHistoryStore {
    fn checkpoint(&self) -> Result<Option<HistoryCheckpointV1>, HistorySyncErrorV1> {
        self.read_checkpoint()
            .map_err(|_| HistorySyncErrorV1::Store)
    }

    fn commit_page(&mut self, records: &[HistoryRecordV1]) -> Result<(), HistorySyncErrorV1> {
        self.commit_page_checked(records)
            .map_err(|_| HistorySyncErrorV1::Store)
    }

    fn complete_partition(
        &mut self,
        checkpoint: HistoryCheckpointV1,
    ) -> Result<(), HistorySyncErrorV1> {
        self.complete_partition_checked(checkpoint)
            .map_err(|_| HistorySyncErrorV1::Store)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use evidentrail_ingest::{
        HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistorySyncLimitsV1,
        HistorySyncStatusV1, synchronize_history_v1,
    };

    fn test_path() -> PathBuf {
        static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "evidentrail-corpus-{}-{stamp}-{}.db",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cleanup(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn encrypted_store_reopens_and_deduplicates_without_advancing_partial_checkpoint() {
        let path = test_path();
        let key = [7; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let record = HistoryRecordV1 {
            native_id: b"event-1".to_vec(),
            event_timestamp_millis: 5,
            bytes: b"secret original log".to_vec(),
        };
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(std::slice::from_ref(&record))
                .unwrap();
            assert_eq!(store.read_checkpoint().unwrap(), None);
        }
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(std::slice::from_ref(&record))
                .unwrap();
            assert_eq!(store.record_count().unwrap(), 1);
            assert_eq!(
                store.read_record_sample(b"event-1", 6).unwrap().unwrap(),
                RecordSample {
                    prefix: b"secret".to_vec(),
                    original_byte_len: 19
                }
            );
            store
                .complete_partition_checked(HistoryCheckpointV1 {
                    completed_through_millis: 10,
                })
                .unwrap();
            assert_eq!(
                store.get_record(b"event-1").unwrap().unwrap().bytes,
                record.bytes
            );
            let mut changed = record.clone();
            changed.bytes = b"changed".to_vec();
            assert_eq!(
                store.commit_page_checked(&[changed]),
                Err(CorpusError::ConflictingRecord)
            );
            assert_eq!(store.record_count().unwrap(), 1);
        }
        for suffix in ["", "-wal"] {
            let file = format!("{}{suffix}", path.display());
            if let Ok(file_bytes) = fs::read(file) {
                assert!(
                    !file_bytes
                        .windows(b"secret original log".len())
                        .any(|window| window == b"secret original log")
                );
            }
        }
        assert!(EncryptedHistoryStore::open(&path, &[8; 32], &tenant, &source).is_err());
        assert!(matches!(
            EncryptedHistoryStore::open(&path, &key, &[3; 32], &source),
            Err(CorpusError::ScopeMismatch)
        ));
        cleanup(&path);
    }

    #[test]
    fn restart_replays_incomplete_partition_into_encrypted_store() {
        struct Pages(VecDeque<HistoryPageV1>);
        impl HistoryPageSourceV1 for Pages {
            fn fetch_page(
                &mut self,
                _: HistoryPartitionV1,
                _: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                self.0.pop_front().ok_or(HistorySyncErrorV1::Provider)
            }
        }
        let path = test_path();
        let key = [9; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let record = HistoryRecordV1 {
            native_id: b"event".to_vec(),
            event_timestamp_millis: 5,
            bytes: b"original".to_vec(),
        };
        let first_page = HistoryPageV1 {
            records: vec![record.clone()],
            next_token: Some(b"next".to_vec()),
        };
        let mut limits = HistorySyncLimitsV1 {
            partition_millis: 10,
            max_partitions: 1,
            max_pages_per_partition: 1,
            max_records_per_page: 10,
            max_record_bytes: 100,
        };
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            let mut pages = Pages(VecDeque::from([first_page.clone()]));
            let receipt = synchronize_history_v1(&mut pages, &mut store, 10, limits).unwrap();
            assert_eq!(receipt.status, HistorySyncStatusV1::PartialPageLimit);
            assert_eq!(store.read_checkpoint().unwrap(), None);
        }
        limits.max_pages_per_partition = 2;
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            let mut pages = Pages(VecDeque::from([
                first_page,
                HistoryPageV1 {
                    records: vec![record],
                    next_token: None,
                },
            ]));
            let receipt = synchronize_history_v1(&mut pages, &mut store, 10, limits).unwrap();
            assert_eq!(receipt.status, HistorySyncStatusV1::ScannedToHighWater);
            assert_eq!(store.record_count().unwrap(), 1);
            assert_eq!(
                store
                    .read_checkpoint()
                    .unwrap()
                    .unwrap()
                    .completed_through_millis,
                10
            );
        }
        cleanup(&path);
    }

    #[test]
    fn cursor_pages_cover_timestamp_ties_and_byte_budget_without_omission() {
        let path = test_path();
        let key = [11; 32];
        let mut store = EncryptedHistoryStore::open(&path, &key, &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[
                HistoryRecordV1 {
                    native_id: b"b".to_vec(),
                    event_timestamp_millis: 5,
                    bytes: b"two".to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"a".to_vec(),
                    event_timestamp_millis: 5,
                    bytes: b"one".to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"c".to_vec(),
                    event_timestamp_millis: 6,
                    bytes: b"three".to_vec(),
                },
            ])
            .unwrap();
        let first = store.read_page(None, 2, 5).unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].native_id, b"a");
        let second = store.read_page(first.next_cursor.as_ref(), 2, 8).unwrap();
        assert_eq!(
            second
                .records
                .iter()
                .map(|record| record.native_id.as_slice())
                .collect::<Vec<_>>(),
            vec![b"b".as_slice(), b"c".as_slice()]
        );
        assert!(second.next_cursor.is_none());
        assert_eq!(
            store.read_page(None, 2, 2),
            Err(CorpusError::RecordExceedsPageBudget)
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn group_index_is_atomic_idempotent_and_orders_late_records() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[12; 32], &[1; 32], &[2; 32]).unwrap();
        let first = HistoryRecordV1 {
            native_id: b"late".to_vec(),
            event_timestamp_millis: 20,
            bytes: b"[checkout] ERROR: request trace_id=bbb status=503".to_vec(),
        };
        let earlier = HistoryRecordV1 {
            native_id: b"early".to_vec(),
            event_timestamp_millis: 10,
            bytes: b"[checkout] ERROR: request trace_id=aaa status=503".to_vec(),
        };
        store
            .commit_page_checked(std::slice::from_ref(&first))
            .unwrap();
        store
            .commit_page_checked(std::slice::from_ref(&earlier))
            .unwrap();
        store
            .commit_page_checked(std::slice::from_ref(&earlier))
            .unwrap();
        assert_eq!(store.record_count().unwrap(), 2);
        assert_eq!(store.group_count().unwrap(), 1);
        let cards = store.read_group_cards(0, 64).unwrap();
        assert_eq!(cards[0].repeat_count, 2);
        assert_eq!(cards[0].first_native_id, b"early");
        assert_eq!(cards[0].last_native_id, b"late");
        let distinct = HistoryRecordV1 {
            native_id: b"other".to_vec(),
            event_timestamp_millis: 30,
            bytes: b"[checkout] ERROR: request trace_id=ccc status=429".to_vec(),
        };
        store.commit_page_checked(&[distinct]).unwrap();
        assert_eq!(store.group_count().unwrap(), 2);
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn candidate_search_finds_old_rare_group_and_reports_truncation() {
        let path = test_path();
        let key = [18; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            let mut records = vec![HistoryRecordV1 {
                native_id: b"rare".to_vec(),
                event_timestamp_millis: 1,
                bytes: b"[checkout] ERROR: inventory reservation failed".to_vec(),
            }];
            for index in 0..100 {
                records.push(HistoryRecordV1 {
                    native_id: format!("noise-{index}").into_bytes(),
                    event_timestamp_millis: index + 2,
                    bytes: format!("[api] INFO: heartbeat shard={index}").into_bytes(),
                });
            }
            store.commit_page_checked(&records).unwrap();
            let match_page = store
                .search_candidate_groups("inventory reservation", 1)
                .unwrap();
            assert_eq!(match_page.groups.len(), 1);
            assert_eq!(match_page.groups[0].first_native_id, b"rare");
            assert!(!match_page.candidate_pool_truncated);
            assert_eq!(match_page.total_groups, store.group_count().unwrap());
            assert_eq!(
                store
                    .search_candidate_groups("checkout error", 1)
                    .unwrap()
                    .groups[0]
                    .first_native_id,
                b"rare"
            );
            let capped = store.search_candidate_groups("heartbeat shard", 1).unwrap();
            assert!(capped.candidate_pool_truncated);
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(
                store
                    .search_candidate_groups("reservation", 1)
                    .unwrap()
                    .groups[0]
                    .first_native_id,
                b"rare"
            );
            store
                .connection
                .execute("DELETE FROM group_terms", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE term_metadata SET backfill_complete = 0", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(
                store
                    .search_candidate_groups("reservation", 1)
                    .unwrap()
                    .groups[0]
                    .first_native_id,
                b"rare"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn reopen_rebuilds_missing_group_members_and_rejects_unknown_parser_version() {
        let path = test_path();
        let key = [13; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[HistoryRecordV1 {
                    native_id: b"event".to_vec(),
                    event_timestamp_millis: 5,
                    bytes: b"[api] ERROR: failed".to_vec(),
                }])
                .unwrap();
            store
                .connection
                .execute("DELETE FROM group_members", [])
                .unwrap();
            store
                .connection
                .execute("DELETE FROM group_terms", [])
                .unwrap();
            store
                .connection
                .execute("DELETE FROM log_groups", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.record_count().unwrap(), 1);
            assert_eq!(store.group_count().unwrap(), 1);
            assert_eq!(store.read_group_cards(0, 64).unwrap()[0].repeat_count, 1);
            store
                .connection
                .execute("UPDATE index_metadata SET parser_version = 999", [])
                .unwrap();
        }
        assert!(matches!(
            EncryptedHistoryStore::open(&path, &key, &tenant, &source),
            Err(CorpusError::IndexVersionMismatch)
        ));
        cleanup(&path);
    }

    #[test]
    fn v1_index_migrates_nested_datadog_fields_without_changing_source_bytes() {
        let path = test_path();
        let key = [25; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let raw = br#"{"id":"evt-1","type":"log","attributes":{"service":"checkout","status":"error","message":"inventory failed","attributes":{"peer.service":"database"}}}"#.to_vec();
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[HistoryRecordV1 {
                    native_id: b"evt-1".to_vec(),
                    event_timestamp_millis: 5,
                    bytes: raw.clone(),
                }])
                .unwrap();
            store
                .connection
                .execute("UPDATE log_groups SET service = 'unknown'", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE index_metadata SET parser_version = 1", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE graph_metadata SET extractor_version = 1", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.get_record(b"evt-1").unwrap().unwrap().bytes, raw);
            assert_eq!(
                store.read_group_cards(0, 10).unwrap()[0].service,
                "checkout"
            );
            let edges = store.read_edge_cards(None, 10).unwrap();
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0].source_service, "checkout");
            assert_eq!(edges[0].target_service, "database");
            assert_eq!(
                store
                    .search_candidate_groups("inventory", 10)
                    .unwrap()
                    .groups
                    .len(),
                1
            );
        }
        cleanup(&path);
    }

    #[test]
    fn oversized_record_cannot_make_a_corpus_unreadable_on_reopen() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[14; 32], &[1; 32], &[2; 32]).unwrap();
        let result = store.commit_page_checked(&[HistoryRecordV1 {
            native_id: b"too-large".to_vec(),
            event_timestamp_millis: 1,
            bytes: vec![b'x'; MAX_RAW_RECORD_BYTES + 1],
        }]);
        assert_eq!(result, Err(CorpusError::RecordTooLarge));
        assert_eq!(store.record_count().unwrap(), 0);
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn graph_edges_require_explicit_peer_fields_and_resolve_to_original_records() {
        let path = test_path();
        let key = [15; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let late = HistoryRecordV1 {
            native_id: b"later".to_vec(),
            event_timestamp_millis: 20,
            bytes: br#"{"service":"checkout","peer.service":"database","message":"write failed"}"#
                .to_vec(),
        };
        let early = HistoryRecordV1 {
            native_id: b"earlier".to_vec(),
            event_timestamp_millis: 10,
            bytes: br#"{"service":"checkout","peer":{"service":"database"},"message":"retry"}"#
                .to_vec(),
        };
        let unrelated = HistoryRecordV1 {
            native_id: b"cooccurrence".to_vec(),
            event_timestamp_millis: 15,
            bytes: br#"{"service":"database","message":"disk full"}"#.to_vec(),
        };
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[late.clone(), early.clone(), unrelated])
                .unwrap();
            store
                .commit_page_checked(std::slice::from_ref(&early))
                .unwrap();
            assert_eq!(store.graph_version().unwrap(), 2);
            let edges = store.read_edge_cards(None, 64).unwrap();
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0].source_service, "checkout");
            assert_eq!(edges[0].target_service, "database");
            assert_eq!(edges[0].evidence_count, 2);
            assert_eq!(edges[0].first_native_id, b"earlier");
            assert_eq!(edges[0].last_native_id, b"later");
            assert_eq!(
                store
                    .get_record(&edges[0].first_native_id)
                    .unwrap()
                    .unwrap()
                    .bytes,
                early.bytes
            );
            let first_page = store
                .read_edge_evidence("checkout", "database", None, 1)
                .unwrap();
            assert_eq!(first_page.native_ids, vec![b"earlier".to_vec()]);
            assert_eq!(first_page.next_cursor, Some(b"earlier".to_vec()));
            let last_page = store
                .read_edge_evidence("checkout", "database", first_page.next_cursor.as_deref(), 1)
                .unwrap();
            assert_eq!(last_page.native_ids, vec![b"later".to_vec()]);
            assert!(last_page.next_cursor.is_none());
            store
                .connection
                .execute("DELETE FROM edge_evidence", [])
                .unwrap();
            store
                .connection
                .execute("DELETE FROM service_edges", [])
                .unwrap();
            store
                .connection
                .execute(
                    "UPDATE graph_metadata SET graph_version = 0, backfill_complete = 0",
                    [],
                )
                .unwrap();
        }
        let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        assert_eq!(store.graph_version().unwrap(), 2);
        assert_eq!(
            store.read_edge_cards(None, 64).unwrap()[0].evidence_count,
            2
        );
        drop(store);
        cleanup(&path);
    }
}
