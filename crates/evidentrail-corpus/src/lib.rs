//! Per-source, SQLCipher-encrypted history storage.
//!
//! The caller owns key acquisition and source authorization. This store
//! provides durable page deduplication and checkpoints; it does not by itself
//! establish provider completeness or make a connected product.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use evidentrail_ingest::{
    HistoryCheckpointV1, HistoryPageStoreV1, HistoryRecordV1, HistorySyncErrorV1,
};
use evidentrail_log_model::{explicit_peer_service, parse_event};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

mod learning_route;
pub use learning_route::{LearningLabel, LearningSplit, RouteVersion};

#[cfg(target_os = "macos")]
mod macos_connected_credentials;
#[cfg(target_os = "macos")]
mod macos_corpus_keychain;
#[cfg(target_os = "macos")]
pub use macos_connected_credentials::MacOsConnectedCredentialKeychainV1;
#[cfg(target_os = "macos")]
pub use macos_corpus_keychain::{
    ConnectedSourceDescriptorV1, CorpusKeychainErrorV1, MacOsCorpusKeychainV1,
};

const PARSER_INDEX_VERSION: i64 = 6;
const GRAPH_INDEX_VERSION: i64 = 2;
const TERM_INDEX_VERSION: i64 = 1;
const MAX_RAW_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 512 * 1024 * 1024;

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
    WalPressure,
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
            Self::WalPressure => "EVIDENTRAIL_CORPUS_WAL_PRESSURE",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackVerdict {
    Useful,
    NotUseful,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackEvaluation {
    pub observations: u64,
    pub positive_groups: u64,
    pub eligible_groups: u64,
    pub promoted_groups: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSample {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
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
pub struct NearbyRecords {
    pub records: Vec<StoredHistoryRecord>,
    pub before_truncated: bool,
    pub after_truncated: bool,
}

/// A local scan receipt, not a provider completeness guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncObservation {
    pub completed_at_millis: i64,
    pub high_water_millis: i64,
    pub scanned_to_high_water: bool,
    pub reconciled_lookback: bool,
}

/// Most recent attempted provider scan. A failed attempt does not erase the
/// last successful observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncAttempt {
    pub completed_at_millis: i64,
    pub high_water_millis: i64,
    pub succeeded: bool,
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
pub struct SevereServiceCard {
    pub service: String,
    pub group_count: u64,
    pub oldest_native_id: Vec<u8>,
    pub newest_native_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SevereServicePage {
    pub services: Vec<SevereServiceCard>,
    pub has_more: bool,
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
    path: PathBuf,
}

/// A stable WAL read view. Writers using another connection can keep syncing
/// while every read through this store observes the same corpus generation.
pub struct CorpusReadSnapshot<'a> {
    store: &'a EncryptedHistoryStore,
}

impl std::ops::Deref for CorpusReadSnapshot<'_> {
    type Target = EncryptedHistoryStore;

    fn deref(&self) -> &Self::Target {
        self.store
    }
}

impl Drop for CorpusReadSnapshot<'_> {
    fn drop(&mut self) {
        let _ = self.store.connection.execute_batch("ROLLBACK");
    }
}

impl EncryptedHistoryStore {
    /// Pin the current committed corpus generation until the guard is dropped.
    /// Opening the snapshot under the catalog lock lets a connected query
    /// release that lock during model selection without mixing sync generations.
    pub fn read_snapshot(&self) -> Result<CorpusReadSnapshot<'_>, CorpusError> {
        self.connection
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| CorpusError::Storage)?;
        if self.record_count().is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(CorpusError::Storage);
        }
        Ok(CorpusReadSnapshot { store: self })
    }

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
                 CREATE TABLE IF NOT EXISTS provider_access_scope_v2 (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     digest BLOB NOT NULL CHECK (length(digest) = 32)
                 );
                 CREATE TABLE IF NOT EXISTS last_sync_observation (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     completed_at_millis INTEGER NOT NULL CHECK (completed_at_millis >= 0),
                     high_water_millis INTEGER NOT NULL CHECK (high_water_millis >= 0),
                     scanned_to_high_water INTEGER NOT NULL CHECK (scanned_to_high_water IN (0, 1)),
                     reconciled_lookback INTEGER NOT NULL CHECK (reconciled_lookback IN (0, 1))
                 );
                 CREATE TABLE IF NOT EXISTS last_sync_attempt (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     completed_at_millis INTEGER NOT NULL CHECK (completed_at_millis >= 0),
                     high_water_millis INTEGER NOT NULL CHECK (high_water_millis >= 0),
                     succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1))
                 );
                 CREATE TABLE IF NOT EXISTS historical_reconciliation (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     cursor_millis INTEGER NOT NULL CHECK (cursor_millis >= 0),
                     last_cycle_end_millis INTEGER CHECK (last_cycle_end_millis >= 0),
                     partition_millis INTEGER NOT NULL DEFAULT 31536000000
                         CHECK (partition_millis > 0 AND partition_millis <= 31536000000)
                 );
                 CREATE TABLE IF NOT EXISTS history_records (
                     native_id BLOB PRIMARY KEY,
                     event_timestamp_millis INTEGER NOT NULL,
                     raw BLOB NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS history_records_time
                     ON history_records(event_timestamp_millis, native_id);
                 CREATE TABLE IF NOT EXISTS feedback_observations (
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     native_id BLOB NOT NULL REFERENCES history_records(native_id) ON DELETE CASCADE,
                     result_nonce BLOB NOT NULL CHECK (length(result_nonce) = 32),
                     verdict INTEGER NOT NULL CHECK (verdict IN (-1, 1)),
                     PRIMARY KEY(task_digest, native_id, result_nonce)
                 );
                 CREATE INDEX IF NOT EXISTS feedback_observations_task
                     ON feedback_observations(task_digest, verdict);
                 CREATE TABLE IF NOT EXISTS independent_log_labels (
                     case_id TEXT NOT NULL,
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     native_id BLOB NOT NULL REFERENCES history_records(native_id) ON DELETE CASCADE,
                     label INTEGER NOT NULL CHECK (label IN (-1, 1)),
                     provenance_digest BLOB NOT NULL CHECK (length(provenance_digest) = 32),
                     split TEXT NOT NULL CHECK (split IN ('development', 'held_out')),
                     parser_version INTEGER NOT NULL,
                     PRIMARY KEY(case_id, native_id)
                 );
                 CREATE TABLE IF NOT EXISTS independent_label_terms (
                     case_id TEXT NOT NULL,
                     term_digest BLOB NOT NULL CHECK (length(term_digest) = 32),
                     PRIMARY KEY(case_id, term_digest)
                 );
                 CREATE TABLE IF NOT EXISTS verified_case_outcomes (
                     case_id TEXT PRIMARY KEY,
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     repaired INTEGER NOT NULL CHECK (repaired IN (0, 1)),
                     verifier_digest BLOB NOT NULL CHECK (length(verifier_digest) = 32)
                 );
                 CREATE TABLE IF NOT EXISTS retrieval_route_versions (
                     version INTEGER PRIMARY KEY,
                     parent_version INTEGER REFERENCES retrieval_route_versions(version),
                     selector_id TEXT NOT NULL,
                     model_id TEXT NOT NULL,
                     training_digest BLOB NOT NULL CHECK (length(training_digest) = 32),
                     report_digest BLOB NOT NULL CHECK (length(report_digest) = 32),
                     held_out_passed INTEGER NOT NULL CHECK (held_out_passed IN (0, 1)),
                     status TEXT NOT NULL CHECK (status IN ('shadow', 'active', 'retired'))
                 );
                 CREATE TABLE IF NOT EXISTS retrieval_route_state (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     active_version INTEGER REFERENCES retrieval_route_versions(version)
                 );
                 CREATE TABLE IF NOT EXISTS feedback_promotions (
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     native_id BLOB NOT NULL REFERENCES history_records(native_id) ON DELETE CASCADE,
                     PRIMARY KEY(task_digest, native_id)
                 );
                 CREATE TABLE IF NOT EXISTS feedback_policy_versions (
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     version INTEGER NOT NULL CHECK (version > 0),
                     parent_version INTEGER,
                     PRIMARY KEY(task_digest, version)
                 );
                 CREATE TABLE IF NOT EXISTS feedback_policy_members (
                     task_digest BLOB NOT NULL CHECK (length(task_digest) = 32),
                     version INTEGER NOT NULL,
                     native_id BLOB NOT NULL REFERENCES history_records(native_id) ON DELETE CASCADE,
                     PRIMARY KEY(task_digest, version, native_id),
                     FOREIGN KEY(task_digest, version)
                         REFERENCES feedback_policy_versions(task_digest, version) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS feedback_policy_state (
                     task_digest BLOB PRIMARY KEY CHECK (length(task_digest) = 32),
                     active_version INTEGER NOT NULL CHECK (active_version > 0),
                     FOREIGN KEY(task_digest, active_version)
                         REFERENCES feedback_policy_versions(task_digest, version)
                 );
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
                 CREATE INDEX IF NOT EXISTS log_groups_severe_time
                     ON log_groups(last_timestamp_millis DESC, group_id DESC)
                     WHERE role IN ('critical', 'error', 'warning');
                 CREATE INDEX IF NOT EXISTS log_groups_severe_service_time
                     ON log_groups(service, last_timestamp_millis DESC, group_id DESC)
                     WHERE role IN ('critical', 'error', 'warning');
                 CREATE INDEX IF NOT EXISTS log_groups_severe_repeat
                     ON log_groups(repeat_count DESC, group_id)
                     WHERE role IN ('critical', 'error', 'warning');
                 CREATE TABLE IF NOT EXISTS severe_service_groups (
                     service TEXT PRIMARY KEY,
                     group_count INTEGER NOT NULL CHECK (group_count > 0),
                     oldest_group_id INTEGER NOT NULL REFERENCES log_groups(group_id),
                     oldest_timestamp_millis INTEGER NOT NULL,
                     newest_group_id INTEGER NOT NULL REFERENCES log_groups(group_id),
                     newest_timestamp_millis INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS severe_service_groups_count
                     ON severe_service_groups(group_count, service);
                 CREATE TABLE IF NOT EXISTS severe_service_metadata (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     index_version INTEGER NOT NULL,
                     backfill_complete INTEGER NOT NULL CHECK (backfill_complete IN (0, 1)),
                     last_group_id INTEGER NOT NULL DEFAULT 0 CHECK (last_group_id >= 0)
                 );
                 DROP INDEX IF EXISTS log_groups_priority;
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
        if !matches!(version, 1 | 2 | 3 | 4 | 5 | PARSER_INDEX_VERSION) {
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
        connection
            .execute(
                "INSERT OR IGNORE INTO severe_service_metadata
                 (singleton, index_version, backfill_complete) VALUES (1, 1, 0)",
                [],
            )
            .map_err(|_| CorpusError::Storage)?;
        let service_index_version: i64 = connection
            .query_row(
                "SELECT index_version FROM severe_service_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        if service_index_version != 1 {
            return Err(CorpusError::IndexVersionMismatch);
        }
        if version == 1 {
            // Reset derived state atomically. A crash during the subsequent
            // bounded backfill leaves version 6 with missing memberships,
            // which `index_unindexed_records` resumes on the next open.
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 DELETE FROM group_members;
                 DELETE FROM group_terms;
                 DELETE FROM severe_service_groups;
                 DELETE FROM log_groups;
                 DELETE FROM edge_evidence;
                 DELETE FROM service_edges;
                 UPDATE index_metadata SET parser_version = 6 WHERE singleton = 1;
                 UPDATE graph_metadata SET extractor_version = 2,
                     graph_version = 0, backfill_complete = 0 WHERE singleton = 1;
                 UPDATE term_metadata SET backfill_complete = 0 WHERE singleton = 1;
                 UPDATE severe_service_metadata SET backfill_complete = 0 WHERE singleton = 1;
                 UPDATE severe_service_metadata SET last_group_id = 0 WHERE singleton = 1;
                 COMMIT;",
                )
                .map_err(|_| CorpusError::Storage)?;
        } else if matches!(version, 2..=5) {
            // Rebuild parser-derived groups, terms, and severe-service summaries
            // without touching source bytes or the independently versioned graph.
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 DELETE FROM group_members;
                 DELETE FROM group_terms;
                 DELETE FROM severe_service_groups;
                 DELETE FROM log_groups;
                 UPDATE index_metadata SET parser_version = 6 WHERE singleton = 1;
                 UPDATE term_metadata SET backfill_complete = 0 WHERE singleton = 1;
                 UPDATE severe_service_metadata SET backfill_complete = 0 WHERE singleton = 1;
                 UPDATE severe_service_metadata SET last_group_id = 0 WHERE singleton = 1;
                 COMMIT;",
                )
                .map_err(|_| CorpusError::Storage)?;
        }
        if version != 1 && graph_extractor_version == 1 {
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
        let mut store = Self {
            connection,
            path: path.to_path_buf(),
        };
        store.backfill_severe_services_if_needed()?;
        store.index_unindexed_records()?;
        store.backfill_graph_if_needed()?;
        store.backfill_terms_if_needed()?;
        Ok(store)
    }

    fn backfill_severe_services_if_needed(&mut self) -> Result<(), CorpusError> {
        let (ready, mut cursor): (i64, i64) = self
            .connection
            .query_row(
                "SELECT backfill_complete, last_group_id
                 FROM severe_service_metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| CorpusError::Storage)?;
        if ready == 1 {
            return Ok(());
        }
        if cursor == 0 {
            self.connection
                .execute("DELETE FROM severe_service_groups", [])
                .map_err(|_| CorpusError::Storage)?;
        }
        loop {
            let cards = self.read_group_cards(cursor, 256)?;
            if cards.is_empty() {
                self.connection
                    .execute(
                        "UPDATE severe_service_metadata SET backfill_complete = 1
                         WHERE singleton = 1",
                        [],
                    )
                    .map_err(|_| CorpusError::Storage)?;
                return Ok(());
            }
            let next_cursor = cards.last().ok_or(CorpusError::Storage)?.group_id;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| CorpusError::Storage)?;
            for card in cards {
                if matches!(card.role.as_str(), "critical" | "error" | "warning") {
                    upsert_severe_service(
                        &transaction,
                        &card.service,
                        card.group_id,
                        card.first_timestamp_millis,
                        card.last_timestamp_millis,
                        true,
                    )?;
                }
            }
            transaction
                .execute(
                    "UPDATE severe_service_metadata SET last_group_id = ?1 WHERE singleton = 1",
                    [next_cursor],
                )
                .map_err(|_| CorpusError::Storage)?;
            transaction.commit().map_err(|_| CorpusError::Storage)?;
            cursor = next_cursor;
        }
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

    /// Cursor for a rolling replay of history older than the recent lookback.
    /// Zero starts a new cycle. The cursor is source-bound inside this corpus.
    pub fn read_historical_reconciliation_cursor(&self) -> Result<i64, CorpusError> {
        self.connection
            .query_row(
                "SELECT cursor_millis FROM historical_reconciliation WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(0))
            .map_err(|_| CorpusError::Storage)
    }

    pub fn read_historical_reconciliation_last_cycle_end(
        &self,
    ) -> Result<Option<i64>, CorpusError> {
        self.connection
            .query_row(
                "SELECT last_cycle_end_millis FROM historical_reconciliation WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.flatten())
            .map_err(|_| CorpusError::Storage)
    }

    pub fn read_historical_reconciliation_partition_millis(&self) -> Result<i64, CorpusError> {
        self.connection
            .query_row(
                "SELECT partition_millis FROM historical_reconciliation WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(365 * 24 * 60 * 60 * 1000))
            .map_err(|_| CorpusError::Storage)
    }

    pub fn record_historical_reconciliation_partition_hint(
        &mut self,
        expected_cursor: i64,
        partition_millis: i64,
    ) -> Result<(), CorpusError> {
        if expected_cursor < 0
            || !(1..=365 * 24 * 60 * 60 * 1000).contains(&partition_millis)
            || self.read_historical_reconciliation_cursor()? != expected_cursor
            || self.read_checkpoint()?.is_none()
        {
            return Err(CorpusError::InvalidCheckpoint);
        }
        self.connection
            .execute(
                "INSERT INTO historical_reconciliation(singleton, cursor_millis, partition_millis)
                 VALUES (1, ?1, ?2) ON CONFLICT(singleton) DO UPDATE SET
                 partition_millis = MIN(historical_reconciliation.partition_millis,
                                        excluded.partition_millis)",
                params![expected_cursor, partition_millis],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    /// Persist only a completed replay boundary. Reaching `cycle_end` starts
    /// the next sweep at zero; a crash before this write safely replays pages.
    pub fn record_historical_reconciliation_progress(
        &mut self,
        expected_cursor: i64,
        completed_through_millis: i64,
        cycle_end_millis: i64,
    ) -> Result<(), CorpusError> {
        if expected_cursor < 0
            || completed_through_millis < expected_cursor
            || cycle_end_millis <= expected_cursor
            || completed_through_millis > cycle_end_millis
            || self.read_historical_reconciliation_cursor()? != expected_cursor
            || self
                .read_checkpoint()?
                .is_none_or(|checkpoint| checkpoint.completed_through_millis < cycle_end_millis)
        {
            return Err(CorpusError::InvalidCheckpoint);
        }
        let next_cursor = if completed_through_millis == cycle_end_millis {
            0
        } else {
            completed_through_millis
        };
        let completed_cycle =
            (completed_through_millis == cycle_end_millis).then_some(cycle_end_millis);
        self.connection
            .execute(
                "INSERT INTO historical_reconciliation(singleton, cursor_millis, last_cycle_end_millis)
                 VALUES (1, ?1, ?2) ON CONFLICT(singleton) DO UPDATE SET
                 cursor_millis = excluded.cursor_millis,
                 last_cycle_end_millis = COALESCE(
                     excluded.last_cycle_end_millis,
                     historical_reconciliation.last_cycle_end_millis)",
                params![next_cursor, completed_cycle],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    pub fn read_sync_observation(&self) -> Result<Option<SyncObservation>, CorpusError> {
        self.connection
            .query_row(
                "SELECT completed_at_millis, high_water_millis,
                        scanned_to_high_water, reconciled_lookback
                 FROM last_sync_observation WHERE singleton = 1",
                [],
                |row| {
                    Ok(SyncObservation {
                        completed_at_millis: row.get(0)?,
                        high_water_millis: row.get(1)?,
                        scanned_to_high_water: row.get(2)?,
                        reconciled_lookback: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|_| CorpusError::Storage)
    }

    pub fn read_sync_attempt(&self) -> Result<Option<SyncAttempt>, CorpusError> {
        self.connection
            .query_row(
                "SELECT completed_at_millis, high_water_millis, succeeded
                 FROM last_sync_attempt WHERE singleton = 1",
                [],
                |row| {
                    Ok(SyncAttempt {
                        completed_at_millis: row.get(0)?,
                        high_water_millis: row.get(1)?,
                        succeeded: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| CorpusError::Storage)
    }

    pub fn record_failed_sync_attempt(&mut self, attempt: SyncAttempt) -> Result<(), CorpusError> {
        if attempt.succeeded {
            return Err(CorpusError::InvalidCheckpoint);
        }
        self.record_sync_attempt(attempt)
    }

    fn record_sync_attempt(&mut self, attempt: SyncAttempt) -> Result<(), CorpusError> {
        if attempt.high_water_millis < 0
            || attempt.completed_at_millis < attempt.high_water_millis
            || self.read_sync_attempt()?.is_some_and(|prior| {
                prior.completed_at_millis > attempt.completed_at_millis
                    || prior.high_water_millis > attempt.high_water_millis
            })
        {
            return Err(CorpusError::InvalidCheckpoint);
        }
        self.connection
            .execute(
                "INSERT INTO last_sync_attempt
                 (singleton, completed_at_millis, high_water_millis, succeeded)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                     completed_at_millis = excluded.completed_at_millis,
                     high_water_millis = excluded.high_water_millis,
                     succeeded = excluded.succeeded",
                params![
                    attempt.completed_at_millis,
                    attempt.high_water_millis,
                    attempt.succeeded,
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    pub fn record_sync_observation(
        &mut self,
        observation: SyncObservation,
    ) -> Result<(), CorpusError> {
        if observation.high_water_millis < 0
            || observation.completed_at_millis < observation.high_water_millis
            || (observation.reconciled_lookback && !observation.scanned_to_high_water)
            || (observation.scanned_to_high_water
                && self.read_checkpoint()?.is_none_or(|checkpoint| {
                    checkpoint.completed_through_millis < observation.high_water_millis
                }))
        {
            return Err(CorpusError::InvalidCheckpoint);
        }
        if self.read_sync_observation()?.is_some_and(|prior| {
            prior.completed_at_millis > observation.completed_at_millis
                || prior.high_water_millis > observation.high_water_millis
        }) || self.read_sync_attempt()?.is_some_and(|prior| {
            prior.completed_at_millis > observation.completed_at_millis
                || prior.high_water_millis > observation.high_water_millis
        }) {
            return Err(CorpusError::InvalidCheckpoint);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "INSERT INTO last_sync_observation
                 (singleton, completed_at_millis, high_water_millis, scanned_to_high_water, reconciled_lookback)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(singleton) DO UPDATE SET
                     completed_at_millis = excluded.completed_at_millis,
                     high_water_millis = excluded.high_water_millis,
                     scanned_to_high_water = excluded.scanned_to_high_water,
                     reconciled_lookback = excluded.reconciled_lookback",
                params![
                    observation.completed_at_millis,
                    observation.high_water_millis,
                    observation.scanned_to_high_water,
                    observation.reconciled_lookback,
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "INSERT INTO last_sync_attempt
                 (singleton, completed_at_millis, high_water_millis, succeeded)
                 VALUES (1, ?1, ?2, 1)
                 ON CONFLICT(singleton) DO UPDATE SET
                     completed_at_millis = excluded.completed_at_millis,
                     high_water_millis = excluded.high_water_millis,
                     succeeded = 1",
                params![
                    observation.completed_at_millis,
                    observation.high_water_millis
                ],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction.commit().map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    /// Return the immutable tenant/source binding recorded in this encrypted
    /// file so a query coordinator can reject mislabeled or mixed-scope stores.
    pub fn scope_digests(&self) -> Result<([u8; 32], [u8; 32]), CorpusError> {
        let (tenant, source): (Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT tenant_digest, source_digest FROM corpus_scope WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| CorpusError::Storage)?;
        let tenant = tenant.try_into().map_err(|_| CorpusError::ScopeMismatch)?;
        let source = source.try_into().map_err(|_| CorpusError::ScopeMismatch)?;
        Ok((tenant, source))
    }

    /// Bind an encrypted corpus to the provider's current access rules. An
    /// older corpus with records but no binding cannot be made safe by merely
    /// observing today's rules; it must be rebuilt under those rules.
    pub fn bind_provider_access_scope(&self, digest: &[u8; 32]) -> Result<(), CorpusError> {
        let prior: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT digest FROM provider_access_scope_v2 WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        if let Some(prior) = prior {
            return if prior.as_slice() == digest {
                Ok(())
            } else {
                Err(CorpusError::ScopeMismatch)
            };
        }
        if self.record_count()? != 0 {
            return Err(CorpusError::ScopeMismatch);
        }
        self.connection
            .execute(
                "INSERT INTO provider_access_scope_v2(singleton, digest) VALUES (1, ?1)",
                [digest.as_slice()],
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    pub fn provider_access_scope_bound(&self) -> Result<bool, CorpusError> {
        self.connection
            .query_row(
                "SELECT 1 FROM provider_access_scope_v2 WHERE singleton = 1",
                [],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(|_| CorpusError::Storage)
    }

    pub fn commit_page_checked(&mut self, records: &[HistoryRecordV1]) -> Result<(), CorpusError> {
        self.ensure_wal_below_limit(MAX_WAL_BYTES)?;
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

    fn ensure_wal_below_limit(&self, max_bytes: u64) -> Result<(), CorpusError> {
        let mut wal = self.path.as_os_str().to_os_string();
        wal.push("-wal");
        let wal = PathBuf::from(wal);
        let wal_bytes = || match wal.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_file() => Ok(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Ok(_) | Err(_) => Err(CorpusError::Storage),
        };
        if wal_bytes()? <= max_bytes {
            return Ok(());
        }
        // A stale large WAL can be truncated after its readers finish. A
        // live snapshot prevents that reset; pause ingestion before the next
        // page rather than letting the file grow without a bound.
        let busy: i64 = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(|_| CorpusError::Storage)?;
        if busy != 0 || wal_bytes()? > max_bytes {
            return Err(CorpusError::WalPressure);
        }
        Ok(())
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

    /// Resolve a source-native record to its current derived template group.
    /// The caller must already hold authorization for this source-bound store.
    pub fn group_for_record(
        &self,
        native_id: &[u8],
    ) -> Result<Option<CorpusGroupCard>, CorpusError> {
        let group_id: Option<i64> = self
            .connection
            .query_row(
                "SELECT group_id FROM group_members WHERE native_id = ?1",
                [native_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        group_id.map(|id| self.read_group_by_id(id)).transpose()
    }

    /// An explicit rating of a previously selected native record. It is
    /// source-local, keyed by a task digest, and cannot modify ranking alone.
    pub fn record_feedback(
        &mut self,
        task: &str,
        native_id: &[u8],
        result_nonce: &[u8; 32],
        verdict: FeedbackVerdict,
    ) -> Result<(), CorpusError> {
        let digest = feedback_task_digest(task)?;
        let group = self
            .group_for_record(native_id)?
            .ok_or(CorpusError::InvalidPageBudget)?;
        let value = match verdict {
            FeedbackVerdict::Useful => 1,
            FeedbackVerdict::NotUseful => -1,
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "INSERT INTO feedback_observations(task_digest,native_id,result_nonce,verdict)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(task_digest,native_id,result_nonce)
             DO UPDATE SET verdict = excluded.verdict",
                params![digest.as_slice(), native_id, result_nonce.as_slice(), value],
            )
            .map_err(|_| CorpusError::Storage)?;
        if verdict == FeedbackVerdict::NotUseful {
            transaction
                .execute(
                    "DELETE FROM feedback_promotions WHERE task_digest=?1 AND native_id IN
                 (SELECT native_id FROM group_members WHERE group_id=?2)",
                    params![digest.as_slice(), group.group_id],
                )
                .map_err(|_| CorpusError::Storage)?;
            transaction
                .execute(
                    "DELETE FROM feedback_policy_members WHERE task_digest=?1 AND native_id IN
                 (SELECT native_id FROM group_members WHERE group_id=?2)",
                    params![digest.as_slice(), group.group_id],
                )
                .map_err(|_| CorpusError::Storage)?;
        }
        transaction.commit().map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    /// Repeated explicit ratings provide a narrow same-task eligibility proxy.
    /// This is not an independent held-out relevance or downstream-fix eval.
    pub fn evaluate_feedback(&self, task: &str) -> Result<FeedbackEvaluation, CorpusError> {
        let digest = feedback_task_digest(task)?;
        let observations = self
            .connection
            .query_row(
                "SELECT count(*) FROM feedback_observations WHERE task_digest=?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT gm.group_id,
                    COUNT(DISTINCT CASE WHEN f.verdict=1 THEN hex(f.result_nonce) END),
                    SUM(CASE WHEN f.verdict=-1 THEN 1 ELSE 0 END)
             FROM feedback_observations f
             JOIN group_members gm ON gm.native_id=f.native_id
             WHERE f.task_digest=?1 GROUP BY gm.group_id",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map([digest.as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .map_err(|_| CorpusError::Storage)?;
        let baseline = self.search_candidate_groups(task, 64)?;
        let baseline_ids = baseline
            .groups
            .iter()
            .map(|card| card.group_id)
            .collect::<BTreeSet<_>>();
        let mut positive_groups = 0;
        let mut eligible_groups = 0;
        for row in rows {
            let (group_id, positives, negatives) = row.map_err(|_| CorpusError::Storage)?;
            if positives > 0 {
                positive_groups += 1;
            }
            if positives >= 3 && negatives == 0 && !baseline_ids.contains(&group_id) {
                eligible_groups += 1;
            }
        }
        let promoted_groups = self
            .connection
            .query_row(
                "SELECT count(*) FROM feedback_promotions WHERE task_digest=?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        Ok(FeedbackEvaluation {
            observations,
            positive_groups,
            eligible_groups,
            promoted_groups,
        })
    }

    pub fn promote_feedback(&mut self, task: &str) -> Result<FeedbackEvaluation, CorpusError> {
        let digest = feedback_task_digest(task)?;
        let baseline = self.search_candidate_groups(task, 64)?;
        let baseline_ids = baseline
            .groups
            .iter()
            .map(|card| card.group_id)
            .collect::<BTreeSet<_>>();
        let mut statement = self
            .connection
            .prepare(
                "SELECT gm.group_id, MIN(f.native_id),
                    COUNT(DISTINCT CASE WHEN f.verdict=1 THEN hex(f.result_nonce) END),
                    SUM(CASE WHEN f.verdict=-1 THEN 1 ELSE 0 END)
             FROM feedback_observations f
             JOIN group_members gm ON gm.native_id=f.native_id
             WHERE f.task_digest=?1 GROUP BY gm.group_id",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map([digest.as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .map_err(|_| CorpusError::Storage)?;
        let eligible = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)?;
        drop(statement);
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        let mut active_version: Option<i64> = transaction
            .query_row(
                "SELECT active_version FROM feedback_policy_state WHERE task_digest=?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        if active_version.is_none() {
            let legacy_count: i64 = transaction
                .query_row(
                    "SELECT count(*) FROM feedback_promotions WHERE task_digest=?1",
                    [digest.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|_| CorpusError::Storage)?;
            if legacy_count > 0 {
                transaction
                    .execute(
                        "INSERT INTO feedback_policy_versions(task_digest,version,parent_version) VALUES (?1,1,NULL)",
                        [digest.as_slice()],
                    )
                    .map_err(|_| CorpusError::Storage)?;
                transaction
                    .execute(
                        "INSERT INTO feedback_policy_members(task_digest,version,native_id)
                         SELECT task_digest,1,native_id FROM feedback_promotions WHERE task_digest=?1",
                        [digest.as_slice()],
                    )
                    .map_err(|_| CorpusError::Storage)?;
                active_version = Some(1);
            }
        }
        let next_version: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(version),0)+1 FROM feedback_policy_versions WHERE task_digest=?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "INSERT INTO feedback_policy_versions(task_digest,version,parent_version) VALUES (?1,?2,?3)",
                params![digest.as_slice(), next_version, active_version],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "DELETE FROM feedback_promotions WHERE task_digest=?1",
                [digest.as_slice()],
            )
            .map_err(|_| CorpusError::Storage)?;
        let mut promoted = 0;
        for (group_id, native_id, positives, negatives) in eligible {
            if positives >= 3 && negatives == 0 && !baseline_ids.contains(&group_id) {
                if promoted == 16 {
                    break;
                }
                transaction.execute(
                    "INSERT OR IGNORE INTO feedback_promotions(task_digest,native_id) VALUES (?1,?2)",
                    params![digest.as_slice(), native_id],
                ).map_err(|_| CorpusError::Storage)?;
                transaction.execute(
                    "INSERT INTO feedback_policy_members(task_digest,version,native_id) VALUES (?1,?2,?3)",
                    params![digest.as_slice(), next_version, native_id],
                ).map_err(|_| CorpusError::Storage)?;
                promoted += 1;
            }
        }
        transaction
            .execute(
                "INSERT INTO feedback_policy_state(task_digest,active_version) VALUES (?1,?2)
                 ON CONFLICT(task_digest) DO UPDATE SET active_version=excluded.active_version",
                params![digest.as_slice(), next_version],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction.commit().map_err(|_| CorpusError::Storage)?;
        self.evaluate_feedback(task)
    }

    pub fn feedback_policy_version(&self, task: &str) -> Result<Option<i64>, CorpusError> {
        let digest = feedback_task_digest(task)?;
        self.connection
            .query_row(
                "SELECT active_version FROM feedback_policy_state WHERE task_digest=?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)
    }

    /// Restore the parent snapshot. A negative rating removes that group's
    /// members from every snapshot, so rollback cannot resurrect rejected
    /// evidence.
    pub fn rollback_feedback(&mut self, task: &str) -> Result<FeedbackEvaluation, CorpusError> {
        let digest = feedback_task_digest(task)?;
        let active = self
            .feedback_policy_version(task)?
            .ok_or(CorpusError::InvalidPageBudget)?;
        let parent: i64 = self
            .connection
            .query_row(
                "SELECT parent_version FROM feedback_policy_versions WHERE task_digest=?1 AND version=?2",
                params![digest.as_slice(), active],
                |row| row.get(0),
            )
            .map_err(|_| CorpusError::InvalidPageBudget)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "DELETE FROM feedback_promotions WHERE task_digest=?1",
                [digest.as_slice()],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "INSERT INTO feedback_promotions(task_digest,native_id)
                 SELECT task_digest,native_id FROM feedback_policy_members
                 WHERE task_digest=?1 AND version=?2",
                params![digest.as_slice(), parent],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction
            .execute(
                "UPDATE feedback_policy_state SET active_version=?2 WHERE task_digest=?1",
                params![digest.as_slice(), parent],
            )
            .map_err(|_| CorpusError::Storage)?;
        transaction.commit().map_err(|_| CorpusError::Storage)?;
        self.evaluate_feedback(task)
    }

    pub fn search_promoted_groups(
        &self,
        task: &str,
        limit: usize,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        if limit == 0 || limit > 16 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let digest = feedback_task_digest(task)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT gm.group_id FROM feedback_promotions p
             JOIN group_members gm ON gm.native_id=p.native_id
             WHERE p.task_digest=?1 ORDER BY gm.group_id LIMIT ?2",
            )
            .map_err(|_| CorpusError::Storage)?;
        let ids = statement
            .query_map(params![digest.as_slice(), limit as i64], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| CorpusError::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)?;
        ids.into_iter()
            .map(|id| self.read_group_by_id(id))
            .collect()
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

    /// Number of distinct query terms and the largest number found in one group.
    pub fn task_match_strength(&self, task: &str) -> Result<(usize, usize), CorpusError> {
        if task.len() > 8192 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let terms = search_terms(task, 32);
        if terms.is_empty() {
            return Ok((0, 0));
        }
        let placeholders = vec!["?"; terms.len()].join(",");
        let sql = format!(
            "SELECT COALESCE(MAX(matches), 0) FROM (
                SELECT COUNT(*) AS matches FROM group_terms
                WHERE term_digest IN ({placeholders}) GROUP BY group_id)"
        );
        let digests = terms
            .iter()
            .map(|term| Sha256::digest(term.as_bytes()).to_vec())
            .collect::<Vec<_>>();
        let matched: i64 = self
            .connection
            .query_row(&sql, rusqlite::params_from_iter(&digests), |row| row.get(0))
            .map_err(|_| CorpusError::Storage)?;
        Ok((
            terms.len(),
            usize::try_from(matched).map_err(|_| CorpusError::Storage)?,
        ))
    }

    /// Fallback when task terms do not match any indexed group. This is a
    /// bounded high-severity sample across observed history, never a
    /// completeness claim.
    pub fn search_priority_groups(&self, limit: usize) -> Result<CandidateGroupPage, CorpusError> {
        if limit == 0 || limit > 256 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let total_groups = self.group_count()?;
        let mut newest = self.read_severe_groups(limit + 1, true)?;
        let candidate_pool_truncated = newest.len() > limit;
        if !candidate_pool_truncated {
            return Ok(CandidateGroupPage {
                groups: newest,
                total_groups,
                candidate_pool_truncated: false,
            });
        }
        if limit == 1 {
            newest.truncate(1);
            return Ok(CandidateGroupPage {
                groups: newest,
                total_groups,
                candidate_pool_truncated: true,
            });
        }
        let end_budget = (limit / 3).max(1);
        let max_timestamp = newest[0].last_timestamp_millis;
        let remaining_recent = newest.split_off(end_budget);
        let oldest = self.read_severe_groups(end_budget, false)?;
        let min_timestamp = oldest[0].last_timestamp_millis;
        let interior_budget = limit.saturating_sub(newest.len() + oldest.len());
        let per_anchor = interior_budget.div_ceil(8);
        let mut streams = vec![oldest, newest];
        let span = i128::from(max_timestamp) - i128::from(min_timestamp);
        for part in [4, 2, 6, 1, 3, 5, 7, 8] {
            let anchor = i128::from(min_timestamp) + span * part / 9;
            let anchor = i64::try_from(anchor).map_err(|_| CorpusError::Storage)?;
            streams.push(self.read_severe_groups_from_time(anchor, per_anchor)?);
        }
        let mut groups = self.read_severe_service_representatives((limit / 8).clamp(1, 32))?;
        if groups.len() >= limit {
            groups.truncate(limit);
            return Ok(CandidateGroupPage {
                groups,
                total_groups,
                candidate_pool_truncated,
            });
        }
        let mut seen = groups
            .iter()
            .map(|card| card.group_id)
            .collect::<BTreeSet<_>>();
        let mut streams = streams.into_iter().map(Vec::into_iter).collect::<Vec<_>>();
        loop {
            let mut advanced = false;
            for stream in &mut streams {
                if let Some(next) = stream.next() {
                    advanced = true;
                    if seen.insert(next.group_id) {
                        groups.push(next);
                        if groups.len() == limit {
                            return Ok(CandidateGroupPage {
                                groups,
                                total_groups,
                                candidate_pool_truncated,
                            });
                        }
                    }
                }
            }
            if !advanced {
                break;
            }
        }
        for next in remaining_recent {
            if seen.insert(next.group_id) {
                groups.push(next);
                if groups.len() == limit {
                    break;
                }
            }
        }
        Ok(CandidateGroupPage {
            groups,
            total_groups,
            candidate_pool_truncated,
        })
    }

    /// High-repeat severe templates across the accessible source corpus.
    /// These are candidates, not proof of causality or a complete ranking.
    pub fn search_repeated_severe_groups(
        &self,
        limit: usize,
    ) -> Result<CandidateGroupPage, CorpusError> {
        if limit == 0 || limit > 256 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let total_groups = self.group_count()?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT group_id, service, role, repeat_count,
                        first_timestamp_millis, last_timestamp_millis,
                        first_native_id, last_native_id
                 FROM log_groups
                 WHERE role IN ('critical', 'error', 'warning')
                   AND repeat_count > 1
                 ORDER BY repeat_count DESC, group_id ASC LIMIT ?1",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map([limit as i64 + 1], |row| {
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

    /// List service names observed in severe original logs. The cursor is an
    /// exact service name from a prior page; this does not read raw log bytes.
    pub fn read_severe_service_directory(
        &self,
        after_service: Option<&str>,
        limit: usize,
    ) -> Result<SevereServicePage, CorpusError> {
        if limit == 0 || limit > 64 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let comparison = if after_service.is_some() { ">" } else { ">=" };
        let sql = format!(
            "SELECT summary.service, summary.group_count,
                    oldest.first_native_id, newest.last_native_id
             FROM severe_service_groups summary
             JOIN log_groups oldest ON oldest.group_id = summary.oldest_group_id
             JOIN log_groups newest ON newest.group_id = summary.newest_group_id
             WHERE summary.service {comparison} ?1
             ORDER BY summary.service LIMIT ?2"
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(
                params![after_service.unwrap_or(""), (limit + 1) as i64],
                |row| {
                    Ok(SevereServiceCard {
                        service: row.get(0)?,
                        group_count: row.get(1)?,
                        oldest_native_id: row.get(2)?,
                        newest_native_id: row.get(3)?,
                    })
                },
            )
            .map_err(|_| CorpusError::Storage)?;
        let mut services = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)?;
        let has_more = services.len() > limit;
        services.truncate(limit);
        Ok(SevereServicePage { services, has_more })
    }

    /// Resolve a model-selected, exact service name to bounded severe group
    /// cards. The full service group count is reported even when truncated.
    pub fn search_severe_service_groups(
        &self,
        service: &str,
        limit: usize,
    ) -> Result<CandidateGroupPage, CorpusError> {
        if service.is_empty() || service.len() > 256 || limit == 0 || limit > 64 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let total_groups: Option<u64> = self
            .connection
            .query_row(
                "SELECT group_count FROM severe_service_groups WHERE service = ?1",
                [service],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        let Some(total_groups) = total_groups else {
            return Ok(CandidateGroupPage {
                groups: Vec::new(),
                total_groups: 0,
                candidate_pool_truncated: false,
            });
        };
        let per_end = limit.div_ceil(2);
        let oldest = self.read_severe_groups_for_service(service, per_end, false)?;
        let newest = self.read_severe_groups_for_service(service, per_end, true)?;
        let mut groups = Vec::with_capacity(limit);
        let mut seen = BTreeSet::new();
        let mut oldest = oldest.into_iter();
        let mut newest = newest.into_iter();
        loop {
            let mut advanced = false;
            for next in [oldest.next(), newest.next()].into_iter().flatten() {
                advanced = true;
                if seen.insert(next.group_id) {
                    groups.push(next);
                    if groups.len() == limit {
                        break;
                    }
                }
            }
            if !advanced || groups.len() == limit {
                break;
            }
        }
        Ok(CandidateGroupPage {
            groups,
            total_groups,
            candidate_pool_truncated: total_groups > limit as u64,
        })
    }

    fn read_severe_groups_for_service(
        &self,
        service: &str,
        limit: usize,
        newest_first: bool,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        let direction = if newest_first { "DESC" } else { "ASC" };
        let sql = format!(
            "SELECT group_id, service, role, repeat_count,
                    first_timestamp_millis, last_timestamp_millis,
                    first_native_id, last_native_id
             FROM log_groups WHERE service = ?1
               AND role IN ('critical', 'error', 'warning')
             ORDER BY last_timestamp_millis {direction}, group_id {direction} LIMIT ?2"
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(params![service, limit as i64], |row| {
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

    fn read_severe_service_representatives(
        &self,
        service_limit: usize,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        let rare_count = service_limit.div_ceil(2);
        let common_count = service_limit / 2;
        let mut ids = Vec::with_capacity(service_limit * 2);
        let mut seen = BTreeSet::new();
        for (direction, count) in [("ASC", rare_count), ("DESC", common_count)] {
            if count == 0 {
                continue;
            }
            let sql = format!(
                "SELECT oldest_group_id, newest_group_id FROM severe_service_groups
                 ORDER BY group_count {direction}, service {direction} LIMIT ?1"
            );
            let mut statement = self
                .connection
                .prepare(&sql)
                .map_err(|_| CorpusError::Storage)?;
            let rows = statement
                .query_map(
                    [i64::try_from(count).map_err(|_| CorpusError::Storage)?],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(|_| CorpusError::Storage)?;
            for row in rows {
                let (oldest, newest) = row.map_err(|_| CorpusError::Storage)?;
                for id in [oldest, newest] {
                    if seen.insert(id) {
                        ids.push(id);
                    }
                }
            }
        }
        ids.into_iter()
            .map(|id| self.read_group_by_id(id))
            .collect()
    }

    fn read_group_by_id(&self, group_id: i64) -> Result<CorpusGroupCard, CorpusError> {
        self.connection
            .query_row(
                "SELECT group_id, service, role, repeat_count,
                        first_timestamp_millis, last_timestamp_millis,
                        first_native_id, last_native_id
                 FROM log_groups WHERE group_id = ?1",
                [group_id],
                |row| {
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
                },
            )
            .map_err(|_| CorpusError::Storage)
    }

    fn read_severe_groups_from_time(
        &self,
        at_or_after_millis: i64,
        limit: usize,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT group_id, service, role, repeat_count,
                        first_timestamp_millis, last_timestamp_millis,
                        first_native_id, last_native_id
                 FROM log_groups
                 WHERE role IN ('critical', 'error', 'warning')
                   AND last_timestamp_millis >= ?1
                 ORDER BY last_timestamp_millis ASC, group_id ASC LIMIT ?2",
            )
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(
                params![
                    at_or_after_millis,
                    i64::try_from(limit).map_err(|_| CorpusError::Storage)?
                ],
                |row| {
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
                },
            )
            .map_err(|_| CorpusError::Storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)
    }

    fn read_severe_groups(
        &self,
        limit: usize,
        newest_first: bool,
    ) -> Result<Vec<CorpusGroupCard>, CorpusError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let direction = if newest_first { "DESC" } else { "ASC" };
        let sql = format!(
            "SELECT group_id, service, role, repeat_count,
                    first_timestamp_millis, last_timestamp_millis,
                    first_native_id, last_native_id
             FROM log_groups WHERE role IN ('critical', 'error', 'warning')
             ORDER BY last_timestamp_millis {direction}, group_id {direction} LIMIT ?1"
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let rows = statement
            .query_map(
                [i64::try_from(limit).map_err(|_| CorpusError::Storage)?],
                |row| {
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
                },
            )
            .map_err(|_| CorpusError::Storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CorpusError::Storage)
    }

    /// Retrieve groups from services connected to lexical hits by an
    /// explicitly observed log edge. This is a candidate expansion only: an
    /// edge is neither a causal claim nor proof that a neighbor is relevant.
    pub fn search_graph_neighbor_groups(
        &self,
        seed_services: &[String],
        limit: usize,
    ) -> Result<CandidateGroupPage, CorpusError> {
        if seed_services.is_empty()
            || seed_services.len() > 32
            || seed_services
                .iter()
                .any(|service| service.is_empty() || service.len() > 256)
            || limit == 0
            || limit > 256
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        let total_groups = self.group_count()?;
        let placeholders = vec!["?"; seed_services.len()].join(",");
        let sql = format!(
            "SELECT g.group_id, g.service, g.role, g.repeat_count,
                    g.first_timestamp_millis, g.last_timestamp_millis,
                    g.first_native_id, g.last_native_id
             FROM log_groups g
             WHERE g.service IN (
                 SELECT target_service FROM service_edges
                 WHERE source_service IN ({placeholders})
                 UNION
                 SELECT source_service FROM service_edges
                 WHERE target_service IN ({placeholders})
             )
             AND g.service NOT IN ({placeholders})
             ORDER BY CASE g.role WHEN 'critical' THEN 0 WHEN 'error' THEN 1
                 WHEN 'warning' THEN 2 WHEN 'change' THEN 3 ELSE 4 END,
                 g.last_timestamp_millis DESC, g.group_id DESC
             LIMIT {}",
            limit + 1
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let values = seed_services.iter().cycle().take(seed_services.len() * 3);
        let rows = statement
            .query_map(rusqlite::params_from_iter(values), |row| {
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

    /// Resolve a source-local anchor and its chronological neighbors. The
    /// byte budget includes the anchor; no neighboring record is truncated.
    pub fn read_nearby(
        &self,
        native_id: &[u8],
        before: usize,
        after: usize,
        max_bytes: usize,
    ) -> Result<Option<NearbyRecords>, CorpusError> {
        if before > 32 || after > 32 || max_bytes == 0 || max_bytes > 256 * 1024 {
            return Err(CorpusError::InvalidPageBudget);
        }
        let Some(anchor) = self.get_record(native_id)? else {
            return Ok(None);
        };
        if anchor.bytes.len() > max_bytes {
            return Err(CorpusError::RecordExceedsPageBudget);
        }
        let mut remaining = max_bytes - anchor.bytes.len();
        let mut neighbors = Vec::with_capacity(before + after + 1);
        let mut truncated = [false; 2];
        for (side, limit) in [(0, before), (1, after)] {
            let comparison = if side == 0 { "<" } else { ">" };
            let order = if side == 0 { "DESC" } else { "ASC" };
            let sql = format!(
                "SELECT native_id, length(raw) FROM history_records
                 WHERE (event_timestamp_millis, native_id) {comparison} (?1, ?2)
                 ORDER BY event_timestamp_millis {order}, native_id {order} LIMIT ?3"
            );
            let mut statement = self
                .connection
                .prepare(&sql)
                .map_err(|_| CorpusError::Storage)?;
            let rows = statement
                .query_map(
                    params![anchor.event_timestamp_millis, native_id, (limit + 1) as i64],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, usize>(1)?)),
                )
                .map_err(|_| CorpusError::Storage)?;
            let candidates = rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| CorpusError::Storage)?;
            truncated[side] = candidates.len() > limit;
            let mut selected = Vec::new();
            for (id, length) in candidates.into_iter().take(limit) {
                if length > remaining {
                    truncated[side] = true;
                    break;
                }
                remaining -= length;
                selected.push(self.get_record(&id)?.ok_or(CorpusError::Storage)?);
            }
            if side == 0 {
                selected.reverse();
                neighbors.extend(selected);
                neighbors.push(anchor.clone());
            } else {
                neighbors.extend(selected);
            }
        }
        Ok(Some(NearbyRecords {
            records: neighbors,
            before_truncated: truncated[0],
            after_truncated: truncated[1],
        }))
    }

    /// Read bounded fragments from both ends for ranking; callers must
    /// resolve the full original record by native ID before including it in a
    /// log pack.
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
                "SELECT substr(raw, 1, ?2), substr(raw, -?2), length(raw)
                 FROM history_records WHERE native_id = ?1",
                params![native_id, max_bytes as i64],
                |row| {
                    Ok(RecordSample {
                        prefix: row.get(0)?,
                        suffix: row.get(1)?,
                        original_byte_len: row.get(2)?,
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
    let new_group = prior.is_none();
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
    if matches!(parsed.role, "critical" | "error" | "warning") {
        upsert_severe_service(
            transaction,
            &parsed.service,
            group_id,
            record.event_timestamp_millis,
            record.event_timestamp_millis,
            new_group,
        )?;
    }
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

fn upsert_severe_service(
    transaction: &Transaction<'_>,
    service: &str,
    group_id: i64,
    first_timestamp_millis: i64,
    last_timestamp_millis: i64,
    new_group: bool,
) -> Result<(), CorpusError> {
    transaction
        .execute(
            "INSERT INTO severe_service_groups (
                service, group_count, oldest_group_id, oldest_timestamp_millis,
                newest_group_id, newest_timestamp_millis
             ) VALUES (?1, 1, ?2, ?3, ?2, ?4)
             ON CONFLICT(service) DO UPDATE SET
                group_count = severe_service_groups.group_count + ?5,
                oldest_group_id = CASE WHEN
                    excluded.oldest_timestamp_millis < severe_service_groups.oldest_timestamp_millis
                    OR (excluded.oldest_timestamp_millis = severe_service_groups.oldest_timestamp_millis
                        AND excluded.oldest_group_id < severe_service_groups.oldest_group_id)
                    THEN excluded.oldest_group_id ELSE severe_service_groups.oldest_group_id END,
                oldest_timestamp_millis = MIN(severe_service_groups.oldest_timestamp_millis,
                    excluded.oldest_timestamp_millis),
                newest_group_id = CASE WHEN
                    excluded.newest_timestamp_millis > severe_service_groups.newest_timestamp_millis
                    OR (excluded.newest_timestamp_millis = severe_service_groups.newest_timestamp_millis
                        AND excluded.newest_group_id > severe_service_groups.newest_group_id)
                    THEN excluded.newest_group_id ELSE severe_service_groups.newest_group_id END,
                newest_timestamp_millis = MAX(severe_service_groups.newest_timestamp_millis,
                    excluded.newest_timestamp_millis)",
            params![
                service,
                group_id,
                first_timestamp_millis,
                last_timestamp_millis,
                i64::from(new_group),
            ],
        )
        .map_err(|_| CorpusError::Storage)?;
    Ok(())
}

fn feedback_task_digest(task: &str) -> Result<[u8; 32], CorpusError> {
    if task.trim().is_empty() || task.len() > 4096 {
        return Err(CorpusError::InvalidPageBudget);
    }
    let mut hash = Sha256::new();
    hash.update(b"evidentrail/feedback-task/v1\0");
    hash.update(task.trim().as_bytes());
    Ok(hash.finalize().into())
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
            .map_err(|error| match error {
                CorpusError::WalPressure => HistorySyncErrorV1::StoreWalPressure,
                _ => HistorySyncErrorV1::Store,
            })
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
    fn independent_cross_task_labels_are_bounded_and_conflicts_suppress_learning() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[
                HistoryRecordV1 {
                    native_id: b"a".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: b"[checkout] ERROR: inventory reservation failed".to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"b".to_vec(),
                    event_timestamp_millis: 2,
                    bytes: b"[checkout] ERROR: inventory reservation failed".to_vec(),
                },
            ])
            .unwrap();
        let cards = store
            .search_candidate_groups("inventory failure", 16)
            .unwrap()
            .groups;
        assert_eq!(cards.len(), 1);
        store
            .record_verified_case_outcome("repair-1", "inventory issue", true, [8; 32])
            .unwrap();
        for nonce in [[1; 32], [2; 32], [3; 32]] {
            store
                .record_feedback("inventory issue", b"a", &nonce, FeedbackVerdict::Useful)
                .unwrap();
        }
        assert!(
            store
                .shadow_group_bonus("inventory failure", &cards)
                .unwrap()
                .is_empty()
        );
        store
            .record_independent_label(
                "case-1",
                "inventory issue",
                b"a",
                LearningLabel::Relevant,
                LearningSplit::Development,
                [9; 32],
            )
            .unwrap();
        assert!(
            store
                .shadow_group_bonus("inventory failure", &cards)
                .unwrap()
                .is_empty()
        );
        store
            .record_independent_label(
                "case-2-held",
                "inventory timeout",
                b"b",
                LearningLabel::Relevant,
                LearningSplit::HeldOut,
                [10; 32],
            )
            .unwrap();
        assert!(
            store
                .shadow_group_bonus("inventory failure", &cards)
                .unwrap()
                .is_empty()
        );
        store
            .record_independent_label(
                "case-2",
                "inventory timeout",
                b"b",
                LearningLabel::Relevant,
                LearningSplit::Development,
                [10; 32],
            )
            .unwrap();
        assert_eq!(
            store
                .shadow_group_bonus("inventory failure", &cards)
                .unwrap(),
            vec![(cards[0].group_id, 2)]
        );
        assert!(
            store
                .shadow_group_bonus("unrelated database", &cards)
                .unwrap()
                .is_empty()
        );
        store
            .record_independent_label(
                "case-3",
                "inventory deadlock",
                b"b",
                LearningLabel::Irrelevant,
                LearningSplit::Development,
                [11; 32],
            )
            .unwrap();
        assert!(
            store
                .shadow_group_bonus("inventory failure", &cards)
                .unwrap()
                .is_empty()
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn route_promotion_requires_held_out_gate_and_revocation_invalidates_active_route() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[HistoryRecordV1 {
                native_id: b"a".to_vec(),
                event_timestamp_millis: 1,
                bytes: b"[checkout] ERROR: inventory reservation failed".to_vec(),
            }])
            .unwrap();
        store
            .record_independent_label(
                "case-1",
                "inventory failure",
                b"a",
                LearningLabel::Relevant,
                LearningSplit::Development,
                [9; 32],
            )
            .unwrap();
        let failed = store
            .register_shadow_route("selector-v2", "model-v1", [8; 32], false)
            .unwrap();
        assert_eq!(
            store.promote_route(failed),
            Err(CorpusError::InvalidPageBudget)
        );
        let passed = store
            .register_shadow_route("selector-v2", "model-v1", [8; 32], true)
            .unwrap();
        store.promote_route(passed).unwrap();
        assert_eq!(store.active_route().unwrap().unwrap().version, passed);
        store.revoke_learning_evidence(b"a").unwrap();
        assert!(store.active_route().unwrap().is_none());
        assert_eq!(store.rollback_route(), Err(CorpusError::InvalidPageBudget));
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn route_rollback_is_atomic_and_never_activates_stale_parent() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        let first = store
            .register_shadow_route("selector-1", "model-1", [1; 32], true)
            .unwrap();
        store.promote_route(first).unwrap();
        let second = store
            .register_shadow_route("selector-2", "model-2", [2; 32], true)
            .unwrap();
        store.promote_route(second).unwrap();
        assert_eq!(store.rollback_route().unwrap(), Some(first));
        assert_eq!(store.active_route().unwrap().unwrap().version, first);
        assert_eq!(
            store.inspect_route(second).unwrap().unwrap().status,
            "retired"
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn learning_history_does_not_cross_source_boundaries() {
        let a_path = test_path();
        let b_path = test_path();
        let mut a = EncryptedHistoryStore::open(&a_path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        let mut b = EncryptedHistoryStore::open(&b_path, &[8; 32], &[1; 32], &[3; 32]).unwrap();
        let record = HistoryRecordV1 {
            native_id: b"same-id".to_vec(),
            event_timestamp_millis: 1,
            bytes: b"[checkout] ERROR: inventory reservation failed".to_vec(),
        };
        a.commit_page_checked(&[record.clone()]).unwrap();
        b.commit_page_checked(&[record]).unwrap();
        a.record_independent_label(
            "a1",
            "inventory failure",
            b"same-id",
            LearningLabel::Relevant,
            LearningSplit::Development,
            [4; 32],
        )
        .unwrap();
        a.record_independent_label(
            "a2",
            "inventory timeout",
            b"same-id",
            LearningLabel::Relevant,
            LearningSplit::Development,
            [5; 32],
        )
        .unwrap();
        let a_cards = a
            .search_candidate_groups("inventory issue", 8)
            .unwrap()
            .groups;
        let b_cards = b
            .search_candidate_groups("inventory issue", 8)
            .unwrap()
            .groups;
        assert_eq!(
            a.shadow_group_bonus("inventory issue", &a_cards)
                .unwrap()
                .len(),
            1
        );
        assert!(
            b.shadow_group_bonus("inventory issue", &b_cards)
                .unwrap()
                .is_empty()
        );
        assert_ne!(
            a.learning_fingerprint().unwrap(),
            b.learning_fingerprint().unwrap()
        );
        drop(a);
        drop(b);
        cleanup(&a_path);
        cleanup(&b_path);
    }

    #[test]
    fn existing_corpus_migrates_learning_schema_on_reopen() {
        let path = test_path();
        let store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store.connection.execute_batch("DROP TABLE retrieval_route_state; DROP TABLE retrieval_route_versions; DROP TABLE verified_case_outcomes; DROP TABLE independent_label_terms; DROP TABLE independent_log_labels;").unwrap();
        drop(store);
        let mut reopened =
            EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        assert!(reopened.active_route().unwrap().is_none());
        assert_eq!(
            reopened
                .register_shadow_route("selector", "model", [3; 32], false)
                .unwrap(),
            1
        );
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn read_snapshot_stays_stable_while_another_connection_syncs() {
        let path = test_path();
        let key = [7; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let first = HistoryRecordV1 {
            native_id: b"first".to_vec(),
            event_timestamp_millis: 1,
            bytes: b"first original log".to_vec(),
        };
        let second = HistoryRecordV1 {
            native_id: b"second".to_vec(),
            event_timestamp_millis: 2,
            bytes: b"second original log".to_vec(),
        };
        let mut writer = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        writer.commit_page_checked(&[first]).unwrap();
        let reader = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        {
            let snapshot = reader.read_snapshot().unwrap();
            assert_eq!(snapshot.record_count().unwrap(), 1);
            writer.commit_page_checked(&[second]).unwrap();
            assert_eq!(snapshot.record_count().unwrap(), 1);
            assert!(snapshot.get_record(b"second").unwrap().is_none());
            let late_reader = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(late_reader.record_count().unwrap(), 2);
        }
        assert_eq!(reader.record_count().unwrap(), 2);
        assert_eq!(
            reader.get_record(b"second").unwrap().unwrap().bytes,
            b"second original log"
        );
        drop(reader);
        drop(writer);
        cleanup(&path);
    }

    #[test]
    fn long_snapshot_pauses_writer_at_wal_limit_then_allows_resume() {
        let path = test_path();
        let key = [7; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let mut writer = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        let reader = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
        let snapshot = reader.read_snapshot().unwrap();
        for index in 0..24 {
            writer
                .commit_page_checked(&[HistoryRecordV1 {
                    native_id: format!("record-{index}").into_bytes(),
                    event_timestamp_millis: index,
                    bytes: vec![b'x'; 8192],
                }])
                .unwrap();
        }
        assert_eq!(snapshot.record_count().unwrap(), 0);
        assert_eq!(
            writer.ensure_wal_below_limit(64 * 1024),
            Err(CorpusError::WalPressure)
        );
        drop(snapshot);
        assert_eq!(writer.ensure_wal_below_limit(64 * 1024), Ok(()));
        assert_eq!(writer.record_count().unwrap(), 24);
        drop(reader);
        drop(writer);
        cleanup(&path);
    }

    #[test]
    fn provider_scope_change_and_unbound_cached_records_fail_closed() {
        let path = test_path();
        let key = [7; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let record = HistoryRecordV1 {
            native_id: b"event-1".to_vec(),
            event_timestamp_millis: 5,
            bytes: b"restricted log".to_vec(),
        };
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert!(!store.provider_access_scope_bound().unwrap());
            store
                .connection
                .execute_batch(
                    "CREATE TABLE provider_access_scope (
                         singleton INTEGER PRIMARY KEY, digest BLOB NOT NULL
                     );",
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO provider_access_scope(singleton, digest) VALUES (1, ?1)",
                    [[9; 32].as_slice()],
                )
                .unwrap();
            store
                .commit_page_checked(std::slice::from_ref(&record))
                .unwrap();
            assert_eq!(
                store.bind_provider_access_scope(&[3; 32]),
                Err(CorpusError::ScopeMismatch)
            );
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert!(!store.provider_access_scope_bound().unwrap());
            assert_eq!(
                store.bind_provider_access_scope(&[3; 32]),
                Err(CorpusError::ScopeMismatch)
            );
        }
        cleanup(&path);
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store.bind_provider_access_scope(&[3; 32]).unwrap();
            assert!(store.provider_access_scope_bound().unwrap());
            store.commit_page_checked(&[record]).unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.bind_provider_access_scope(&[3; 32]), Ok(()));
            assert_eq!(
                store.bind_provider_access_scope(&[4; 32]),
                Err(CorpusError::ScopeMismatch)
            );
        }
        cleanup(&path);
    }

    #[test]
    fn sync_observation_persists_and_cannot_overstate_checkpoint() {
        let path = test_path();
        let key = [7; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let complete = SyncObservation {
            completed_at_millis: 120,
            high_water_millis: 100,
            scanned_to_high_water: true,
            reconciled_lookback: true,
        };
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.read_sync_observation().unwrap(), None);
            assert_eq!(
                store.record_sync_observation(complete),
                Err(CorpusError::InvalidCheckpoint)
            );
            store
                .complete_partition_checked(HistoryCheckpointV1 {
                    completed_through_millis: 100,
                })
                .unwrap();
            store.record_sync_observation(complete).unwrap();
            assert_eq!(
                store.read_sync_attempt().unwrap(),
                Some(SyncAttempt {
                    completed_at_millis: 120,
                    high_water_millis: 100,
                    succeeded: true,
                })
            );
            store
                .record_failed_sync_attempt(SyncAttempt {
                    completed_at_millis: 130,
                    high_water_millis: 125,
                    succeeded: false,
                })
                .unwrap();
        }
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.read_sync_observation().unwrap(), Some(complete));
            assert_eq!(
                store.read_sync_attempt().unwrap(),
                Some(SyncAttempt {
                    completed_at_millis: 130,
                    high_water_millis: 125,
                    succeeded: false,
                })
            );
            assert_eq!(
                store.record_sync_observation(SyncObservation {
                    completed_at_millis: 119,
                    ..complete
                }),
                Err(CorpusError::InvalidCheckpoint)
            );
            assert_eq!(
                store.record_sync_observation(SyncObservation {
                    completed_at_millis: 130,
                    high_water_millis: 90,
                    ..complete
                }),
                Err(CorpusError::InvalidCheckpoint)
            );
            store
                .complete_partition_checked(HistoryCheckpointV1 {
                    completed_through_millis: 140,
                })
                .unwrap();
            store
                .record_sync_observation(SyncObservation {
                    completed_at_millis: 150,
                    high_water_millis: 140,
                    ..complete
                })
                .unwrap();
            assert!(store.read_sync_attempt().unwrap().unwrap().succeeded);
        }
        cleanup(&path);
    }

    #[test]
    fn historical_reconciliation_cursor_persists_and_resets_only_at_cycle_end() {
        let path = test_path();
        let key = [32; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .complete_partition_checked(HistoryCheckpointV1 {
                    completed_through_millis: 100,
                })
                .unwrap();
            assert_eq!(store.read_historical_reconciliation_cursor().unwrap(), 0);
            assert_eq!(
                store
                    .read_historical_reconciliation_partition_millis()
                    .unwrap(),
                365 * 24 * 60 * 60 * 1000
            );
            store
                .record_historical_reconciliation_partition_hint(0, 50)
                .unwrap();
            assert_eq!(
                store
                    .read_historical_reconciliation_partition_millis()
                    .unwrap(),
                50
            );
            assert_eq!(
                store
                    .read_historical_reconciliation_last_cycle_end()
                    .unwrap(),
                None
            );
            assert_eq!(
                store.record_historical_reconciliation_progress(0, 40, 101),
                Err(CorpusError::InvalidCheckpoint)
            );
            store
                .record_historical_reconciliation_progress(0, 40, 80)
                .unwrap();
            assert_eq!(
                store.record_historical_reconciliation_progress(0, 50, 80),
                Err(CorpusError::InvalidCheckpoint)
            );
        }
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.read_historical_reconciliation_cursor().unwrap(), 40);
            assert_eq!(
                store
                    .read_historical_reconciliation_partition_millis()
                    .unwrap(),
                50
            );
            store
                .record_historical_reconciliation_progress(40, 80, 80)
                .unwrap();
            assert_eq!(store.read_historical_reconciliation_cursor().unwrap(), 0);
            assert_eq!(
                store
                    .read_historical_reconciliation_last_cycle_end()
                    .unwrap(),
                Some(80)
            );
        }
        cleanup(&path);
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
                    suffix: b"al log".to_vec(),
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
    fn record_sample_reads_bounded_head_and_tail_of_large_record() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        let mut raw = b"header".to_vec();
        raw.extend(std::iter::repeat_n(b'x', 10_000));
        raw.extend_from_slice(b"disk exhausted");
        store
            .commit_page_checked(&[HistoryRecordV1 {
                native_id: b"long".to_vec(),
                event_timestamp_millis: 1,
                bytes: raw.clone(),
            }])
            .unwrap();
        let sample = store.read_record_sample(b"long", 32).unwrap().unwrap();
        assert_eq!(sample.prefix.len(), 32);
        assert_eq!(sample.suffix.len(), 32);
        assert!(sample.prefix.starts_with(b"header"));
        assert!(sample.suffix.ends_with(b"disk exhausted"));
        assert_eq!(sample.original_byte_len, raw.len() as u64);
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn feedback_requires_three_independent_ratings_and_explicit_promotion() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[HistoryRecordV1 {
                native_id: b"rare".to_vec(),
                event_timestamp_millis: 1,
                bytes: br#"{"service":"billing","message":"rare upstream timeout"}"#.to_vec(),
            }])
            .unwrap();
        let task = "checkout failure";
        assert!(
            store
                .search_candidate_groups(task, 64)
                .unwrap()
                .groups
                .is_empty()
        );
        for nonce in [[1; 32], [2; 32], [3; 32]] {
            store
                .record_feedback(task, b"rare", &nonce, FeedbackVerdict::Useful)
                .unwrap();
        }
        let evaluation = store.evaluate_feedback(task).unwrap();
        assert_eq!(evaluation.observations, 3);
        assert_eq!(evaluation.eligible_groups, 1);
        assert!(store.search_promoted_groups(task, 8).unwrap().is_empty());
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 1);
        assert_eq!(store.search_promoted_groups(task, 8).unwrap().len(), 1);
        store
            .record_feedback(task, b"rare", &[4; 32], FeedbackVerdict::NotUseful)
            .unwrap();
        assert!(store.search_promoted_groups(task, 8).unwrap().is_empty());
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 0);
        assert!(store.search_promoted_groups(task, 8).unwrap().is_empty());
        assert!(
            store
                .record_feedback(task, b"missing", &[5; 32], FeedbackVerdict::Useful)
                .is_err()
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn feedback_policy_rollback_restores_parent_without_resurrecting_rejected_groups() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[
                HistoryRecordV1 {
                    native_id: b"first".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: br#"{"service":"payments","message":"rare upstream timeout"}"#.to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"second".to_vec(),
                    event_timestamp_millis: 2,
                    bytes: br#"{"service":"inventory","message":"stock counter mismatch"}"#
                        .to_vec(),
                },
            ])
            .unwrap();
        let task = "checkout failure";
        for nonce in [[1; 32], [2; 32], [3; 32]] {
            store
                .record_feedback(task, b"first", &nonce, FeedbackVerdict::Useful)
                .unwrap();
        }
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 1);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(1));
        for nonce in [[4; 32], [5; 32], [6; 32]] {
            store
                .record_feedback(task, b"second", &nonce, FeedbackVerdict::Useful)
                .unwrap();
        }
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 2);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(2));
        assert_eq!(store.rollback_feedback(task).unwrap().promoted_groups, 1);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(1));
        store
            .record_feedback(task, b"first", &[7; 32], FeedbackVerdict::NotUseful)
            .unwrap();
        assert!(store.search_promoted_groups(task, 8).unwrap().is_empty());
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 1);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(3));
        assert_eq!(store.rollback_feedback(task).unwrap().promoted_groups, 0);
        assert!(store.search_promoted_groups(task, 8).unwrap().is_empty());
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn legacy_feedback_promotion_becomes_the_first_rollback_snapshot() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[HistoryRecordV1 {
                native_id: b"legacy".to_vec(),
                event_timestamp_millis: 1,
                bytes: br#"{"service":"payments","message":"rare upstream timeout"}"#.to_vec(),
            }])
            .unwrap();
        let task = "checkout failure";
        let digest = feedback_task_digest(task).unwrap();
        store
            .connection
            .execute(
                "INSERT INTO feedback_promotions(task_digest,native_id) VALUES (?1,?2)",
                params![digest.as_slice(), b"legacy".as_slice()],
            )
            .unwrap();
        assert_eq!(store.feedback_policy_version(task).unwrap(), None);
        assert_eq!(store.promote_feedback(task).unwrap().promoted_groups, 0);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(2));
        assert_eq!(store.rollback_feedback(task).unwrap().promoted_groups, 1);
        assert_eq!(store.feedback_policy_version(task).unwrap(), Some(1));
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn nearby_records_are_exact_ordered_bounded_and_source_scoped() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[7; 32], &[1; 32], &[2; 32]).unwrap();
        let records = [
            (b"a", 1, b"aa"),
            (b"b", 2, b"bb"),
            (b"c", 2, b"cc"),
            (b"d", 3, b"dd"),
        ]
        .into_iter()
        .map(|(id, time, bytes)| HistoryRecordV1 {
            native_id: id.to_vec(),
            event_timestamp_millis: time,
            bytes: bytes.to_vec(),
        })
        .collect::<Vec<_>>();
        store.commit_page_checked(&records).unwrap();
        let nearby = store.read_nearby(b"b", 2, 2, 8).unwrap().unwrap();
        assert_eq!(
            nearby
                .records
                .iter()
                .map(|record| record.native_id.as_slice())
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b", b"c", b"d"]
        );
        assert!(!nearby.before_truncated && !nearby.after_truncated);
        let tight = store.read_nearby(b"b", 2, 2, 4).unwrap().unwrap();
        assert_eq!(
            tight
                .records
                .iter()
                .map(|record| record.native_id.as_slice())
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b"]
        );
        assert!(tight.after_truncated);
        assert_eq!(store.read_nearby(b"missing", 1, 1, 8).unwrap(), None);
        assert_eq!(
            store.read_nearby(b"b", 1, 1, 1),
            Err(CorpusError::RecordExceedsPageBudget)
        );
        assert_eq!(
            store.read_nearby(b"b", 33, 1, 8),
            Err(CorpusError::InvalidPageBudget)
        );
        drop(store);
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
                store.task_match_strength("inventory reservation").unwrap(),
                (2, 2)
            );
            assert_eq!(store.task_match_strength("unmatched quux").unwrap(), (2, 0));
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
                .execute("DELETE FROM severe_service_groups", [])
                .unwrap();
            store
                .connection
                .execute("DELETE FROM log_groups", [])
                .unwrap();
            store
                .connection
                .execute(
                    "UPDATE severe_service_metadata SET backfill_complete = 0,
                     last_group_id = 0",
                    [],
                )
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
    fn v2_index_reclassifies_top_level_status_without_changing_source_bytes_or_graph() {
        let path = test_path();
        let key = [26; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let raw = br#"{"service":"billing","status":"error","message":"downstream call blocked"}"#
            .to_vec();
        let graph_version;
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[HistoryRecordV1 {
                    native_id: b"billing".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: raw.clone(),
                }])
                .unwrap();
            graph_version = store.graph_version().unwrap();
            store
                .connection
                .execute("UPDATE log_groups SET role = 'context'", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE index_metadata SET parser_version = 2", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.get_record(b"billing").unwrap().unwrap().bytes, raw);
            assert_eq!(store.read_group_cards(0, 10).unwrap()[0].role, "error");
            assert_eq!(store.graph_version().unwrap(), graph_version);
            assert_eq!(store.search_priority_groups(10).unwrap().groups.len(), 1);
        }
        cleanup(&path);
    }

    #[test]
    fn v3_index_rebuilds_bgl_groups_without_changing_original_records() {
        let path = test_path();
        let key = [31; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let raw = b"APPREAD 1117869872 2005.06.04 R04-M1-N4-I:J18-U11 2005-06-04-00.24.32.432192 R04-M1-N4-I:J18-U11 RAS APP FATAL worker failed to read control stream".to_vec();
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[HistoryRecordV1 {
                    native_id: b"bgl-alert".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: raw.clone(),
                }])
                .unwrap();
            store
                .connection
                .execute("UPDATE log_groups SET role = 'context'", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE index_metadata SET parser_version = 3", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.get_record(b"bgl-alert").unwrap().unwrap().bytes, raw);
            let groups = store.read_group_cards(0, 10).unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].service, "app");
            assert_eq!(groups[0].role, "critical");
        }
        cleanup(&path);
    }

    #[test]
    fn v4_index_rebuilds_spring_groups_without_changing_original_records() {
        let path = test_path();
        let key = [32; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let first = br#"{"service":"carts","message":"2024-11-22 02:51:59.404 WARN [carts,aaa,aaa,false] 7 --- [exec-1] logger : Request method 'POST' not supported"}"#.to_vec();
        let second = br#"{"service":"carts","message":"2024-11-22 05:44:56.787 WARN [carts,bbb,bbb,false] 7 --- [exec-2] logger : Request method 'POST' not supported"}"#.to_vec();
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[
                    HistoryRecordV1 {
                        native_id: b"first".to_vec(),
                        event_timestamp_millis: 1,
                        bytes: first.clone(),
                    },
                    HistoryRecordV1 {
                        native_id: b"second".to_vec(),
                        event_timestamp_millis: 2,
                        bytes: second.clone(),
                    },
                ])
                .unwrap();
            store
                .connection
                .execute("UPDATE log_groups SET role = 'context'", [])
                .unwrap();
            store
                .connection
                .execute("UPDATE index_metadata SET parser_version = 4", [])
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            assert_eq!(store.get_record(b"first").unwrap().unwrap().bytes, first);
            assert_eq!(store.get_record(b"second").unwrap().unwrap().bytes, second);
            let groups = store.read_group_cards(0, 10).unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].repeat_count, 2);
            assert_eq!(groups[0].role, "warning");
        }
        cleanup(&path);
    }

    #[test]
    fn native_record_resolves_to_its_derived_group() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[33; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[
                HistoryRecordV1 {
                    native_id: b"first".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: br#"{"service":"front-end","message":"POST /cart 500 72.969 ms - 70"}"#
                        .to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"second".to_vec(),
                    event_timestamp_millis: 2,
                    bytes: br#"{"service":"front-end","message":"POST /cart 500 54.305 ms - 82"}"#
                        .to_vec(),
                },
            ])
            .unwrap();
        let first = store.group_for_record(b"first").unwrap().unwrap();
        let second = store.group_for_record(b"second").unwrap().unwrap();
        assert_eq!(first.group_id, second.group_id);
        assert_eq!(first.repeat_count, 2);
        assert_eq!(store.group_for_record(b"missing").unwrap(), None);
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn repeated_severe_search_orders_by_repeat_count_and_reports_cap() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[34; 32], &[1; 32], &[2; 32]).unwrap();
        let mut records = Vec::new();
        for (label, status, count) in [
            ("rare", "error", 2),
            ("common", "warning", 3),
            ("healthy", "info", 5),
        ] {
            for index in 0..count {
                records.push(HistoryRecordV1 {
                    native_id: format!("{label}-{index}").into_bytes(),
                    event_timestamp_millis: index,
                    bytes: format!(
                        "{{\"service\":\"api\",\"status\":\"{status}\",\"message\":\"{label}\"}}"
                    )
                    .into_bytes(),
                });
            }
        }
        store.commit_page_checked(&records).unwrap();
        let page = store.search_repeated_severe_groups(1).unwrap();
        assert!(page.candidate_pool_truncated);
        assert_eq!(page.groups.len(), 1);
        assert_eq!(page.groups[0].repeat_count, 3);
        assert_eq!(
            store.search_repeated_severe_groups(2).unwrap().groups[1].repeat_count,
            2
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn priority_fallback_reports_pool_truncation_and_orders_recent_errors() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[27; 32], &[1; 32], &[2; 32]).unwrap();
        let records = (0..3).map(|index| HistoryRecordV1 {
            native_id: format!("error-{index}").into_bytes(),
            event_timestamp_millis: index,
            bytes: format!("{{\"service\":\"billing\",\"status\":\"error\",\"message\":\"blocked code{}\"}}", ['a', 'b', 'c'][index as usize]).into_bytes(),
        }).collect::<Vec<_>>();
        store.commit_page_checked(&records).unwrap();
        let page = store.search_priority_groups(1).unwrap();
        assert_eq!(page.total_groups, 3);
        assert!(page.candidate_pool_truncated);
        assert_eq!(page.groups[0].first_native_id, b"error-2");
        let stratified = store.search_priority_groups(2).unwrap();
        assert!(stratified.candidate_pool_truncated);
        assert_eq!(
            stratified
                .groups
                .iter()
                .map(|card| card.first_native_id.as_slice())
                .collect::<Vec<_>>(),
            vec![b"error-0".as_slice(), b"error-2"]
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn severe_service_summary_survives_reopen_and_rebuilds_from_existing_groups() {
        let path = test_path();
        let key = [28; 32];
        let tenant = [1; 32];
        let source = [2; 32];
        let billing_raw = br#"{"service":"billing","status":"error","message":"blocked"}"#;
        {
            let mut store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            store
                .commit_page_checked(&[
                    HistoryRecordV1 {
                        native_id: b"billing-new".to_vec(),
                        event_timestamp_millis: 500,
                        bytes: billing_raw.to_vec(),
                    },
                    HistoryRecordV1 {
                        native_id: b"noise".to_vec(),
                        event_timestamp_millis: 100,
                        bytes: br#"{"service":"noise","status":"error","message":"filler"}"#
                            .to_vec(),
                    },
                    HistoryRecordV1 {
                        native_id: b"billing-old".to_vec(),
                        event_timestamp_millis: 50,
                        bytes: billing_raw.to_vec(),
                    },
                ])
                .unwrap();
            let (count, oldest): (i64, i64) = store
                .connection
                .query_row(
                    "SELECT group_count, oldest_timestamp_millis FROM severe_service_groups
                     WHERE service = 'billing'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!((count, oldest), (1, 50));
            assert!(
                store
                    .search_priority_groups(1)
                    .unwrap()
                    .candidate_pool_truncated
            );
            store
                .connection
                .execute("DELETE FROM severe_service_groups", [])
                .unwrap();
            store
                .connection
                .execute(
                    "UPDATE severe_service_metadata SET backfill_complete = 0",
                    [],
                )
                .unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            let (count, oldest): (i64, i64) = store
                .connection
                .query_row(
                    "SELECT group_count, oldest_timestamp_millis FROM severe_service_groups
                     WHERE service = 'billing'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!((count, oldest), (1, 50));
            assert_eq!(store.record_count().unwrap(), 3);
            let first_page = store.read_severe_service_directory(None, 1).unwrap();
            assert_eq!(first_page.services[0].service, "billing");
            assert!(first_page.has_more);
            let second_page = store
                .read_severe_service_directory(Some("billing"), 1)
                .unwrap();
            assert_eq!(second_page.services[0].service, "noise");
            assert!(!second_page.has_more);
            let billing_groups = store.search_severe_service_groups("billing", 4).unwrap();
            assert_eq!(billing_groups.total_groups, 1);
            assert_eq!(billing_groups.groups[0].repeat_count, 2);
            assert_eq!(
                store.get_record(b"billing-old").unwrap().unwrap().bytes,
                billing_raw
            );
            let first = store.read_group_cards(0, 1).unwrap().remove(0);
            store
                .connection
                .execute("DELETE FROM severe_service_groups", [])
                .unwrap();
            let transaction = store.connection.unchecked_transaction().unwrap();
            upsert_severe_service(
                &transaction,
                &first.service,
                first.group_id,
                first.first_timestamp_millis,
                first.last_timestamp_millis,
                true,
            )
            .unwrap();
            transaction
                .execute(
                    "UPDATE severe_service_metadata SET backfill_complete = 0,
                     last_group_id = ?1 WHERE singleton = 1",
                    [first.group_id],
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        {
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &source).unwrap();
            let services: i64 = store
                .connection
                .query_row("SELECT count(*) FROM severe_service_groups", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(services, 2);
            let billing_count: i64 = store
                .connection
                .query_row(
                    "SELECT group_count FROM severe_service_groups WHERE service = 'billing'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(billing_count, 1);
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

    #[test]
    fn graph_neighbors_include_only_explicitly_connected_services() {
        let path = test_path();
        let mut store = EncryptedHistoryStore::open(&path, &[27; 32], &[1; 32], &[2; 32]).unwrap();
        store
            .commit_page_checked(&[
                HistoryRecordV1 {
                    native_id: b"checkout".to_vec(),
                    event_timestamp_millis: 1,
                    bytes: br#"{"service":"checkout","peer.service":"database","status":"error","message":"reservation failed"}"#.to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"database".to_vec(),
                    event_timestamp_millis: 2,
                    bytes: br#"{"service":"database","status":"error","message":"disk full"}"#.to_vec(),
                },
                HistoryRecordV1 {
                    native_id: b"other".to_vec(),
                    event_timestamp_millis: 3,
                    bytes: br#"{"service":"billing","status":"error","message":"unrelated"}"#.to_vec(),
                },
            ])
            .unwrap();
        let lexical = store.search_candidate_groups("reservation", 10).unwrap();
        assert_eq!(lexical.groups.len(), 1);
        assert_eq!(lexical.groups[0].service, "checkout");
        let graph = store
            .search_graph_neighbor_groups(&["checkout".to_owned()], 10)
            .unwrap();
        assert_eq!(graph.groups.len(), 1);
        assert_eq!(graph.groups[0].first_native_id, b"database");
        assert!(!graph.candidate_pool_truncated);
        drop(store);
        cleanup(&path);
    }
}
