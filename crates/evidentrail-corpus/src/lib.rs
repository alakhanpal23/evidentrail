//! Per-source, SQLCipher-encrypted history storage.
//!
//! The caller owns key acquisition and source authorization. This store
//! provides durable page deduplication and checkpoints; it does not by itself
//! establish provider completeness or make a connected product.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use evidentrail_ingest::{
    HistoryCheckpointV1, HistoryPageStoreV1, HistoryRecordV1, HistorySyncErrorV1,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    InvalidKey,
    EncryptionUnavailable,
    ScopeMismatch,
    ConflictingRecord,
    InvalidCheckpoint,
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
                     ON history_records(event_timestamp_millis, native_id);",
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
        Ok(Self { connection })
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use evidentrail_ingest::{
        HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistorySyncLimitsV1,
        HistorySyncStatusV1, synchronize_history_v1,
    };

    fn test_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "evidentrail-corpus-{}-{stamp}.db",
            std::process::id()
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
}
