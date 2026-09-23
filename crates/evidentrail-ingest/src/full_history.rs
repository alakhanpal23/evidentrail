//! Provider-neutral full-history synchronization contract.
//!
//! A caller supplies a system-chosen high-water mark. There is no task or
//! user-selected time window in this API. A store must commit each page
//! idempotently by source-native event identity and make the completed-through
//! checkpoint durable only after the final page of a partition is committed.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryPartitionV1 {
    pub start_millis: i64,
    pub end_millis: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRecordV1 {
    pub native_id: Vec<u8>,
    pub event_timestamp_millis: i64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPageV1 {
    pub records: Vec<HistoryRecordV1>,
    pub next_token: Option<Vec<u8>>,
}

/// The checkpoint is exclusive of earlier partitions. Providers with
/// inclusive time filters will replay the boundary event; the store dedups it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCheckpointV1 {
    pub completed_through_millis: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistorySyncLimitsV1 {
    pub partition_millis: i64,
    pub max_partitions: usize,
    pub max_pages_per_partition: usize,
    pub max_records_per_page: usize,
    pub max_record_bytes: usize,
}

impl HistorySyncLimitsV1 {
    #[must_use]
    pub fn valid(self) -> bool {
        self.partition_millis > 0
            && self.max_partitions > 0
            && self.max_pages_per_partition > 0
            && self.max_records_per_page > 0
            && self.max_record_bytes > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistorySyncErrorV1 {
    InvalidConfiguration,
    InvalidPage,
    PermissionDenied,
    AuthenticationChanged,
    TokenExpired,
    Throttled,
    Network,
    Provider,
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistorySyncStatusV1 {
    CaughtUp,
    Backfilling,
    PartialPageLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistorySyncReceiptV1 {
    pub status: HistorySyncStatusV1,
    pub completed_through_millis: i64,
    pub high_water_millis: i64,
    pub completed_partitions: usize,
    pub committed_pages: usize,
    /// Includes replayed records; the store owns durable unique counts.
    pub submitted_records: usize,
}

pub trait HistoryPageSourceV1 {
    fn fetch_page(
        &mut self,
        partition: HistoryPartitionV1,
        next_token: Option<&[u8]>,
    ) -> Result<HistoryPageV1, HistorySyncErrorV1>;
}

/// Implementations must atomically deduplicate each page by native ID and
/// reject a repeated ID with different bytes or timestamp. A checkpoint write
/// must be durable before this method returns, and must never be ahead of the
/// durable pages. The store is scoped to exactly one authorized source.
pub trait HistoryPageStoreV1 {
    fn checkpoint(&self) -> Result<Option<HistoryCheckpointV1>, HistorySyncErrorV1>;
    fn commit_page(&mut self, records: &[HistoryRecordV1]) -> Result<(), HistorySyncErrorV1>;
    fn complete_partition(
        &mut self,
        checkpoint: HistoryCheckpointV1,
    ) -> Result<(), HistorySyncErrorV1>;
}

/// Make bounded progress through every available provider partition from the
/// durable checkpoint up to a frozen system high-water mark. A page cap never
/// advances the checkpoint, so restart replays the incomplete partition.
pub fn synchronize_history_v1(
    source: &mut impl HistoryPageSourceV1,
    store: &mut impl HistoryPageStoreV1,
    high_water_millis: i64,
    limits: HistorySyncLimitsV1,
) -> Result<HistorySyncReceiptV1, HistorySyncErrorV1> {
    if !limits.valid() || high_water_millis <= 0 {
        return Err(HistorySyncErrorV1::InvalidConfiguration);
    }
    let mut completed_through = store
        .checkpoint()?
        .map_or(0, |checkpoint| checkpoint.completed_through_millis);
    if completed_through < 0 || completed_through > high_water_millis {
        return Err(HistorySyncErrorV1::InvalidConfiguration);
    }
    let mut receipt = HistorySyncReceiptV1 {
        status: HistorySyncStatusV1::Backfilling,
        completed_through_millis: completed_through,
        high_water_millis,
        completed_partitions: 0,
        committed_pages: 0,
        submitted_records: 0,
    };
    while completed_through < high_water_millis
        && receipt.completed_partitions < limits.max_partitions
    {
        let end = completed_through
            .saturating_add(limits.partition_millis)
            .min(high_water_millis);
        let partition = HistoryPartitionV1 {
            start_millis: completed_through,
            end_millis: end,
        };
        let mut next_token = None::<Vec<u8>>;
        let mut seen_tokens = BTreeSet::new();
        let mut pages = 0;
        loop {
            if pages == limits.max_pages_per_partition {
                receipt.status = HistorySyncStatusV1::PartialPageLimit;
                return Ok(receipt);
            }
            let page = source.fetch_page(partition, next_token.as_deref())?;
            pages += 1;
            if page.records.len() > limits.max_records_per_page
                || page.records.iter().any(|record| {
                    record.native_id.is_empty()
                        || record.bytes.len() > limits.max_record_bytes
                        || record.event_timestamp_millis < partition.start_millis
                        || record.event_timestamp_millis > partition.end_millis
                })
            {
                return Err(HistorySyncErrorV1::InvalidPage);
            }
            store.commit_page(&page.records)?;
            receipt.committed_pages += 1;
            receipt.submitted_records += page.records.len();
            match page.next_token {
                None => break,
                Some(token) if token.is_empty() || !seen_tokens.insert(token.clone()) => {
                    return Err(HistorySyncErrorV1::InvalidPage);
                }
                Some(token) => next_token = Some(token),
            }
        }
        store.complete_partition(HistoryCheckpointV1 {
            completed_through_millis: end,
        })?;
        completed_through = end;
        receipt.completed_through_millis = end;
        receipt.completed_partitions += 1;
    }
    receipt.status = if completed_through == high_water_millis {
        HistorySyncStatusV1::CaughtUp
    } else {
        HistorySyncStatusV1::Backfilling
    };
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;

    struct Source(VecDeque<HistoryPageV1>);

    impl HistoryPageSourceV1 for Source {
        fn fetch_page(
            &mut self,
            _: HistoryPartitionV1,
            _: Option<&[u8]>,
        ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
            self.0.pop_front().ok_or(HistorySyncErrorV1::Provider)
        }
    }

    #[derive(Default)]
    struct Store {
        checkpoint: Option<HistoryCheckpointV1>,
        records: BTreeMap<Vec<u8>, (i64, Vec<u8>)>,
    }

    impl HistoryPageStoreV1 for Store {
        fn checkpoint(&self) -> Result<Option<HistoryCheckpointV1>, HistorySyncErrorV1> {
            Ok(self.checkpoint)
        }

        fn commit_page(&mut self, records: &[HistoryRecordV1]) -> Result<(), HistorySyncErrorV1> {
            let mut staged = self.records.clone();
            for record in records {
                let value = (record.event_timestamp_millis, record.bytes.clone());
                match staged.get(&record.native_id) {
                    Some(previous) if previous != &value => return Err(HistorySyncErrorV1::Store),
                    Some(_) => {}
                    None => {
                        staged.insert(record.native_id.clone(), value);
                    }
                }
            }
            self.records = staged;
            Ok(())
        }

        fn complete_partition(
            &mut self,
            checkpoint: HistoryCheckpointV1,
        ) -> Result<(), HistorySyncErrorV1> {
            self.checkpoint = Some(checkpoint);
            Ok(())
        }
    }

    fn limits(max_pages: usize) -> HistorySyncLimitsV1 {
        HistorySyncLimitsV1 {
            partition_millis: 10,
            max_partitions: 2,
            max_pages_per_partition: max_pages,
            max_records_per_page: 10,
            max_record_bytes: 100,
        }
    }

    fn record() -> HistoryRecordV1 {
        HistoryRecordV1 {
            native_id: b"event-1".to_vec(),
            event_timestamp_millis: 5,
            bytes: b"original log".to_vec(),
        }
    }

    #[test]
    fn empty_page_with_token_continues_and_checkpoint_follows_last_page() {
        let mut source = Source(VecDeque::from([
            HistoryPageV1 {
                records: vec![],
                next_token: Some(b"next".to_vec()),
            },
            HistoryPageV1 {
                records: vec![record()],
                next_token: None,
            },
        ]));
        let mut store = Store::default();
        let receipt = synchronize_history_v1(&mut source, &mut store, 10, limits(3)).unwrap();
        assert_eq!(receipt.status, HistorySyncStatusV1::CaughtUp);
        assert_eq!(receipt.committed_pages, 2);
        assert_eq!(store.records.len(), 1);
        assert_eq!(store.checkpoint.unwrap().completed_through_millis, 10);
    }

    #[test]
    fn page_cap_keeps_checkpoint_behind_and_restart_replays_idempotently() {
        let first_page = HistoryPageV1 {
            records: vec![record()],
            next_token: Some(b"next".to_vec()),
        };
        let mut source = Source(VecDeque::from([first_page.clone()]));
        let mut store = Store::default();
        let receipt = synchronize_history_v1(&mut source, &mut store, 10, limits(1)).unwrap();
        assert_eq!(receipt.status, HistorySyncStatusV1::PartialPageLimit);
        assert_eq!(receipt.completed_through_millis, 0);
        assert_eq!(store.checkpoint, None);
        let mut resumed = Source(VecDeque::from([
            first_page,
            HistoryPageV1 {
                records: vec![],
                next_token: None,
            },
        ]));
        let receipt = synchronize_history_v1(&mut resumed, &mut store, 10, limits(3)).unwrap();
        assert_eq!(receipt.status, HistorySyncStatusV1::CaughtUp);
        assert_eq!(store.records.len(), 1);
    }

    #[test]
    fn duplicate_token_and_out_of_partition_records_fail_closed() {
        let mut source = Source(VecDeque::from([HistoryPageV1 {
            records: vec![HistoryRecordV1 {
                event_timestamp_millis: 11,
                ..record()
            }],
            next_token: None,
        }]));
        let mut store = Store::default();
        assert_eq!(
            synchronize_history_v1(&mut source, &mut store, 10, limits(3)),
            Err(HistorySyncErrorV1::InvalidPage)
        );
        assert_eq!(store.checkpoint, None);
        let mut source = Source(VecDeque::from([
            HistoryPageV1 {
                records: vec![],
                next_token: Some(b"next".to_vec()),
            },
            HistoryPageV1 {
                records: vec![],
                next_token: Some(b"next".to_vec()),
            },
        ]));
        assert_eq!(
            synchronize_history_v1(&mut source, &mut store, 10, limits(3)),
            Err(HistorySyncErrorV1::InvalidPage)
        );
        assert_eq!(store.checkpoint, None);
    }

    #[test]
    fn resumes_from_durable_partition_boundary_without_user_window() {
        struct RecordingSource {
            requested: Vec<HistoryPartitionV1>,
        }
        impl HistoryPageSourceV1 for RecordingSource {
            fn fetch_page(
                &mut self,
                partition: HistoryPartitionV1,
                token: Option<&[u8]>,
            ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
                assert!(token.is_none());
                self.requested.push(partition);
                Ok(HistoryPageV1 {
                    records: vec![],
                    next_token: None,
                })
            }
        }
        let mut source = RecordingSource { requested: vec![] };
        let mut store = Store::default();
        let first = synchronize_history_v1(&mut source, &mut store, 25, limits(2)).unwrap();
        assert_eq!(first.status, HistorySyncStatusV1::Backfilling);
        assert_eq!(first.completed_through_millis, 20);
        let second = synchronize_history_v1(&mut source, &mut store, 25, limits(2)).unwrap();
        assert_eq!(second.status, HistorySyncStatusV1::CaughtUp);
        assert_eq!(second.completed_through_millis, 25);
        assert_eq!(
            source.requested,
            vec![
                HistoryPartitionV1 {
                    start_millis: 0,
                    end_millis: 10,
                },
                HistoryPartitionV1 {
                    start_millis: 10,
                    end_millis: 20,
                },
                HistoryPartitionV1 {
                    start_millis: 20,
                    end_millis: 25,
                }
            ]
        );
    }
}
