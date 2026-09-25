//! Source-local, bounded learning. Only independent record labels contribute to
//! ranking; case outcomes and user ratings are stored in separate tables.
use super::{
    CorpusError, CorpusGroupCard, EncryptedHistoryStore, PARSER_INDEX_VERSION,
    feedback_task_digest, search_terms,
};
use rusqlite::{OptionalExtension as _, params};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearningLabel {
    Relevant,
    Irrelevant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearningSplit {
    Development,
    HeldOut,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteVersion {
    pub version: i64,
    pub parent_version: Option<i64>,
    pub selector_id: String,
    pub model_id: String,
    pub training_digest: [u8; 32],
    pub report_digest: [u8; 32],
    pub held_out_passed: bool,
    pub status: String,
}

impl EncryptedHistoryStore {
    /// Remove every learning annotation for a revoked record. The active
    /// fingerprint changes immediately, so the old route stops applying.
    pub fn revoke_learning_evidence(&mut self, native_id: &[u8]) -> Result<(), CorpusError> {
        let tx = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        tx.execute(
            "DELETE FROM independent_log_labels WHERE native_id=?1",
            [native_id],
        )
        .map_err(|_| CorpusError::Storage)?;
        tx.execute("DELETE FROM independent_label_terms WHERE case_id NOT IN (SELECT DISTINCT case_id FROM independent_log_labels)", [])
            .map_err(|_| CorpusError::Storage)?;
        tx.commit().map_err(|_| CorpusError::Storage)
    }
    /// The provenance digest identifies an independently reviewed record-level
    /// annotation. A case-level repair outcome must never call this method.
    pub fn record_independent_label(
        &mut self,
        case_id: &str,
        task: &str,
        native_id: &[u8],
        label: LearningLabel,
        split: LearningSplit,
        provenance_digest: [u8; 32],
    ) -> Result<(), CorpusError> {
        if case_id.is_empty()
            || case_id.len() > 128
            || task.trim().is_empty()
            || task.len() > 4096
            || provenance_digest == [0; 32]
            || self.group_for_record(native_id)?.is_none()
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        let task_digest = feedback_task_digest(task)?;
        let terms = search_terms(task, 32);
        let existing_case: Option<(Vec<u8>, String)> = self
            .connection
            .query_row(
                "SELECT task_digest,split FROM independent_log_labels WHERE case_id=?1 LIMIT 1",
                [case_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?;
        let requested_split = if split == LearningSplit::Development {
            "development"
        } else {
            "held_out"
        };
        if existing_case.is_some_and(|(digest, old_split)| {
            digest != task_digest || old_split != requested_split
        }) {
            return Err(CorpusError::InvalidPageBudget);
        }
        let existing_record: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM independent_log_labels WHERE case_id=?1 AND native_id=?2)",
            params![case_id, native_id], |row| row.get(0),
        ).map_err(|_| CorpusError::Storage)?;
        if !existing_record {
            let count: i64 = self
                .connection
                .query_row("SELECT COUNT(*) FROM independent_log_labels", [], |row| {
                    row.get(0)
                })
                .map_err(|_| CorpusError::Storage)?;
            if count >= 4096 {
                return Err(CorpusError::InvalidPageBudget);
            }
        }
        let tx = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        tx.execute("INSERT INTO independent_log_labels(case_id,task_digest,native_id,label,provenance_digest,split,parser_version) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(case_id,native_id) DO UPDATE SET label=excluded.label, provenance_digest=excluded.provenance_digest, split=excluded.split, parser_version=excluded.parser_version", params![case_id, task_digest.as_slice(), native_id, if label == LearningLabel::Relevant {1} else {-1}, provenance_digest.as_slice(), if split == LearningSplit::Development {"development"} else {"held_out"}, PARSER_INDEX_VERSION]).map_err(|_| CorpusError::Storage)?;
        tx.execute(
            "DELETE FROM independent_label_terms WHERE case_id=?1",
            [case_id],
        )
        .map_err(|_| CorpusError::Storage)?;
        for term in terms {
            let digest = Sha256::digest(term.as_bytes());
            tx.execute(
                "INSERT OR IGNORE INTO independent_label_terms(case_id,term_digest) VALUES (?1,?2)",
                params![case_id, digest.as_slice()],
            )
            .map_err(|_| CorpusError::Storage)?;
        }
        tx.commit().map_err(|_| CorpusError::Storage)
    }

    pub fn record_verified_case_outcome(
        &mut self,
        case_id: &str,
        task: &str,
        repaired: bool,
        verifier_digest: [u8; 32],
    ) -> Result<(), CorpusError> {
        if case_id.is_empty() || case_id.len() > 128 || verifier_digest == [0; 32] {
            return Err(CorpusError::InvalidPageBudget);
        }
        let digest = feedback_task_digest(task)?;
        self.connection.execute("INSERT INTO verified_case_outcomes(case_id,task_digest,repaired,verifier_digest) VALUES (?1,?2,?3,?4) ON CONFLICT(case_id) DO UPDATE SET repaired=excluded.repaired,verifier_digest=excluded.verifier_digest", params![case_id, digest.as_slice(), repaired, verifier_digest.as_slice()]).map_err(|_| CorpusError::Storage)?;
        Ok(())
    }

    /// Stable fingerprint changes on label revocation, relabeling, or a
    /// parser-derived group change. No raw log bytes leave the DB.
    pub fn learning_fingerprint(&self) -> Result<[u8; 32], CorpusError> {
        let mut hash = Sha256::new();
        hash.update(b"evidentrail/learning/source/v1\0");
        hash.update(PARSER_INDEX_VERSION.to_be_bytes());
        let mut stmt = self.connection.prepare("SELECT l.case_id,l.task_digest,l.native_id,l.label,l.provenance_digest,l.parser_version,g.fingerprint_digest,gm.group_id FROM independent_log_labels l LEFT JOIN group_members gm ON gm.native_id=l.native_id LEFT JOIN log_groups g ON g.group_id=gm.group_id WHERE l.split='development' ORDER BY l.case_id,l.native_id").map_err(|_| CorpusError::Storage)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(|_| CorpusError::Storage)?;
        for row in rows {
            let (case, task, native, label, provenance, parser, group, group_id) =
                row.map_err(|_| CorpusError::Storage)?;
            for bytes in [
                case.as_bytes(),
                &task,
                &native,
                &provenance,
                group.as_deref().unwrap_or(&[]),
            ] {
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
            hash.update(label.to_be_bytes());
            hash.update(parser.to_be_bytes());
            hash.update(group_id.unwrap_or(-1).to_be_bytes());
        }
        Ok(hash.finalize().into())
    }

    /// Signed, source-local memory is used only for candidate groups already
    /// found by current retrieval. Two independent cases and a matching task
    /// term are required; a conflicting negative suppresses the boost.
    pub fn shadow_group_bonus(
        &self,
        task: &str,
        cards: &[CorpusGroupCard],
    ) -> Result<Vec<(i64, u8)>, CorpusError> {
        let terms = search_terms(task, 32);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let digests = terms
            .iter()
            .map(|t| Sha256::digest(t.as_bytes()).to_vec())
            .collect::<Vec<_>>();
        let allowed = cards
            .iter()
            .take(256)
            .map(|card| card.group_id)
            .collect::<BTreeSet<_>>();
        let placeholders = vec!["?"; digests.len()].join(",");
        let sql = format!(
            "SELECT DISTINCT gm.group_id,l.case_id,l.label FROM independent_log_labels l JOIN group_members gm ON gm.native_id=l.native_id JOIN independent_label_terms lt ON lt.case_id=l.case_id WHERE l.split='development' AND l.parser_version={PARSER_INDEX_VERSION} AND lt.term_digest IN ({placeholders}) LIMIT 4097"
        );
        let mut stmt = self
            .connection
            .prepare(&sql)
            .map_err(|_| CorpusError::Storage)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(&digests), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| CorpusError::Storage)?;
        let mut by_group = BTreeMap::<i64, (BTreeSet<String>, BTreeSet<String>)>::new();
        let mut observed = 0;
        for row in rows {
            let (group, case, label) = row.map_err(|_| CorpusError::Storage)?;
            observed += 1;
            if observed > 4096 {
                return Ok(Vec::new());
            }
            if !allowed.contains(&group) {
                continue;
            }
            let entry = by_group.entry(group).or_default();
            if label > 0 {
                entry.0.insert(case);
            } else {
                entry.1.insert(case);
            }
        }
        Ok(cards
            .iter()
            .take(256)
            .filter_map(|card| {
                let (positive, negative) = by_group.get(&card.group_id)?;
                (positive.len() >= 2 && negative.is_empty())
                    .then_some((card.group_id, positive.len().min(4) as u8))
            })
            .collect())
    }

    pub fn register_shadow_route(
        &mut self,
        selector_id: &str,
        model_id: &str,
        report_digest: [u8; 32],
        held_out_passed: bool,
    ) -> Result<i64, CorpusError> {
        if selector_id.is_empty()
            || selector_id.len() > 128
            || model_id.is_empty()
            || model_id.len() > 128
            || report_digest == [0; 32]
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        let fingerprint = self.learning_fingerprint()?;
        let parent = self.active_route()?.map(|route| route.version);
        let tx = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        let version: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(version),0)+1 FROM retrieval_route_versions",
                [],
                |r| r.get(0),
            )
            .map_err(|_| CorpusError::Storage)?;
        tx.execute("INSERT INTO retrieval_route_versions(version,parent_version,selector_id,model_id,training_digest,report_digest,held_out_passed,status) VALUES (?1,?2,?3,?4,?5,?6,?7,'shadow')", params![version,parent,selector_id,model_id,fingerprint.as_slice(),report_digest.as_slice(),held_out_passed]).map_err(|_| CorpusError::Storage)?;
        tx.commit().map_err(|_| CorpusError::Storage)?;
        Ok(version)
    }

    pub fn inspect_route(&self, version: i64) -> Result<Option<RouteVersion>, CorpusError> {
        self.connection.query_row("SELECT version,parent_version,selector_id,model_id,training_digest,report_digest,held_out_passed,status FROM retrieval_route_versions WHERE version=?1", [version], |r| {
            let training: Vec<u8> = r.get(4)?; let report: Vec<u8> = r.get(5)?;
            Ok(RouteVersion { version:r.get(0)?, parent_version:r.get(1)?, selector_id:r.get(2)?, model_id:r.get(3)?, training_digest: training.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, report_digest: report.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, held_out_passed:r.get(6)?, status:r.get(7)? })
        }).optional().map_err(|_| CorpusError::Storage)
    }

    pub fn active_route(&self) -> Result<Option<RouteVersion>, CorpusError> {
        let version: Option<i64> = self
            .connection
            .query_row(
                "SELECT active_version FROM retrieval_route_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| CorpusError::Storage)?
            .flatten();
        let Some(route) = version
            .map(|v| self.inspect_route(v))
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        if route.training_digest != self.learning_fingerprint()? || !route.held_out_passed {
            return Ok(None);
        }
        Ok(Some(route))
    }

    pub fn promote_route(&mut self, version: i64) -> Result<(), CorpusError> {
        let route = self
            .inspect_route(version)?
            .ok_or(CorpusError::InvalidPageBudget)?;
        if !route.held_out_passed
            || route.report_digest == [0; 32]
            || route.training_digest != self.learning_fingerprint()?
            || route.status != "shadow"
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        if route.parent_version != self.active_route()?.map(|active| active.version) {
            return Err(CorpusError::InvalidPageBudget);
        }
        let tx = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        tx.execute(
            "UPDATE retrieval_route_versions SET status='retired' WHERE status='active'",
            [],
        )
        .map_err(|_| CorpusError::Storage)?;
        tx.execute(
            "UPDATE retrieval_route_versions SET status='active' WHERE version=?1",
            [version],
        )
        .map_err(|_| CorpusError::Storage)?;
        tx.execute("INSERT INTO retrieval_route_state(singleton,active_version) VALUES (1,?1) ON CONFLICT(singleton) DO UPDATE SET active_version=excluded.active_version", [version]).map_err(|_| CorpusError::Storage)?;
        tx.commit().map_err(|_| CorpusError::Storage)
    }

    pub fn rollback_route(&mut self) -> Result<Option<i64>, CorpusError> {
        let active = self.active_route()?.ok_or(CorpusError::InvalidPageBudget)?;
        let parent = active.parent_version;
        let parent_route = parent.map(|p| self.inspect_route(p)).transpose()?.flatten();
        let fingerprint = self.learning_fingerprint()?;
        if parent_route
            .as_ref()
            .is_some_and(|r| !r.held_out_passed || r.training_digest != fingerprint)
        {
            return Err(CorpusError::InvalidPageBudget);
        }
        let tx = self
            .connection
            .transaction()
            .map_err(|_| CorpusError::Storage)?;
        tx.execute(
            "UPDATE retrieval_route_versions SET status='retired' WHERE version=?1",
            [active.version],
        )
        .map_err(|_| CorpusError::Storage)?;
        if let Some(p) = parent {
            tx.execute(
                "UPDATE retrieval_route_versions SET status='active' WHERE version=?1",
                [p],
            )
            .map_err(|_| CorpusError::Storage)?;
        }
        tx.execute(
            "UPDATE retrieval_route_state SET active_version=?1 WHERE singleton=1",
            [parent],
        )
        .map_err(|_| CorpusError::Storage)?;
        tx.commit().map_err(|_| CorpusError::Storage)?;
        Ok(parent)
    }
}
