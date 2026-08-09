use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{DeviceIdentity, EndpointId};
use crate::path::{PathError, ProtocolPath};
use crate::record::{Record, RecordError};
use crate::roster::{RosterChange, RosterError, RosterHash, RosterRevision, select_chain};

const SCHEMA_VERSION: i64 = 1;
const MAX_PEER_HINT_BYTES: usize = 16 * 1024;
const MAX_ROSTER_RETRY_DEPTH: usize = 1_024;
const MAX_OPERATIONAL_EVENT_BYTES: usize = 16 * 1024;
const SCHEMA_APPLICATION_ID: i64 = 1_397_445_465;
const SCHEMA_TABLES: [(&str, &[&str]); 6] = [
    (
        "collections",
        &[
            "name",
            "local_path",
            "resolved_root",
            "scan_status",
            "watch_status",
        ],
    ),
    ("operational_logs", &["id", "created_ns", "payload"]),
    (
        "path_records",
        &[
            "collection",
            "path",
            "record_hash",
            "kind",
            "canonical",
            "materialized",
            "materialized_modified_ns",
            "materialized_size",
            "materialized_hash",
        ],
    ),
    ("peer_health", &["endpoint_id", "reachable"]),
    ("peer_hints", &["endpoint_id", "hint"]),
    ("roster_revisions", &["hash", "canonical"]),
];

pub struct StateStore {
    connection: Connection,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, StateError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StateError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<i64, StateError> {
        Ok(self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn add_collection(
        &self,
        name: &str,
        local_path: &Path,
        resolved_root: Option<&Path>,
    ) -> Result<(), StateError> {
        self.connection.execute(
            "INSERT INTO collections (name, local_path, resolved_root) VALUES (?1, ?2, ?3)",
            params![
                name,
                local_path.as_os_str().as_bytes(),
                resolved_root.map(|path| path.as_os_str().as_bytes())
            ],
        )?;
        Ok(())
    }

    pub fn replace_collection_path(
        &mut self,
        name: &str,
        local_path: &Path,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE collections SET
                local_path = ?2,
                resolved_root = NULL,
                scan_status = 'pending',
                watch_status = 'pending'
             WHERE name = ?1",
            params![name, local_path.as_os_str().as_bytes()],
        )?;
        transaction.execute(
            "UPDATE path_records SET
                materialized = 0,
                materialized_modified_ns = NULL,
                materialized_size = NULL,
                materialized_hash = NULL
             WHERE collection = ?1 AND kind = 1",
            [name],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_collection_scan(
        &mut self,
        name: &str,
        local_path: &Path,
        resolved_root: &Path,
    ) -> Result<bool, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = transaction
            .query_row(
                "SELECT resolved_root FROM collections WHERE name = ?1",
                [name],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .ok_or(StateError::MissingCollection)?;
        let resolved_bytes = resolved_root.as_os_str().as_bytes();
        let changed = previous.as_deref() != Some(resolved_bytes);
        transaction.execute(
            "UPDATE collections SET
                local_path = ?2,
                resolved_root = ?3,
                scan_status = 'active'
             WHERE name = ?1",
            params![name, local_path.as_os_str().as_bytes(), resolved_bytes],
        )?;
        if changed {
            transaction.execute(
                "UPDATE path_records SET
                    materialized = 0,
                    materialized_modified_ns = NULL,
                    materialized_size = NULL,
                    materialized_hash = NULL
                 WHERE collection = ?1 AND kind = 1",
                [name],
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    pub fn set_collection_scan_status(
        &self,
        name: &str,
        status: CollectionScanStatus,
    ) -> Result<(), StateError> {
        self.connection.execute(
            "UPDATE collections SET scan_status = ?2 WHERE name = ?1",
            params![name, status.as_str()],
        )?;
        Ok(())
    }

    pub fn set_collection_watch_status(
        &self,
        name: &str,
        status: CollectionWatchStatus,
    ) -> Result<(), StateError> {
        self.connection.execute(
            "UPDATE collections SET watch_status = ?2 WHERE name = ?1",
            params![name, status.as_str()],
        )?;
        Ok(())
    }

    pub fn remove_collection(&self, name: &str) -> Result<bool, StateError> {
        Ok(self
            .connection
            .execute("DELETE FROM collections WHERE name = ?1", [name])?
            != 0)
    }

    pub fn collections(&self) -> Result<Vec<CollectionState>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT name, local_path, resolved_root, scan_status, watch_status
             FROM collections ORDER BY name",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| decode_collection(row?)).collect()
    }

    pub fn collection(&self, name: &str) -> Result<Option<CollectionState>, StateError> {
        self.connection
            .query_row(
                "SELECT name, local_path, resolved_root, scan_status, watch_status
                 FROM collections WHERE name = ?1",
                [name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(StateError::from)?
            .map(decode_collection)
            .transpose()
    }

    pub fn insert_roster_revision(&mut self, revision: &RosterRevision) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if revision.number() == 0 {
            let count: i64 =
                transaction.query_row("SELECT count(*) FROM roster_revisions", [], |row| {
                    row.get(0)
                })?;
            if count != 0 {
                return Err(StateError::RosterTopology(
                    "the database already contains a roster genesis",
                ));
            }
            revision.validate_genesis()?;
        } else {
            let parent_hash = revision.parent_hash().ok_or(StateError::RosterTopology(
                "roster child does not name a parent",
            ))?;
            let parent = load_roster_revision(&transaction, parent_hash)?.ok_or(
                StateError::RosterTopology("roster child parent is not stored"),
            )?;
            revision.validate_child(&parent)?;
        }
        let hash = revision.canonical_hash();
        transaction.execute(
            "INSERT INTO roster_revisions (hash, canonical) VALUES (?1, ?2)",
            params![hash.as_bytes(), revision.canonical_bytes()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn roster_revision(&self, hash: RosterHash) -> Result<Option<RosterRevision>, StateError> {
        load_roster_revision(&self.connection, hash)
    }

    pub fn selected_roster_chain(&self) -> Result<Vec<RosterRevision>, StateError> {
        let mut statement = self
            .connection
            .prepare("SELECT hash, canonical FROM roster_revisions")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut revisions = BTreeMap::new();
        for row in rows {
            let (stored_hash, canonical) = row?;
            let revision = RosterRevision::from_canonical(&canonical)?;
            let hash = roster_hash_from_blob(stored_hash)?;
            if revision.canonical_hash() != hash {
                return Err(StateError::InvalidStoredState(
                    "roster hash does not match canonical bytes",
                ));
            }
            if revisions.insert(hash, revision).is_some() {
                return Err(StateError::InvalidStoredState("duplicate roster hash"));
            }
        }
        if revisions.is_empty() {
            return Ok(Vec::new());
        }

        let mut genesis_candidates = revisions
            .values()
            .filter(|revision| revision.number() == 0 && revision.parent_hash().is_none());
        let genesis = genesis_candidates
            .next()
            .ok_or(StateError::RosterTopology("roster genesis is missing"))?
            .clone();
        if genesis_candidates.next().is_some() {
            return Err(StateError::RosterTopology(
                "database contains more than one roster genesis",
            ));
        }
        genesis.validate_genesis()?;

        for revision in revisions.values() {
            if revision.canonical_hash() == genesis.canonical_hash() {
                continue;
            }
            if revision.group_id() != genesis.group_id() {
                return Err(StateError::RosterTopology(
                    "database contains more than one group",
                ));
            }
            let parent_hash = revision.parent_hash().ok_or(StateError::RosterTopology(
                "non-genesis roster revision has no parent",
            ))?;
            let parent = revisions
                .get(&parent_hash)
                .ok_or(StateError::RosterTopology(
                    "roster revision parent is missing",
                ))?;
            revision.validate_child(parent)?;
        }

        let candidates = revisions
            .into_values()
            .filter(|revision| revision.canonical_hash() != genesis.canonical_hash())
            .collect::<Vec<_>>();
        let mut selected = vec![genesis.clone()];
        selected.extend(select_chain(&genesis, &candidates)?.into_iter().cloned());
        Ok(selected)
    }

    pub fn merge_selected_roster_chain(
        &mut self,
        revisions: &[RosterRevision],
    ) -> Result<(), StateError> {
        let Some(remote_genesis) = revisions.first() else {
            return Err(StateError::RosterTopology("remote roster is empty"));
        };
        remote_genesis.validate_genesis()?;
        for pair in revisions.windows(2) {
            pair[1].validate_child(&pair[0])?;
        }
        let local = self.selected_roster_chain()?;
        let Some(local_genesis) = local.first() else {
            return Err(StateError::RosterTopology(
                "local roster genesis is missing",
            ));
        };
        if remote_genesis.canonical_hash() != local_genesis.canonical_hash() {
            return Err(StateError::RosterTopology("remote roster genesis differs"));
        }
        for revision in revisions.iter().skip(1) {
            if self.roster_revision(revision.canonical_hash())?.is_none() {
                self.insert_roster_revision(revision)?;
            }
        }
        Ok(())
    }

    pub fn apply_roster_change(
        &mut self,
        identity: &DeviceIdentity,
        change: RosterChange,
    ) -> Result<RosterRevision, StateError> {
        self.apply_roster_change_inner(identity, change, None)
    }

    pub fn apply_roster_change_with_peer_hint(
        &mut self,
        identity: &DeviceIdentity,
        change: RosterChange,
        hint_endpoint: EndpointId,
        hint: &str,
    ) -> Result<RosterRevision, StateError> {
        validate_peer_hint(hint)?;
        self.apply_roster_change_inner(identity, change, Some((hint_endpoint, hint)))
    }

    fn apply_roster_change_inner(
        &mut self,
        identity: &DeviceIdentity,
        change: RosterChange,
        peer_hint: Option<(EndpointId, &str)>,
    ) -> Result<RosterRevision, StateError> {
        for _ in 0..=MAX_ROSTER_RETRY_DEPTH {
            let chain = self.selected_roster_chain()?;
            let parent = chain
                .last()
                .ok_or(StateError::RosterTopology("roster genesis is missing"))?;
            if roster_change_is_satisfied(parent, &change) {
                if let Some((endpoint, hint)) = peer_hint {
                    let transaction = self
                        .connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)?;
                    replace_peer_hint_in(&transaction, endpoint, hint)?;
                    transaction.commit()?;
                }
                return Ok(parent.clone());
            }
            let revision = RosterRevision::child(parent, change.clone(), identity)?;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if load_roster_revision(&transaction, revision.canonical_hash())?.is_none() {
                insert_roster_revision_row(&transaction, &revision)?;
            }
            if let Some((endpoint, hint)) = peer_hint {
                replace_peer_hint_in(&transaction, endpoint, hint)?;
            }
            transaction.commit()?;
            let selected = self.selected_roster_chain()?;
            let selected_tip = selected
                .last()
                .ok_or(StateError::RosterTopology("roster genesis is missing"))?;
            if roster_change_is_satisfied(selected_tip, &change) {
                return Ok(selected_tip.clone());
            }
        }
        Err(StateError::RosterRetryLimit)
    }

    pub fn install_joined_roster_chain(
        &mut self,
        revisions: &[RosterRevision],
        local_endpoint: EndpointId,
    ) -> Result<(), StateError> {
        self.install_joined_state(revisions, local_endpoint, &[])
    }

    pub fn install_joined_state(
        &mut self,
        revisions: &[RosterRevision],
        local_endpoint: EndpointId,
        peer_hints: &[(EndpointId, String)],
    ) -> Result<(), StateError> {
        self.install_joined_state_inner(revisions, local_endpoint, None, peer_hints, false)
    }

    pub fn install_or_resume_joined_state(
        &mut self,
        revisions: &[RosterRevision],
        local_endpoint: EndpointId,
        local_name: &str,
        peer_hints: &[(EndpointId, String)],
    ) -> Result<(), StateError> {
        self.install_joined_state_inner(
            revisions,
            local_endpoint,
            Some(local_name),
            peer_hints,
            true,
        )
    }

    fn install_joined_state_inner(
        &mut self,
        revisions: &[RosterRevision],
        local_endpoint: EndpointId,
        local_name: Option<&str>,
        peer_hints: &[(EndpointId, String)],
        allow_resume: bool,
    ) -> Result<(), StateError> {
        let Some(genesis) = revisions.first() else {
            return Err(StateError::RosterTopology("joined roster is empty"));
        };
        genesis.validate_genesis()?;
        for pair in revisions.windows(2) {
            pair[1].validate_child(&pair[0])?;
        }
        let tip = revisions
            .last()
            .ok_or(StateError::RosterTopology("joined roster is empty"))?;
        if !tip.members().contains_key(&local_endpoint) {
            return Err(StateError::RosterTopology(
                "joined roster does not contain this device",
            ));
        }
        if local_name.is_some_and(|name| {
            tip.members().get(&local_endpoint).map(String::as_str) != Some(name)
        }) {
            return Err(StateError::RosterTopology(
                "joined roster has a different local device name",
            ));
        }
        let existing = self.selected_roster_chain()?;
        if !allow_resume && !existing.is_empty() {
            return Err(StateError::RosterTopology(
                "local state already belongs to a group",
            ));
        }
        if existing.first().is_some_and(|existing_genesis| {
            existing_genesis.canonical_hash() != genesis.canonical_hash()
        }) {
            return Err(StateError::RosterTopology(
                "joined roster belongs to a different group",
            ));
        }
        if allow_resume
            && existing.last().is_some_and(|tip| {
                local_name.is_none_or(|name| {
                    tip.members().get(&local_endpoint).map(String::as_str) != Some(name)
                })
            })
        {
            return Err(StateError::RosterTopology(
                "local membership cannot resume this join",
            ));
        }
        for (_, hint) in peer_hints {
            validate_peer_hint(hint)?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for revision in revisions {
            if load_roster_revision(&transaction, revision.canonical_hash())?.is_none() {
                insert_roster_revision_row(&transaction, revision)?;
            }
        }
        for (endpoint, hint) in peer_hints {
            replace_peer_hint_in(&transaction, *endpoint, hint)?;
        }
        transaction.commit()?;
        if allow_resume
            && self.selected_roster_chain()?.last().is_none_or(|tip| {
                local_name.is_none_or(|name| {
                    tip.members().get(&local_endpoint).map(String::as_str) != Some(name)
                })
            })
        {
            return Err(StateError::RosterTopology(
                "selected roster cannot resume this join",
            ));
        }
        Ok(())
    }

    pub fn merge_record(
        &mut self,
        record: &Record,
        observed_ns: i64,
        source_peer: Option<EndpointId>,
        max_logs: usize,
    ) -> Result<bool, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_record(&transaction, record.collection(), record.path().as_str())?;
        let accepted = current
            .as_ref()
            .is_none_or(|current| record.compare_winner(current).is_gt());
        if accepted {
            let materialized = source_peer.is_none();
            upsert_record(&transaction, record, materialized)?;
        }
        let event = match current {
            _ if accepted => OperationalEvent::RecordAccepted {
                collection: record.collection().to_owned(),
                path: record.path().clone(),
                source_peer,
            },
            Some(winner) => OperationalEvent::RecordRejected {
                collection: record.collection().to_owned(),
                path: record.path().clone(),
                source_peer,
                candidate_modified_ns: record.modified_ns(),
                candidate_author: record.author(),
                winner_modified_ns: winner.modified_ns(),
                winner_author: winner.author(),
            },
            None => unreachable!("a missing current record is accepted"),
        };
        insert_log(&transaction, observed_ns, &event, max_logs)?;
        transaction.commit()?;
        Ok(accepted)
    }

    #[cfg(test)]
    pub(crate) fn insert_materialized_records_for_test(
        &mut self,
        records: &[Record],
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for record in records {
            upsert_record(&transaction, record, true)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn record(&self, collection: &str, path: &str) -> Result<Option<Record>, StateError> {
        let stored = self
            .connection
            .query_row(
                "SELECT record_hash, canonical FROM path_records
                 WHERE collection = ?1 AND path = ?2",
                params![collection, path],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        stored
            .map(|stored| decode_indexed_record(stored, collection, path))
            .transpose()
    }

    pub fn records(&self, collection: &str) -> Result<Vec<Record>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT path, record_hash, canonical FROM path_records
             WHERE collection = ?1 ORDER BY path",
        )?;
        let rows = statement.query_map([collection], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (path, hash, canonical) = row?;
            decode_indexed_record((hash, canonical), collection, &path)
        })
        .collect()
    }

    pub fn record_states(&self, collection: &str) -> Result<Vec<PathRecordState>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT path, record_hash, canonical, materialized,
                    materialized_modified_ns, materialized_size, materialized_hash
             FROM path_records WHERE collection = ?1 ORDER BY path",
        )?;
        let rows = statement.query_map([collection], stored_path_record_state)?;
        rows.map(|row| decode_path_record_state(row?, collection))
            .collect()
    }

    pub fn record_state(
        &self,
        collection: &str,
        path: &str,
    ) -> Result<Option<PathRecordState>, StateError> {
        let stored = self
            .connection
            .query_row(
                "SELECT path, record_hash, canonical, materialized,
                        materialized_modified_ns, materialized_size, materialized_hash
                 FROM path_records WHERE collection = ?1 AND path = ?2",
                params![collection, path],
                stored_path_record_state,
            )
            .optional()?;
        stored
            .map(|stored| decode_path_record_state(stored, collection))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn set_repair_required(
        &self,
        collection: &str,
        path: &str,
    ) -> Result<(), StateError> {
        self.connection.execute(
            "UPDATE path_records SET
                materialized = 0,
                materialized_modified_ns = NULL,
                materialized_size = NULL,
                materialized_hash = NULL
             WHERE collection = ?1 AND path = ?2",
            params![collection, path],
        )?;
        Ok(())
    }

    pub fn mark_repair_required_and_log(
        &mut self,
        collection: &str,
        path: &str,
        created_ns: i64,
        event: &OperationalEvent,
        max_logs: usize,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE path_records SET
                materialized = 0,
                materialized_modified_ns = NULL,
                materialized_size = NULL,
                materialized_hash = NULL
             WHERE collection = ?1 AND path = ?2 AND kind = 1",
            params![collection, path],
        )?;
        if updated != 1 {
            return Err(StateError::MissingPathRecord);
        }
        insert_log(&transaction, created_ns, event, max_logs)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn set_materialized_fingerprint(
        &mut self,
        collection: &str,
        path: &str,
        fingerprint: FileFingerprint,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        update_materialized_fingerprint(&transaction, collection, path, fingerprint)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_materialized_and_log(
        &mut self,
        collection: &str,
        path: &str,
        materialized: MaterializedFile<'_>,
        created_ns: i64,
        event: &OperationalEvent,
        max_logs: usize,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_root = transaction
            .query_row(
                "SELECT resolved_root FROM collections WHERE name = ?1",
                [collection],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .ok_or(StateError::MissingCollection)?;
        let resolved_bytes = materialized.resolved_root.as_os_str().as_bytes();
        if previous_root.as_deref() != Some(resolved_bytes) {
            transaction.execute(
                "UPDATE collections SET resolved_root = ?2 WHERE name = ?1",
                params![collection, resolved_bytes],
            )?;
            transaction.execute(
                "UPDATE path_records SET
                    materialized = 0,
                    materialized_modified_ns = NULL,
                    materialized_size = NULL,
                    materialized_hash = NULL
                 WHERE collection = ?1 AND path != ?2 AND kind = 1",
                params![collection, path],
            )?;
        }
        update_materialized_fingerprint(&transaction, collection, path, materialized.fingerprint)?;
        insert_log(&transaction, created_ns, event, max_logs)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_tombstone_materialized_and_log(
        &mut self,
        collection: &str,
        path: &str,
        created_ns: i64,
        event: &OperationalEvent,
        max_logs: usize,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE path_records SET materialized = 1
             WHERE collection = ?1 AND path = ?2 AND kind = 0",
            params![collection, path],
        )?;
        if updated != 1 {
            return Err(StateError::MissingPathRecord);
        }
        insert_log(&transaction, created_ns, event, max_logs)?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reject_future_log_inserts(&self) -> Result<(), StateError> {
        self.connection.execute_batch(
            "CREATE TEMP TRIGGER reject_operational_log_insert
             BEFORE INSERT ON operational_logs
             BEGIN
                SELECT RAISE(FAIL, 'injected operational log failure');
             END;",
        )?;
        Ok(())
    }

    pub fn local_counts(&self) -> Result<(u64, u64), StateError> {
        let (files, degraded): (i64, i64) = self.connection.query_row(
            "SELECT
                coalesce(sum(CASE WHEN kind = 1 AND materialized = 1 THEN 1 ELSE 0 END), 0),
                coalesce(sum(CASE WHEN materialized = 0 THEN 1 ELSE 0 END), 0)
             FROM path_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((
            u64::try_from(files).map_err(|_| StateError::NumberOverflow)?,
            u64::try_from(degraded).map_err(|_| StateError::NumberOverflow)?,
        ))
    }

    pub fn peer_hint(&self, endpoint_id: EndpointId) -> Result<Option<String>, StateError> {
        self.connection
            .query_row(
                "SELECT (
                    SELECT hint FROM peer_hints
                    WHERE endpoint_id = ?1
                      AND typeof(hint) = 'text'
                      AND length(CAST(hint AS BLOB)) BETWEEN 1 AND 16384
                 )",
                [endpoint_id.as_bytes()],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(Into::into)
    }

    pub fn replace_peer_hint(
        &mut self,
        endpoint_id: EndpointId,
        hint: &str,
    ) -> Result<(), StateError> {
        validate_peer_hint(hint)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        replace_peer_hint_in(&transaction, endpoint_id, hint)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_peer_health(
        &mut self,
        endpoint_id: EndpointId,
        reachable: bool,
        observed_ns: i64,
        event: &OperationalEvent,
        max_logs: usize,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO peer_health (endpoint_id, reachable)
             VALUES (?1, ?2)
             ON CONFLICT(endpoint_id) DO UPDATE SET
                reachable = excluded.reachable",
            params![endpoint_id.as_bytes(), reachable],
        )?;
        insert_log(&transaction, observed_ns, event, max_logs)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn peer_reachable(&self, endpoint_id: EndpointId) -> Result<bool, StateError> {
        Ok(self
            .connection
            .query_row(
                "SELECT reachable FROM peer_health WHERE endpoint_id = ?1",
                [endpoint_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    #[cfg(test)]
    pub(crate) fn peer_health_row_count(&self) -> Result<usize, StateError> {
        let count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM peer_health", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| StateError::NumberOverflow)
    }

    pub fn append_log(
        &mut self,
        created_ns: i64,
        event: &OperationalEvent,
        max_logs: usize,
    ) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_log(&transaction, created_ns, event, max_logs)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn logs(&self) -> Result<Vec<OperationalLog>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT id, created_ns,
                    CASE WHEN typeof(payload) = 'blob' THEN
                        CASE WHEN length(payload) BETWEEN 1 AND 16384
                             THEN payload END
                    END
             FROM operational_logs ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        let mut logs = Vec::new();
        while let Some(row) = rows.next()? {
            logs.push(decode_operational_log_row(row)?);
        }
        Ok(logs)
    }

    pub fn logs_page(&self, after_id: i64, limit: usize) -> Result<OperationalLogPage, StateError> {
        let limit = limit.clamp(1, 64);
        let query_limit = i64::try_from(limit + 1).map_err(|_| StateError::NumberOverflow)?;
        let mut statement = self.connection.prepare(
            "SELECT id, created_ns,
                    CASE WHEN typeof(payload) = 'blob' THEN
                        CASE WHEN length(payload) BETWEEN 1 AND 16384
                             THEN payload END
                    END
             FROM operational_logs WHERE id > ?1 ORDER BY id LIMIT ?2",
        )?;
        let mut rows = statement.query(params![after_id, query_limit])?;
        let mut logs = Vec::new();
        while let Some(row) = rows.next()? {
            logs.push(decode_operational_log_row(row)?);
        }
        let has_more = logs.len() > limit;
        logs.truncate(limit);
        let next_after_id = logs.last().map_or(after_id, |log| log.id);
        Ok(OperationalLogPage {
            logs,
            next_after_id,
            has_more,
        })
    }

    fn migrate(&mut self) -> Result<(), StateError> {
        let version = self.schema_version()?;
        if version > SCHEMA_VERSION {
            return Err(StateError::UnsupportedSchema(version));
        }
        if version == 0 {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE roster_revisions (
                    hash BLOB PRIMARY KEY NOT NULL CHECK (length(hash) = 32),
                    canonical BLOB NOT NULL UNIQUE CHECK (length(canonical) > 0)
                );
                CREATE TABLE collections (
                    name TEXT PRIMARY KEY NOT NULL CHECK (name <> ''),
                    local_path BLOB NOT NULL CHECK (length(local_path) > 0),
                    resolved_root BLOB,
                    scan_status TEXT NOT NULL DEFAULT 'pending' CHECK (
                        scan_status IN ('pending', 'active', 'missing', 'not_directory', 'error')
                    ),
                    watch_status TEXT NOT NULL DEFAULT 'pending' CHECK (
                        watch_status IN ('pending', 'active', 'root_unavailable', 'backend_error')
                    )
                );
                CREATE TABLE path_records (
                    collection TEXT NOT NULL REFERENCES collections(name) ON DELETE CASCADE,
                    path TEXT NOT NULL CHECK (path <> ''),
                    record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
                    kind INTEGER NOT NULL CHECK (kind IN (0, 1)),
                    canonical BLOB NOT NULL CHECK (length(canonical) > 0),
                    materialized INTEGER NOT NULL CHECK (materialized IN (0, 1)),
                    materialized_modified_ns INTEGER,
                    materialized_size INTEGER,
                    materialized_hash BLOB,
                    PRIMARY KEY (collection, path),
                    CHECK (
                        (kind = 0 AND materialized_modified_ns IS NULL AND
                         materialized_size IS NULL AND materialized_hash IS NULL) OR
                        (kind = 1 AND materialized = 0 AND
                         materialized_modified_ns IS NULL AND materialized_size IS NULL AND
                         materialized_hash IS NULL) OR
                        (kind = 1 AND materialized = 1 AND
                         materialized_modified_ns IS NOT NULL AND materialized_size >= 0 AND
                         length(materialized_hash) = 32)
                    )
                );
                CREATE TABLE peer_hints (
                    endpoint_id BLOB PRIMARY KEY NOT NULL CHECK (length(endpoint_id) = 32),
                    hint TEXT NOT NULL CHECK (
                        typeof(hint) = 'text' AND
                        length(CAST(hint AS BLOB)) BETWEEN 1 AND 16384
                    )
                );
                CREATE TABLE operational_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_ns INTEGER NOT NULL,
                    payload BLOB NOT NULL CHECK (
                        typeof(payload) = 'blob' AND length(payload) BETWEEN 1 AND 16384
                    )
                );
                CREATE TABLE peer_health (
                    endpoint_id BLOB PRIMARY KEY NOT NULL CHECK (length(endpoint_id) = 32),
                    reachable INTEGER NOT NULL CHECK (reachable IN (0, 1))
                );
                PRAGMA application_id = 1397445465;
                PRAGMA user_version = 1;",
            )?;
            transaction.commit()?;
        }
        self.validate_current_schema()?;
        Ok(())
    }

    fn validate_current_schema(&self) -> Result<(), StateError> {
        let application_id: i64 =
            self.connection
                .pragma_query_value(None, "application_id", |row| row.get(0))?;
        if application_id != SCHEMA_APPLICATION_ID {
            return Err(StateError::InvalidStoredState(
                "database schema identity is not recognized",
            ));
        }

        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?;
        let stored_tables = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let expected_tables = SCHEMA_TABLES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>();
        if stored_tables != expected_tables {
            return Err(StateError::InvalidStoredState(
                "database table shape is not recognized",
            ));
        }

        for (table, expected_columns) in SCHEMA_TABLES {
            let mut statement = self
                .connection
                .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
            let stored_columns = statement
                .query_map([table], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if stored_columns != expected_columns {
                return Err(StateError::InvalidStoredState(
                    "database column shape is not recognized",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionState {
    pub name: String,
    pub local_path: PathBuf,
    pub resolved_root: Option<PathBuf>,
    pub scan_status: CollectionScanStatus,
    pub watch_status: CollectionWatchStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionScanStatus {
    Pending,
    Active,
    Missing,
    NotDirectory,
    Error,
}

impl CollectionScanStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Missing => "missing",
            Self::NotDirectory => "not_directory",
            Self::Error => "error",
        }
    }

    fn from_str(value: &str) -> Result<Self, StateError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "missing" => Ok(Self::Missing),
            "not_directory" => Ok(Self::NotDirectory),
            "error" => Ok(Self::Error),
            _ => Err(StateError::InvalidStoredState(
                "collection scan status is unknown",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionWatchStatus {
    Pending,
    Active,
    RootUnavailable,
    BackendError,
}

impl CollectionWatchStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RootUnavailable => "root_unavailable",
            Self::BackendError => "backend_error",
        }
    }

    fn from_str(value: &str) -> Result<Self, StateError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "root_unavailable" => Ok(Self::RootUnavailable),
            "backend_error" => Ok(Self::BackendError),
            _ => Err(StateError::InvalidStoredState(
                "collection watch status is unknown",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRecordState {
    pub record: Record,
    pub materialized: bool,
    pub materialized_fingerprint: Option<FileFingerprint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileFingerprint {
    pub modified_ns: i64,
    pub size: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializedFile<'a> {
    pub resolved_root: &'a Path,
    pub fingerprint: FileFingerprint,
}

fn decode_collection(
    stored: (String, Vec<u8>, Option<Vec<u8>>, String, String),
) -> Result<CollectionState, StateError> {
    Ok(CollectionState {
        name: stored.0,
        local_path: PathBuf::from(OsString::from_vec(stored.1)),
        resolved_root: stored
            .2
            .map(|bytes| PathBuf::from(OsString::from_vec(bytes))),
        scan_status: CollectionScanStatus::from_str(&stored.3)?,
        watch_status: CollectionWatchStatus::from_str(&stored.4)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalLog {
    pub id: i64,
    pub created_ns: i64,
    pub event: OperationalEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalLogPage {
    pub logs: Vec<OperationalLog>,
    pub next_after_id: i64,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationalEvent {
    DaemonStarted,
    DaemonStopped,
    CollectionAttached {
        collection: String,
    },
    CollectionDetached {
        collection: String,
    },
    CollectionPaused {
        collection: String,
    },
    CollectionScanned {
        collection: String,
    },
    CollectionWarning {
        collection: String,
        path: Option<ProtocolPath>,
        issue: CollectionIssue,
    },
    RecordAccepted {
        collection: String,
        path: ProtocolPath,
        source_peer: Option<EndpointId>,
    },
    RecordRejected {
        collection: String,
        path: ProtocolPath,
        source_peer: Option<EndpointId>,
        candidate_modified_ns: i64,
        candidate_author: EndpointId,
        winner_modified_ns: i64,
        winner_author: EndpointId,
    },
    FileInstalled {
        collection: String,
        path: ProtocolPath,
    },
    FileApplyRejected {
        collection: String,
        path: ProtocolPath,
    },
    RepairRequired {
        collection: String,
        path: ProtocolPath,
    },
    PeerUnreachable {
        peer_endpoint: EndpointId,
    },
    PeerAttempted {
        peer_endpoint: EndpointId,
    },
    PeerSynchronized {
        peer_endpoint: EndpointId,
    },
    PeerRejected {
        peer_endpoint: EndpointId,
    },
    PeerSessionFailed {
        peer_endpoint: EndpointId,
    },
    FileSent {
        collection: String,
        path: ProtocolPath,
        peer_endpoint: EndpointId,
    },
    FileReceived {
        collection: String,
        path: ProtocolPath,
        peer_endpoint: EndpointId,
    },
    TransferRejected {
        collection: String,
        path: ProtocolPath,
        peer_endpoint: EndpointId,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionIssue {
    SymlinkEscape,
    SymlinkCycle,
    PathRejected,
    TimestampRejected,
}

impl OperationalEvent {
    pub const fn level(&self) -> LogLevel {
        match self {
            Self::CollectionScanned { .. } => LogLevel::Debug,
            Self::DaemonStarted
            | Self::DaemonStopped
            | Self::CollectionAttached { .. }
            | Self::CollectionDetached { .. }
            | Self::RecordAccepted { .. }
            | Self::FileInstalled { .. }
            | Self::PeerAttempted { .. }
            | Self::PeerSynchronized { .. }
            | Self::FileSent { .. }
            | Self::FileReceived { .. } => LogLevel::Info,
            Self::CollectionPaused { .. }
            | Self::CollectionWarning { .. }
            | Self::RecordRejected { .. }
            | Self::FileApplyRejected { .. }
            | Self::RepairRequired { .. }
            | Self::PeerUnreachable { .. }
            | Self::PeerRejected { .. }
            | Self::PeerSessionFailed { .. }
            | Self::TransferRejected { .. } => LogLevel::Warn,
        }
    }
}

fn load_roster_revision(
    connection: &Connection,
    hash: RosterHash,
) -> Result<Option<RosterRevision>, StateError> {
    let encoded = connection
        .query_row(
            "SELECT canonical FROM roster_revisions WHERE hash = ?1",
            [hash.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    encoded
        .map(|bytes| {
            let revision = RosterRevision::from_canonical(&bytes)?;
            if revision.canonical_hash() != hash {
                return Err(StateError::InvalidStoredState(
                    "roster hash does not match canonical bytes",
                ));
            }
            Ok(revision)
        })
        .transpose()
}

fn insert_roster_revision_row(
    transaction: &Transaction<'_>,
    revision: &RosterRevision,
) -> Result<(), StateError> {
    let hash = revision.canonical_hash();
    transaction.execute(
        "INSERT INTO roster_revisions (hash, canonical) VALUES (?1, ?2)",
        params![hash.as_bytes(), revision.canonical_bytes()],
    )?;
    Ok(())
}

fn roster_change_is_satisfied(revision: &RosterRevision, change: &RosterChange) -> bool {
    match change {
        RosterChange::Initialize(member) => revision
            .members()
            .get(&member.endpoint_id)
            .is_some_and(|name| name == &member.device_name),
        RosterChange::Admit(member) => revision.members().contains_key(&member.endpoint_id),
        RosterChange::Remove(endpoint_id) => !revision.members().contains_key(endpoint_id),
    }
}

fn validate_peer_hint(hint: &str) -> Result<(), StateError> {
    if hint.is_empty() || hint.len() > MAX_PEER_HINT_BYTES {
        return Err(StateError::PeerHintLimit);
    }
    Ok(())
}

fn replace_peer_hint_in(
    connection: &Connection,
    endpoint_id: EndpointId,
    hint: &str,
) -> Result<(), StateError> {
    connection.execute(
        "INSERT INTO peer_hints (endpoint_id, hint) VALUES (?1, ?2)
         ON CONFLICT(endpoint_id) DO UPDATE SET hint = excluded.hint",
        params![endpoint_id.as_bytes(), hint],
    )?;
    Ok(())
}

fn roster_hash_from_blob(bytes: Vec<u8>) -> Result<RosterHash, StateError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| StateError::InvalidStoredState("roster hash has the wrong length"))?;
    Ok(RosterHash::from_bytes(bytes))
}

fn upsert_record(
    transaction: &Transaction<'_>,
    record: &Record,
    materialized: bool,
) -> Result<(), StateError> {
    let kind = match record.kind() {
        crate::record::RecordKind::Tombstone => 0,
        crate::record::RecordKind::File { .. } => 1,
    };
    let materialized_fingerprint = if materialized {
        match record.kind() {
            crate::record::RecordKind::Tombstone => None,
            crate::record::RecordKind::File { size, content_hash } => Some(FileFingerprint {
                modified_ns: record.modified_ns(),
                size,
                hash: content_hash,
            }),
        }
    } else {
        None
    };
    transaction.execute(
        "INSERT INTO path_records
            (collection, path, record_hash, kind, canonical, materialized,
             materialized_modified_ns, materialized_size, materialized_hash)
         VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
         )
         ON CONFLICT(collection, path) DO UPDATE SET
            record_hash = excluded.record_hash,
            kind = excluded.kind,
            canonical = excluded.canonical,
            materialized = excluded.materialized,
            materialized_modified_ns = excluded.materialized_modified_ns,
            materialized_size = excluded.materialized_size,
            materialized_hash = excluded.materialized_hash",
        params![
            record.collection(),
            record.path().as_str(),
            record.canonical_hash().as_bytes(),
            kind,
            record.canonical_bytes(),
            materialized,
            materialized_fingerprint.map(|value| value.modified_ns),
            materialized_fingerprint
                .map(|value| i64::try_from(value.size))
                .transpose()
                .map_err(|_| StateError::NumberOverflow)?,
            materialized_fingerprint.map(|value| value.hash),
        ],
    )?;
    Ok(())
}

fn update_materialized_fingerprint(
    transaction: &Transaction<'_>,
    collection: &str,
    path: &str,
    fingerprint: FileFingerprint,
) -> Result<(), StateError> {
    let size = i64::try_from(fingerprint.size).map_err(|_| StateError::NumberOverflow)?;
    let updated = transaction.execute(
        "UPDATE path_records SET
            materialized = 1,
            materialized_modified_ns = ?3,
            materialized_size = ?4,
            materialized_hash = ?5
         WHERE collection = ?1 AND path = ?2 AND kind = 1",
        params![
            collection,
            path,
            fingerprint.modified_ns,
            size,
            fingerprint.hash
        ],
    )?;
    if updated != 1 {
        return Err(StateError::MissingPathRecord);
    }
    Ok(())
}

fn decode_materialized_fingerprint(
    modified_ns: Option<i64>,
    size: Option<i64>,
    hash: Option<Vec<u8>>,
) -> Result<Option<FileFingerprint>, StateError> {
    match (modified_ns, size, hash) {
        (None, None, None) => Ok(None),
        (Some(modified_ns), Some(size), Some(hash)) => Ok(Some(FileFingerprint {
            modified_ns,
            size: u64::try_from(size).map_err(|_| {
                StateError::InvalidStoredState("materialized file size is negative")
            })?,
            hash: hash.try_into().map_err(|_| {
                StateError::InvalidStoredState("materialized file hash has the wrong length")
            })?,
        })),
        _ => Err(StateError::InvalidStoredState(
            "materialized fingerprint is incomplete",
        )),
    }
}

type StoredPathRecordState = (
    String,
    Vec<u8>,
    Vec<u8>,
    bool,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
);

fn stored_path_record_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredPathRecordState> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn decode_path_record_state(
    stored: StoredPathRecordState,
    collection: &str,
) -> Result<PathRecordState, StateError> {
    let (
        path,
        hash,
        canonical,
        materialized,
        materialized_modified_ns,
        materialized_size,
        materialized_hash,
    ) = stored;
    Ok(PathRecordState {
        record: decode_indexed_record((hash, canonical), collection, &path)?,
        materialized,
        materialized_fingerprint: decode_materialized_fingerprint(
            materialized_modified_ns,
            materialized_size,
            materialized_hash,
        )?,
    })
}

fn load_record(
    transaction: &Transaction<'_>,
    collection: &str,
    path: &str,
) -> Result<Option<Record>, StateError> {
    let stored = transaction
        .query_row(
            "SELECT record_hash, canonical FROM path_records
             WHERE collection = ?1 AND path = ?2",
            params![collection, path],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    stored
        .map(|stored| decode_indexed_record(stored, collection, path))
        .transpose()
}

fn decode_stored_record(stored: (Vec<u8>, Vec<u8>)) -> Result<Record, StateError> {
    let (hash, canonical) = stored;
    let record = Record::from_canonical(&canonical)?;
    if hash.as_slice() != record.canonical_hash().as_bytes() {
        return Err(StateError::InvalidStoredState(
            "record hash does not match canonical bytes",
        ));
    }
    Ok(record)
}

fn decode_indexed_record(
    stored: (Vec<u8>, Vec<u8>),
    collection: &str,
    path: &str,
) -> Result<Record, StateError> {
    let record = decode_stored_record(stored)?;
    if record.collection() != collection || record.path().as_str() != path {
        return Err(StateError::InvalidStoredState(
            "record index does not match canonical bytes",
        ));
    }
    Ok(record)
}

fn insert_log(
    transaction: &Transaction<'_>,
    created_ns: i64,
    event: &OperationalEvent,
    max_logs: usize,
) -> Result<(), StateError> {
    validate_operational_event(event)?;
    let payload = serde_json::to_vec(event)
        .map_err(|_| StateError::InvalidStoredState("operational event cannot be encoded"))?;
    if payload.len() > MAX_OPERATIONAL_EVENT_BYTES {
        return Err(StateError::InvalidStoredState(
            "operational event exceeds its encoded size limit",
        ));
    }
    transaction.execute(
        "INSERT INTO operational_logs (created_ns, payload) VALUES (?1, ?2)",
        params![created_ns, payload],
    )?;
    let max_logs = i64::try_from(max_logs).map_err(|_| StateError::NumberOverflow)?;
    transaction.execute(
        "DELETE FROM operational_logs
         WHERE id NOT IN (
             SELECT id FROM operational_logs ORDER BY id DESC LIMIT ?1
         )",
        [max_logs],
    )?;
    Ok(())
}

fn decode_operational_log_row(row: &rusqlite::Row<'_>) -> Result<OperationalLog, StateError> {
    let payload = row
        .get::<_, Option<Vec<u8>>>(2)?
        .ok_or(StateError::InvalidStoredState(
            "operational event payload has invalid storage",
        ))?;
    Ok(OperationalLog {
        id: row.get(0)?,
        created_ns: row.get(1)?,
        event: decode_operational_event(&payload)?,
    })
}

fn decode_operational_event(payload: &[u8]) -> Result<OperationalEvent, StateError> {
    if payload.is_empty() || payload.len() > MAX_OPERATIONAL_EVENT_BYTES {
        return Err(StateError::InvalidStoredState(
            "operational event payload has an invalid size",
        ));
    }
    let event = serde_json::from_slice(payload)
        .map_err(|_| StateError::InvalidStoredState("operational event payload is invalid"))?;
    validate_operational_event(&event)?;
    let canonical = serde_json::to_vec(&event)
        .map_err(|_| StateError::InvalidStoredState("operational event payload is invalid"))?;
    if canonical != payload {
        return Err(StateError::InvalidStoredState(
            "operational event payload is invalid",
        ));
    }
    Ok(event)
}

fn validate_operational_event(event: &OperationalEvent) -> Result<(), StateError> {
    let (collection, path) = match event {
        OperationalEvent::DaemonStarted
        | OperationalEvent::DaemonStopped
        | OperationalEvent::PeerUnreachable { .. }
        | OperationalEvent::PeerAttempted { .. }
        | OperationalEvent::PeerSynchronized { .. }
        | OperationalEvent::PeerRejected { .. }
        | OperationalEvent::PeerSessionFailed { .. } => (None, None),
        OperationalEvent::CollectionAttached { collection }
        | OperationalEvent::CollectionDetached { collection }
        | OperationalEvent::CollectionPaused { collection }
        | OperationalEvent::CollectionScanned { collection } => (Some(collection), None),
        OperationalEvent::CollectionWarning {
            collection, path, ..
        } => (Some(collection), path.as_ref()),
        OperationalEvent::RecordAccepted {
            collection, path, ..
        }
        | OperationalEvent::RecordRejected {
            collection, path, ..
        }
        | OperationalEvent::FileInstalled { collection, path }
        | OperationalEvent::FileApplyRejected { collection, path }
        | OperationalEvent::RepairRequired { collection, path }
        | OperationalEvent::FileSent {
            collection, path, ..
        }
        | OperationalEvent::FileReceived {
            collection, path, ..
        }
        | OperationalEvent::TransferRejected {
            collection, path, ..
        } => (Some(collection), Some(path)),
    };
    if collection.is_some_and(|value| value.is_empty() || value.len() > 255) {
        return Err(StateError::InvalidStoredState(
            "operational event collection has an invalid size",
        ));
    }
    if path.is_some_and(|value| value.as_str().len() > 4_096) {
        return Err(StateError::InvalidStoredState(
            "operational event path exceeds its size limit",
        ));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite state failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {0} is newer than this binary")]
    UnsupportedSchema(i64),
    #[error("stored state is invalid: {0}")]
    InvalidStoredState(&'static str),
    #[error("collection is missing from local state")]
    MissingCollection,
    #[error("file path is missing from local state")]
    MissingPathRecord,
    #[error("roster topology is invalid: {0}")]
    RosterTopology(&'static str),
    #[error("numeric state cannot be represented in SQLite")]
    NumberOverflow,
    #[error("peer address hints exceed their count or size limit")]
    PeerHintLimit,
    #[error("roster mutation could not be selected within the revision limit")]
    RosterRetryLimit,
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    Path(#[from] PathError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::identity::{DeviceIdentity, GroupId};
    use crate::path::ProtocolPath;
    use crate::record::Record;
    use crate::roster::{RosterChange, RosterMember};

    fn sample_record(timestamp: i64, hash: u8) -> Record {
        Record::file(
            ".agents",
            ProtocolPath::parse("review/SKILL.md").unwrap(),
            timestamp,
            EndpointId::from_bytes([3; 32]),
            5,
            [hash; 32],
        )
        .unwrap()
    }

    fn admission(identity: &DeviceIdentity, name: &str) -> RosterChange {
        RosterChange::Admit(RosterMember::new(identity.endpoint_id(), name).unwrap())
    }

    fn roster_count(store: &StateStore) -> i64 {
        store
            .connection
            .query_row("SELECT count(*) FROM roster_revisions", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn fresh_database_migrates_transactionally() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("state.sqlite3");
        Connection::open(&database).unwrap().close().unwrap();

        let store = StateStore::open(&database).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let table_count: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'path_records'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn logical_write_rolls_back_when_log_insert_fails() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let path = "x".repeat(4_097);
        let candidate = Record::file(
            ".agents",
            ProtocolPath::parse(&path).unwrap(),
            20,
            EndpointId::from_bytes([3; 32]),
            5,
            [2; 32],
        )
        .unwrap();
        assert!(store.merge_record(&candidate, 20, None, 100).is_err());
        assert_eq!(store.record(".agents", &path).unwrap(), None);
    }

    #[test]
    fn older_record_cannot_replace_the_persisted_winner() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let winner = sample_record(20, 2);
        let loser = sample_record(10, 1);
        assert!(
            store
                .merge_record(&winner, 20, Some(EndpointId::from_bytes([4; 32])), 100)
                .unwrap()
        );
        assert!(
            !store
                .merge_record(&loser, 10, Some(EndpointId::from_bytes([4; 32])), 100)
                .unwrap()
        );
        assert_eq!(
            store.record(".agents", "review/SKILL.md").unwrap(),
            Some(winner)
        );
    }

    #[test]
    fn failed_migration_rolls_back_schema_and_version() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("broken.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("CREATE TABLE operational_logs (wrong TEXT)", [])
            .unwrap();
        connection.close().unwrap();

        assert!(StateStore::open(&database).is_err());
        let connection = Connection::open(&database).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let application_id: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        let roster_tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'roster_revisions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 0);
        assert_eq!(application_id, 0);
        assert_eq!(roster_tables, 0);
    }

    #[test]
    fn current_version_with_an_arbitrary_shape_is_rejected() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "application_id", SCHEMA_APPLICATION_ID)
            .unwrap();
        connection
            .execute_batch("CREATE TABLE arbitrary (value TEXT); PRAGMA user_version = 1;")
            .unwrap();
        assert!(matches!(
            StateStore::from_connection(connection),
            Err(StateError::InvalidStoredState(
                "database table shape is not recognized"
            ))
        ));
    }

    #[test]
    fn former_version_one_shape_is_rejected_without_compatibility_conversion() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE identity_refs (
                    slot TEXT PRIMARY KEY NOT NULL,
                    backend TEXT NOT NULL,
                    locator BLOB NOT NULL
                 );
                 CREATE TABLE operational_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_ns INTEGER NOT NULL,
                    event_kind TEXT NOT NULL
                 );
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        assert!(matches!(
            StateStore::from_connection(connection),
            Err(StateError::InvalidStoredState(
                "database schema identity is not recognized"
            ))
        ));
    }

    #[test]
    fn future_schema_is_rejected_without_changes() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            StateStore::from_connection(connection),
            Err(StateError::UnsupportedSchema(version)) if version == SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn uniqueness_constraints_reject_duplicate_collections() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/first"), None)
            .unwrap();
        assert!(
            store
                .add_collection(".agents", Path::new("/second"), None)
                .is_err()
        );
    }

    #[test]
    fn roster_persistence_validates_genesis_parent_membership_and_signature() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let joining = DeviceIdentity::from_secret([2; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([3; 32]), "creator", &creator).unwrap();
        let child =
            RosterRevision::child(&genesis, admission(&joining, "first"), &creator).unwrap();

        let mut missing_parent_store = StateStore::open_in_memory().unwrap();
        assert!(missing_parent_store.insert_roster_revision(&child).is_err());
        assert_eq!(roster_count(&missing_parent_store), 0);

        let mut store = StateStore::open_in_memory().unwrap();
        store.insert_roster_revision(&genesis).unwrap();
        let other_genesis = RosterRevision::genesis(
            GroupId::from_bytes([4; 32]),
            "other",
            &DeviceIdentity::from_secret([5; 32]),
        )
        .unwrap();
        assert!(store.insert_roster_revision(&other_genesis).is_err());
        assert_eq!(roster_count(&store), 1);

        let mut bad_signature_bytes = child.canonical_bytes();
        *bad_signature_bytes.last_mut().unwrap() ^= 1;
        let bad_signature = RosterRevision::from_canonical(&bad_signature_bytes).unwrap();
        assert!(store.insert_roster_revision(&bad_signature).is_err());
        assert_eq!(roster_count(&store), 1);

        let mut wrong_members_bytes = child.canonical_bytes();
        let position = wrong_members_bytes
            .windows(b"first".len())
            .position(|window| window == b"first")
            .unwrap();
        wrong_members_bytes[position..position + 5].copy_from_slice(b"other");
        let wrong_members = RosterRevision::from_canonical(&wrong_members_bytes).unwrap();
        assert!(store.insert_roster_revision(&wrong_members).is_err());
        assert_eq!(roster_count(&store), 1);

        let mut wrong_parent_bytes = child.canonical_bytes();
        let parent_offset = b"skillsync-roster-v1\0".len() + 32 + 8 + 1;
        wrong_parent_bytes[parent_offset] ^= 1;
        let wrong_parent = RosterRevision::from_canonical(&wrong_parent_bytes).unwrap();
        assert!(store.insert_roster_revision(&wrong_parent).is_err());
        assert_eq!(roster_count(&store), 1);

        store.insert_roster_revision(&child).unwrap();
        assert_eq!(roster_count(&store), 2);
    }

    #[test]
    fn selected_roster_head_is_stable_across_insertion_order_and_reopen() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let first = DeviceIdentity::from_secret([2; 32]);
        let second = DeviceIdentity::from_secret([3; 32]);
        let third = DeviceIdentity::from_secret([4; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([9; 32]), "creator", &creator).unwrap();
        let admit_first =
            RosterRevision::child(&genesis, admission(&first, "first"), &creator).unwrap();
        let admit_second =
            RosterRevision::child(&genesis, admission(&second, "second"), &creator).unwrap();
        let removal = RosterRevision::child(
            &genesis,
            RosterChange::Remove(creator.endpoint_id()),
            &creator,
        )
        .unwrap();
        let stale_descendant =
            RosterRevision::child(&admit_first, admission(&third, "third"), &creator).unwrap();
        let siblings = [&admit_first, &admit_second, &removal];
        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        for (index, order) in permutations.into_iter().enumerate() {
            let temporary = tempfile::tempdir().unwrap();
            let database = temporary.path().join(format!("state-{index}.sqlite3"));
            {
                let mut store = StateStore::open(&database).unwrap();
                store.insert_roster_revision(&genesis).unwrap();
                for sibling in order {
                    store.insert_roster_revision(siblings[sibling]).unwrap();
                }
                store.insert_roster_revision(&stale_descendant).unwrap();
            }

            let reopened = StateStore::open(&database).unwrap();
            let selected = reopened.selected_roster_chain().unwrap();
            assert_eq!(selected.len(), 2);
            assert_eq!(selected[0].canonical_hash(), genesis.canonical_hash());
            assert_eq!(selected[1].canonical_hash(), removal.canonical_hash());
        }
    }

    #[test]
    fn restart_reconstruction_rejects_tampered_canonical_roster() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([3; 32]), "creator", &creator).unwrap();
        let mut canonical = genesis.canonical_bytes();
        *canonical.last_mut().unwrap() ^= 1;
        assert!(RosterRevision::from_canonical(&canonical).is_ok());
        let store = StateStore::open_in_memory().unwrap();
        store
            .connection
            .execute(
                "INSERT INTO roster_revisions (hash, canonical) VALUES (?1, ?2)",
                params![genesis.canonical_hash().as_bytes(), canonical],
            )
            .unwrap();
        assert!(store.selected_roster_chain().is_err());
    }

    #[test]
    fn record_read_rejects_canonical_bytes_with_a_different_hash() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let record = sample_record(10, 7);
        let other = sample_record(11, 8);
        store.merge_record(&record, 10, None, 100).unwrap();
        store
            .connection
            .execute(
                "UPDATE path_records SET canonical = ?3
                 WHERE collection = ?1 AND path = ?2",
                params![".agents", "review/SKILL.md", other.canonical_bytes()],
            )
            .unwrap();
        assert!(matches!(
            store.record(".agents", "review/SKILL.md"),
            Err(StateError::InvalidStoredState(
                "record hash does not match canonical bytes"
            ))
        ));
    }

    #[test]
    fn record_read_rejects_an_index_that_disagrees_with_canonical_identity() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let record = sample_record(10, 7);
        store.merge_record(&record, 10, None, 100).unwrap();
        store
            .connection
            .execute(
                "UPDATE path_records SET path = 'other/SKILL.md'
                 WHERE collection = '.agents' AND path = 'review/SKILL.md'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.record(".agents", "other/SKILL.md"),
            Err(StateError::InvalidStoredState(
                "record index does not match canonical bytes"
            ))
        ));
        assert!(matches!(
            store.records(".agents"),
            Err(StateError::InvalidStoredState(
                "record index does not match canonical bytes"
            ))
        ));
    }

    #[test]
    fn state_reopens_without_changing_values() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("state.sqlite3");
        let creator = DeviceIdentity::from_secret([1; 32]);
        let roster =
            RosterRevision::genesis(GroupId::from_bytes([2; 32]), "creator", &creator).unwrap();
        let record = sample_record(10, 7);
        {
            let mut store = StateStore::open(&database).unwrap();
            store
                .add_collection(".agents", Path::new("/skills"), Some(Path::new("/real")))
                .unwrap();
            store.insert_roster_revision(&roster).unwrap();
            store
                .merge_record(&record, 10, Some(EndpointId::from_bytes([4; 32])), 100)
                .unwrap();
            store
                .replace_peer_hint(creator.endpoint_id(), "127.0.0.1:7000")
                .unwrap();
        }

        let reopened = StateStore::open(&database).unwrap();
        assert_eq!(
            reopened.collection(".agents").unwrap(),
            Some(CollectionState {
                name: ".agents".to_owned(),
                local_path: PathBuf::from("/skills"),
                resolved_root: Some(PathBuf::from("/real")),
                scan_status: CollectionScanStatus::Pending,
                watch_status: CollectionWatchStatus::Pending,
            })
        );
        assert_eq!(
            reopened.roster_revision(roster.canonical_hash()).unwrap(),
            Some(roster)
        );
        assert_eq!(
            reopened.record(".agents", "review/SKILL.md").unwrap(),
            Some(record)
        );
        assert_eq!(
            reopened.peer_hint(creator.endpoint_id()).unwrap(),
            Some("127.0.0.1:7000".to_owned())
        );
        assert_eq!(reopened.logs().unwrap().len(), 1);
        assert_eq!(
            reopened.logs().unwrap()[0],
            OperationalLog {
                id: 1,
                created_ns: 10,
                event: OperationalEvent::RecordAccepted {
                    collection: ".agents".to_owned(),
                    path: ProtocolPath::parse("review/SKILL.md").unwrap(),
                    source_peer: Some(EndpointId::from_bytes([4; 32])),
                },
            }
        );
    }

    #[test]
    fn operational_log_stays_bounded() {
        let mut store = StateStore::open_in_memory().unwrap();
        for index in 0..5 {
            store
                .append_log(index, &OperationalEvent::DaemonStarted, 3)
                .unwrap();
        }
        let logs = store.logs().unwrap();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].created_ns, 2);
        assert_eq!(logs[2].created_ns, 4);
    }

    #[test]
    fn operational_log_pages_use_stable_ids_across_retention_wrap() {
        let mut store = StateStore::open_in_memory().unwrap();
        for index in 0..10 {
            store
                .append_log(index, &OperationalEvent::DaemonStarted, 3)
                .unwrap();
        }
        let first = store.logs_page(0, 2).unwrap();
        assert_eq!(
            first.logs.iter().map(|log| log.id).collect::<Vec<_>>(),
            vec![8, 9]
        );
        assert_eq!(first.next_after_id, 9);
        assert!(first.has_more);
        let second = store.logs_page(first.next_after_id, 2).unwrap();
        assert_eq!(
            second.logs.iter().map(|log| log.id).collect::<Vec<_>>(),
            vec![10]
        );
        assert!(!second.has_more);

        store
            .append_log(10, &OperationalEvent::DaemonStarted, 3)
            .unwrap();
        let followed = store.logs_page(second.next_after_id, 64).unwrap();
        assert_eq!(followed.logs[0].id, 11);
    }

    #[test]
    fn materialized_fingerprint_replaces_in_place_per_path() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let record = sample_record(10, 7);
        store
            .merge_record(&record, 10, Some(record.author()), 100)
            .unwrap();
        let first = FileFingerprint {
            modified_ns: 9,
            size: 5,
            hash: [7; 32],
        };
        let second = FileFingerprint {
            modified_ns: 8,
            size: 5,
            hash: [7; 32],
        };
        store
            .set_materialized_fingerprint(".agents", "review/SKILL.md", first)
            .unwrap();
        store
            .set_materialized_fingerprint(".agents", "review/SKILL.md", second)
            .unwrap();
        let states = store.record_states(".agents").unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].materialized_fingerprint, Some(second));
    }

    #[test]
    fn indexed_record_state_lookup_handles_present_absent_and_corrupt_rows() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let record = sample_record(10, 7);
        store.merge_record(&record, 10, None, 100).unwrap();
        assert_eq!(
            store.record_state(".agents", "review/SKILL.md").unwrap(),
            Some(store.record_states(".agents").unwrap().remove(0))
        );
        assert_eq!(
            store.record_state(".agents", "missing/SKILL.md").unwrap(),
            None
        );

        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE path_records SET materialized_hash = ?3
                 WHERE collection = ?1 AND path = ?2",
                params![".agents", "review/SKILL.md", vec![1_u8]],
            )
            .unwrap();
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        assert!(matches!(
            store.record_state(".agents", "review/SKILL.md"),
            Err(StateError::InvalidStoredState(
                "materialized file hash has the wrong length"
            ))
        ));
    }

    #[test]
    fn materialization_root_change_unmaterializes_other_file_winners_atomically() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(
                ".agents",
                Path::new("/configured"),
                Some(Path::new("/physical-b")),
            )
            .unwrap();
        let first = sample_record(10, 7);
        let second = Record::file(
            ".agents",
            ProtocolPath::parse("other/SKILL.md").unwrap(),
            11,
            EndpointId::from_bytes([4; 32]),
            5,
            [8; 32],
        )
        .unwrap();
        store
            .merge_record(&first, 10, Some(first.author()), 100)
            .unwrap();
        store
            .merge_record(&second, 11, Some(second.author()), 100)
            .unwrap();
        let first_fingerprint = FileFingerprint {
            modified_ns: 10,
            size: 5,
            hash: [7; 32],
        };
        let second_fingerprint = FileFingerprint {
            modified_ns: 11,
            size: 5,
            hash: [8; 32],
        };
        store
            .set_materialized_fingerprint(".agents", first.path().as_str(), first_fingerprint)
            .unwrap();
        store
            .set_materialized_fingerprint(".agents", second.path().as_str(), second_fingerprint)
            .unwrap();

        store
            .mark_materialized_and_log(
                ".agents",
                first.path().as_str(),
                MaterializedFile {
                    resolved_root: Path::new("/physical-a"),
                    fingerprint: first_fingerprint,
                },
                12,
                &OperationalEvent::FileInstalled {
                    collection: ".agents".to_owned(),
                    path: first.path().clone(),
                },
                100,
            )
            .unwrap();

        assert_eq!(
            store.collection(".agents").unwrap().unwrap().resolved_root,
            Some(PathBuf::from("/physical-a"))
        );
        let states = store.record_states(".agents").unwrap();
        let installed = states
            .iter()
            .find(|state| state.record.path() == first.path())
            .unwrap();
        assert!(installed.materialized);
        assert_eq!(installed.materialized_fingerprint, Some(first_fingerprint));
        let detached = states
            .iter()
            .find(|state| state.record.path() == second.path())
            .unwrap();
        assert!(!detached.materialized);
        assert_eq!(detached.materialized_fingerprint, None);
    }

    #[test]
    fn repair_transition_rolls_back_when_its_log_fails() {
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .add_collection(".agents", Path::new("/skills"), None)
            .unwrap();
        let record = sample_record(10, 7);
        store
            .merge_record(&record, 10, Some(record.author()), 100)
            .unwrap();
        let fingerprint = FileFingerprint {
            modified_ns: 10,
            size: 5,
            hash: [7; 32],
        };
        store
            .set_materialized_fingerprint(".agents", record.path().as_str(), fingerprint)
            .unwrap();
        let before = store.record_states(".agents").unwrap();
        store.reject_future_log_inserts().unwrap();

        let result = store.mark_repair_required_and_log(
            ".agents",
            record.path().as_str(),
            11,
            &OperationalEvent::CollectionWarning {
                collection: ".agents".to_owned(),
                path: Some(record.path().clone()),
                issue: CollectionIssue::TimestampRejected,
            },
            100,
        );

        assert!(result.is_err());
        assert_eq!(store.record_states(".agents").unwrap(), before);
    }

    #[test]
    fn operational_log_rejects_unbounded_fields() {
        let mut store = StateStore::open_in_memory().unwrap();
        let path = ProtocolPath::parse(&"x".repeat(4_097)).unwrap();
        let event = OperationalEvent::RecordAccepted {
            collection: ".agents".to_owned(),
            path,
            source_peer: None,
        };
        assert!(store.append_log(1, &event, 10).is_err());
        assert!(store.logs().unwrap().is_empty());
    }

    #[test]
    fn operational_log_rejects_corrupt_unknown_and_oversized_payloads() {
        let store = StateStore::open_in_memory().unwrap();
        for payload in [
            b"{".to_vec(),
            br#"{"event":"unknown"}"#.to_vec(),
            br#"{"event":"daemon_started","body":"unexpected"}"#.to_vec(),
        ] {
            store
                .connection
                .execute("DELETE FROM operational_logs", [])
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO operational_logs (created_ns, payload) VALUES (1, ?1)",
                    [payload],
                )
                .unwrap();
            let error = store.logs().unwrap_err();
            assert!(
                matches!(
                    error,
                    StateError::InvalidStoredState("operational event payload is invalid")
                ),
                "{error:?}"
            );
        }

        let oversized = i64::try_from(MAX_OPERATIONAL_EVENT_BYTES + 1).unwrap();
        assert!(
            store
                .connection
                .execute(
                    "INSERT INTO operational_logs (created_ns, payload)
                     VALUES (1, zeroblob(?1))",
                    [oversized],
                )
                .is_err()
        );
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        for insert in [
            "INSERT INTO operational_logs (created_ns, payload) VALUES (1, '{}')",
            "INSERT INTO operational_logs (created_ns, payload) VALUES (1, X'')",
            "INSERT INTO operational_logs (created_ns, payload)
             VALUES (1, zeroblob(16385))",
        ] {
            store
                .connection
                .execute("DELETE FROM operational_logs", [])
                .unwrap();
            store.connection.execute(insert, []).unwrap();
            let errors = [
                store.logs().map(|_| ()).unwrap_err(),
                store.logs_page(0, 10).map(|_| ()).unwrap_err(),
            ];
            for error in errors {
                assert!(
                    matches!(
                        error,
                        StateError::InvalidStoredState(
                            "operational event payload has invalid storage"
                        )
                    ),
                    "{error:?}"
                );
            }
        }
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
    }

    #[test]
    fn operational_log_api_and_debug_output_exclude_secrets() {
        let config = Config::from_toml(
            r#"
            [joining.headers]
            Authorization = "Bearer private-auth-value"
            "#,
        )
        .unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store
            .append_log(
                1,
                &OperationalEvent::PeerSessionFailed {
                    peer_endpoint: EndpointId::from_bytes([7; 32]),
                },
                10,
            )
            .unwrap();
        let debug = format!("{config:?} {:?}", store.logs().unwrap());
        let cli_json = crate::daemon::logs_page_value(&store, 0, 10)
            .unwrap()
            .to_string();
        for secret in [
            "private-auth-value",
            "funny-capybara",
            "iroh-endpoint-ticket",
            "join-nonce",
            "request-body",
            "skill-file-contents",
        ] {
            assert!(!debug.contains(secret));
            assert!(!cli_json.contains(secret));
        }
        let stored_bytes: Vec<u8> = store
            .connection
            .query_row("SELECT payload FROM operational_logs", [], |row| row.get(0))
            .unwrap();
        assert!(
            !String::from_utf8(stored_bytes)
                .unwrap()
                .contains(config.joining.headers["Authorization"].expose())
        );
    }

    #[test]
    fn peer_hint_is_atomically_replaced_and_bounded() {
        let mut store = StateStore::open_in_memory().unwrap();
        let peer = EndpointId::from_bytes([8; 32]);
        store.replace_peer_hint(peer, "first").unwrap();
        store.replace_peer_hint(peer, "new").unwrap();
        assert_eq!(store.peer_hint(peer).unwrap(), Some("new".to_owned()));
        let too_large = "x".repeat(MAX_PEER_HINT_BYTES + 1);
        assert!(store.replace_peer_hint(peer, &too_large).is_err());
        assert_eq!(store.peer_hint(peer).unwrap(), Some("new".to_owned()));
    }

    #[test]
    fn peer_hint_read_guard_never_returns_invalid_sqlite_cells() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("state.sqlite3");
        let peer = EndpointId::from_bytes([18; 32]);
        StateStore::open(&database)
            .unwrap()
            .replace_peer_hint(peer, "valid")
            .unwrap();
        let store = StateStore::open(&database).unwrap();
        assert_eq!(store.peer_hint(peer).unwrap(), Some("valid".to_owned()));
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();

        store
            .connection
            .execute(
                "UPDATE peer_hints SET hint = '' WHERE endpoint_id = ?1",
                [peer.as_bytes()],
            )
            .unwrap();
        assert_eq!(store.peer_hint(peer).unwrap(), None);
        store
            .connection
            .execute(
                "UPDATE peer_hints SET hint = CAST(zeroblob(32) AS BLOB)
                 WHERE endpoint_id = ?1",
                [peer.as_bytes()],
            )
            .unwrap();
        assert_eq!(store.peer_hint(peer).unwrap(), None);
        store
            .connection
            .execute(
                "UPDATE peer_hints SET hint = printf('%*s', 16385, '')
                 WHERE endpoint_id = ?1",
                [peer.as_bytes()],
            )
            .unwrap();
        assert_eq!(store.peer_hint(peer).unwrap(), None);

        store
            .connection
            .pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        for rejected in [
            "UPDATE peer_hints SET hint = '' WHERE endpoint_id = ?1",
            "UPDATE peer_hints SET hint = CAST(zeroblob(1) AS BLOB) WHERE endpoint_id = ?1",
            "UPDATE peer_hints SET hint = printf('%*s', 16385, '') WHERE endpoint_id = ?1",
        ] {
            assert!(
                store
                    .connection
                    .execute(rejected, [peer.as_bytes()])
                    .is_err()
            );
        }
    }

    #[test]
    fn losing_local_admission_retries_from_the_selected_parent() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let first = DeviceIdentity::from_secret([2; 32]);
        let second = DeviceIdentity::from_secret([3; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([8; 32]), "creator", &creator).unwrap();
        let first_change = admission(&first, "first");
        let first_child = RosterRevision::child(&genesis, first_change.clone(), &creator).unwrap();
        let second_child =
            RosterRevision::child(&genesis, admission(&second, "second"), &creator).unwrap();
        let (losing_change, winner) =
            if first_child.canonical_hash() < second_child.canonical_hash() {
                (first_change, second_child.clone())
            } else {
                (admission(&second, "second"), first_child.clone())
            };
        let mut store = StateStore::open_in_memory().unwrap();
        store.insert_roster_revision(&genesis).unwrap();
        store.insert_roster_revision(&first_child).unwrap();
        store.insert_roster_revision(&second_child).unwrap();
        let selected = store
            .apply_roster_change(&creator, losing_change.clone())
            .unwrap();
        assert_eq!(selected.parent_hash(), Some(winner.canonical_hash()));
        assert!(roster_change_is_satisfied(&selected, &losing_change));
        assert_eq!(store.selected_roster_chain().unwrap().len(), 3);
    }

    #[test]
    fn competing_names_for_one_endpoint_keep_the_selected_name_without_retrying() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("state.sqlite3");
        let creator = DeviceIdentity::from_secret([11; 32]);
        let joining = DeviceIdentity::from_secret([12; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([13; 32]), "creator", &creator).unwrap();
        let first_change = admission(&joining, "first-name");
        let second_change = admission(&joining, "second-name");
        let first = RosterRevision::child(&genesis, first_change.clone(), &creator).unwrap();
        let second = RosterRevision::child(&genesis, second_change.clone(), &creator).unwrap();
        let (winner, losing_change) = if first.canonical_hash() > second.canonical_hash() {
            (&first, second_change)
        } else {
            (&second, first_change)
        };
        let selected_name = winner
            .members()
            .get(&joining.endpoint_id())
            .unwrap()
            .clone();
        let mut store = StateStore::open(&database).unwrap();
        for revision in [&genesis, &first, &second] {
            store.insert_roster_revision(revision).unwrap();
        }
        for _ in 0..3 {
            store
                .apply_roster_change(&creator, losing_change.clone())
                .unwrap();
        }
        assert_eq!(store.selected_roster_chain().unwrap().len(), 2);
        assert_eq!(
            store
                .selected_roster_chain()
                .unwrap()
                .last()
                .unwrap()
                .members()
                .get(&joining.endpoint_id()),
            Some(&selected_name)
        );
        drop(store);
        let mut reopened = StateStore::open(&database).unwrap();
        reopened
            .apply_roster_change(&creator, losing_change)
            .unwrap();
        let selected = reopened.selected_roster_chain().unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected
                .last()
                .unwrap()
                .members()
                .get(&joining.endpoint_id()),
            Some(&selected_name)
        );
    }

    #[test]
    fn competing_removal_wins_then_admission_retries_and_reopens() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("state.sqlite3");
        let creator = DeviceIdentity::from_secret([1; 32]);
        let existing = DeviceIdentity::from_secret([2; 32]);
        let joining = DeviceIdentity::from_secret([3; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([7; 32]), "creator", &creator).unwrap();
        let parent =
            RosterRevision::child(&genesis, admission(&existing, "existing"), &creator).unwrap();
        let removal = RosterRevision::child(
            &parent,
            RosterChange::Remove(existing.endpoint_id()),
            &creator,
        )
        .unwrap();
        let joining_change = admission(&joining, "joining");
        let competing_admission =
            RosterRevision::child(&parent, joining_change.clone(), &creator).unwrap();
        let mut store = StateStore::open(&database).unwrap();
        for revision in [&genesis, &parent, &competing_admission, &removal] {
            store.insert_roster_revision(revision).unwrap();
        }
        let selected = store.apply_roster_change(&creator, joining_change).unwrap();
        assert_eq!(selected.parent_hash(), Some(removal.canonical_hash()));
        assert!(!selected.members().contains_key(&existing.endpoint_id()));
        assert!(selected.members().contains_key(&joining.endpoint_id()));
        drop(store);
        let reopened = StateStore::open(&database).unwrap();
        assert_eq!(
            reopened
                .selected_roster_chain()
                .unwrap()
                .last()
                .unwrap()
                .canonical_hash(),
            selected.canonical_hash()
        );
    }

    #[test]
    fn joined_roster_install_is_all_or_nothing_and_requires_local_membership() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let joiner = DeviceIdentity::from_secret([2; 32]);
        let outsider = DeviceIdentity::from_secret([3; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([6; 32]), "creator", &creator).unwrap();
        let admission =
            RosterRevision::child(&genesis, admission(&joiner, "joiner"), &creator).unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        assert!(
            store
                .install_joined_roster_chain(
                    &[genesis.clone(), admission.clone()],
                    outsider.endpoint_id()
                )
                .is_err()
        );
        assert!(store.selected_roster_chain().unwrap().is_empty());
        let oversized_hint = "x".repeat(MAX_PEER_HINT_BYTES + 1);
        assert!(
            store
                .install_joined_state(
                    &[genesis.clone(), admission.clone()],
                    joiner.endpoint_id(),
                    &[(creator.endpoint_id(), oversized_hint)]
                )
                .is_err()
        );
        assert!(store.selected_roster_chain().unwrap().is_empty());
        store
            .install_joined_roster_chain(
                &[genesis.clone(), admission.clone()],
                joiner.endpoint_id(),
            )
            .unwrap();
        assert_eq!(
            store.selected_roster_chain().unwrap(),
            vec![genesis.clone(), admission.clone()]
        );
        store
            .install_or_resume_joined_state(
                &[genesis.clone(), admission.clone()],
                joiner.endpoint_id(),
                "joiner",
                &[(creator.endpoint_id(), "refreshed".to_owned())],
            )
            .unwrap();
        assert_eq!(
            store.peer_hint(creator.endpoint_id()).unwrap(),
            Some("refreshed".to_owned())
        );
        assert!(
            store
                .install_or_resume_joined_state(
                    &[genesis, admission],
                    joiner.endpoint_id(),
                    "different",
                    &[]
                )
                .is_err()
        );
    }
}
