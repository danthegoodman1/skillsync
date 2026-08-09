use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, MetadataExt, OpenOptions};
use globset::{Glob, GlobSet, GlobSetBuilder};
use thiserror::Error;

use crate::identity::EndpointId;
use crate::path::{FilenameComparison, LocalPathIndex, PathError, ProtocolPath};
use crate::record::{Record, RecordKind};
use crate::root::{StableRoot, StableRootError, open_stable_root_with_hook};
use crate::setup::now_ns;
use crate::state::{
    CollectionIssue, CollectionScanStatus, CollectionState, FileFingerprint, OperationalEvent,
    StateError, StateStore,
};

const INTERNAL_PREFIX: &str = ".skillsync-tmp-";

pub struct Scanner {
    ignores: GlobSet,
    max_future_skew: Duration,
    max_logs: usize,
    comparisons: Mutex<BTreeMap<std::path::PathBuf, FilenameComparison>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanStage {
    BeforeOpen,
    AfterMetadata,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanSummary {
    pub files: usize,
    pub accepted: usize,
    pub tombstones: usize,
    pub rejected: usize,
    pub repair_required: usize,
    pub paused: bool,
}

impl Scanner {
    pub fn new(
        patterns: &[String],
        max_future_skew: Duration,
        max_logs: usize,
    ) -> Result<Self, ScanError> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            builder.add(Glob::new(pattern)?);
        }
        Ok(Self {
            ignores: builder.build()?,
            max_future_skew,
            max_logs,
            comparisons: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn scan_collection(
        &self,
        state: &mut StateStore,
        collection: &CollectionState,
        author: EndpointId,
    ) -> Result<ScanSummary, ScanError> {
        self.scan_collection_with_hook(state, collection, author, &mut |_, _| {})
    }

    pub fn scan_collection_with_hook(
        &self,
        state: &mut StateStore,
        collection: &CollectionState,
        author: EndpointId,
        hook: &mut dyn FnMut(&ProtocolPath, ScanStage),
    ) -> Result<ScanSummary, ScanError> {
        self.scan_collection_with_hooks(state, collection, author, &mut || Ok(()), hook)
    }

    fn scan_collection_with_hooks(
        &self,
        state: &mut StateStore,
        collection: &CollectionState,
        author: EndpointId,
        root_hook: &mut dyn FnMut() -> io::Result<()>,
        hook: &mut dyn FnMut(&ProtocolPath, ScanStage),
    ) -> Result<ScanSummary, ScanError> {
        let observed_ns = now_ns();
        let StableRoot {
            directory: root_dir,
            resolved_path: resolved_root,
        } = match open_stable_root_with_hook(&collection.local_path, root_hook) {
            Ok(root) => root,
            Err(StableRootError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotADirectory | io::ErrorKind::InvalidInput
                ) =>
            {
                state.set_collection_scan_status(
                    &collection.name,
                    CollectionScanStatus::NotDirectory,
                )?;
                self.log(
                    state,
                    observed_ns,
                    OperationalEvent::CollectionPaused {
                        collection: collection.name.clone(),
                    },
                )?;
                return Ok(ScanSummary {
                    paused: true,
                    ..ScanSummary::default()
                });
            }
            Err(StableRootError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                state
                    .set_collection_scan_status(&collection.name, CollectionScanStatus::Missing)?;
                self.log(
                    state,
                    observed_ns,
                    OperationalEvent::CollectionPaused {
                        collection: collection.name.clone(),
                    },
                )?;
                return Ok(ScanSummary {
                    paused: true,
                    ..ScanSummary::default()
                });
            }
            Err(StableRootError::Io(error)) => return Err(error.into()),
            Err(StableRootError::Unstable) => return Err(ScanError::UnstableRoot),
        };

        let comparison = if let Some(comparison) = self
            .comparisons
            .lock()
            .expect("comparison cache lock poisoned")
            .get(&resolved_root)
            .copied()
        {
            comparison
        } else {
            let comparison = probe_filename_comparison_in(&root_dir)?;
            self.comparisons
                .lock()
                .expect("comparison cache lock poisoned")
                .insert(resolved_root.clone(), comparison);
            comparison
        };
        let mut context = WalkContext {
            root: &root_dir,
            resolved_root: &resolved_root,
            collection: &collection.name,
            ignores: &self.ignores,
            paths: LocalPathIndex::new(comparison),
            files: BTreeMap::new(),
            excluded_prefixes: Vec::new(),
            warnings: Vec::new(),
            hook,
        };
        let mut ancestors = BTreeSet::new();
        walk_directory(&root_dir, Path::new(""), &mut ancestors, &mut context)?;

        state.complete_collection_scan(&collection.name, &collection.local_path, &resolved_root)?;

        for warning in std::mem::take(&mut context.warnings) {
            self.log(state, observed_ns, warning)?;
        }

        let mut summary = ScanSummary {
            files: context.files.len(),
            ..ScanSummary::default()
        };
        let current = state.record_states(&collection.name)?;
        let materialized_fingerprints = current
            .iter()
            .filter_map(|record| {
                record
                    .materialized_fingerprint
                    .map(|fingerprint| (record.record.path().as_str().to_owned(), fingerprint))
            })
            .collect::<BTreeMap<_, _>>();
        let future_limit = observed_ns.saturating_add(duration_ns(self.max_future_skew));

        for (path, disk) in &context.files {
            if disk.modified_ns > future_limit {
                let event = OperationalEvent::CollectionWarning {
                    collection: collection.name.clone(),
                    path: Some(path.clone()),
                    issue: CollectionIssue::TimestampRejected,
                };
                let diverged_materialized_winner = current.iter().any(|winner| {
                    winner.record.path() == path
                        && winner.materialized
                        && !disk_bytes_match_record(disk, &winner.record)
                });
                if diverged_materialized_winner {
                    state.mark_repair_required_and_log(
                        &collection.name,
                        path.as_str(),
                        observed_ns,
                        &event,
                        self.max_logs,
                    )?;
                    summary.repair_required += 1;
                } else {
                    self.log(state, observed_ns, event)?;
                }
                summary.rejected += 1;
                continue;
            }
            let candidate = Record::file(
                collection.name.clone(),
                path.clone(),
                disk.modified_ns,
                author,
                disk.size,
                disk.hash,
            )?;
            if let Some(winner) = state.record(&collection.name, path.as_str())? {
                let fingerprint = disk.fingerprint();
                let durable_match = materialized_fingerprints
                    .get(path.as_str())
                    .is_some_and(|stored| *stored == fingerprint);
                if durable_match || disk_matches_record(disk, &winner) {
                    state.set_materialized_fingerprint(
                        &collection.name,
                        path.as_str(),
                        fingerprint,
                    )?;
                    continue;
                }
                if !state.merge_record(&candidate, observed_ns, None, self.max_logs)? {
                    if matches!(winner.kind(), RecordKind::File { .. }) {
                        let event = OperationalEvent::RepairRequired {
                            collection: collection.name.clone(),
                            path: path.clone(),
                        };
                        state.mark_repair_required_and_log(
                            &collection.name,
                            path.as_str(),
                            observed_ns,
                            &event,
                            self.max_logs,
                        )?;
                        summary.repair_required += 1;
                    }
                    summary.rejected += 1;
                    continue;
                }
            } else {
                state.merge_record(&candidate, observed_ns, None, self.max_logs)?;
            }
            summary.accepted += 1;
        }

        for winner_state in current {
            let winner = winner_state.record;
            if !matches!(winner.kind(), RecordKind::File { .. })
                || !winner_state.materialized
                || context.files.contains_key(winner.path())
                || self.is_ignored(winner.path().as_str())
                || context.is_excluded(winner.path().as_str())
            {
                continue;
            }
            let modified_ns = observed_ns.max(winner.modified_ns().saturating_add(1));
            let tombstone = Record::tombstone(
                collection.name.clone(),
                winner.path().clone(),
                modified_ns,
                author,
            )?;
            if state.merge_record(&tombstone, observed_ns, None, self.max_logs)? {
                summary.tombstones += 1;
            }
        }

        self.log(
            state,
            observed_ns,
            OperationalEvent::CollectionScanned {
                collection: collection.name.clone(),
            },
        )?;
        Ok(summary)
    }

    fn is_ignored(&self, path: &str) -> bool {
        path.split('/')
            .any(|component| component.starts_with(INTERNAL_PREFIX))
            || self.ignores.is_match(path)
    }

    fn log(
        &self,
        state: &mut StateStore,
        created_ns: i64,
        event: OperationalEvent,
    ) -> Result<(), ScanError> {
        state.append_log(created_ns, &event, self.max_logs)?;
        Ok(())
    }

    pub const fn max_logs(&self) -> usize {
        self.max_logs
    }
}

struct DiskFile {
    modified_ns: i64,
    size: u64,
    hash: [u8; 32],
}

impl DiskFile {
    fn fingerprint(&self) -> FileFingerprint {
        FileFingerprint {
            modified_ns: self.modified_ns,
            size: self.size,
            hash: self.hash,
        }
    }
}

struct WalkContext<'a> {
    root: &'a Dir,
    resolved_root: &'a Path,
    collection: &'a str,
    ignores: &'a GlobSet,
    paths: LocalPathIndex,
    files: BTreeMap<ProtocolPath, DiskFile>,
    excluded_prefixes: Vec<String>,
    warnings: Vec<OperationalEvent>,
    hook: &'a mut dyn FnMut(&ProtocolPath, ScanStage),
}

impl WalkContext<'_> {
    fn is_ignored(&self, path: &ProtocolPath) -> bool {
        path.as_str()
            .split('/')
            .any(|component| component.starts_with(INTERNAL_PREFIX))
            || self.ignores.is_match(path.as_str())
    }

    fn exclude(&mut self, path: Option<ProtocolPath>, issue: CollectionIssue) {
        if let Some(path) = &path {
            self.excluded_prefixes.push(path.as_str().to_owned());
        }
        self.warnings.push(OperationalEvent::CollectionWarning {
            collection: self.collection.to_owned(),
            path,
            issue,
        });
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.excluded_prefixes.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

fn walk_directory(
    directory: &Dir,
    logical: &Path,
    ancestors: &mut BTreeSet<(u64, u64)>,
    context: &mut WalkContext<'_>,
) -> Result<(), ScanError> {
    let metadata = directory.dir_metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    if !ancestors.insert(identity) {
        context.exclude(protocol_path(logical).ok(), CollectionIssue::SymlinkCycle);
        return Ok(());
    }

    let mut entries = directory.entries()?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);
    for entry in entries {
        let logical_path = logical.join(entry.file_name());
        let protocol = match protocol_path(&logical_path) {
            Ok(path) => path,
            Err(_) => {
                context.exclude(None, CollectionIssue::PathRejected);
                continue;
            }
        };
        if context.is_ignored(&protocol) {
            continue;
        }
        let file_type = entry.file_type()?;
        (context.hook)(&protocol, ScanStage::BeforeOpen);
        if file_type.is_symlink() {
            let target = resolve_symlink(context.resolved_root, &logical_path);
            let target_dir = target.as_ref().ok().and_then(|target| {
                if target.as_os_str().is_empty() {
                    context.root.try_clone().ok()
                } else {
                    context.root.open_dir(target).ok()
                }
            });
            if let Some(target_dir) = target_dir {
                walk_directory(&target_dir, &logical_path, ancestors, context)?;
            } else {
                match target {
                    Ok(target) => match stable_file(
                        || context.root.open(&target),
                        || (context.hook)(&protocol, ScanStage::AfterMetadata),
                    ) {
                        Ok(Some(disk)) => insert_disk_file(protocol, disk, context)?,
                        _ => context.exclude(Some(protocol), CollectionIssue::SymlinkEscape),
                    },
                    Err(_) => context.exclude(Some(protocol), CollectionIssue::SymlinkEscape),
                }
            }
        } else if file_type.is_dir() {
            let target_dir = entry.open_dir()?;
            walk_directory(&target_dir, &logical_path, ancestors, context)?;
        } else if file_type.is_file() {
            match stable_file(
                || entry.open(),
                || (context.hook)(&protocol, ScanStage::AfterMetadata),
            )? {
                Some(disk) => insert_disk_file(protocol, disk, context)?,
                None => context.exclude(Some(protocol), CollectionIssue::PathRejected),
            }
        }
    }
    ancestors.remove(&identity);
    Ok(())
}

fn resolve_symlink(resolved_root: &Path, logical: &Path) -> io::Result<std::path::PathBuf> {
    fs::canonicalize(resolved_root.join(logical))?
        .strip_prefix(resolved_root)
        .map(Path::to_path_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "symlink escapes root"))
}

fn insert_disk_file(
    protocol: ProtocolPath,
    disk: DiskFile,
    context: &mut WalkContext<'_>,
) -> Result<(), ScanError> {
    if let Err(error) = context.paths.insert(protocol.clone()) {
        context.exclude(Some(protocol), CollectionIssue::PathRejected);
        if matches!(error, PathError::Collision { .. }) {
            return Ok(());
        }
        return Err(error.into());
    }
    context.files.insert(protocol, disk);
    Ok(())
}

fn stable_file(
    mut open: impl FnMut() -> io::Result<cap_std::fs::File>,
    mut after_metadata: impl FnMut(),
) -> Result<Option<DiskFile>, ScanError> {
    for _ in 0..3 {
        let mut file = open()?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Ok(None);
        }
        after_metadata();
        let mut hasher = blake3::Hasher::new();
        io::copy(&mut file, &mut hasher)?;
        let after = file.metadata()?;
        if stable_metadata(&before, &after) {
            return Ok(Some(DiskFile {
                modified_ns: metadata_modified_ns(&after),
                size: after.len(),
                hash: *hasher.finalize().as_bytes(),
            }));
        }
    }
    Ok(None)
}

fn stable_metadata(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn metadata_modified_ns(metadata: &Metadata) -> i64 {
    metadata
        .mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(metadata.mtime_nsec())
}

fn protocol_path(path: &Path) -> Result<ProtocolPath, PathError> {
    let text = path.to_str().ok_or(PathError::InvalidUtf8)?;
    ProtocolPath::parse(text)
}

fn disk_matches_record(disk: &DiskFile, record: &Record) -> bool {
    match record.kind() {
        RecordKind::File { size, content_hash } => {
            disk.modified_ns == record.modified_ns()
                && disk.size == size
                && disk.hash == content_hash
        }
        RecordKind::Tombstone => false,
    }
}

fn disk_bytes_match_record(disk: &DiskFile, record: &Record) -> bool {
    match record.kind() {
        RecordKind::File { size, content_hash } => disk.size == size && disk.hash == content_hash,
        RecordKind::Tombstone => false,
    }
}

pub fn probe_filename_comparison(root: &Path) -> Result<FilenameComparison, ScanError> {
    let root = Dir::open_ambient_dir(root, ambient_authority())?;
    probe_filename_comparison_in(&root)
}

fn probe_filename_comparison_in(root: &Dir) -> Result<FilenameComparison, ScanError> {
    let token = format!("{}-{}", std::process::id(), now_ns().unsigned_abs());
    let case_sensitive = probe_distinct_names(
        root,
        &format!("{INTERNAL_PREFIX}{token}-case"),
        &format!("{INTERNAL_PREFIX}{token}-CASE"),
    )?;
    let normalization_sensitive = probe_distinct_names(
        root,
        &format!("{INTERNAL_PREFIX}{token}-caf\u{e9}"),
        &format!("{INTERNAL_PREFIX}{token}-cafe\u{301}"),
    )?;
    Ok(match (case_sensitive, normalization_sensitive) {
        (true, true) => FilenameComparison::CaseSensitive,
        (false, true) => FilenameComparison::CaseInsensitive,
        (true, false) => FilenameComparison::NormalizationInsensitive,
        (false, false) => FilenameComparison::CaseAndNormalizationInsensitive,
    })
}

fn probe_distinct_names(
    root: &Dir,
    first_name: &str,
    second_name: &str,
) -> Result<bool, ScanError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let first = root.open_with(first_name, &options)?;
    drop(first);
    let distinct = match root.open_with(second_name, &options) {
        Ok(file) => {
            drop(file);
            true
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            let _ = root.remove_file(first_name);
            return Err(error.into());
        }
    };
    let _ = root.remove_file(first_name);
    let _ = root.remove_file(second_name);
    Ok(distinct)
}

fn duration_ns(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("filesystem scan I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("ignore pattern is invalid: {0}")]
    Glob(#[from] globset::Error),
    #[error("collection root resolution changed during scan setup")]
    UnstableRoot,
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Record(#[from] crate::record::RecordError),
    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::config::Config;

    fn scanner() -> Scanner {
        let config = Config::default();
        Scanner::new(
            &config.sync.ignore,
            config.sync.max_future_clock_skew,
            config.logging.max_entries,
        )
        .unwrap()
    }

    fn collection(name: &str, root: &Path) -> CollectionState {
        CollectionState {
            name: name.to_owned(),
            local_path: root.to_path_buf(),
            resolved_root: None,
            scan_status: CollectionScanStatus::Pending,
            watch_status: crate::state::CollectionWatchStatus::Pending,
        }
    }

    fn store_with_collection(database: &Path, name: &str, root: &Path) -> StateStore {
        let store = StateStore::open(database).unwrap();
        store.add_collection(name, root, None).unwrap();
        store
    }

    #[test]
    fn scans_edits_deletes_ignores_pauses_and_reopens() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(root.join("review/.git")).unwrap();
        fs::write(root.join("review/SKILL.md"), "first").unwrap();
        fs::write(root.join("review/.git/config"), "ignored").unwrap();
        fs::write(root.join("review/.DS_Store"), "ignored").unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = store_with_collection(&database, ".agents", &root);
        let endpoint = EndpointId::from_bytes([4; 32]);

        let first = scanner()
            .scan_collection(&mut store, &collection(".agents", &root), endpoint)
            .unwrap();
        assert_eq!(first.files, 1);
        assert_eq!(store.records(".agents").unwrap().len(), 1);

        let old = store.record(".agents", "review/SKILL.md").unwrap().unwrap();
        fs::write(root.join("review/SKILL.md"), "second").unwrap();
        let newer = old.modified_ns().saturating_add(1_000_000);
        filetime::set_file_mtime(
            root.join("review/SKILL.md"),
            filetime::FileTime::from_unix_time(
                newer.div_euclid(1_000_000_000),
                u32::try_from(newer.rem_euclid(1_000_000_000)).unwrap(),
            ),
        )
        .unwrap();
        let attached = store.collection(".agents").unwrap().unwrap();
        scanner()
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        let edited = store.record(".agents", "review/SKILL.md").unwrap().unwrap();
        assert!(edited.modified_ns() > old.modified_ns());

        fs::remove_file(root.join("review/SKILL.md")).unwrap();
        let attached = store.collection(".agents").unwrap().unwrap();
        let deleted = scanner()
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        assert_eq!(deleted.tombstones, 1);
        assert!(matches!(
            store
                .record(".agents", "review/SKILL.md")
                .unwrap()
                .unwrap()
                .kind(),
            RecordKind::Tombstone
        ));
        drop(store);

        let mut reopened = StateStore::open(&database).unwrap();
        fs::remove_dir_all(&root).unwrap();
        let attached = reopened.collection(".agents").unwrap().unwrap();
        let paused = scanner()
            .scan_collection(&mut reopened, &attached, endpoint)
            .unwrap();
        assert!(paused.paused);
        assert!(matches!(
            reopened
                .record(".agents", "review/SKILL.md")
                .unwrap()
                .unwrap()
                .kind(),
            RecordKind::Tombstone
        ));
    }

    #[test]
    fn follows_safe_symlinks_and_rejects_escape_and_cycle() {
        let temporary = tempfile::tempdir().unwrap();
        let physical = temporary.path().join("physical");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(physical.join("shared")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(physical.join("shared/SKILL.md"), "safe").unwrap();
        fs::write(outside.join("secret"), "secret").unwrap();
        symlink(physical.join("shared"), physical.join("alias")).unwrap();
        symlink("alias", physical.join("alias-chain")).unwrap();
        symlink(&outside, physical.join("escape")).unwrap();
        symlink(&physical, physical.join("cycle")).unwrap();
        let root_link = temporary.path().join("root-link");
        symlink(&physical, &root_link).unwrap();

        let database = temporary.path().join("state.sqlite3");
        let mut store = store_with_collection(&database, ".claude", &root_link);
        scanner()
            .scan_collection(
                &mut store,
                &collection(".claude", &root_link),
                EndpointId::from_bytes([2; 32]),
            )
            .unwrap();

        assert!(
            store
                .record(".claude", "shared/SKILL.md")
                .unwrap()
                .is_some()
        );
        assert!(store.record(".claude", "alias/SKILL.md").unwrap().is_some());
        assert!(
            store
                .record(".claude", "alias-chain/SKILL.md")
                .unwrap()
                .is_some()
        );
        assert!(store.record(".claude", "escape/secret").unwrap().is_none());
        assert!(
            store
                .record(".claude", "cycle/shared/SKILL.md")
                .unwrap()
                .is_none()
        );
        let logs = store.logs().unwrap();
        assert!(logs.iter().any(|log| matches!(
            log.event,
            OperationalEvent::CollectionWarning {
                issue: CollectionIssue::SymlinkEscape,
                ..
            }
        )));
        assert!(logs.iter().any(|log| matches!(
            log.event,
            OperationalEvent::CollectionWarning {
                issue: CollectionIssue::SymlinkCycle,
                ..
            }
        )));
    }

    #[test]
    fn aliased_roots_are_scanned_as_separate_collections() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("SKILL.md"), "shared").unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection(".agents", &root, None).unwrap();
        store.add_collection(".claude", &root, None).unwrap();
        let scanner = scanner();
        let endpoint = EndpointId::from_bytes([5; 32]);
        scanner
            .scan_collection(&mut store, &collection(".agents", &root), endpoint)
            .unwrap();
        scanner
            .scan_collection(&mut store, &collection(".claude", &root), endpoint)
            .unwrap();
        assert!(store.record(".agents", "SKILL.md").unwrap().is_some());
        assert!(store.record(".claude", "SKILL.md").unwrap().is_some());
    }

    #[test]
    fn collision_probe_reports_the_actual_root_behavior_and_cleans_up() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let case_sensitive = {
            let lower = root.join("manual-case-probe");
            let upper = root.join("manual-CASE-probe");
            fs::write(&lower, "").unwrap();
            let result = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&upper)
            {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => panic!("case probe failed: {error}"),
            };
            let _ = fs::remove_file(lower);
            let _ = fs::remove_file(upper);
            result
        };
        let root_dir = Dir::open_ambient_dir(root, ambient_authority()).unwrap();
        let normalization_sensitive =
            probe_distinct_names(&root_dir, "manual-caf\u{e9}", "manual-cafe\u{301}").unwrap();
        let expected = match (case_sensitive, normalization_sensitive) {
            (true, true) => FilenameComparison::CaseSensitive,
            (false, true) => FilenameComparison::CaseInsensitive,
            (true, false) => FilenameComparison::NormalizationInsensitive,
            (false, false) => FilenameComparison::CaseAndNormalizationInsensitive,
        };
        assert_eq!(probe_filename_comparison(root).unwrap(), expected);
        assert!(fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(INTERNAL_PREFIX)
        }));
    }

    #[test]
    fn a_losing_disk_candidate_keeps_winner_metadata_and_marks_repair() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("SKILL.md"), "disk loser").unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection(".codex", &root, None).unwrap();
        let path = ProtocolPath::parse("SKILL.md").unwrap();
        let winner = Record::file(
            ".codex",
            path.clone(),
            now_ns().saturating_add(100_000_000),
            EndpointId::from_bytes([9; 32]),
            6,
            *blake3::hash(b"winner").as_bytes(),
        )
        .unwrap();
        store.merge_record(&winner, now_ns(), None, 100).unwrap();

        let summary = scanner()
            .scan_collection(
                &mut store,
                &collection(".codex", &root),
                EndpointId::from_bytes([1; 32]),
            )
            .unwrap();
        assert_eq!(summary.repair_required, 1);
        assert_eq!(store.record(".codex", "SKILL.md").unwrap(), Some(winner));
        assert_eq!(store.local_counts().unwrap().1, 1);
    }

    #[test]
    fn future_dated_divergent_disk_file_preserves_winner_and_marks_repair() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("SKILL.md");
        fs::write(&destination, "winner bytes").unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection(".agents", &root, None).unwrap();
        let scanner = scanner();
        let endpoint = EndpointId::from_bytes([3; 32]);
        scanner
            .scan_collection(&mut store, &collection(".agents", &root), endpoint)
            .unwrap();
        let winner = store.record(".agents", "SKILL.md").unwrap().unwrap();
        assert_eq!(store.local_counts().unwrap(), (1, 0));

        fs::write(&destination, "different future bytes").unwrap();
        let future_ns = now_ns().saturating_add(3_600_000_000_000);
        filetime::set_file_mtime(
            &destination,
            filetime::FileTime::from_unix_time(
                future_ns.div_euclid(1_000_000_000),
                u32::try_from(future_ns.rem_euclid(1_000_000_000)).unwrap(),
            ),
        )
        .unwrap();
        let attached = store.collection(".agents").unwrap().unwrap();
        let summary = scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();

        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.repair_required, 1);
        assert_eq!(store.record(".agents", "SKILL.md").unwrap(), Some(winner));
        assert_eq!(store.local_counts().unwrap(), (0, 1));
        let state = &store.record_states(".agents").unwrap()[0];
        assert!(!state.materialized);
        assert_eq!(state.materialized_fingerprint, None);
        assert!(store.logs().unwrap().iter().any(|log| matches!(
            &log.event,
            OperationalEvent::CollectionWarning {
                collection,
                path: Some(path),
                issue: CollectionIssue::TimestampRejected,
            } if collection == ".agents" && path.as_str() == "SKILL.md"
        )));
    }

    #[test]
    fn unseen_future_dated_path_creates_no_repair_row() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("UNSEEN.md");
        fs::write(&destination, "future bytes").unwrap();
        let future_ns = now_ns().saturating_add(3_600_000_000_000);
        filetime::set_file_mtime(
            &destination,
            filetime::FileTime::from_unix_time(
                future_ns.div_euclid(1_000_000_000),
                u32::try_from(future_ns.rem_euclid(1_000_000_000)).unwrap(),
            ),
        )
        .unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection(".agents", &root, None).unwrap();

        let summary = scanner()
            .scan_collection(
                &mut store,
                &collection(".agents", &root),
                EndpointId::from_bytes([3; 32]),
            )
            .unwrap();

        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.repair_required, 0);
        assert_eq!(store.record(".agents", "UNSEEN.md").unwrap(), None);
        assert!(store.record_states(".agents").unwrap().is_empty());
        assert_eq!(store.local_counts().unwrap(), (0, 0));
        assert!(store.logs().unwrap().iter().any(|log| matches!(
            &log.event,
            OperationalEvent::CollectionWarning {
                collection,
                path: Some(path),
                issue: CollectionIssue::TimestampRejected,
            } if collection == ".agents" && path.as_str() == "UNSEEN.md"
        )));
    }

    #[test]
    fn collection_root_replacement_stays_unmaterialized_across_scans_and_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("SKILL.md"), "present").unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = StateStore::open(&database).unwrap();
        store
            .add_collection("team", &first, Some(&fs::canonicalize(&first).unwrap()))
            .unwrap();
        let endpoint = EndpointId::from_bytes([6; 32]);
        let scanner = scanner();
        scanner
            .scan_collection(&mut store, &collection("team", &first), endpoint)
            .unwrap();
        let winner = store.record("team", "SKILL.md").unwrap().unwrap();

        store.replace_collection_path("team", &second).unwrap();
        scanner
            .scan_collection(
                &mut store,
                &CollectionState {
                    name: "team".to_owned(),
                    local_path: second,
                    resolved_root: None,
                    scan_status: CollectionScanStatus::Pending,
                    watch_status: crate::state::CollectionWatchStatus::Pending,
                },
                endpoint,
            )
            .unwrap();
        let attached = store.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        assert_eq!(
            store.record("team", "SKILL.md").unwrap(),
            Some(winner.clone())
        );
        assert!(!store.record_states("team").unwrap()[0].materialized);
        drop(store);

        let mut reopened = StateStore::open(&database).unwrap();
        let attached = reopened.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut reopened, &attached, endpoint)
            .unwrap();
        assert_eq!(reopened.record("team", "SKILL.md").unwrap(), Some(winner));
        assert!(!reopened.record_states("team").unwrap()[0].materialized);
    }

    #[test]
    fn failed_first_replacement_scan_never_arms_deletions() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let replacement = temporary.path().join("replacement");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(replacement.join("removed-during-walk")).unwrap();
        fs::write(first.join("SKILL.md"), "present").unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = StateStore::open(&database).unwrap();
        store.add_collection("team", &first, None).unwrap();
        let endpoint = EndpointId::from_bytes([6; 32]);
        let scanner = scanner();
        let attached = store.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        let winner = store.record("team", "SKILL.md").unwrap().unwrap();

        store.replace_collection_path("team", &replacement).unwrap();
        let attached = store.collection("team").unwrap().unwrap();
        let result = scanner.scan_collection_with_hook(
            &mut store,
            &attached,
            endpoint,
            &mut |path, stage| {
                if path.as_str() == "removed-during-walk" && stage == ScanStage::BeforeOpen {
                    fs::remove_dir(replacement.join("removed-during-walk")).unwrap();
                }
            },
        );
        assert!(result.is_err());
        let attached = store.collection("team").unwrap().unwrap();
        assert_eq!(attached.resolved_root, None);
        assert_eq!(attached.scan_status, CollectionScanStatus::Pending);
        assert_eq!(
            store.record("team", "SKILL.md").unwrap(),
            Some(winner.clone())
        );
        assert!(!store.record_states("team").unwrap()[0].materialized);

        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        assert_eq!(store.record("team", "SKILL.md").unwrap(), Some(winner));
        assert!(!store.record_states("team").unwrap()[0].materialized);
    }

    #[test]
    fn live_root_symlink_retarget_stays_unmaterialized_across_scans_and_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let populated = temporary.path().join("populated");
        let empty = temporary.path().join("empty");
        let root_link = temporary.path().join("root-link");
        fs::create_dir_all(&populated).unwrap();
        fs::create_dir_all(&empty).unwrap();
        fs::write(populated.join("SKILL.md"), "present").unwrap();
        symlink(&populated, &root_link).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = StateStore::open(&database).unwrap();
        store
            .add_collection(
                "team",
                &root_link,
                Some(&fs::canonicalize(&root_link).unwrap()),
            )
            .unwrap();
        let endpoint = EndpointId::from_bytes([6; 32]);
        let scanner = scanner();
        let attached = store.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        let winner = store.record("team", "SKILL.md").unwrap().unwrap();

        fs::remove_file(&root_link).unwrap();
        symlink(&empty, &root_link).unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        let retargeted = store.collection("team").unwrap().unwrap();
        assert_eq!(
            retargeted.resolved_root,
            Some(fs::canonicalize(&empty).unwrap())
        );
        scanner
            .scan_collection(&mut store, &retargeted, endpoint)
            .unwrap();
        assert_eq!(
            store.record("team", "SKILL.md").unwrap(),
            Some(winner.clone())
        );
        assert!(!store.record_states("team").unwrap()[0].materialized);
        drop(store);

        let mut reopened = StateStore::open(&database).unwrap();
        let attached = reopened.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut reopened, &attached, endpoint)
            .unwrap();
        assert_eq!(reopened.record("team", "SKILL.md").unwrap(), Some(winner));
        assert!(!reopened.record_states("team").unwrap()[0].materialized);
    }

    #[test]
    fn atomic_root_retarget_never_commits_mixed_identity_and_contents() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        let root_link = temporary.path().join("root-link");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("ONLY_A"), "a").unwrap();
        fs::write(second.join("ONLY_B"), "b").unwrap();
        symlink(&first, &root_link).unwrap();
        let first_resolved = fs::canonicalize(&first).unwrap();
        let second_resolved = fs::canonicalize(&second).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = StateStore::open(&database).unwrap();
        store
            .add_collection("team", &root_link, Some(&first_resolved))
            .unwrap();
        let endpoint = EndpointId::from_bytes([6; 32]);
        let scanner = scanner();
        let attached = store.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        let thread_link = root_link.clone();
        let thread_first = first.clone();
        let thread_second = second.clone();
        let toggler = std::thread::spawn(move || {
            let parent = thread_link.parent().unwrap();
            let mut iteration = 0_u64;
            while thread_running.load(Ordering::Relaxed) {
                let target = if iteration.is_multiple_of(2) {
                    &thread_second
                } else {
                    &thread_first
                };
                let replacement = parent.join(format!(".root-retarget-{iteration}"));
                symlink(target, &replacement).unwrap();
                fs::rename(&replacement, &thread_link).unwrap();
                iteration = iteration.wrapping_add(1);
                std::thread::yield_now();
            }
        });

        let mut committed = 0;
        let mut aborted = 0;
        let mut failure = None;
        for _ in 0..300 {
            let attached = store.collection("team").unwrap().unwrap();
            let records_before = store.record_states("team").unwrap();
            let mut observed = BTreeSet::new();
            match scanner.scan_collection_with_hook(
                &mut store,
                &attached,
                endpoint,
                &mut |path, stage| {
                    if stage == ScanStage::BeforeOpen {
                        observed.insert(path.as_str().to_owned());
                    }
                },
            ) {
                Ok(_) => {
                    committed += 1;
                    let resolved = store
                        .collection("team")
                        .unwrap()
                        .unwrap()
                        .resolved_root
                        .unwrap();
                    let expected = if resolved == first_resolved {
                        BTreeSet::from(["ONLY_A".to_owned()])
                    } else if resolved == second_resolved {
                        BTreeSet::from(["ONLY_B".to_owned()])
                    } else {
                        failure = Some(format!("unexpected resolved root {resolved:?}"));
                        break;
                    };
                    if observed != expected {
                        failure = Some(format!(
                            "resolved root {resolved:?} was paired with {observed:?}"
                        ));
                        break;
                    }
                }
                Err(ScanError::UnstableRoot) => {
                    aborted += 1;
                    assert_eq!(store.collection("team").unwrap(), Some(attached));
                    assert_eq!(store.record_states("team").unwrap(), records_before);
                }
                Err(error) => {
                    failure = Some(format!("unexpected scan error: {error}"));
                    break;
                }
            }
        }
        running.store(false, Ordering::Relaxed);
        toggler.join().unwrap();

        let attached = store.collection("team").unwrap().unwrap();
        let records_before = store.record_states("team").unwrap();
        let logs_before = store.logs().unwrap();
        let resolved_before = fs::canonicalize(&root_link).unwrap();
        let forced_target = if resolved_before == first_resolved {
            &second
        } else {
            &first
        };
        let mut retargeted = false;
        let forced = scanner.scan_collection_with_hooks(
            &mut store,
            &attached,
            endpoint,
            &mut || {
                if !retargeted {
                    let replacement = temporary.path().join(".forced-scan-retarget");
                    symlink(forced_target, &replacement)?;
                    fs::rename(&replacement, &root_link)?;
                    retargeted = true;
                }
                Ok(())
            },
            &mut |_, _| {},
        );
        assert!(matches!(forced, Err(ScanError::UnstableRoot)));
        aborted += 1;
        assert_eq!(store.collection("team").unwrap(), Some(attached));
        assert_eq!(store.record_states("team").unwrap(), records_before);
        assert_eq!(store.logs().unwrap(), logs_before);

        assert!(failure.is_none(), "{}", failure.unwrap_or_default());
        assert!(committed > 0);
        assert!(aborted > 0);

        fs::write(second.join("ONLY_A"), "a").unwrap();
        let pinned = temporary.path().join(".root-pinned");
        symlink(&second, &pinned).unwrap();
        fs::rename(&pinned, &root_link).unwrap();
        drop(store);

        let mut reopened = StateStore::open(&database).unwrap();
        let attached = reopened.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut reopened, &attached, endpoint)
            .unwrap();
        let attached = reopened.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut reopened, &attached, endpoint)
            .unwrap();
        assert!(
            reopened
                .records("team")
                .unwrap()
                .iter()
                .all(|record| matches!(record.kind(), RecordKind::File { .. }))
        );
        assert_eq!(reopened.local_counts().unwrap(), (2, 0));
    }

    #[test]
    fn descriptor_relative_scan_cannot_follow_a_swapped_ancestor_outside() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(root.join("parent")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("parent/SKILL.md"), "inside").unwrap();
        fs::write(outside.join("SKILL.md"), "outside secret").unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection("team", &root, None).unwrap();
        let attached = store.collection("team").unwrap().unwrap();
        let mut swapped = false;
        scanner()
            .scan_collection_with_hook(
                &mut store,
                &attached,
                EndpointId::from_bytes([7; 32]),
                &mut |path, stage| {
                    if !swapped
                        && path.as_str() == "parent/SKILL.md"
                        && stage == ScanStage::BeforeOpen
                    {
                        fs::rename(root.join("parent"), root.join("held")).unwrap();
                        symlink(&outside, root.join("parent")).unwrap();
                        swapped = true;
                    }
                },
            )
            .unwrap();
        let record = store.record("team", "parent/SKILL.md").unwrap().unwrap();
        assert_eq!(
            record.kind(),
            RecordKind::File {
                size: 6,
                content_hash: *blake3::hash(b"inside").as_bytes()
            }
        );
    }

    #[test]
    fn changing_file_is_excluded_without_changing_the_winner() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("SKILL.md");
        fs::write(&file, "stable").unwrap();
        let mut store = StateStore::open_in_memory().unwrap();
        store.add_collection("team", &root, None).unwrap();
        let endpoint = EndpointId::from_bytes([8; 32]);
        let scanner = scanner();
        let attached = store.collection("team").unwrap().unwrap();
        scanner
            .scan_collection(&mut store, &attached, endpoint)
            .unwrap();
        let winner = store.record("team", "SKILL.md").unwrap().unwrap();
        let mut writes = 0;
        scanner
            .scan_collection_with_hook(&mut store, &attached, endpoint, &mut |path, stage| {
                if path.as_str() == "SKILL.md" && stage == ScanStage::AfterMetadata {
                    writes += 1;
                    fs::write(&file, vec![b'x'; 10 + writes]).unwrap();
                }
            })
            .unwrap();
        assert_eq!(writes, 3);
        assert_eq!(store.record("team", "SKILL.md").unwrap(), Some(winner));
    }

    #[test]
    fn durable_installed_fingerprint_survives_expiry_and_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut store = StateStore::open(&database).unwrap();
        store
            .add_collection("team", &root, Some(&fs::canonicalize(&root).unwrap()))
            .unwrap();
        let bytes = b"remote";
        let record = Record::file(
            "team",
            ProtocolPath::parse("SKILL.md").unwrap(),
            1_700_000_000_123_456_789,
            EndpointId::from_bytes([9; 32]),
            u64::try_from(bytes.len()).unwrap(),
            *blake3::hash(bytes).as_bytes(),
        )
        .unwrap();
        store
            .merge_record(&record, now_ns(), Some(record.author()), 100)
            .unwrap();
        crate::installer::apply_file_fixture(
            &mut store,
            &root,
            &record,
            &mut Cursor::new(bytes),
            100,
        )
        .unwrap();
        filetime::set_file_mtime(
            root.join("SKILL.md"),
            filetime::FileTime::from_unix_time(record.modified_ns().div_euclid(1_000_000_000), 0),
        )
        .unwrap();
        let metadata = fs::metadata(root.join("SKILL.md")).unwrap();
        let rounded_fingerprint = {
            use std::os::unix::fs::MetadataExt as _;

            FileFingerprint {
                modified_ns: metadata
                    .mtime()
                    .saturating_mul(1_000_000_000)
                    .saturating_add(metadata.mtime_nsec()),
                size: metadata.len(),
                hash: *blake3::hash(bytes).as_bytes(),
            }
        };
        assert_ne!(rounded_fingerprint.modified_ns, record.modified_ns());
        store
            .set_materialized_fingerprint("team", "SKILL.md", rounded_fingerprint)
            .unwrap();
        let expired_scanner = scanner();
        let attached = store.collection("team").unwrap().unwrap();
        expired_scanner
            .scan_collection(&mut store, &attached, EndpointId::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(
            store.record("team", "SKILL.md").unwrap(),
            Some(record.clone())
        );
        drop(store);

        let mut reopened = StateStore::open(&database).unwrap();
        let attached = reopened.collection("team").unwrap().unwrap();
        scanner()
            .scan_collection(&mut reopened, &attached, EndpointId::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(
            reopened.record("team", "SKILL.md").unwrap(),
            Some(record.clone())
        );

        fs::write(root.join("SKILL.md"), "user edit").unwrap();
        filetime::set_file_mtime(
            root.join("SKILL.md"),
            filetime::FileTime::from_unix_time(1_700_000_002, 0),
        )
        .unwrap();
        scanner()
            .scan_collection(&mut reopened, &attached, EndpointId::from_bytes([1; 32]))
            .unwrap();
        assert_ne!(reopened.record("team", "SKILL.md").unwrap(), Some(record));
    }
}
