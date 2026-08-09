use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use cap_std::fs::{Dir, OpenOptions};
use filetime::FileTime;
use thiserror::Error;

use crate::record::{Record, RecordKind};
use crate::root::{StableRoot, StableRootError, open_stable_root_with_hook};
use crate::setup::now_ns;
use crate::state::{FileFingerprint, MaterializedFile, OperationalEvent, StateError, StateStore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallStage {
    DuringRootAcquisition,
    BeforeAncestorSync,
    BeforeWrite,
    AfterWrite,
    BeforeMetadata,
    BeforeFileSync,
    BeforeRename,
    AfterRename,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledFile {
    pub path: PathBuf,
    pub resolved_root: PathBuf,
    pub fingerprint: FileFingerprint,
}

pub fn install_file(
    root: &Path,
    record: &Record,
    reader: &mut impl Read,
) -> Result<InstalledFile, InstallError> {
    install_file_with_hook(root, record, reader, |_| Ok(()))
}

pub fn install_file_with_hook(
    root: &Path,
    record: &Record,
    reader: &mut impl Read,
    mut hook: impl FnMut(InstallStage) -> io::Result<()>,
) -> Result<InstalledFile, InstallError> {
    let (declared_size, declared_hash) = match record.kind() {
        RecordKind::File { size, content_hash } => (size, content_hash),
        RecordKind::Tombstone => return Err(InstallError::Tombstone),
    };
    let StableRoot {
        directory: root_dir,
        resolved_path: resolved_root,
    } = match open_stable_root_with_hook(root, &mut || hook(InstallStage::DuringRootAcquisition)) {
        Ok(root) => root,
        Err(StableRootError::Io(error)) => return Err(error.into()),
        Err(StableRootError::Unstable) => return Err(InstallError::UnstableRoot),
    };
    let relative = Path::new(record.path().as_str());
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    ensure_safe_parent(&root_dir, parent_relative, &mut hook)?;
    let file_name = relative
        .file_name()
        .ok_or(InstallError::UnsafeDestination)?;
    reject_concrete_collision(&root_dir, parent_relative, file_name)?;
    let temporary = temporary_name(&root_dir)?;
    let destination = resolved_root.join(relative);

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut temporary_file = root_dir.open_with(&temporary, &options)?.into_std();
        hook(InstallStage::BeforeWrite)?;
        let mut limited = reader.take(declared_size.saturating_add(1));
        let mut hasher = blake3::Hasher::new();
        let mut written = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = limited.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            written = written
                .checked_add(u64::try_from(read).map_err(|_| InstallError::SizeMismatch)?)
                .ok_or(InstallError::SizeMismatch)?;
            if written > declared_size {
                return Err(InstallError::SizeMismatch);
            }
            temporary_file.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
        }
        if written != declared_size {
            return Err(InstallError::SizeMismatch);
        }
        if hasher.finalize().as_bytes() != &declared_hash {
            return Err(InstallError::HashMismatch);
        }
        hook(InstallStage::AfterWrite)?;
        temporary_file.flush()?;
        hook(InstallStage::BeforeMetadata)?;
        set_mtime(&temporary_file, record.modified_ns())?;
        hook(InstallStage::BeforeFileSync)?;
        temporary_file.sync_all()?;
        let metadata = temporary_file.metadata()?;
        let fingerprint = FileFingerprint {
            modified_ns: metadata_time_ns(&metadata),
            size: metadata.len(),
            hash: declared_hash,
        };
        hook(InstallStage::BeforeRename)?;
        ensure_safe_parent(&root_dir, parent_relative, &mut hook)?;
        reject_concrete_collision(&root_dir, parent_relative, file_name)?;
        root_dir.rename(&temporary, &root_dir, relative)?;
        let installed = InstalledFile {
            path: destination.clone(),
            resolved_root: resolved_root.clone(),
            fingerprint,
        };
        if let Err(source) = hook(InstallStage::AfterRename).and_then(|()| {
            let parent = open_relative_dir(&root_dir, parent_relative)?;
            sync_dir(&parent)
        }) {
            return Err(InstallError::PostRenameDurability {
                installed: Box::new(installed),
                source,
            });
        }
        Ok(installed)
    })();

    if !matches!(&result, Err(InstallError::PostRenameDurability { .. })) {
        let _ = root_dir.remove_file(&temporary);
    }
    result
}

pub fn apply_file_fixture(
    state: &mut StateStore,
    root: &Path,
    record: &Record,
    reader: &mut impl Read,
    max_logs: usize,
) -> Result<InstalledFile, InstallError> {
    apply_file_fixture_with_hook(state, root, record, reader, max_logs, |_| Ok(()))
}

pub fn open_verified_file(root: &Path, record: &Record) -> Result<fs::File, InstallError> {
    let (declared_size, declared_hash) = match record.kind() {
        RecordKind::File { size, content_hash } => (size, content_hash),
        RecordKind::Tombstone => return Err(InstallError::Tombstone),
    };
    let StableRoot {
        directory: root_dir,
        ..
    } = match open_stable_root_with_hook(root, &mut || Ok(())) {
        Ok(root) => root,
        Err(StableRootError::Io(error)) => return Err(error.into()),
        Err(StableRootError::Unstable) => return Err(InstallError::UnstableRoot),
    };
    let relative = Path::new(record.path().as_str());
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    if open_existing_safe_parent(&root_dir, parent_relative)?.is_none() {
        return Err(InstallError::UnsafeDestination);
    }
    let mut file = root_dir.open(relative)?.into_std();
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != declared_size {
        return Err(InstallError::SizeMismatch);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hasher.finalize().as_bytes() != &declared_hash {
        return Err(InstallError::HashMismatch);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

pub fn materialize_tombstone(
    state: &mut StateStore,
    root: &Path,
    record: &Record,
    max_logs: usize,
) -> Result<(), InstallError> {
    if !matches!(record.kind(), RecordKind::Tombstone) {
        return Err(InstallError::NotTombstone);
    }
    let StableRoot {
        directory: root_dir,
        ..
    } = match open_stable_root_with_hook(root, &mut || Ok(())) {
        Ok(root) => root,
        Err(StableRootError::Io(error)) => return Err(error.into()),
        Err(StableRootError::Unstable) => return Err(InstallError::UnstableRoot),
    };
    let relative = Path::new(record.path().as_str());
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    if let Some(parent) = open_existing_safe_parent(&root_dir, parent_relative)? {
        let file_name = relative
            .file_name()
            .ok_or(InstallError::UnsafeDestination)?;
        match parent.remove_file(file_name) {
            Ok(()) => {
                sync_dir(&parent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    state.mark_tombstone_materialized_and_log(
        record.collection(),
        record.path().as_str(),
        now_ns(),
        &OperationalEvent::FileInstalled {
            collection: record.collection().to_owned(),
            path: record.path().clone(),
        },
        max_logs,
    )?;
    Ok(())
}

fn apply_file_fixture_with_hook(
    state: &mut StateStore,
    root: &Path,
    record: &Record,
    reader: &mut impl Read,
    max_logs: usize,
    hook: impl FnMut(InstallStage) -> io::Result<()>,
) -> Result<InstalledFile, InstallError> {
    match install_file_with_hook(root, record, reader, hook) {
        Ok(installed) => {
            let event = OperationalEvent::FileInstalled {
                collection: record.collection().to_owned(),
                path: record.path().clone(),
            };
            state
                .mark_materialized_and_log(
                    record.collection(),
                    record.path().as_str(),
                    MaterializedFile {
                        resolved_root: &installed.resolved_root,
                        fingerprint: installed.fingerprint,
                    },
                    now_ns(),
                    &event,
                    max_logs,
                )
                .map_err(|source| InstallError::PostRenameState {
                    installed: Box::new(installed.clone()),
                    source,
                })?;
            Ok(installed)
        }
        Err(InstallError::PostRenameDurability { installed, source }) => {
            let installed = *installed;
            let event = OperationalEvent::FileApplyRejected {
                collection: record.collection().to_owned(),
                path: record.path().clone(),
            };
            state
                .mark_materialized_and_log(
                    record.collection(),
                    record.path().as_str(),
                    MaterializedFile {
                        resolved_root: &installed.resolved_root,
                        fingerprint: installed.fingerprint,
                    },
                    now_ns(),
                    &event,
                    max_logs,
                )
                .map_err(|state_source| InstallError::PostRenameState {
                    installed: Box::new(installed.clone()),
                    source: state_source,
                })?;
            Err(InstallError::PostRenameDurability {
                installed: Box::new(installed),
                source,
            })
        }
        Err(error @ InstallError::UnstableRoot) => Err(error),
        Err(error) => {
            state.mark_repair_required_and_log(
                record.collection(),
                record.path().as_str(),
                now_ns(),
                &OperationalEvent::FileApplyRejected {
                    collection: record.collection().to_owned(),
                    path: record.path().clone(),
                },
                max_logs,
            )?;
            Err(error)
        }
    }
}

fn ensure_safe_parent(
    root: &Dir,
    relative: &Path,
    hook: &mut impl FnMut(InstallStage) -> io::Result<()>,
) -> Result<(), InstallError> {
    let mut current = root.try_clone()?;
    let mut logical = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(InstallError::UnsafeDestination);
        };
        logical.push(component);
        if exact_entry_exists(&current, component)? {
            current = root
                .open_dir(&logical)
                .map_err(|_| InstallError::UnsafeDestination)?;
            continue;
        }
        match current.symlink_metadata(component) {
            Ok(_) => return Err(InstallError::LocalNameCollision),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current.create_dir(component)?;
                let created = current.open_dir(component)?;
                hook(InstallStage::BeforeAncestorSync)?;
                sync_dir(&created)?;
                sync_dir(&current)?;
                current = created;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn open_existing_safe_parent(root: &Dir, relative: &Path) -> Result<Option<Dir>, InstallError> {
    let mut current = root.try_clone()?;
    let mut logical = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(InstallError::UnsafeDestination);
        };
        logical.push(component);
        if !exact_entry_exists(&current, component)? {
            return Ok(None);
        }
        current = root
            .open_dir(&logical)
            .map_err(|_| InstallError::UnsafeDestination)?;
    }
    Ok(Some(current))
}

fn sync_dir(directory: &Dir) -> io::Result<()> {
    // A cap-std traversal descriptor may be O_PATH on Linux and cannot be
    // fsynced. Opening `.` relative to it preserves the directory identity
    // while obtaining a read descriptor that supports fsync.
    directory.open(".")?.sync_all()
}

fn temporary_name(root: &Dir) -> Result<PathBuf, InstallError> {
    for _ in 0..16 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| InstallError::Random)?;
        let name = format!(
            ".skillsync-tmp-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        );
        let path = PathBuf::from(name);
        match root.symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(InstallError::TemporaryName)
}

fn reject_concrete_collision(
    root: &Dir,
    parent_relative: &Path,
    file_name: &OsStr,
) -> Result<(), InstallError> {
    let parent = open_relative_dir(root, parent_relative)?;
    if exact_entry_exists(&parent, file_name)? {
        return Ok(());
    }
    match parent.symlink_metadata(file_name) {
        Ok(_) => Err(InstallError::LocalNameCollision),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn open_relative_dir(root: &Dir, relative: &Path) -> io::Result<Dir> {
    if relative.as_os_str().is_empty() {
        root.try_clone()
    } else {
        root.open_dir(relative)
    }
}

fn exact_entry_exists(parent: &Dir, name: &OsStr) -> Result<bool, InstallError> {
    for entry in parent.entries()? {
        if entry?.file_name() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set_mtime(file: &fs::File, modified_ns: i64) -> Result<(), InstallError> {
    let seconds = modified_ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(modified_ns.rem_euclid(1_000_000_000))
        .map_err(|_| InstallError::Timestamp)?;
    filetime::set_file_handle_times(file, None, Some(FileTime::from_unix_time(seconds, nanos)))?;
    Ok(())
}

fn metadata_time_ns(metadata: &fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata
        .mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(metadata.mtime_nsec())
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("file installation I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("a tombstone has no file bytes to install")]
    Tombstone,
    #[error("a file record cannot be materialized as a tombstone")]
    NotTombstone,
    #[error("destination escapes the collection root")]
    UnsafeDestination,
    #[error("destination name collides on the collection filesystem")]
    LocalNameCollision,
    #[error("collection root resolution changed during installation")]
    UnstableRoot,
    #[error("received file size does not match its record")]
    SizeMismatch,
    #[error("received file hash does not match its record")]
    HashMismatch,
    #[error("secure random generation failed")]
    Random,
    #[error("could not allocate a temporary file name")]
    TemporaryName,
    #[error("file timestamp cannot be represented")]
    Timestamp,
    #[error("file was installed but destination-directory durability failed: {source}")]
    PostRenameDurability {
        installed: Box<InstalledFile>,
        #[source]
        source: io::Error,
    },
    #[error("file was installed but local state finalization failed: {source}")]
    PostRenameState {
        installed: Box<InstalledFile>,
        #[source]
        source: StateError,
    },
    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::config::Config;
    use crate::filesystem::Scanner;
    use crate::identity::EndpointId;

    fn record(bytes: &[u8], modified_ns: i64) -> Record {
        record_at("review/SKILL.md", bytes, modified_ns)
    }

    fn record_at(path: &str, bytes: &[u8], modified_ns: i64) -> Record {
        Record::file(
            ".agents",
            crate::path::ProtocolPath::parse(path).unwrap(),
            modified_ns,
            EndpointId::from_bytes([3; 32]),
            u64::try_from(bytes.len()).unwrap(),
            *blake3::hash(bytes).as_bytes(),
        )
        .unwrap()
    }

    fn root_snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, i64)> {
        fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, (Vec<u8>, i64)>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    visit(root, &entry.path(), result);
                } else if file_type.is_file() {
                    let metadata = entry.metadata().unwrap();
                    result.insert(
                        entry.path().strip_prefix(root).unwrap().to_path_buf(),
                        (fs::read(entry.path()).unwrap(), metadata_time_ns(&metadata)),
                    );
                }
            }
        }

        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }

    fn retarget_link(link: &Path, target: &Path, suffix: &str) -> io::Result<()> {
        let replacement = link.parent().unwrap().join(format!(".retarget-{suffix}"));
        symlink(target, &replacement)?;
        fs::rename(replacement, link)
    }

    fn assert_missing_bound_root_never_tombstones(
        database: &Path,
        candidate: &Record,
        scanner_author: EndpointId,
    ) {
        let config = Config::default();
        let scanner = Scanner::new(
            &config.sync.ignore,
            config.sync.max_future_clock_skew,
            config.logging.max_entries,
        )
        .unwrap();
        let mut state = StateStore::open(database).unwrap();
        for _ in 0..2 {
            let attached = state.collection(".agents").unwrap().unwrap();
            let summary = scanner
                .scan_collection(&mut state, &attached, scanner_author)
                .unwrap();
            assert_eq!(summary.tombstones, 0);
            assert_eq!(
                state.record(".agents", "SKILL.md").unwrap(),
                Some(candidate.clone())
            );
        }
        let records = state.record_states(".agents").unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].materialized);
        assert_eq!(state.local_counts().unwrap(), (0, 1));
        drop(state);

        let mut restarted = StateStore::open(database).unwrap();
        let attached = restarted.collection(".agents").unwrap().unwrap();
        let summary = scanner
            .scan_collection(&mut restarted, &attached, scanner_author)
            .unwrap();
        assert_eq!(summary.tombstones, 0);
        assert_eq!(
            restarted.record(".agents", "SKILL.md").unwrap(),
            Some(candidate.clone())
        );
        let records = restarted.record_states(".agents").unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].materialized);
        assert_eq!(restarted.local_counts().unwrap(), (0, 1));
    }

    #[test]
    fn validates_size_and_hash_without_replacing_the_old_file() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::create_dir_all(root.join("review")).unwrap();
        let destination = root.join("review/SKILL.md");
        fs::write(&destination, "old").unwrap();

        let expected = record(b"new", 1_700_000_000_123_456_789);
        assert!(matches!(
            install_file(root, &expected, &mut Cursor::new(b"no")),
            Err(InstallError::SizeMismatch)
        ));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "old");
        assert!(matches!(
            install_file(root, &expected, &mut Cursor::new(b"bad")),
            Err(InstallError::HashMismatch)
        ));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "old");
        assert!(fs::read_dir(root.join("review")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".skillsync-tmp-")
        }));
    }

    #[test]
    fn tombstone_materialization_does_not_create_missing_parents_or_follow_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("skills");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("SKILL.md"), b"outside").unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state.add_collection(".agents", &root, Some(&root)).unwrap();

        let missing = Record::tombstone(
            ".agents",
            crate::path::ProtocolPath::parse("missing/SKILL.md").unwrap(),
            10,
            EndpointId::from_bytes([9; 32]),
        )
        .unwrap();
        state
            .merge_record(&missing, 10, Some(EndpointId::from_bytes([9; 32])), 100)
            .unwrap();
        materialize_tombstone(&mut state, &root, &missing, 100).unwrap();
        assert!(!root.join("missing").exists());
        let missing_state = state.record_states(".agents").unwrap().remove(0);
        assert!(missing_state.materialized);

        symlink(&outside, root.join("linked")).unwrap();
        let linked = Record::tombstone(
            ".agents",
            crate::path::ProtocolPath::parse("linked/SKILL.md").unwrap(),
            20,
            EndpointId::from_bytes([9; 32]),
        )
        .unwrap();
        state
            .merge_record(&linked, 20, Some(EndpointId::from_bytes([9; 32])), 100)
            .unwrap();
        assert!(matches!(
            materialize_tombstone(&mut state, &root, &linked, 100),
            Err(InstallError::UnsafeDestination)
        ));
        assert_eq!(fs::read(outside.join("SKILL.md")).unwrap(), b"outside");
        let linked_state = state
            .record_states(".agents")
            .unwrap()
            .into_iter()
            .find(|item| item.record == linked)
            .unwrap();
        assert!(!linked_state.materialized);
    }

    #[test]
    fn every_pre_rename_fault_keeps_the_previous_file_visible() {
        for stage in [
            InstallStage::BeforeWrite,
            InstallStage::AfterWrite,
            InstallStage::BeforeMetadata,
            InstallStage::BeforeFileSync,
            InstallStage::BeforeRename,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            fs::create_dir_all(temporary.path().join("review")).unwrap();
            let destination = temporary.path().join("review/SKILL.md");
            fs::write(&destination, "old").unwrap();
            let candidate = record(b"replacement", 1_700_000_000_000_000_000);
            let result = install_file_with_hook(
                temporary.path(),
                &candidate,
                &mut Cursor::new(b"replacement"),
                |current| {
                    if current == stage {
                        Err(io::Error::other("injected fault"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(fs::read_to_string(destination).unwrap(), "old");
        }
    }

    #[test]
    fn ancestor_directory_sync_failure_happens_before_file_installation() {
        let temporary = tempfile::tempdir().unwrap();
        let candidate = record_at(
            "new/ancestor/SKILL.md",
            b"replacement",
            1_700_000_000_000_000_000,
        );
        let result = install_file_with_hook(
            temporary.path(),
            &candidate,
            &mut Cursor::new(b"replacement"),
            |stage| {
                if stage == InstallStage::BeforeAncestorSync {
                    Err(io::Error::other("injected ancestor sync fault"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(InstallError::Io(_))));
        assert!(!temporary.path().join("new/ancestor/SKILL.md").exists());
    }

    #[test]
    fn directory_durability_uses_an_fsync_capable_relative_handle() {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority()).unwrap();

        sync_dir(&directory).unwrap();
    }

    #[test]
    fn post_rename_failure_reports_that_the_new_file_is_installed() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("review")).unwrap();
        let destination = temporary.path().join("review/SKILL.md");
        fs::write(&destination, "old").unwrap();
        let candidate = record(b"replacement", 1_700_000_000_000_000_000);
        let result = install_file_with_hook(
            temporary.path(),
            &candidate,
            &mut Cursor::new(b"replacement"),
            |stage| {
                if stage == InstallStage::AfterRename {
                    Err(io::Error::other("injected directory sync fault"))
                } else {
                    Ok(())
                }
            },
        );
        let Err(InstallError::PostRenameDurability { installed, .. }) = result else {
            panic!("expected a post-rename durability error")
        };
        assert_eq!(
            installed.path,
            fs::canonicalize(destination.parent().unwrap())
                .unwrap()
                .join("SKILL.md")
        );
        assert_eq!(fs::read_to_string(destination).unwrap(), "replacement");
    }

    #[test]
    fn post_rename_state_failure_reports_that_the_new_file_is_installed() {
        let temporary = tempfile::tempdir().unwrap();
        let mut state = StateStore::open_in_memory().unwrap();
        state
            .add_collection(".agents", temporary.path(), None)
            .unwrap();
        let candidate = record(b"replacement", 1_700_000_000_000_000_000);
        state
            .merge_record(&candidate, 10, Some(candidate.author()), 100)
            .unwrap();
        state.reject_future_log_inserts().unwrap();
        let result = apply_file_fixture(
            &mut state,
            temporary.path(),
            &candidate,
            &mut Cursor::new(b"replacement"),
            100,
        );
        let Err(InstallError::PostRenameState { installed, .. }) = result else {
            panic!("expected an explicit post-rename state error")
        };
        assert_eq!(fs::read(&installed.path).unwrap(), b"replacement");
        assert!(!state.record_states(".agents").unwrap()[0].materialized);
        assert_eq!(
            state.collection(".agents").unwrap().unwrap().resolved_root,
            None
        );
    }

    #[test]
    fn ancestor_swap_before_rename_cannot_write_outside_the_collection() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(root.join("review")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("review/SKILL.md"), "old").unwrap();
        let candidate = record(b"replacement", 1_700_000_000_000_000_000);
        let result = install_file_with_hook(
            &root,
            &candidate,
            &mut Cursor::new(b"replacement"),
            |stage| {
                if stage == InstallStage::BeforeRename {
                    fs::rename(root.join("review"), root.join("held"))?;
                    symlink(&outside, root.join("review"))?;
                }
                Ok(())
            },
        );
        assert!(matches!(result, Err(InstallError::UnsafeDestination)));
        assert!(!outside.join("SKILL.md").exists());
        assert_eq!(
            fs::read_to_string(root.join("held/SKILL.md")).unwrap(),
            "old"
        );
    }

    #[test]
    fn atomic_root_retarget_never_misreports_or_partially_starts_an_install() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        let root_link = temporary.path().join("root-link");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("SKILL.md"), "old first").unwrap();
        fs::write(second.join("SKILL.md"), "old second").unwrap();
        symlink(&first, &root_link).unwrap();
        let first_resolved = fs::canonicalize(&first).unwrap();
        let second_resolved = fs::canonicalize(&second).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state
            .add_collection(".agents", &root_link, Some(&first_resolved))
            .unwrap();
        let bytes = b"replacement";
        let candidate = record_at("SKILL.md", bytes, 1_700_000_000_000_000_000);
        state
            .merge_record(&candidate, 10, Some(candidate.author()), 100)
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
                let replacement = parent.join(format!(".install-retarget-{iteration}"));
                symlink(target, &replacement).unwrap();
                fs::rename(&replacement, &thread_link).unwrap();
                iteration = iteration.wrapping_add(1);
                std::thread::yield_now();
            }
        });

        let mut installed = 0;
        let mut aborted = 0;
        let mut failure = None;
        for _ in 0..300 {
            let first_before = root_snapshot(&first);
            let second_before = root_snapshot(&second);
            let collection_before = state.collection(".agents").unwrap();
            let records_before = state.record_states(".agents").unwrap();
            let logs_before = state.logs().unwrap();
            match apply_file_fixture(
                &mut state,
                &root_link,
                &candidate,
                &mut Cursor::new(bytes),
                100,
            ) {
                Ok(result) => {
                    installed += 1;
                    if result.path != first_resolved.join("SKILL.md")
                        && result.path != second_resolved.join("SKILL.md")
                    {
                        failure = Some(format!(
                            "install reported an unknown root: {:?}",
                            result.path
                        ));
                        break;
                    }
                    if fs::read(&result.path).unwrap() != bytes {
                        failure = Some(format!(
                            "install reported a path without its bytes: {:?}",
                            result.path
                        ));
                        break;
                    }
                }
                Err(InstallError::UnstableRoot) => {
                    aborted += 1;
                    assert_eq!(root_snapshot(&first), first_before);
                    assert_eq!(root_snapshot(&second), second_before);
                    assert_eq!(state.collection(".agents").unwrap(), collection_before);
                    assert_eq!(state.record_states(".agents").unwrap(), records_before);
                    assert_eq!(state.logs().unwrap(), logs_before);
                }
                Err(error) => {
                    failure = Some(format!("unexpected install error: {error}"));
                    break;
                }
            }
        }
        running.store(false, Ordering::Relaxed);
        toggler.join().unwrap();

        let first_before = root_snapshot(&first);
        let second_before = root_snapshot(&second);
        let collection_before = state.collection(".agents").unwrap();
        let records_before = state.record_states(".agents").unwrap();
        let logs_before = state.logs().unwrap();
        let resolved_before = fs::canonicalize(&root_link).unwrap();
        let forced_target = if resolved_before == first_resolved {
            &second
        } else {
            &first
        };
        let mut retargeted = false;
        let forced = apply_file_fixture_with_hook(
            &mut state,
            &root_link,
            &candidate,
            &mut Cursor::new(bytes),
            100,
            |stage| {
                if stage == InstallStage::DuringRootAcquisition && !retargeted {
                    let replacement = temporary.path().join(".forced-install-retarget");
                    symlink(forced_target, &replacement)?;
                    fs::rename(&replacement, &root_link)?;
                    retargeted = true;
                }
                Ok(())
            },
        );
        assert!(matches!(forced, Err(InstallError::UnstableRoot)));
        aborted += 1;
        assert_eq!(root_snapshot(&first), first_before);
        assert_eq!(root_snapshot(&second), second_before);
        assert_eq!(state.collection(".agents").unwrap(), collection_before);
        assert_eq!(state.record_states(".agents").unwrap(), records_before);
        assert_eq!(state.logs().unwrap(), logs_before);

        assert!(failure.is_none(), "{}", failure.unwrap_or_default());
        assert!(installed > 0);
        assert!(aborted > 0);

        let pinned = temporary.path().join(".install-pinned");
        symlink(&second, &pinned).unwrap();
        fs::rename(&pinned, &root_link).unwrap();
        apply_file_fixture(
            &mut state,
            &root_link,
            &candidate,
            &mut Cursor::new(bytes),
            100,
        )
        .unwrap();
        assert_eq!(fs::read(second.join("SKILL.md")).unwrap(), bytes);
        drop(state);

        let config = Config::default();
        let scanner = Scanner::new(
            &config.sync.ignore,
            config.sync.max_future_clock_skew,
            config.logging.max_entries,
        )
        .unwrap();
        let mut reopened = StateStore::open(&database).unwrap();
        let attached = reopened.collection(".agents").unwrap().unwrap();
        scanner
            .scan_collection(&mut reopened, &attached, EndpointId::from_bytes([7; 32]))
            .unwrap();
        drop(reopened);
        let mut restarted = StateStore::open(&database).unwrap();
        let attached = restarted.collection(".agents").unwrap().unwrap();
        scanner
            .scan_collection(&mut restarted, &attached, EndpointId::from_bytes([7; 32]))
            .unwrap();
        assert_eq!(
            restarted.record(".agents", "SKILL.md").unwrap(),
            Some(candidate)
        );
        let records = restarted.record_states(".agents").unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].materialized);
        assert_eq!(restarted.local_counts().unwrap(), (1, 0));
    }

    #[test]
    fn post_acquisition_retarget_binds_materialization_to_the_acquired_root() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        let root_link = temporary.path().join("root-link");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        symlink(&first, &root_link).unwrap();
        let first_resolved = fs::canonicalize(&first).unwrap();
        let second_resolved = fs::canonicalize(&second).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state
            .add_collection(".agents", &root_link, Some(&second_resolved))
            .unwrap();
        let bytes = b"bound to first";
        let candidate = record_at("SKILL.md", bytes, 1_700_000_000_000_000_000);
        state
            .merge_record(&candidate, 10, Some(candidate.author()), 100)
            .unwrap();

        let installed = apply_file_fixture_with_hook(
            &mut state,
            &root_link,
            &candidate,
            &mut Cursor::new(bytes),
            100,
            |stage| {
                if stage == InstallStage::BeforeWrite {
                    retarget_link(&root_link, &second, "exact")?;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(installed.resolved_root, first_resolved);
        assert_eq!(installed.path, first_resolved.join("SKILL.md"));
        assert_eq!(fs::read(first.join("SKILL.md")).unwrap(), bytes);
        assert!(!second.join("SKILL.md").exists());
        assert_eq!(fs::canonicalize(&root_link).unwrap(), second_resolved);
        let attached = state.collection(".agents").unwrap().unwrap();
        assert_eq!(attached.resolved_root, Some(first_resolved));
        assert!(state.record_states(".agents").unwrap()[0].materialized);
        drop(state);

        assert_missing_bound_root_never_tombstones(
            &database,
            &candidate,
            EndpointId::from_bytes([8; 32]),
        );
    }

    #[test]
    fn post_acquisition_aba_retarget_keeps_the_acquired_root_binding() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        let root_link = temporary.path().join("root-link");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        symlink(&first, &root_link).unwrap();
        let first_resolved = fs::canonicalize(&first).unwrap();
        let second_resolved = fs::canonicalize(&second).unwrap();
        let database = temporary.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state
            .add_collection(".agents", &root_link, Some(&second_resolved))
            .unwrap();
        let bytes = b"aba bound to first";
        let candidate = record_at("SKILL.md", bytes, 1_700_000_000_000_000_000);
        state
            .merge_record(&candidate, 10, Some(candidate.author()), 100)
            .unwrap();

        let installed = apply_file_fixture_with_hook(
            &mut state,
            &root_link,
            &candidate,
            &mut Cursor::new(bytes),
            100,
            |stage| {
                match stage {
                    InstallStage::BeforeWrite => retarget_link(&root_link, &second, "aba-b")?,
                    InstallStage::AfterWrite => retarget_link(&root_link, &first, "aba-a")?,
                    InstallStage::AfterRename => retarget_link(&root_link, &second, "aba-final-b")?,
                    _ => {}
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(installed.resolved_root, first_resolved);
        assert_eq!(installed.path, first_resolved.join("SKILL.md"));
        assert_eq!(fs::read(first.join("SKILL.md")).unwrap(), bytes);
        assert!(!second.join("SKILL.md").exists());
        assert_eq!(fs::canonicalize(&root_link).unwrap(), second_resolved);
        assert_eq!(
            state.collection(".agents").unwrap().unwrap().resolved_root,
            Some(first_resolved)
        );
        assert!(state.record_states(".agents").unwrap()[0].materialized);
        drop(state);

        assert_missing_bound_root_never_tombstones(
            &database,
            &candidate,
            EndpointId::from_bytes([9; 32]),
        );
    }

    #[test]
    fn concrete_case_and_unicode_collisions_follow_the_destination_filesystem() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();

        fs::write(root.join("case-name"), "old case").unwrap();
        let case_distinct = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("CASE-NAME"))
        {
            Ok(file) => {
                drop(file);
                fs::remove_file(root.join("CASE-NAME")).unwrap();
                true
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => panic!("case probe failed: {error}"),
        };
        let case_record = record_at("CASE-NAME", b"new case", 10);
        let case_result = install_file(root, &case_record, &mut Cursor::new(b"new case"));
        assert_eq!(
            matches!(case_result, Err(InstallError::LocalNameCollision)),
            !case_distinct
        );
        if !case_distinct {
            assert_eq!(
                fs::read_to_string(root.join("case-name")).unwrap(),
                "old case"
            );
        }

        fs::write(root.join("cafe\u{301}"), "old unicode").unwrap();
        let unicode_distinct = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("caf\u{e9}"))
        {
            Ok(file) => {
                drop(file);
                fs::remove_file(root.join("caf\u{e9}")).unwrap();
                true
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => panic!("Unicode probe failed: {error}"),
        };
        let unicode_record = record_at("caf\u{e9}", b"new unicode", 10);
        let unicode_result = install_file(root, &unicode_record, &mut Cursor::new(b"new unicode"));
        assert_eq!(
            matches!(unicode_result, Err(InstallError::LocalNameCollision)),
            !unicode_distinct
        );
        if !unicode_distinct {
            assert_eq!(
                fs::read_to_string(root.join("cafe\u{301}")).unwrap(),
                "old unicode"
            );
        }
    }

    #[test]
    fn successful_install_is_atomic_and_preserves_mtime() {
        let temporary = tempfile::tempdir().unwrap();
        let modified_ns = 1_700_000_000_123_456_789;
        let candidate = record(b"complete", modified_ns);
        let installed =
            install_file(temporary.path(), &candidate, &mut Cursor::new(b"complete")).unwrap();
        assert_eq!(fs::read(&installed.path).unwrap(), b"complete");
        let actual = fs::metadata(installed.path).unwrap().modified().unwrap();
        let actual_ns = actual
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        assert_eq!(actual_ns, u128::try_from(modified_ns).unwrap());
    }

    #[test]
    fn destination_symlink_cannot_escape_the_collection() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("review")).unwrap();
        let candidate = record(b"secret", 10);
        assert!(matches!(
            install_file(&root, &candidate, &mut Cursor::new(b"secret")),
            Err(InstallError::UnsafeDestination)
        ));
        assert!(!outside.join("SKILL.md").exists());
    }

    #[test]
    fn failed_winner_install_marks_repair_and_logs_rejection() {
        let temporary = tempfile::tempdir().unwrap();
        let mut state = StateStore::open_in_memory().unwrap();
        state
            .add_collection(".agents", temporary.path(), None)
            .unwrap();
        let winner = record(b"expected", 10);
        state.merge_record(&winner, 10, None, 100).unwrap();
        assert!(matches!(
            apply_file_fixture(
                &mut state,
                temporary.path(),
                &winner,
                &mut Cursor::new(b"corrupt!"),
                100,
            ),
            Err(InstallError::HashMismatch)
        ));
        assert_eq!(state.local_counts().unwrap().1, 1);
        assert!(
            state
                .logs()
                .unwrap()
                .iter()
                .any(|log| matches!(log.event, OperationalEvent::FileApplyRejected { .. }))
        );
    }

    #[test]
    fn failed_install_rolls_back_repair_when_its_log_fails() {
        let temporary = tempfile::tempdir().unwrap();
        let mut state = StateStore::open_in_memory().unwrap();
        state
            .add_collection(".agents", temporary.path(), None)
            .unwrap();
        let winner = record(b"expected", 10);
        state.merge_record(&winner, 10, None, 100).unwrap();
        let records_before = state.record_states(".agents").unwrap();
        let logs_before = state.logs().unwrap();
        state.reject_future_log_inserts().unwrap();

        assert!(matches!(
            apply_file_fixture(
                &mut state,
                temporary.path(),
                &winner,
                &mut Cursor::new(b"corrupt!"),
                100,
            ),
            Err(InstallError::State(_))
        ));
        assert_eq!(state.record_states(".agents").unwrap(), records_before);
        assert_eq!(state.logs().unwrap(), logs_before);
    }
}
