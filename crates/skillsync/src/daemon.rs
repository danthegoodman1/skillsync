use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::{Config as NotifyConfig, PollWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::config::{Config, PlatformPaths};
use crate::filesystem::{ScanError, Scanner};
use crate::identity::EndpointId;
use crate::setup::{DEFAULT_COLLECTIONS, load_identity, now_ns, setup};
use crate::state::{
    CollectionScanStatus, CollectionWatchStatus, OperationalEvent, OperationalLog,
    OperationalLogPage, StateError, StateStore,
};

const SOCKET_FILE: &str = "control.sock";
const REQUEST_LIMIT: usize = 64 * 1024;
const RESPONSE_LIMIT: usize = 512 * 1024;
const LOG_PAGE_LIMIT: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Collections,
    AddCollection {
        name: String,
        path: PathBuf,
    },
    RemoveCollection {
        name: String,
    },
    Logs {
        #[serde(default)]
        after_id: i64,
        #[serde(default = "default_log_limit")]
        limit: usize,
    },
    Scan,
    Shutdown,
}

const fn default_log_limit() -> usize {
    LOG_PAGE_LIMIT
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ControlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

impl ControlResponse {
    fn success(result: Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(ControlError {
                code: code.to_owned(),
                message: message.into(),
            }),
        }
    }
}

pub fn socket_path(paths: &PlatformPaths) -> PathBuf {
    paths.runtime_dir.join(SOCKET_FILE)
}

pub fn send_request(
    paths: &PlatformPaths,
    request: &ControlRequest,
) -> Result<ControlResponse, DaemonError> {
    let mut stream = UnixStream::connect(socket_path(paths))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = serde_json::to_vec(request)?;
    if request.len() > REQUEST_LIMIT {
        return Err(DaemonError::FrameTooLarge);
    }
    stream.write_all(&request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let response = read_frame(&mut BufReader::new(stream), RESPONSE_LIMIT)?;
    Ok(serde_json::from_slice(&response)?)
}

pub fn is_running(paths: &PlatformPaths) -> bool {
    send_request(paths, &ControlRequest::Status)
        .map(|response| response.ok)
        .unwrap_or(false)
}

pub fn run(paths: PlatformPaths, config: Config) -> Result<(), DaemonError> {
    setup(&paths, &config)?;
    let identity = load_identity(&paths)?;
    let endpoint_id = identity.endpoint_id();
    let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3"))?;
    let scanner = Scanner::new(
        &config.sync.ignore,
        config.sync.max_future_clock_skew,
        config.logging.max_entries,
    )?;

    fs::create_dir_all(&paths.runtime_dir)?;
    let socket = socket_path(&paths);
    if socket.exists() {
        if UnixStream::connect(&socket).is_ok() {
            return Err(DaemonError::AlreadyRunning);
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    state.append_log(
        now_ns(),
        &OperationalEvent::DaemonStarted,
        config.logging.max_entries,
    )?;
    scan_all(&scanner, &mut state, endpoint_id)?;

    let watch_inbox = WatchInbox::default();
    let mut watchers = build_watchers(&mut state, watch_inbox.clone(), config.logging.max_entries)?;
    let mut pending = BTreeSet::new();
    let mut next_full_scan = Instant::now() + config.sync.interval;
    let mut running = true;

    while running {
        drain_watch_events(
            &watch_inbox,
            &mut pending,
            &mut state,
            config.logging.max_entries,
        )?;
        for name in std::mem::take(&mut pending) {
            if let Some(collection) = state.collection(&name)? {
                scan_collection_safely(&scanner, &mut state, &collection, endpoint_id)?;
            }
        }

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let request = read_request(&stream);
                    let (response, action) = match request {
                        Ok(request) => {
                            handle_request(request, &config, &scanner, &mut state, endpoint_id)
                        }
                        Err(error) => (
                            ControlResponse::failure("invalid_request", error.to_string()),
                            DaemonAction::None,
                        ),
                    };
                    let _ = write_response(stream, &response);
                    match action {
                        DaemonAction::None => {}
                        DaemonAction::RebuildWatchers => {
                            watchers = build_watchers(
                                &mut state,
                                watch_inbox.clone(),
                                config.logging.max_entries,
                            )?;
                        }
                        DaemonAction::Stop => running = false,
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }

        if Instant::now() >= next_full_scan {
            scan_all(&scanner, &mut state, endpoint_id)?;
            watchers = build_watchers(&mut state, watch_inbox.clone(), config.logging.max_entries)?;
            next_full_scan = Instant::now() + config.sync.interval;
        }

        let _keep_watchers_alive = &watchers;
        std::thread::sleep(Duration::from_millis(25));
    }

    state.append_log(
        now_ns(),
        &OperationalEvent::DaemonStopped,
        config.logging.max_entries,
    )?;
    drop(listener);
    let _ = fs::remove_file(socket);
    Ok(())
}

fn read_request(stream: &UnixStream) -> Result<ControlRequest, DaemonError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let frame = read_frame(&mut BufReader::new(stream), REQUEST_LIMIT)?;
    Ok(serde_json::from_slice(&frame)?)
}

fn write_response(mut stream: UnixStream, response: &ControlResponse) -> Result<(), DaemonError> {
    let mut encoded = serde_json::to_vec(response)?;
    if encoded.len() > RESPONSE_LIMIT {
        encoded = serde_json::to_vec(&ControlResponse::failure(
            "response_too_large",
            "daemon response exceeds the control limit",
        ))?;
    }
    if encoded.len() > RESPONSE_LIMIT {
        return Err(DaemonError::FrameTooLarge);
    }
    stream.write_all(&encoded)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_frame(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, DaemonError> {
    let mut frame = Vec::new();
    reader
        .take(u64::try_from(limit + 2).map_err(|_| DaemonError::FrameTooLarge)?)
        .read_until(b'\n', &mut frame)?;
    if frame.last() != Some(&b'\n') {
        return if frame.len() >= limit {
            Err(DaemonError::FrameTooLarge)
        } else {
            Err(DaemonError::MissingNewline)
        };
    }
    frame.pop();
    if frame.len() > limit {
        return Err(DaemonError::FrameTooLarge);
    }
    Ok(frame)
}

enum DaemonAction {
    None,
    RebuildWatchers,
    Stop,
}

fn handle_request(
    request: ControlRequest,
    config: &Config,
    scanner: &Scanner,
    state: &mut StateStore,
    endpoint_id: EndpointId,
) -> (ControlResponse, DaemonAction) {
    let result = match request {
        ControlRequest::Status => status_value(state, &config.device.name, endpoint_id)
            .map(|value| (value, DaemonAction::None)),
        ControlRequest::Collections => {
            collections_value(state).map(|value| (value, DaemonAction::None))
        }
        ControlRequest::AddCollection { name, path } => {
            attach_collection(state, config, &name, &path).and_then(|_| {
                let collection = state
                    .collection(&name)?
                    .ok_or(DaemonError::Protocol("attached collection is missing"))?;
                scan_collection_safely(scanner, state, &collection, endpoint_id)?;
                Ok((
                    json!({ "name": name, "path": path, "attached": true }),
                    DaemonAction::RebuildWatchers,
                ))
            })
        }
        ControlRequest::RemoveCollection { name } => {
            detach_collection(state, config, &name).map(|removed| {
                (
                    json!({ "name": name, "removed": removed }),
                    DaemonAction::RebuildWatchers,
                )
            })
        }
        ControlRequest::Logs { after_id, limit } => {
            logs_page_value(state, after_id, limit).map(|value| (value, DaemonAction::None))
        }
        ControlRequest::Scan => scan_all(scanner, state, endpoint_id)
            .and_then(|_| status_value(state, &config.device.name, endpoint_id))
            .map(|value| (value, DaemonAction::RebuildWatchers)),
        ControlRequest::Shutdown => Ok((json!({ "stopped": true }), DaemonAction::Stop)),
    };
    match result {
        Ok(value) => (ControlResponse::success(value.0), value.1),
        Err(error) => (
            ControlResponse::failure("daemon_operation_failed", error.to_string()),
            DaemonAction::None,
        ),
    }
}

fn scan_all(
    scanner: &Scanner,
    state: &mut StateStore,
    endpoint_id: EndpointId,
) -> Result<(), DaemonError> {
    for collection in state.collections()? {
        scan_collection_safely(scanner, state, &collection, endpoint_id)?;
    }
    Ok(())
}

fn scan_collection_safely(
    scanner: &Scanner,
    state: &mut StateStore,
    collection: &crate::state::CollectionState,
    endpoint_id: EndpointId,
) -> Result<(), DaemonError> {
    if scanner
        .scan_collection(state, collection, endpoint_id)
        .is_err()
    {
        state.set_collection_scan_status(&collection.name, CollectionScanStatus::Error)?;
        state.append_log(
            now_ns(),
            &OperationalEvent::CollectionPaused {
                collection: collection.name.clone(),
            },
            scanner.max_logs(),
        )?;
    }
    Ok(())
}

fn build_watchers(
    state: &mut StateStore,
    inbox: WatchInbox,
    max_logs: usize,
) -> Result<Vec<PollWatcher>, DaemonError> {
    let mut watchers = Vec::new();
    for collection in state.collections()? {
        let Ok(root) = fs::canonicalize(&collection.local_path) else {
            state.set_collection_watch_status(
                &collection.name,
                CollectionWatchStatus::RootUnavailable,
            )?;
            state.append_log(
                now_ns(),
                &OperationalEvent::CollectionPaused {
                    collection: collection.name,
                },
                max_logs,
            )?;
            continue;
        };
        let name = collection.name.clone();
        let callback_inbox = inbox.clone();
        let watcher = PollWatcher::new(
            move |event: notify::Result<notify::Event>| {
                callback_inbox.push(&name, event);
            },
            NotifyConfig::default().with_poll_interval(Duration::from_millis(500)),
        );
        let Ok(mut watcher) = watcher else {
            state.set_collection_watch_status(
                &collection.name,
                CollectionWatchStatus::BackendError,
            )?;
            state.append_log(
                now_ns(),
                &OperationalEvent::CollectionPaused {
                    collection: collection.name,
                },
                max_logs,
            )?;
            continue;
        };
        if watcher.watch(&root, RecursiveMode::Recursive).is_err() {
            state.set_collection_watch_status(
                &collection.name,
                CollectionWatchStatus::BackendError,
            )?;
            state.append_log(
                now_ns(),
                &OperationalEvent::CollectionPaused {
                    collection: collection.name,
                },
                max_logs,
            )?;
        } else {
            state.set_collection_watch_status(&collection.name, CollectionWatchStatus::Active)?;
            watchers.push(watcher);
        }
    }
    Ok(watchers)
}

#[derive(Clone, Default)]
struct WatchInbox {
    pending: Arc<Mutex<WatchPending>>,
}

#[derive(Default)]
struct WatchPending {
    changed: BTreeSet<String>,
    errors: BTreeSet<String>,
}

impl WatchInbox {
    fn push(&self, name: &str, event: notify::Result<notify::Event>) {
        let mut pending = self.pending.lock().expect("watch inbox lock poisoned");
        if event.is_ok() {
            pending.changed.insert(name.to_owned());
        } else {
            pending.errors.insert(name.to_owned());
        }
    }

    fn take(&self) -> WatchPending {
        std::mem::take(&mut *self.pending.lock().expect("watch inbox lock poisoned"))
    }
}

fn drain_watch_events(
    inbox: &WatchInbox,
    pending: &mut BTreeSet<String>,
    state: &mut StateStore,
    max_logs: usize,
) -> Result<(), DaemonError> {
    let events = inbox.take();
    pending.extend(events.changed);
    for name in events.errors {
        state.set_collection_watch_status(&name, CollectionWatchStatus::BackendError)?;
        state.append_log(
            now_ns(),
            &OperationalEvent::CollectionPaused { collection: name },
            max_logs,
        )?;
    }
    Ok(())
}

pub fn attach_collection(
    state: &mut StateStore,
    config: &Config,
    name: &str,
    path: &Path,
) -> Result<(), DaemonError> {
    validate_collection_name(name)?;
    fs::create_dir_all(path)?;
    let existing = state.collection(name)?;
    let changed = existing
        .as_ref()
        .is_none_or(|existing| existing.local_path != path);
    match existing {
        None => state.add_collection(name, path, None)?,
        Some(existing) if existing.local_path != path => {
            state.replace_collection_path(name, path)?
        }
        Some(_) => {}
    }
    if changed {
        state.append_log(
            now_ns(),
            &OperationalEvent::CollectionAttached {
                collection: name.to_owned(),
            },
            config.logging.max_entries,
        )?;
    }
    Ok(())
}

pub fn detach_collection(
    state: &mut StateStore,
    config: &Config,
    name: &str,
) -> Result<bool, DaemonError> {
    if DEFAULT_COLLECTIONS
        .iter()
        .any(|(default, _)| *default == name)
    {
        return Err(DaemonError::DefaultCollection);
    }
    let removed = state.remove_collection(name)?;
    if removed {
        state.append_log(
            now_ns(),
            &OperationalEvent::CollectionDetached {
                collection: name.to_owned(),
            },
            config.logging.max_entries,
        )?;
    }
    Ok(removed)
}

fn validate_collection_name(name: &str) -> Result<(), DaemonError> {
    if name.is_empty() || name.len() > 255 {
        return Err(DaemonError::InvalidCollectionName);
    }
    Ok(())
}

pub fn status_value(
    state: &StateStore,
    device_name: &str,
    endpoint_id: EndpointId,
) -> Result<Value, DaemonError> {
    let (files, degraded) = state.local_counts()?;
    Ok(json!({
        "device": { "name": device_name, "endpoint_id": endpoint_id.to_string() },
        "daemon": "running",
        "peers": { "known": 0, "online": 0 },
        "files": { "synchronized": files, "degraded": degraded }
    }))
}

pub fn collections_value(state: &StateStore) -> Result<Value, DaemonError> {
    let collections = state
        .collections()?
        .into_iter()
        .map(|collection| {
            let (state, reason) = match collection.scan_status {
                CollectionScanStatus::Pending => ("pending", "scan_pending"),
                CollectionScanStatus::Missing => ("paused", "root_missing"),
                CollectionScanStatus::NotDirectory => ("paused", "root_not_directory"),
                CollectionScanStatus::Error => ("paused", "scan_error"),
                CollectionScanStatus::Active => match collection.watch_status {
                    CollectionWatchStatus::Pending => ("active", "watch_pending"),
                    CollectionWatchStatus::Active => ("active", "none"),
                    CollectionWatchStatus::RootUnavailable => {
                        ("degraded", "watch_root_unavailable")
                    }
                    CollectionWatchStatus::BackendError => ("degraded", "watch_backend_error"),
                },
            };
            json!({
                "name": collection.name,
                "path": collection.local_path,
                "state": state,
                "reason": reason
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "collections": collections }))
}

pub fn logs_page_value(
    state: &StateStore,
    after_id: i64,
    limit: usize,
) -> Result<Value, DaemonError> {
    let page = state.logs_page(after_id, limit.min(LOG_PAGE_LIMIT))?;
    Ok(log_page_value(&page))
}

fn log_page_value(page: &OperationalLogPage) -> Value {
    json!({
        "logs": page.logs.iter().map(log_value).collect::<Vec<_>>(),
        "next_after_id": page.next_after_id,
        "has_more": page.has_more
    })
}

fn log_value(log: &OperationalLog) -> Value {
    let mut value = json!({
        "id": log.id,
        "created_ns": log.created_ns,
        "level": format!("{:?}", log.event.level()).to_lowercase(),
        "event": event_name(&log.event)
    });
    let object = value.as_object_mut().expect("log JSON is an object");
    match &log.event {
        OperationalEvent::CollectionAttached { collection }
        | OperationalEvent::CollectionDetached { collection }
        | OperationalEvent::CollectionPaused { collection }
        | OperationalEvent::CollectionScanned { collection } => {
            object.insert("collection".to_owned(), json!(collection));
        }
        OperationalEvent::CollectionWarning {
            collection, path, ..
        } => {
            object.insert("collection".to_owned(), json!(collection));
            if let Some(path) = path {
                object.insert("path".to_owned(), json!(path.as_str()));
            }
        }
        OperationalEvent::RecordAccepted {
            collection, path, ..
        }
        | OperationalEvent::FileInstalled { collection, path }
        | OperationalEvent::FileApplyRejected { collection, path }
        | OperationalEvent::RepairRequired { collection, path } => {
            object.insert("collection".to_owned(), json!(collection));
            object.insert("path".to_owned(), json!(path.as_str()));
        }
        OperationalEvent::RecordRejected {
            collection,
            path,
            candidate_modified_ns,
            candidate_author,
            winner_modified_ns,
            winner_author,
            ..
        } => {
            object.insert("collection".to_owned(), json!(collection));
            object.insert("path".to_owned(), json!(path.as_str()));
            object.insert(
                "candidate_modified_ns".to_owned(),
                json!(candidate_modified_ns),
            );
            object.insert(
                "candidate_author".to_owned(),
                json!(candidate_author.to_string()),
            );
            object.insert("winner_modified_ns".to_owned(), json!(winner_modified_ns));
            object.insert("winner_author".to_owned(), json!(winner_author.to_string()));
        }
        OperationalEvent::PeerUnreachable { peer_endpoint } => {
            object.insert("peer_endpoint".to_owned(), json!(peer_endpoint.to_string()));
        }
        OperationalEvent::StateOpened
        | OperationalEvent::DaemonStarted
        | OperationalEvent::DaemonStopped => {}
    }
    value
}

fn event_name(event: &OperationalEvent) -> &'static str {
    match event {
        OperationalEvent::StateOpened => "state_opened",
        OperationalEvent::DaemonStarted => "daemon_started",
        OperationalEvent::DaemonStopped => "daemon_stopped",
        OperationalEvent::CollectionAttached { .. } => "collection_attached",
        OperationalEvent::CollectionDetached { .. } => "collection_detached",
        OperationalEvent::CollectionPaused { .. } => "collection_paused",
        OperationalEvent::CollectionScanned { .. } => "collection_scanned",
        OperationalEvent::CollectionWarning { issue, .. } => match issue {
            crate::state::CollectionIssue::SymlinkEscape => "symlink_escape",
            crate::state::CollectionIssue::SymlinkCycle => "symlink_cycle",
            crate::state::CollectionIssue::PathRejected => "path_rejected",
            crate::state::CollectionIssue::TimestampRejected => "timestamp_rejected",
        },
        OperationalEvent::RecordAccepted { .. } => "record_accepted",
        OperationalEvent::RecordRejected { .. } => "record_rejected",
        OperationalEvent::FileInstalled { .. } => "file_installed",
        OperationalEvent::FileApplyRejected { .. } => "file_apply_rejected",
        OperationalEvent::RepairRequired { .. } => "repair_required",
        OperationalEvent::PeerUnreachable { .. } => "peer_unreachable",
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("daemon control JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon control protocol failed: {0}")]
    Protocol(&'static str),
    #[error("daemon control frame exceeds its limit")]
    FrameTooLarge,
    #[error("daemon control frame is missing its newline terminator")]
    MissingNewline,
    #[error("the daemon is already running")]
    AlreadyRunning,
    #[error("default collections cannot be detached")]
    DefaultCollection,
    #[error("collection name must contain from 1 through 255 bytes")]
    InvalidCollectionName,
    #[error(transparent)]
    Notify(#[from] notify::Error),
    #[error(transparent)]
    Setup(#[from] crate::setup::SetupError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn watcher_callback_coalesces_changes_and_preserves_errors() {
        let inbox = WatchInbox::default();
        let event = || Ok(notify::Event::new(notify::EventKind::Any));
        inbox.push("team", event());
        inbox.push("team", event());
        inbox.push("other", Err(notify::Error::generic("watch failed")));
        let pending = inbox.take();
        assert_eq!(pending.changed, BTreeSet::from(["team".to_owned()]));
        assert_eq!(pending.errors, BTreeSet::from(["other".to_owned()]));
        assert!(inbox.take().changed.is_empty());
    }

    #[test]
    fn control_frames_require_a_bounded_newline_terminated_request() {
        assert_eq!(read_frame(&mut Cursor::new(b"{}\n"), 2).unwrap(), b"{}");
        assert!(matches!(
            read_frame(&mut Cursor::new(b"{}"), 3),
            Err(DaemonError::MissingNewline)
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(vec![b'x'; 8]), 8),
            Err(DaemonError::FrameTooLarge)
        ));
        let mut oversized = vec![b'x'; 9];
        oversized.push(b'\n');
        assert!(matches!(
            read_frame(&mut Cursor::new(oversized), 8),
            Err(DaemonError::FrameTooLarge)
        ));
    }

    #[test]
    fn oversized_response_is_replaced_with_a_bounded_error() {
        let (writer, reader) = UnixStream::pair().unwrap();
        let response = ControlResponse::success(json!({
            "payload": "x".repeat(RESPONSE_LIMIT + 1)
        }));
        write_response(writer, &response).unwrap();
        let encoded = read_frame(&mut BufReader::new(reader), RESPONSE_LIMIT).unwrap();
        let response: ControlResponse = serde_json::from_slice(&encoded).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "response_too_large");
    }
}
