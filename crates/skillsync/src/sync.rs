use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::EndpointAddr;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use thiserror::Error;

use crate::config::Config;
use crate::identity::EndpointId;
use crate::installer::{
    InstallError, apply_file_fixture, materialize_tombstone, open_verified_file,
};
use crate::protocol::{
    FileRequest, FrameTag, Hello, IO_IDLE_TIMEOUT, MAX_ENDPOINT_ADDRS, MAX_SESSION_FILE_BYTES,
    MAX_TRANSFERS, ManifestBundle, ProtocolError, ReceiveState, RequestBundle, RosterBundle,
    add_received, decode_file_header, decode_file_unavailable, encode_file_header,
    encode_file_unavailable, read_frame_async, write_frame_async,
};
use crate::record::{Manifest, RecordKind};
use crate::setup::now_ns;
use crate::state::{CollectionIssue, OperationalEvent, StateError, StateStore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionSide {
    Dialer,
    Acceptor,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub database: PathBuf,
    pub data_dir: PathBuf,
    pub local_endpoint: EndpointId,
    pub local_addr: EndpointAddr,
    pub max_future_clock_skew: Duration,
    pub max_logs: usize,
}

impl SessionConfig {
    pub fn from_daemon(
        paths: &crate::config::PlatformPaths,
        config: &Config,
        local_endpoint: EndpointId,
        local_addr: EndpointAddr,
    ) -> Self {
        Self {
            database: paths.data_dir.join("state.sqlite3"),
            data_dir: paths.data_dir.clone(),
            local_endpoint,
            local_addr,
            max_future_clock_skew: config.sync.max_future_clock_skew,
            max_logs: config.logging.max_entries,
        }
    }
}

pub async fn run_session(
    connection: Connection,
    side: ConnectionSide,
    config: SessionConfig,
) -> Result<EndpointId, SyncError> {
    let remote_endpoint = endpoint_from_iroh(connection.remote_id());
    authorize_local_roster(&config.database, config.local_endpoint, remote_endpoint)?;

    let (mut send, mut recv) = match side {
        ConnectionSide::Dialer => tokio::time::timeout(IO_IDLE_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| SyncError::Timeout)?
            .map_err(|_| SyncError::Transport)?,
        ConnectionSide::Acceptor => tokio::time::timeout(IO_IDLE_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| SyncError::Timeout)?
            .map_err(|_| SyncError::Transport)?,
    };
    let mut received_bytes = 0_u64;
    let mut receive_state = ReceiveState::Hello;

    let (local_chain, local_collections) = local_session_state(&config.database)?;
    let local_genesis = local_chain.first().ok_or(SyncError::MissingRoster)?;
    let local_tip = local_chain.last().ok_or(SyncError::MissingRoster)?;
    let local_name = local_tip
        .members()
        .get(&config.local_endpoint)
        .ok_or(SyncError::UnauthorizedPeer)?;
    if config.local_addr.addrs.len() > MAX_ENDPOINT_ADDRS {
        return Err(SyncError::HintAddressLimit);
    }
    let local_addr_json = serde_json::to_string(&config.local_addr)?;
    let hello = Hello {
        group_id: local_genesis.group_id(),
        device_name: local_name.clone(),
        roster_hash: *local_tip.canonical_hash().as_bytes(),
        collections: local_collections.clone(),
        endpoint_addr_json: local_addr_json,
    };
    let hello = hello.encode()?;
    let remote_hello = Hello::decode(
        &exchange_frame(
            &mut send,
            &mut recv,
            &mut receive_state,
            FrameTag::Hello,
            &hello,
            &mut received_bytes,
        )
        .await?,
    )?;
    if remote_hello.group_id != local_genesis.group_id() {
        return Err(SyncError::WrongGroup);
    }
    persist_remote_hint(
        &config.database,
        remote_endpoint,
        &remote_hello.endpoint_addr_json,
    )?;

    let local_roster = RosterBundle {
        revisions: local_chain,
    }
    .encode()?;
    let remote_roster = RosterBundle::decode(
        &exchange_frame(
            &mut send,
            &mut recv,
            &mut receive_state,
            FrameTag::Roster,
            &local_roster,
            &mut received_bytes,
        )
        .await?,
    )?;
    if remote_roster
        .revisions
        .last()
        .is_none_or(|revision| revision.canonical_hash().as_bytes() != &remote_hello.roster_hash)
    {
        return Err(SyncError::RosterDigestMismatch);
    }
    merge_and_authorize_remote_roster(
        &config.database,
        &remote_roster.revisions,
        config.local_endpoint,
        remote_endpoint,
        &remote_hello.device_name,
    )?;

    let remote_collections = remote_hello
        .collections
        .into_iter()
        .collect::<BTreeSet<_>>();
    let shared = local_collections
        .iter()
        .filter(|collection| remote_collections.contains(*collection))
        .cloned()
        .collect::<Vec<_>>();
    let local_manifests = build_manifests(&config.database, &shared)?.encode()?;
    let remote_manifests = ManifestBundle::decode(
        &exchange_frame(
            &mut send,
            &mut recv,
            &mut receive_state,
            FrameTag::Manifests,
            &local_manifests,
            &mut received_bytes,
        )
        .await?,
    )?;
    let requests = merge_remote_manifests(&config, remote_endpoint, &shared, &remote_manifests)?;

    let local_requests = RequestBundle {
        requests: requests.clone(),
    }
    .encode()?;
    let remote_requests = RequestBundle::decode(
        &exchange_frame(
            &mut send,
            &mut recv,
            &mut receive_state,
            FrameTag::Requests,
            &local_requests,
            &mut received_bytes,
        )
        .await?,
    )?;
    receive_state.expect_files(requests.len())?;

    match side {
        ConnectionSide::Dialer => {
            send_files(
                &config,
                remote_endpoint,
                &mut send,
                &shared,
                &remote_requests.requests,
            )
            .await?;
            receive_files(
                &config,
                remote_endpoint,
                &mut recv,
                &mut receive_state,
                &mut received_bytes,
                &requests,
            )
            .await?;
        }
        ConnectionSide::Acceptor => {
            receive_files(
                &config,
                remote_endpoint,
                &mut recv,
                &mut receive_state,
                &mut received_bytes,
                &requests,
            )
            .await?;
            send_files(
                &config,
                remote_endpoint,
                &mut send,
                &shared,
                &remote_requests.requests,
            )
            .await?;
        }
    }

    let done = exchange_frame(
        &mut send,
        &mut recv,
        &mut receive_state,
        FrameTag::Done,
        &[],
        &mut received_bytes,
    )
    .await?;
    if !done.is_empty() || receive_state != ReceiveState::Finished {
        return Err(SyncError::UnexpectedState);
    }
    send.finish().map_err(|_| SyncError::Transport)?;
    let mut trailing = [0_u8; 1];
    match tokio::time::timeout(IO_IDLE_TIMEOUT, recv.read(&mut trailing)).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => return Err(SyncError::UnexpectedState),
        Ok(Err(_)) => return Err(SyncError::Transport),
        Err(_) => return Err(SyncError::Timeout),
    }
    if tokio::time::timeout(IO_IDLE_TIMEOUT, send.stopped())
        .await
        .map_err(|_| SyncError::Timeout)?
        .map_err(|_| SyncError::Transport)?
        .is_some()
    {
        return Err(SyncError::Transport);
    }
    Ok(remote_endpoint)
}

fn authorize_local_roster(
    database: &Path,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
) -> Result<(), SyncError> {
    let state = StateStore::open(database)?;
    let chain = state.selected_roster_chain()?;
    let tip = chain.last().ok_or(SyncError::MissingRoster)?;
    if !tip.members().contains_key(&local_endpoint) || !tip.members().contains_key(&remote_endpoint)
    {
        return Err(SyncError::UnauthorizedPeer);
    }
    Ok(())
}

fn local_session_state(
    database: &Path,
) -> Result<(Vec<crate::roster::RosterRevision>, Vec<String>), SyncError> {
    let state = StateStore::open(database)?;
    let chain = state.selected_roster_chain()?;
    let collections = state
        .collections()?
        .into_iter()
        .map(|collection| collection.name)
        .collect();
    Ok((chain, collections))
}

fn merge_and_authorize_remote_roster(
    database: &Path,
    revisions: &[crate::roster::RosterRevision],
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    remote_name: &str,
) -> Result<(), SyncError> {
    let mut state = StateStore::open(database)?;
    state.merge_selected_roster_chain(revisions)?;
    let selected = state.selected_roster_chain()?;
    let tip = selected.last().ok_or(SyncError::MissingRoster)?;
    if !tip.members().contains_key(&local_endpoint) || !tip.members().contains_key(&remote_endpoint)
    {
        return Err(SyncError::UnauthorizedPeer);
    }
    if tip.members().get(&remote_endpoint).map(String::as_str) != Some(remote_name) {
        return Err(SyncError::DeviceNameMismatch);
    }
    Ok(())
}

fn persist_remote_hint(
    database: &Path,
    remote_endpoint: EndpointId,
    encoded: &str,
) -> Result<(), SyncError> {
    let addr: EndpointAddr = serde_json::from_str(encoded)?;
    if endpoint_from_iroh(addr.id) != remote_endpoint {
        return Err(SyncError::HintIdentityMismatch);
    }
    if addr.addrs.len() > MAX_ENDPOINT_ADDRS {
        return Err(SyncError::HintAddressLimit);
    }
    let mut state = StateStore::open(database)?;
    state.replace_peer_hints(remote_endpoint, &[encoded.to_owned()], now_ns())?;
    Ok(())
}

fn build_manifests(database: &Path, shared: &[String]) -> Result<ManifestBundle, SyncError> {
    let state = StateStore::open(database)?;
    let manifests = shared
        .iter()
        .map(|collection| {
            Ok((
                collection.clone(),
                Manifest::new(state.records(collection)?)?,
            ))
        })
        .collect::<Result<Vec<_>, SyncError>>()?;
    Ok(ManifestBundle { manifests })
}

fn merge_remote_manifests(
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    shared: &[String],
    bundle: &ManifestBundle,
) -> Result<Vec<FileRequest>, SyncError> {
    let shared = shared.iter().cloned().collect::<BTreeSet<_>>();
    let bundle_names = bundle
        .manifests
        .iter()
        .map(|(collection, _)| collection.clone())
        .collect::<BTreeSet<_>>();
    if bundle_names != shared {
        return Err(SyncError::WrongCollections);
    }
    let future_limit = now_ns().saturating_add(duration_ns(config.max_future_clock_skew));
    let mut state = StateStore::open(&config.database)?;
    for (collection, manifest) in &bundle.manifests {
        let local_collection = state
            .collection(collection)?
            .ok_or(SyncError::WrongCollections)?;
        for candidate in manifest.records() {
            if candidate.modified_ns() > future_limit {
                state.append_log(
                    now_ns(),
                    &OperationalEvent::CollectionWarning {
                        collection: collection.clone(),
                        path: Some(candidate.path().clone()),
                        issue: CollectionIssue::TimestampRejected,
                    },
                    config.max_logs,
                )?;
                continue;
            }
            let current = state.record(collection, candidate.path().as_str())?;
            if current.as_ref() != Some(candidate) {
                state.merge_record(candidate, now_ns(), Some(remote_endpoint), config.max_logs)?;
            }
            let winner = state.record(collection, candidate.path().as_str())?;
            if winner.as_ref() == Some(candidate)
                && matches!(candidate.kind(), RecordKind::Tombstone)
            {
                let needs_repair = state
                    .record_state(collection, candidate.path().as_str())?
                    .is_some_and(|item| item.needs_repair);
                if needs_repair
                    && let Err(_error) = materialize_tombstone(
                        &mut state,
                        &local_collection.local_path,
                        candidate,
                        config.max_logs,
                    )
                {
                    state.append_log(
                        now_ns(),
                        &OperationalEvent::RepairRequired {
                            collection: collection.clone(),
                            path: candidate.path().clone(),
                        },
                        config.max_logs,
                    )?;
                }
            }
        }
    }

    let mut requests = Vec::new();
    for (collection, manifest) in &bundle.manifests {
        let states = state
            .record_states(collection)?
            .into_iter()
            .map(|item| (item.record.path().clone(), item))
            .collect::<BTreeMap<_, _>>();
        for remote in manifest.records() {
            if remote.modified_ns() > future_limit {
                continue;
            }
            let Some(winner) = states.get(remote.path()) else {
                continue;
            };
            if winner.record == *remote
                && matches!(remote.kind(), RecordKind::File { .. })
                && (!winner.materialized || winner.needs_repair)
            {
                requests.push(FileRequest {
                    collection: collection.clone(),
                    path: remote.path().as_str().to_owned(),
                    record_hash: *remote.canonical_hash().as_bytes(),
                });
            }
        }
    }
    requests.sort();
    requests.dedup();
    let mut selected = Vec::new();
    let mut selected_bytes = 0_u64;
    for request in requests {
        if selected.len() == MAX_TRANSFERS {
            break;
        }
        let Some(record) = state.record(&request.collection, &request.path)? else {
            continue;
        };
        let RecordKind::File { size, .. } = record.kind() else {
            continue;
        };
        let Some(next_bytes) = selected_bytes.checked_add(size) else {
            break;
        };
        if next_bytes > MAX_SESSION_FILE_BYTES {
            break;
        }
        selected_bytes = next_bytes;
        selected.push(request);
    }
    Ok(selected)
}

async fn send_files(
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    send: &mut SendStream,
    shared: &[String],
    requests: &[FileRequest],
) -> Result<(), SyncError> {
    validate_requested_collections(shared, requests)?;
    let mut sent_bytes = 0_u64;
    for request in requests {
        let Some((record, mut file, size)) =
            prepare_requested_file(config, remote_endpoint, request)?
        else {
            write_frame_async(
                send,
                FrameTag::FileUnavailable,
                &encode_file_unavailable(request)?,
            )
            .await?;
            continue;
        };
        let next_sent = sent_bytes.checked_add(size);
        if next_sent.is_none_or(|bytes| bytes > MAX_SESSION_FILE_BYTES) {
            log_unavailable(config, remote_endpoint, request, false)?;
            write_frame_async(
                send,
                FrameTag::FileUnavailable,
                &encode_file_unavailable(request)?,
            )
            .await?;
            continue;
        }
        sent_bytes = next_sent.expect("checked above");
        write_frame_async(send, FrameTag::File, &encode_file_header(&record)?).await?;
        stream_file(send, &mut file, size).await?;
        let mut state = StateStore::open(&config.database)?;
        state.append_log(
            now_ns(),
            &OperationalEvent::FileSent {
                collection: request.collection.clone(),
                path: record.path().clone(),
                peer_endpoint: remote_endpoint,
            },
            config.max_logs,
        )?;
    }
    Ok(())
}

fn validate_requested_collections(
    shared: &[String],
    requests: &[FileRequest],
) -> Result<(), SyncError> {
    if requests
        .iter()
        .any(|request| !shared.contains(&request.collection))
    {
        return Err(SyncError::WrongCollections);
    }
    Ok(())
}

fn prepare_requested_file(
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    request: &FileRequest,
) -> Result<Option<(crate::record::Record, File, u64)>, SyncError> {
    let mut state = StateStore::open(&config.database)?;
    let Some(record) = state.record(&request.collection, &request.path)? else {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    };
    if record.canonical_hash().as_bytes() != &request.record_hash {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    }
    let Some(record_state) = state.record_state(&request.collection, &request.path)? else {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    };
    if !record_state.materialized || record_state.needs_repair {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    }
    let Some(collection) = state.collection(&request.collection)? else {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    };
    let RecordKind::File { size, .. } = record.kind() else {
        log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
        return Ok(None);
    };
    match open_verified_file(&collection.local_path, &record) {
        Ok(file) => Ok(Some((record, file, size))),
        Err(_) => {
            log_unavailable_in(&mut state, config, remote_endpoint, request, true)?;
            Ok(None)
        }
    }
}

fn log_unavailable(
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    request: &FileRequest,
    mark_repair: bool,
) -> Result<(), SyncError> {
    let mut state = StateStore::open(&config.database)?;
    log_unavailable_in(&mut state, config, remote_endpoint, request, mark_repair)
}

fn log_unavailable_in(
    state: &mut StateStore,
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    request: &FileRequest,
    mark_repair: bool,
) -> Result<(), SyncError> {
    let event = OperationalEvent::TransferRejected {
        collection: request.collection.clone(),
        path: crate::path::ProtocolPath::parse(&request.path).map_err(ProtocolError::from)?,
        peer_endpoint: remote_endpoint,
    };
    if mark_repair {
        state.mark_repair_required_and_log(
            &request.collection,
            &request.path,
            now_ns(),
            &event,
            config.max_logs,
        )?;
    } else {
        state.append_log(now_ns(), &event, config.max_logs)?;
    }
    Ok(())
}

async fn stream_file(send: &mut SendStream, file: &mut File, size: u64) -> Result<(), SyncError> {
    let mut remaining = size;
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| SyncError::FileSize)?;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(SyncError::InterruptedFile);
        }
        tokio::time::timeout(IO_IDLE_TIMEOUT, send.write_all(&buffer[..read]))
            .await
            .map_err(|_| SyncError::Timeout)?
            .map_err(|_| SyncError::Transport)?;
        remaining -= u64::try_from(read).map_err(|_| SyncError::FileSize)?;
    }
    Ok(())
}

async fn receive_files(
    config: &SessionConfig,
    remote_endpoint: EndpointId,
    recv: &mut RecvStream,
    state_machine: &mut ReceiveState,
    received_bytes: &mut u64,
    requests: &[FileRequest],
) -> Result<(), SyncError> {
    for request in requests {
        let (tag, header) = read_frame_async(recv, received_bytes).await?;
        if !matches!(tag, FrameTag::File | FrameTag::FileUnavailable) {
            return Err(SyncError::Protocol(ProtocolError::UnexpectedFrame));
        }
        state_machine.accept(tag)?;
        if tag == FrameTag::FileUnavailable {
            if decode_file_unavailable(&header)? != *request {
                return Err(SyncError::UnsolicitedFile);
            }
            log_unavailable(config, remote_endpoint, request, false)?;
            continue;
        }
        let record = decode_file_header(&header)?;
        if record.collection() != request.collection
            || record.path().as_str() != request.path
            || record.canonical_hash().as_bytes() != &request.record_hash
        {
            return Err(SyncError::UnsolicitedFile);
        }
        let RecordKind::File { size, content_hash } = record.kind() else {
            return Err(SyncError::UnsolicitedFile);
        };
        add_received(received_bytes, size)?;
        let mut staged = tempfile::tempfile_in(&config.data_dir)?;
        let result = receive_raw_file(recv, &mut staged, size, content_hash).await;
        if let Err(error) = result {
            let mut state = StateStore::open(&config.database)?;
            state.append_log(
                now_ns(),
                &OperationalEvent::TransferRejected {
                    collection: request.collection.clone(),
                    path: record.path().clone(),
                    peer_endpoint: remote_endpoint,
                },
                config.max_logs,
            )?;
            return Err(error);
        }
        staged.seek(SeekFrom::Start(0))?;
        let mut state = StateStore::open(&config.database)?;
        if state.record(&request.collection, &request.path)?.as_ref() != Some(&record) {
            log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
            continue;
        }
        let Some(collection) = state.collection(&request.collection)? else {
            log_unavailable_in(&mut state, config, remote_endpoint, request, false)?;
            continue;
        };
        let apply_result = apply_file_fixture(
            &mut state,
            &collection.local_path,
            &record,
            &mut staged,
            config.max_logs,
        );
        if let Err(error) = apply_result {
            if matches!(
                error,
                InstallError::UnstableRoot | InstallError::PostRenameState { .. }
            ) {
                let _ = state.append_log(
                    now_ns(),
                    &OperationalEvent::FileApplyRejected {
                        collection: request.collection.clone(),
                        path: record.path().clone(),
                    },
                    config.max_logs,
                );
            }
            continue;
        }
        state.append_log(
            now_ns(),
            &OperationalEvent::FileReceived {
                collection: request.collection.clone(),
                path: record.path().clone(),
                peer_endpoint: remote_endpoint,
            },
            config.max_logs,
        )?;
    }
    Ok(())
}

async fn receive_raw_file(
    recv: &mut RecvStream,
    staged: &mut File,
    size: u64,
    expected_hash: [u8; 32],
) -> Result<(), SyncError> {
    let mut remaining = size;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| SyncError::FileSize)?;
        tokio::time::timeout(IO_IDLE_TIMEOUT, recv.read_exact(&mut buffer[..wanted]))
            .await
            .map_err(|_| SyncError::Timeout)?
            .map_err(|_| SyncError::InterruptedFile)?;
        staged.write_all(&buffer[..wanted])?;
        hasher.update(&buffer[..wanted]);
        remaining -= u64::try_from(wanted).map_err(|_| SyncError::FileSize)?;
    }
    if hasher.finalize().as_bytes() != &expected_hash {
        return Err(SyncError::CorruptFile);
    }
    staged.flush()?;
    staged.sync_all()?;
    Ok(())
}

async fn read_expected(
    recv: &mut RecvStream,
    state: &mut ReceiveState,
    expected: FrameTag,
    received_bytes: &mut u64,
) -> Result<Vec<u8>, SyncError> {
    let (tag, payload) = read_frame_async(recv, received_bytes).await?;
    if tag != expected {
        return Err(SyncError::Protocol(ProtocolError::UnexpectedFrame));
    }
    state.accept(tag)?;
    Ok(payload)
}

async fn exchange_frame(
    send: &mut SendStream,
    recv: &mut RecvStream,
    state: &mut ReceiveState,
    tag: FrameTag,
    local_payload: &[u8],
    received_bytes: &mut u64,
) -> Result<Vec<u8>, SyncError> {
    let write = async {
        write_frame_async(send, tag, local_payload)
            .await
            .map_err(SyncError::from)
    };
    let read = read_expected(recv, state, tag, received_bytes);
    let ((), remote_payload) = tokio::try_join!(write, read)?;
    Ok(remote_payload)
}

pub fn endpoint_from_iroh(endpoint: iroh::EndpointId) -> EndpointId {
    EndpointId::from_bytes(*endpoint.as_bytes())
}

pub fn endpoint_to_iroh(endpoint: EndpointId) -> Result<iroh::EndpointId, SyncError> {
    iroh::EndpointId::from_bytes(endpoint.as_bytes()).map_err(|_| SyncError::InvalidEndpoint)
}

fn duration_ns(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("peer synchronization made no progress before the idle timeout")]
    Timeout,
    #[error("peer transport failed")]
    Transport,
    #[error("local roster is missing")]
    MissingRoster,
    #[error("peer is not an active roster member")]
    UnauthorizedPeer,
    #[error("peer belongs to a different group")]
    WrongGroup,
    #[error("peer roster digest does not match the exchanged roster")]
    RosterDigestMismatch,
    #[error("peer device name does not match the selected roster")]
    DeviceNameMismatch,
    #[error("peer advertised unexpected collections")]
    WrongCollections,
    #[error("peer address hint names a different EndpointID")]
    HintIdentityMismatch,
    #[error("peer address hint contains too many addresses")]
    HintAddressLimit,
    #[error("peer sent an unsolicited file")]
    UnsolicitedFile,
    #[error("peer file transfer was interrupted")]
    InterruptedFile,
    #[error("peer file transfer failed hash validation")]
    CorruptFile,
    #[error("file size cannot be represented")]
    FileSize,
    #[error("peer protocol ended in an unexpected state")]
    UnexpectedState,
    #[error("EndpointID is not a valid iroh public key")]
    InvalidEndpoint,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Record(#[from] crate::record::RecordError),
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl SyncError {
    pub(crate) fn is_connectivity_failure(&self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::Transport
                | Self::InterruptedFile
                | Self::Protocol(
                    ProtocolError::Timeout | ProtocolError::Transport | ProtocolError::Truncated
                )
        )
    }

    pub(crate) fn is_local_failure(&self) -> bool {
        matches!(
            self,
            Self::State(_) | Self::Io(_) | Self::Install(_) | Self::Protocol(ProtocolError::Io(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::identity::GroupId;
    use crate::path::ProtocolPath;
    use crate::record::Record;
    use crate::roster::{RosterChange, RosterMember, RosterRevision};

    #[test]
    fn iroh_endpoint_id_round_trips_without_a_claimed_frame_identity() {
        let identity = DeviceIdentity::from_secret([7; 32]);
        let iroh = endpoint_to_iroh(identity.endpoint_id()).unwrap();
        assert_eq!(endpoint_from_iroh(iroh), identity.endpoint_id());
    }

    #[test]
    fn file_requests_are_limited_to_negotiated_collections() {
        let request = FileRequest {
            collection: ".codex".to_owned(),
            path: "review/SKILL.md".to_owned(),
            record_hash: [3; 32],
        };
        assert!(matches!(
            validate_requested_collections(&[".agents".to_owned()], &[request]),
            Err(SyncError::WrongCollections)
        ));
        assert!(SyncError::Timeout.is_connectivity_failure());
        assert!(SyncError::Protocol(ProtocolError::Transport).is_connectivity_failure());
        assert!(!SyncError::WrongGroup.is_connectivity_failure());
        assert!(SyncError::Io(std::io::Error::other("local")).is_local_failure());
        assert!(!SyncError::WrongGroup.is_local_failure());
    }

    #[test]
    fn roster_merge_requires_common_genesis_and_active_members() {
        let local = DeviceIdentity::from_secret([1; 32]);
        let remote = DeviceIdentity::from_secret([2; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([4; 32]), "local", &local).unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(remote.endpoint_id(), "remote").unwrap()),
            &local,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        drop(state);
        merge_and_authorize_remote_roster(
            &database,
            &[genesis, child],
            local.endpoint_id(),
            remote.endpoint_id(),
            "remote",
        )
        .unwrap();
    }

    #[test]
    fn request_generation_uses_only_the_exact_remote_winner() {
        let remote = DeviceIdentity::from_secret([90; 32]).endpoint_id();
        let local = DeviceIdentity::from_secret([91; 32]).endpoint_id();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skills");
        std::fs::create_dir(&root).unwrap();
        let database = temp.path().join("state.sqlite3");
        let state = StateStore::open(&database).unwrap();
        state.add_collection(".agents", &root, Some(&root)).unwrap();
        let record = Record::file(
            ".agents",
            ProtocolPath::parse("x/SKILL.md").unwrap(),
            5,
            remote,
            3,
            *blake3::hash(b"new").as_bytes(),
        )
        .unwrap();
        let bundle = ManifestBundle {
            manifests: vec![(
                ".agents".to_owned(),
                Manifest::new(vec![record.clone()]).unwrap(),
            )],
        };
        drop(state);
        let config = SessionConfig {
            database,
            data_dir: temp.path().to_path_buf(),
            local_endpoint: local,
            local_addr: EndpointAddr::new(endpoint_to_iroh(local).unwrap()),
            max_future_clock_skew: Duration::from_secs(60),
            max_logs: 100,
        };
        let requests =
            merge_remote_manifests(&config, remote, &[".agents".to_owned()], &bundle).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].record_hash, *record.canonical_hash().as_bytes());
    }

    #[test]
    fn losing_remote_candidate_never_replaces_or_requests_the_winner() {
        let local = DeviceIdentity::from_secret([81; 32]).endpoint_id();
        let remote = DeviceIdentity::from_secret([82; 32]).endpoint_id();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skills");
        std::fs::create_dir(&root).unwrap();
        let database = temp.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state.add_collection(".agents", &root, Some(&root)).unwrap();
        let winner = Record::file(
            ".agents",
            ProtocolPath::parse("x/SKILL.md").unwrap(),
            20,
            local,
            3,
            *blake3::hash(b"new").as_bytes(),
        )
        .unwrap();
        state.merge_record(&winner, now_ns(), None, 100).unwrap();
        let loser = Record::file(
            ".agents",
            ProtocolPath::parse("x/SKILL.md").unwrap(),
            10,
            remote,
            3,
            *blake3::hash(b"old").as_bytes(),
        )
        .unwrap();
        drop(state);
        let config = SessionConfig {
            database: database.clone(),
            data_dir: temp.path().to_path_buf(),
            local_endpoint: local,
            local_addr: EndpointAddr::new(endpoint_to_iroh(local).unwrap()),
            max_future_clock_skew: Duration::from_secs(60),
            max_logs: 100,
        };
        let requests = merge_remote_manifests(
            &config,
            remote,
            &[".agents".to_owned()],
            &ManifestBundle {
                manifests: vec![(".agents".to_owned(), Manifest::new(vec![loser]).unwrap())],
            },
        )
        .unwrap();
        assert!(requests.is_empty());
        assert_eq!(
            StateStore::open(&database)
                .unwrap()
                .record(".agents", "x/SKILL.md")
                .unwrap(),
            Some(winner)
        );
    }

    #[test]
    fn request_generation_enforces_the_session_byte_budget() {
        let local = DeviceIdentity::from_secret([83; 32]).endpoint_id();
        let remote = DeviceIdentity::from_secret([84; 32]).endpoint_id();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skills");
        std::fs::create_dir(&root).unwrap();
        let database = temp.path().join("state.sqlite3");
        StateStore::open(&database)
            .unwrap()
            .add_collection(".agents", &root, Some(&root))
            .unwrap();
        let records = (0_u8..4)
            .map(|index| {
                Record::file(
                    ".agents",
                    ProtocolPath::parse(&format!("{index}/SKILL.md")).unwrap(),
                    10,
                    remote,
                    crate::protocol::MAX_FILE_BYTES,
                    [index; 32],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let config = SessionConfig {
            database,
            data_dir: temp.path().to_path_buf(),
            local_endpoint: local,
            local_addr: EndpointAddr::new(endpoint_to_iroh(local).unwrap()),
            max_future_clock_skew: Duration::from_secs(60),
            max_logs: 100,
        };
        let requests = merge_remote_manifests(
            &config,
            remote,
            &[".agents".to_owned()],
            &ManifestBundle {
                manifests: vec![(".agents".to_owned(), Manifest::new(records).unwrap())],
            },
        )
        .unwrap();
        assert_eq!(requests.len(), 3);
    }

    #[test]
    fn future_dated_record_does_not_block_a_valid_record_in_the_same_manifest() {
        let local = DeviceIdentity::from_secret([85; 32]).endpoint_id();
        let remote = DeviceIdentity::from_secret([86; 32]).endpoint_id();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skills");
        std::fs::create_dir(&root).unwrap();
        let database = temp.path().join("state.sqlite3");
        StateStore::open(&database)
            .unwrap()
            .add_collection(".agents", &root, Some(&root))
            .unwrap();
        let future = Record::file(
            ".agents",
            ProtocolPath::parse("future/SKILL.md").unwrap(),
            i64::MAX,
            remote,
            1,
            *blake3::hash(b"x").as_bytes(),
        )
        .unwrap();
        let valid = Record::file(
            ".agents",
            ProtocolPath::parse("valid/SKILL.md").unwrap(),
            10,
            remote,
            2,
            *blake3::hash(b"ok").as_bytes(),
        )
        .unwrap();
        let config = SessionConfig {
            database: database.clone(),
            data_dir: temp.path().to_path_buf(),
            local_endpoint: local,
            local_addr: EndpointAddr::new(endpoint_to_iroh(local).unwrap()),
            max_future_clock_skew: Duration::from_secs(60),
            max_logs: 100,
        };
        let requests = merge_remote_manifests(
            &config,
            remote,
            &[".agents".to_owned()],
            &ManifestBundle {
                manifests: vec![(
                    ".agents".to_owned(),
                    Manifest::new(vec![future, valid.clone()]).unwrap(),
                )],
            },
        )
        .unwrap();
        let state = StateStore::open(&database).unwrap();
        assert!(
            state
                .record(".agents", "future/SKILL.md")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.record(".agents", "valid/SKILL.md").unwrap(),
            Some(valid)
        );
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "valid/SKILL.md");
        assert!(state.logs().unwrap().iter().any(|log| matches!(
            log.event,
            OperationalEvent::CollectionWarning {
                issue: CollectionIssue::TimestampRejected,
                ..
            }
        )));
    }

    #[test]
    fn removed_and_unknown_peers_are_rejected_from_authenticated_sessions() {
        let local = DeviceIdentity::from_secret([31; 32]);
        let removed = DeviceIdentity::from_secret([32; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([6; 32]), "local", &local).unwrap();
        let admitted = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(removed.endpoint_id(), "removed").unwrap()),
            &local,
        )
        .unwrap();
        let removal = RosterRevision::child(
            &admitted,
            RosterChange::Remove(removed.endpoint_id()),
            &local,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        state.insert_roster_revision(&admitted).unwrap();
        state.insert_roster_revision(&removal).unwrap();
        drop(state);
        assert!(matches!(
            authorize_local_roster(&database, local.endpoint_id(), removed.endpoint_id()),
            Err(SyncError::UnauthorizedPeer)
        ));
        assert!(matches!(
            authorize_local_roster(
                &database,
                local.endpoint_id(),
                EndpointId::from_bytes([99; 32])
            ),
            Err(SyncError::UnauthorizedPeer)
        ));
    }

    async fn raw_transfer_result(
        bytes: &'static [u8],
        declared_size: u64,
        expected_hash: [u8; 32],
    ) -> Result<(), SyncError> {
        let sender_identity = DeviceIdentity::from_secret([71; 32]);
        let receiver_identity = DeviceIdentity::from_secret([72; 32]);
        let sender = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_address_lookup()
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .secret_key(iroh::SecretKey::from_bytes(&sender_identity.secret_bytes()))
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let receiver = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_address_lookup()
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .secret_key(iroh::SecretKey::from_bytes(
                &receiver_identity.secret_bytes(),
            ))
            .alpns(vec![b"skillsync-raw-test".to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let receiver_task = tokio::spawn({
            let receiver = receiver.clone();
            async move {
                let incoming = receiver.accept().await.unwrap();
                let connection = incoming.accept().unwrap().await.unwrap();
                let (_send, mut recv) = connection.accept_bi().await.unwrap();
                let mut staged = tempfile::tempfile().unwrap();
                receive_raw_file(&mut recv, &mut staged, declared_size, expected_hash).await
            }
        });
        let connection = sender
            .connect(receiver.addr(), b"skillsync-raw-test")
            .await
            .unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(bytes).await.unwrap();
        send.finish().unwrap();
        let result = receiver_task.await.unwrap();
        sender.close().await;
        receiver.close().await;
        result
    }

    #[tokio::test]
    async fn interrupted_and_corrupt_transfers_are_rejected_before_installation() {
        let _guard = crate::network::IROH_TEST_LOCK.lock().await;
        assert!(matches!(
            raw_transfer_result(b"no", 3, *blake3::hash(b"new").as_bytes()).await,
            Err(SyncError::InterruptedFile)
        ));
        assert!(matches!(
            raw_transfer_result(b"bad", 3, *blake3::hash(b"new").as_bytes()).await,
            Err(SyncError::CorruptFile)
        ));
    }
}
