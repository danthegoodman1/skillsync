use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use iroh::address_lookup::{PkarrPublisher, PkarrResolver};
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::Url;

use crate::config::{Config, IrohPreset, PlatformPaths};
use crate::identity::{DeviceIdentity, EndpointId};
use crate::join::{
    JOIN_ALPN, JoinCoordinator, JoinDecision, JoinError, PendingJoinInfo, SecretNonce, run_inviter,
};
use crate::protocol::{MAX_ADDRESS_HINT_BYTES, MAX_ENDPOINT_ADDRS, ProtocolError};
use crate::roster::{RosterChange, RosterMember};
use crate::setup::now_ns;
use crate::state::{OperationalEvent, StateError, StateStore};
use crate::sync::{
    ConnectionSide, SessionConfig, SyncError, endpoint_from_iroh, endpoint_to_iroh,
    run_session_with_outcome,
};

const COMMAND_CAPACITY: usize = 8;
const MAX_CONCURRENT_SESSIONS: usize = 4;
const READY_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
pub(crate) static IROH_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointPlan {
    N0,
    Custom {
        relay_urls: Vec<String>,
        address_lookup_urls: Vec<String>,
    },
}

impl EndpointPlan {
    pub fn from_config(config: &Config) -> Self {
        match config.iroh.preset {
            IrohPreset::N0 => Self::N0,
            IrohPreset::Custom => Self::Custom {
                relay_urls: config.iroh.relay_urls.clone(),
                address_lookup_urls: config.iroh.address_lookup_urls.clone(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncSummary {
    pub attempted: usize,
    pub succeeded: usize,
}

enum NetworkCommand {
    Trigger,
    Sync {
        completed: mpsc::Sender<SyncSummary>,
    },
    Shutdown {
        completed: mpsc::Sender<()>,
    },
}

pub struct NetworkHandle {
    commands: mpsc::SyncSender<NetworkCommand>,
    endpoint_addr: Arc<Mutex<Option<EndpointAddr>>>,
    thread: Option<thread::JoinHandle<()>>,
    joins: Arc<JoinCoordinator>,
    paths: PlatformPaths,
}

impl NetworkHandle {
    pub fn start(
        paths: PlatformPaths,
        config: Config,
        identity: DeviceIdentity,
    ) -> Result<Self, NetworkError> {
        let (commands, receiver) = mpsc::sync_channel(COMMAND_CAPACITY);
        let joins = Arc::new(JoinCoordinator::default());
        let worker_joins = joins.clone();
        let endpoint_addr = Arc::new(Mutex::new(None));
        let shared_addr = endpoint_addr.clone();
        let worker_paths = paths.clone();
        let worker_config = config.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("skillsync-network".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(NetworkError::Runtime(error)));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let endpoint = match bind_endpoint(&worker_config, &identity).await {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    };
                    let local_endpoint = identity.endpoint_id();
                    if endpoint_from_iroh(endpoint.id()) != local_endpoint {
                        let _ = ready_tx.send(Err(NetworkError::IdentityMismatch));
                        endpoint.close().await;
                        return;
                    }
                    *shared_addr.lock().expect("endpoint address lock poisoned") =
                        Some(endpoint.addr());
                    if ready_tx.send(Ok(())).is_err() {
                        endpoint.close().await;
                        return;
                    }
                    run_network_loop(
                        endpoint.clone(),
                        worker_paths,
                        worker_config,
                        local_endpoint,
                        receiver,
                        shared_addr,
                        worker_joins,
                    )
                    .await;
                    endpoint.close().await;
                });
            })?;
        ready_rx
            .recv_timeout(READY_TIMEOUT)
            .map_err(|_| NetworkError::StartupTimeout)??;
        Ok(Self {
            commands,
            endpoint_addr,
            thread: Some(thread),
            joins,
            paths,
        })
    }

    pub fn trigger(&self) {
        let _ = self.commands.try_send(NetworkCommand::Trigger);
    }

    pub fn start_sync(&self) -> Result<mpsc::Receiver<SyncSummary>, NetworkError> {
        let (completed, receiver) = mpsc::channel();
        self.commands
            .try_send(NetworkCommand::Sync { completed })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => NetworkError::Busy,
                mpsc::TrySendError::Disconnected(_) => NetworkError::Stopped,
            })?;
        Ok(receiver)
    }

    pub fn endpoint_addr_json(&self) -> Result<String, NetworkError> {
        let addr = self
            .endpoint_addr
            .lock()
            .expect("endpoint address lock poisoned")
            .clone()
            .ok_or(NetworkError::Stopped)?;
        Ok(serde_json::to_string(&addr)?)
    }

    pub fn activate_invitation(
        &self,
        nonce: SecretNonce,
        lifetime: Duration,
    ) -> Result<(), NetworkError> {
        self.joins.activate(nonce, lifetime)?;
        Ok(())
    }

    pub fn pending_join(&self) -> Result<Option<PendingJoinInfo>, NetworkError> {
        Ok(self.joins.pending()?)
    }

    pub fn decide_join(&self, request_id: &str, approve: bool) -> Result<(), NetworkError> {
        if !approve {
            self.joins.decide(request_id, JoinDecision::rejected())?;
            return Ok(());
        }
        let decision = match self.build_join_approval(request_id) {
            Ok(decision) => decision,
            Err(error) => {
                let _ = self.joins.decide(request_id, JoinDecision::rejected());
                return Err(error);
            }
        };
        self.joins.decide(request_id, decision)?;
        self.trigger();
        Ok(())
    }

    fn build_join_approval(&self, request_id: &str) -> Result<JoinDecision, NetworkError> {
        let (pending, joiner_addr) = self.joins.pending_addr(request_id)?;
        build_join_approval_in(
            &self.paths,
            &self.endpoint_addr_json()?,
            &pending,
            &joiner_addr,
        )
    }

    pub fn remove_peer(&self, peer: EndpointId) -> Result<bool, NetworkError> {
        let identity = crate::setup::load_identity(&self.paths)?;
        if peer == identity.endpoint_id() {
            return Err(NetworkError::CannotRemoveSelf);
        }
        let mut state = StateStore::open(&self.paths.data_dir.join("state.sqlite3"))?;
        let chain = state.selected_roster_chain()?;
        let tip = chain.last().ok_or(NetworkError::MissingRoster)?;
        if !tip.members().contains_key(&peer) {
            return Ok(false);
        }
        state.apply_roster_change(&identity, RosterChange::Remove(peer))?;
        self.trigger();
        Ok(true)
    }

    pub fn shutdown(mut self) -> Result<(), NetworkError> {
        let (completed, receiver) = mpsc::channel();
        let _ = self.commands.send(NetworkCommand::Shutdown { completed });
        let _ = receiver.recv_timeout(Duration::from_secs(5));
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| NetworkError::ThreadPanicked)?;
        }
        Ok(())
    }
}

fn build_join_approval_in(
    paths: &PlatformPaths,
    local_addr_json: &str,
    pending: &PendingJoinInfo,
    joiner_addr: &str,
) -> Result<JoinDecision, NetworkError> {
    let identity = crate::setup::load_identity(paths)?;
    let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3"))?;
    let roster = state.selected_roster_chain()?;
    let tip = roster.last().ok_or(NetworkError::MissingRoster)?;
    let active_name = tip.members().get(&pending.endpoint_id);
    if active_name.is_some_and(|name| name != &pending.device_name) {
        return Err(NetworkError::MemberNameMismatch);
    }
    if active_name.is_none()
        && roster
            .iter()
            .any(|revision| revision.members().contains_key(&pending.endpoint_id))
    {
        return Err(NetworkError::RemovedMember);
    }
    let peer_hints = approval_peer_hints(&state, pending, &identity, local_addr_json)?;
    if active_name.is_none() {
        let change = RosterChange::Admit(RosterMember::new(
            pending.endpoint_id,
            pending.device_name.clone(),
        )?);
        let candidate = crate::roster::RosterRevision::child(tip, change.clone(), &identity)?;
        let mut candidate_roster = roster;
        candidate_roster.push(candidate);
        JoinDecision::approved(candidate_roster, peer_hints.clone())?;
        state.apply_roster_change_with_peer_hint(
            &identity,
            change,
            pending.endpoint_id,
            joiner_addr,
        )?;
    } else {
        state.replace_peer_hint(pending.endpoint_id, joiner_addr)?;
    }
    let roster = state.selected_roster_chain()?;
    if roster
        .last()
        .and_then(|tip| tip.members().get(&pending.endpoint_id))
        != Some(&pending.device_name)
    {
        return Err(NetworkError::MemberNameMismatch);
    }
    let peer_hints = approval_peer_hints(&state, pending, &identity, local_addr_json)?;
    Ok(JoinDecision::approved(roster, peer_hints)?)
}

fn approval_peer_hints(
    state: &StateStore,
    pending: &PendingJoinInfo,
    identity: &DeviceIdentity,
    local_addr_json: &str,
) -> Result<BTreeMap<String, String>, NetworkError> {
    let roster = state.selected_roster_chain()?;
    let tip = roster.last().ok_or(NetworkError::MissingRoster)?;
    let mut peer_hints = BTreeMap::new();
    for endpoint in tip.members().keys().copied() {
        if endpoint == pending.endpoint_id {
            continue;
        }
        let hint = if endpoint == identity.endpoint_id() {
            Some(local_addr_json.to_owned())
        } else {
            state
                .peer_hint(endpoint)?
                .filter(|hint| decode_peer_hint(hint, endpoint).is_some())
        };
        if let Some(hint) = hint {
            peer_hints.insert(endpoint.to_string(), hint);
        }
    }
    Ok(peer_hints)
}

impl Drop for NetworkHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let (completed, _receiver) = mpsc::channel();
            let _ = self
                .commands
                .try_send(NetworkCommand::Shutdown { completed });
        }
    }
}

pub async fn bind_endpoint(
    config: &Config,
    identity: &DeviceIdentity,
) -> Result<Endpoint, NetworkError> {
    configured_builder(config, identity)?
        .bind()
        .await
        .map_err(|error| NetworkError::Bind(error.to_string()))
}

fn configured_builder(
    config: &Config,
    identity: &DeviceIdentity,
) -> Result<iroh::endpoint::Builder, NetworkError> {
    let secret = SecretKey::from_bytes(&identity.secret_bytes());
    let builder = match EndpointPlan::from_config(config) {
        EndpointPlan::N0 => Endpoint::builder(presets::N0),
        EndpointPlan::Custom {
            relay_urls,
            address_lookup_urls,
        } => {
            let relays = relay_urls
                .iter()
                .map(|value| value.parse::<RelayUrl>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| NetworkError::InvalidRelayUrl)?;
            let mut builder = Endpoint::builder(presets::Minimal)
                .clear_address_lookup()
                .relay_mode(RelayMode::custom(relays));
            for value in address_lookup_urls {
                let url = value
                    .parse::<Url>()
                    .map_err(|_| NetworkError::InvalidAddressLookupUrl)?;
                builder = builder
                    .address_lookup(PkarrPublisher::builder(url.clone()))
                    .address_lookup(PkarrResolver::builder(url));
            }
            builder
        }
    };
    Ok(builder
        .secret_key(secret)
        .alpns(vec![crate::protocol::ALPN.to_vec(), JOIN_ALPN.to_vec()]))
}

async fn run_network_loop(
    endpoint: Endpoint,
    paths: PlatformPaths,
    config: Config,
    local_endpoint: EndpointId,
    commands: mpsc::Receiver<NetworkCommand>,
    shared_addr: Arc<Mutex<Option<EndpointAddr>>>,
    joins: Arc<JoinCoordinator>,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));
    let mut tasks = JoinSet::new();
    let mut outgoing = BTreeSet::new();
    let mut waiters = Vec::new();
    let mut pending_trigger = true;
    let mut deferred_trigger = false;
    let mut summary = SyncSummary::default();
    let mut stopping = None;
    let mut interval = tokio::time::interval(Duration::from_millis(25));
    let mut next_periodic = tokio::time::Instant::now() + config.sync.interval;

    loop {
        while let Ok(command) = commands.try_recv() {
            match command {
                NetworkCommand::Trigger => {
                    if waiters.is_empty() {
                        pending_trigger = true;
                    } else {
                        deferred_trigger = true;
                    }
                }
                NetworkCommand::Sync { completed } => {
                    if waiters.is_empty() {
                        summary = SyncSummary {
                            attempted: outgoing.len(),
                            succeeded: 0,
                        };
                        pending_trigger = true;
                    }
                    waiters.push(completed);
                }
                NetworkCommand::Shutdown { completed } => {
                    stopping = Some(completed);
                }
            }
        }
        if stopping.is_some() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            if let Some(completed) = stopping.take() {
                let _ = completed.send(());
            }
            break;
        }
        if tokio::time::Instant::now() >= next_periodic {
            if waiters.is_empty() {
                pending_trigger = true;
            }
            next_periodic = tokio::time::Instant::now() + config.sync.interval;
        }
        if pending_trigger {
            pending_trigger = false;
            if let Ok(peers) = active_peers(&paths, local_endpoint) {
                for peer in peers {
                    if !outgoing.insert(peer) {
                        continue;
                    }
                    if !waiters.is_empty() {
                        summary.attempted = summary.attempted.saturating_add(1);
                    }
                    spawn_outgoing(
                        &mut tasks,
                        endpoint.clone(),
                        paths.clone(),
                        config.clone(),
                        local_endpoint,
                        peer,
                        semaphore.clone(),
                    );
                }
            }
        }
        if outgoing.is_empty() && !waiters.is_empty() {
            for waiter in waiters.drain(..) {
                let _ = waiter.send(summary);
            }
            summary = SyncSummary::default();
            if deferred_trigger {
                pending_trigger = true;
                deferred_trigger = false;
            }
        }
        *shared_addr.lock().expect("endpoint address lock poisoned") = Some(endpoint.addr());

        tokio::select! {
            accepting = endpoint.accept() => {
                if let Some(incoming) = accepting
                    && let Ok(permit) = semaphore.clone().try_acquire_owned()
                    && let Ok(accepting) = incoming.accept()
                {
                        spawn_incoming(
                            &mut tasks,
                            accepting,
                            permit,
                            IncomingContext {
                                local_addr: endpoint.addr(),
                                paths: paths.clone(),
                                config: config.clone(),
                                local_endpoint,
                                joins: joins.clone(),
                            },
                        );
                }
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(result)) = completed {
                    if result.outgoing {
                        outgoing.remove(&result.peer);
                        if result.success && !waiters.is_empty() {
                            summary.succeeded = summary.succeeded.saturating_add(1);
                        }
                    }
                    if result.reconcile_again {
                        pending_trigger = true;
                    }
                    record_result(
                        &paths,
                        &config,
                        result.peer,
                        result.success,
                        result.rejected,
                        result.local_failure,
                    );
                }
            }
            _ = interval.tick() => {}
        }
    }
}

struct TaskResult {
    peer: EndpointId,
    outgoing: bool,
    success: bool,
    rejected: bool,
    local_failure: bool,
    reconcile_again: bool,
}

fn spawn_outgoing(
    tasks: &mut JoinSet<TaskResult>,
    endpoint: Endpoint,
    paths: PlatformPaths,
    config: Config,
    local_endpoint: EndpointId,
    peer: EndpointId,
    semaphore: Arc<Semaphore>,
) {
    tasks.spawn(async move {
        let Ok(_permit) = semaphore.acquire_owned().await else {
            return TaskResult {
                peer,
                outgoing: true,
                success: false,
                rejected: false,
                local_failure: false,
                reconcile_again: false,
            };
        };
        record_attempt(&paths, &config, peer);
        let result = async {
            let target = peer_target(&paths, peer)?;
            let connection = tokio::time::timeout(
                Duration::from_secs(10),
                endpoint.connect(target, crate::protocol::ALPN),
            )
            .await
            .map_err(|_| NetworkError::ConnectTimeout)?
            .map_err(|error| NetworkError::Connect(error.to_string()))?;
            let session =
                SessionConfig::from_daemon(&paths, &config, local_endpoint, endpoint.addr());
            let outcome = run_session_with_outcome(connection, ConnectionSide::Dialer, session)
                .await
                .map_err(NetworkError::Sync)?;
            Ok::<bool, NetworkError>(outcome.roster_changed)
        }
        .await;
        let local_failure = matches!(
            &result,
            Err(NetworkError::Sync(error)) if error.is_local_failure()
        );
        let rejected = matches!(
            &result,
            Err(NetworkError::Sync(error))
                if !error.is_connectivity_failure() && !error.is_local_failure()
        );
        TaskResult {
            peer,
            outgoing: true,
            success: result.is_ok(),
            rejected,
            local_failure,
            reconcile_again: result.as_ref().copied().unwrap_or_else(|error| {
                matches!(
                    error,
                    NetworkError::Sync(SyncError::RosterChangedAndUnauthorizedPeer)
                )
            }),
        }
    });
}

#[derive(Clone)]
struct IncomingContext {
    local_addr: EndpointAddr,
    paths: PlatformPaths,
    config: Config,
    local_endpoint: EndpointId,
    joins: Arc<JoinCoordinator>,
}

fn spawn_incoming(
    tasks: &mut JoinSet<TaskResult>,
    accepting: iroh::endpoint::Accepting,
    permit: tokio::sync::OwnedSemaphorePermit,
    context: IncomingContext,
) {
    tasks.spawn(async move {
        let _permit = permit;
        let connection = tokio::time::timeout(Duration::from_secs(10), accepting).await;
        let (peer, result, reconcile_again) = match connection {
            Ok(Ok(connection)) => {
                let peer = endpoint_from_iroh(connection.remote_id());
                match connection.alpn() {
                    JOIN_ALPN => {
                        let result = run_inviter(connection, context.joins)
                            .await
                            .map(|_| peer)
                            .map_err(|_| SyncError::JoinRejected);
                        (peer, result, false)
                    }
                    crate::protocol::ALPN => {
                        let session = SessionConfig::from_daemon(
                            &context.paths,
                            &context.config,
                            context.local_endpoint,
                            context.local_addr,
                        );
                        let outcome =
                            run_session_with_outcome(connection, ConnectionSide::Acceptor, session)
                                .await;
                        let reconcile_again =
                            outcome.as_ref().is_ok_and(|outcome| outcome.roster_changed)
                                || matches!(
                                    outcome.as_ref(),
                                    Err(SyncError::RosterChangedAndUnauthorizedPeer)
                                );
                        let result = outcome.map(|outcome| outcome.remote_endpoint);
                        (peer, result, reconcile_again)
                    }
                    _ => (
                        peer,
                        Err(SyncError::Protocol(ProtocolError::UnexpectedFrame)),
                        false,
                    ),
                }
            }
            _ => (
                EndpointId::from_bytes([0; 32]),
                Err(SyncError::Transport),
                false,
            ),
        };
        TaskResult {
            peer,
            outgoing: false,
            success: result.is_ok(),
            rejected: result
                .as_ref()
                .is_err_and(|error| !error.is_connectivity_failure() && !error.is_local_failure()),
            local_failure: result.as_ref().is_err_and(SyncError::is_local_failure),
            reconcile_again,
        }
    });
}

fn active_peers(
    paths: &PlatformPaths,
    local_endpoint: EndpointId,
) -> Result<Vec<EndpointId>, NetworkError> {
    let state = StateStore::open(&paths.data_dir.join("state.sqlite3"))?;
    let chain = state.selected_roster_chain()?;
    let tip = chain.last().ok_or(NetworkError::MissingRoster)?;
    Ok(tip
        .members()
        .keys()
        .copied()
        .filter(|peer| *peer != local_endpoint)
        .collect())
}

fn peer_target(paths: &PlatformPaths, peer: EndpointId) -> Result<EndpointAddr, NetworkError> {
    let state = StateStore::open(&paths.data_dir.join("state.sqlite3"))?;
    if let Some(hint) = state.peer_hint(peer)?
        && let Some(addr) = decode_peer_hint(&hint, peer)
    {
        return Ok(addr);
    }
    Ok(EndpointAddr::new(
        endpoint_to_iroh(peer).map_err(NetworkError::Sync)?,
    ))
}

fn decode_peer_hint(encoded: &str, peer: EndpointId) -> Option<EndpointAddr> {
    if encoded.is_empty() || encoded.len() > MAX_ADDRESS_HINT_BYTES {
        return None;
    }
    let addr = serde_json::from_str::<EndpointAddr>(encoded).ok()?;
    if endpoint_from_iroh(addr.id) != peer || addr.addrs.len() > MAX_ENDPOINT_ADDRS {
        return None;
    }
    Some(addr)
}

fn record_attempt(paths: &PlatformPaths, config: &Config, peer: EndpointId) {
    if let Ok(mut state) = StateStore::open(&paths.data_dir.join("state.sqlite3")) {
        let _ = state.append_log(
            now_ns(),
            &OperationalEvent::PeerAttempted {
                peer_endpoint: peer,
            },
            config.logging.max_entries,
        );
    }
}

fn record_result(
    paths: &PlatformPaths,
    config: &Config,
    peer: EndpointId,
    success: bool,
    rejected: bool,
    local_failure: bool,
) {
    if peer == EndpointId::from_bytes([0; 32]) {
        return;
    }
    if let Ok(mut state) = StateStore::open(&paths.data_dir.join("state.sqlite3")) {
        let event = if success {
            OperationalEvent::PeerSynchronized {
                peer_endpoint: peer,
            }
        } else if local_failure {
            OperationalEvent::PeerSessionFailed {
                peer_endpoint: peer,
            }
        } else if rejected {
            OperationalEvent::PeerRejected {
                peer_endpoint: peer,
            }
        } else {
            OperationalEvent::PeerUnreachable {
                peer_endpoint: peer,
            }
        };
        let active = state
            .selected_roster_chain()
            .ok()
            .and_then(|chain| chain.last().cloned())
            .is_some_and(|tip| tip.members().contains_key(&peer));
        if active {
            let _ = state.record_peer_health(
                peer,
                success,
                now_ns(),
                &event,
                config.logging.max_entries,
            );
        } else if rejected {
            let _ = state.append_log(now_ns(), &event, config.logging.max_entries);
        }
    }
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network runtime failed: {0}")]
    Runtime(std::io::Error),
    #[error("network worker failed to start")]
    StartupTimeout,
    #[error("network worker stopped")]
    Stopped,
    #[error("network command queue is full")]
    Busy,
    #[error("network synchronization timed out")]
    SyncTimeout,
    #[error("network worker thread panicked")]
    ThreadPanicked,
    #[error("iroh endpoint identity differs from the persisted identity")]
    IdentityMismatch,
    #[error("custom iroh relay URL is invalid")]
    InvalidRelayUrl,
    #[error("custom iroh address lookup URL is invalid")]
    InvalidAddressLookupUrl,
    #[error("iroh endpoint bind failed: {0}")]
    Bind(String),
    #[error("iroh connection failed: {0}")]
    Connect(String),
    #[error("iroh connection timed out")]
    ConnectTimeout,
    #[error("local roster is missing")]
    MissingRoster,
    #[error("this device cannot remove itself")]
    CannotRemoveSelf,
    #[error("joining EndpointID is active under a different device name")]
    MemberNameMismatch,
    #[error("joining EndpointID was removed from this group")]
    RemovedMember,
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Join(#[from] JoinError),
    #[error(transparent)]
    Roster(#[from] crate::roster::RosterError),
    #[error(transparent)]
    Setup(#[from] crate::setup::SetupError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::path::ProtocolPath;
    use crate::record::{Manifest, Record};
    use crate::roster::{RosterChange, RosterMember, RosterRevision};
    use crate::sync::run_session;

    use super::*;

    struct PkarrFixture {
        url: String,
        records: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl PkarrFixture {
        async fn run() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/pkarr", listener.local_addr().unwrap());
            let records = Arc::new(Mutex::new(BTreeMap::new()));
            let shared = records.clone();
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let records = shared.clone();
                    tokio::spawn(async move {
                        let _ = serve_pkarr_request(stream, records).await;
                    });
                }
            });
            Self { url, records, task }
        }

        async fn wait_for(&self, endpoint: iroh::EndpointId) {
            let path = format!("/pkarr/{}", endpoint.to_z32());
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if self.records.lock().unwrap().contains_key(&path) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }

    impl Drop for PkarrFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_pkarr_request(
        mut stream: tokio::net::TcpStream,
        records: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    ) -> std::io::Result<()> {
        const HEADER_LIMIT: usize = 16 * 1024;
        const BODY_LIMIT: usize = 64 * 1024;
        let mut request = Vec::new();
        let header_end = loop {
            if let Some(index) = request.windows(4).position(|item| item == b"\r\n\r\n") {
                break index + 4;
            }
            if request.len() >= HEADER_LIMIT {
                return Ok(());
            }
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            request.extend_from_slice(&chunk[..read]);
        };
        let (method, path, content_length) = {
            let header = String::from_utf8_lossy(&request[..header_end]);
            let mut lines = header.split("\r\n");
            let mut parts = lines.next().unwrap_or_default().split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let content_length = lines
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            (method, path, content_length)
        };
        if content_length > BODY_LIMIT {
            return Ok(());
        }
        while request.len() < header_end + content_length {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let (status, body) = match method.as_str() {
            "PUT" => {
                records.lock().unwrap().insert(
                    path,
                    request[header_end..header_end + content_length].to_vec(),
                );
                ("204 No Content", Vec::new())
            }
            "GET" => match records.lock().unwrap().get(&path).cloned() {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", Vec::new()),
            },
            _ => ("405 Method Not Allowed", Vec::new()),
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        stream.write_all(&body).await?;
        stream.shutdown().await
    }

    #[test]
    fn endpoint_plan_preserves_n0_and_custom_configuration() {
        assert_eq!(
            EndpointPlan::from_config(&Config::default()),
            EndpointPlan::N0
        );
        let config = Config::from_toml(
            r#"
            [iroh]
            preset = "custom"
            relay_urls = ["https://relay.example.net"]
            address_lookup_urls = ["https://lookup.example.net"]
            "#,
        )
        .unwrap();
        assert_eq!(
            EndpointPlan::from_config(&config),
            EndpointPlan::Custom {
                relay_urls: vec!["https://relay.example.net".to_owned()],
                address_lookup_urls: vec!["https://lookup.example.net".to_owned()],
            }
        );
    }

    #[test]
    fn peer_target_retains_valid_replacements_and_rejects_corrupt_stored_bundles() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        let peer = DeviceIdentity::from_secret([72; 32]).endpoint_id();
        let assert_endpoint_only = || {
            let fallback = peer_target(&paths, peer).unwrap();
            assert_eq!(endpoint_from_iroh(fallback.id), peer);
            assert!(fallback.addrs.is_empty());
        };
        assert_endpoint_only();

        let old = EndpointAddr::new(endpoint_to_iroh(peer).unwrap())
            .with_ip_addr("127.0.0.1:42000".parse().unwrap());
        let old_encoded = serde_json::to_string(&old).unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3"))
            .unwrap()
            .replace_peer_hint(peer, &old_encoded)
            .unwrap();
        let expected = EndpointAddr::new(endpoint_to_iroh(peer).unwrap())
            .with_ip_addr("127.0.0.1:42001".parse().unwrap())
            .with_ip_addr("127.0.0.1:42002".parse().unwrap());
        let encoded = serde_json::to_string(&expected).unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3"))
            .unwrap()
            .replace_peer_hint(peer, &encoded)
            .unwrap();
        let retained = peer_target(&paths, peer).unwrap();
        assert_eq!(retained.id, expected.id);
        assert_eq!(retained.addrs, expected.addrs);

        StateStore::open(&paths.data_dir.join("state.sqlite3"))
            .unwrap()
            .replace_peer_hint(peer, "{")
            .unwrap();
        assert_endpoint_only();
        let wrong_id = serde_json::to_string(&EndpointAddr::new(
            endpoint_to_iroh(DeviceIdentity::from_secret([73; 32]).endpoint_id()).unwrap(),
        ))
        .unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3"))
            .unwrap()
            .replace_peer_hint(peer, &wrong_id)
            .unwrap();
        assert_endpoint_only();
        let mut too_many = EndpointAddr::new(endpoint_to_iroh(peer).unwrap());
        for port in 43_000..43_033 {
            too_many = too_many.with_ip_addr(([127, 0, 0, 1], port).into());
        }
        let too_many = serde_json::to_string(&too_many).unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3"))
            .unwrap()
            .replace_peer_hint(peer, &too_many)
            .unwrap();
        assert_endpoint_only();

        let database = paths.data_dir.join("state.sqlite3");
        let connection = rusqlite::Connection::open(database).unwrap();
        connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        for update in [
            "UPDATE peer_hints SET hint = '' WHERE endpoint_id = ?1",
            "UPDATE peer_hints SET hint = CAST(zeroblob(32) AS BLOB) WHERE endpoint_id = ?1",
            "UPDATE peer_hints SET hint = printf('%*s', 16385, '') WHERE endpoint_id = ?1",
        ] {
            connection.execute(update, [peer.as_bytes()]).unwrap();
            assert_endpoint_only();
        }
    }

    #[test]
    fn failed_delivery_can_resume_the_same_member_and_refresh_its_hint() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        fs::create_dir_all(&paths.data_dir).unwrap();
        let (local, _) = crate::identity::IdentityStore::new(&paths)
            .load_or_create()
            .unwrap();
        let joiner = DeviceIdentity::from_secret([73; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([71; 32]),
            "local",
            &local,
        )
        .unwrap();
        let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        drop(state);
        let local_addr = serde_json::to_string(&EndpointAddr::new(
            endpoint_to_iroh(local.endpoint_id()).unwrap(),
        ))
        .unwrap();
        let pending = PendingJoinInfo {
            request_id: "first".to_owned(),
            endpoint_id: joiner.endpoint_id(),
            device_name: "joiner".to_owned(),
        };
        let first_addr = serde_json::to_string(
            &EndpointAddr::new(endpoint_to_iroh(joiner.endpoint_id()).unwrap())
                .with_ip_addr("127.0.0.1:41001".parse().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            build_join_approval_in(&paths, &"x".repeat(16 * 1024 + 1), &pending, &first_addr),
            Err(NetworkError::Join(JoinError::InvalidAddress))
        ));
        assert_eq!(
            StateStore::open(&paths.data_dir.join("state.sqlite3"))
                .unwrap()
                .selected_roster_chain()
                .unwrap()
                .len(),
            1
        );
        build_join_approval_in(&paths, &local_addr, &pending, &first_addr).unwrap();

        // Dropping the decision models a response or acknowledgement failure after
        // the signed admission has committed.
        let second_addr = serde_json::to_string(
            &EndpointAddr::new(endpoint_to_iroh(joiner.endpoint_id()).unwrap())
                .with_ip_addr("127.0.0.1:41002".parse().unwrap()),
        )
        .unwrap();
        build_join_approval_in(&paths, &local_addr, &pending, &second_addr).unwrap();
        let state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        let chain = state.selected_roster_chain().unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain.last().unwrap().members().get(&joiner.endpoint_id()),
            Some(&"joiner".to_owned())
        );
        assert_eq!(
            state.peer_hint(joiner.endpoint_id()).unwrap(),
            Some(second_addr)
        );
        drop(state);

        let mismatched = PendingJoinInfo {
            request_id: "different-name".to_owned(),
            endpoint_id: joiner.endpoint_id(),
            device_name: "other".to_owned(),
        };
        assert!(matches!(
            build_join_approval_in(&paths, &local_addr, &mismatched, &first_addr),
            Err(NetworkError::MemberNameMismatch)
        ));
        let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        state
            .apply_roster_change(&local, RosterChange::Remove(joiner.endpoint_id()))
            .unwrap();
        drop(state);
        assert!(matches!(
            build_join_approval_in(&paths, &local_addr, &pending, &first_addr),
            Err(NetworkError::RemovedMember)
        ));
    }

    #[test]
    fn joining_skips_an_unusable_non_inviter_bundle() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        let local = DeviceIdentity::from_secret([74; 32]);
        let existing = DeviceIdentity::from_secret([75; 32]);
        let joining = DeviceIdentity::from_secret([76; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([77; 32]),
            "local",
            &local,
        )
        .unwrap();
        let admission = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(existing.endpoint_id(), "existing").unwrap()),
            &local,
        )
        .unwrap();
        let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        state.insert_roster_revision(&admission).unwrap();
        state
            .replace_peer_hint(existing.endpoint_id(), "{")
            .unwrap();
        let local_addr = serde_json::to_string(&EndpointAddr::new(
            endpoint_to_iroh(local.endpoint_id()).unwrap(),
        ))
        .unwrap();
        let hints = approval_peer_hints(
            &state,
            &PendingJoinInfo {
                request_id: "joining".to_owned(),
                endpoint_id: joining.endpoint_id(),
                device_name: "joining".to_owned(),
            },
            &local,
            &local_addr,
        )
        .unwrap();
        assert_eq!(
            hints,
            BTreeMap::from([(local.endpoint_id().to_string(), local_addr)])
        );
    }

    #[test]
    fn unknown_rejections_do_not_grow_peer_health_and_logs_stay_bounded() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        fs::create_dir_all(&paths.data_dir).unwrap();
        let local = DeviceIdentity::from_secret([80; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([81; 32]),
            "local",
            &local,
        )
        .unwrap();
        let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        drop(state);
        let mut config = Config::default();
        config.logging.max_entries = 7;
        for seed in 0_u16..200 {
            let mut bytes = [0_u8; 32];
            bytes[..2].copy_from_slice(&seed.to_be_bytes());
            record_result(
                &paths,
                &config,
                DeviceIdentity::from_secret(bytes).endpoint_id(),
                false,
                true,
                false,
            );
        }
        let state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        assert_eq!(state.peer_health_row_count().unwrap(), 0);
        let logs = state.logs().unwrap();
        assert_eq!(logs.len(), 7);
        assert!(
            logs.iter()
                .all(|log| matches!(log.event, OperationalEvent::PeerRejected { .. }))
        );
    }

    #[tokio::test]
    async fn endpoint_uses_the_persisted_identity_and_raw_alpn() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let identity = DeviceIdentity::from_secret([42; 32]);
        let endpoint = configured_builder(&Config::default(), &identity)
            .unwrap()
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        assert_eq!(endpoint_from_iroh(endpoint.id()), identity.endpoint_id());
        endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incompatible_sync_and_join_alpns_fail_during_negotiation() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let server_identity = DeviceIdentity::from_secret([45; 32]);
        let client_identity = DeviceIdentity::from_secret([46; 32]);
        let server = configured_builder(&Config::default(), &server_identity)
            .unwrap()
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client = configured_builder(&Config::default(), &client_identity)
            .unwrap()
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();

        for incompatible in [b"skillsync/2".as_slice(), b"skillsync-join/2".as_slice()] {
            let accept_endpoint = server.clone();
            let rejected = tokio::spawn(async move {
                let incoming =
                    tokio::time::timeout(Duration::from_secs(5), accept_endpoint.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let Ok(accepting) = incoming.accept() else {
                    return true;
                };
                tokio::time::timeout(Duration::from_secs(5), accepting)
                    .await
                    .is_ok_and(|result| result.is_err())
            });
            let dial = tokio::time::timeout(
                Duration::from_secs(5),
                client.connect(server.addr(), incompatible),
            )
            .await
            .unwrap();
            assert!(dial.is_err(), "incompatible ALPN negotiated");
            assert!(
                rejected.await.unwrap(),
                "server accepted an application connection"
            );
        }

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn custom_relay_and_lookup_configuration_transfers_without_direct_addresses() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let (_relay_map, relay_url, _relay_server) =
            iroh::test_utils::run_relay_server().await.unwrap();
        let lookup = PkarrFixture::run().await;
        let config = Config::from_toml(&format!(
            r#"
            [iroh]
            preset = "custom"
            relay_urls = ["{relay_url}"]
            address_lookup_urls = ["{}"]
            "#,
            lookup.url
        ))
        .unwrap();
        let first = configured_builder(&config, &DeviceIdentity::from_secret([43; 32]))
            .unwrap()
            .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
            .clear_ip_transports()
            .bind()
            .await
            .unwrap();
        let second = configured_builder(&config, &DeviceIdentity::from_secret([44; 32]))
            .unwrap()
            .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
            .clear_ip_transports()
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), first.online())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), second.online())
            .await
            .unwrap();
        lookup.wait_for(second.id()).await;

        let accept_endpoint = second.clone();
        let accepting = tokio::spawn(async move {
            let incoming = accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            let mut recv = connection.accept_uni().await.unwrap();
            let mut bytes = [0_u8; 4];
            recv.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            first.connect(EndpointAddr::new(second.id()), crate::protocol::ALPN),
        )
        .await
        .unwrap()
        .unwrap();
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        assert_eq!(accepting.await.unwrap(), *b"ping");
        first.close().await;
        second.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn network_shutdown_cancels_an_active_authenticated_session() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([45; 32]);
        let second = DeviceIdentity::from_secret([46; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([47; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        fs::create_dir_all(&paths.data_dir).unwrap();
        let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        state.insert_roster_revision(&child).unwrap();
        drop(state);
        let config = Config::from_toml(
            r#"
            [iroh]
            preset = "custom"
            relay_urls = ["http://127.0.0.1:9"]
            address_lookup_urls = ["http://127.0.0.1:9/pkarr"]

            [sync]
            interval = "1h"
            "#,
        )
        .unwrap();
        let network = NetworkHandle::start(paths, config, first).unwrap();
        let target: EndpointAddr =
            serde_json::from_str(&network.endpoint_addr_json().unwrap()).unwrap();
        let second_endpoint = direct_endpoint(&second).await;
        let connection = second_endpoint
            .connect(target, crate::protocol::ALPN)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        network.shutdown().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(connection);
        second_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configured_interval_reconciles_without_an_external_trigger() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([48; 32]);
        let second = DeviceIdentity::from_secret([49; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([50; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let first_data = temporary.path().join("first");
        let second_data = temporary.path().join("second");
        fs::create_dir_all(&first_data).unwrap();
        fs::create_dir_all(&second_data).unwrap();
        let first_session = fixture_state(&first_data, &first, &genesis, &child);
        let second_session = fixture_state(&second_data, &second, &genesis, &child);
        let first_paths = PlatformPaths {
            config_file: first_data.join("config.toml"),
            data_dir: first_data.clone(),
            runtime_dir: first_data.join("run"),
        };
        let second_paths = PlatformPaths {
            config_file: second_data.join("config.toml"),
            data_dir: second_data.clone(),
            runtime_dir: second_data.join("run"),
        };
        let config = Config::from_toml(
            r#"
            [iroh]
            preset = "custom"
            relay_urls = ["http://127.0.0.1:9"]
            address_lookup_urls = ["http://127.0.0.1:9/pkarr"]

            [sync]
            interval = "200ms"
            "#,
        )
        .unwrap();
        let first_network =
            NetworkHandle::start(first_paths.clone(), config.clone(), first).unwrap();
        let first_addr = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let addr: EndpointAddr =
                    serde_json::from_str(&first_network.endpoint_addr_json().unwrap()).unwrap();
                if addr.ip_addrs().next().is_some() {
                    return addr;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let first_port = first_addr.ip_addrs().next().unwrap().port();
        let first_addr = serde_json::to_string(
            &EndpointAddr::new(first_addr.id)
                .with_ip_addr(std::net::SocketAddr::from(([127, 0, 0, 1], first_port))),
        )
        .unwrap();
        StateStore::open(&second_session.database)
            .unwrap()
            .replace_peer_hint(first_session.local_endpoint, &first_addr)
            .unwrap();
        let second_network = NetworkHandle::start(second_paths.clone(), config, second).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if StateStore::open(&second_session.database)
                    .unwrap()
                    .peer_reachable(first_session.local_endpoint)
                    .unwrap()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();

        let record = Record::file(
            ".agents",
            ProtocolPath::parse("interval/SKILL.md").unwrap(),
            100,
            first_session.local_endpoint,
            8,
            *blake3::hash(b"periodic").as_bytes(),
        )
        .unwrap();
        put_local(&first_session, &record, b"periodic");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if fs::read(second_data.join("skills/interval/SKILL.md"))
                    .is_ok_and(|bytes| bytes == b"periodic")
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        first_network.shutdown().unwrap();
        second_network.shutdown().unwrap();
    }

    async fn direct_endpoint(identity: &DeviceIdentity) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .secret_key(SecretKey::from_bytes(&identity.secret_bytes()))
            .alpns(vec![crate::protocol::ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    fn fixture_state(
        base: &std::path::Path,
        identity: &DeviceIdentity,
        genesis: &RosterRevision,
        child: &RosterRevision,
    ) -> SessionConfig {
        let root = base.join("skills");
        fs::create_dir_all(&root).unwrap();
        let database = base.join("state.sqlite3");
        let mut state = StateStore::open(&database).unwrap();
        state.insert_roster_revision(genesis).unwrap();
        state.insert_roster_revision(child).unwrap();
        state.add_collection(".agents", &root, Some(&root)).unwrap();
        SessionConfig {
            database,
            data_dir: base.to_path_buf(),
            local_endpoint: identity.endpoint_id(),
            local_addr: EndpointAddr::new(endpoint_to_iroh(identity.endpoint_id()).unwrap()),
            max_future_clock_skew: Duration::from_secs(300),
            max_logs: 1_000,
        }
    }

    fn put_local(config: &SessionConfig, record: &Record, bytes: &[u8]) {
        let root = config.data_dir.join("skills");
        let path = root.join(record.path().as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        let mut state = StateStore::open(&config.database).unwrap();
        assert!(
            state
                .merge_record(record, now_ns(), None, config.max_logs)
                .unwrap()
        );
    }

    async fn connect_once(
        left: &Endpoint,
        right: &Endpoint,
        left_config: &SessionConfig,
        right_config: &SessionConfig,
    ) {
        let mut left_config = left_config.clone();
        left_config.local_addr = left.addr();
        let mut right_config = right_config.clone();
        right_config.local_addr = right.addr();
        let right_endpoint = right.clone();
        let accept = tokio::spawn(async move {
            let incoming = right_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_session(connection, ConnectionSide::Acceptor, right_config).await
        });
        let connection = left
            .connect(right.addr(), crate::protocol::ALPN)
            .await
            .unwrap();
        let dial = run_session(connection, ConnectionSide::Dialer, left_config);
        let (dial, accept) = tokio::join!(dial, accept);
        let accept = accept.unwrap();
        assert!(
            dial.is_ok() && accept.is_ok(),
            "dial={dial:?} accept={accept:?}"
        );
    }

    async fn connect_simultaneously(
        left: &Endpoint,
        right: &Endpoint,
        left_config: &SessionConfig,
        right_config: &SessionConfig,
    ) {
        let mut left_out = left_config.clone();
        left_out.local_addr = left.addr();
        let left_in = left_out.clone();
        let mut right_out = right_config.clone();
        right_out.local_addr = right.addr();
        let right_in = right_out.clone();
        let left_accept_endpoint = left.clone();
        let right_accept_endpoint = right.clone();
        let left_accept = tokio::spawn(async move {
            let incoming = left_accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_session(connection, ConnectionSide::Acceptor, left_in).await
        });
        let right_accept = tokio::spawn(async move {
            let incoming = right_accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_session(connection, ConnectionSide::Acceptor, right_in).await
        });
        let (left_connection, right_connection) = tokio::join!(
            left.connect(right.addr(), crate::protocol::ALPN),
            right.connect(left.addr(), crate::protocol::ALPN)
        );
        let left_dial = tokio::spawn(run_session(
            left_connection.unwrap(),
            ConnectionSide::Dialer,
            left_out,
        ));
        let right_dial = tokio::spawn(run_session(
            right_connection.unwrap(),
            ConnectionSide::Dialer,
            right_out,
        ));
        let (left_dial, right_dial, left_accept, right_accept) =
            tokio::join!(left_dial, right_dial, left_accept, right_accept);
        let left_dial = left_dial.unwrap();
        let right_dial = right_dial.unwrap();
        let left_accept = left_accept.unwrap();
        let right_accept = right_accept.unwrap();
        assert!(
            left_dial.is_ok() && right_dial.is_ok() && left_accept.is_ok() && right_accept.is_ok(),
            "left_dial={left_dial:?} right_dial={right_dial:?} left_accept={left_accept:?} right_accept={right_accept:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn direct_peers_converge_create_offline_tie_delete_and_restart() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([11; 32]);
        let second = DeviceIdentity::from_secret([22; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([8; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let path = ProtocolPath::parse("review/SKILL.md").unwrap();

        let initial = Record::file(
            ".agents",
            path.clone(),
            100,
            first.endpoint_id(),
            3,
            *blake3::hash(b"one").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &initial, b"one");
        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert_eq!(
            fs::read(second_dir.join("skills/review/SKILL.md")).unwrap(),
            b"one"
        );
        fs::write(second_dir.join("skills/review/SKILL.md"), b"bad").unwrap();
        StateStore::open(&second_config.database)
            .unwrap()
            .set_repair_required(".agents", "review/SKILL.md")
            .unwrap();
        connect_once(
            &second_endpoint,
            &first_endpoint,
            &second_config,
            &first_config,
        )
        .await;
        assert_eq!(
            fs::read(second_dir.join("skills/review/SKILL.md")).unwrap(),
            b"one"
        );

        let first_offline = Record::file(
            ".agents",
            path.clone(),
            200,
            first.endpoint_id(),
            5,
            *blake3::hash(b"first").as_bytes(),
        )
        .unwrap();
        let second_offline = Record::file(
            ".agents",
            path.clone(),
            200,
            second.endpoint_id(),
            6,
            *blake3::hash(b"second").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &first_offline, b"first");
        put_local(&second_config, &second_offline, b"second");
        connect_simultaneously(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        let expected = if first_offline.compare_winner(&second_offline).is_gt() {
            b"first".as_slice()
        } else {
            b"second".as_slice()
        };
        assert_eq!(
            fs::read(first_dir.join("skills/review/SKILL.md")).unwrap(),
            expected
        );
        assert_eq!(
            fs::read(second_dir.join("skills/review/SKILL.md")).unwrap(),
            expected
        );

        let tombstone = Record::tombstone(".agents", path, 300, first.endpoint_id()).unwrap();
        fs::remove_file(first_dir.join("skills/review/SKILL.md")).unwrap();
        StateStore::open(&first_config.database)
            .unwrap()
            .merge_record(&tombstone, now_ns(), None, first_config.max_logs)
            .unwrap();
        first_endpoint.close().await;
        second_endpoint.close().await;

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert!(!second_dir.join("skills/review/SKILL.md").exists());

        let unknown_identity = DeviceIdentity::from_secret([33; 32]);
        let unknown_endpoint = direct_endpoint(&unknown_identity).await;
        let accept_endpoint = first_endpoint.clone();
        let mut accept_config = first_config.clone();
        accept_config.local_addr = first_endpoint.addr();
        let rejection = tokio::spawn(async move {
            let incoming = accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_session(connection, ConnectionSide::Acceptor, accept_config).await
        });
        let unknown_connection = unknown_endpoint
            .connect(first_endpoint.addr(), crate::protocol::ALPN)
            .await
            .unwrap();
        assert!(matches!(
            rejection.await.unwrap(),
            Err(SyncError::UnauthorizedPeer)
        ));
        drop(unknown_connection);
        unknown_endpoint.close().await;
        first_endpoint.close().await;
        second_endpoint.close().await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_local_collision_does_not_block_later_files_or_retries() {
        use std::os::unix::fs::symlink;

        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([51; 32]);
        let second = DeviceIdentity::from_secret([52; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([53; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, second_dir.join("skills/a-blocked")).unwrap();

        for (path, modified_ns, bytes) in [
            ("a-blocked/SKILL.md", 100, b"blocked".as_slice()),
            ("b-ok/SKILL.md", 101, b"ok".as_slice()),
        ] {
            let record = Record::file(
                ".agents",
                ProtocolPath::parse(path).unwrap(),
                modified_ns,
                first.endpoint_id(),
                bytes.len() as u64,
                *blake3::hash(bytes).as_bytes(),
            )
            .unwrap();
            put_local(&first_config, &record, bytes);
        }

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert!(!outside.join("SKILL.md").exists());
        assert_eq!(
            fs::read(second_dir.join("skills/b-ok/SKILL.md")).unwrap(),
            b"ok"
        );
        let state = StateStore::open(&second_config.database).unwrap();
        let blocked = state
            .record_states(".agents")
            .unwrap()
            .into_iter()
            .find(|record| record.record.path().as_str() == "a-blocked/SKILL.md")
            .unwrap();
        assert!(!blocked.materialized && blocked.needs_repair);
        assert!(state.logs().unwrap().iter().any(|log| matches!(
            &log.event,
            OperationalEvent::FileApplyRejected { path, .. }
                if path.as_str() == "a-blocked/SKILL.md"
        )));
        drop(state);

        let retry_peer = Record::file(
            ".agents",
            ProtocolPath::parse("z-after-retry/SKILL.md").unwrap(),
            102,
            first.endpoint_id(),
            5,
            *blake3::hash(b"later").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &retry_peer, b"later");
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert_eq!(
            fs::read(second_dir.join("skills/z-after-retry/SKILL.md")).unwrap(),
            b"later"
        );
        assert!(!outside.join("SKILL.md").exists());
        first_endpoint.close().await;
        second_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unavailable_winners_do_not_deadlock_an_available_file() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([54; 32]);
        let second = DeviceIdentity::from_secret([55; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([56; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let unavailable = Record::file(
            ".agents",
            ProtocolPath::parse("a-unavailable/SKILL.md").unwrap(),
            100,
            first.endpoint_id(),
            7,
            *blake3::hash(b"missing").as_bytes(),
        )
        .unwrap();
        StateStore::open(&first_config.database)
            .unwrap()
            .merge_record(
                &unavailable,
                now_ns(),
                Some(second.endpoint_id()),
                first_config.max_logs,
            )
            .unwrap();
        StateStore::open(&second_config.database)
            .unwrap()
            .merge_record(
                &unavailable,
                now_ns(),
                Some(first.endpoint_id()),
                second_config.max_logs,
            )
            .unwrap();
        let available = Record::file(
            ".agents",
            ProtocolPath::parse("b-available/SKILL.md").unwrap(),
            101,
            first.endpoint_id(),
            9,
            *blake3::hash(b"available").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &available, b"available");

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert_eq!(
            fs::read(second_dir.join("skills/b-available/SKILL.md")).unwrap(),
            b"available"
        );
        for config in [&first_config, &second_config] {
            let state = StateStore::open(&config.database).unwrap();
            let missing = state
                .record_states(".agents")
                .unwrap()
                .into_iter()
                .find(|record| record.record.path().as_str() == "a-unavailable/SKILL.md")
                .unwrap();
            assert!(!missing.materialized && missing.needs_repair);
            assert!(state.logs().unwrap().iter().any(|log| matches!(
                &log.event,
                OperationalEvent::TransferRejected { path, .. }
                    if path.as_str() == "a-unavailable/SKILL.md"
            )));
        }
        first_endpoint.close().await;
        second_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unavailable_collection_root_does_not_block_another_collection() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([57; 32]);
        let second = DeviceIdentity::from_secret([58; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([59; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let first_codex = first_dir.join("codex-skills");
        let second_codex = second_dir.join("codex-skills");
        fs::create_dir(&first_codex).unwrap();
        fs::create_dir(&second_codex).unwrap();
        StateStore::open(&first_config.database)
            .unwrap()
            .add_collection(".codex", &first_codex, Some(&first_codex))
            .unwrap();
        StateStore::open(&second_config.database)
            .unwrap()
            .add_collection(".codex", &second_codex, Some(&second_codex))
            .unwrap();

        let unavailable = Record::file(
            ".agents",
            ProtocolPath::parse("a-root-missing/SKILL.md").unwrap(),
            100,
            first.endpoint_id(),
            7,
            *blake3::hash(b"blocked").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &unavailable, b"blocked");
        let available = Record::file(
            ".codex",
            ProtocolPath::parse("b-available/SKILL.md").unwrap(),
            101,
            first.endpoint_id(),
            5,
            *blake3::hash(b"works").as_bytes(),
        )
        .unwrap();
        fs::create_dir_all(first_codex.join("b-available")).unwrap();
        fs::write(first_codex.join("b-available/SKILL.md"), b"works").unwrap();
        StateStore::open(&first_config.database)
            .unwrap()
            .merge_record(&available, now_ns(), None, first_config.max_logs)
            .unwrap();
        fs::remove_dir_all(second_dir.join("skills")).unwrap();

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert_eq!(
            fs::read(second_codex.join("b-available/SKILL.md")).unwrap(),
            b"works"
        );
        let state = StateStore::open(&second_config.database).unwrap();
        let missing = state
            .record_states(".agents")
            .unwrap()
            .into_iter()
            .find(|record| record.record.path().as_str() == "a-root-missing/SKILL.md")
            .unwrap();
        assert!(!missing.materialized && missing.needs_repair);
        assert!(state.logs().unwrap().iter().any(|log| matches!(
            &log.event,
            OperationalEvent::FileApplyRejected { path, .. }
                if path.as_str() == "a-root-missing/SKILL.md"
        )));
        first_endpoint.close().await;
        second_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_future_record_does_not_block_a_valid_file_in_the_same_session() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([60; 32]);
        let second = DeviceIdentity::from_secret([61; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([62; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let future = Record::file(
            ".agents",
            ProtocolPath::parse("a-future/SKILL.md").unwrap(),
            i64::MAX,
            first.endpoint_id(),
            6,
            *blake3::hash(b"future").as_bytes(),
        )
        .unwrap();
        let valid = Record::file(
            ".agents",
            ProtocolPath::parse("b-valid/SKILL.md").unwrap(),
            100,
            first.endpoint_id(),
            5,
            *blake3::hash(b"valid").as_bytes(),
        )
        .unwrap();
        put_local(&first_config, &future, b"future");
        put_local(&first_config, &valid, b"valid");

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        connect_once(
            &first_endpoint,
            &second_endpoint,
            &first_config,
            &second_config,
        )
        .await;
        assert!(!second_dir.join("skills/a-future/SKILL.md").exists());
        assert!(
            StateStore::open(&second_config.database)
                .unwrap()
                .record(".agents", "a-future/SKILL.md")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(second_dir.join("skills/b-valid/SKILL.md")).unwrap(),
            b"valid"
        );
        first_endpoint.close().await;
        second_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn four_thousand_record_symmetric_manifests_complete_and_converge() {
        let _guard = IROH_TEST_LOCK.lock().await;
        let first = DeviceIdentity::from_secret([63; 32]);
        let second = DeviceIdentity::from_secret([64; 32]);
        let genesis = RosterRevision::genesis(
            crate::identity::GroupId::from_bytes([65; 32]),
            "first",
            &first,
        )
        .unwrap();
        let child = RosterRevision::child(
            &genesis,
            RosterChange::Admit(RosterMember::new(second.endpoint_id(), "second").unwrap()),
            &first,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_config = fixture_state(&first_dir, &first, &genesis, &child);
        let second_config = fixture_state(&second_dir, &second, &genesis, &child);
        let long_tail = "x".repeat(380);
        let common_records = (0..4_000)
            .map(|index| {
                Record::tombstone(
                    ".agents",
                    ProtocolPath::parse(&format!("common-{index:04}-{long_tail}/SKILL.md"))
                        .unwrap(),
                    i64::from(index) + 100,
                    first.endpoint_id(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let first_unique = Record::tombstone(
            ".agents",
            ProtocolPath::parse("left-only/SKILL.md").unwrap(),
            1_000,
            first.endpoint_id(),
        )
        .unwrap();
        let second_unique = Record::tombstone(
            ".agents",
            ProtocolPath::parse("right-only/SKILL.md").unwrap(),
            1_000,
            second.endpoint_id(),
        )
        .unwrap();
        let mut first_records = common_records.clone();
        first_records.push(first_unique);
        let mut second_records = common_records;
        second_records.push(second_unique);
        let encoded_first = crate::protocol::ManifestBundle {
            manifests: vec![(
                ".agents".to_owned(),
                Manifest::new(first_records.clone()).unwrap(),
            )],
        }
        .encode()
        .unwrap();
        let encoded_second = crate::protocol::ManifestBundle {
            manifests: vec![(
                ".agents".to_owned(),
                Manifest::new(second_records.clone()).unwrap(),
            )],
        }
        .encode()
        .unwrap();
        println!(
            "large symmetric manifests: left={} right={}",
            encoded_first.len(),
            encoded_second.len()
        );
        assert!(encoded_first.len() > 1_500_000);
        assert!(encoded_second.len() > 1_500_000);
        let mut first_state = StateStore::open(&first_config.database).unwrap();
        let mut second_state = StateStore::open(&second_config.database).unwrap();
        first_state
            .insert_materialized_records_for_test(&first_records)
            .unwrap();
        second_state
            .insert_materialized_records_for_test(&second_records)
            .unwrap();
        drop(first_state);
        drop(second_state);

        let first_endpoint = direct_endpoint(&first).await;
        let second_endpoint = direct_endpoint(&second).await;
        tokio::time::timeout(
            Duration::from_secs(15),
            connect_once(
                &first_endpoint,
                &second_endpoint,
                &first_config,
                &second_config,
            ),
        )
        .await
        .expect("symmetric large manifest exchange timed out");
        let first_records = StateStore::open(&first_config.database)
            .unwrap()
            .records(".agents")
            .unwrap();
        let second_records = StateStore::open(&second_config.database)
            .unwrap()
            .records(".agents")
            .unwrap();
        assert_eq!(first_records.len(), 4_002);
        assert_eq!(first_records, second_records);
        first_endpoint.close().await;
        second_endpoint.close().await;
    }
}
