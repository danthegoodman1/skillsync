use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::EndpointAddr;
use iroh::endpoint::Connection;
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::config::{Config, PlatformPaths};
use crate::identity::{DeviceIdentity, EndpointId};
use crate::network::bind_endpoint;
use crate::protocol::{MAX_ENDPOINT_ADDRS, MAX_ROSTER_BYTES, MAX_ROSTER_REVISIONS, RosterBundle};
use crate::roster::RosterRevision;
use crate::state::{StateError, StateStore};
use crate::sync::{endpoint_from_iroh, endpoint_to_iroh};

pub const JOIN_ALPN: &[u8] = b"skillsync-join/1";
const JOIN_REQUEST_LIMIT: usize = 32 * 1024;
const JOIN_RESPONSE_LIMIT: usize = MAX_ROSTER_BYTES * 4 / 3 + 1 + 512 * 1024;
pub(crate) const MAX_JOIN_HINT_TEXT_BYTES: usize = 200 * 1024;
const JOIN_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DEVICE_NAME_BYTES: usize = 255;
const MAX_INVITATION_LIFETIME: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SecretNonce([u8; 32]);

impl SecretNonce {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn matches(&self, other: &[u8; 32]) -> bool {
        let mut difference = 0_u8;
        let mut index = 0;
        while index < 32 {
            difference |= self.0[index] ^ other[index];
            index += 1;
        }
        difference == 0
    }
}

impl fmt::Debug for SecretNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted nonce]")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingJoinInfo {
    pub request_id: String,
    pub endpoint_id: EndpointId,
    pub device_name: String,
}

pub struct JoinCoordinator {
    inner: Mutex<JoinState>,
}

impl Default for JoinCoordinator {
    fn default() -> Self {
        Self {
            inner: Mutex::new(JoinState::default()),
        }
    }
}

#[derive(Default)]
struct JoinState {
    active: Option<ActiveInvitation>,
    pending: Option<PendingJoin>,
}

struct ActiveInvitation {
    nonce: SecretNonce,
    deadline: Instant,
}

struct PendingJoin {
    info: PendingJoinInfo,
    endpoint_addr_json: String,
    decision: Option<oneshot::Sender<JoinDecision>>,
    deadline: Instant,
}

pub struct JoinDecision {
    approved: bool,
    roster: Vec<RosterRevision>,
    peer_hints: BTreeMap<String, Vec<String>>,
}

impl JoinDecision {
    pub fn rejected() -> Self {
        Self {
            approved: false,
            roster: Vec::new(),
            peer_hints: BTreeMap::new(),
        }
    }

    pub fn approved(
        roster: Vec<RosterRevision>,
        peer_hints: BTreeMap<String, Vec<String>>,
    ) -> Result<Self, JoinError> {
        validate_approval_payload(&roster, &peer_hints)?;
        Ok(Self {
            approved: true,
            roster,
            peer_hints,
        })
    }
}

impl JoinCoordinator {
    pub fn activate(&self, nonce: SecretNonce, lifetime: Duration) -> Result<(), JoinError> {
        if !(Duration::from_secs(60)..=MAX_INVITATION_LIFETIME).contains(&lifetime) {
            return Err(JoinError::InvalidInvitationLifetime);
        }
        let mut state = self.inner.lock().map_err(|_| JoinError::Coordinator)?;
        expire_locked(&mut state);
        if state.active.is_some() || state.pending.is_some() {
            return Err(JoinError::InvitationBusy);
        }
        state.active = Some(ActiveInvitation {
            nonce,
            deadline: Instant::now() + lifetime,
        });
        Ok(())
    }

    pub fn pending(&self) -> Result<Option<PendingJoinInfo>, JoinError> {
        let mut state = self.inner.lock().map_err(|_| JoinError::Coordinator)?;
        expire_locked(&mut state);
        Ok(state.pending.as_ref().map(|pending| pending.info.clone()))
    }

    pub fn pending_addr(&self, request_id: &str) -> Result<(PendingJoinInfo, String), JoinError> {
        let mut state = self.inner.lock().map_err(|_| JoinError::Coordinator)?;
        expire_locked(&mut state);
        let pending = state
            .pending
            .as_ref()
            .filter(|pending| pending.info.request_id == request_id)
            .ok_or(JoinError::UnknownJoinRequest)?;
        Ok((pending.info.clone(), pending.endpoint_addr_json.clone()))
    }

    pub fn decide(&self, request_id: &str, decision: JoinDecision) -> Result<(), JoinError> {
        let mut state = self.inner.lock().map_err(|_| JoinError::Coordinator)?;
        expire_locked(&mut state);
        let mut pending = state
            .pending
            .take()
            .filter(|pending| pending.info.request_id == request_id)
            .ok_or(JoinError::UnknownJoinRequest)?;
        let sender = pending
            .decision
            .take()
            .ok_or(JoinError::UnknownJoinRequest)?;
        sender.send(decision).map_err(|_| JoinError::JoinerGone)
    }

    fn cancel(&self, request_id: &str) {
        if let Ok(mut state) = self.inner.lock()
            && state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.info.request_id == request_id)
        {
            state.pending = None;
        }
    }

    fn claim(
        &self,
        nonce: &[u8; 32],
        remote_endpoint: EndpointId,
        device_name: String,
        endpoint_addr_json: String,
    ) -> Result<(oneshot::Receiver<JoinDecision>, Duration, String), JoinError> {
        validate_join_device_name(&device_name)?;
        validate_endpoint_addr(&endpoint_addr_json, remote_endpoint)?;
        let mut state = self.inner.lock().map_err(|_| JoinError::Coordinator)?;
        expire_locked(&mut state);
        let invitation = state
            .active
            .take()
            .ok_or(JoinError::InvitationUnavailable)?;
        if !invitation.nonce.matches(nonce) {
            state.active = Some(invitation);
            return Err(JoinError::InvitationUnavailable);
        }
        if state.pending.is_some() {
            return Err(JoinError::InvitationBusy);
        }
        let remaining = invitation
            .deadline
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(JoinError::InvitationUnavailable);
        }
        let (decision, receiver) = oneshot::channel();
        let request_id = Uuid::new_v4().to_string();
        state.pending = Some(PendingJoin {
            info: PendingJoinInfo {
                request_id: request_id.clone(),
                endpoint_id: remote_endpoint,
                device_name,
            },
            endpoint_addr_json,
            decision: Some(decision),
            deadline: invitation.deadline,
        });
        Ok((receiver, remaining, request_id))
    }
}

fn expire_locked(state: &mut JoinState) {
    if state
        .active
        .as_ref()
        .is_some_and(|invitation| Instant::now() >= invitation.deadline)
    {
        state.active = None;
    }
    if state
        .pending
        .as_ref()
        .is_some_and(|pending| Instant::now() >= pending.deadline)
    {
        state.pending = None;
    }
}

pub fn endpoint_ticket(addr: EndpointAddr) -> String {
    EndpointTicket::new(addr).to_string()
}

pub async fn run_joiner(
    paths: &PlatformPaths,
    config: &Config,
    identity: &DeviceIdentity,
    inviter_ticket: &str,
    nonce: [u8; 32],
    device_name: &str,
) -> Result<EndpointId, JoinError> {
    validate_join_device_name(device_name)?;
    let ticket = EndpointTicket::from_str(inviter_ticket).map_err(|_| JoinError::InvalidTicket)?;
    let target: EndpointAddr = ticket.into();
    let inviter = endpoint_from_iroh(target.id);
    let endpoint = bind_endpoint(config, identity)
        .await
        .map_err(|error| JoinError::Bind(error.to_string()))?;
    let result = run_joiner_on_endpoint(
        paths,
        identity,
        &endpoint,
        target,
        inviter,
        nonce,
        device_name,
    )
    .await;
    endpoint.close().await;
    result
}

async fn run_joiner_on_endpoint(
    paths: &PlatformPaths,
    identity: &DeviceIdentity,
    endpoint: &iroh::Endpoint,
    target: EndpointAddr,
    inviter: EndpointId,
    nonce: [u8; 32],
    device_name: &str,
) -> Result<EndpointId, JoinError> {
    let connection =
        tokio::time::timeout(Duration::from_secs(10), endpoint.connect(target, JOIN_ALPN))
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|_| JoinError::Transport)?;
    if endpoint_from_iroh(connection.remote_id()) != inviter {
        return Err(JoinError::WrongInviter);
    }
    let (mut send, mut recv) = tokio::time::timeout(JOIN_IO_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(|_| JoinError::Transport)?;
    let request = JoinRequest {
        protocol: "skillsync/1".to_owned(),
        nonce,
        device_name: device_name.to_owned(),
        endpoint_addr_json: serde_json::to_string(&endpoint.addr())
            .map_err(|_| JoinError::InvalidAddress)?,
    };
    write_json(&mut send, &request, JOIN_REQUEST_LIMIT).await?;
    let response: JoinResponse =
        read_json_waiting(&mut recv, JOIN_RESPONSE_LIMIT, MAX_INVITATION_LIFETIME).await?;
    if !response.approved {
        return Err(JoinError::Rejected);
    }
    let roster = decode_roster(&response.roster)?;
    let tip = roster.last().ok_or(JoinError::InvalidRoster)?;
    if tip
        .members()
        .get(&identity.endpoint_id())
        .map(String::as_str)
        != Some(device_name)
        || !tip.members().contains_key(&inviter)
    {
        return Err(JoinError::InvalidRoster);
    }
    let mut validated_hints = Vec::new();
    for (endpoint, hints) in response.peer_hints {
        let endpoint = EndpointId::from_str(&endpoint).map_err(|_| JoinError::InvalidAddress)?;
        if !tip.members().contains_key(&endpoint) || endpoint == identity.endpoint_id() {
            return Err(JoinError::InvalidAddress);
        }
        for hint in &hints {
            validate_endpoint_addr(hint, endpoint)?;
        }
        validated_hints.push((endpoint, hints));
    }
    if !validated_hints
        .iter()
        .any(|(endpoint, hints)| *endpoint == inviter && !hints.is_empty())
    {
        return Err(JoinError::InvalidAddress);
    }
    let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3"))?;
    state.install_or_resume_joined_state(
        &roster,
        identity.endpoint_id(),
        device_name,
        &validated_hints,
    )?;
    write_json(&mut send, &JoinAck { accepted: true }, JOIN_REQUEST_LIMIT).await?;
    send.finish().map_err(|_| JoinError::Transport)?;
    wait_for_ack_delivery(send.stopped()).await?;
    Ok(inviter)
}

async fn wait_for_ack_delivery<F, S, E>(stopped: F) -> Result<(), JoinError>
where
    F: Future<Output = Result<Option<S>, E>>,
{
    match tokio::time::timeout(JOIN_IO_TIMEOUT, stopped).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) | Ok(Err(_)) => return Err(JoinError::Transport),
        Err(_) => return Err(JoinError::Timeout),
    }
    Ok(())
}

pub async fn run_inviter(
    connection: Connection,
    coordinator: std::sync::Arc<JoinCoordinator>,
) -> Result<EndpointId, JoinError> {
    let remote_endpoint = endpoint_from_iroh(connection.remote_id());
    let (mut send, mut recv) = tokio::time::timeout(JOIN_IO_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(|_| JoinError::Transport)?;
    let request: JoinRequest = read_json(&mut recv, JOIN_REQUEST_LIMIT).await?;
    if request.protocol != "skillsync/1" {
        return Err(JoinError::WrongProtocol);
    }
    let (decision, remaining, request_id) = coordinator.claim(
        &request.nonce,
        remote_endpoint,
        request.device_name,
        request.endpoint_addr_json,
    )?;
    let closed = connection.closed();
    tokio::pin!(closed);
    let decision = tokio::select! {
        decision = tokio::time::timeout(remaining, decision) => {
            match decision {
                Ok(Ok(decision)) => decision,
                Ok(Err(_)) => return Err(JoinError::JoinerGone),
                Err(_) => {
                    coordinator.cancel(&request_id);
                    return Err(JoinError::InvitationUnavailable);
                }
            }
        }
        _ = &mut closed => {
            coordinator.cancel(&request_id);
            return Err(JoinError::JoinerGone);
        }
    };
    let response = if decision.approved {
        JoinResponse {
            approved: true,
            roster: encode_roster(&decision.roster)?,
            peer_hints: decision.peer_hints,
        }
    } else {
        JoinResponse {
            approved: false,
            roster: Vec::new(),
            peer_hints: BTreeMap::new(),
        }
    };
    write_json(&mut send, &response, JOIN_RESPONSE_LIMIT).await?;
    send.finish().map_err(|_| JoinError::Transport)?;
    if !response.approved {
        return Err(JoinError::Rejected);
    }
    let ack: JoinAck = read_json(&mut recv, JOIN_REQUEST_LIMIT).await?;
    if !ack.accepted {
        return Err(JoinError::InvalidFrame);
    }
    Ok(remote_endpoint)
}

#[derive(Deserialize, Serialize)]
struct JoinRequest {
    protocol: String,
    nonce: [u8; 32],
    device_name: String,
    endpoint_addr_json: String,
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinRequest")
            .field("protocol", &self.protocol)
            .field("nonce", &"[redacted]")
            .field("device_name", &self.device_name)
            .field("endpoint_addr_json", &"[redacted address]")
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
struct JoinResponse {
    approved: bool,
    roster: Vec<String>,
    peer_hints: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize, Serialize)]
struct JoinAck {
    accepted: bool,
}

fn encode_roster(revisions: &[RosterRevision]) -> Result<Vec<String>, JoinError> {
    RosterBundle {
        revisions: revisions.to_vec(),
    }
    .encode()
    .map_err(|_| JoinError::InvalidRoster)?;
    Ok(revisions
        .iter()
        .map(|revision| URL_SAFE_NO_PAD.encode(revision.canonical_bytes()))
        .collect())
}

fn validate_approval_payload(
    roster: &[RosterRevision],
    peer_hints: &BTreeMap<String, Vec<String>>,
) -> Result<(), JoinError> {
    let encoded_roster = encode_roster(roster)?;
    let tip = roster.last().ok_or(JoinError::InvalidRoster)?;
    let mut hint_text_bytes = 0_usize;
    for (endpoint, hints) in peer_hints {
        let endpoint_id = EndpointId::from_str(endpoint).map_err(|_| JoinError::InvalidAddress)?;
        if !tip.members().contains_key(&endpoint_id) || hints.is_empty() {
            return Err(JoinError::InvalidAddress);
        }
        hint_text_bytes = hint_text_bytes
            .checked_add(endpoint.len())
            .ok_or(JoinError::FrameTooLarge)?;
        for hint in hints {
            validate_endpoint_addr(hint, endpoint_id)?;
            hint_text_bytes = hint_text_bytes
                .checked_add(hint.len())
                .ok_or(JoinError::FrameTooLarge)?;
        }
    }
    if hint_text_bytes > MAX_JOIN_HINT_TEXT_BYTES {
        return Err(JoinError::FrameTooLarge);
    }
    let response = JoinResponse {
        approved: true,
        roster: encoded_roster,
        peer_hints: peer_hints.clone(),
    };
    if serde_json::to_vec(&response)
        .map_err(|_| JoinError::InvalidFrame)?
        .len()
        > JOIN_RESPONSE_LIMIT
    {
        return Err(JoinError::FrameTooLarge);
    }
    Ok(())
}

fn decode_roster(encoded: &[String]) -> Result<Vec<RosterRevision>, JoinError> {
    if encoded.is_empty() || encoded.len() > MAX_ROSTER_REVISIONS {
        return Err(JoinError::InvalidRoster);
    }
    let mut revisions = Vec::with_capacity(encoded.len());
    let mut bytes = 0_usize;
    for revision in encoded {
        let canonical = URL_SAFE_NO_PAD
            .decode(revision)
            .map_err(|_| JoinError::InvalidRoster)?;
        bytes = bytes
            .checked_add(canonical.len())
            .ok_or(JoinError::InvalidRoster)?;
        if bytes > MAX_ROSTER_BYTES {
            return Err(JoinError::InvalidRoster);
        }
        revisions.push(
            RosterRevision::from_canonical(&canonical).map_err(|_| JoinError::InvalidRoster)?,
        );
    }
    RosterBundle {
        revisions: revisions.clone(),
    }
    .encode()
    .map_err(|_| JoinError::InvalidRoster)?;
    Ok(revisions)
}

async fn write_json<T: Serialize>(
    stream: &mut iroh::endpoint::SendStream,
    value: &T,
    limit: usize,
) -> Result<(), JoinError> {
    let bytes = serde_json::to_vec(value).map_err(|_| JoinError::InvalidFrame)?;
    if bytes.len() > limit {
        return Err(JoinError::FrameTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| JoinError::FrameTooLarge)?;
    tokio::time::timeout(JOIN_IO_TIMEOUT, stream.write_all(&length.to_be_bytes()))
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(|_| JoinError::Transport)?;
    for chunk in bytes.chunks(64 * 1024) {
        tokio::time::timeout(JOIN_IO_TIMEOUT, stream.write_all(chunk))
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|_| JoinError::Transport)?;
    }
    Ok(())
}

async fn read_json<T, R>(stream: &mut R, limit: usize) -> Result<T, JoinError>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    read_json_waiting(stream, limit, JOIN_IO_TIMEOUT).await
}

async fn read_json_waiting<T, R>(
    stream: &mut R,
    limit: usize,
    first_byte_timeout: Duration,
) -> Result<T, JoinError>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    tokio::time::timeout(first_byte_timeout, stream.read_exact(&mut length[..1]))
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(|_| JoinError::Transport)?;
    tokio::time::timeout(JOIN_IO_TIMEOUT, stream.read_exact(&mut length[1..]))
        .await
        .map_err(|_| JoinError::Timeout)?
        .map_err(|_| JoinError::Transport)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| JoinError::FrameTooLarge)?;
    if length > limit {
        return Err(JoinError::FrameTooLarge);
    }
    let mut bytes = vec![0_u8; length];
    for chunk in bytes.chunks_mut(64 * 1024) {
        tokio::time::timeout(JOIN_IO_TIMEOUT, stream.read_exact(chunk))
            .await
            .map_err(|_| JoinError::Timeout)?
            .map_err(|_| JoinError::Transport)?;
    }
    serde_json::from_slice(&bytes).map_err(|_| JoinError::InvalidFrame)
}

pub fn validate_join_device_name(device_name: &str) -> Result<(), JoinError> {
    if device_name.trim().is_empty()
        || device_name.len() > MAX_DEVICE_NAME_BYTES
        || device_name.chars().any(terminal_unsafe_character)
    {
        return Err(JoinError::InvalidDeviceName);
    }
    Ok(())
}

pub fn terminal_safe_device_name(device_name: &str) -> String {
    let mut rendered = String::with_capacity(device_name.len());
    for character in device_name.chars() {
        if terminal_unsafe_character(character) {
            use std::fmt::Write as _;
            write!(rendered, "\\u{{{:x}}}", character as u32)
                .expect("writing to a string cannot fail");
        } else {
            rendered.push(character);
        }
    }
    rendered
}

fn terminal_unsafe_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn validate_endpoint_addr(encoded: &str, endpoint: EndpointId) -> Result<(), JoinError> {
    if encoded.is_empty() || encoded.len() > 16 * 1024 {
        return Err(JoinError::InvalidAddress);
    }
    let addr: EndpointAddr =
        serde_json::from_str(encoded).map_err(|_| JoinError::InvalidAddress)?;
    if endpoint_from_iroh(addr.id) != endpoint || addr.addrs.len() > MAX_ENDPOINT_ADDRS {
        return Err(JoinError::InvalidAddress);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum JoinError {
    #[error("invitation lifetime must be from 60 through 900 seconds")]
    InvalidInvitationLifetime,
    #[error("another invitation or join request is active")]
    InvitationBusy,
    #[error("invitation is unavailable or expired")]
    InvitationUnavailable,
    #[error("join coordinator failed")]
    Coordinator,
    #[error("join request is unknown or expired")]
    UnknownJoinRequest,
    #[error("joining device disconnected")]
    JoinerGone,
    #[error("inviter ticket is invalid")]
    InvalidTicket,
    #[error("joining device name is invalid")]
    InvalidDeviceName,
    #[error("join protocol is incompatible")]
    WrongProtocol,
    #[error("connected inviter does not match the ticket")]
    WrongInviter,
    #[error("join request was rejected")]
    Rejected,
    #[error("join roster is invalid")]
    InvalidRoster,
    #[error("join peer address is invalid")]
    InvalidAddress,
    #[error("join frame is invalid")]
    InvalidFrame,
    #[error("join frame exceeds its limit")]
    FrameTooLarge,
    #[error("join operation timed out")]
    Timeout,
    #[error("join transport failed")]
    Transport,
    #[error("join endpoint failed to bind: {0}")]
    Bind(String),
    #[error(transparent)]
    State(#[from] StateError),
}

pub fn endpoint_addr_for(endpoint: EndpointId) -> Result<EndpointAddr, JoinError> {
    Ok(EndpointAddr::new(
        endpoint_to_iroh(endpoint).map_err(|_| JoinError::InvalidAddress)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use iroh::SecretKey;
    use iroh::endpoint::{RelayMode, presets};

    use crate::identity::GroupId;
    use crate::roster::{RosterChange, RosterMember};

    use super::*;

    fn identity(seed: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret([seed; 32])
    }

    fn address(identity: &DeviceIdentity) -> String {
        serde_json::to_string(&endpoint_addr_for(identity.endpoint_id()).unwrap()).unwrap()
    }

    async fn direct_endpoint(identity: &DeviceIdentity) -> iroh::Endpoint {
        iroh::Endpoint::builder(presets::Minimal)
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .secret_key(SecretKey::from_bytes(&identity.secret_bytes()))
            .alpns(vec![JOIN_ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn coordinator_consumes_only_the_matching_nonce_and_rejects_by_default() {
        let coordinator = JoinCoordinator::default();
        coordinator
            .activate(SecretNonce::new([7; 32]), Duration::from_secs(60))
            .unwrap();
        let joiner = identity(2);
        assert!(matches!(
            coordinator.claim(
                &[8; 32],
                joiner.endpoint_id(),
                "laptop".to_owned(),
                address(&joiner)
            ),
            Err(JoinError::InvitationUnavailable)
        ));
        let (decision, _, request_id) = coordinator
            .claim(
                &[7; 32],
                joiner.endpoint_id(),
                "laptop".to_owned(),
                address(&joiner),
            )
            .unwrap();
        let pending = coordinator.pending().unwrap().unwrap();
        assert_eq!(pending.endpoint_id, joiner.endpoint_id());
        assert_eq!(pending.request_id, request_id);
        assert!(matches!(
            coordinator.claim(
                &[7; 32],
                joiner.endpoint_id(),
                "other".to_owned(),
                address(&joiner)
            ),
            Err(JoinError::InvitationUnavailable)
        ));
        coordinator
            .decide(&request_id, JoinDecision::rejected())
            .unwrap();
        assert!(!decision.await.unwrap().approved);
        assert!(coordinator.pending().unwrap().is_none());
    }

    #[test]
    fn pending_join_expiry_and_disconnect_release_the_bounded_slot() {
        let coordinator = JoinCoordinator::default();
        let joiner = identity(2);
        coordinator
            .activate(SecretNonce::new([7; 32]), Duration::from_secs(60))
            .unwrap();
        let (_decision, _, request_id) = coordinator
            .claim(
                &[7; 32],
                joiner.endpoint_id(),
                "laptop".to_owned(),
                address(&joiner),
            )
            .unwrap();
        coordinator.cancel(&request_id);
        assert!(coordinator.pending().unwrap().is_none());
        coordinator
            .activate(SecretNonce::new([9; 32]), Duration::from_secs(60))
            .unwrap();
        let (_decision, _, _) = coordinator
            .claim(
                &[9; 32],
                joiner.endpoint_id(),
                "laptop".to_owned(),
                address(&joiner),
            )
            .unwrap();
        coordinator
            .inner
            .lock()
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .deadline = Instant::now() - Duration::from_millis(1);
        assert!(coordinator.pending().unwrap().is_none());
        coordinator
            .activate(SecretNonce::new([10; 32]), Duration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn nonce_debug_and_human_decision_wait_are_bounded() {
        let debug = format!("{:?}", SecretNonce::new([42; 32]));
        assert_eq!(debug, "[redacted nonce]");
        assert_eq!(JOIN_IO_TIMEOUT, Duration::from_secs(30));
        assert_eq!(MAX_INVITATION_LIFETIME, Duration::from_secs(900));
    }

    #[test]
    fn new_join_names_reject_terminal_and_bidi_controls() {
        assert!(validate_join_device_name("ordinary device").is_ok());
        for name in [
            "line\nbreak",
            "ansi\u{1b}[31m",
            "override\u{202e}name",
            "isolate\u{2066}name",
            "mark\u{061c}name",
        ] {
            assert!(matches!(
                validate_join_device_name(name),
                Err(JoinError::InvalidDeviceName)
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn response_wait_uses_the_invitation_deadline_only_before_the_first_byte() {
        use tokio::io::AsyncWriteExt as _;

        let (mut writer, mut reader) = tokio::io::duplex(64);
        let waiting = tokio::spawn(async move {
            read_json_waiting::<JoinAck, _>(
                &mut reader,
                JOIN_REQUEST_LIMIT,
                MAX_INVITATION_LIFETIME,
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(JOIN_IO_TIMEOUT + Duration::from_secs(1)).await;
        assert!(!waiting.is_finished());
        let body = serde_json::to_vec(&JoinAck { accepted: true }).unwrap();
        writer
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        writer.write_all(&body).await.unwrap();
        assert!(waiting.await.unwrap().unwrap().accepted);

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0]).await.unwrap();
        let stalled = tokio::spawn(async move {
            read_json_waiting::<JoinAck, _>(
                &mut reader,
                JOIN_REQUEST_LIMIT,
                MAX_INVITATION_LIFETIME,
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(JOIN_IO_TIMEOUT + Duration::from_secs(1)).await;
        assert!(matches!(stalled.await.unwrap(), Err(JoinError::Timeout)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_join_installs_the_complete_signed_roster_and_hints() {
        let _guard = crate::network::IROH_TEST_LOCK.lock().await;
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        fs::create_dir_all(&paths.data_dir).unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        let inviter_identity = identity(11);
        let joiner_identity = identity(12);
        let inviter_id = inviter_identity.endpoint_id();
        let inviter_endpoint = direct_endpoint(&inviter_identity).await;
        let joiner_endpoint = direct_endpoint(&joiner_identity).await;
        let ticket = endpoint_ticket(inviter_endpoint.addr());
        let coordinator = Arc::new(JoinCoordinator::default());
        coordinator
            .activate(SecretNonce::new([7; 32]), Duration::from_secs(60))
            .unwrap();
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([5; 32]), "inviter", &inviter_identity)
                .unwrap();
        let admission = RosterRevision::child(
            &genesis,
            RosterChange::Admit(
                RosterMember::new(joiner_identity.endpoint_id(), "joiner").unwrap(),
            ),
            &inviter_identity,
        )
        .unwrap();
        let accepting_endpoint = inviter_endpoint.clone();
        let accepting_coordinator = coordinator.clone();
        let inviter_task = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_inviter(connection, accepting_coordinator).await
        });
        let deciding_coordinator = coordinator.clone();
        let inviter_hint = serde_json::to_string(&inviter_endpoint.addr()).unwrap();
        let roster = vec![genesis.clone(), admission.clone()];
        let decision_task = tokio::spawn(async move {
            loop {
                if let Some(pending) = deciding_coordinator.pending().unwrap() {
                    let hints = BTreeMap::from([(inviter_id.to_string(), vec![inviter_hint])]);
                    deciding_coordinator
                        .decide(
                            &pending.request_id,
                            JoinDecision::approved(roster, hints).unwrap(),
                        )
                        .unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let join_result = run_joiner_on_endpoint(
            &paths,
            &joiner_identity,
            &joiner_endpoint,
            EndpointTicket::from_str(&ticket).unwrap().into(),
            inviter_id,
            [7; 32],
            "joiner",
        )
        .await;
        decision_task.await.unwrap();
        let inviter_result = inviter_task.await.unwrap();
        assert!(
            join_result.is_ok() && inviter_result.is_ok(),
            "joiner={join_result:?} inviter={inviter_result:?}"
        );
        let authenticated_inviter = join_result.unwrap();
        assert_eq!(authenticated_inviter, inviter_id);
        assert_eq!(inviter_result.unwrap(), joiner_identity.endpoint_id());
        let state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        assert_eq!(
            state.selected_roster_chain().unwrap(),
            vec![genesis, admission]
        );
        assert_eq!(state.peer_hints(authenticated_inviter).unwrap().len(), 1);
        joiner_endpoint.close().await;
        inviter_endpoint.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn ack_delivery_wait_is_bounded_and_requires_transport_confirmation() {
        let (confirm, confirmation) = oneshot::channel::<Result<Option<()>, ()>>();
        let waiting = tokio::spawn(wait_for_ack_delivery(
            async move { confirmation.await.unwrap() },
        ));
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        confirm.send(Ok(None)).unwrap();
        waiting.await.unwrap().unwrap();

        assert!(matches!(
            wait_for_ack_delivery(async { Ok::<_, ()>(Some(())) }).await,
            Err(JoinError::Transport)
        ));
        assert!(matches!(
            wait_for_ack_delivery(async { Err::<Option<()>, _>(()) }).await,
            Err(JoinError::Transport)
        ));

        let timed_out = tokio::spawn(wait_for_ack_delivery(std::future::pending::<
            Result<Option<()>, ()>,
        >()));
        tokio::task::yield_now().await;
        tokio::time::advance(JOIN_IO_TIMEOUT + Duration::from_secs(1)).await;
        assert!(matches!(timed_out.await.unwrap(), Err(JoinError::Timeout)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_disconnect_releases_the_pending_join() {
        let _guard = crate::network::IROH_TEST_LOCK.lock().await;
        let inviter_identity = identity(21);
        let joiner_identity = identity(22);
        let inviter_endpoint = direct_endpoint(&inviter_identity).await;
        let joiner_endpoint = direct_endpoint(&joiner_identity).await;
        let coordinator = Arc::new(JoinCoordinator::default());
        coordinator
            .activate(SecretNonce::new([7; 32]), Duration::from_secs(60))
            .unwrap();
        let accepting_endpoint = inviter_endpoint.clone();
        let accepting_coordinator = coordinator.clone();
        let inviter_task = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_inviter(connection, accepting_coordinator).await
        });
        let connection = joiner_endpoint
            .connect(inviter_endpoint.addr(), JOIN_ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        write_json(
            &mut send,
            &JoinRequest {
                protocol: "skillsync/1".to_owned(),
                nonce: [7; 32],
                device_name: "joiner".to_owned(),
                endpoint_addr_json: serde_json::to_string(&joiner_endpoint.addr()).unwrap(),
            },
            JOIN_REQUEST_LIMIT,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while coordinator.pending().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        connection.close(0_u32.into(), b"test disconnect");
        assert!(matches!(
            inviter_task.await.unwrap(),
            Err(JoinError::JoinerGone)
        ));
        assert!(coordinator.pending().unwrap().is_none());
        joiner_endpoint.close().await;
        inviter_endpoint.close().await;
    }

    async fn failed_attempt_then_same_identity_recovery(disconnect_before_response: bool) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        fs::create_dir_all(&paths.data_dir).unwrap();
        StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        let inviter_identity = identity(31);
        let joiner_identity = identity(32);
        let inviter_id = inviter_identity.endpoint_id();
        let inviter_endpoint = direct_endpoint(&inviter_identity).await;
        let joiner_endpoint = direct_endpoint(&joiner_identity).await;
        let coordinator = Arc::new(JoinCoordinator::default());
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([33; 32]), "inviter", &inviter_identity)
                .unwrap();
        let admission = RosterRevision::child(
            &genesis,
            RosterChange::Admit(
                RosterMember::new(joiner_identity.endpoint_id(), "joiner").unwrap(),
            ),
            &inviter_identity,
        )
        .unwrap();
        let roster = vec![genesis.clone(), admission.clone()];
        let inviter_hint = serde_json::to_string(&inviter_endpoint.addr()).unwrap();
        let hints = BTreeMap::from([(inviter_id.to_string(), vec![inviter_hint.clone()])]);

        coordinator
            .activate(SecretNonce::new([7; 32]), Duration::from_secs(60))
            .unwrap();
        let accepting_endpoint = inviter_endpoint.clone();
        let accepting_coordinator = coordinator.clone();
        let inviter_task = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_inviter(connection, accepting_coordinator).await
        });
        let connection = joiner_endpoint
            .connect(inviter_endpoint.addr(), JOIN_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_json(
            &mut send,
            &JoinRequest {
                protocol: "skillsync/1".to_owned(),
                nonce: [7; 32],
                device_name: "joiner".to_owned(),
                endpoint_addr_json: serde_json::to_string(&joiner_endpoint.addr()).unwrap(),
            },
            JOIN_REQUEST_LIMIT,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while coordinator.pending().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        if disconnect_before_response {
            connection.close(0_u32.into(), b"before response");
        } else {
            let request_id = coordinator.pending().unwrap().unwrap().request_id;
            coordinator
                .decide(
                    &request_id,
                    JoinDecision::approved(roster.clone(), hints.clone()).unwrap(),
                )
                .unwrap();
            let response: JoinResponse = read_json(&mut recv, JOIN_RESPONSE_LIMIT).await.unwrap();
            assert!(response.approved);
            let mut state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
            state
                .install_or_resume_joined_state(
                    &roster,
                    joiner_identity.endpoint_id(),
                    "joiner",
                    &[(inviter_id, vec![inviter_hint.clone()])],
                )
                .unwrap();
            connection.close(0_u32.into(), b"after response before ack");
        }
        assert!(inviter_task.await.unwrap().is_err());
        assert!(coordinator.pending().unwrap().is_none());
        drop(send);
        drop(recv);

        coordinator
            .activate(SecretNonce::new([8; 32]), Duration::from_secs(60))
            .unwrap();
        let accepting_endpoint = inviter_endpoint.clone();
        let accepting_coordinator = coordinator.clone();
        let recovery_inviter = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            run_inviter(connection, accepting_coordinator).await
        });
        let deciding_coordinator = coordinator.clone();
        let recovery_roster = roster.clone();
        let recovery_hints = hints.clone();
        let decision = tokio::spawn(async move {
            loop {
                if let Some(pending) = deciding_coordinator.pending().unwrap() {
                    deciding_coordinator
                        .decide(
                            &pending.request_id,
                            JoinDecision::approved(recovery_roster, recovery_hints).unwrap(),
                        )
                        .unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        run_joiner_on_endpoint(
            &paths,
            &joiner_identity,
            &joiner_endpoint,
            inviter_endpoint.addr(),
            inviter_id,
            [8; 32],
            "joiner",
        )
        .await
        .unwrap();
        decision.await.unwrap();
        recovery_inviter.await.unwrap().unwrap();
        let state = StateStore::open(&paths.data_dir.join("state.sqlite3")).unwrap();
        assert_eq!(state.selected_roster_chain().unwrap(), roster);
        inviter_endpoint.close().await;
        joiner_endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_before_response_allows_fresh_same_identity_recovery() {
        let _guard = crate::network::IROH_TEST_LOCK.lock().await;
        failed_attempt_then_same_identity_recovery(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_after_response_before_ack_allows_fresh_same_identity_recovery() {
        let _guard = crate::network::IROH_TEST_LOCK.lock().await;
        failed_attempt_then_same_identity_recovery(false).await;
    }
}
