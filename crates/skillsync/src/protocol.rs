use std::collections::BTreeSet;
use std::io::{self, Read};
use std::time::Duration;

use iroh::endpoint::{RecvStream, SendStream};
use thiserror::Error;

use crate::identity::GroupId;
use crate::record::{Manifest, Record, RecordError};
use crate::roster::{RosterError, RosterRevision};

pub const ALPN: &[u8] = b"skillsync/1";
pub const PROTOCOL_VERSION: u8 = 1;

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_RECORDS: usize = 10_000;
pub const MAX_ROSTER_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ROSTER_REVISIONS: usize = 1_024;
pub const MAX_ROSTER_MEMBERS: usize = 1_024;
pub const MAX_COLLECTIONS: usize = 64;
pub const MAX_COLLECTION_NAME_BYTES: usize = 255;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TRANSFERS: usize = 1_024;
pub const MAX_SESSION_FILE_BYTES: u64 = 192 * 1024 * 1024;
pub const MAX_ADDRESS_HINT_BYTES: usize = 16 * 1024;
pub const MAX_ENDPOINT_ADDRS: usize = 32;
pub const MAX_CONNECTION_BYTES: u64 = 256 * 1024 * 1024;
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

const MAGIC: &[u8; 4] = b"SSP1";
const HEADER_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameTag {
    Hello = 1,
    Roster = 2,
    Manifests = 3,
    Requests = 4,
    File = 5,
    Done = 6,
    FileUnavailable = 7,
}

impl FrameTag {
    fn from_byte(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Roster),
            3 => Ok(Self::Manifests),
            4 => Ok(Self::Requests),
            5 => Ok(Self::File),
            6 => Ok(Self::Done),
            7 => Ok(Self::FileUnavailable),
            _ => Err(ProtocolError::UnknownFrameType),
        }
    }

    const fn payload_limit(self) -> usize {
        match self {
            Self::Hello => 64 * 1024,
            Self::Roster => MAX_ROSTER_BYTES,
            Self::Manifests => MAX_MANIFEST_BYTES,
            Self::Requests => MAX_FRAME_BYTES,
            Self::File => 64 * 1024,
            Self::Done => 0,
            Self::FileUnavailable => 8 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub group_id: GroupId,
    pub device_name: String,
    pub roster_hash: [u8; 32],
    pub collections: Vec<String>,
    pub endpoint_addr_json: String,
}

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_short_string(&self.device_name, MAX_COLLECTION_NAME_BYTES)?;
        validate_collections(&self.collections)?;
        if self.endpoint_addr_json.len() > MAX_ADDRESS_HINT_BYTES {
            return Err(ProtocolError::AddressHintTooLarge);
        }
        let mut writer = WireWriter::default();
        writer.fixed(self.group_id.as_bytes());
        writer.string(&self.device_name)?;
        writer.fixed(&self.roster_hash);
        writer.count(self.collections.len())?;
        for collection in &self.collections {
            writer.string(collection)?;
        }
        writer.string(&self.endpoint_addr_json)?;
        Ok(writer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = WireReader::new(bytes);
        let group_id = GroupId::from_bytes(reader.fixed()?);
        let device_name = reader.string(MAX_COLLECTION_NAME_BYTES)?;
        let roster_hash = reader.fixed()?;
        let count = reader.count(MAX_COLLECTIONS)?;
        let mut collections = Vec::with_capacity(count);
        for _ in 0..count {
            collections.push(reader.string(MAX_COLLECTION_NAME_BYTES)?);
        }
        validate_collections(&collections)?;
        let endpoint_addr_json = reader.string(MAX_ADDRESS_HINT_BYTES)?;
        reader.finish()?;
        Ok(Self {
            group_id,
            device_name,
            roster_hash,
            collections,
            endpoint_addr_json,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterBundle {
    pub revisions: Vec<RosterRevision>,
}

impl RosterBundle {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.revisions.is_empty() || self.revisions.len() > MAX_ROSTER_REVISIONS {
            return Err(ProtocolError::RosterLimit);
        }
        let mut writer = WireWriter::default();
        writer.count(self.revisions.len())?;
        for revision in &self.revisions {
            if revision.members().len() > MAX_ROSTER_MEMBERS {
                return Err(ProtocolError::RosterLimit);
            }
            writer.bytes(&revision.canonical_bytes())?;
        }
        let bytes = writer.finish();
        if bytes.len() > MAX_ROSTER_BYTES {
            return Err(ProtocolError::RosterLimit);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_ROSTER_BYTES {
            return Err(ProtocolError::RosterLimit);
        }
        let mut reader = WireReader::new(bytes);
        let count = reader.count(MAX_ROSTER_REVISIONS)?;
        if count == 0 {
            return Err(ProtocolError::InvalidRoster);
        }
        let mut revisions = Vec::with_capacity(count);
        for _ in 0..count {
            let canonical = reader.bytes(MAX_ROSTER_BYTES)?;
            let revision =
                RosterRevision::from_canonical_with_member_limit(canonical, MAX_ROSTER_MEMBERS)?;
            if revision.members().len() > MAX_ROSTER_MEMBERS {
                return Err(ProtocolError::RosterLimit);
            }
            revisions.push(revision);
        }
        reader.finish()?;
        validate_roster_chain(&revisions)?;
        Ok(Self { revisions })
    }
}

pub fn validate_roster_chain(revisions: &[RosterRevision]) -> Result<(), ProtocolError> {
    let Some(genesis) = revisions.first() else {
        return Err(ProtocolError::InvalidRoster);
    };
    genesis.validate_genesis()?;
    for pair in revisions.windows(2) {
        pair[1].validate_child(&pair[0])?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestBundle {
    pub manifests: Vec<(String, Manifest)>,
}

impl ManifestBundle {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.manifests.len() > MAX_COLLECTIONS {
            return Err(ProtocolError::CollectionLimit);
        }
        let mut seen = BTreeSet::new();
        let mut records = 0_usize;
        let mut writer = WireWriter::default();
        writer.count(self.manifests.len())?;
        for (collection, manifest) in &self.manifests {
            validate_collection(collection)?;
            if !seen.insert(collection) {
                return Err(ProtocolError::DuplicateCollection);
            }
            records = records
                .checked_add(manifest.records().len())
                .ok_or(ProtocolError::ManifestLimit)?;
            if records > MAX_MANIFEST_RECORDS {
                return Err(ProtocolError::ManifestLimit);
            }
            for record in manifest.records() {
                validate_record(record, collection)?;
            }
            writer.string(collection)?;
            writer.bytes(&manifest.canonical_bytes())?;
        }
        let bytes = writer.finish();
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProtocolError::ManifestLimit);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProtocolError::ManifestLimit);
        }
        let mut reader = WireReader::new(bytes);
        let count = reader.count(MAX_COLLECTIONS)?;
        let mut seen = BTreeSet::new();
        let mut record_count = 0_usize;
        let mut manifests = Vec::with_capacity(count);
        for _ in 0..count {
            let collection = reader.string(MAX_COLLECTION_NAME_BYTES)?;
            validate_collection(&collection)?;
            if !seen.insert(collection.clone()) {
                return Err(ProtocolError::DuplicateCollection);
            }
            let canonical = reader.bytes(MAX_MANIFEST_BYTES)?;
            let remaining = MAX_MANIFEST_RECORDS.saturating_sub(record_count);
            let manifest = Manifest::from_canonical_with_limit(canonical, remaining)?;
            record_count = record_count
                .checked_add(manifest.records().len())
                .ok_or(ProtocolError::ManifestLimit)?;
            if record_count > MAX_MANIFEST_RECORDS {
                return Err(ProtocolError::ManifestLimit);
            }
            for record in manifest.records() {
                validate_record(record, &collection)?;
            }
            manifests.push((collection, manifest));
        }
        reader.finish()?;
        Ok(Self { manifests })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileRequest {
    pub collection: String,
    pub path: String,
    pub record_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestBundle {
    pub requests: Vec<FileRequest>,
}

impl RequestBundle {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.requests.len() > MAX_TRANSFERS {
            return Err(ProtocolError::TransferLimit);
        }
        let mut previous = None;
        let mut writer = WireWriter::default();
        writer.count(self.requests.len())?;
        for request in &self.requests {
            validate_request(request)?;
            if previous.as_ref().is_some_and(|item| *item >= request) {
                return Err(ProtocolError::UnorderedRequests);
            }
            writer.string(&request.collection)?;
            writer.string(&request.path)?;
            writer.fixed(&request.record_hash);
            previous = Some(request);
        }
        Ok(writer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = WireReader::new(bytes);
        let count = reader.count(MAX_TRANSFERS)?;
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            let request = FileRequest {
                collection: reader.string(MAX_COLLECTION_NAME_BYTES)?,
                path: reader.string(MAX_PATH_BYTES)?,
                record_hash: reader.fixed()?,
            };
            validate_request(&request)?;
            if requests.last().is_some_and(|item| item >= &request) {
                return Err(ProtocolError::UnorderedRequests);
            }
            requests.push(request);
        }
        reader.finish()?;
        Ok(Self { requests })
    }
}

pub fn encode_file_header(record: &Record) -> Result<Vec<u8>, ProtocolError> {
    validate_record(record, record.collection())?;
    match record.kind() {
        crate::record::RecordKind::File { size, .. } if size <= MAX_FILE_BYTES => {}
        crate::record::RecordKind::File { .. } => return Err(ProtocolError::FileLimit),
        crate::record::RecordKind::Tombstone => return Err(ProtocolError::UnexpectedTombstone),
    }
    Ok(record.canonical_bytes())
}

pub fn decode_file_header(bytes: &[u8]) -> Result<Record, ProtocolError> {
    let record = Record::from_canonical(bytes)?;
    validate_record(&record, record.collection())?;
    match record.kind() {
        crate::record::RecordKind::File { size, .. } if size <= MAX_FILE_BYTES => Ok(record),
        crate::record::RecordKind::File { .. } => Err(ProtocolError::FileLimit),
        crate::record::RecordKind::Tombstone => Err(ProtocolError::UnexpectedTombstone),
    }
}

pub fn encode_file_unavailable(request: &FileRequest) -> Result<Vec<u8>, ProtocolError> {
    RequestBundle {
        requests: vec![request.clone()],
    }
    .encode()
}

pub fn decode_file_unavailable(bytes: &[u8]) -> Result<FileRequest, ProtocolError> {
    let mut requests = RequestBundle::decode(bytes)?.requests;
    if requests.len() != 1 {
        return Err(ProtocolError::UnexpectedFrame);
    }
    Ok(requests.remove(0))
}

fn validate_record(record: &Record, collection: &str) -> Result<(), ProtocolError> {
    validate_collection(collection)?;
    if record.collection() != collection {
        return Err(ProtocolError::WrongCollection);
    }
    if record.path().as_str().len() > MAX_PATH_BYTES {
        return Err(ProtocolError::PathLimit);
    }
    if let crate::record::RecordKind::File { size, .. } = record.kind()
        && size > MAX_FILE_BYTES
    {
        return Err(ProtocolError::FileLimit);
    }
    Ok(())
}

fn validate_request(request: &FileRequest) -> Result<(), ProtocolError> {
    validate_collection(&request.collection)?;
    if request.path.len() > MAX_PATH_BYTES {
        return Err(ProtocolError::PathLimit);
    }
    crate::path::ProtocolPath::parse(&request.path)?;
    Ok(())
}

fn validate_collections(collections: &[String]) -> Result<(), ProtocolError> {
    if collections.len() > MAX_COLLECTIONS {
        return Err(ProtocolError::CollectionLimit);
    }
    let mut previous: Option<&str> = None;
    for collection in collections {
        validate_collection(collection)?;
        if previous.is_some_and(|item| item >= collection.as_str()) {
            return Err(ProtocolError::UnorderedCollections);
        }
        previous = Some(collection);
    }
    Ok(())
}

fn validate_collection(collection: &str) -> Result<(), ProtocolError> {
    validate_short_string(collection, MAX_COLLECTION_NAME_BYTES)
}

fn validate_short_string(value: &str, limit: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > limit {
        return Err(ProtocolError::StringLimit);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveState {
    Hello,
    Roster,
    Manifests,
    Requests,
    Files { remaining: usize },
    Done,
    Finished,
}

impl ReceiveState {
    pub fn accept(&mut self, tag: FrameTag) -> Result<(), ProtocolError> {
        let valid = matches!(
            (*self, tag),
            (Self::Hello, FrameTag::Hello)
                | (Self::Roster, FrameTag::Roster)
                | (Self::Manifests, FrameTag::Manifests)
                | (Self::Requests, FrameTag::Requests)
                | (Self::Files { .. }, FrameTag::File)
                | (Self::Files { .. }, FrameTag::FileUnavailable)
                | (Self::Done, FrameTag::Done)
        );
        if !valid {
            return Err(ProtocolError::UnexpectedFrame);
        }
        *self = match *self {
            Self::Hello => Self::Roster,
            Self::Roster => Self::Manifests,
            Self::Manifests => Self::Requests,
            Self::Requests => Self::Files { remaining: 0 },
            Self::Files { remaining } if remaining > 1 => Self::Files {
                remaining: remaining - 1,
            },
            Self::Files { .. } => Self::Done,
            Self::Done => Self::Finished,
            Self::Finished => return Err(ProtocolError::UnexpectedFrame),
        };
        Ok(())
    }

    pub fn expect_files(&mut self, count: usize) -> Result<(), ProtocolError> {
        if count > MAX_TRANSFERS || !matches!(self, Self::Files { remaining: 0 }) {
            return Err(ProtocolError::UnexpectedFrame);
        }
        *self = if count == 0 {
            Self::Done
        } else {
            Self::Files { remaining: count }
        };
        Ok(())
    }
}

pub fn encode_frame(tag: FrameTag, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() > tag.payload_limit() || payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameLimit);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameLimit)?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(PROTOCOL_VERSION);
    bytes.push(tag as u8);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_frame(reader: &mut impl Read) -> Result<(FrameTag, Vec<u8>), ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    reader.read_exact(&mut header).map_err(map_truncation)?;
    let (tag, length) = decode_header(&header)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).map_err(map_truncation)?;
    Ok((tag, payload))
}

pub async fn write_frame_async(
    stream: &mut SendStream,
    tag: FrameTag,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let bytes = encode_frame(tag, payload)?;
    for chunk in bytes.chunks(64 * 1024) {
        tokio::time::timeout(IO_IDLE_TIMEOUT, stream.write_all(chunk))
            .await
            .map_err(|_| ProtocolError::Timeout)?
            .map_err(|_| ProtocolError::Transport)?;
    }
    Ok(())
}

pub async fn read_frame_async(
    stream: &mut RecvStream,
    received: &mut u64,
) -> Result<(FrameTag, Vec<u8>), ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    tokio::time::timeout(IO_IDLE_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| ProtocolError::Timeout)?
        .map_err(|_| ProtocolError::Truncated)?;
    let (tag, length) = decode_header(&header)?;
    add_received(received, HEADER_BYTES as u64 + length as u64)?;
    let mut payload = vec![0_u8; length];
    for chunk in payload.chunks_mut(64 * 1024) {
        tokio::time::timeout(IO_IDLE_TIMEOUT, stream.read_exact(chunk))
            .await
            .map_err(|_| ProtocolError::Timeout)?
            .map_err(|_| ProtocolError::Truncated)?;
    }
    Ok((tag, payload))
}

pub fn add_received(received: &mut u64, amount: u64) -> Result<(), ProtocolError> {
    *received = received
        .checked_add(amount)
        .ok_or(ProtocolError::ConnectionLimit)?;
    if *received > MAX_CONNECTION_BYTES {
        return Err(ProtocolError::ConnectionLimit);
    }
    Ok(())
}

fn decode_header(header: &[u8; HEADER_BYTES]) -> Result<(FrameTag, usize), ProtocolError> {
    if &header[..4] != MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    let tag = FrameTag::from_byte(header[5])?;
    let length = usize::try_from(u32::from_be_bytes(
        header[6..10].try_into().expect("length"),
    ))
    .map_err(|_| ProtocolError::FrameLimit)?;
    if length > MAX_FRAME_BYTES || length > tag.payload_limit() {
        return Err(ProtocolError::FrameLimit);
    }
    Ok((tag, length))
}

fn map_truncation(error: io::Error) -> ProtocolError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ProtocolError::Truncated
    } else {
        ProtocolError::Io(error)
    }
}

#[derive(Default)]
struct WireWriter {
    bytes: Vec<u8>,
}

impl WireWriter {
    fn fixed(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn count(&mut self, count: usize) -> Result<(), ProtocolError> {
        let count = u32::try_from(count).map_err(|_| ProtocolError::LengthOverflow)?;
        self.fixed(&count.to_be_bytes());
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.count(bytes.len())?;
        self.fixed(bytes);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), ProtocolError> {
        self.bytes(value.as_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn count(&mut self, limit: usize) -> Result<usize, ProtocolError> {
        let count = usize::try_from(u32::from_be_bytes(self.fixed()?))
            .map_err(|_| ProtocolError::LengthOverflow)?;
        if count > limit {
            return Err(ProtocolError::CountLimit);
        }
        Ok(count)
    }

    fn bytes(&mut self, limit: usize) -> Result<&'a [u8], ProtocolError> {
        let length = self.count(limit)?;
        self.take(length)
    }

    fn string(&mut self, limit: usize) -> Result<String, ProtocolError> {
        let bytes = self.bytes(limit)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol input is truncated")]
    Truncated,
    #[error("protocol input has trailing bytes")]
    TrailingBytes,
    #[error("protocol input has the wrong magic")]
    WrongMagic,
    #[error("protocol version is unsupported")]
    WrongVersion,
    #[error("protocol frame type is unknown")]
    UnknownFrameType,
    #[error("protocol frame arrived out of order")]
    UnexpectedFrame,
    #[error("protocol frame exceeds its limit")]
    FrameLimit,
    #[error("protocol connection exceeds its byte limit")]
    ConnectionLimit,
    #[error("protocol count exceeds its limit")]
    CountLimit,
    #[error("protocol length cannot be represented")]
    LengthOverflow,
    #[error("protocol string is not valid UTF-8")]
    InvalidUtf8,
    #[error("protocol string is empty or exceeds its limit")]
    StringLimit,
    #[error("protocol collection count exceeds its limit")]
    CollectionLimit,
    #[error("protocol collection names are not strictly ordered")]
    UnorderedCollections,
    #[error("protocol contains a duplicate collection")]
    DuplicateCollection,
    #[error("protocol manifest exceeds its limit")]
    ManifestLimit,
    #[error("protocol roster exceeds its limit")]
    RosterLimit,
    #[error("protocol roster is invalid")]
    InvalidRoster,
    #[error("protocol path exceeds its limit")]
    PathLimit,
    #[error("protocol record names the wrong collection")]
    WrongCollection,
    #[error("protocol file exceeds its limit")]
    FileLimit,
    #[error("protocol transfer count exceeds its limit")]
    TransferLimit,
    #[error("protocol requests are not strictly ordered")]
    UnorderedRequests,
    #[error("protocol file header contains a tombstone")]
    UnexpectedTombstone,
    #[error("protocol address hint exceeds its limit")]
    AddressHintTooLarge,
    #[error("protocol transport failed")]
    Transport,
    #[error("protocol transport made no progress before the idle timeout")]
    Timeout,
    #[error("protocol I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    Path(#[from] crate::path::PathError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::identity::DeviceIdentity;
    use crate::identity::EndpointId;
    use crate::path::ProtocolPath;

    use super::*;

    fn record(path: &str) -> Record {
        Record::file(
            ".agents",
            ProtocolPath::parse(path).unwrap(),
            7,
            EndpointId::from_bytes([3; 32]),
            4,
            [9; 32],
        )
        .unwrap()
    }

    #[test]
    fn frame_codec_rejects_truncation_version_type_and_limits_before_payload_read() {
        let valid = encode_frame(FrameTag::Hello, b"hello").unwrap();
        assert_eq!(
            decode_frame(&mut Cursor::new(&valid)).unwrap(),
            (FrameTag::Hello, b"hello".to_vec())
        );
        assert!(matches!(
            decode_frame(&mut Cursor::new(&valid[..8])),
            Err(ProtocolError::Truncated)
        ));
        let mut wrong_version = valid.clone();
        wrong_version[4] = 2;
        assert!(matches!(
            decode_frame(&mut Cursor::new(wrong_version)),
            Err(ProtocolError::WrongVersion)
        ));
        let mut wrong_type = valid.clone();
        wrong_type[5] = 99;
        assert!(matches!(
            decode_frame(&mut Cursor::new(wrong_type)),
            Err(ProtocolError::UnknownFrameType)
        ));
        let mut oversized = valid;
        oversized[6..10]
            .copy_from_slice(&(u32::try_from(MAX_FRAME_BYTES).unwrap() + 1).to_be_bytes());
        assert!(matches!(
            decode_frame(&mut Cursor::new(oversized)),
            Err(ProtocolError::FrameLimit)
        ));
    }

    #[test]
    fn receive_state_rejects_wrong_order_and_exactly_counts_files() {
        let mut state = ReceiveState::Hello;
        assert!(matches!(
            state.accept(FrameTag::Roster),
            Err(ProtocolError::UnexpectedFrame)
        ));
        state.accept(FrameTag::Hello).unwrap();
        state.accept(FrameTag::Roster).unwrap();
        state.accept(FrameTag::Manifests).unwrap();
        state.accept(FrameTag::Requests).unwrap();
        state.expect_files(2).unwrap();
        state.accept(FrameTag::File).unwrap();
        assert!(matches!(state, ReceiveState::Files { remaining: 1 }));
        state.accept(FrameTag::FileUnavailable).unwrap();
        state.accept(FrameTag::Done).unwrap();
        assert_eq!(state, ReceiveState::Finished);
    }

    #[test]
    fn manifest_rejects_wrong_collection_and_path_limit() {
        let wrong = ManifestBundle {
            manifests: vec![(
                ".codex".to_owned(),
                Manifest::new(vec![record("a")]).unwrap(),
            )],
        };
        assert!(matches!(
            wrong.encode(),
            Err(ProtocolError::WrongCollection)
        ));

        let long_path = "a".repeat(MAX_PATH_BYTES + 1);
        let long = record(&long_path);
        let bundle = ManifestBundle {
            manifests: vec![(".agents".to_owned(), Manifest::new(vec![long]).unwrap())],
        };
        assert!(matches!(bundle.encode(), Err(ProtocolError::PathLimit)));
    }

    #[test]
    fn roster_round_trip_validates_the_complete_chain() {
        let creator = DeviceIdentity::from_secret([1; 32]);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([2; 32]), "creator", &creator).unwrap();
        let bytes = RosterBundle {
            revisions: vec![genesis.clone()],
        }
        .encode()
        .unwrap();
        assert_eq!(
            RosterBundle::decode(&bytes).unwrap().revisions,
            vec![genesis]
        );
    }

    #[test]
    fn requests_must_be_unique_sorted_and_valid() {
        let request = FileRequest {
            collection: ".agents".to_owned(),
            path: "skill/SKILL.md".to_owned(),
            record_hash: [1; 32],
        };
        assert_eq!(
            decode_file_unavailable(&encode_file_unavailable(&request).unwrap()).unwrap(),
            request
        );
        let two_unavailable = RequestBundle {
            requests: vec![
                request.clone(),
                FileRequest {
                    collection: ".agents".to_owned(),
                    path: "skill/other.md".to_owned(),
                    record_hash: [2; 32],
                },
            ],
        }
        .encode()
        .unwrap();
        assert!(matches!(
            decode_file_unavailable(&two_unavailable),
            Err(ProtocolError::UnexpectedFrame)
        ));
        assert!(matches!(
            RequestBundle {
                requests: vec![request.clone(), request]
            }
            .encode(),
            Err(ProtocolError::UnorderedRequests)
        ));
    }
}
