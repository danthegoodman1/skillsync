use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;

use crate::canonical::{CanonicalError, Decoder, Encoder};
use crate::identity::EndpointId;
use crate::path::{PathError, ProtocolPath};

const RECORD_DOMAIN: &[u8] = b"skillsync-record-v1\0";
const MANIFEST_DOMAIN: &[u8] = b"skillsync-manifest-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    File { size: u64, content_hash: [u8; 32] },
    Tombstone,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Record {
    collection: String,
    path: ProtocolPath,
    modified_ns: i64,
    author: EndpointId,
    kind: RecordKind,
}

impl Record {
    pub fn file(
        collection: impl Into<String>,
        path: ProtocolPath,
        modified_ns: i64,
        author: EndpointId,
        size: u64,
        content_hash: [u8; 32],
    ) -> Result<Self, RecordError> {
        Self::new(
            collection.into(),
            path,
            modified_ns,
            author,
            RecordKind::File { size, content_hash },
        )
    }

    pub fn tombstone(
        collection: impl Into<String>,
        path: ProtocolPath,
        modified_ns: i64,
        author: EndpointId,
    ) -> Result<Self, RecordError> {
        Self::new(
            collection.into(),
            path,
            modified_ns,
            author,
            RecordKind::Tombstone,
        )
    }

    fn new(
        collection: String,
        path: ProtocolPath,
        modified_ns: i64,
        author: EndpointId,
        kind: RecordKind,
    ) -> Result<Self, RecordError> {
        if collection.is_empty() {
            return Err(RecordError::EmptyCollection);
        }
        ensure_u32_length(collection.len())?;
        ensure_u32_length(path.as_str().len())?;
        if let RecordKind::File { size, .. } = kind {
            i64::try_from(size).map_err(|_| RecordError::FileTooLarge)?;
        }
        Ok(Self {
            collection,
            path,
            modified_ns,
            author,
            kind,
        })
    }

    pub fn collection(&self) -> &str {
        &self.collection
    }

    pub fn path(&self) -> &ProtocolPath {
        &self.path
    }

    pub const fn modified_ns(&self) -> i64 {
        self.modified_ns
    }

    pub const fn author(&self) -> EndpointId {
        self.author
    }

    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(RECORD_DOMAIN);
        encoder
            .string(&self.collection)
            .expect("record collection length was validated");
        encoder
            .string(self.path.as_str())
            .expect("record path length was validated");
        encoder.i64(self.modified_ns);
        encoder.fixed(self.author.as_bytes());
        match self.kind {
            RecordKind::Tombstone => encoder.u8(0),
            RecordKind::File { size, content_hash } => {
                encoder.u8(1);
                encoder.u64(size);
                encoder.fixed(&content_hash);
            }
        }
        encoder.finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes, RECORD_DOMAIN)?;
        let collection = decoder.string()?;
        let path = ProtocolPath::parse(&decoder.string()?)?;
        let modified_ns = decoder.i64()?;
        let author = EndpointId::from_bytes(decoder.fixed()?);
        let kind = match decoder.u8()? {
            0 => RecordKind::Tombstone,
            1 => RecordKind::File {
                size: decoder.u64()?,
                content_hash: decoder.fixed()?,
            },
            _ => return Err(CanonicalError::UnknownTag.into()),
        };
        decoder.finish()?;
        Self::new(collection, path, modified_ns, author, kind)
    }

    pub fn canonical_hash(&self) -> RecordHash {
        RecordHash(*blake3::hash(&self.canonical_bytes()).as_bytes())
    }

    pub fn compare_winner(&self, other: &Self) -> Ordering {
        self.modified_ns
            .cmp(&other.modified_ns)
            .then_with(|| self.author.cmp(&other.author))
            .then_with(|| self.canonical_hash().cmp(&other.canonical_hash()))
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Record")
            .field("collection", &self.collection)
            .field("path", &self.path)
            .field("modified_ns", &self.modified_ns)
            .field("author", &self.author)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordHash([u8; 32]);

impl RecordHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RecordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    records: Vec<Record>,
}

impl Manifest {
    pub fn new(mut records: Vec<Record>) -> Result<Self, RecordError> {
        records.sort_by(|left, right| {
            (&left.collection, &left.path).cmp(&(&right.collection, &right.path))
        });
        let mut keys = BTreeSet::new();
        for record in &records {
            if !keys.insert((&record.collection, &record.path)) {
                return Err(RecordError::DuplicatePath);
            }
        }
        Ok(Self { records })
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(MANIFEST_DOMAIN);
        encoder.u32(
            u32::try_from(self.records.len()).expect("manifest cannot contain more u32 records"),
        );
        for record in &self.records {
            encoder
                .sized_bytes(&record.canonical_bytes())
                .expect("record encoding length fits u32");
        }
        encoder.finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes, MANIFEST_DOMAIN)?;
        let count = usize::try_from(decoder.u32()?)
            .map_err(|_| CanonicalError::Invalid("manifest count cannot be represented"))?;
        let mut records = Vec::new();
        for _ in 0..count {
            records.push(Record::from_canonical(decoder.sized_bytes()?)?);
        }
        decoder.finish()?;
        let manifest = Self::new(records)?;
        if manifest.canonical_bytes() != bytes {
            return Err(CanonicalError::UnorderedKeys.into());
        }
        Ok(manifest)
    }
}

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("collection name must not be empty")]
    EmptyCollection,
    #[error("record field is too long")]
    LengthOverflow,
    #[error("file size is too large to persist")]
    FileTooLarge,
    #[error("manifest contains the same collection path more than once")]
    DuplicatePath,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    #[error(transparent)]
    Path(#[from] PathError),
}

fn ensure_u32_length(length: usize) -> Result<(), RecordError> {
    u32::try_from(length)
        .map(|_| ())
        .map_err(|_| RecordError::LengthOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(byte: u8) -> EndpointId {
        EndpointId::from_bytes([byte; 32])
    }

    fn file(timestamp: i64, author: u8, hash: u8) -> Record {
        Record::file(
            ".agents",
            ProtocolPath::parse("review/SKILL.md").unwrap(),
            timestamp,
            endpoint(author),
            4,
            [hash; 32],
        )
        .unwrap()
    }

    #[test]
    fn record_order_is_total_for_files_and_tombstones() {
        let candidates = [
            file(10, 1, 1),
            file(11, 0, 0),
            file(11, 2, 1),
            file(11, 2, 2),
            Record::tombstone(
                ".agents",
                ProtocolPath::parse("review/SKILL.md").unwrap(),
                11,
                endpoint(2),
            )
            .unwrap(),
        ];
        for (left_index, left) in candidates.iter().enumerate() {
            for (right_index, right) in candidates.iter().enumerate() {
                let ordering = left.compare_winner(right);
                assert_eq!(ordering, right.compare_winner(left).reverse());
                if left_index == right_index {
                    assert_eq!(ordering, Ordering::Equal);
                } else {
                    assert_ne!(ordering, Ordering::Equal);
                }
            }
        }
        assert_eq!(
            candidates
                .iter()
                .max_by(|left, right| left.compare_winner(right))
                .unwrap()
                .modified_ns(),
            11
        );
    }

    #[test]
    fn record_encoding_round_trips_and_rejects_trailing_data() {
        let record = file(1_700_000_000_000_000_000, 3, 7);
        let encoded = record.canonical_bytes();
        assert_eq!(Record::from_canonical(&encoded).unwrap(), record);
        let mut extended = encoded;
        extended.push(0);
        assert!(Record::from_canonical(&extended).is_err());
    }

    #[test]
    fn manifest_encoding_is_independent_of_input_order() {
        let first = file(10, 1, 1);
        let second = Record::file(
            ".codex",
            ProtocolPath::parse("other/SKILL.md").unwrap(),
            12,
            endpoint(2),
            9,
            [8; 32],
        )
        .unwrap();
        let forward = Manifest::new(vec![first.clone(), second.clone()]).unwrap();
        let reverse = Manifest::new(vec![second, first]).unwrap();
        assert_eq!(forward.canonical_bytes(), reverse.canonical_bytes());
        assert_eq!(
            Manifest::from_canonical(&forward.canonical_bytes()).unwrap(),
            forward
        );
    }

    #[test]
    fn manifest_rejects_duplicate_paths() {
        let record = file(10, 1, 1);
        assert!(matches!(
            Manifest::new(vec![record.clone(), record]),
            Err(RecordError::DuplicatePath)
        ));
    }
}
