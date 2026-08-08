use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::canonical::{CanonicalError, Decoder, Encoder};
use crate::identity::{DeviceIdentity, EndpointId, GroupId};

const ROSTER_DOMAIN: &[u8] = b"skillsync-roster-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterMember {
    pub endpoint_id: EndpointId,
    pub device_name: String,
}

impl RosterMember {
    pub fn new(
        endpoint_id: EndpointId,
        device_name: impl Into<String>,
    ) -> Result<Self, RosterError> {
        let device_name = device_name.into();
        validate_device_name(&device_name)?;
        Ok(Self {
            endpoint_id,
            device_name,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RosterChange {
    Initialize(RosterMember),
    Admit(RosterMember),
    Remove(EndpointId),
}

impl RosterChange {
    fn selection_priority(&self) -> u8 {
        match self {
            Self::Remove(_) => 1,
            Self::Admit(_) => 0,
            Self::Initialize(_) => 0,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RosterRevision {
    group_id: GroupId,
    number: u64,
    parent_hash: Option<RosterHash>,
    members: BTreeMap<EndpointId, String>,
    change: RosterChange,
    author: EndpointId,
    signature: [u8; 64],
}

impl RosterRevision {
    pub fn genesis(
        group_id: GroupId,
        creator_name: impl Into<String>,
        creator: &DeviceIdentity,
    ) -> Result<Self, RosterError> {
        let member = RosterMember::new(creator.endpoint_id(), creator_name)?;
        let members = BTreeMap::from([(member.endpoint_id, member.device_name.clone())]);
        let mut revision = Self {
            group_id,
            number: 0,
            parent_hash: None,
            members,
            change: RosterChange::Initialize(member),
            author: creator.endpoint_id(),
            signature: [0; 64],
        };
        revision.signature = creator.sign(&revision.unsigned_canonical_bytes());
        revision.validate_genesis()?;
        Ok(revision)
    }

    pub fn child(
        parent: &Self,
        change: RosterChange,
        author: &DeviceIdentity,
    ) -> Result<Self, RosterError> {
        if !parent.members.contains_key(&author.endpoint_id()) {
            return Err(RosterError::AuthorNotActive);
        }
        if matches!(change, RosterChange::Initialize(_)) {
            return Err(RosterError::InvalidChange);
        }
        let mut members = parent.members.clone();
        apply_change(&mut members, &change)?;
        let mut revision = Self {
            group_id: parent.group_id,
            number: parent
                .number
                .checked_add(1)
                .ok_or(RosterError::RevisionOverflow)?,
            parent_hash: Some(parent.canonical_hash()),
            members,
            change,
            author: author.endpoint_id(),
            signature: [0; 64],
        };
        revision.signature = author.sign(&revision.unsigned_canonical_bytes());
        revision.validate_child(parent)?;
        Ok(revision)
    }

    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub const fn number(&self) -> u64 {
        self.number
    }

    pub const fn parent_hash(&self) -> Option<RosterHash> {
        self.parent_hash
    }

    pub fn members(&self) -> &BTreeMap<EndpointId, String> {
        &self.members
    }

    pub const fn change(&self) -> &RosterChange {
        &self.change
    }

    pub const fn author(&self) -> EndpointId {
        self.author
    }

    pub fn validate_genesis(&self) -> Result<(), RosterError> {
        if self.number != 0 || self.parent_hash.is_some() {
            return Err(RosterError::InvalidGenesis);
        }
        let RosterChange::Initialize(creator) = &self.change else {
            return Err(RosterError::InvalidGenesis);
        };
        if self.author != creator.endpoint_id
            || self.members.len() != 1
            || self.members.get(&creator.endpoint_id) != Some(&creator.device_name)
        {
            return Err(RosterError::InvalidGenesis);
        }
        self.verify_signature(self.author)
    }

    pub fn validate_child(&self, parent: &Self) -> Result<(), RosterError> {
        if self.group_id != parent.group_id
            || self.number
                != parent
                    .number
                    .checked_add(1)
                    .ok_or(RosterError::RevisionOverflow)?
            || self.parent_hash != Some(parent.canonical_hash())
        {
            return Err(RosterError::WrongParent);
        }
        if !parent.members.contains_key(&self.author) {
            return Err(RosterError::AuthorNotActive);
        }
        if matches!(self.change, RosterChange::Initialize(_)) {
            return Err(RosterError::InvalidChange);
        }
        let mut expected_members = parent.members.clone();
        apply_change(&mut expected_members, &self.change)?;
        if expected_members != self.members {
            return Err(RosterError::WrongMembers);
        }
        self.verify_signature(self.author)
    }

    pub fn canonical_hash(&self) -> RosterHash {
        RosterHash(*blake3::hash(&self.canonical_bytes()).as_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_canonical_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, RosterError> {
        let mut decoder = Decoder::new(bytes, ROSTER_DOMAIN)?;
        let group_id = GroupId::from_bytes(decoder.fixed()?);
        let number = decoder.u64()?;
        let parent_hash = match decoder.u8()? {
            0 => None,
            1 => Some(RosterHash::from_bytes(decoder.fixed()?)),
            _ => return Err(CanonicalError::UnknownTag.into()),
        };
        let member_count = usize::try_from(decoder.u32()?)
            .map_err(|_| CanonicalError::Invalid("member count cannot be represented"))?;
        let mut members = BTreeMap::new();
        let mut previous = None;
        for _ in 0..member_count {
            let endpoint_id = EndpointId::from_bytes(decoder.fixed()?);
            if previous.is_some_and(|previous| previous >= endpoint_id) {
                return Err(CanonicalError::UnorderedKeys.into());
            }
            let device_name = decoder.string()?;
            validate_device_name(&device_name)?;
            members.insert(endpoint_id, device_name);
            previous = Some(endpoint_id);
        }
        let change = decode_change(&mut decoder)?;
        let author = EndpointId::from_bytes(decoder.fixed()?);
        let signature = decoder.fixed()?;
        decoder.finish()?;
        let revision = Self {
            group_id,
            number,
            parent_hash,
            members,
            change,
            author,
            signature,
        };
        if revision.canonical_bytes() != bytes {
            return Err(CanonicalError::Invalid("non-canonical roster revision").into());
        }
        Ok(revision)
    }

    fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(ROSTER_DOMAIN);
        encoder.fixed(self.group_id.as_bytes());
        encoder.u64(self.number);
        match self.parent_hash {
            None => encoder.u8(0),
            Some(parent_hash) => {
                encoder.u8(1);
                encoder.fixed(parent_hash.as_bytes());
            }
        }
        encoder.u32(
            u32::try_from(self.members.len()).expect("roster cannot contain more u32 members"),
        );
        for (endpoint_id, device_name) in &self.members {
            encoder.fixed(endpoint_id.as_bytes());
            encoder
                .string(device_name)
                .expect("device name length was validated");
        }
        encode_change(&mut encoder, &self.change);
        encoder.fixed(self.author.as_bytes());
        encoder.finish()
    }

    fn verify_signature(&self, signer: EndpointId) -> Result<(), RosterError> {
        let verifying_key =
            VerifyingKey::from_bytes(signer.as_bytes()).map_err(|_| RosterError::InvalidSigner)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&self.unsigned_canonical_bytes(), &signature)
            .map_err(|_| RosterError::InvalidSignature)
    }
}

impl fmt::Debug for RosterRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RosterRevision")
            .field("group_id", &self.group_id)
            .field("number", &self.number)
            .field("parent_hash", &self.parent_hash)
            .field("members", &self.members)
            .field("change", &self.change)
            .field("author", &self.author)
            .field("signature", &"[signature]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RosterHash([u8; 32]);

impl RosterHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RosterHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub fn select_child<'a>(
    parent: &RosterRevision,
    candidates: impl IntoIterator<Item = &'a RosterRevision>,
) -> Option<&'a RosterRevision> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.validate_child(parent).is_ok())
        .max_by_key(|candidate| {
            (
                candidate.change.selection_priority(),
                candidate.canonical_hash(),
            )
        })
}

pub fn select_chain<'a>(
    genesis: &'a RosterRevision,
    candidates: &'a [RosterRevision],
) -> Result<Vec<&'a RosterRevision>, RosterError> {
    genesis.validate_genesis()?;
    let mut selected = Vec::new();
    let mut parent = genesis;
    while let Some(child) = select_child(parent, candidates) {
        selected.push(child);
        parent = child;
    }
    Ok(selected)
}

fn apply_change(
    members: &mut BTreeMap<EndpointId, String>,
    change: &RosterChange,
) -> Result<(), RosterError> {
    match change {
        RosterChange::Initialize(_) => Err(RosterError::InvalidChange),
        RosterChange::Admit(member) => {
            validate_device_name(&member.device_name)?;
            if members.contains_key(&member.endpoint_id) {
                return Err(RosterError::AlreadyActive);
            }
            members.insert(member.endpoint_id, member.device_name.clone());
            Ok(())
        }
        RosterChange::Remove(endpoint_id) => {
            if members.remove(endpoint_id).is_none() {
                return Err(RosterError::NotActive);
            }
            Ok(())
        }
    }
}

fn encode_change(encoder: &mut Encoder, change: &RosterChange) {
    match change {
        RosterChange::Initialize(member) => {
            encoder.u8(0);
            encode_member(encoder, member);
        }
        RosterChange::Admit(member) => {
            encoder.u8(1);
            encode_member(encoder, member);
        }
        RosterChange::Remove(endpoint_id) => {
            encoder.u8(2);
            encoder.fixed(endpoint_id.as_bytes());
        }
    }
}

fn encode_member(encoder: &mut Encoder, member: &RosterMember) {
    encoder.fixed(member.endpoint_id.as_bytes());
    encoder
        .string(&member.device_name)
        .expect("device name length was validated");
}

fn decode_change(decoder: &mut Decoder<'_>) -> Result<RosterChange, RosterError> {
    match decoder.u8()? {
        0 => Ok(RosterChange::Initialize(decode_member(decoder)?)),
        1 => Ok(RosterChange::Admit(decode_member(decoder)?)),
        2 => Ok(RosterChange::Remove(EndpointId::from_bytes(
            decoder.fixed()?,
        ))),
        _ => Err(CanonicalError::UnknownTag.into()),
    }
}

fn decode_member(decoder: &mut Decoder<'_>) -> Result<RosterMember, RosterError> {
    RosterMember::new(EndpointId::from_bytes(decoder.fixed()?), decoder.string()?)
}

fn validate_device_name(device_name: &str) -> Result<(), RosterError> {
    if device_name.trim().is_empty() {
        return Err(RosterError::InvalidDeviceName);
    }
    u32::try_from(device_name.len()).map_err(|_| RosterError::InvalidDeviceName)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum RosterError {
    #[error("genesis roster revision is invalid")]
    InvalidGenesis,
    #[error("roster child does not extend its claimed parent")]
    WrongParent,
    #[error("roster revision author is not active in its parent")]
    AuthorNotActive,
    #[error("roster revision member set does not match its change")]
    WrongMembers,
    #[error("roster revision change is invalid at this position")]
    InvalidChange,
    #[error("device is already active")]
    AlreadyActive,
    #[error("device is not active")]
    NotActive,
    #[error("device name must not be empty")]
    InvalidDeviceName,
    #[error("roster revision number overflowed")]
    RevisionOverflow,
    #[error("roster revision signer is not a valid Ed25519 public key")]
    InvalidSigner,
    #[error("roster revision signature is invalid")]
    InvalidSignature,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret([byte; 32])
    }

    fn admission(identity: &DeviceIdentity, name: &str) -> RosterChange {
        RosterChange::Admit(RosterMember::new(identity.endpoint_id(), name).unwrap())
    }

    #[test]
    fn genesis_is_self_signed_and_round_trips() {
        let creator = identity(1);
        let revision =
            RosterRevision::genesis(GroupId::from_bytes([9; 32]), "creator", &creator).unwrap();
        revision.validate_genesis().unwrap();
        assert_eq!(
            RosterRevision::from_canonical(&revision.canonical_bytes()).unwrap(),
            revision
        );
    }

    #[test]
    fn signature_and_complete_membership_are_validated() {
        let creator = identity(1);
        let joining = identity(2);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([9; 32]), "creator", &creator).unwrap();
        let child =
            RosterRevision::child(&genesis, admission(&joining, "laptop"), &creator).unwrap();
        child.validate_child(&genesis).unwrap();

        let mut tampered_signature = child.clone();
        tampered_signature.signature[0] ^= 1;
        assert!(matches!(
            tampered_signature.validate_child(&genesis),
            Err(RosterError::InvalidSignature)
        ));

        let mut tampered_members = child;
        tampered_members
            .members
            .insert(identity(3).endpoint_id(), "extra".to_owned());
        assert!(matches!(
            tampered_members.validate_child(&genesis),
            Err(RosterError::WrongMembers)
        ));
    }

    #[test]
    fn removal_wins_every_candidate_permutation() {
        let creator = identity(1);
        let first = identity(2);
        let second = identity(3);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([8; 32]), "creator", &creator).unwrap();
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
        let permutations = [
            [&admit_first, &admit_second, &removal],
            [&admit_first, &removal, &admit_second],
            [&admit_second, &admit_first, &removal],
            [&admit_second, &removal, &admit_first],
            [&removal, &admit_first, &admit_second],
            [&removal, &admit_second, &admit_first],
        ];
        for permutation in permutations {
            assert_eq!(
                select_child(&genesis, permutation)
                    .unwrap()
                    .canonical_hash(),
                removal.canonical_hash()
            );
        }
    }

    #[test]
    fn same_kind_tie_uses_greater_revision_hash() {
        let creator = identity(1);
        let first = identity(2);
        let second = identity(3);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([8; 32]), "creator", &creator).unwrap();
        let left = RosterRevision::child(&genesis, admission(&first, "first"), &creator).unwrap();
        let right =
            RosterRevision::child(&genesis, admission(&second, "second"), &creator).unwrap();
        let expected = left.canonical_hash().max(right.canonical_hash());
        assert_eq!(
            select_child(&genesis, [&left, &right])
                .unwrap()
                .canonical_hash(),
            expected
        );
        assert_eq!(
            select_child(&genesis, [&right, &left])
                .unwrap()
                .canonical_hash(),
            expected
        );
    }

    #[test]
    fn descendants_of_a_losing_child_cannot_extend_selected_chain() {
        let creator = identity(1);
        let first = identity(2);
        let second = identity(3);
        let third = identity(4);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([8; 32]), "creator", &creator).unwrap();
        let left = RosterRevision::child(&genesis, admission(&first, "first"), &creator).unwrap();
        let right =
            RosterRevision::child(&genesis, admission(&second, "second"), &creator).unwrap();
        let (winner, loser) = if left.canonical_hash() > right.canonical_hash() {
            (left.clone(), right)
        } else {
            (right.clone(), left)
        };
        let stale_descendant =
            RosterRevision::child(&loser, admission(&third, "third"), &creator).unwrap();
        let candidates = vec![loser, stale_descendant, winner.clone()];
        let chain = select_chain(&genesis, &candidates).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].canonical_hash(), winner.canonical_hash());
    }

    #[test]
    fn removed_author_cannot_extend_revision() {
        let creator = identity(1);
        let remaining = identity(2);
        let genesis =
            RosterRevision::genesis(GroupId::from_bytes([8; 32]), "creator", &creator).unwrap();
        let admission =
            RosterRevision::child(&genesis, admission(&remaining, "remaining"), &creator).unwrap();
        let removal = RosterRevision::child(
            &admission,
            RosterChange::Remove(creator.endpoint_id()),
            &remaining,
        )
        .unwrap();
        assert!(matches!(
            RosterRevision::child(
                &removal,
                RosterChange::Remove(remaining.endpoint_id()),
                &creator
            ),
            Err(RosterError::AuthorNotActive)
        ));
    }
}
