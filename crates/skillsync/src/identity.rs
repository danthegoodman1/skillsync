use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

use crate::config::PlatformPaths;

const KEYRING_SERVICE: &str = "skillsync-device-identity";
const SECRET_LENGTH: usize = 32;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointId([u8; 32]);

impl EndpointId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for EndpointId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(IdentityError::InvalidEndpointId);
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output = (hex_nibble(value.as_bytes()[offset])? << 4)
                | hex_nibble(value.as_bytes()[offset + 1])?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GroupId([u8; 32]);

impl GroupId {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| IdentityError::Random)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub struct DeviceIdentity {
    signing_key: SigningKey,
    endpoint_id: EndpointId,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut secret = [0_u8; SECRET_LENGTH];
        getrandom::fill(&mut secret).map_err(|_| IdentityError::Random)?;
        Ok(Self::from_secret(secret))
    }

    pub fn from_secret(secret: [u8; SECRET_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        let endpoint_id = EndpointId(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            endpoint_id,
        }
    }

    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn secret_bytes(&self) -> [u8; SECRET_LENGTH] {
        self.signing_key.to_bytes()
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("endpoint_id", &self.endpoint_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityReference {
    Keyring { account: String },
    File { path: PathBuf },
}

pub struct IdentityStore {
    data_dir: PathBuf,
}

impl IdentityStore {
    pub fn new(paths: &PlatformPaths) -> Self {
        Self {
            data_dir: paths.data_dir.clone(),
        }
    }

    pub fn load_or_create(&self) -> Result<(DeviceIdentity, IdentityReference), IdentityError> {
        fs::create_dir_all(&self.data_dir)?;
        let reference_path = self.data_dir.join("identity.ref");
        if reference_path.exists() {
            return self.load_referenced(&reference_path);
        }

        let secret_path = self.data_dir.join("identity.key");
        if secret_path.exists() {
            let identity = identity_from_slice(&read_owner_only(&secret_path)?)?;
            write_owner_only(&reference_path, b"file\nidentity.key\n")?;
            return Ok((identity, IdentityReference::File { path: secret_path }));
        }

        let account = keyring_account(&self.data_dir);
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &account) {
            match entry.get_secret() {
                Ok(secret) => {
                    let identity = identity_from_slice(&secret)?;
                    write_owner_only(&reference_path, format!("keyring\n{account}\n").as_bytes())?;
                    return Ok((identity, IdentityReference::Keyring { account }));
                }
                Err(keyring::Error::NoEntry) => {
                    let identity = DeviceIdentity::generate()?;
                    if entry.set_secret(&identity.secret_bytes()).is_ok() {
                        write_owner_only(
                            &reference_path,
                            format!("keyring\n{account}\n").as_bytes(),
                        )?;
                        return Ok((identity, IdentityReference::Keyring { account }));
                    }
                    return self.persist_file_identity(identity, reference_path, secret_path);
                }
                Err(_) => {}
            }
        }

        self.persist_file_identity(DeviceIdentity::generate()?, reference_path, secret_path)
    }

    fn load_referenced(
        &self,
        reference_path: &Path,
    ) -> Result<(DeviceIdentity, IdentityReference), IdentityError> {
        let reference = fs::read_to_string(reference_path)?;
        let mut lines = reference.lines();
        match (lines.next(), lines.next(), lines.next()) {
            (Some("keyring"), Some(account), None) => {
                let entry = keyring::Entry::new(KEYRING_SERVICE, account)
                    .map_err(|_| IdentityError::KeyringUnavailable)?;
                let secret = entry
                    .get_secret()
                    .map_err(|_| IdentityError::KeyringUnavailable)?;
                let identity = identity_from_slice(&secret)?;
                Ok((
                    identity,
                    IdentityReference::Keyring {
                        account: account.to_owned(),
                    },
                ))
            }
            (Some("file"), Some(relative), None) => {
                let relative = Path::new(relative);
                if relative.is_absolute() || relative.components().count() != 1 {
                    return Err(IdentityError::InvalidReference);
                }
                let path = self.data_dir.join(relative);
                let secret = read_owner_only(&path)?;
                Ok((
                    identity_from_slice(&secret)?,
                    IdentityReference::File { path },
                ))
            }
            _ => Err(IdentityError::InvalidReference),
        }
    }

    fn persist_file_identity(
        &self,
        identity: DeviceIdentity,
        reference_path: PathBuf,
        secret_path: PathBuf,
    ) -> Result<(DeviceIdentity, IdentityReference), IdentityError> {
        write_owner_only(&secret_path, &identity.secret_bytes())?;
        write_owner_only(&reference_path, b"file\nidentity.key\n")?;
        Ok((identity, IdentityReference::File { path: secret_path }))
    }
}

fn identity_from_slice(secret: &[u8]) -> Result<DeviceIdentity, IdentityError> {
    let secret: [u8; SECRET_LENGTH] = secret
        .try_into()
        .map_err(|_| IdentityError::InvalidSecret)?;
    Ok(DeviceIdentity::from_secret(secret))
}

fn keyring_account(data_dir: &Path) -> String {
    let path = data_dir.as_os_str().as_encoded_bytes();
    blake3::hash(path).to_hex().to_string()
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_owner_only(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(IdentityError::UnsafePermissions);
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(path)?
        .take((SECRET_LENGTH + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, IdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(IdentityError::InvalidEndpointId),
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("secure random generation failed")]
    Random,
    #[error("identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the operating-system secret store for this identity is unavailable")]
    KeyringUnavailable,
    #[error("identity reference is invalid")]
    InvalidReference,
    #[error("identity secret has the wrong length")]
    InvalidSecret,
    #[error("identity secret file has group or other permissions")]
    UnsafePermissions,
    #[error("EndpointID must contain exactly 64 hexadecimal characters")]
    InvalidEndpointId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(root: &Path) -> PlatformPaths {
        PlatformPaths {
            config_file: root.join("config.toml"),
            data_dir: root.join("data"),
            runtime_dir: root.join("run"),
        }
    }

    #[test]
    fn endpoint_id_round_trips_as_hex() {
        let identity = DeviceIdentity::from_secret([7; 32]);
        let text = identity.endpoint_id().to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<EndpointId>().unwrap(), identity.endpoint_id());
    }

    #[test]
    fn debug_never_contains_secret_bytes() {
        let identity = DeviceIdentity::from_secret([0x5a; 32]);
        let debug = format!("{identity:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(&"5a".repeat(32)));
    }

    #[test]
    fn file_reference_reopens_the_same_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = test_paths(temporary.path());
        fs::create_dir_all(&paths.data_dir).unwrap();
        let identity = DeviceIdentity::from_secret([9; 32]);
        write_owner_only(
            &paths.data_dir.join("identity.key"),
            &identity.secret_bytes(),
        )
        .unwrap();
        write_owner_only(
            &paths.data_dir.join("identity.ref"),
            b"file\nidentity.key\n",
        )
        .unwrap();

        let (reopened, reference) = IdentityStore::new(&paths).load_or_create().unwrap();
        assert_eq!(reopened.endpoint_id(), identity.endpoint_id());
        assert!(matches!(reference, IdentityReference::File { .. }));
        assert_eq!(
            fs::metadata(paths.data_dir.join("identity.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[test]
    fn rejects_secret_file_with_broad_permissions() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = test_paths(temporary.path());
        fs::create_dir_all(&paths.data_dir).unwrap();
        let secret_path = paths.data_dir.join("identity.key");
        fs::write(&secret_path, [1; 32]).unwrap();
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(paths.data_dir.join("identity.ref"), "file\nidentity.key\n").unwrap();

        let error = IdentityStore::new(&paths).load_or_create().unwrap_err();
        assert!(matches!(error, IdentityError::UnsafePermissions));
    }
}
