use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::{Config, PlatformPaths};
use crate::identity::{DeviceIdentity, EndpointId, GroupId, IdentityError, IdentityStore};
use crate::roster::{RosterError, RosterRevision};
use crate::state::{OperationalEvent, StateError, StateStore};

pub const DEFAULT_COLLECTIONS: [(&str, &str); 3] = [
    (".agents", ".agents/skills"),
    (".claude", ".claude/skills"),
    (".codex", ".codex/skills"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupResult {
    pub device_name: String,
    pub endpoint_id: EndpointId,
    pub collections: Vec<(String, PathBuf)>,
    pub created: bool,
}

pub fn setup(paths: &PlatformPaths, config: &Config) -> Result<SetupResult, SetupError> {
    config.validate()?;
    fs::create_dir_all(&paths.data_dir)?;
    fs::create_dir_all(&paths.runtime_dir)?;

    let (identity, _) = IdentityStore::new(paths).load_or_create()?;
    let database = paths.data_dir.join("state.sqlite3");
    let mut state = StateStore::open(&database)?;
    let created = state.selected_roster_chain()?.is_empty();
    if created {
        let genesis =
            RosterRevision::genesis(GroupId::generate()?, config.device.name.clone(), &identity)?;
        state.insert_roster_revision(&genesis)?;
    }

    let collections = attach_default_collections(&mut state, config)?;

    let device_name = state
        .selected_roster_chain()?
        .last()
        .and_then(|revision| revision.members().get(&identity.endpoint_id()))
        .cloned()
        .unwrap_or_else(|| config.device.name.clone());
    Ok(SetupResult {
        device_name,
        endpoint_id: identity.endpoint_id(),
        collections,
        created,
    })
}

pub fn setup_joining_device(
    paths: &PlatformPaths,
    config: &Config,
) -> Result<SetupResult, SetupError> {
    config.validate()?;
    fs::create_dir_all(&paths.data_dir)?;
    fs::create_dir_all(&paths.runtime_dir)?;
    let (identity, _) = IdentityStore::new(paths).load_or_create()?;
    let database = paths.data_dir.join("state.sqlite3");
    let mut state = StateStore::open(&database)?;
    let existing_roster = state.selected_roster_chain()?;
    let existing_name = existing_roster
        .last()
        .and_then(|tip| tip.members().get(&identity.endpoint_id()))
        .cloned();
    if !existing_roster.is_empty() && existing_name.is_none() {
        return Err(SetupError::LocalDeviceRemoved);
    }
    let collections = attach_default_collections(&mut state, config)?;
    Ok(SetupResult {
        device_name: existing_name
            .clone()
            .unwrap_or_else(|| config.device.name.clone()),
        endpoint_id: identity.endpoint_id(),
        collections,
        created: existing_name.is_none(),
    })
}

fn attach_default_collections(
    state: &mut StateStore,
    config: &Config,
) -> Result<Vec<(String, PathBuf)>, SetupError> {
    let home = env::var_os("HOME").ok_or(SetupError::MissingHome)?;
    let mut collections = Vec::new();
    for (name, relative) in DEFAULT_COLLECTIONS {
        let local_path = Path::new(&home).join(relative);
        match state.collection(name)? {
            Some(existing) => collections.push((name.to_owned(), existing.local_path)),
            None => {
                fs::create_dir_all(&local_path)?;
                let resolved = fs::canonicalize(&local_path)?;
                state.add_collection(name, &local_path, Some(&resolved))?;
                state.append_log(
                    now_ns(),
                    &OperationalEvent::CollectionAttached {
                        collection: name.to_owned(),
                    },
                    config.logging.max_entries,
                )?;
                collections.push((name.to_owned(), local_path));
            }
        }
    }
    Ok(collections)
}

pub fn load_identity(paths: &PlatformPaths) -> Result<DeviceIdentity, SetupError> {
    let (identity, _) = IdentityStore::new(paths).load_or_create()?;
    Ok(identity)
}

pub fn load_identity_from_data_dir(data_dir: &Path) -> Result<DeviceIdentity, SetupError> {
    let paths = PlatformPaths {
        config_file: data_dir.join("unused-config.toml"),
        data_dir: data_dir.to_path_buf(),
        runtime_dir: data_dir.join("unused-run"),
    };
    load_identity(&paths)
}

pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("HOME is not set")]
    MissingHome,
    #[error("setup I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("this device has been removed from its group")]
    LocalDeviceRemoved,
}
