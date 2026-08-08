use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt};
use thiserror::Error;

const OPEN_ATTEMPTS: usize = 8;

pub(crate) struct StableRoot {
    pub directory: Dir,
    pub resolved_path: PathBuf,
}

pub(crate) fn open_stable_root_with_hook(
    path: &Path,
    hook: &mut (impl FnMut() -> io::Result<()> + ?Sized),
) -> Result<StableRoot, StableRootError> {
    let mut last_open_error = None;
    for _ in 0..OPEN_ATTEMPTS {
        let configured = match Dir::open_ambient_dir(path, ambient_authority()) {
            Ok(directory) => directory,
            Err(error) => {
                last_open_error = Some(error);
                std::thread::yield_now();
                continue;
            }
        };
        let configured_metadata = configured.dir_metadata()?;
        hook()?;
        let resolved_path = fs::canonicalize(path).map_err(|_| StableRootError::Unstable)?;
        let resolved_directory = Dir::open_ambient_dir(&resolved_path, ambient_authority())
            .map_err(|_| StableRootError::Unstable)?;
        let resolved_metadata = resolved_directory
            .dir_metadata()
            .map_err(|_| StableRootError::Unstable)?;
        let resolved_after = fs::canonicalize(path).map_err(|_| StableRootError::Unstable)?;
        if resolved_path == resolved_after
            && configured_metadata.dev() == resolved_metadata.dev()
            && configured_metadata.ino() == resolved_metadata.ino()
        {
            return Ok(StableRoot {
                directory: configured,
                resolved_path,
            });
        }
        return Err(StableRootError::Unstable);
    }
    if let Some(error) = last_open_error {
        return Err(error.into());
    }
    Err(StableRootError::Unstable)
}

#[derive(Debug, Error)]
pub(crate) enum StableRootError {
    #[error("root I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("root resolution changed during acquisition")]
    Unstable,
}
