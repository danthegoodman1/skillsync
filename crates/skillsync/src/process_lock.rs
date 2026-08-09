use std::fs::{self, File, OpenOptions, TryLockError};

use thiserror::Error;

use crate::config::PlatformPaths;

const LOCK_FILE: &str = "process.lock";

pub struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    pub fn acquire(paths: &PlatformPaths) -> Result<Self, ProcessLockError> {
        fs::create_dir_all(&paths.data_dir)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(paths.data_dir.join(LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(ProcessLockError::Busy),
            Err(TryLockError::Error(error)) => Err(ProcessLockError::Io(error)),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProcessLockError {
    #[error("another skillsync daemon or join is active")]
    Busy,
    #[error("process lock failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lock_is_released_with_its_file() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            config_file: temporary.path().join("config.toml"),
            data_dir: temporary.path().join("data"),
            runtime_dir: temporary.path().join("run"),
        };
        let first = ProcessLock::acquire(&paths).unwrap();
        assert!(matches!(
            ProcessLock::acquire(&paths),
            Err(ProcessLockError::Busy)
        ));
        drop(first);
        ProcessLock::acquire(&paths).unwrap();
    }
}
