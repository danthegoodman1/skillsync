use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

const DEFAULT_JOINING_SERVICE: &str = "https://skillsync.danthegoodman.com";

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub device: DeviceConfig,
    pub joining: JoiningConfig,
    pub iroh: IrohConfig,
    pub sync: SyncConfig,
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        Self::from_toml(&contents)
    }

    pub fn from_toml(contents: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn effective_joining_service_url(&self) -> String {
        env::var("SKILLSYNC_JOINING_SERVICE_URL")
            .unwrap_or_else(|_| self.joining.service_url.clone())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.device.name.trim().is_empty() {
            return Err(ConfigError::Invalid("device.name must not be empty"));
        }
        if !(60..=900).contains(&self.joining.invitation_ttl.as_secs()) {
            return Err(ConfigError::Invalid(
                "joining.invitation_ttl must be from 60s through 15m",
            ));
        }
        match self.iroh.preset {
            IrohPreset::N0 => {
                if !self.iroh.relay_urls.is_empty() || !self.iroh.address_lookup_urls.is_empty() {
                    return Err(ConfigError::Invalid(
                        "custom iroh URLs require preset = \"custom\"",
                    ));
                }
            }
            IrohPreset::Custom => {
                if self.iroh.relay_urls.is_empty() || self.iroh.address_lookup_urls.is_empty() {
                    return Err(ConfigError::Invalid(
                        "custom iroh preset requires relay_urls and address_lookup_urls",
                    ));
                }
            }
        }
        if self.sync.interval.is_zero() {
            return Err(ConfigError::Invalid("sync.interval must be positive"));
        }
        if self.logging.max_entries == 0 || self.logging.max_entries > 100_000 {
            return Err(ConfigError::Invalid(
                "logging.max_entries must be from 1 through 100000",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("device", &self.device)
            .field("joining", &self.joining)
            .field("iroh", &self.iroh)
            .field("sync", &self.sync)
            .field("logging", &self.logging)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DeviceConfig {
    pub name: String,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            name: "device".to_owned(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct JoiningConfig {
    pub service_url: String,
    #[serde(with = "humantime_serde")]
    pub invitation_ttl: Duration,
    pub headers: BTreeMap<String, SecretValue>,
}

impl Default for JoiningConfig {
    fn default() -> Self {
        Self {
            service_url: DEFAULT_JOINING_SERVICE.to_owned(),
            invitation_ttl: Duration::from_secs(600),
            headers: BTreeMap::new(),
        }
    }
}

impl fmt::Debug for JoiningConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoiningConfig")
            .field("service_url", &"[configured]")
            .field("invitation_ttl", &self.invitation_ttl)
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IrohPreset {
    #[default]
    N0,
    Custom,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct IrohConfig {
    pub preset: IrohPreset,
    pub relay_urls: Vec<String>,
    pub address_lookup_urls: Vec<String>,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            preset: IrohPreset::N0,
            relay_urls: Vec::new(),
            address_lookup_urls: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub max_future_clock_skew: Duration,
    pub ignore: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15 * 60),
            max_future_clock_skew: Duration::from_secs(5 * 60),
            ignore: vec![
                "**/.git/**".to_owned(),
                "**/.DS_Store".to_owned(),
                "**/*.swp".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub max_entries: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { max_entries: 1_000 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformPaths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl PlatformPaths {
    pub fn discover() -> Result<Self, ConfigError> {
        let home = env::var_os("HOME").ok_or(ConfigError::MissingHome)?;
        let home = PathBuf::from(home);

        #[cfg(target_os = "macos")]
        let defaults = Self::for_macos_home(&home);
        #[cfg(target_os = "linux")]
        let defaults = Self::for_linux_home(&home);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(ConfigError::UnsupportedPlatform);

        let config_file = env::var_os("SKILLSYNC_CONFIG_DIR")
            .map(PathBuf::from)
            .map(|directory| directory.join("config.toml"))
            .unwrap_or(defaults.config_file);
        let data_dir = env::var_os("SKILLSYNC_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.data_dir);
        let runtime_dir = env::var_os("SKILLSYNC_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.runtime_dir);

        Ok(Self {
            config_file,
            data_dir,
            runtime_dir,
        })
    }

    pub fn for_macos_home(home: &Path) -> Self {
        let data_dir = home
            .join("Library")
            .join("Application Support")
            .join("skillsync");
        Self {
            config_file: data_dir.join("config.toml"),
            runtime_dir: data_dir.join("run"),
            data_dir,
        }
    }

    pub fn for_linux_home(home: &Path) -> Self {
        let config_root = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let data_dir = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("skillsync");
        let runtime_dir = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|root| root.join("skillsync"))
            .unwrap_or_else(|| data_dir.join("run"));
        Self {
            config_file: config_root.join("skillsync/config.toml"),
            data_dir,
            runtime_dir,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("HOME is not set")]
    MissingHome,
    #[error("Skillsync supports macOS and Linux")]
    UnsupportedPlatform,
    #[error("configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENVIRONMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn defaults_match_the_product_contract() {
        let config = Config::default();
        assert_eq!(config.joining.service_url, DEFAULT_JOINING_SERVICE);
        assert_eq!(config.joining.invitation_ttl, Duration::from_secs(600));
        assert_eq!(config.iroh.preset, IrohPreset::N0);
        assert_eq!(config.sync.interval, Duration::from_secs(900));
        assert_eq!(config.sync.max_future_clock_skew, Duration::from_secs(300));
        assert_eq!(config.logging.max_entries, 1_000);
        config.validate().unwrap();
    }

    #[test]
    fn parses_custom_infrastructure_and_redacts_headers() {
        let config = Config::from_toml(
            r#"
            [device]
            name = "laptop"
            [joining]
            service_url = "https://join.example.net"
            invitation_ttl = "15m"
            [joining.headers]
            Authorization = "Bearer private-token"
            [iroh]
            preset = "custom"
            relay_urls = ["https://relay.example.net"]
            address_lookup_urls = ["https://lookup.example.net"]
            [sync]
            interval = "15m"
            max_future_clock_skew = "5m"
            "#,
        )
        .unwrap();
        assert_eq!(
            config.joining.headers["Authorization"].expose(),
            "Bearer private-token"
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("private-token"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn rejects_out_of_range_ttl_and_incomplete_custom_iroh_config() {
        let ttl_error = Config::from_toml(
            r#"
            [joining]
            invitation_ttl = "16m"
            "#,
        )
        .unwrap_err();
        assert!(ttl_error.to_string().contains("60s through 15m"));

        let custom_error = Config::from_toml(
            r#"
            [iroh]
            preset = "custom"
            relay_urls = ["https://relay.example.net"]
            "#,
        )
        .unwrap_err();
        assert!(custom_error.to_string().contains("address_lookup_urls"));
    }

    #[test]
    fn missing_file_loads_defaults() {
        let temporary = tempfile::tempdir().unwrap();
        let config = Config::load(&temporary.path().join("missing.toml")).unwrap();
        assert_eq!(config.sync.interval, Duration::from_secs(900));
    }

    #[test]
    fn joining_service_environment_override_has_precedence() {
        let _guard = ENVIRONMENT_LOCK.lock().unwrap();
        let previous = env::var_os("SKILLSYNC_JOINING_SERVICE_URL");
        // SAFETY: this test serializes all mutation of this process variable.
        unsafe {
            env::set_var(
                "SKILLSYNC_JOINING_SERVICE_URL",
                "https://environment.example.test",
            );
        }
        let mut config = Config::default();
        config.joining.service_url = "https://config.example.test".to_owned();
        assert_eq!(
            config.effective_joining_service_url(),
            "https://environment.example.test"
        );
        // SAFETY: the same process-wide lock remains held while restoring the variable.
        unsafe {
            match previous {
                Some(value) => env::set_var("SKILLSYNC_JOINING_SERVICE_URL", value),
                None => env::remove_var("SKILLSYNC_JOINING_SERVICE_URL"),
            }
        }
    }

    #[test]
    fn produces_platform_paths() {
        let home = Path::new("/home/person");
        let linux = PlatformPaths::for_linux_home(home);
        assert!(linux.config_file.ends_with("skillsync/config.toml"));
        assert!(linux.data_dir.ends_with("skillsync"));

        let macos = PlatformPaths::for_macos_home(home);
        assert!(macos.data_dir.ends_with("Application Support/skillsync"));
    }
}
