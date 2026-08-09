use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use skillsync::config::{Config, IrohPreset, PlatformPaths};
use skillsync::daemon::{
    ControlRequest, ControlResponse, DaemonError, attach_collection, collections_value,
    detach_collection, logs_page_value, send_request, status_value,
};
use skillsync::setup::{load_identity, setup};
use skillsync::state::StateStore;

#[derive(Parser)]
#[command(
    name = "skillsync",
    version,
    about = "Synchronize agent skills between trusted devices"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Setup,
    Status,
    Collections {
        #[command(subcommand)]
        command: CollectionsCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Logs(LogsArgs),
    Sync(SyncArgs),
    #[command(name = "__daemon", hide = true)]
    Daemon,
}

#[derive(Subcommand)]
enum CollectionsCommand {
    List,
    Add {
        name: String,
        path: PathBuf,
        #[arg(long)]
        replace: bool,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Show,
    Path,
}

#[derive(Args)]
struct LogsArgs {
    #[arg(long)]
    follow: bool,
}

#[derive(Args)]
struct SyncArgs {
    #[arg(long)]
    wait: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if cli.json {
                println!(
                    "{}",
                    json!({ "error": { "code": error.code, "message": error.message } })
                );
            } else {
                eprintln!("error: {}", error.message);
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: &Cli) -> Result<(), CliError> {
    let paths = PlatformPaths::discover().map_err(CliError::from_error)?;
    let config = Config::load(&paths.config_file).map_err(CliError::from_error)?;
    match &cli.command {
        Command::Setup => command_setup(&paths, &config, cli.json),
        Command::Status => command_status(&paths, &config, cli.json),
        Command::Collections { command } => command_collections(&paths, &config, command, cli.json),
        Command::Config { command } => command_config(&paths, &config, command, cli.json),
        Command::Logs(arguments) => command_logs(&paths, arguments, cli.json),
        Command::Sync(arguments) => command_sync(&paths, arguments, cli.json),
        Command::Daemon => skillsync::daemon::run(paths, config).map_err(CliError::from_error),
    }
}

fn command_setup(
    paths: &PlatformPaths,
    config: &Config,
    json_output: bool,
) -> Result<(), CliError> {
    let result = setup(paths, config).map_err(CliError::from_error)?;
    if json_output {
        print_json(&json!({
            "device": { "name": result.device_name, "endpoint_id": result.endpoint_id.to_string() },
            "group": "personal",
            "collections": result.collections.iter().map(|(name, path)| {
                json!({ "name": name, "path": path })
            }).collect::<Vec<_>>(),
            "created": result.created
        }));
    } else {
        println!("Device: {}", result.device_name);
        println!("Group: personal\n");
        println!("Collections:");
        for (name, path) in result.collections {
            println!("  {name:<8} -> {}", path.display());
        }
        println!("\nSetup complete.");
    }
    Ok(())
}

fn command_status(
    paths: &PlatformPaths,
    config: &Config,
    json_output: bool,
) -> Result<(), CliError> {
    let value = match request_if_running(paths, &ControlRequest::Status)? {
        Some(response) => response.result.expect("successful response has a result"),
        None => {
            let database = paths.data_dir.join("state.sqlite3");
            if !database.exists() {
                return Err(CliError::new("not_setup", "run `skillsync setup` first"));
            }
            let state = StateStore::open(&database).map_err(CliError::from_error)?;
            let identity = load_identity(paths).map_err(CliError::from_error)?;
            let mut value = status_value(&state, &config.device.name, identity.endpoint_id())
                .map_err(CliError::from_error)?;
            value["daemon"] = json!("stopped");
            value
        }
    };
    if json_output {
        print_json(&value);
    } else {
        println!(
            "Device   {}",
            value["device"]["name"].as_str().unwrap_or("unknown")
        );
        println!(
            "Peers    {} online",
            value["peers"]["online"].as_u64().unwrap_or(0)
        );
        println!(
            "Files    {} synchronized",
            value["files"]["synchronized"].as_u64().unwrap_or(0)
        );
        println!("Daemon   {}", value["daemon"].as_str().unwrap_or("stopped"));
    }
    Ok(())
}

fn command_collections(
    paths: &PlatformPaths,
    config: &Config,
    command: &CollectionsCommand,
    json_output: bool,
) -> Result<(), CliError> {
    let database = paths.data_dir.join("state.sqlite3");
    if !database.exists() {
        return Err(CliError::new("not_setup", "run `skillsync setup` first"));
    }
    match command {
        CollectionsCommand::List => {
            let value = match request_if_running(paths, &ControlRequest::Collections)? {
                Some(response) => response.result.expect("successful response has a result"),
                None => {
                    collections_value(&StateStore::open(&database).map_err(CliError::from_error)?)
                        .map_err(CliError::from_error)?
                }
            };
            if json_output {
                print_json(&value);
            } else {
                for collection in value["collections"]
                    .as_array()
                    .expect("collections response is an array")
                {
                    println!(
                        "{:<16} {} ({})",
                        collection["name"].as_str().unwrap_or(""),
                        collection["path"].as_str().unwrap_or(""),
                        collection["state"].as_str().unwrap_or("paused")
                    );
                }
            }
        }
        CollectionsCommand::Add {
            name,
            path,
            replace,
        } => {
            let path = absolute_path(path).map_err(CliError::from_error)?;
            let mut state = StateStore::open(&database).map_err(CliError::from_error)?;
            if let Some(existing) = state.collection(name).map_err(CliError::from_error)?
                && existing.local_path != path
                && !replace
            {
                if json_output {
                    return Err(CliError::new(
                        "replacement_requires_flag",
                        "use --replace to change an existing collection path",
                    ));
                }
                if !confirm_replacement(name, &existing.local_path, &path)? {
                    return Err(CliError::new(
                        "cancelled",
                        "collection path was not changed",
                    ));
                }
            }
            let value = match request_if_running(
                paths,
                &ControlRequest::AddCollection {
                    name: name.clone(),
                    path: path.clone(),
                },
            )? {
                Some(response) => response.result.expect("successful response"),
                None => {
                    attach_collection(&mut state, config, name, &path)
                        .map_err(CliError::from_error)?;
                    json!({ "name": name, "path": path, "attached": true })
                }
            };
            if json_output {
                print_json(&value);
            } else {
                println!("Collection {name} attached at {}.", path.display());
            }
        }
        CollectionsCommand::Remove { name } => {
            let mut state = StateStore::open(&database).map_err(CliError::from_error)?;
            let value = match request_if_running(
                paths,
                &ControlRequest::RemoveCollection { name: name.clone() },
            )? {
                Some(response) => response.result.expect("successful response"),
                None => {
                    let removed = detach_collection(&mut state, config, name)
                        .map_err(CliError::from_error)?;
                    json!({ "name": name, "removed": removed })
                }
            };
            if json_output {
                print_json(&value);
            } else if value["removed"].as_bool().unwrap_or(false) {
                println!("Collection {name} detached. Local files were left in place.");
            } else {
                println!("Collection {name} is not attached.");
            }
        }
    }
    Ok(())
}

fn command_config(
    paths: &PlatformPaths,
    config: &Config,
    command: &ConfigCommand,
    json_output: bool,
) -> Result<(), CliError> {
    match command {
        ConfigCommand::Path => {
            if json_output {
                print_json(&json!({ "path": paths.config_file }));
            } else {
                println!("{}", paths.config_file.display());
            }
        }
        ConfigCommand::Show => {
            if json_output {
                print_json(&config_json(config));
            } else {
                print!("{}", config_toml(config));
            }
        }
    }
    Ok(())
}

fn command_logs(
    paths: &PlatformPaths,
    arguments: &LogsArgs,
    json_output: bool,
) -> Result<(), CliError> {
    let database = paths.data_dir.join("state.sqlite3");
    if !database.exists() {
        return Err(CliError::new("not_setup", "run `skillsync setup` first"));
    }
    let mut after_id = 0_i64;
    loop {
        let request = ControlRequest::Logs {
            after_id,
            limit: 64,
        };
        let value = match request_if_running(paths, &request)? {
            Some(response) => response.result.expect("successful response"),
            None => logs_page_value(
                &StateStore::open(&database).map_err(CliError::from_error)?,
                after_id,
                64,
            )
            .map_err(CliError::from_error)?,
        };
        let logs = value["logs"].as_array().expect("logs response is an array");
        for log in logs {
            if json_output {
                print_json(log);
            } else {
                println!(
                    "{} {:<5} {}{}{}",
                    log["created_ns"].as_i64().unwrap_or(0),
                    log["level"].as_str().unwrap_or("info"),
                    log["event"].as_str().unwrap_or("event"),
                    log.get("collection")
                        .and_then(Value::as_str)
                        .map(|value| format!(" {value}"))
                        .unwrap_or_default(),
                    log.get("path")
                        .and_then(Value::as_str)
                        .map(|value| format!("/{value}"))
                        .unwrap_or_default()
                );
            }
        }
        after_id = value["next_after_id"].as_i64().unwrap_or(after_id);
        let has_more = value["has_more"].as_bool().unwrap_or(false);
        if has_more {
            continue;
        }
        if !arguments.follow {
            break;
        }
        io::stdout().flush().map_err(CliError::from_error)?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

fn command_sync(
    paths: &PlatformPaths,
    arguments: &SyncArgs,
    json_output: bool,
) -> Result<(), CliError> {
    let response = send_request(
        paths,
        &ControlRequest::Sync {
            wait: arguments.wait,
        },
    )
    .map_err(|error| match error {
        DaemonError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            CliError::new("daemon_not_running", "the skillsync daemon is not running")
        }
        error => CliError::from_error(error),
    })?;
    if !response.ok {
        return Err(response_error(response));
    }
    let value = response.result.expect("successful response has a result");
    if json_output {
        print_json(&value);
    } else if arguments.wait {
        println!(
            "Synchronized with {} of {} peers.",
            value["succeeded"].as_u64().unwrap_or(0),
            value["attempted"].as_u64().unwrap_or(0)
        );
    } else {
        println!("Synchronization queued.");
    }
    Ok(())
}

fn confirm_replacement(name: &str, old: &Path, new: &Path) -> Result<bool, CliError> {
    eprint!(
        "Replace collection {name} path {} with {}? [y/N] ",
        old.display(),
        new.display()
    );
    io::stderr().flush().map_err(CliError::from_error)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(CliError::from_error)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let expanded = if path == Path::new("~") {
        PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?,
        )
    } else if let Ok(rest) = path.strip_prefix("~/") {
        PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?,
        )
        .join(rest)
    } else {
        path.to_path_buf()
    };
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Ok(std::env::current_dir()?.join(expanded))
    }
}

fn config_json(config: &Config) -> Value {
    json!({
        "device": { "name": config.device.name },
        "joining": {
            "service_url": config.effective_joining_service_url(),
            "invitation_ttl": humantime::format_duration(config.joining.invitation_ttl).to_string(),
            "headers": config.joining.headers.keys().map(|key| (key.clone(), json!("[redacted]"))).collect::<serde_json::Map<_, _>>()
        },
        "iroh": {
            "preset": match config.iroh.preset { IrohPreset::N0 => "n0", IrohPreset::Custom => "custom" },
            "relay_urls": config.iroh.relay_urls,
            "address_lookup_urls": config.iroh.address_lookup_urls
        },
        "sync": {
            "interval": humantime::format_duration(config.sync.interval).to_string(),
            "max_future_clock_skew": humantime::format_duration(config.sync.max_future_clock_skew).to_string(),
            "ignore": config.sync.ignore
        },
        "logging": { "max_entries": config.logging.max_entries }
    })
}

fn config_toml(config: &Config) -> String {
    let value = config_json(config);
    let headers = value["joining"]["headers"]
        .as_object()
        .expect("headers is an object")
        .iter()
        .map(|(key, value)| format!("{key} = {}\n", toml_string(value.as_str().unwrap())))
        .collect::<String>();
    format!(
        "[device]\nname = {}\n\n[joining]\nservice_url = {}\ninvitation_ttl = {}\n{}\n[iroh]\npreset = {}\nrelay_urls = {}\naddress_lookup_urls = {}\n\n[sync]\ninterval = {}\nmax_future_clock_skew = {}\nignore = {}\n\n[logging]\nmax_entries = {}\n",
        toml_string(value["device"]["name"].as_str().unwrap()),
        toml_string(value["joining"]["service_url"].as_str().unwrap()),
        toml_string(value["joining"]["invitation_ttl"].as_str().unwrap()),
        if headers.is_empty() {
            String::new()
        } else {
            format!("\n[joining.headers]\n{headers}")
        },
        toml_string(value["iroh"]["preset"].as_str().unwrap()),
        toml_array(value["iroh"]["relay_urls"].as_array().unwrap()),
        toml_array(value["iroh"]["address_lookup_urls"].as_array().unwrap()),
        toml_string(value["sync"]["interval"].as_str().unwrap()),
        toml_string(value["sync"]["max_future_clock_skew"].as_str().unwrap()),
        toml_array(value["sync"]["ignore"].as_array().unwrap()),
        value["logging"]["max_entries"].as_u64().unwrap()
    )
}

fn toml_string(value: &str) -> String {
    format!("{value:?}")
}

fn toml_array(values: &[Value]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| toml_string(value.as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn print_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).expect("JSON values always serialize")
    );
}

fn response_error(response: skillsync::daemon::ControlResponse) -> CliError {
    let error = response.error.expect("failed response has an error");
    CliError::new(error.code, error.message)
}

fn request_if_running(
    paths: &PlatformPaths,
    request: &ControlRequest,
) -> Result<Option<ControlResponse>, CliError> {
    match send_request(paths, request) {
        Ok(response) if response.ok => Ok(Some(response)),
        Ok(response) => Err(response_error(response)),
        Err(DaemonError::Io(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(CliError::from_error(error)),
    }
}

struct CliError {
    code: String,
    message: String,
}

impl CliError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn from_error(error: impl std::fmt::Display) -> Self {
        Self::new("operation_failed", error.to_string())
    }
}
