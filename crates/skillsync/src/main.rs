use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use skillsync::config::{Config, IrohPreset, PlatformPaths};
use skillsync::daemon::{
    ControlRequest, ControlResponse, DaemonError, attach_collection, collections_value,
    detach_collection, logs_page_value, peers_value, resolve_peer, send_request, status_value,
};
use skillsync::join::{
    SecretNonce, endpoint_ticket, run_joiner, terminal_safe_device_name, validate_join_device_name,
};
use skillsync::joining_service::JoiningServiceClient;
use skillsync::network::NetworkHandle;
use skillsync::process_lock::ProcessLock;
use skillsync::roster::RosterChange;
use skillsync::setup::{load_identity, setup, setup_joining_device};
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
    Invite,
    Join {
        code: String,
        #[arg(long)]
        name: String,
    },
    Peers {
        #[command(subcommand)]
        command: PeersCommand,
    },
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

#[derive(Subcommand)]
enum PeersCommand {
    List,
    Remove { device: String },
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
        Command::Invite => command_invite(&paths, &config, cli.json),
        Command::Join { code, name } => command_join(&paths, &config, code, name, cli.json),
        Command::Peers { command } => command_peers(&paths, &config, command, cli.json),
        Command::Daemon => skillsync::daemon::run(paths, config).map_err(CliError::from_error),
    }
}

fn command_invite(
    paths: &PlatformPaths,
    config: &Config,
    json_output: bool,
) -> Result<(), CliError> {
    let endpoint = send_request(paths, &ControlRequest::EndpointAddr)
        .map_err(|_| CliError::new("daemon_not_running", "the skillsync daemon is not running"))?;
    if !endpoint.ok {
        return Err(response_error(endpoint));
    }
    let address = endpoint
        .result
        .and_then(|value| value["address"].as_str().map(str::to_owned))
        .ok_or_else(|| {
            CliError::new("invalid_daemon_response", "daemon endpoint is unavailable")
        })?;
    let address =
        serde_json::from_str::<iroh::EndpointAddr>(&address).map_err(CliError::from_error)?;
    let ticket = endpoint_ticket(address);
    let client = JoiningServiceClient::from_config(config).map_err(CliError::from_error)?;
    let invitation = client
        .create(&ticket, config.joining.invitation_ttl)
        .map_err(CliError::from_error)?;
    let response = send_request(
        paths,
        &ControlRequest::ActivateInvitation {
            nonce: SecretNonce::new(invitation.join_nonce),
            lifetime_seconds: config.joining.invitation_ttl.as_secs(),
        },
    )
    .map_err(CliError::from_error)?;
    if !response.ok {
        return Err(response_error(response));
    }
    if json_output {
        print_json(&json!({
            "event": "invitation_created",
            "code": invitation.code,
            "expires_at": invitation.expires_at
        }));
    } else {
        println!("Joining code: {}", invitation.code);
        println!(
            "Expires in {}.\n",
            humantime::format_duration(config.joining.invitation_ttl)
        );
        println!("Waiting for another device…");
    }
    io::stdout().flush().map_err(CliError::from_error)?;

    let deadline = std::time::Instant::now() + config.joining.invitation_ttl;
    let pending = loop {
        if std::time::Instant::now() >= deadline {
            return Err(CliError::new(
                "invitation_expired",
                "the invitation expired",
            ));
        }
        let response =
            send_request(paths, &ControlRequest::PendingJoin).map_err(CliError::from_error)?;
        if !response.ok {
            return Err(response_error(response));
        }
        let result = response.result.expect("successful response");
        if !result["pending"].is_null() {
            break result["pending"].clone();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let request_id = pending["request_id"]
        .as_str()
        .ok_or_else(|| CliError::new("invalid_daemon_response", "join request is invalid"))?;
    let endpoint_id = pending["endpoint_id"]
        .as_str()
        .ok_or_else(|| CliError::new("invalid_daemon_response", "join request is invalid"))?;
    let device_name = pending["device_name"].as_str().unwrap_or("device");
    if json_output {
        print_json(&json!({
            "event": "join_requested",
            "device_name": device_name,
            "endpoint_id": endpoint_id
        }));
    } else {
        println!("{}", join_request_human(device_name, endpoint_id));
    }
    let approved = confirm_join()?;
    let response = send_request(
        paths,
        &ControlRequest::DecideJoin {
            request_id: request_id.to_owned(),
            approve: approved,
        },
    )
    .map_err(CliError::from_error)?;
    if !response.ok {
        return Err(response_error(response));
    }
    if json_output {
        print_json(&json!({
            "event": "join_decided",
            "approved": approved,
            "endpoint_id": endpoint_id
        }));
    } else if approved {
        println!("Device approved.");
    } else {
        println!("Device rejected.");
    }
    Ok(())
}

fn join_request_human(device_name: &str, endpoint_id: &str) -> String {
    format!(
        "\nJoin request from: {}\nJoining iroh EndpointID:\n{endpoint_id}\n",
        terminal_safe_device_name(device_name)
    )
}

fn confirm_join() -> Result<bool, CliError> {
    eprint!("Does this exactly match the EndpointID on the joining device? [y/N] ");
    io::stderr().flush().map_err(CliError::from_error)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(CliError::from_error)?;
    Ok(approval_answer(&answer))
}

fn approval_answer(answer: &str) -> bool {
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
}

fn command_join(
    paths: &PlatformPaths,
    config: &Config,
    code: &str,
    name: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let _process_lock = ProcessLock::acquire(paths).map_err(CliError::from_error)?;
    validate_join_device_name(name).map_err(CliError::from_error)?;
    let setup = setup_joining_device(paths, config).map_err(CliError::from_error)?;
    if !setup.created && setup.device_name != name {
        return Err(CliError::new(
            "device_name_mismatch",
            "the joining name does not match this device's current group membership",
        ));
    }
    let identity = load_identity(paths).map_err(CliError::from_error)?;
    if json_output {
        print_json(&json!({
            "event": "identity",
            "endpoint_id": identity.endpoint_id().to_string()
        }));
    } else {
        println!("This device's iroh EndpointID:");
        println!("{}\n", identity.endpoint_id());
        println!("Compare this exact EndpointID on the inviting device.");
        println!("Waiting for approval…");
    }
    io::stdout().flush().map_err(CliError::from_error)?;
    let client = JoiningServiceClient::from_config(config).map_err(CliError::from_error)?;
    let claimed = client.claim(code).map_err(CliError::from_error)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(CliError::from_error)?;
    let inviter = runtime
        .block_on(run_joiner(
            paths,
            config,
            &identity,
            &claimed.inviter_ticket,
            claimed.join_nonce,
            name,
        ))
        .map_err(CliError::from_error)?;

    let network = NetworkHandle::start(paths.clone(), config.clone(), identity)
        .map_err(CliError::from_error)?;
    let completed = network.start_sync().map_err(CliError::from_error)?;
    let summary = completed
        .recv_timeout(std::time::Duration::from_secs(45))
        .map_err(|_| CliError::new("sync_timeout", "initial synchronization timed out"))?;
    network.shutdown().map_err(CliError::from_error)?;
    if summary.succeeded == 0 {
        return Err(CliError::new(
            "initial_sync_failed",
            "joined the group but could not synchronize with a peer",
        ));
    }
    if json_output {
        print_json(&json!({
            "event": "joined",
            "device_name": name,
            "endpoint_id": setup.endpoint_id.to_string(),
            "inviter_endpoint_id": inviter.to_string(),
            "peers_synchronized": summary.succeeded
        }));
    } else {
        println!("\nDevice approved. Initial synchronization complete.");
    }
    Ok(())
}

fn command_peers(
    paths: &PlatformPaths,
    _config: &Config,
    command: &PeersCommand,
    json_output: bool,
) -> Result<(), CliError> {
    let database = paths.data_dir.join("state.sqlite3");
    if !database.exists() {
        return Err(CliError::new("not_setup", "run `skillsync setup` first"));
    }
    let identity = load_identity(paths).map_err(CliError::from_error)?;
    match command {
        PeersCommand::List => {
            let value = match request_if_running(paths, &ControlRequest::Peers)? {
                Some(response) => response.result.expect("successful response"),
                None => peers_value(
                    &StateStore::open(&database).map_err(CliError::from_error)?,
                    identity.endpoint_id(),
                )
                .map_err(CliError::from_error)?,
            };
            if json_output {
                print_json(&value);
            } else {
                for peer in value["peers"].as_array().expect("peers is an array") {
                    let local = if peer["local"].as_bool() == Some(true) {
                        " (this device)"
                    } else {
                        ""
                    };
                    let online = if peer["online"].as_bool() == Some(true) {
                        "online"
                    } else {
                        "offline"
                    };
                    println!(
                        "{}{}\n  {}  {}",
                        terminal_safe_device_name(peer["name"].as_str().unwrap_or("device")),
                        local,
                        peer["endpoint_id"].as_str().unwrap_or(""),
                        online
                    );
                }
            }
        }
        PeersCommand::Remove { device } => {
            let mut state = StateStore::open(&database).map_err(CliError::from_error)?;
            let endpoint = resolve_peer(&state, device).map_err(CliError::from_error)?;
            let removed = match request_if_running(
                paths,
                &ControlRequest::RemovePeer {
                    peer: endpoint.to_string(),
                },
            )? {
                Some(response) => response.result.expect("successful response")["removed"]
                    .as_bool()
                    .unwrap_or(false),
                None => {
                    if endpoint == identity.endpoint_id() {
                        return Err(CliError::new(
                            "cannot_remove_self",
                            "this device cannot remove itself",
                        ));
                    }
                    state
                        .apply_roster_change(&identity, RosterChange::Remove(endpoint))
                        .map_err(CliError::from_error)?;
                    true
                }
            };
            if json_output {
                print_json(&json!({
                    "endpoint_id": endpoint.to_string(),
                    "removed": removed
                }));
            } else {
                println!("Device {} removed.", endpoint);
            }
        }
    }
    Ok(())
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
        println!("Device: {}", terminal_safe_device_name(&result.device_name));
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
            terminal_safe_device_name(value["device"]["name"].as_str().unwrap_or("unknown"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_approval_defaults_to_rejection() {
        for answer in ["", "\n", "n", "no", "maybe", "true", "1"] {
            assert!(!approval_answer(answer));
        }
        for answer in ["y", "Y", "yes", "YES", " yes\n"] {
            assert!(approval_answer(answer));
        }
    }

    #[test]
    fn human_device_names_escape_terminal_controls_without_hiding_the_endpoint() {
        let endpoint = "03ce2e2f55af140d0b18395fff054d3f3ab6a30aa680e4a2a3ab4526838151a5";
        for name in [
            "line\nbreak",
            "ansi\u{1b}[31m",
            "bidi\u{202e}name",
            "mark\u{2067}name",
        ] {
            let output = join_request_human(name, endpoint);
            assert!(output.contains(endpoint));
            assert!(!output.contains('\u{1b}'));
            assert!(!output.contains('\u{202e}'));
            assert!(!output.contains('\u{2067}'));
            assert!(!output.contains("line\nbreak"));
            assert!(output.contains("\\u{"));
        }
    }
}
