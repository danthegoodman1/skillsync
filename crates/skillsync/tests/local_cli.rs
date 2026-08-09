use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;
use skillsync::config::PlatformPaths;
use skillsync::daemon::{ControlRequest, send_request};
use skillsync::identity::DeviceIdentity;
use skillsync::record::RecordKind;
use skillsync::roster::{RosterChange, RosterMember, RosterRevision};
use skillsync::setup::load_identity;
use skillsync::state::{CollectionScanStatus, CollectionWatchStatus, OperationalEvent, StateStore};

fn paths(root: &Path) -> PlatformPaths {
    PlatformPaths {
        config_file: root.join("config/config.toml"),
        data_dir: root.join("data"),
        runtime_dir: root.join("run"),
    }
}

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_skillsync"));
    command
        .env("HOME", root)
        .env("SKILLSYNC_DATA_DIR", root.join("data"))
        .env("SKILLSYNC_RUNTIME_DIR", root.join("run"))
        .env("SKILLSYNC_CONFIG_DIR", root.join("config"));
    command
}

fn output(root: &Path, arguments: &[&str]) -> Output {
    command(root).args(arguments).output().unwrap()
}

fn json_output(root: &Path, arguments: &[&str]) -> Value {
    let output = output(root, arguments);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn start_daemon(root: &Path) -> Child {
    command(root)
        .arg("__daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_daemon(paths: &PlatformPaths) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if send_request(paths, &ControlRequest::Status).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("daemon did not start");
}

fn wait_for_hash(database: &Path, collection: &str, path: &str, hash: [u8; 32], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(store) = StateStore::open(database)
            && let Ok(Some(record)) = store.record(collection, path)
            && matches!(record.kind(), RecordKind::File { content_hash, .. } if content_hash == hash)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let store = StateStore::open(database).unwrap();
    panic!(
        "record did not converge, collection: {:?}, records: {:?}, logs: {:?}",
        store.collection(collection).unwrap(),
        store.records(collection).unwrap(),
        store.logs().unwrap()
    )
}

fn wait_for_watch_status(
    database: &Path,
    collection: &str,
    status: CollectionWatchStatus,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(store) = StateStore::open(database)
            && let Ok(Some(state)) = store.collection(collection)
            && state.watch_status == status
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("collection watch status did not converge to {status:?}")
}

fn raw_request(paths: &PlatformPaths, bytes: &[u8]) -> String {
    let mut stream = UnixStream::connect(skillsync::daemon::socket_path(paths)).unwrap();
    if let Err(error) = stream.write_all(bytes) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected
            ),
            "unexpected control write error: {error}"
        );
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    response
}

#[test]
fn setup_daemon_watch_repair_and_local_cli_work_across_processes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let platform_paths = paths(root);
    fs::create_dir_all(root.join("config")).unwrap();
    fs::write(
        &platform_paths.config_file,
        "[device]\nname = \"test-device\"\n[joining.headers]\nAuthorization = \"Bearer secret-value\"\n[iroh]\npreset = \"custom\"\nrelay_urls = [\"http://127.0.0.1:9\"]\naddress_lookup_urls = [\"http://127.0.0.1:9/pkarr\"]\n[sync]\ninterval = \"5s\"\n",
    )
    .unwrap();

    let setup = json_output(root, &["setup", "--json"]);
    assert!(setup["created"].as_bool().unwrap());
    assert_eq!(setup["device"]["name"], "test-device");
    assert_eq!(setup["collections"].as_array().unwrap().len(), 3);
    for relative in [".agents/skills", ".claude/skills", ".codex/skills"] {
        assert!(root.join(relative).is_dir());
    }
    let setup_again = json_output(root, &["setup", "--json"]);
    assert!(!setup_again["created"].as_bool().unwrap());
    assert_eq!(setup_again["device"], setup["device"]);
    let stopped = json_output(root, &["status", "--json"]);
    assert_eq!(stopped["daemon"], "stopped");
    let shown = output(root, &["config", "show"]);
    assert!(shown.status.success());
    let shown = String::from_utf8(shown.stdout).unwrap();
    assert!(!shown.contains("secret-value"));
    assert!(shown.contains("[redacted]"));
    toml::from_str::<toml::Value>(&shown).unwrap();
    let shown_json = command(root)
        .env(
            "SKILLSYNC_JOINING_SERVICE_URL",
            "https://environment.example.test",
        )
        .args(["config", "show", "--json"])
        .output()
        .unwrap();
    assert!(shown_json.status.success());
    let shown_json: Value = serde_json::from_slice(&shown_json.stdout).unwrap();
    assert_eq!(
        shown_json["joining"]["service_url"],
        "https://environment.example.test"
    );
    assert_eq!(
        shown_json["joining"]["headers"]["Authorization"],
        "[redacted]"
    );

    fs::create_dir_all(&platform_paths.runtime_dir).unwrap();
    let stale = UnixListener::bind(skillsync::daemon::socket_path(&platform_paths)).unwrap();
    drop(stale);
    let mut daemon = start_daemon(root);
    wait_for_daemon(&platform_paths);
    assert_eq!(
        fs::metadata(skillsync::daemon::socket_path(&platform_paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let running = json_output(root, &["status", "--json"]);
    assert_eq!(running["daemon"], "running");

    let malformed: Value =
        serde_json::from_str(raw_request(&platform_paths, b"{bad}\n").trim()).unwrap();
    assert!(!malformed["ok"].as_bool().unwrap());
    let oversized = vec![b'x'; 64 * 1024];
    let oversized: Value =
        serde_json::from_str(raw_request(&platform_paths, &oversized).trim()).unwrap();
    assert!(!oversized["ok"].as_bool().unwrap());
    let mut disconnected =
        UnixStream::connect(skillsync::daemon::socket_path(&platform_paths)).unwrap();
    disconnected
        .write_all(b"{\"command\":\"status\"}\n")
        .unwrap();
    drop(disconnected);
    assert!(
        send_request(&platform_paths, &ControlRequest::Status)
            .unwrap()
            .ok
    );

    fs::create_dir_all(root.join(".agents/skills/reviewer")).unwrap();
    let skill = root.join(".agents/skills/reviewer/SKILL.md");
    fs::write(&skill, "first").unwrap();
    let database = platform_paths.data_dir.join("state.sqlite3");
    wait_for_hash(
        &database,
        ".agents",
        "reviewer/SKILL.md",
        *blake3::hash(b"first").as_bytes(),
        Duration::from_secs(3),
    );

    fs::remove_dir_all(root.join(".agents/skills")).unwrap();
    wait_for_watch_status(
        &database,
        ".agents",
        CollectionWatchStatus::RootUnavailable,
        Duration::from_secs(7),
    );
    fs::create_dir_all(root.join(".agents/skills/reviewer")).unwrap();
    fs::write(&skill, "periodic repair").unwrap();
    let metadata = fs::metadata(&skill).unwrap();
    let current = filetime::FileTime::from_last_modification_time(&metadata);
    filetime::set_file_mtime(
        &skill,
        filetime::FileTime::from_unix_time(current.unix_seconds() + 1, 0),
    )
    .unwrap();
    wait_for_hash(
        &database,
        ".agents",
        "reviewer/SKILL.md",
        *blake3::hash(b"periodic repair").as_bytes(),
        Duration::from_secs(7),
    );

    let custom = root.join("custom-a");
    let added = json_output(
        root,
        &[
            "collections",
            "add",
            "team",
            custom.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(added["attached"].as_bool().unwrap());
    let repeated = json_output(
        root,
        &[
            "collections",
            "add",
            "team",
            custom.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(repeated["attached"].as_bool().unwrap());

    let replacement = root.join("custom-b");
    let mut declined = command(root)
        .args(["collections", "add", "team", replacement.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    declined.stdin.as_mut().unwrap().write_all(b"n\n").unwrap();
    let declined = declined.wait_with_output().unwrap();
    assert!(!declined.status.success());
    assert!(String::from_utf8_lossy(&declined.stderr).contains("Replace collection team path"));
    let refused = output(
        root,
        &[
            "collections",
            "add",
            "team",
            replacement.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(!refused.status.success());
    let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(error["error"]["code"], "replacement_requires_flag");
    let replaced = json_output(
        root,
        &[
            "collections",
            "add",
            "team",
            replacement.to_str().unwrap(),
            "--replace",
            "--json",
        ],
    );
    assert_eq!(replaced["path"], replacement.to_str().unwrap());
    fs::write(replacement.join("kept.txt"), "keep").unwrap();
    let removed = json_output(root, &["collections", "remove", "team", "--json"]);
    assert!(removed["removed"].as_bool().unwrap());
    assert_eq!(
        fs::read_to_string(replacement.join("kept.txt")).unwrap(),
        "keep"
    );

    let listed = json_output(root, &["collections", "list", "--json"]);
    assert_eq!(listed["collections"].as_array().unwrap().len(), 3);
    let logs = output(root, &["logs", "--json"]);
    assert!(logs.status.success());
    let events = String::from_utf8(logs.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "daemon_started")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "record_accepted")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "collection_detached")
    );
    let page = send_request(
        &platform_paths,
        &ControlRequest::Logs {
            after_id: 0,
            limit: usize::MAX,
        },
    )
    .unwrap();
    let page = page.result.unwrap();
    let page_logs = page["logs"].as_array().unwrap();
    assert!(page_logs.len() <= 64);
    assert!(
        page_logs
            .windows(2)
            .all(|logs| logs[0]["id"].as_i64() < logs[1]["id"].as_i64())
    );
    assert!(serde_json::to_vec(&page).unwrap().len() < 512 * 1024);

    let unavailable_secret = [70; 32];
    let unavailable = DeviceIdentity::from_secret(unavailable_secret);
    let unavailable_endpoint = unavailable.endpoint_id();
    let (address_sender, address_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .clear_address_lookup()
                .relay_mode(iroh::endpoint::RelayMode::Disabled)
                .secret_key(iroh::SecretKey::from_bytes(&unavailable_secret))
                .alpns(vec![skillsync::protocol::ALPN.to_vec()])
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
                .await
                .unwrap();
            address_sender.send(endpoint.addr()).unwrap();
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            tokio::task::spawn_blocking(move || release_receiver.recv().unwrap())
                .await
                .unwrap();
            drop(connection);
            endpoint.close().await;
        });
    });
    let unavailable_addr = address_receiver
        .recv_timeout(Duration::from_secs(15))
        .unwrap();
    let local = load_identity(&platform_paths).unwrap();
    let mut state = StateStore::open(&database).unwrap();
    let genesis = state.selected_roster_chain().unwrap()[0].clone();
    let admission = RosterRevision::child(
        &genesis,
        RosterChange::Admit(RosterMember::new(unavailable_endpoint, "unavailable-peer").unwrap()),
        &local,
    )
    .unwrap();
    state.insert_roster_revision(&admission).unwrap();
    let unavailable_hint = serde_json::to_string(&unavailable_addr).unwrap();
    state
        .replace_peer_hint(unavailable_endpoint, &unavailable_hint)
        .unwrap();
    drop(state);

    let mut waiting_sync = command(root)
        .args(["sync", "--wait", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let attempt_deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_attempt = false;
    while Instant::now() < attempt_deadline {
        if StateStore::open(&database)
            .unwrap()
            .logs()
            .unwrap()
            .iter()
            .any(|log| {
                matches!(
                    log.event,
                    OperationalEvent::PeerAttempted { peer_endpoint }
                        if peer_endpoint == unavailable_endpoint
                )
            })
        {
            saw_attempt = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(saw_attempt);
    assert!(waiting_sync.try_wait().unwrap().is_none());
    let status_during_sync = json_output(root, &["status", "--json"]);
    assert_eq!(status_during_sync["daemon"], "running");

    let during_sync = root.join(".agents/skills/during-sync/SKILL.md");
    fs::create_dir_all(during_sync.parent().unwrap()).unwrap();
    fs::write(&during_sync, "watch remains live").unwrap();
    wait_for_hash(
        &database,
        ".agents",
        "during-sync/SKILL.md",
        *blake3::hash(b"watch remains live").as_bytes(),
        Duration::from_secs(3),
    );
    assert!(waiting_sync.try_wait().unwrap().is_none());
    release_sender.send(()).unwrap();
    let waiting_output = waiting_sync.wait_with_output().unwrap();
    assert!(
        waiting_output.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&waiting_output.stderr)
    );
    let waiting_result: Value = serde_json::from_slice(&waiting_output.stdout).unwrap();
    assert_eq!(waiting_result["attempted"], 1);
    assert_eq!(waiting_result["succeeded"], 0);
    let peer_logs = StateStore::open(&database).unwrap().logs().unwrap();
    assert!(peer_logs.iter().any(|log| matches!(
        log.event,
        OperationalEvent::PeerUnreachable { peer_endpoint }
            if peer_endpoint == unavailable_endpoint
    )));
    assert!(!peer_logs.iter().any(|log| matches!(
        log.event,
        OperationalEvent::PeerRejected { peer_endpoint }
            if peer_endpoint == unavailable_endpoint
    )));
    peer.join().unwrap();

    let human = output(root, &["status"]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Daemon   running"));

    let refused_default = output(root, &["collections", "remove", ".agents", "--json"]);
    assert!(!refused_default.status.success());
    let error: Value = serde_json::from_slice(&refused_default.stdout).unwrap();
    assert_eq!(error["error"]["code"], "daemon_operation_failed");

    let shutdown = send_request(&platform_paths, &ControlRequest::Shutdown).unwrap();
    assert!(shutdown.ok);
    let status = daemon.wait().unwrap();
    assert!(status.success());
    let stopped_again = json_output(root, &["status", "--json"]);
    assert_eq!(stopped_again["daemon"], "stopped");

    let default_root = root.join(".agents/skills");
    let moved_root = root.join(".agents/skills-moved");
    fs::rename(&default_root, &moved_root).unwrap();
    let mut restarted = start_daemon(root);
    wait_for_daemon(&platform_paths);
    assert!(!default_root.exists());
    let state = StateStore::open(&database).unwrap();
    let collection = state.collection(".agents").unwrap().unwrap();
    assert_eq!(collection.scan_status, CollectionScanStatus::Missing);
    assert!(matches!(
        state
            .record(".agents", "reviewer/SKILL.md")
            .unwrap()
            .unwrap()
            .kind(),
        RecordKind::File { .. }
    ));
    drop(state);
    let shutdown = send_request(&platform_paths, &ControlRequest::Shutdown).unwrap();
    assert!(shutdown.ok);
    assert!(restarted.wait().unwrap().success());

    let socket = skillsync::daemon::socket_path(&platform_paths);
    let listener = UnixListener::bind(&socket).unwrap();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let server = std::thread::spawn(move || {
        ready_sender.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 256];
        let _ = stream.read(&mut request).unwrap();
        stream.write_all(b"not-json\n").unwrap();
    });
    ready_receiver.recv().unwrap();
    let live_protocol_error = output(root, &["status", "--json"]);
    assert!(!live_protocol_error.status.success());
    let error: Value = serde_json::from_slice(&live_protocol_error.stdout).unwrap();
    assert_eq!(error["error"]["code"], "operation_failed");
    server.join().unwrap();
}
