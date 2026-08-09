use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use skillsync::config::PlatformPaths;
use skillsync::daemon::{ControlRequest, send_request};
use skillsync::identity::{GroupId, IdentityStore};
use skillsync::roster::{RosterChange, RosterMember, RosterRevision};
use skillsync::state::{OperationalEvent, StateStore};
use tempfile::TempDir;

use base64::Engine as _;

struct DeviceFixture {
    root: PathBuf,
    home: PathBuf,
    paths: PlatformPaths,
}

struct JoiningFixture {
    url: String,
    ticket: Arc<Mutex<Option<String>>>,
    stages: Arc<Mutex<Vec<&'static str>>>,
    thread: thread::JoinHandle<()>,
}

struct StalledJoiningFixture {
    url: String,
    received: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl StalledJoiningFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (received_tx, received) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_http_request(&mut stream);
            received_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let body = br#"{"error":{"code":"join_unavailable","message":"released"}}"#;
            write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        Self {
            url,
            received,
            release,
            thread,
        }
    }

    fn wait_until_stalled(&self) {
        self.received.recv_timeout(Duration::from_secs(10)).unwrap();
    }

    fn finish(self) {
        self.release.send(()).unwrap();
        self.thread.join().unwrap();
    }
}

impl JoiningFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let ticket = Arc::new(Mutex::new(None));
        let shared_ticket = ticket.clone();
        let stages = Arc::new(Mutex::new(Vec::new()));
        let shared_stages = stages.clone();
        let thread = thread::spawn(move || {
            for request_number in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                shared_stages.lock().unwrap().push(if request_number == 0 {
                    "create_received"
                } else {
                    "claim_received"
                });
                let header_end = request
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let body: serde_json::Value =
                    serde_json::from_slice(&request[header_end..]).unwrap();
                let response = if request_number == 0 {
                    let inviter_ticket = body["inviter_ticket"].as_str().unwrap().to_owned();
                    *shared_ticket.lock().unwrap() = Some(inviter_ticket);
                    serde_json::json!({
                        "code": "furry-salamander",
                        "join_nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]),
                        "expires_at": "2026-08-08T17:20:00Z"
                    })
                } else {
                    assert_eq!(body["code"], "furry-salamander");
                    serde_json::json!({
                        "protocol": "skillsync/1",
                        "inviter_ticket": shared_ticket.lock().unwrap().clone().unwrap(),
                        "join_nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]),
                        "expires_at": "2026-08-08T17:20:00Z"
                    })
                };
                let response = serde_json::to_vec(&response).unwrap();
                let status = if request_number == 0 {
                    "201 Created"
                } else {
                    "200 OK"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(&response).unwrap();
                shared_stages.lock().unwrap().push(if request_number == 0 {
                    "create_sent"
                } else {
                    "claim_sent"
                });
            }
        });
        Self {
            url,
            ticket,
            stages,
            thread,
        }
    }

    fn wait_created(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.ticket.lock().unwrap().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("invitation was not created");
    }

    fn finish(self) {
        self.thread.join().unwrap();
    }

    fn stages(&self) -> String {
        self.stages.lock().unwrap().join(",")
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let header_end = loop {
        if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
        let mut bytes = [0_u8; 1024];
        let read = stream.read(&mut bytes).unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&bytes[..read]);
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let mut bytes = [0_u8; 1024];
        let read = stream.read(&mut bytes).unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&bytes[..read]);
    }
    request.truncate(header_end + content_length);
    request
}

impl DeviceFixture {
    fn new(parent: &Path, name: &str, seed: u8) -> Self {
        let root = parent.join(name);
        let home = root.join("home");
        let config_dir = root.join("config");
        let paths = PlatformPaths {
            config_file: config_dir.join("config.toml"),
            data_dir: root.join("data"),
            runtime_dir: root.join("run"),
        };
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&paths.data_dir).unwrap();
        let key = paths.data_dir.join("identity.key");
        fs::write(&key, [seed; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let reference = paths.data_dir.join("identity.ref");
        fs::write(&reference, b"file\nidentity.key\n").unwrap();
        fs::set_permissions(&reference, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &paths.config_file,
            format!(
                r#"[device]
name = "{name}"

[iroh]
preset = "custom"
relay_urls = ["http://127.0.0.1:9"]
address_lookup_urls = ["http://127.0.0.1:9/pkarr"]

[sync]
interval = "1h"
"#
            ),
        )
        .unwrap();
        Self { root, home, paths }
    }

    fn agents(&self) -> PathBuf {
        self.home.join(".agents/skills")
    }

    fn set_joining_service(&self, url: &str) {
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(&self.paths.config_file)
            .unwrap();
        writeln!(
            config,
            "\n[joining]\nservice_url = {url:?}\ninvitation_ttl = \"60s\""
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_skillsync"));
        command
            .env("HOME", &self.home)
            .env(
                "SKILLSYNC_CONFIG_DIR",
                self.paths.config_file.parent().unwrap(),
            )
            .env("SKILLSYNC_DATA_DIR", &self.paths.data_dir)
            .env("SKILLSYNC_RUNTIME_DIR", &self.paths.runtime_dir);
        command
    }

    fn spawn(&self) -> Child {
        self.command()
            .arg("__daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

fn initialize_group(first: &DeviceFixture, second: &DeviceFixture) {
    let (first_identity, _) = IdentityStore::new(&first.paths).load_or_create().unwrap();
    let (second_identity, _) = IdentityStore::new(&second.paths).load_or_create().unwrap();
    let genesis =
        RosterRevision::genesis(GroupId::from_bytes([91; 32]), "first", &first_identity).unwrap();
    let admission = RosterRevision::child(
        &genesis,
        RosterChange::Admit(RosterMember::new(second_identity.endpoint_id(), "second").unwrap()),
        &first_identity,
    )
    .unwrap();
    for fixture in [first, second] {
        let mut state = StateStore::open(&fixture.paths.data_dir.join("state.sqlite3")).unwrap();
        state.insert_roster_revision(&genesis).unwrap();
        state.insert_roster_revision(&admission).unwrap();
        for (collection, relative) in [
            (".agents", ".agents/skills"),
            (".claude", ".claude/skills"),
            (".codex", ".codex/skills"),
        ] {
            let root = fixture.home.join(relative);
            fs::create_dir_all(&root).unwrap();
            state
                .add_collection(collection, &root, Some(&fs::canonicalize(&root).unwrap()))
                .unwrap();
        }
    }
}

fn wait_running(fixture: &DeviceFixture, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if send_request(&fixture.paths, &ControlRequest::Status).is_ok_and(|response| response.ok) {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = child
                .stderr
                .take()
                .map(|stderr| std::io::read_to_string(stderr).unwrap_or_default())
                .unwrap_or_default();
            panic!("daemon exited early with {status}: {stderr}");
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not start at {}", fixture.root.display());
}

fn endpoint_addr(fixture: &DeviceFixture) -> String {
    let response = send_request(&fixture.paths, &ControlRequest::EndpointAddr).unwrap();
    response.unwrap_result()["address"]
        .as_str()
        .unwrap()
        .to_owned()
}

trait ResponseResult {
    fn unwrap_result(self) -> serde_json::Value;
}

impl ResponseResult for skillsync::daemon::ControlResponse {
    fn unwrap_result(self) -> serde_json::Value {
        assert!(self.ok, "control request failed: {:?}", self.error);
        self.result.unwrap()
    }
}

fn connect_hints(first: &DeviceFixture, second: &DeviceFixture) {
    let first_addr = endpoint_addr(first);
    let second_addr = endpoint_addr(second);
    let first_endpoint = serde_json::from_str::<iroh::EndpointAddr>(&first_addr)
        .unwrap()
        .id;
    let second_endpoint = serde_json::from_str::<iroh::EndpointAddr>(&second_addr)
        .unwrap()
        .id;
    let mut first_state = StateStore::open(&first.paths.data_dir.join("state.sqlite3")).unwrap();
    first_state
        .replace_peer_hints(
            skillsync::sync::endpoint_from_iroh(second_endpoint),
            &[second_addr],
            1,
        )
        .unwrap();
    let mut second_state = StateStore::open(&second.paths.data_dir.join("state.sqlite3")).unwrap();
    second_state
        .replace_peer_hints(
            skillsync::sync::endpoint_from_iroh(first_endpoint),
            &[first_addr],
            1,
        )
        .unwrap();
}

fn scan_and_sync(fixture: &DeviceFixture) {
    assert!(
        send_request(&fixture.paths, &ControlRequest::Scan)
            .unwrap()
            .ok
    );
    let response = send_request(&fixture.paths, &ControlRequest::Sync { wait: true }).unwrap();
    let result = response.unwrap_result();
    assert_eq!(result["attempted"].as_u64(), Some(1));
    assert_eq!(result["succeeded"].as_u64(), Some(1));
}

fn wait_contents(path: &Path, expected: Option<&[u8]>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match (fs::read(path), expected) {
            (Ok(bytes), Some(expected)) if bytes == expected => return,
            (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => return,
            _ => thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("path did not converge: {}", path.display());
}

fn stop(fixture: &DeviceFixture, child: &mut Child) {
    let _ = send_request(&fixture.paths, &ControlRequest::Shutdown);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.kill().unwrap();
    panic!("daemon did not stop cleanly");
}

fn wait_output(mut child: Child, timeout: Duration) -> std::process::Output {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        thread::sleep(Duration::from_millis(25));
    }
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    panic!(
        "command timed out: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn wait_for_output_marker(path: &Path, child: &mut Child, marker: &[u8], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let output = fs::read(path).unwrap_or_default();
        if output.windows(marker.len()).any(|window| window == marker) {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "command exited before readiness marker with {status}: stdout={}",
                String::from_utf8_lossy(&output)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "command did not emit its readiness marker: stdout={}",
        String::from_utf8_lossy(&fs::read(path).unwrap_or_default())
    );
}

fn wait_outputs_together(
    mut first: Child,
    mut second: Child,
    timeout: Duration,
) -> (std::process::Output, std::process::Output, bool) {
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        let first_status = first.try_wait().unwrap();
        let second_status = second.try_wait().unwrap();
        if first_status.is_some() && second_status.is_some() {
            break;
        }
        if first_status.is_some_and(|status| !status.success())
            || second_status.is_some_and(|status| !status.success())
        {
            let _ = first.kill();
            let _ = second.kill();
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = first.kill();
            let _ = second.kill();
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let first_output = first.wait_with_output().unwrap();
    let second_output = second.wait_with_output().unwrap();
    (first_output, second_output, timed_out)
}

#[test]
fn two_daemons_sync_create_edit_delete_and_restart_without_external_services() {
    let temp = TempDir::new().unwrap();
    let first = DeviceFixture::new(temp.path(), "first", 51);
    let second = DeviceFixture::new(temp.path(), "second", 52);
    initialize_group(&first, &second);
    let mut first_child = first.spawn();
    let mut second_child = second.spawn();
    wait_running(&first, &mut first_child);
    wait_running(&second, &mut second_child);
    connect_hints(&first, &second);

    let first_file = first.agents().join("review/SKILL.md");
    let second_file = second.agents().join("review/SKILL.md");
    fs::create_dir_all(first_file.parent().unwrap()).unwrap();
    fs::write(&first_file, b"created").unwrap();
    assert!(
        send_request(&first.paths, &ControlRequest::Scan)
            .unwrap()
            .ok
    );
    wait_contents(&second_file, Some(b"created"));

    fs::write(&second_file, b"edited").unwrap();
    scan_and_sync(&second);
    wait_contents(&first_file, Some(b"edited"));

    fs::remove_file(&first_file).unwrap();
    scan_and_sync(&first);
    wait_contents(&second_file, None);

    stop(&second, &mut second_child);
    fs::create_dir_all(first_file.parent().unwrap()).unwrap();
    fs::write(&first_file, b"after-restart").unwrap();
    assert!(
        send_request(&first.paths, &ControlRequest::Scan)
            .unwrap()
            .ok
    );
    second_child = second.spawn();
    wait_running(&second, &mut second_child);
    wait_contents(&second_file, Some(b"after-restart"));

    stop(&first, &mut first_child);
    stop(&second, &mut second_child);
}

#[test]
fn stalled_join_excludes_daemon_and_second_join_until_every_error_path_releases_the_lock() {
    let temp = TempDir::new().unwrap();
    let device = DeviceFixture::new(temp.path(), "locked", 58);
    let service = StalledJoiningFixture::start();
    device.set_joining_service(&service.url);

    let mut first = device.command();
    first
        .args(["join", "opaque", "--name", "first"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let first = first.spawn().unwrap();
    service.wait_until_stalled();

    let state = StateStore::open(&device.paths.data_dir.join("state.sqlite3")).unwrap();
    assert!(state.selected_roster_chain().unwrap().is_empty());
    drop(state);

    let mut daemon = device.command();
    daemon
        .arg("__daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let daemon_output = wait_output(daemon.spawn().unwrap(), Duration::from_secs(10));
    assert!(!daemon_output.status.success());
    assert!(
        String::from_utf8_lossy(&daemon_output.stderr)
            .contains("another skillsync daemon or join is active")
    );

    let mut second = device.command();
    second
        .args(["join", "opaque", "--name", "second"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let second_output = wait_output(second.spawn().unwrap(), Duration::from_secs(10));
    assert!(!second_output.status.success());
    assert!(
        String::from_utf8_lossy(&second_output.stderr)
            .contains("another skillsync daemon or join is active")
    );

    service.finish();
    let first_output = wait_output(first, Duration::from_secs(10));
    assert!(!first_output.status.success());

    let mut daemon = device.spawn();
    wait_running(&device, &mut daemon);
    stop(&device, &mut daemon);
}

#[test]
fn third_device_joins_one_member_learns_every_peer_syncs_and_is_refused_after_removal() {
    let temp = TempDir::new().unwrap();
    let first = DeviceFixture::new(temp.path(), "first", 61);
    let second = DeviceFixture::new(temp.path(), "second", 62);
    let third = DeviceFixture::new(temp.path(), "third", 63);
    initialize_group(&first, &second);
    let joining = JoiningFixture::start();
    first.set_joining_service(&joining.url);
    third.set_joining_service(&joining.url);

    let mut first_child = first.spawn();
    let mut second_child = second.spawn();
    wait_running(&first, &mut first_child);
    wait_running(&second, &mut second_child);
    connect_hints(&first, &second);

    let shared_file = second.agents().join("joined/SKILL.md");
    fs::create_dir_all(shared_file.parent().unwrap()).unwrap();
    fs::write(&shared_file, b"learned through one member").unwrap();
    scan_and_sync(&second);
    wait_contents(
        &first.agents().join("joined/SKILL.md"),
        Some(b"learned through one member"),
    );

    let mut invite = first.command();
    let invite_stdout_path = temp.path().join("invite.stdout");
    invite
        .arg("invite")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(fs::File::create(&invite_stdout_path).unwrap()))
        .stderr(Stdio::piped());
    let mut invite = invite.spawn().unwrap();
    invite.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
    invite.stdin.take();
    joining.wait_created();
    // The service receives creation before the daemon activates the invitation.
    wait_for_output_marker(
        &invite_stdout_path,
        &mut invite,
        b"Waiting for another device",
        Duration::from_secs(15),
    );

    let third_identity = IdentityStore::new(&third.paths).load_or_create().unwrap().0;
    let third_endpoint = third_identity.endpoint_id();
    let mut join = third.command();
    join.arg("join")
        .arg("furry-salamander")
        .arg("--name")
        .arg("third")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let join = join.spawn().unwrap();
    let (mut invite_output, join_output, commands_timed_out) =
        wait_outputs_together(invite, join, Duration::from_secs(60));
    invite_output.stdout = fs::read(&invite_stdout_path).unwrap();
    assert!(
        !commands_timed_out,
        "commands timed out: stages={} invite stdout={} stderr={} join stdout={} stderr={}",
        joining.stages(),
        String::from_utf8_lossy(&invite_output.stdout),
        String::from_utf8_lossy(&invite_output.stderr),
        String::from_utf8_lossy(&join_output.stdout),
        String::from_utf8_lossy(&join_output.stderr)
    );
    assert!(
        invite_output.status.success() && join_output.status.success(),
        "invite stdout={} stderr={} join stdout={} stderr={}",
        String::from_utf8_lossy(&invite_output.stdout),
        String::from_utf8_lossy(&invite_output.stderr),
        String::from_utf8_lossy(&join_output.stdout),
        String::from_utf8_lossy(&join_output.stderr)
    );
    joining.finish();
    let invite_stdout = String::from_utf8(invite_output.stdout).unwrap();
    let join_stdout = String::from_utf8(join_output.stdout).unwrap();
    assert!(invite_stdout.contains(&third_endpoint.to_string()));
    assert!(join_stdout.contains(&third_endpoint.to_string()));
    assert!(invite_stdout.contains("Device approved."));
    assert!(join_stdout.contains("Initial synchronization complete."));

    let third_state = StateStore::open(&third.paths.data_dir.join("state.sqlite3")).unwrap();
    let third_chain = third_state.selected_roster_chain().unwrap();
    let third_tip = third_chain.last().unwrap();
    assert_eq!(third_tip.members().len(), 3);
    assert!(third_tip.members().contains_key(&third_endpoint));
    let second_endpoint = IdentityStore::new(&second.paths)
        .load_or_create()
        .unwrap()
        .0
        .endpoint_id();
    assert!(!third_state.peer_hints(second_endpoint).unwrap().is_empty());
    drop(third_state);
    let peers = third
        .command()
        .args(["--json", "peers", "list"])
        .output()
        .unwrap();
    assert!(peers.status.success());
    let peers: serde_json::Value = serde_json::from_slice(&peers.stdout).unwrap();
    assert_eq!(peers["peers"].as_array().unwrap().len(), 3);
    wait_contents(
        &third.agents().join("joined/SKILL.md"),
        Some(b"learned through one member"),
    );

    let removed = first
        .command()
        .args(["--json", "peers", "remove", &third_endpoint.to_string()])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "remove stderr={}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["removed"].as_bool(), Some(true));
    let _ = send_request(&first.paths, &ControlRequest::Sync { wait: true }).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let state = StateStore::open(&second.paths.data_dir.join("state.sqlite3")).unwrap();
        if state
            .selected_roster_chain()
            .unwrap()
            .last()
            .is_some_and(|tip| !tip.members().contains_key(&third_endpoint))
        {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let second_state = StateStore::open(&second.paths.data_dir.join("state.sqlite3")).unwrap();
    let selected_after_removal = second_state.selected_roster_chain().unwrap();
    assert!(
        !selected_after_removal
            .last()
            .unwrap()
            .members()
            .contains_key(&third_endpoint)
    );

    let mut third_child = third.spawn();
    wait_running(&third, &mut third_child);
    let refused = send_request(&third.paths, &ControlRequest::Sync { wait: true })
        .unwrap()
        .result
        .unwrap();
    assert_eq!(refused["succeeded"].as_u64(), Some(0));
    let third_after_refusal =
        StateStore::open(&third.paths.data_dir.join("state.sqlite3")).unwrap();
    assert!(
        third_after_refusal
            .selected_roster_chain()
            .unwrap()
            .last()
            .unwrap()
            .members()
            .contains_key(&third_endpoint)
    );
    let rejection_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let second_logs = StateStore::open(&second.paths.data_dir.join("state.sqlite3")).unwrap();
        if second_logs.logs().unwrap().iter().any(|log| {
            matches!(
                log.event,
                OperationalEvent::PeerRejected { peer_endpoint }
                    if peer_endpoint == third_endpoint
            )
        }) {
            break;
        }
        assert!(
            Instant::now() < rejection_deadline,
            "current peer did not record refusing the removed EndpointID"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let stale_target = skillsync::identity::DeviceIdentity::from_secret([64; 32]);
    let stale = RosterRevision::child(
        third_chain.last().unwrap(),
        RosterChange::Admit(RosterMember::new(stale_target.endpoint_id(), "stale-target").unwrap()),
        &third_identity,
    )
    .unwrap();
    drop(second_state);
    let mut second_state = StateStore::open(&second.paths.data_dir.join("state.sqlite3")).unwrap();
    second_state.insert_roster_revision(&stale).unwrap();
    let selected = second_state.selected_roster_chain().unwrap();
    assert!(
        !selected
            .last()
            .unwrap()
            .members()
            .contains_key(&third_endpoint)
    );
    assert!(
        !selected
            .last()
            .unwrap()
            .members()
            .contains_key(&stale_target.endpoint_id())
    );

    stop(&first, &mut first_child);
    stop(&second, &mut second_child);
    stop(&third, &mut third_child);
}
