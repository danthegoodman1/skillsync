use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use skillsync::config::PlatformPaths;
use skillsync::daemon::{ControlRequest, send_request};
use skillsync::identity::{GroupId, IdentityStore};
use skillsync::roster::{RosterChange, RosterMember, RosterRevision};
use skillsync::state::StateStore;
use tempfile::TempDir;

struct DeviceFixture {
    root: PathBuf,
    home: PathBuf,
    paths: PlatformPaths,
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

    fn spawn(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_skillsync"))
            .arg("__daemon")
            .env("HOME", &self.home)
            .env(
                "SKILLSYNC_CONFIG_DIR",
                self.paths.config_file.parent().unwrap(),
            )
            .env("SKILLSYNC_DATA_DIR", &self.paths.data_dir)
            .env("SKILLSYNC_RUNTIME_DIR", &self.paths.runtime_dir)
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
