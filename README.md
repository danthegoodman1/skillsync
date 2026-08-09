# Skillsync

Keep agent skills synchronized between your devices over encrypted
P2P connections.

Skillsync is a small local-first daemon. It watches the standard Agents,
Claude, and Codex skill directories and sends changes directly between your
approved macOS and Linux devices over [iroh](https://www.iroh.computer/).

The maintainer-hosted joining service turns a short code into the first iroh
connection. Normal synchronization is peer to peer and end-to-end encrypted.

## Contents

- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Collections](#collections)
- [Joining a device](#joining-a-device)
- [Sync rules](#sync-rules)
- [CLI and automation](#cli-and-automation)
- [Configuration](#configuration)
- [Security and privacy](#security-and-privacy)
- [Troubleshooting](#troubleshooting)

## Quickstart

Install Skillsync:

```console
cargo install skillsync
```

Set up the first device:

```console
$ skillsync setup
Device: studio-mac
Group: personal

Collections:
  .agents  -> ~/.agents/skills
  .claude  -> ~/.claude/skills
  .codex   -> ~/.codex/skills

Setup complete.
```

Enable the daemon:

```console
$ skillsync enable
Skillsync is running and will start automatically at login.
```

Create a joining code:

```console
$ skillsync invite
Joining code: funny-capybara
Expires in 10 minutes.

Waiting for another device…
```

On the other machine:

```console
$ skillsync join funny-capybara --name work-laptop
Connecting to studio-mac…

This device's iroh EndpointID:
03ce2e2f55af140d0b18395fff054d3f3ab6a30aa680e4a2a3ab4526838151a5

Compare this exact EndpointID on studio-mac.
Waiting for approval…
```

The inviting device shows the identity authenticated by iroh:

```console
Join request from: work-laptop
Joining iroh EndpointID:
03ce2e2f55af140d0b18395fff054d3f3ab6a30aa680e4a2a3ab4526838151a5

Does this exactly match the EndpointID on work-laptop? [y/N] y
Device approved.
```

The joining device receives the peer list and immediately synchronizes the
three default collections.

```console
$ skillsync status
Device   work-laptop
Peers    1 online
Files    24 synchronized
Daemon   running
```

Run `skillsync enable` on the new device to keep its daemon running across
future logins.

## How it works

Every device has a persistent iroh EndpointID. Joining adds that identity to the
group's approved peer list. Once approved, a device can connect to any known
peer, learn about the remaining members, and synchronize directly.

On connection, peers exchange a complete manifest for each shared collection.
A manifest contains one small record per path: its filesystem write timestamp
in UTC, author EndpointID, content hash, and whether it was deleted. Peers
compare those records and transfer only files whose winning content is missing.

Skill collections are small, so exchanging complete manifests is fast and
keeps the protocol predictable.

Incoming files are streamed to temporary files, verified against their BLAKE3
hash, and atomically renamed into place. Files become visible only after the
complete contents pass verification.

The daemon reconciles with every reachable peer when it starts and at the
configured sync interval. This catches changes made while a device was offline
and repairs missed filesystem or peer notifications.

The implementation architecture is described in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Collections

Every device starts with three collections:

| Collection | Local path |
| --- | --- |
| `.agents` | `~/.agents/skills` |
| `.claude` | `~/.claude/skills` |
| `.codex` | `~/.codex/skills` |

Each collection contains one directory per skill:

```text
~/.agents/skills/
├── release-notes/
│   ├── SKILL.md
│   └── references/
└── test-reviewer/
    ├── SKILL.md
    └── scripts/
```

### Custom collections

Add a local directory to a named collection:

```console
skillsync collections add team-skills ~/work/agent-skills
```

`add` is idempotent:

- If the collection is new, its name becomes visible to the group and the path
  is used on this device.
- If a peer already advertises that collection, the command attaches this
  device's path to it.
- Repeating the same command changes nothing.
- Running it with a new path replaces the local path after confirmation.

Each device chooses its own path. Run the same command on every device where
that collection should materialize:

```console
# On another device
skillsync collections add team-skills ~/different/path
```

A custom collection begins syncing on a device after it has a local path.
Removing a collection stops local syncing and leaves its files in place:

```console
skillsync collections remove team-skills
```

### Symlinked roots

Skillsync follows symlinked collection roots automatically and synchronizes
their contents as ordinary files and directories on other devices.

## Joining a device

`skillsync invite` and `skillsync join` are the only device-admission path.

The maintainers of this repository operate the default joining service at
`https://skillsync.danthegoodman.com` using the open-source Cloudflare Workers and
Durable Objects deployment from this repository. The service stores one
short-lived invitation containing the inviter's iroh ticket. Normal sync moves
group state and skill contents directly between peers.

You can host the same service or use any compatible implementation:

```toml
[joining]
service_url = "https://join.example.net"

[joining.headers]
Authorization = "Bearer private-token"
```

The environment variable `SKILLSYNC_JOINING_SERVICE_URL` overrides the
configured URL. Custom headers are sent with both joining-service requests and
their values are redacted by `skillsync config show`. Both devices must use the
same joining service and provide any headers it requires.

The complete two-endpoint HTTP contract is documented in
[JOINING_SERVICE.md](JOINING_SERVICE.md).

## Sync rules

Skillsync uses deterministic last-write-wins for every file and deletion.

The ordering key is:

```text
(filesystem write time in UTC, author EndpointID)
```

The later filesystem timestamp wins. The lexicographically greater EndpointID
breaks the rare exact-timestamp tie so every peer reaches the same result. If
the timestamp and author are both equal, the lexicographically greater BLAKE3
hash of the complete canonical record is the final tie-breaker. Files and
tombstones therefore have one total ordering.

When peers compare a path:

- The newer record wins and is materialized.
- The older record is rejected and logged.
- Skillsync discards losing contents after logging the rejection.
- Deletes use tombstones and follow the same ordering.

Skillsync retains at most one tombstone for each distinct deleted path.

If an older local write has already replaced the file on disk, Skillsync keeps
advertising the winning record. The path reports as degraded until the daemon
restores the winning bytes from a reachable peer, then discards the rejected
bytes.

Concurrent offline edits can therefore discard one version permanently. Use
Git or normal backups when file history matters.

A timestamp too far ahead of the receiving device's clock is rejected and
reported by `skillsync doctor`. Applied remote files retain the winning write
time. Scans recognize the durable observed mtime, size, and BLAKE3 fingerprint
as a synchronized write.

## CLI and automation

| Command | Purpose |
| --- | --- |
| `skillsync setup` | Create the local identity, group, and default collections |
| `skillsync enable` | Register the daemon for boot or login and start it now |
| `skillsync disable` | Unregister startup and stop the daemon |
| `skillsync invite` | Create a short-lived joining code |
| `skillsync join <code> --name <name>` | Join an existing group |
| `skillsync status` | Show daemon, peer, and synchronization health |
| `skillsync sync [--wait]` | Synchronize with reachable peers now |
| `skillsync collections list` | Show local collections and paths |
| `skillsync collections add <name> <path>` | Create or attach a collection locally |
| `skillsync collections remove <name>` | Stop syncing a collection on this device |
| `skillsync peers list` | Show approved devices and connection state |
| `skillsync peers remove <device>` | Remove a device from the group |
| `skillsync config show` | Show the effective configuration |
| `skillsync config path` | Show the configuration file path |
| `skillsync doctor` | Check paths, clocks, identity, discovery, and connectivity |
| `skillsync logs [--follow]` | Read synchronization and rejection logs |

Every command supports `--json` for agents and scripts. Standard output contains
only the requested result. Progress and diagnostics go to standard error.

```console
$ skillsync status --json
```

```json
{
  "device": {
    "name": "work-laptop",
    "endpoint_id": "03ce2e2f55af140d0b18395fff054d3f3ab6a30aa680e4a2a3ab4526838151a5"
  },
  "daemon": "running",
  "peers": {
    "known": 1,
    "online": 1
  },
  "files": {
    "synchronized": 24,
    "degraded": 0
  }
}
```

JSON field names and meanings are stable within a major release. Failures use a
nonzero exit status and emit an `error` object with a machine-readable `code`
and human-readable `message`. Streaming commands emit one complete JSON object
per line. The daemon's local control socket is private implementation detail.
Automation uses the CLI.

## Configuration

Skillsync's defaults provide a complete configuration. Inspect it with:

```console
skillsync config show
skillsync config path
```

```toml
[device]
name = "work-laptop"

[joining]
service_url = "https://skillsync.danthegoodman.com"
invitation_ttl = "10m"

[iroh]
preset = "n0"

[sync]
interval = "15m"
max_future_clock_skew = "5m"
ignore = ["**/.git/**", "**/.DS_Store", "**/*.swp"]

[logging]
max_entries = 1000
```

The `n0` preset uses iroh's hosted address lookup and public relays. Custom
infrastructure replaces that preset:

```toml
[iroh]
preset = "custom"
relay_urls = ["https://relay.example.net"]
address_lookup_urls = ["https://lookup.example.net"]
```

Use the same custom infrastructure configuration on every group device.

Joining services accept invitation TTLs up to 15 minutes and reject longer
requests.

The configuration file contains user settings. Device identities and sync
metadata live in the platform data directory.

## Security and privacy

- Iroh authenticates EndpointIDs and encrypts peer connections end to end.
- The inviter compares the joiner's complete EndpointID before approval.
- The approved peer list is signed and shared only with group members.
- Peers refuse an identity after learning its signed removal from the group.
- Received paths are normalized and constrained beneath the configured
  collection root.
- Received files are hash-verified before atomic replacement.

The joining service can observe IP addresses, joining codes, timing, and the
inviter's iroh ticket. It is trusted to return the ticket associated with the
claimed code. Membership approval stays with the inviting device, and normal
sync traffic travels directly between peers. Iroh relays observe encrypted
traffic metadata and carry ciphertext.

Skills can contain executable scripts and agent instructions. Only approve
devices you trust.

## Troubleshooting

Start with:

```console
skillsync doctor
```

It checks the daemon, collection roots, unsafe symlinks, clock skew, iroh
address discovery, peer connectivity, and relay fallback. Diagnostic output
excludes identity secrets, joining codes, and skill contents.

If an expected edit loses the last-write-wins comparison, inspect:

```console
skillsync logs
```

The log includes the path, both UTC timestamps, both EndpointIDs, and the reason
the candidate was rejected. Skillsync discards the losing file contents.
