# Skillsync architecture

Skillsync is a small peer-to-peer daemon that keeps agent skill directories in
sync across a trusted group of personal devices.

The architecture favors a small number of strong guarantees over protocol
generality. Skill collections are small, groups contain a handful of devices,
and every admitted device is trusted to read and change every shared skill.

## Contents

- [Design principles](#design-principles)
- [System overview](#system-overview)
- [Device model](#device-model)
- [Collections](#collections)
- [Replication model](#replication-model)
- [Peer protocol](#peer-protocol)
- [Joining](#joining)
- [Membership](#membership)
- [Local state](#local-state)
- [Failure behavior](#failure-behavior)
- [Security boundaries](#security-boundaries)
- [Implementation boundaries](#implementation-boundaries)
- [Invariants](#invariants)

## Design principles

1. **The filesystem is the interface.** Users and agents edit ordinary files,
   and the daemon observes those files directly.
2. **Peers own the data.** Skill contents move directly between group devices
   over authenticated, encrypted iroh connections.
3. **One peer is enough.** A device that reaches any current member can learn
   the roster and synchronize all content that member has.
4. **Small data permits simple protocols.** Peers exchange complete manifests
   because each group contains a modest number of skill files.
5. **One winner is enough.** Each path has one current value, selected by
   deterministic last-write-wins. Losing versions are logged and discarded.
6. **Infrastructure only introduces devices.** The joining service converts an
   opaque code into the first iroh connection and leaves the data path.
7. **Correctness is visible.** Rejections and unreachable peers are explicit in
   status, logs, and `doctor`. Files appear after complete transfer and hash
   verification.

## System overview

```text
                          create / claim code
                  +-----------------------------+
                  |                             |
                  v                             v
            +-----------------------------------------+
            | joining service                         |
            | opaque code -> inviter iroh ticket      |
            +-----------------------------------------+
                  |                             |
                  | ticket + nonce only         | short-lived state
                  v                             v

        +-------------------+   iroh QUIC   +-------------------+
        | device A          |<=============>| device B          |
        |                   | authenticated |                   |
        | CLI -> daemon     |   encrypted   | daemon <- CLI     |
        |        |          |               |          |        |
        | skill directories |               | skill directories |
        +-------------------+               +-------------------+
                  ^                             ^
                  +-------- other peers --------+
```

Iroh supplies EndpointID authentication, address lookup, NAT traversal, and
encrypted relay fallback. The joining service is a separate, replaceable HTTP
service described in [JOINING_SERVICE.md](JOINING_SERVICE.md). It is used only
before the inviter and joiner have a direct iroh session.

`iroh.preset = "n0"` uses iroh's hosted address lookup and public relay preset.
`iroh.preset = "custom"` builds the endpoint from the configured
`address_lookup_urls` and `relay_urls`. Group devices use the same custom
address lookup set so every EndpointID remains resolvable.

Every device has the same role. The device that creates a group becomes an
ordinary member after setup, and any active member can invite another device.

## Device model

Each installation runs one daemon for the local operating-system user. The
daemon owns:

- one persistent iroh keypair and EndpointID
- one human-readable device name
- one group identity and approved-device roster
- collection paths and filesystem watches
- a small SQLite metadata database
- one iroh endpoint for joining and synchronization
- a user-local control socket used by the `skillsync` CLI

The CLI is a thin client. Commands report results on standard output, progress
and diagnostics on standard error, and expose the same result shapes through
`--json`. The CLI is the supported automation surface. Its local daemon socket
remains an internal transport.

An installation belongs to one group. This keeps configuration, membership,
and collection naming unambiguous.

`skillsync enable` registers the daemon with the operating system's user-level
startup manager and starts it immediately. It starts at login, or at boot where
the platform activates user services before login. The registration uses a
launchd LaunchAgent on macOS and a systemd user service on Linux. Repeating the
command repairs the registration and leaves one running daemon.

`skillsync disable` removes that startup registration and stops the daemon.
Repeating it succeeds, and the device identity, group membership, configuration,
metadata, and synchronized files remain in place.

## Collections

A collection is a name shared by the group and a local directory chosen
independently on each participating device. Every device starts with:

| Name | Local path |
| --- | --- |
| `.agents` | `~/.agents/skills` |
| `.claude` | `~/.claude/skills` |
| `.codex` | `~/.codex/skills` |

Default collections are attached automatically during setup and join. A custom
collection is advertised by name when a member runs:

```console
skillsync collections add team-skills ~/work/agent-skills
```

The command performs both operations that matter: it introduces the shared
name if necessary and attaches this device's local path. Other devices see the
advertised name and begin participating after attaching their own path with the
same command.

Removing a collection detaches only the current device and leaves its local
files and every other device unchanged.

### Paths and symlinks

The configured collection root may be a symlink. The daemon resolves it,
watches the physical directory, and publishes entries under the collection's
logical name.

Skillsync materializes regular file and directory contents. A peer whose
`.claude/skills` points at `.agents/skills` therefore still sends `.claude` and
`.agents` as distinct collections, and a receiving peer materializes each in
its own configured directory.

A shared physical root holds one state. A file received through either
collection changes that root and is consequently published in both manifests.
The aliased collections converge to the same contents across the group, which
matches the local meaning of the symlink.

Nested symlinks are followed only when their resolved target remains beneath
the resolved collection root. Links that escape the root are ignored and
reported. This keeps a collection from accidentally publishing unrelated
files or secrets. Scans track resolved filesystem identities and terminate a
branch when they encounter a symlink cycle.

Collection names are opaque identifiers. Relative paths use `/` as the
protocol separator, are UTF-8, and are rejected if they are absolute, contain
an empty component, or contain `.` or `..` components. A receiver also rejects
and reports paths that cannot be represented on its local filesystem or that
collide under its filesystem's filename comparison rules.

## Replication model

### One record per path

The current state of a collection is a manifest with one record for each file
or deletion:

```text
collection
relative path
filesystem write time in UTC nanoseconds
author EndpointID
kind: file | tombstone
file size and BLAKE3 hash (files only)
```

Directory entries are implicit. Receiving a file creates its parent directories
as needed. The authenticated iroh connection identifies the approved sending
device, and every approved device has authority to replace file contents.

### Last-write-wins

Records for the same collection and path are ordered by:

```text
(filesystem write time in UTC, author EndpointID)
```

The later filesystem timestamp wins. The lexicographically greater EndpointID
is used only when two distinct records have the exact same timestamp, which
gives every peer the same answer. For two records with the same timestamp and
author, the lexicographically greater BLAKE3 hash of the deterministic encoding
of the complete record is the final tie-breaker. The encoding includes the
record kind, so it orders a file and tombstone from the same author at the same
timestamp.

When a peer or local scan presents an older record, the daemon rejects it and
logs the path, timestamps, authors, and reason, then discards the losing
content. Git and ordinary backups provide history when desired.

If the rejected candidate has already overwritten the local path, the daemon
keeps the winning metadata, marks the path as needing repair, and requests the
winning bytes from peers. It continues advertising the winning record and keeps
the path visibly degraded until a reachable peer supplies those bytes.

The daemon preserves a received file's winning write time when it atomically
installs the file. It stores the installed file's observed write time, size,
and hash with the current path record so later and restarted scans recognize
the materialized winner at the filesystem's timestamp precision. The same
transaction binds the materialized record to the physical collection root
opened for installation. A changed physical root unmaterializes the other file
winners before the installed record is marked materialized.

### Deletions

A missing path that was previously known produces a tombstone stamped with the
filesystem time at which the daemon observes the deletion. Tombstones use the
same ordering as files and remain in metadata so a device returning after a
long absence retains the deletion. Repeated changes to one path replace its
single winning record rather than appending records. Tombstone storage is
bounded to one record for each distinct path observed by the collection.

A deletion is generated only for a path that the local database previously
recorded as present. A newly scanned empty collection therefore starts with an
empty manifest.

### Clock behavior

Filesystem write times are converted to UTC while preserving their instant.
The daemon rejects a candidate timestamp farther in the future than
`sync.max_future_clock_skew` and reports clock health through `skillsync
doctor`. Accepted timestamps remain unchanged.

Clock accuracy determines which offline edit wins. This is an explicit product
tradeoff of filesystem-time last-write-wins.

## Peer protocol

One iroh endpoint accepts two versioned ALPNs:

```text
skillsync/1
skillsync-join/1
```

`skillsync-join/1` carries the nonce proof, EndpointID approval, signed
membership grant, complete roster, and initial peer EndpointAddr bundles.
`skillsync/1`
carries synchronization between current members. Each synchronization
connection follows this shape:

1. The iroh handshake authenticates both EndpointIDs and encrypts the channel.
2. Peers exchange attached collection names and their current iroh EndpointAddr
   bundles.
3. Peers exchange complete signed roster chains and deterministically select
   the current chain.
4. Unknown, removed, or wrong-group identities are refused. An authenticated
   peer's EndpointAddr bundle replaces its previous bundle.
5. For every collection attached at both ends, peers exchange complete
   manifests.
6. Each side deterministically selects winning records and requests missing
   file content.
7. Peers finish when manifests agree or report a concrete validation or
   connectivity error.

Manifest exchange is symmetric. Either peer may have the newer file, and both
may send and receive during one connection. A device contacts all known peers
when the daemon starts and after a local change. It also contacts every
reachable peer at `sync.interval`, which defaults to fifteen minutes. Each pass
exchanges complete manifests and repairs changes missed while either peer was
offline.

### File transfer

The receiver validates membership, path, timestamp, declared size, and
configured limits before accepting bytes. It then:

1. streams content into a bounded staging file in the skillsync data directory
2. computes BLAKE3 while receiving
3. rejects a size or hash mismatch
4. copies validated content into a temporary file inside the destination
   collection
5. applies the winning filesystem write time to the collection-local temporary
   file
6. flushes and synchronizes the completed temporary file
7. atomically renames it over the destination
8. synchronizes the destination directory

New destination directories are synchronized as they are created.

An interrupted transfer leaves only an ignorable temporary file. The previous
valid file remains visible until replacement succeeds.

The protocol places a fixed upper bound on a manifest, path, file, and
connection message. Oversized input is rejected before unbounded allocation or
disk use.

## Joining

There is one admission path:

```text
inviter creates code
        -> joiner claims inviter ticket
        -> joiner dials inviter over iroh
        -> both display the joiner's EndpointID
        -> inviter compares and approves
        -> inviter sends signed roster revision
        -> joiner synchronizes default collections
```

`skillsync invite` sends the inviter's short-lived iroh EndpointTicket to the
joining service and receives an opaque code plus a high-entropy join nonce.
`skillsync join <code> --name <name>` atomically claims the code, receives the
ticket and nonce, and dials the inviter.

The joiner proves possession of the claimed nonce inside the encrypted iroh
session. The inviter obtains the joiner's EndpointID from the authenticated
connection. The joiner prints its own EndpointID and the inviter prints that
authenticated remote EndpointID in full. Approval requires an exact human
comparison.

Approval commits the signed admission before sending the roster to the joiner.
If delivery is interrupted, a fresh invitation for the same EndpointID and
device name refreshes its EndpointAddr bundle and sends the current roster. A
different name or a previously removed EndpointID is refused.

The joining service's role ends after returning the inviter's ticket and join
nonce. Membership approval stays with the inviter over iroh. The complete HTTP
contract is defined in [JOINING_SERVICE.md](JOINING_SERVICE.md).

## Membership

Membership is a signed, hash-linked sequence of complete roster revisions. The
group creator self-signs revision zero. Every later revision contains its
revision number, parent hash, complete active roster, one admission or removal,
and the EndpointID and signature of its author. A revision is valid when it
increments its parent by one and its author is active in that parent.

All admitted devices have the same authority: read and write collections,
invite devices, and remove devices.

Peers exchange roster revisions before manifests. When two valid revisions
compete for the same parent, a removal is selected before an admission, then
the lexicographically greater canonical revision hash breaks a tie of the same
kind. The command that produced the other revision reconciles and retries from
the selected revision. Creating a revision does not wait for every peer, and
only descendants of the selected revision extend the chain.

A removed EndpointID cannot author a valid child of the revision that removed
it. Admissions based on an older parent are stale and are not applied to the
current roster. A device that was offline adopts the selected revision chain
when it next reaches a current member. An isolated peer continues using the
last roster revision it received.

The peer list contains EndpointIDs and each peer's most recent usable iroh
EndpointAddr bundle. EndpointIDs and signed roster revisions establish identity
and membership. A peer's EndpointAddr bundle is a replaceable observation.

## Local state

SQLite stores only the state needed to restart safely:

- the device name and references to protected identity keys
- group identity and signed roster revisions
- configured collection names, paths, and resolved roots
- the winning record for each known path, including tombstones, and the
  observed fingerprint for its current materialized file
- peer EndpointIDs and each peer's current iroh EndpointAddr bundle
- a bounded operational log

Skill contents live in configured collection directories and temporary transfer
files. SQLite stores metadata alongside those canonical contents.

Identity private keys and active invitation nonces use operating-system secret
storage when available and owner-only files otherwise. SQLite migrations are
transactional.

## Failure behavior

| Event | Behavior |
| --- | --- |
| Joining service unavailable | Existing peers continue syncing. New joins fail clearly and can be retried. |
| Inviter goes offline | The code may be claimed, but joining waits or fails until its invitation expires. |
| Direct path unavailable | Iroh uses encrypted relay fallback. |
| All peers offline | Local editing continues. Reconciliation occurs when a peer returns. |
| Transfer interrupted | The previous file stays intact. The temporary file is discarded or reused only after validation. |
| Older peer edit arrives | It is rejected and logged. The current file remains. |
| Older local write replaces a file | The winning record remains advertised. The path reports degraded until its bytes arrive from a peer. |
| Equal timestamps | EndpointID, then the canonical record hash, selects the same winner everywhere. |
| Far-future timestamp | It is rejected and surfaced by status and `doctor`. |
| Daemon restarts | SQLite and a fresh filesystem scan reconstruct the current manifest. |
| Collection path missing | That collection pauses locally while remote state stays unchanged. |
| Peer misses a notification | The next complete-manifest exchange repairs it. |
| Device removed | Peers refuse it after learning the selected roster revision. |

Filesystem watches provide prompt updates. The startup reconciliation and
periodic full scans provide correctness by reconciling dropped watch events and
edits made while the daemon was stopped.

## Security boundaries

### Trusted devices

An admitted device can read and replace synchronized skills, including scripts
and agent instructions. Protocol authentication proves which approved device
sent a record. Synchronized content receives the same trust as files created by
the local user, so users approve devices at that trust level.

### Joining service

The service is trusted for code availability, atomic claim, and returning the
inviter ticket associated with a claimed code. It can observe inviter IP
addresses, joiner IP addresses, code timing, request headers, and the inviter's
iroh ticket. Iroh authenticates the resulting peer connection, and the inviting
device approves the joiner's EndpointID before membership changes.

### Iroh infrastructure

Iroh discovery and relay operators can observe connection metadata and relay
encrypted packets. Endpoint authentication and QUIC encryption keep group and
skill contents confidential and tamper-evident.

### Local filesystem

The daemon runs with the user's permissions. It normalizes every remote path,
constrains it beneath the resolved collection root, materializes regular files
and directories, and uses atomic replacement. Collection overlap and unsafe
symlinks are reported by `doctor`.

## Implementation boundaries

The codebase has three internal responsibility areas:

- **CLI and daemon:** commands, local control socket, configuration, watches,
  status, logs, and process lifecycle.
- **Core:** manifests, record validation, last-write-wins comparison, SQLite
  state, membership, and the `skillsync/1` iroh protocol.
- **Joining service:** the Cloudflare Worker and Durable Object implementing the
  small HTTP API in [JOINING_SERVICE.md](JOINING_SERVICE.md).

Versioned ALPNs identify the peer protocols. Membership records have
deterministic serialization for signing. Compatibility covers the peer
protocol, joining API, and CLI JSON shapes within their stated versions.

## Invariants

An implementation is correct only while all of these remain true:

1. The inviting peer grants group membership after identity comparison.
2. A join is approved against the EndpointID authenticated by iroh.
3. Skill bytes move only over authenticated, encrypted peer connections.
4. Reaching one current member is sufficient to learn the rest of the roster.
5. Peers choose the same winning record from the same inputs.
6. The primary ordering signal is the file's filesystem write time in UTC.
7. Skillsync rejects and discards losing contents.
8. File replacement occurs after a complete transfer passes hash validation.
9. Every materialized path stays beneath its configured collection root.
10. Deletions originate only from paths previously known locally.
11. Default collections are present on every device. Custom collections store
    data only on devices that attach a local path.
12. Normal synchronization runs directly between peers.
