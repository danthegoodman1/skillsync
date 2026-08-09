# Skillsync Implementation Plan

## Overarching Goal

Build the finished experience in [README.md](README.md) as one native Rust
`skillsync` binary for macOS and Linux plus one TypeScript Cloudflare Worker
for the joining service. The implementation follows the guarantees in
[ARCHITECTURE.md](ARCHITECTURE.md) and the HTTP contract in
[JOINING_SERVICE.md](JOINING_SERVICE.md).

The native binary contains the CLI and daemon. Files remain canonical in the
configured collection directories, SQLite stores restart-safe metadata, and
peers exchange complete manifests over one iroh ALPN. The joining service only
supports the two joining endpoints.

## Implementation Principles

- Keep the native binary in the Cargo workspace and the joining service in a
  small TypeScript Worker package. Keep native modules inside `skillsync`
  unless a real compilation boundary requires another crate.
- Add dependencies with `cargo add` and inspect `Cargo.toml` and `Cargo.lock`
  after every addition.
- Add Worker dependencies with the package manager and keep its lockfile in
  sync.
- Use one iroh endpoint with raw QUIC streams under `skillsync/1` for sync and
  `skillsync-join/1` for admission.
- Keep one winning SQLite record per collection path and exchange complete
  manifests.
- Make record comparison, roster selection, path validation, and protocol
  limits pure deterministic functions before connecting them to I/O.
- Write state before acknowledging it and install received files only after
  complete hash validation.
- Keep filesystem, SQLite, iroh, and HTTP boundaries concrete. Add traits only
  when tests or a second implementation need one.
- Support macOS and Linux. Use Unix domain sockets for local CLI-to-daemon
  control.
- Keep credentials, joining codes, nonces, tickets, configured header values,
  and skill contents out of logs.

## Testing Strategy

- Run Rust formatting, linting, and native tests plus TypeScript Worker checks
  in CI.
- Use table-driven and permutation tests for every deterministic merge or
  ordering rule.
- Use temporary directories and real SQLite databases for filesystem and
  restart tests.
- Run multi-daemon tests in separate processes with isolated data directories
  and loopback iroh endpoints.
- Exercise offline edits, dropped connections, restarts, stale roster branches,
  corrupt transfers, and path attacks before release.
- Run CI on macOS and Linux. Keep managed-service deployment smoke tests
  separate from deterministic local tests.

## Phase 1: Rust Foundation and Deterministic State

Goal:
Establish the smallest buildable workspace and implement the state rules that
all later I/O depends on.

Scope:

- Create the Cargo workspace, native binary crate, native CI, and basic command
  entrypoint.
- Define configuration loading, platform paths, persistent device identity,
  group identity, operating-system secret storage, and the owner-only file
  fallback.
- Define canonical encodings for records, manifests, roster revisions, and
  signatures.
- Implement last-write-wins comparison, canonical record hashing, roster
  revision validation and selection, and local path validation.
- Add transactional SQLite migrations and queries for identity references,
  roster revisions, collections, path records, peer hints, and bounded logs.

Out of scope:

- Filesystem watching, iroh connections, joining HTTP calls, and startup
  registration.

Completion gate:
The native workspace builds on macOS and Linux. Fresh and migrated databases
reopen without changing state, and every deterministic rule produces the same
result under input reordering.

Testing plan:

- Unit tests for record ordering across files and tombstones, including exact
  timestamp and author ties.
- Permutation tests for competing roster admissions and removals, stale-parent
  rejection, and signature validation.
- Path tests for traversal, invalid UTF-8, symlink-safe relative paths, and
  case-collision detection using platform-specific fixtures.
- SQLite tests for migrations, transaction rollback, restart, and uniqueness
  constraints.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | P1.1: Create the native Rust workspace and CI targets | `Cargo.toml`, the native crate manifest, `Cargo.lock`, and `.github/workflows/ci.yml`. |
| Complete | Work | P1.2: Implement configuration, platform paths, and persistent identities | `config.rs` and `identity.rs`, including redaction, permission, and restart tests. |
| Complete | Work | P1.3: Implement canonical records and deterministic LWW comparison | `canonical.rs` and `record.rs`, including total-order and permutation-independent manifest tests. |
| Complete | Work | P1.4: Implement signed roster revision validation and branch selection | `roster.rs` and `state.rs`, including signature, stale-parent, removal-priority, insertion-order, and reopen tests. |
| Complete | Work | P1.5: Implement SQLite schema and transactional access | `state.rs` migration, rollback, winner, roster reconstruction, log retention, and reopen tests. |
| Complete | Test | Phase 1 deterministic and persistence test plan | `cargo test --workspace --locked` passes 34 tests and strict Clippy passes. |
| Complete | Gate | Phase 1 completion gate | Local gates pass and [CI run 31274704319](https://github.com/danthegoodman1/skillsync/actions/runs/31274704319) passes Ubuntu and macOS jobs. |

## Phase 2: Local Filesystem and Daemon

Goal:
Turn configured skill directories into a restart-safe local manifest managed by
one daemon.

Scope:

- Implement setup for the three default collections and local attachment of
  custom collections.
- Scan collection roots, follow permitted symlinks, apply ignore patterns, and
  report unsafe or unrepresentable paths.
- Detect file changes and deletions, preserve filesystem write times, and keep
  one file or tombstone record per path.
- Apply received-file fixtures through temporary files, BLAKE3 validation,
  flush, atomic rename, and watcher suppression.
- Run the daemon event loop, Unix control socket, startup scan, periodic full
  scan, bounded logging, and configuration reload on restart.
- Implement `setup`, `status`, `collections`, `config`, and local `logs`
  commands with human and JSON output.

Out of scope:

- Peer connections, device joining, roster mutation commands, and operating
  system startup registration.

Completion gate:
Local edits, deletes, restarts, root symlinks, and nested safe symlinks produce
the expected manifest without publishing paths outside a collection. Applying a
validated candidate never exposes partial contents.

Testing plan:

- Temporary-directory tests for initial scans, edits, deletes, ignored files,
  missing roots, symlink aliases, safe nested links, escapes, and cycles.
- Restart tests that compare the database winner with a fresh filesystem scan.
- Fault tests at each temporary-file installation step.
- CLI snapshot tests for human output and schema tests for `--json` output.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | P2.1: Implement default and custom collection attachment | `setup.rs`, `state.rs`, and CLI tests cover the three defaults, idempotent attachment, replacement, removal, and missing-root restart behavior. |
| Complete | Work | P2.2: Implement safe scanning, symlink traversal, and ignore matching | `filesystem.rs` and `root.rs` use descriptor-relative traversal and stable root identity, with escape, cycle, collision, churn, and atomic-retarget tests. |
| Complete | Work | P2.3: Implement watch events, tombstones, full scans, and clock checks | `daemon.rs` uses bounded polling watchers plus startup and periodic scans, with deletion, dropped-watch repair, future-time rejection, and degraded-state tests. |
| Complete | Work | P2.4: Implement validated atomic file installation and repair state | `installer.rs` validates bytes and metadata before rename, synchronizes directories, binds the acquired physical root transactionally, and passes fault and ABA tests. |
| Complete | Work | P2.5: Implement daemon socket and local CLI commands | The private bounded Unix socket and setup, status, collections, config, and logs commands pass the real-process CLI and daemon test. |
| Complete | Test | Phase 2 filesystem and restart test plan | Locked tests pass 70 unit tests plus one real-process integration test, strict Clippy, and formatting. |
| Complete | Gate | Phase 2 completion gate | Local gates pass and [CI run 31279534675](https://github.com/danthegoodman1/skillsync/actions/runs/31279534675) passes Ubuntu and macOS jobs. |

## Phase 3: Direct Peer Synchronization

Goal:
Make two pre-authorized daemons converge directly over iroh with no joining
service in the data path.

Scope:

- Build one persistent iroh endpoint with the `n0` preset and custom address
  lookup and relay configuration.
- Implement framed messages selected by the versioned `skillsync/1` ALPN with
  size, path, manifest, file, and connection limits.
- Authenticate the remote EndpointID, validate its selected roster revision,
  and exchange roster state before collection state.
- Exchange complete manifests symmetrically, select winners, stream missing
  bytes, validate BLAKE3 hashes, and commit winners through the Phase 2 file
  installer.
- Persist peer EndpointIDs and replaceable address hints.
- Reconcile at daemon startup, after local changes, on explicit `sync`, and at
  the configured fifteen-minute interval.
- Surface unreachable peers, rejected candidates, corrupt transfers, and paths
  waiting for repair through status and logs.

Out of scope:

- Human invitation codes, joining-service HTTP calls, and roster admissions or
  removals from the CLI.

Completion gate:
Two pre-authorized daemons converge after online edits, concurrent offline
edits, deletion, disconnection, restart, and interrupted transfer. A peer with
the losing candidate cannot replace the deterministic winner.

Testing plan:

- Protocol codec tests for truncation, oversized frames, incompatible ALPNs,
  invalid paths, and unexpected message order.
- Two-process convergence tests for file creation, edit, delete, equal-time
  ties, offline changes, and restart.
- Transfer interruption and corrupt-hash tests proving the previous valid file
  remains visible.
- Direct-path and configured-relay smoke tests using isolated test identities.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | P3.1: Build configurable persistent iroh endpoints | One persistent identity-bound endpoint supports N0 defaults and custom address lookup and relay configuration. |
| Complete | Work | P3.2: Implement bounded `skillsync/1` framing and handshake | The versioned ALPN and bounded frames enforce protocol, path, record, manifest, roster, transfer, hint, and connection limits. |
| Complete | Work | P3.3: Implement symmetric manifest comparison and file transfer | Concurrent symmetric exchange converges deterministic winners and validates staged bytes before atomic installation. |
| Complete | Work | P3.4: Implement reconciliation triggers and peer health reporting | Startup, local-change, explicit, and interval triggers are covered with bounded typed health logs. |
| Complete | Work | P3.5: Implement degraded-path repair from a reachable winner | Repair-only scans request reconciliation and unavailable paths do not block transferable siblings. |
| Complete | Test | Phase 3 peer synchronization test plan | 101 local tests cover direct and relay paths, online and offline convergence, restart, repair, corruption, interruption, limits, and daemon responsiveness. |
| Complete | Gate | Phase 3 completion gate | Implementation and skeptical review are approved. [CI run 31286777773](https://github.com/danthegoodman1/skillsync/actions/runs/31286777773) passed on Ubuntu and macOS. |

## Phase 4: Membership and Human Joining

Goal:
Let a person securely add and remove devices while preserving deterministic
roster state across offline peers.

Scope:

- Connect setup to roster revision zero and implement signed admission and
  removal revisions.
- Resolve competing children with removal priority and canonical revision hash,
  then retry a losing local mutation from the selected parent.
- Implement `peers list`, `peers remove`, and refusal of removed EndpointIDs.
- Implement the joining-service HTTP client with URL override, invitation TTL,
  custom headers, idempotency keys, response limits, and redaction.
- Implement `invite` and `join`, EndpointTicket handling, one-use nonce proof,
  exact joiner EndpointID display, inviter confirmation, and immediate default
  collection synchronization.
- Learn the complete roster from the inviter so reaching one current member is
  enough to discover the group.

Out of scope:

- The deployed Cloudflare service and operating system startup registration.

Completion gate:
A third device joins through a contract-compatible local service, verifies the
same joiner EndpointID on both terminals, learns all peers, and synchronizes.
After removal, current peers refuse that EndpointID and reject its stale roster
children.

Testing plan:

- Roster tests for sequential and competing joins, competing removal and
  admission, stale children, tampered signatures, and offline catch-up.
- HTTP client tests for timeouts, retries, idempotent responses, body limits,
  opaque codes, custom headers, and secret redaction.
- Three-process joining tests with success, wrong nonce, rejected EndpointID,
  consumed code, inviter disconnect, removal, and stale-peer recovery.
- Terminal interaction tests proving approval defaults to rejection and uses
  the EndpointID authenticated by iroh.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | P4.1: Implement roster admission, removal, conflict selection, and retry | Signed mutations replay losing local changes from the selected parent and propagate selected-tip changes. |
| Complete | Work | P4.2: Implement peer listing, removal, and connection refusal | Human and JSON peer commands are implemented, and current peers refuse stale removed identities. |
| Complete | Work | P4.3: Implement the bounded joining-service HTTP client | The redirect-free client enforces URL, header, body, TTL, timeout, retry, idempotency, response, and redaction bounds. |
| Complete | Work | P4.4: Implement invite, nonce proof, identity confirmation, and join | One persistent endpoint handles bounded join sessions with nonce proof, exact EndpointID approval, default rejection, and resumable delivery. |
| Complete | Work | P4.5: Implement roster discovery through one member | A joiner receives the complete selected roster and peer hints, attaches defaults, and synchronizes immediately. |
| Complete | Test | Phase 4 membership and joining test plan | 139 local tests cover roster branches, client failures, terminal safety, process locking, three-device joining, removal, stale-peer refusal, and deterministic timeout behavior. |
| Complete | Gate | Phase 4 completion gate | Implementation and skeptical review are approved. [CI run 31294512696](https://github.com/danthegoodman1/skillsync/actions/runs/31294512696) passed on Ubuntu and macOS. |

## Phase 5: TypeScript Joining Service

Goal:
Provide the two-endpoint joining contract as a self-hostable TypeScript
Cloudflare Worker and operate the default service at
`skillsync.danthegoodman.com`.

Scope:

- Create a small TypeScript Worker package with Wrangler, then implement the
  request router, validation, response shapes, body limit, TTL limit, uniform
  unavailable-code response, and log redaction.
- Implement one named `JoinCoordinator` Durable Object for reservation, expiry,
  one-time claim, and idempotent retries.
- Generate managed-service codes as two independently selected words from the
  bundled 4,096-word list while keeping client handling opaque.
- Apply bounded abuse controls for creation, claims, active invitations, and
  per-code attempts.
- Add Wrangler configuration, local development commands, deployment command,
  and custom-domain configuration.

Out of scope:

- Accounts, group storage, skill storage, and peer traffic proxying.

Completion gate:
The local Worker passes the HTTP contract suite under concurrent claims and
Durable Object restarts. The deployed domain passes create, claim, expiry,
idempotency, body-limit, and redaction smoke tests.

Testing plan:

- TypeScript handler tests for accepted fields, validation boundaries, opaque
  codes, uniform unavailable responses, and safe headers.
- Concurrent tests proving exactly one claim succeeds and an idempotent retry
  returns its original result.
- Durable Object restart tests proving active invitations and idempotency state
  survive eviction.
- Local Wrangler contract tests plus a bounded managed-service smoke suite.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | P5.1: Implement the TypeScript Worker router and validation | Missing: Worker package, handlers, and HTTP contract tests. |
| Incomplete | Work | P5.2: Implement atomic invitation state in `JoinCoordinator` | Missing: Durable Object code and concurrent-claim tests. |
| Incomplete | Work | P5.3: Implement hosted code generation, expiry, idempotency, and limits | Missing: deterministic boundary and abuse-limit tests. |
| Incomplete | Work | P5.4: Add local and managed deployment configuration | Missing: Wrangler configuration and documented commands. |
| Incomplete | Test | Phase 5 service contract and persistence test plan | Missing: local Worker, eviction, and managed smoke evidence. |
| Incomplete | Gate | Phase 5 completion gate | Missing: passing deployed contract checks at the managed domain. |

## Phase 6: Startup Integration and Release Gate

Goal:
Deliver the complete install, startup, diagnostics, automation, and clean-machine
experience promised by the README.

Scope:

- Implement idempotent `enable` and `disable` for macOS launchd LaunchAgents and
  Linux systemd user services.
- Complete `doctor`, peer connectivity checks, relay checks, clock checks, and
  bounded `logs --follow` behavior.
- Verify every CLI command's human output, `--json` schema, exit status, stdout,
  and stderr behavior.
- Add release profiles, `cargo install` verification, reproducible CI commands,
  and release artifacts for supported targets.
- Run clean-machine scenarios for first setup, second-device join, offline edit,
  restart, removal of a permanently offline peer, custom joining service, and
  custom iroh infrastructure.

Out of scope:

- Windows, graphical interfaces, automatic updates, alternate invitation
  transports, file history, and automatic tombstone pruning.

Completion gate:
A new macOS or Linux user can follow the README without undocumented steps, all
automated suites pass, startup registration survives login or reboot as the
platform permits, and the managed joining service completes a real join.

Testing plan:

- launchd and systemd install, repair, start, stop, disable, and restart tests.
- CLI JSON schema and secret-redaction tests for every command.
- Clean-environment `cargo install` and first-run tests on macOS and Linux.
- Final two-device and three-device end-to-end runs covering direct and relayed
  connections, removal, custom service headers, and missed-change repair.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | P6.1: Implement idempotent launchd and systemd registration | Missing: platform service modules and lifecycle tests. |
| Incomplete | Work | P6.2: Complete doctor, status, logging, and connectivity diagnostics | Missing: diagnostic commands and failure fixtures. |
| Incomplete | Work | P6.3: Stabilize all human and JSON CLI contracts | Missing: command-wide snapshot and schema evidence. |
| Incomplete | Work | P6.4: Add release builds and `cargo install` verification | Missing: release workflow and clean-install artifacts. |
| Incomplete | Test | P6.5: Run clean-machine and multi-device release scenarios | Missing: macOS and Linux end-to-end logs. |
| Incomplete | Gate | Phase 6 completion gate | Missing: complete automated suite and README walkthrough evidence. |
