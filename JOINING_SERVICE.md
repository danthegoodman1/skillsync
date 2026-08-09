# Skillsync joining service

The joining service exists for cases where copy and paste is unavailable. It
lets a person type a short code instead of an entire Ed25519 public key, which
iroh uses as the device's EndpointID. The code establishes the first direct
iroh connection between two Skillsync devices.

The maintainers host the default service at
`https://skillsync.danthegoodman.com` from the Cloudflare deployment in this
repository. A self-hosted or independently implemented service works by
providing the same two endpoints.

## Contents

- [Responsibilities](#responsibilities)
- [Client configuration](#client-configuration)
- [Joining sequence](#joining-sequence)
- [HTTP conventions](#http-conventions)
- [Create an invitation](#create-an-invitation)
- [Claim an invitation](#claim-an-invitation)
- [Errors](#errors)
- [Consistency](#consistency)
- [Cloudflare deployment](#cloudflare-deployment)
- [Security and privacy](#security-and-privacy)
- [Self-hosting requirements](#self-hosting-requirements)

## Responsibilities

The service does exactly three things:

1. reserves an opaque code for a short time
2. stores the inviter's iroh EndpointTicket and a high-entropy nonce behind
   that code
3. returns that payload to the first client that claims the code

## Client configuration

Clients select a service URL in this order:

1. `SKILLSYNC_JOINING_SERVICE_URL`
2. `joining.service_url` in the configuration file
3. `https://skillsync.danthegoodman.com`

```toml
[joining]
service_url = "https://join.example.net"
invitation_ttl = "10m"

[joining.headers]
Authorization = "Bearer private-token"
```

Configured headers are sent with both API requests. `skillsync config show`
redacts their values, and Skillsync excludes them from logs. Both devices use
the same service and provide any headers it requires for a join.

## Joining sequence

```text
inviting device              joining service               joining device
       |                             |                             |
       | POST /v1/invitations        |                             |
       | EndpointTicket + TTL        |                             |
       |---------------------------->|                             |
       | code + join nonce           |                             |
       |<----------------------------|                             |
       |                             |  POST /v1/invitations/claim |
       |                             |  opaque code                |
       |                             |<----------------------------|
       |                             |  EndpointTicket + nonce     |
       |                             |---------------------------->|
       |                                                           |
       |<========== authenticated, encrypted iroh session =========|
       |            nonce + joining device name                    |
       |                                                           |
       | displays authenticated             displays its own       |
       | joining EndpointID                 EndpointID             |
       |                                                           |
       | human compares exact EndpointIDs and approves             |
       |================ signed membership grant =================>|
```

The 32-byte nonce binds the iroh join request to the invitation that produced
the displayed code.

The inviter displays the EndpointID authenticated by iroh. The joining device
displays its own EndpointID, and the inviter approves only after the two strings
match exactly.

## HTTP conventions

- The API base path is `/v1`.
- Requests use HTTPS and `Content-Type: application/json`.
- Responses use `Content-Type: application/json`.
- Unknown JSON fields are ignored for forward compatibility.
- Missing, mistyped, or out-of-range required fields are rejected.
- Timestamps are UTC RFC 3339 strings with a `Z` suffix.
- Invitation codes contain 1 through 128 characters from
  `[A-Za-z0-9._~-]`.
- Clients treat invitation codes as opaque, display them exactly, and return
  them unchanged when claiming.
- Request and response bodies are limited to 32 KiB.

Both endpoints require an `Idempotency-Key` UUID so interrupted requests can be
retried safely.

## Create an invitation

```http
POST /v1/invitations
Idempotency-Key: 6b50627f-9794-45e4-ae15-cf6e93cf643f
Content-Type: application/json
```

```json
{
  "protocol": "skillsync/1",
  "inviter_ticket": "iroh-endpoint-ticket...",
  "ttl_seconds": 600
}
```

Fields:

| Field | Requirement |
| --- | --- |
| `protocol` | Must equal `skillsync/1`. |
| `inviter_ticket` | An opaque, non-empty iroh EndpointTicket, at most 16 KiB. |
| `ttl_seconds` | Integer from 60 through 900. |

The service rejects TTLs above the 900-second protocol maximum. An accepted
invitation uses the requested TTL exactly.

A successful reservation returns `201 Created`:

```json
{
  "code": "funny-capybara",
  "join_nonce": "xE0Baf5vVjvLI8t7uRLQmuv8VQd-LHzjOFsdi9TwucE",
  "expires_at": "2026-08-08T17:20:00Z"
}
```

`join_nonce` is an unpadded base64url encoding of 32 bytes generated by the
service. The inviter keeps it only in local protected state for the lifetime of
the invitation.

## Claim an invitation

```http
POST /v1/invitations/claim
Idempotency-Key: 59070869-29e9-42e0-9d44-ef642c7b1361
Content-Type: application/json
```

```json
{
  "code": "funny-capybara"
}
```

The first successful claim atomically consumes the invitation and returns
`200 OK`:

```json
{
  "protocol": "skillsync/1",
  "inviter_ticket": "iroh-endpoint-ticket...",
  "join_nonce": "xE0Baf5vVjvLI8t7uRLQmuv8VQd-LHzjOFsdi9TwucE",
  "expires_at": "2026-08-08T17:20:00Z"
}
```

The claimant then dials `inviter_ticket` with the `skillsync-join/1` ALPN and
sends `join_nonce` in the first application message. The inviter accepts the
request only while the same nonce is active locally. Membership begins after
the EndpointID comparison and the inviter's signed grant.

The invitation remains consumed after a dropped connection or rejected
EndpointID. The inviter creates a new code for another attempt.

## Errors

Unsuccessful requests use conventional HTTP status codes and return the same
JSON shape:

```json
{
  "error": {
    "code": "join_unavailable",
    "message": "The joining code is unavailable or expired."
  }
}
```

`error.code` is stable and machine-readable. `error.message` is suitable for
display. Unknown, expired, and claimed codes all return `join_unavailable` so
the response does not reveal the history of a code. Retryable responses include
`Retry-After` when the service can provide a useful delay.

## Consistency

Code reservation and claim are strongly consistent. One claim succeeds, an
idempotent retry returns its original response, and expired invitations resolve
as unavailable.

## Cloudflare deployment

The maintainer-hosted service consists of:

- a Cloudflare Worker that validates HTTP requests, applies coarse rate limits,
  and forwards the two API operations
- one named `JoinCoordinator` Durable Object that serializes code allocation,
  claims, idempotency, and expiry state

`skillsync.danthegoodman.com` formats each code as two independently selected
words from the bundled 4,096-word list, such as `funny-capybara`, providing 24
bits of random space.

The deployment source and configuration live in this repository.

## Security and privacy

### Code guessing

Codes provide at least 24 bits of random space. Short expiry, one-time claim,
and per-source rate limits reduce guessing and denial-of-service attempts. A
guessed code reveals an ephemeral inviter ticket and can consume an invitation.
Admission still requires the inviter to compare and approve the EndpointID
authenticated by iroh.

### Stored and observed data

The service can observe source IP addresses, timing, codes, request headers,
and inviter EndpointTickets. Application logs redact complete codes, tickets,
nonces, configured header values, request bodies, and IP addresses.

### Abuse limits

The service limits request size, invitations created per source, claim attempts
per source, total active invitations, and requests per code. Limits may vary by
deployment. The standard `429` response keeps the joining protocol consistent.

## Self-hosting requirements

A compatible service:

1. implements the two `/v1/invitations` endpoints exactly as specified
2. serves them over HTTPS
3. generates codes with at least 24 bits of random space and 32-byte nonces
   from a cryptographically secure random source
4. provides atomic reservation and one-time claim
5. preserves idempotent results across client retries until expiry
6. enforces the TTL and request-size ranges in this document
7. uses uniform unavailable-code errors

Compatible implementations may use a single process with transactional SQLite,
a relational database, or another strongly consistent store.
