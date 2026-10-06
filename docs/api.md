# Approval client API v1

This repository ships the broker and agent CLI only. Smartphones, browser apps, dsh and Even clients belong in separate repositories. They can all use this API concurrently. No key is sent through an agent tool call or an LLM conversation.

All examples below are schemas with placeholders, not runnable credentials. Transport is HTTPS (or a restricted Unix socket); JSON requests use exactly `Content-Type: application/json`. Request bodies are limited to 1 MiB. Unknown JSON fields are rejected. Responses include `Cache-Control: no-store`. Tokens must be in `Authorization: Bearer TOKEN`, never in query parameters. There are no cookies.

## Registration and lifecycle

The broker keeps two kinds of record.

- A **device** is a key registration. It holds one copy of the master key, wrapped with a device key. A device is not a physical machine. A key that a password manager syncs exists on every machine that the password manager reaches.
- A **session** is one client installation. It has a name, a view token, and an expiry time. A device holds up to 16 active sessions.

Choose between the two by where the client keeps its key.

- If a client uses a key that is already registered, add a session to that device. Example: a phone page and a dsh plugin both read the same 1Password item. A separate key for each client adds no protection, because 1Password syncs every key to the same machines.
- If a client keeps its key somewhere else, register a new device. Example: an Even app that stores its key inside the app.

A view token lets a session list requests, read a request, deny a request, and subscribe to events. Approval and the management operations below also need the key of the device that the session belongs to. A view token cannot be combined with the key of another device.

### Register the first device

1. Generate 32 cryptographically random bytes and encode them as **unpadded base64url**. This value is the device key. It is not a user password, and the broker rejects a short key derived from a password. Store the device key in the client's secure storage or in 1Password.
2. On an uninitialized broker started with `--bootstrap`, send:

   ```http
   POST /v1/bootstrap
   Content-Type: application/json

   {"name":"1Password key","session_name":"Phone","key":"CLIENT_GENERATED_KEY","service_account_token":"TOKEN_FROM_USER"}
   ```

   `session_name` is optional. The default is `name`.
3. The response is `201 {"id":"DEVICE_ID","session_id":"SESSION_ID","view_token":"VIEW_TOKEN","view_until":"RFC3339"}`. Keep the view token for routine inspection. The broker does not store or return the device key. The broker accepts initialization only once.

### Add a session

Send the device key. No view token is needed, because possession of the device key is the authentication.

```http
POST /v1/devices/DEVICE_ID/sessions
Content-Type: application/json

{"key":"DEVICE_KEY","name":"dsh plugin"}
```

The response is `201` with the same fields as the bootstrap response. The existing sessions of the device do not change, and their view tokens stay valid.

- A wrong key and an unknown device ID both return 401 with the same body.
- If the device already has 16 active sessions, the response is 409. The broker never removes a session to make room. Revoke a session first.
- A session expires 90 days after creation. There is no renewal. When a session expires, create a new session with the device key.

### List and revoke sessions

| Method and route | Authentication | Behavior |
| --- | --- | --- |
| `GET /v1/devices/DEVICE_ID/sessions` | View token of a session on that device | Active sessions as `[{"session_id","name","created_at","view_until","current"}]`. `current` marks the caller's session. A different device ID returns 404 |
| `POST /v1/sessions/SESSION_ID/revoke` for the caller's own session | View token, no body | Log out. Only that session ends |
| `POST /v1/sessions/SESSION_ID/revoke` for another session on the same device | View token plus `{"key":"DEVICE_KEY"}` | End that session. Without the key the response is 401 |

A session cannot revoke a session on another device. That request returns 404. Revoke the whole device instead.

Session and device names are text that the registering client supplied. The broker limits each name to 128 characters of valid UTF-8 and does not otherwise check it. Treat a name as untrusted data. Never render a name as HTML.

### Add or revoke a device

- To register a second key, an existing session sends `POST /v1/devices` with its view token and `{"name":"Even app","key":"EXISTING_DEVICE_KEY","new_key":"NEW_CLIENT_GENERATED_KEY"}`. The response has the same fields as the bootstrap response and contains the first session of the new device. Give the response to the new client over the trusted registration channel. The clients own the pairing and QR coordination. The CLI has no pairing UX.
- To revoke a device, send `POST /v1/devices/DEVICE_ID/revoke` with a view token and `{"key":"APPROVING_DEVICE_KEY"}`. The broker deletes the wrapped master key and every session of the revoked device. The revoked key can no longer approve or create sessions.
- To rotate the service account token, send `POST /v1/token/rotate` with a view token and `{"key":"DEVICE_KEY","service_account_token":"NEW_TOKEN"}`. Rotation keeps the master key. Recovery from a compromise is a different procedure. See SECURITY.md.

Clear the key input field after each send. Never put a key in telemetry, crash reports, console output, URLs, or event payloads. The broker never returns or logs a view token after it issues the token, and it never returns a view token hash.

## Inspect and decide

| Method and route | Authentication | Behavior |
| --- | --- | --- |
| `GET /healthz` | None | Liveness and initialization status; no credential data |
| `GET /v1/requests` | View token | Currently pending, unexpired requests |
| `GET /v1/requests/ID` | View token **or** receiver token | Sanitized immutable request and separate approval/execution states |
| `POST /v1/requests/ID/approve` | View token plus JSON `{"key":"DEVICE_KEY"}` | Commit approval, run the 1Password operation, return `{"status":"processed"}` |
| `POST /v1/requests/ID/deny` | View token | Deny without unlocking |
| `GET /v1/events` | View token | SSE event hints; subscribe from every client |

`processed` means the decision was handled, not that a write succeeded. Fetch the request's `execution` field afterwards. All clients see the same pending queue; only the first valid decision is accepted. Repeated approvals return 409 and never execute again. A wrong key leaves the request pending. A decided request records the device in `approved_by` and the session in `approved_session`, for a denial as well as an approval. The audit log records the same two IDs. The broker checks the view token again before each SSE write, so a revoked or expired session loses its stream.

SSE starts with `event: sync`. Fetch a complete pending list on connect/reconnect. Subsequent `event: change` data is `{"id":"REQUEST_ID","kind":"requested","at":"RFC3339"}` (kinds also include approval, execution and lifecycle changes). Queues are bounded and may drop hints; there are no replay IDs. Clients must reconcile periodically, on reconnect, and on foreground resume. Browser clients should use a fetch-based SSE reader because native `EventSource` cannot set the bearer header. CORS supports exact allowlisted origins and Authorization/Content-Type preflights, without credentials or wildcard origins.

`--webhook https://receiver.example/events` provides the same non-secret event hints by POST. It is best-effort, bounded and unsigned; a receiver must treat it as a wake-up hint and fetch authenticated state. It does not deliver approval keys, values or receiver tokens. Redirects are not followed. Web Push delivery is not yet implemented.

## Agent request schema

`POST /v1/requests` has no agent login; access is limited by the listener/network. Response: `202 {"id":"REQUEST_ID","token":"RECEIVER_TOKEN"}`. Only the submitting CLI receives this capability. The CLI stores it in a new mode-0600 receipt file and prints only the file path.

```json
{
  "method": "exec",
  "refs": [{"vault":"VAULT_ID","item":"ITEM_ID","field":"password"}],
  "reason": "Run the requested deployment",
  "agent": "agent-name",
  "command": ["deploy-tool", "--check"],
  "directory": "/project",
  "bindings": {"API_TOKEN":"VAULT_ID/ITEM_ID/password"},
  "ttl_seconds": 300,
  "uses": 3,
  "wait_seconds": 900,
  "unredacted": false
}
```

- Methods: `reveal`, `otp`, `exec`, `proxy`, `type`, `clipboard`, `write`, `refresh`.
- `refs` contains at most 64 distinct fields. Cached vault/item names and field labels are resolved at submission. Explicit vault/item IDs are 26 lowercase alphanumeric characters. Section-qualified field IDs use `section.field`; the CLI accepts `op://vault/item/section/field`. Ambiguity fails. Passkeys/binary fields are outside the current adapter.
- Default `uses` is 1. More than one use requires an explicit positive TTL. Maximum TTL is 24 hours, maximum uses 10,000. Default approval deadline is 15 minutes, which callers may shorten but not extend. No explicit lease gives a 15-minute result collection window after approval.
- `exec` and `proxy` require command/working directory. `bindings` names environment variables and their approved refs. `OP_*` and `HANDKEY_*` bindings are rejected. `unredacted` must be visible in the approval client. The helper uses the approved argv/cwd; it does not snapshot executable or script content.
- `proxy` additionally requires one ref, `origin` (HTTPS scheme/host/port only), `header` and optional `prefix`. Hop-by-hop/routing headers cannot be credential targets. The destination cannot be changed while consuming a lease.
- `type` requires one ref and `target`, captured as `PID|application|window title` before approval. The macOS helper checks again just before typing. This is not a website/domain check.
- `clipboard` accepts one ref. It attempts cleanup after 10 seconds or cancellation only if the current clipboard is unchanged.
- `write` requires `create: {vault,title,category,generate_password?,fields?}`. Fields have `id`, `label`, `type`, `value`. Categories currently accepted: `LOGIN`, `PASSWORD`, `API_CREDENTIAL`, `SECURE_NOTE`, `CREDIT_CARD`, `IDENTITY`. Values go to real `op` on stdin. Write/refresh cannot be leased. Views omit supplied field values, but retain their field IDs/types. Do not infer that a hidden value was independently checked by the approver.
- `refresh` syncs item metadata and, if refs are included, metadata for those items. A successful refresh is an approved metadata action and exposes no field values.
- Output format is optional `output_format: "json"` or empty. All arbitrary caller-supplied descriptive strings are untrusted data for client rendering; never render them as executable HTML.

## Receive and reuse

| Route | Credential | Behavior |
| --- | --- | --- |
| `GET /v1/requests/ID` | Receiver token | Check status without consuming |
| `POST /v1/requests/ID/cancel` | Receiver token | Cancel a pending request |
| `POST /v1/requests/ID/consume` | Receiver token | Atomically consume one allowed use |
| `GET /v1/items?q=TEXT` | None by default | Value-free metadata envelope |

Receiver tokens expire 24 hours after submission. A consume response contains `request` and `values`, keyed by canonical `vault/item/field`. OTP returns only a fresh code, never its stored seed. The helper receives values for exec/type/clipboard but does not print them. Writes finish with metadata in `created_item`; they have no value-consumption step. Delivery is at-most-once: a lost consume response spends that use; it is not replayed automatically.

Proxy consumption returns `execution_token` instead of values. The helper starts a loopback server with a random URL path, gives that URL to the command as `HANDKEY_PROXY_URL`, and forwards requests to `/v1/requests/ID/proxy/PATH` with the execution token. It sends `POST /v1/requests/ID/heartbeat` every 5 seconds and `DELETE /v1/requests/ID/execution` when done. Sessions expire after 20 seconds without a heartbeat. A session started before lease expiry remains active until completion/disconnect, regardless of lease TTL. A receiver token cannot act as an execution token.

Metadata envelopes distinguish `synced: false` from an empty synchronized list. `fields_known: false` means the client must request a refresh for field names. URLs are reduced to origin. With `--require-metadata-approval`, GET items needs `?receipt_id=ID` plus the receiver token of a successful refresh approved within the last 15 minutes. The low-level API supports this; high-level `item list/get` do not yet attach an existing refresh receipt automatically.

## Durable state and failures

Approval: `pending → approved | denied | expired | cancelled`.

Execution: `not_started → running → ready | succeeded | failed | unknown`, followed by `consumed` or `expired` for value delivery. A write interrupted while running recovers as `unknown`; other interrupted work recovers as `failed`. Pending requests survive restart, including encrypted caller-supplied write fields. Ready in-memory values become `expired`. Proxy executions never survive restart.

New items carry the tag `handkey-request:REQUEST_ID`. On an unknown outcome, inspect 1Password for that tag before creating a replacement request. The API never retries writes. Requests remain queryable until receiver expiry; state is pruned seven days later. Audit retention is operator-managed.

Errors are sanitized JSON `{"error":"message"}`: 400 invalid input, 401 invalid view/key authentication, 404 absent/not-authorized receipt, 409 decision conflict or session limit, 410 unavailable/expired values, 413/400 oversized input, 415 wrong content type, 503 broker state failure. Do not put response bodies or arbitrary provider errors into telemetry.
