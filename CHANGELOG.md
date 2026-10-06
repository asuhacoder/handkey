# Release notes

## Unreleased

### Breaking changes

- `POST /v1/devices/{id}/renew` is removed and returns 404. To replace an expired view token, create a session with `POST /v1/devices/{id}/sessions` and the device key. The new session does not invalidate the other sessions of the device.
- The state file format is version 2. The broker migrates a version 1 state directory the first time it opens the directory, and existing view tokens keep working. A broker from v0.1.0 or earlier cannot open a version 2 state directory. Back up the complete state directory before you upgrade if you might roll back.
- Responses from `POST /v1/bootstrap` and `POST /v1/devices` include `session_id`. Clients that reject unknown response fields must accept this field.

### Added

- Requests include a submission-time `display` snapshot of cached vault, item, and field names and origins for approval clients.
- One device (key registration) holds up to 16 sessions. Each client installation has its own named session, view token, and 90-day expiry. Clients that share a 1Password-synced key no longer invalidate each other's view tokens.
- `POST /v1/devices/{id}/sessions` creates a session. `GET /v1/devices/{id}/sessions` lists the active sessions of the caller's device. `POST /v1/sessions/{sid}/revoke` ends one session.
- `POST /v1/bootstrap` accepts an optional `session_name`.
- Requests record `approved_session`, and audit records include `session`, for approvals and denials.

See the [API contract](docs/api.md#registration-and-lifecycle) and [security boundaries](SECURITY.md).
