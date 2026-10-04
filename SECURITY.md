# Security boundaries

Handkey is experimental. Report a vulnerability using GitHub's private vulnerability reporting for this repository if enabled; otherwise contact the maintainer through their GitHub profile before publishing exploit details. Never include credentials, device keys, receiver tokens, or vault exports in an issue.

## What is enforced

- A client-generated 256-bit device key is required to unwrap the service-account token. An active view token alone can inspect or deny requests, but cannot approve or receive values.
- Canonical vault/item/field IDs and the delivery method are frozen before approval. Leases cannot select extra fields or another proxy origin. A separate receiver capability is required to consume a result.
- Only the first valid approval/denial/cancellation/expiry transition succeeds. A durable running state is committed before touching `op`. Writes with uncertain outcomes are never automatically retried.
- `op` gets a minimal environment, a private temporary configuration directory and `--cache=false`. Its authentication token is not placed in the broker's process-wide environment or a user command. Untrusted output and stderr are not used as error messages.
- Proxy destination, HTTP Host and TLS verification name share one fixed HTTPS origin. Redirects are returned without following them. Broker/execution bearer tokens are not sent upstream.
- Audit records omit free-form reason/agent/command text, templates, input values, HTTP bodies, and output. Fetched values exist only in memory and are absent from state, metadata and audit files.

## Trusted components

The broker, its dedicated `op`, the host administrator, approval client code, and the caller-side helper are trusted. A compromised approval client can copy its device key. A compromised broker or administrator can copy the vault-wide service token during approval. Agent claims and request purposes are not independently verified. Tailscale-derived node identities and local process ancestry are not implemented; current source metadata is the listener's peer address only.

The agent API has no login: Unix socket permissions or a private network with explicit ACLs restrict access. All remote traffic must use HTTPS. A TLS-terminating proxy is trusted with plaintext. A receiver token prevents accidental cross-request collection, not compromise of the requesting user's filesystem.

## Deliberate limits

- This is not a defense against malicious approved commands or prompt injection. `exec` can reveal transformed secrets. A target app can expose typed text. A proxy response can echo its credential. Clipboard history and external sessions cannot be revoked.
- Revocation prevents future unwraps by that device; it does not claw back values already released or revoke existing approved leases.
- Device keys and plaintext tokens are cleared from owned byte buffers promptly. Go/runtime/subprocess copies cannot be guaranteed to disappear immediately. Leased strings are released, not securely erased.
- POSIX broker startup disables core dumps. Swap, OS diagnostics, memory inspection and Windows crash reporting require deployment controls. Signed/Hardened Runtime macOS distributions are not produced yet.
- State encryption protects accidental file disclosure only as long as `state.key` is separate. With both files, pending agent-supplied writes and request metadata are readable; the service token still requires a device key.
- Audit metadata can itself identify accounts. State, audit and receipt files require private storage and a retention policy. Audit records currently remain until an operator rotates them; completed request state is removed seven days after receiver expiry.
- Losing state persistence makes the broker fail closed until restart. Restore the complete state directory, not individual encryption files. Backups contain encrypted credentials and must be protected.

If only a device key leaks, revoke that device. If the service-account token leaks, revoke and replace it in 1Password. If the master key, device key plus encrypted data, or all approval devices are lost, revoke/reissue the 1Password token and bootstrap a fresh state directory with newly generated device keys. Routine token rotation does not replace the master key and is not the recovery procedure for master-key compromise.
