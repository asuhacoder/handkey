# Deployment

Use one broker process per state directory. The broker holds an OS file lock and refuses a second instance. The CLI/helper runs as the agent's user; the broker should use a dedicated account.

## Linux installer

Build the appropriate Linux binary first and install the genuine `op` from its official distribution. The installer copies both executables to a root-owned directory and creates the service account/group automatically. It does not download or execute a remote installation script.

```sh
sudo sh scripts/install-linux.sh /absolute/path/handkey /absolute/path/real/op AGENT_USER
```

The installer creates `/opt/handkey`, `/var/lib/handkey`, `/etc/handkey`, the `handkey` system user/group, and a systemd unit. It adds `AGENT_USER` to the broker socket group; start a new login session before accessing the socket. Set `HANDKEY_LISTEN` and the TLS paths in `/etc/handkey/server.env`, then explicitly start the service. The broker does not start without a listen address, because approval clients have no other way in:

```sh
sudo systemctl enable --now handkey.service
export HANDKEY_ENDPOINT=unix:///run/handkey/agent.sock
```

The socket serves the agent API only. The listen address serves the approval API only, including first-device bootstrap, so a process with socket access cannot register itself as the first device. The sample environment enables first-device bootstrap. Disable `HANDKEY_BOOTSTRAP` after successful registration. Once initialized, the API refuses another bootstrap even if the flag remains set. The TLS private key must be readable by the broker account but not by the agent. The listener should bind to a restricted private-network address; do not bind publicly without a separate access-control boundary. Add `--remote-agents` to the unit only when agents run on another host. It serves the unauthenticated agent API on the listen address, so every peer that can reach that address can submit requests. Configure exact external client origins with `HANDKEY_ORIGINS`.

The installer is supplied for review and has not been exercised on a production host. It never migrates vault items, requests credentials, or changes 1Password settings. Upgrades replace executables only and do not initialize or overwrite state. Stop the service before replacing binaries.

## macOS

The binary and macOS helper compile and run, but a production launchd installer is not included yet. For development, run the broker with `--dev` under your own account and understand that this provides no user isolation. For a manually configured production service, place the broker, real `op` and launchd configuration under root ownership; keep the state under a dedicated service user with mode 0700. Set the service's core-size limit to zero as well as the broker's process-level control. Production signing/notarization and Hardened Runtime remain release work.

The dedicated real `op` must be an absolute path with no symlink or group/world-writable parent directory; each component must be owned by root or the broker account. A usual user-writable Homebrew executable does not meet the intended isolation model. The executable/path checks are an accident guard, not a substitute for reviewing account permissions or sudo access.

Use `--socket-mode 0660` only with a dedicated socket group and a directory that the agent cannot replace. Mode 0600 is the default. Create the socket directory outside the private state directory so socket clients cannot read state. A clean Unix listener shutdown removes its socket; after a crash, verify the old process is stopped before removing a stale socket.

## Windows

Cross-compiled CLI and core API builds are available. Production service ACL validation and native GUI helpers are not implemented. Use only `--dev` for evaluation and configure crash-dump policy separately. Do not infer Windows deployment isolation from Unix mode bits.

## Credentials, persistence and recovery

Use a service account with read/write access to a custom vault. Built-in Private/Personal vaults are not accessible to service accounts. Keep the service account token and approval keys outside accessible vaults when possible. The setup API accepts the token from the separate approval client; neither the installer nor CLI needs it.

Back up the complete private state directory while the service is stopped. `state.key` encrypts `state.enc`; the latter contains a separately wrapped service-account token, wrapped device keys, token hashes, requests and metadata. Fetched values are never backed up. Audit files contain request IDs, canonical field IDs, method, origin, device, lease conditions and result, but omit arbitrary text and payloads.

State files are atomically replaced and synced before executing `op`. On a persistent storage failure the broker fails closed. A crash after beginning a write can leave an unknown result even if the item was created. Reconcile its request-ID tag using a trusted 1Password client; do not automatically submit a replacement create.

Agent receipts default to the platform's user cache directory under `handkey/receipts`; they are mode 0600 and grant access to that request. Remove expired receipts according to the caller's retention policy. Receiver tokens expire after 24 hours. Broker request state is pruned after eight days total; audit files currently require operator-managed rotation. Metadata remains until the next full refresh removes it.
