# handkey

Approval-gated access to 1Password for AI agents. A Go CLI and broker API, with **no approval UI**. Approval clients are developed in separate repositories.

An agent requests specific fields and a delivery method. A registered client approves by sending its device key. The broker briefly decrypts a 1Password service account token, invokes the real `op`, then releases the token before the caller runs a command. Leases retain only approved field values in memory.

**Status: experimental initial implementation.** The broker and CLI are tested with an isolated 1Password process fixture; live service-account access, GUI typing, and deployment on a dedicated account still need integration testing. This is a scoped CLI shim, not a complete drop-in implementation of every `op` command or output format.

## Install or update

Install [Go 1.25 or newer](https://go.dev/doc/install), then run this from any directory:

```sh
go install github.com/asuhacoder/handkey/cmd/handkey@latest
```

The same command updates an existing installation. To install a specific release, replace `@latest` with a tag such as `@v0.1.0`. Go downloads the published module and builds the executable for your machine; cloning this repository, Homebrew and a separate package registry are not required. Go is needed for installation and updates, not to run the installed executable.

Go installs commands into `GOBIN` if configured, otherwise the `bin` directory inside `GOPATH` (usually `$HOME/go/bin`). Add that directory to your shell's `PATH` once. For the default location on macOS/Linux:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
handkey --help
handkey version
```

Save the `export` line in your shell startup file to keep it across sessions. If `go env GOBIN` prints a custom directory, use that directory instead. On Windows, add the corresponding Go binary directory to your user `Path`; the installed command is `handkey.exe`.

Runtime dependencies: the real [1Password CLI](https://developer.1password.com/docs/cli/), and macOS Accessibility permission for `type`. Installing Handkey does not start a broker or register approval devices; configure those separately below.

The same binary provides `handkey serve` and the agent CLI. It can also be installed as `op`; configure the broker with an absolute path to a **separate real `op` binary**, never this shim. This server-side setting is independent of how you install or invoke `handkey`.

## Start a development broker

```sh
mkdir -m 700 .handkey
handkey serve \
  --state-dir "$PWD/.handkey" \
  --op /absolute/path/to/real/op \
  --socket "$PWD/.handkey/agent.sock" \
  --listen 127.0.0.1:7843 --dev --bootstrap
```

This prints endpoint addresses only. It does not print keys, tokens, or a registration website. When you set `--listen`, the Unix socket serves the agent API only and `--listen` serves the approval API only. `--bootstrap` then enables the first-device API on `--listen` until initialization succeeds; expose it only to the intended first client. Without `--listen`, the socket serves both APIs, so every process that can open the socket can register the first device. Use the separately implemented approval client and the [client API contract](docs/api.md) to register a client-generated 32-byte key and a service account token. There is no built-in approval command or webpage that takes custody of a user's key on behalf of an agent.

For remote access, supply `--tls-cert`, `--tls-key`, and a restricted listen address instead of development HTTP. Configure `--origins` with the exact HTTPS origin of an independently hosted browser client. Agents on another host need `--remote-agents`, which adds the agent API to `--listen`. Restrict that address using tailnet ACLs or an equivalent private network; the agent API intentionally has no login, and anyone who can reach it can submit a request for you to approve. HTTPS alone does **not** restrict who can submit requests. See [deployment](docs/deployment.md).

## Use the CLI

```sh
export HANDKEY_ENDPOINT="unix://$PWD/.handkey/agent.sock"

# Populate the metadata cache (requires approval).
handkey refresh --reason 'Find the account for this task'
handkey item list --query example.com

# Refresh an item's field names using canonical IDs before resolving names.
handkey refresh op://VAULT_ID/ITEM_ID/password

# Request raw output directly when that is the intended delivery method.
handkey read op://Main/Example/password --reason 'Log into the requested account'

# Supply a credential to one command; exact values are masked in its output.
API_TOKEN=op://Main/Example/credential \
  handkey run --reason 'Run the deployment tool' -- your-command

# Repeated use: receiver token goes to a private file, never printed.
handkey read op://Main/Example/password \
  --ttl 5m --uses 3 --receipt ./task.receipt.json
handkey use ./task.receipt.json
```

Placeholders such as `VAULT_ID` must be replaced with actual 26-character IDs; they are not literal example credentials. Names must already be in the cache; explicit vault/item/field IDs work before a cache refresh. `--no-wait` returns a request ID and receipt **file path**, so an agent can do other work while waiting. `status`, `cancel`, and `use` take that receipt file. `--help` describes supported flags and error recovery.

## Develop from source

There are no Go module dependencies. From a checkout of this repository:

```sh
go install ./cmd/handkey
go test -race ./...
go vet ./...
```

For a repository-local build instead, run `go build -trimpath -o bin/handkey ./cmd/handkey`. This is a development option; normal users can use the `go install ...@latest` command above.

## Current support

| Area | Implemented | Limitations |
| --- | --- | --- |
| Approval | Envelope encryption, device (key) registration and revocation, up to 16 named sessions per device with independent view tokens, per-session revocation, token rotation, first valid decision wins | Separate client supplies all key generation, storage and approval UX. Sessions expire after 90 days and are replaced, not renewed |
| Requests | Durable states, cancellation, 15-minute maximum pending timeout, receiver capabilities, restart recovery | Single broker process; in-memory values and proxy sessions do not survive restart |
| Metadata | Value-free search and field metadata, optional approval requirement, origin-only cached URLs | Uncached field names require an approved refresh; full list sync is piggybacked at most every 15 minutes |
| `reveal`, `otp` | Text fields, multiple references, RFC 6238 TOTP, field-scoped leases | No passkeys, documents, binary attachments or structured SSH-key fields |
| `run` / `exec` | Caller-side execution, environment injection, original argv/cwd, streaming exact-value redaction | Environment references must occupy the full value; a command can deliberately disclose/transform a secret |
| `inject` | Local template input and private output files; always reveal approval | Does not overwrite existing files; no background `--no-wait`; supports the documented reference syntax |
| `proxy` | One loopback URL per command, fixed HTTPS origin, injected header, no redirects, heartbeat cleanup | Not an HTTP CONNECT proxy; upstream responses can themselves contain credentials |
| `type`, `clipboard` | macOS helper, foreground PID/app/title check, conditional clipboard cleanup | GUI paths are not yet exercised on hardware; Linux/Windows GUI adapters are not implemented |
| `item create` | JSON fields over stdin, generated passwords, request-ID reconciliation tag, metadata-only result | Existing-item edits and two-phase password changes await a verified lossless update adapter |
| Events | Authenticated SSE fan-out, bounded queues, optional generic HTTPS webhook | Hints are not a durable event log; clients reconcile after reconnect; no Web Push sender yet |
| Packaging | macOS/Linux/Windows cross-builds, CI, Linux dedicated-user installer | macOS launchd installer, signed/notarized builds and production Windows ACL support remain open |

Supported `item list` returns a Handkey metadata envelope (`items`, `synced`, `last_sync`). `item get --format json` returns an approved reference-to-value object. These schemas intentionally differ from the full `op` item JSON; unknown commands and flags fail instead of bypassing approval. Plain `item get` returns metadata only. `--fields` is a comma-separated list; positional `field=value` arguments are rejected.

## Architecture and boundaries

```text
Agent / CLI ── Unix socket (or --remote-agents HTTPS) ── Broker ── isolated real op ── 1Password
                                                    ▲
Separate approval client ── HTTPS, view token + key ──┘

Approved field values ── caller-side helper ── command / macOS foreground window
```

The service token is encrypted with a random master key. Each device, meaning each registered key, has a separately encrypted copy of the master key. Each client that uses the key has its own session and view token. View and receiver tokens are stored as hashes. The encrypted state file has a separate local storage key; that key alone cannot unlock the service token. No fetched field values, TOTP seeds, or active proxy tokens are written to disk. Agent-supplied pending write fields are part of encrypted request state until execution finishes.

Protect the broker executable, dedicated `op`, state, startup configuration, and approval client code from the agent's user account. An agent with the same UID or administrator access can bypass that separation. Approval unlocks a vault-wide service token briefly; it is not a field-scoped credential issued by 1Password. Go cannot promise immediate erasure of every memory copy. See [security boundaries](SECURITY.md), [API](docs/api.md), and [roadmap](docs/roadmap.md).

Keep the broker's own service account token and approval keys in a Private vault outside its service-account-accessible vaults. Handkey deliberately does not prohibit requesting these fields if you store them in an accessible vault.

MIT licensed. Unaffiliated with 1Password.
