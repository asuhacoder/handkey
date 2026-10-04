# Implementation roadmap

The starting design is a 1Password-only approval broker using Go and the real `op`. This repository implements the CLI/broker, while approval clients are separate projects. The original private discussion document is not copied into the public repository.

## Next implementation work

- Verify the existing-item field-update path against real `op`, including passkey preservation and no secret process arguments. Use a narrowly scoped official SDK adapter if the CLI cannot do this safely. Until verified, reject `item edit`; never use a whole-item JSON rewrite as a fallback.
- Add durable candidate-password creation and promotion after the agent reports that the external site's change succeeded. Keep the old password until promotion.
- Add Web Push/VAPID sender support and per-device notification settings. Keep client/service-worker code in client repositories.
- Add dedicated-user macOS launchd installation, signed/notarized Hardened Runtime binaries and GUI integration tests. Evaluate native Unicode typing across keyboard layouts and remote desktops.
- Add native Windows/Linux GUI helpers and production Windows ACL/crash-report controls.
- Add approval-client enrollment coordination, advisory device method preferences, and operational device listing. The existing authenticated device-rewrap API is sufficient for clients that coordinate enrollment themselves.
- Expand the scoped `op` compatibility surface, receipt-based metadata approval CLI ergonomics, document/attachment delivery, process ancestry and verified tailnet node attribution.
- Add opt-in audit rotation and backup/recovery tooling. Keep notification retries bounded and avoid retaining secret payloads.

## Real-world validation still required

- Real service-account permissions, CLI item-create JSON over stdin, category/field behavior and generated-password recipes across supported `op` versions.
- Separate clients: phone autofill to the approval API, iOS/Android lifecycle, dsh direct-to-broker key submission, Even Hub storage/lifecycle and fixed-origin packaging.
- Rate limits and the 15-minute opportunistic list refresh under real workloads. Large vaults may exceed the current 8 MiB `op` output bound and must receive an explicit supported strategy.
- macOS foreground identity and typing, clipboard behavior and remote Windows sessions.
- Dedicated-user Linux installation, service upgrade/rollback, backups and restore with new/revoked devices.

## Intentionally out of scope

Master-password unlock, vault-session keepalive, service-token retention during leases, command-identity restrictions on lease reuse, passkeys, other password managers, multi-instance clustering, native notification apps, and detection of a malicious approval client or a malicious approved agent command.
