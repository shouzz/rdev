# SSH over WebSocket release — 2026-10-01

Production is `v0.2.121-feidu.33-4714565`, built from
`47145653b2bf08b0867712891684bb65bb330ea7`.

- Image: `rdev-new-local:v0.2.121-feidu.33-4714565`.
- Server SHA-256: `6982468470314d95ef120839f95c16a6b30a7a2c9618de3bba8d5a1190f2f7e1`.
- Agent SHA-256: `af5360c661651494faf8c7a380b50216a1ffd6f33d18d54b9efa8e766676760d`.
- Compose: `/opt/rdev-new/rdev-compose-v0.2.121-feidu.33-4714565.yml`.
- Rollback: `/opt/rdev-new/backups/ssh-wss-4714565-20261001T073345Z/rollback.sh`.
- Previous image: `rdev-new-local:v0.2.121-feidu.32-bb12969`, also tagged
  `rdev-new-local:rollback-ssh-wss-4714565`.

The original pre-task image `rdev-new-local:v0.2.121-feidu.31-973023b` and its
Compose remain available. The first task backup is
`/opt/rdev-new/backups/ssh-wss-bb12969-20261001T070434Z`. No old backup was deleted.
Backups include the data volume (excluding downloadable releases), control
credential file and previous Compose; runtime credentials are not in this report.

## Behavior

`/ssh-ws?device=EXACT-ID` authenticates the existing credential subprotocol before
upgrading. Permanent credentials require `ssh`; browser-only tickets and raw
device passwords are rejected. The inner SSH username must match the outer
device, and no credential is sent to the device. The same SSH host key and
session handlers provide exec, PTY/shell and SFTP. Modern SCP uses SFTP.

The Agent defaults to an SSH banner probe, with WSS fallback before execution.
Explicit `raw` and `wss` are supported; a failed command is never replayed.
WSS disables OpenSSH connection reuse and rejects TCP, Agent and X11 forwarding.
Limits and the dependency `websockets>=15,<17` are recorded in the public manifest.

## Verification

- Full `go test ./... -count=1 -timeout=10m` passed on Windows and Linux.
- `go test -race ./internal/server -run TestSSHWS -count=1 -timeout=90s` passed.
- Python discovery under `skills/rdev-agent/tests`: 43 tests passed, including
  subprocess encoding, DPAPI-related existing coverage, automatic selection,
  command non-replay, bounded client buffers, half-close, redirect rejection,
  secret redaction and distribution hashes.
- Vitest `web/tests/agent-docs.test.js`: 6 tests passed.
- Go WSS tests cover exact-device authorization, capability denial, browser
  ticket denial, expiry/revocation, actual SSH binary input/output and exit 23,
  SFTP subsystem, independent stdin EOF, wrong SSH username, both forwarding
  directions, oversize/text rejection, concurrency, idle/write/handshake timeout
  and duplex EOF.
- Public Agent, skill, manifest, artifact guide and `tools/feidu-drive.py`
  matched repository bytes. All corresponding distribution copies matched.

After final deployment, a Linux cloud host ran the Agent through a temporary
HTTP CONNECT proxy which accepted only `r.feidu.fit:443`. It opened 10 tunnels:

- Exact device and returned hostname: `DESKTOP-Q4DTNMS`.
- Unique output: `RDEV_WSS_f39fbb047e0c4b809ed1062667d97430`.
- Actual command exit code: `37`; independent stderr verified.
- SCP and SFTP each uploaded and downloaded 524,329 bytes. Local source,
  device-side hash and downloaded hash all matched
  `46caf8072820cf02c78d6791e7cf4af3ab7b7a45050ff3183d2a59bb53bee243`.
- Invalid credential handshake returned HTTP `401`.
- Both remote temporary files were deleted and absence verified.
- Local Windows WSS and raw SSH each returned the same real hostname.

The final container was running with restart count `0`, the public `/api/config`
returned current SSH port `18112`, the SSH host key matched the backup, and no
panic/fatal/segmentation-fault log entries appeared after deployment. Successful
post-deployment SSH proves the tested device reconnected.

## Acceptance boundary

The cloud test used a real cloud VM and a controlled CONNECT proxy. It did not
run inside the user's particular Codex hosted sandbox. That environment still
needs to permit HTTPS CONNECT and WebSocket Upgrade to the service. WSS port
forwarding is intentionally unsupported; select raw SSH for forwarding.

An initial SFTP test used Windows `C:/...` as a relative SFTP path and failed;
using the required `/C:/...` absolute form passed. An initial Windows full-suite
failure exposed persistence errors being confused with device-not-found; the
integrated fix passed the final Windows and Linux suites.
