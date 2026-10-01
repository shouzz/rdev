# Device names and remote RDev maintenance

These are backend control APIs. Send `X-RDev-Control-Token` over HTTPS from a
trusted backend; never put the control token in browser JavaScript, a URL, a
command line, or logs. Browser tickets and per-device SSH tokens do not authorize
these endpoints. Control must be configured; disabled control returns 503.

Every request supplies the actual operator's `subject` and an exact,
case-sensitive, URL-encoded device ID in the path. Display names cannot select
devices. Only non-revoked managed devices are eligible. Authorization uses the
existing managed-device policy: ordinary subjects must match the owner; Feidu
devices are shared with valid Feidu account subjects. The trusted backend must
derive the subject from its authenticated session, never from untrusted user input.

## Display names

`PATCH /api/control/devices/{exactDeviceId}/name`

```json
{"subject":"account-subject","displayName":"机房控制器"}
```

Returns `{"deviceId":"exactDeviceId","displayName":"机房控制器"}`.
Names allow up to 256 UTF-8 bytes, no control characters or surrounding
whitespace. Empty string clears the override. Duplicate names are allowed.
`GET` on the same path with `?subject=account-subject` reads it, including while
the device is offline.

Names persist in the managed-device registry across reconnect, replacement
enrollment by the same owner, and server restart. Registry writes are atomic;
write failure returns 500 and restores the in-memory record. The ID, requested ID,
instance, device secret, maintenance token and credential generation are untouched.
Registry schema v6 is emitted when a nonempty name exists; older schemas still
load. An old server cannot read v6: back up the registry before a server downgrade.

Device lists, terminal device metadata and device events expose `displayName`.
The dashboard shows the name together with the stable ID. Online rename emits
`device.updated`. This backend API deliberately does not expose the control
credential through dashboard editing controls.

## Upgrade, one-shot stop, optional uninstall

Read the current `instanceId` and `deviceManagementV1` from the authenticated
device list or device event snapshot. Only the Go client with this capability can
execute maintenance. Older clients and the Rust GPU client return 409 at dispatch.

`POST /api/control/devices/{exactDeviceId}/actions`

```json
{
  "subject":"account-subject",
  "instanceId":"current-instance-from-device-list",
  "requestId":"0123456789abcdef0123456789abcdef",
  "action":"upgrade"
}
```

`requestId` is a newly generated random 16-byte value encoded as 32 lowercase
hexadecimal characters. Supported actions: `upgrade`, `stop`, `uninstall`.
Uninstall additionally requires `"confirm":true`. Only uninstall accepts
`"deleteIdentity":true`; its default is false.

202 means dispatched, not completed. Poll:

`GET /api/control/devices/{exactDeviceId}/actions?subject=account-subject&requestId=0123456789abcdef0123456789abcdef`

The response includes `requestId`, `deviceId`, `instanceId`, `action`, `state`,
and, on failure, a sanitized `errorCode`.

| State | Meaning |
| --- | --- |
| `dispatched` | Sent to the specified connection; waiting for a result |
| `up_to_date` | Updater found no newer stable release |
| `applied_restart_pending` | Verified binary applied; restart is about to be attempted |
| `stopping` | Client acknowledged a one-shot stop and is about to exit |
| `uninstalled_stopping` | Supported installation files removed; client is about to stop |
| `failed` | Client rejected or failed the action; no credential-bearing diagnostic is returned |
| `unknown` | Delivery failed or no acknowledgement arrived within 15 minutes; do not assume success or retry automatically |

Verify a new connection's reported version after upgrading and offline state
after stopping. An acknowledgement before process exit is not proof of a
successful restart or service stop. A restart/stop failure can change the pending
state to `failed`; a lost connection can prevent that report.

Within a running server, repeating the exact POST with the same request ID reads
the existing operation; conflicting reuse returns 409. Each client also prevents
re-execution of request IDs for its process lifetime. Results bind the exact
connection object, ID and instance; another device or a replacement connection
cannot supply them. At most one dispatched action per device is allowed.
No command is queued for an offline device or replayed on reconnect.

History is in memory, limited to 1,024 operations for 24 hours. Full history
returns 503 instead of evicting a recent deduplication entry. Client request
history is also capped at 1,024 for its process lifetime and fails closed when
full. After a server restart, absent history returns 404; **never interpret 404
as permission to replay a command**. Generate unique IDs and reconcile device
state before intentionally issuing another action.

### Upgrade behavior

The existing updater selects the latest stable release from `icepie/rdev` and
the matching Go OS/architecture asset. The API cannot supply URLs, shell commands,
arbitrary versions or an alternate executable. Automatic and requested upgrades
share a serialized apply path. Metadata and SHA-256 digest come directly from
GitHub over verified HTTPS; optional download mirrors supply only asset bytes.
A missing/mismatched digest fails before replacement. Replacement retains the
existing updater rollback behavior. An applied update blocks another apply until
restart. The existing process arguments and environment are reused.

Development builds cannot report a successful upgrade. Windows versions before
Windows 10 reject this update channel: Win7 requires a separately built,
hash-pinned go-win7 artifact and real legacy-machine acceptance. This feature
does not publish such an artifact. `--no-auto-update` disables periodic polling;
an explicitly authenticated upgrade remains available.

### Stop and installation boundaries

Stop ends the current process without reconnecting and preserves identity and
startup configuration. A standalone client exits with reserved code 75. The
updated Windows service wrapper treats code 75 as an intentional, clean stop.
Login startup installations remain configured for the next login.

For the standard Linux installation, the client verifies its executable path
(`/usr/local/lib/rdev/rdev-client`) and its `rdev-client.service` cgroup, then
requests `systemctl --no-block stop rdev-client.service`. This suppresses
`Restart=always` for the current run without disabling boot startup. An unknown
systemd installation with `INVOCATION_ID` fails closed. External supervisors must
honor exit code 75; custom supervisors and old Windows wrappers are not covered.

### Optional uninstall

Uninstall additionally requires local startup opt-in:
`rdev-client --allow-remote-uninstall ...`.
Currently only the standard Linux systemd installation above is supported.
Windows, macOS, Android/Termux and custom installations return failure without
deleting files. No task names, service names or paths are guessed.

The client disables the standard unit, removes only its fixed unit file and
executable, reloads systemd and stops. It never recursively deletes installation
or user directories. The configured identity file and server-side device record,
tokens and display name are retained. `"deleteIdentity":true` additionally removes
only the exact absolute identity file configured locally, and only after removal
of the installation files succeeds. Remote uninstallation can partially fail;
inspect the device before issuing a new action. Server-side revocation remains a
separate existing API.

## Validation and rollout

Tests use local fixtures and loopback transports. They cover registry restart and
rollback, authorization, exact-ID and instance checks, protocol result binding,
deduplication, WS/TCP/KCP dispatch, digest verification, subprocess termination
and retained identity. Windows import regression tests exercise real child
process encodings and DPAPI readback independently.

Do not equate fixture tests with production deployment, real systemd uninstall
acceptance, Windows service installation acceptance or Win7 hardware acceptance.
Deploy the server and compatible clients separately when authorized.
