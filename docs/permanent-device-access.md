# Permanent device access

Feidu grants one permanent `fdpat_` per device after the account and directory are authorized. The one-copy configuration is `rdev-device-access.v1`; its seven fields are listed in [the manifest](ai-agent-manifest.json) and import commands in [the artifact bridge](ai-agent-artifact-bridge.md). The same saved token supplies SSH/SFTP and the Feidu developer API. Normal connection loss, a new AI conversation, client restart, or server restart does not rotate or expire it.

## Server contract

`GET` / `PUT /api/control/devices/{escaped-device-id}/maintenance-token` uses the existing `X-RDev-Control-Token`. PUT fields are `tokenId`, `tokenHash`, `subject`, `generation`, `capabilities`, `revoked`. `tokenHash` is lowercase SHA-256 of the complete token; the subject is `feidu-user:<account-id>`. There is no expiry field.

The response contains device ID, token ID, subject, generation, sorted capabilities, revocation state and `persisted:true`. It never contains the digest or token. Equal generation and equal data are idempotent. Conflicting or older updates return 409. A device keeps its original token subject; a token ID or digest cannot be shared with another device. Offline registered devices accept updates. Explicit revocation closes active connections and persists a tombstone.

The service authenticates using its durable device registry. Feidu availability is not part of each SSH authentication. Feidu periodically re-sends bindings, including already synchronized entries, so its intended state can be restored after a control outage or registry rollback without recovering plaintext tokens.

## Connection behavior

The production Feidu browser supplies WebSocket protocols `rdev-browser-v1` and `rdev-access-ticket.<fdpat>` and sends the same token in the channel authentication message. Supported paths are `/terminal`, `/files`, `/desktop`, and `/peripherals`; each checks the corresponding capability. The fixed-token message requires a fixed-token handshake. Existing browser short tickets remain a separate compatibility path.

The standalone legacy RDev HTML, raw VNC port, and GPU HTTP proxy are not a fixed-token browser entry point in this change. A protocol-level desktop or peripheral test does not establish a live screen, camera, or serial-device test.

Default capacity is 256 concurrent sessions and 1024 forwards per device, exposed as `maxSessions` and `maxForwards` strings by `/api/config`. SSH has no five-connection lease. `--max-sessions` and `--max-forwards` configure actual server limits. These are capacity settings, not token expiry. A stale SSH connection cannot close a newer connection using the same grant.

## Deployment and recovery

Deploy the RDev server first, then Feidu's database migration, server and browser assets. Existing clients and temporary tickets continue to work. A server restart interrupts current transports; clients reconnect and use their original device enrollment secret, while the permanent access token stays unchanged.

Before replacement, record the old image and compose file and back up the current device registry and host key with restricted permissions. Keep the host key and existing device data volume. Build a versioned server artifact from the tested commit; compare its SHA-256 after upload and in the running container. Validate config, registered-device reconnect, actual SSH/SFTP and fixed-token control round trips after replacement.

The registry becomes `rdev-device-registry.v4` when a maintenance binding is saved. Old servers accept only v2/v3. An old-image rollback therefore requires stopping the server and converting the **current** registry with the offline rollback tool described in [maintenance token rollback](maintenance-token-rollback.md). Do not overwrite current enrollment data with an older snapshot. Keep the full v4 backup; after upgrading again, Feidu can re-send bindings using stored hashes. Permanent-token access is unavailable while an old server is running.

Cloud transfer verification must distinguish local isolated-storage tests from live storage validation. Keep the same transfer ID, operation ID and upload session on resume. Completion requires the final file size and hash, not merely a successful control response.
