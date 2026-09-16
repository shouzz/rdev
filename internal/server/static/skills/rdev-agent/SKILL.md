---
name: rdev-agent
description: Operate an exact RDev device with saved permanent device access, including SSH, SFTP, port forwarding and Feidu file transfers. Import copied device access once; subsequent AI sessions reuse it automatically.
---

# RDev Agent

Use the saved authorization for the exact device and the user's requested work. Permanent device access is the default; it needs no claim, heartbeat, renewal or end-of-task revocation.

## Import once

The authenticated Feidu device page supplies one JSON object with exactly `schema`, `device_id`, `rdev_base`, `api_base`, `ssh_host`, `ssh_port` and `token`. Its schema is `rdev-device-access.v1`; the single `fdpat_` is used by both RDev and Feidu. Do not ask the user to paste that JSON into an AI chat.

After the user copies access on the authorization page, run:

```powershell
python rdev-agent.py --import-clipboard
```

Windows imports the clipboard directly, saves current-user DPAPI protected access, and clears the same clipboard value after successful import. The tool prints only non-secret connection metadata. On Unix, pass the JSON through a protected stdin channel to `python3 rdev-agent.py --import-stdin`; the tool saves a mode `0600` file. Never interpolate the JSON or Token into shell command text or process arguments.

Each device has its own saved entry. Reimporting identical access is harmless. Changed access requires explicit `--replace` after an intentional reset or change; network errors never reset it. Losing a local entry does not make the server able to recover plaintext from its hash: use another protected copy or the authorization page's explicit reset.

## Use automatically

If one device is saved, omit `--device`. For multiple devices, select the exact non-secret ID:

```bash
python3 rdev-agent.py --device DEVICE-ID status
python3 rdev-agent.py --device DEVICE-ID ssh -- hostname
python3 rdev-agent.py --device DEVICE-ID ssh --local-forward 127.0.0.1:8080:127.0.0.1:80 --no-command
python3 rdev-agent.py --device DEVICE-ID sftp
python3 rdev-agent.py --device DEVICE-ID sftp --batch-file -
python3 rdev-agent.py --device DEVICE-ID scp-to ./artifact.bin /tmp/artifact.bin
python3 rdev-agent.py --device DEVICE-ID scp-from /tmp/result.bin ./result.bin
python3 rdev-agent.py --device DEVICE-ID drive capabilities
```

`status` reports saved connection information; it is not a live authorization or device-health check. Verify the exact endpoint and the device's returned identity when starting remote work, then continue the authorized task. Do not request another claim because an AI session changed, either server restarted, the device disconnected, or a cloud request failed.

SSH uses a 10-second connection timeout and 15-second keepalives with three missed replies. Remote commands have no short automatic deadline. Fixed access does not start a lease-maintenance thread, and a Feidu outage cannot kill a healthy SSH process. If SSH exits, preserve its exit result and inspect remote task state before retrying a write; do not assume killing the local SSH process stopped the remote operation. Ordinary remote commands are never automatically replayed.

The tool loads the same Token as the runtime SSH/SFTP password and `FEIDU_DRIVE_TOKEN` for the bundled drive client. No Token is needed in command text. SFTP is preferred for file transfer; modern SCP uses SFTP without `-O`. Use the exact copied SSH host and port. Do not infer device IDs or require `/api/clients` discovery.

## Cloud transfers

Use `drive capabilities` and returned `content_id` values for Feidu objects. Ordinary developer uploads/downloads retain the existing upload `operation_id` and `session_id` on recovery. For files larger than `104857600` bytes, use the cloud transfer commands so bytes flow directly between the device and storage:

```bash
python3 rdev-agent.py --device DEVICE-ID transfer create --direction cloud_to_device --source-content-id CONTENT-ID --destination-parent-path /tmp --file-name artifact.bin --size-bytes 104857601 --wait
python3 rdev-agent.py --device DEVICE-ID transfer create --direction device_to_cloud --source-path /tmp/result.bin --file-name result.bin --size-bytes 104857601 --wait
python3 rdev-agent.py --device DEVICE-ID transfer list
python3 rdev-agent.py --device DEVICE-ID transfer status TRANSFER-UUID --wait
python3 rdev-agent.py --device DEVICE-ID transfer resume TRANSFER-UUID
```

The tool uses fixed-Token `POST/GET /developer/v1/rdev/transfers`, then `GET /{transfer_id}` or `POST /{transfer_id}/pause|resume|cancel`. The server derives account, device and root from the Token binding. AI does not create an AgentSession or handle internal `fdtx_` credentials.

The tool prints a non-secret transfer UUID before create, allowing recovery after a lost response. Keep this ID. `--wait` reports state changes and 5% progress, retries recoverable reads, and resumes the original failed or expired transfer at most twice by default. An expired internal 24-hour task credential is recovered through the same fixed Token and transfer ID. Use `--auto-resume-attempts` to change the bound. Completed means success; failed, cancelled or exhausted recovery returns nonzero. Recover with the same ID, never a fresh object or a new claim. A user's paused or cancelled task is not automatically restarted.

For manual SFTP/local staging compare file size and hashes across each hop. For cloud transfers require terminal `completed` plus the device/service integrity result; HTTP 200 from a control request alone is not completion.

## Authorization and credentials

Keep the Token only in the tool's protected store and process secret channels. Never print it, paste it into chat, place it in URLs, logs, source, screenshots or AI memory. The Feidu web workspace opens WebSocket with subprotocols `rdev-browser-v1` and `rdev-access-ticket.<runtime fdpat_>`, then sends that same Token and device ID in the channel auth message. Both handshake and message credentials must match; the Token is never in the URL. This release does not add fixed-Token support to the old standalone RDev HTML pages or raw VNC/GPU proxy paths. Do not forward the Feidu Authorization header to signed storage download URLs.

View and revoke permanent authorization on the Feidu device page when requested. Finishing a maintenance task, stopping a command or closing an AI session does not revoke it. During a control-channel outage, RDev can authenticate using its persisted binding; a new Feidu revocation reaches it after synchronization returns. Report that condition accurately rather than treating offline status as credential expiry.

## Legacy temporary handoffs

Only an explicitly supplied legacy `fdhc_` uses `start --device ... --claim-expires-at ...`, with claim from hidden prompt/stdin. That path retains its original temporary AgentSession, heartbeat and renewal API. It is separate from permanent access. Never switch an imported permanent device to this path or request a replacement claim for it.

Read [the artifact bridge guide](https://r.feidu.fit/docs/ai-agent-artifact-bridge.md) for protocol details and [the manifest](https://r.feidu.fit/docs/ai-agent-manifest.json) for exact schemas. Source definitions take precedence when developing RDev itself.
