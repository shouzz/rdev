---
name: rdev-agent
description: Connect an AI coding agent to one exact RDev device and the account-scoped Feidu artifact plane using a copied one-time handoff. Use for remote diagnosis, deployment, file transfer, OTA, or port forwarding after the user provides an RDev claim.
---

# RDev Agent

Use the handoff only for the device and task authorized by the user. Creating or redeeming a handoff does not authorize unrelated scans, deployments, file changes, or cloud mutations.

The public join launchers never use `--replace-existing`: a fresh installation receives a separate server-assigned ID when its hostname collides, including within the same account. A persistent installation reuses its OS-protected identity on subsequent runs and does not redeem another invitation. The advanced client's explicit `--replace-existing` option still permits only an exact, non-revoked managed ID owned by the same Feidu account; it rotates the secret, advances the credential version, invalidates old tickets, and disconnects the old connection. Never infer that two computers are the same device from a hostname.

## Redeem And Verify

1. Read the exact device ID, `fdhc_` claim, claim deadline, and requested task from the copied handoff. If the claim is expired or the task is not stated, stop and ask for a new handoff or the concrete task.
2. Pass the claim to `rdev-agent.py start` only through its standard input or hidden interactive prompt. Never add the claim to process arguments. The tool sends one `POST application/json` request to `https://pan.feidu.fit/agent/v1/handoffs/redeem` with `{"claim":"<runtime claim>"}`. Require HTTP 200 and JSON `code == 0`, then clear the claim from runtime state.
3. Read only these exact response fields:
   - `data.credentials.device_id`
   - `data.credentials.rdev_ticket.ticket`
   - `data.credentials.developer_token.token`
   - `data.credentials.agent_session.agent_session_id`
   - `data.credentials.agent_session.renewal_token`
   - `data.credentials.agent_session.state`
   - `data.credentials.agent_session.ticket_remaining_seconds`
   - `data.credentials.agent_session.developer_token_remaining_seconds`
   - `data.credentials.agent_session.estimated_transfer_seconds`
   - `data.credentials.agent_session.minimum_safety_margin_seconds`
   - `data.credentials.agent_session.renewal_due_at_ms`
   - `data.credentials.agent_session.absolute_expires_at_ms`
   - `data.credentials.agent_session.selected_transport`
4. Require the returned device ID to equal the copied device ID and the session state to equal `active`.
5. Read `https://r.feidu.fit/api/config` and use its exact `sshPort`. Run one non-interactive, no-PTY `hostname` through SSH and verify the returned identity before starting the requested task. Do not call `/api/clients`.
6. Report the verified device identity, current SSH port, remaining lease time, absolute session deadline, and selected transport without exposing any secret. Then continue only with the requested task.

Use the RDev ticket only as the runtime SSH/SFTP password. Set the developer token only in the runtime environment variable `FEIDU_DRIVE_TOKEN`. Do not put either value in command text that will be logged.

## Keep The Session Alive

Authenticate session operations with `Authorization: Bearer <renewal_token>`. Keep the token in memory.

- Inspect the lease with `POST https://pan.feidu.fit/agent/v1/sessions/{agent_session_id}/heartbeat`.
- Renew it with `POST https://pan.feidu.fit/agent/v1/sessions/{agent_session_id}/renew`.
- Revoke it when the task is complete with `DELETE https://pan.feidu.fit/agent/v1/sessions/{agent_session_id}`.

For heartbeat and renewal, send the exact workload fields `size_bytes` and `observed_bytes_per_second`. Before a long transfer, use the known file size and a measured end-to-end rate. Renew before `renewal_due_at_ms`, or earlier when the smaller remaining credential lifetime is not greater than `estimated_transfer_seconds + minimum_safety_margin_seconds`.

A successful renewal returns the updated session under `data.session`. Keep the original RDev ticket, developer token, and renewal token; renewal extends their expiry in place and must not interrupt an established SSH, SFTP, or port-forwarding connection. Update only `ticket_expires_at_ms`, `developer_token_expires_at_ms`, the remaining-time fields, and `renewal_due_at_ms`. If a renewal response includes `renewal_token`, require it to be byte-for-byte identical. Stop on HTTP 401, a nonzero JSON `code`, a non-`active` state, or an elapsed `absolute_expires_at_ms`; ask the user for a new handoff instead of changing account, device, or path.

Use the official `rdev-agent.py ssh`, `scp-to`, `scp-from`, and `drive` commands for long-running child processes. They maintain heartbeat and renewal in the background without restarting a healthy child process. A maintenance failure stops the child and returns nonzero; do not hide that result or start an unmanaged replacement command.

For an unattended port forward, put every forwarding rule in an explicit Agent option before `--no-command`:

```bash
python3 rdev-agent.py ssh --local-forward '127.0.0.1:8080:127.0.0.1:80' --no-command
python3 rdev-agent.py ssh --remote-forward '127.0.0.1:3000:127.0.0.1:3000' --no-command
```

Repeat either forwarding option to open more than one rule. The Agent sets OpenSSH `ExitOnForwardFailure=yes`; a zero exit code therefore never means that a requested listener silently failed to bind. Do not place raw `-L`, `-R`, or `-N` after the device target through the remote-command argument.

## Choose The Data Plane

Use `data.session.selected_transport` from heartbeat or renewal, or `data.credentials.agent_session.selected_transport` from redemption:

- `sftp`: transfer directly through RDev using the exact device ID and current `sshPort`.
- `cloud`: use the session transfer endpoints below so the device exchanges file bytes directly with the artifact provider.
- `not_selected`: no workload was supplied; send a heartbeat with measured workload before choosing.

Run `python3 tools/feidu-drive.py capabilities` before direct developer API operations. Resolve cloud objects only by the returned `content_id`; never infer identity from a name, path, hash, size, case, or similar object.

Create or resume a cloud transfer with `POST https://pan.feidu.fit/agent/v1/sessions/{agent_session_id}/transfers`. Use a canonical lowercase UUID as `transfer_id` and one exact direction:

- `cloud_to_device`: send `transfer_id`, `direction`, `source_content_id`, `destination_parent_path`, `file_name`, and `size_bytes`.
- `device_to_cloud`: send `transfer_id`, `direction`, `source_path`, `file_name`, and `size_bytes`.

Read status with `GET /agent/v1/sessions/{agent_session_id}/transfers/{transfer_id}`. Pause, resume, or cancel by appending `/pause`, `/resume`, or `/cancel` and sending `POST`. Keep the same `transfer_id` across retries. Do not proxy signed URLs or file bytes through the Agent when this cloud path is selected.

Prefer one `rdev-agent.py transfer create ... --wait` invocation for unattended work. Waiting maintains the renewable session, reports only state changes or 5% progress boundaries, and automatically resumes a failed transfer at most 2 times. Use `--auto-resume-attempts 0` when the requested operation must stop at the first failure. Do not build a manual high-frequency polling loop around the status endpoint.

Treat `failed` and `cancelled` as nonzero terminal results. Only `completed` proves that an unattended transfer command succeeded.

For direct SFTP and any local staging, compare size and SHA-256 before and after each hop. For cloud transfers, require the terminal transfer state and the service/device integrity result; an HTTP 200 from a control request alone is not completion.

## Secrets And References

Never persist or echo the claim, Cookie, signed download URL, or upload URL. The official `rdev-agent.py` may persist the renewal token, RDev ticket, and developer token only in its protected local state: current-user DPAPI on Windows or a mode `0600` file on Unix. Do not place any secret in repositories, shell history, task descriptions, logs, screenshots, or AI memory.

Read [the artifact bridge guide](https://r.feidu.fit/docs/ai-agent-artifact-bridge.md) for detailed file workflows and [the machine-readable manifest](https://r.feidu.fit/docs/ai-agent-manifest.json) for current protocol fields. Exact source definitions override these documents when developing the product itself.
