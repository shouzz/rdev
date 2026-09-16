# RDev Agent Instructions

Read `skills/rdev-agent/SKILL.md` for device operations and `docs/ai-agent-artifact-bridge.md` / `docs/ai-agent-manifest.json` for file-transfer protocol details.

## Permanent access is the default

- Import the authorization page's exact seven-field `rdev-device-access.v1` once using `rdev-agent.py --import-clipboard` on Windows or a protected stdin channel with `--import-stdin` on Unix.
- Do not put the copied JSON or Token in chat, process arguments, URLs, logs, source, screenshots or persistent AI memory. The tool saves current-user DPAPI on Windows or mode `0600` on Unix and automatically loads the entry by device ID.
- Use `--device EXACT-ID` when multiple devices are saved. Both the device ID and SSH endpoint come from the copied access, not names, guesses or `/api/clients`.
- The one fixed `fdpat_` supplies SSH/SFTP/SCP and `FEIDU_DRIVE_TOKEN`. No claim, heartbeat or renewal is required. Closing a task never revokes permanent authorization.
- A device or server restart, new AI session or network error does not expire the Token. Preserve saved access, inspect the real failure and continue the authorized business task. Never replay an uncertain remote write automatically.
- `status` confirms local saved metadata only. Verify the endpoint and returned device identity for live work; report actual health and completion evidence.

## File transfers

Use `rdev-agent.py drive` for Feidu developer operations; it loads the saved API endpoint and Token. The public `tools/feidu-drive.py` must remain content-equivalent to the repository tool.

Use exact returned `content_id` values for cloud objects. For uploads retain one `operation_id`, concurrency 1 and the original `session_id` during recovery; only HTTP 200 or 409 confirms a part. Do not forward Authorization to signed storage URLs.

Prefer SFTP for direct device transfers, with size and hash checks for local staging. Modern SCP uses SFTP; do not force `-O`.

For files larger than `104857600` bytes, the product's automatic cloud transfer uses `/developer/v1/rdev/transfers` and the fixed Token. Account, device and root are derived server-side. Keep the original transfer UUID through pause/resume/recovery. Internal `fdtx_` credentials and signed URLs are server/device concerns and must never reach AI state. Resume handles the internal 24-hour task deadline without a new claim.

Only explicit legacy temporary handoffs use the separate `start` / AgentSession path. Never apply their expiry or revocation rules to permanent device access.

## Delivery evidence

Relevant local tests and actual transfer integrity evidence are distinct. Deployment claims require actual service status, public endpoints, device reconnect and tested operations; an HTTP 200 page alone does not establish working SSH or transfer. Preserve a concrete rollback artifact when deploying. Do not require unrelated tests or additional user approvals for work already authorized.
