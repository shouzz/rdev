# RDev Agent Instructions

## Required reading

Before any device or artifact file-transfer task, read:

- `docs/ai-agent-artifact-bridge.md`
- `docs/ai-agent-manifest.json`

Use `tools/feidu-drive.py` for the Feidu developer API. The public copy at `https://r.feidu.fit/tools/feidu-drive.py` must remain content-equivalent to the repository copy.

## Exact discovery

1. Start from the handoff copied by an authenticated user at `https://pan.feidu.fit/rdev`.
2. Redeem its `fdhc_` claim once through the exact `redeem_path`. Require HTTP 200 and JSON `code == 0`.
3. Read the device ID only from `data.credentials.device_id`, the RDev credential only from `data.credentials.rdev_ticket.ticket`, and the Feidu token only from `data.credentials.developer_token.token`.
4. Read `https://r.feidu.fit/api/config` for the current RDev ports. Do not call the protected `/api/clients` endpoint; the exact device ID came from the redemption response.
5. Set the Feidu token as `FEIDU_DRIVE_TOKEN`, then call `python3 tools/feidu-drive.py capabilities` before cloud operations.
6. Use the returned `content_id`; never infer identity from names, paths, hashes, sizes, casing, or similar content.

Do not hard-code a previously observed device, port, upload session, cloud object, signed URL, or lifecycle state.

## Credential boundary

- Keep the `fdhc_` claim and redeemed credentials in process memory or protected runtime secret channels only. Clear the claim immediately after redemption.
- Inject the redeemed Feidu token through `FEIDU_DRIVE_TOKEN` at runtime.
- Never write claims, tokens, account passwords, RDev tickets, cookies, signed download URLs, or upload URLs to source files, logs, task descriptions, checkpoints, or persistent AI memory.
- Never forward the Feidu `Authorization` header to a redirected download host.
- The RDev ticket and Feidu developer token expire independently even though one handoff issues both.

## Transfer boundary

- RDev is the Device Plane: SSH, Exec, SFTP, SCP when its exact client version is verified, Rsync, port forwarding, remote desktop, and device file operations.
- Feidu is the Artifact Plane: scoped content browsing, downloads, sequential multipart uploads, session recovery, and lifecycle policy.
- Bridge the planes through a local staging file. Verify size and SHA-256 before and after the RDev hop.
- Default to SFTP for handoff-driven file transfer. Use SCP only when the exact connected client version is independently verified as the version named in the manifest.
- For Feidu uploads, keep one `operation_id`, concurrency 1, and the original `session_id` during recovery. Only HTTP 200 and 409 confirm a part.

## Completion gate

Do not report completion from an HTTP 200 page alone. A file-transfer change requires the relevant local tests plus a real transfer with size/hash verification. A production deployment also requires container status, restart count, `/api/config`, public endpoints, client reconnect, and a recorded rollback image/Compose file.
