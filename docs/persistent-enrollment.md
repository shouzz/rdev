# Persistent installation with duplicate computer names

The 2026-09-08 field screenshots show two separate computers with the same hostname. The old persistent launchers always sent `--replace-existing`: a different enrollment owner caused HTTP 409, while the same owner could replace the first computer and disconnect it. A hostname is not proof of device identity.

Both launchers now perform fresh enrollment without replacement. The existing server allocates an unused ID (`HOST`, `HOST-2`, etc.) under its registry lock. Windows stores that exact identity using current-user DPAPI; Linux keeps the protected identity file. Repeating persistent installation reuses the saved identity without redeeming another invitation. Windows leaves an already running installation alone; a stopped installation starts again and its login startup entry is restored. Linux restores/enables the systemd service and verifies it is active.

Each new computer still needs a separate valid invitation. Consumed or expired invitations return HTTP 401. The explicit advanced-client replacement API remains available with its existing owner/revocation checks; the public installers do not invoke it. Existing field device records are preserved, since similar names cannot prove that records belong to the same physical machine.

Windows enrollment captures native output as plain text. PowerShell 5.1/.NET Framework stdin can prepend a UTF-8 BOM at process creation; the launcher temporarily selects BOM-free input encoding, restores the caller's encoding, and writes the invitation bytes explicitly. This avoids introducing a spurious 401 and keeps native diagnostics out of PowerShell's ErrorRecord formatting path. The screenshot's separate console formatter exception was not reproduced on the field machine.

## Verification

- Server regression tests: same hostname under the same and different owners receives distinct identities; original credential and connected transport remain valid. Existing explicit replacement/revocation/replay tests also pass.
- Full Go tests and `go vet`; onboarding browser tests; POSIX launcher syntax check.
- `scripts/test-persistent-enrollment.ps1`, run with Windows PowerShell 5.1 against a real isolated RDev server and the exact published Windows client (SHA-256 `9a72a3dfa04696a2b2b67f13a51daa533c8dc4757dd2d92b962576d298185abd`). Three independent installation directories with the same requested hostname connect simultaneously (two same-owner, one different-owner). Repetition preserves process IDs, protected identity bytes, device count and unused invitation. Stopping and repeating reconnects under the original identity, even with a consumed invitation. A new installation with a consumed invitation fails without creating identity/startup or interrupting the three clients.

The integration test redirects startup folders and uses an isolated registry; it removes its processes and protected runtime secrets afterward. It does not install a startup entry for the developer's real user profile. The two physical field PCs still need to execute the refreshed installer; their post-update operation cannot be inferred from this isolated test.
