import { describe, expect, test } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSDOM } from "jsdom";

const root = resolve(import.meta.dirname, "../..");

describe("RDev browser onboarding", () => {
  test("join page emits non-interactive commands for both platforms and modes", async () => {
    const source = await readFile(
      resolve(root, "internal/server/static/join.html"),
      "utf8",
    );

    expect(source).toContain(
      "[Environment]::SetEnvironmentVariable('RDEV_ENROLLMENT_CODE'",
    );
    expect(source).toContain("RDEV_ENROLLMENT_CODE='");
    expect(source).toContain(
      "const mode = state.mode === 'persistent' ? '-Persist' : '-Enroll'",
    );
    expect(source).toContain(
      "const mode = state.mode === 'persistent' ? '--persist' : '--enroll'",
    );
    expect(source).toContain("RDev '${origin}' ${mode}");
    expect(source).toContain("'${origin}' ${mode}");
    expect(source).not.toContain("Read-Host");
  });

  test("launchers consume the enrollment environment variable only after capability validation", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const shell = await readFile(
      resolve(root, "internal/server/static/run.sh"),
      "utf8",
    );

    expect(powershell).toContain("$EnrollmentCode = $env:RDEV_ENROLLMENT_CODE");
    expect(powershell).toContain("$env:RDEV_ENROLLMENT_CODE = $null");
    expect(
      powershell.indexOf("Test-RDevManagedEnrollmentSupport $RunPath"),
    ).toBeLessThan(
      powershell.indexOf("$EnrollmentCode = $env:RDEV_ENROLLMENT_CODE"),
    );
    expect(shell).toContain('RDEV_ENROLLMENT_CODE="${RDEV_ENROLLMENT_CODE:-}"');
    expect(shell).toContain('if [ -n "$RDEV_ENROLLMENT_CODE" ]; then');
    expect(shell).toContain('RDEV_ENROLLMENT_CODE=""');
    expect(shell).toContain("client_supports_managed_enrollment");
    expect(shell).toContain(
      "Downloaded client does not support managed enrollment.",
    );
    expect(powershell).toContain("'--replace-existing'");
    expect(shell).toContain("--enroll-only --replace-existing --identity-file");
  });

  test("Windows enrollment falls through when the verified local asset is missing", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const localAttempt = powershell.indexOf(
      "$LocalUrl = Get-RDevLocalReleaseUrl $Server $Asset",
    );
    const releaseFallback = powershell.indexOf(
      "$ReleaseUrl = Get-RDevReleaseUrl $Server $Asset $Tag",
    );
    const finalCapabilityGate = powershell.indexOf(
      "Test-RDevManagedEnrollmentSupport $RunPath",
    );

    expect(localAttempt).toBeGreaterThan(-1);
    expect(releaseFallback).toBeGreaterThan(localAttempt);
    expect(finalCapabilityGate).toBeGreaterThan(releaseFallback);
  });

  test("Windows enrollment rejects a changed local SHA before trying public sources", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const hashGate = powershell.indexOf(
      "$LocalHash -eq $script:LocalWindowsAMD64SHA256",
    );
    const rejectedLocalCleanup = powershell.indexOf(
      "if (-not $OK) { Remove-Item $OutPath -Force -EA SilentlyContinue }",
      hashGate,
    );
    const releaseFallback = powershell.indexOf(
      "$ReleaseUrl = Get-RDevReleaseUrl $Server $Asset $Tag",
    );

    expect(hashGate).toBeGreaterThan(-1);
    expect(rejectedLocalCleanup).toBeGreaterThan(hashGate);
    expect(releaseFallback).toBeGreaterThan(rejectedLocalCleanup);
  });

  test("Windows enrollment rejects an unsupported public fallback without consuming the invitation", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const supportFunction = powershell.indexOf(
      "function Test-RDevManagedEnrollmentSupport",
    );
    const enrollFlag = powershell.indexOf(
      "$Help.Contains('--enroll-stdin')",
      supportFunction,
    );
    const identityFlag = powershell.indexOf(
      "$Help.Contains('--identity-file')",
      supportFunction,
    );
    const replaceFlag = powershell.indexOf(
      "$Help.Contains('--replace-existing')",
      supportFunction,
    );
    const finalCapabilityGate = powershell.indexOf(
      "if (-not (Test-RDevManagedEnrollmentSupport $RunPath))",
    );
    const failure = powershell.indexOf(
      "Write-Error 'Downloaded client does not support managed enrollment.'",
      finalCapabilityGate,
    );
    const consumeInvitation = powershell.indexOf(
      "$EnrollmentCode = $env:RDEV_ENROLLMENT_CODE",
    );
    const createStartupDirectory = powershell.indexOf(
      "New-Item -ItemType Directory -Force -Path $InstallDir",
    );

    expect(enrollFlag).toBeGreaterThan(supportFunction);
    expect(identityFlag).toBeGreaterThan(enrollFlag);
    expect(replaceFlag).toBeGreaterThan(identityFlag);
    expect(failure).toBeGreaterThan(finalCapabilityGate);
    expect(consumeInvitation).toBeGreaterThan(failure);
    expect(createStartupDirectory).toBeGreaterThan(consumeInvitation);
  });

  test("valid invitation renders an executable command without a second prompt", async () => {
    const source = await readFile(
      resolve(root, "internal/server/static/join.html"),
      "utf8",
    );
    const invitation = `rdeve_${"a".repeat(43)}`;
    const dom = new JSDOM(source, {
      url: `https://rdev.example/join#${invitation}`,
      runScripts: "dangerously",
      pretendToBeVisual: true,
    });

    const command = dom.window.document.getElementById("command").textContent;
    expect(command).toContain(
      `[Environment]::SetEnvironmentVariable('RDEV_ENROLLMENT_CODE','${invitation}','Process')`,
    );
    expect(command).toContain("RDev 'https://rdev.example' -Enroll");
    expect(command).not.toContain("Read-Host");
    dom.window.document.querySelector('[data-os="linux"]').click();
    expect(dom.window.document.getElementById("command").textContent).toContain(
      `RDEV_ENROLLMENT_CODE='${invitation}'`,
    );
  });
});
