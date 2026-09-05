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

  test("advanced-only endpoints retain the branded HTTPS control plane", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const shell = await readFile(
      resolve(root, "internal/server/static/run.sh"),
      "utf8",
    );

    expect(powershell).toContain(
      "$script:DefaultControlBase = 'https://r.feidu.fit'",
    );
    expect(powershell).toContain("return $script:DefaultControlBase");
    expect(powershell).toContain("function Add-RDevManagedControlEndpoint");
    expect(powershell).toContain('$ClientServer = if ($ManagedEnrollment)');
    expect(shell).toContain('DEFAULT_CONTROL_BASE="https://r.feidu.fit"');
    expect(shell).toContain('echo "$DEFAULT_CONTROL_BASE"; return 0');
    expect(shell).toContain("managed_server_list()");
    expect(shell).toContain('RDEV_CLIENT_SERVER="$(managed_server_list)"');
  });

  test("managed downloads validate every source before acceptance", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const shell = await readFile(
      resolve(root, "internal/server/static/run.sh"),
      "utf8",
    );

    expect(powershell).toContain("function Test-RDevDownloadedPackage");
    expect(powershell).toContain(
      "Test-RDevDownloadedPackage $OutPath $PackageKind $Asset $ManagedEnrollment",
    );
    expect(shell).toContain("download_is_acceptable()");
    expect(shell).toContain('managed_client_expected_sha256()');
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
      "'--enroll-stdin'",
      supportFunction,
    );
    const identityFlag = powershell.indexOf(
      "'--identity-file'",
      supportFunction,
    );
    const replaceFlag = powershell.indexOf(
      "'--replace-existing'",
      supportFunction,
    );
    const releaseFallback = powershell.indexOf(
      "$ReleaseUrl = Get-RDevReleaseUrl $Server $Asset $Tag",
    );
    const verifiedCapabilityGate = powershell.indexOf(
      "Test-RDevVerifiedManagedEnrollmentClient $RunPath $Asset",
    );
    const finalCapabilityProbe = powershell.indexOf(
      "Test-RDevManagedEnrollmentSupport $RunPath",
      verifiedCapabilityGate,
    );
    const failure = powershell.indexOf(
      'Write-Error "Managed enrollment is unavailable because $Reason."',
      finalCapabilityProbe,
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
    expect(verifiedCapabilityGate).toBeGreaterThan(releaseFallback);
    expect(finalCapabilityProbe).toBeGreaterThan(verifiedCapabilityGate);
    expect(failure).toBeGreaterThan(finalCapabilityProbe);
    expect(consumeInvitation).toBeGreaterThan(failure);
    expect(createStartupDirectory).toBeGreaterThan(consumeInvitation);
  });

  test("Windows trusts the exact published client hash without executing a capability probe", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const verifier = powershell.indexOf(
      "function Test-RDevVerifiedManagedEnrollmentClient",
    );
    const assetGate = powershell.indexOf(
      "$Asset -ne $script:LocalWindowsAMD64Asset",
      verifier,
    );
    const hashGate = powershell.indexOf(
      "(Get-RDevSHA256 $Path) -eq $script:LocalWindowsAMD64SHA256",
      assetGate,
    );
    const finalGate = powershell.lastIndexOf(
      "Test-RDevVerifiedManagedEnrollmentClient $RunPath $Asset",
    );
    const fallbackProbe = powershell.indexOf(
      "Test-RDevManagedEnrollmentSupport $RunPath",
      finalGate,
    );

    expect(verifier).toBeGreaterThan(-1);
    expect(assetGate).toBeGreaterThan(verifier);
    expect(hashGate).toBeGreaterThan(assetGate);
    expect(finalGate).toBeGreaterThan(hashGate);
    expect(fallbackProbe).toBeGreaterThan(finalGate);
  });

  test("Windows capability probing reports distinct execution failures", async () => {
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );

    expect(powershell).toContain("the downloaded client file is missing");
    expect(powershell).toContain(
      "the downloaded client process did not start",
    );
    expect(powershell).toContain(
      "the downloaded client timed out while reporting its capabilities",
    );
    expect(powershell).toContain(
      "the downloaded client capability check exited with code",
    );
    expect(powershell).toContain(
      "the downloaded client is missing required option(s):",
    );
    expect(powershell).toContain(
      "the downloaded client could not be started:",
    );
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
