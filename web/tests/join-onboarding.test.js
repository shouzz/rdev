import { describe, expect, test } from 'vitest';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { JSDOM } from 'jsdom';

const root = resolve(import.meta.dirname, '../..');

describe('RDev browser onboarding', () => {
  test('join page emits non-interactive commands for both platforms and modes', async () => {
    const source = await readFile(resolve(root, 'internal/server/static/join.html'), 'utf8');

    expect(source).toContain("$env:RDEV_ENROLLMENT_CODE='");
    expect(source).toContain("RDEV_ENROLLMENT_CODE='");
    expect(source).toContain("const mode = state.mode === 'persistent' ? '-Persist' : '-Enroll'");
    expect(source).toContain("const mode = state.mode === 'persistent' ? '--persist' : '--enroll'");
    expect(source).toContain("RDev '${origin}' ${mode}");
    expect(source).toContain("'${origin}' ${mode}");
    expect(source).not.toContain('Read-Host');
  });

  test('launchers consume the enrollment environment variable before starting the client', async () => {
    const powershell = await readFile(resolve(root, 'internal/server/static/run.ps1'), 'utf8');
    const shell = await readFile(resolve(root, 'internal/server/static/run.sh'), 'utf8');

    expect(powershell).toContain('$EnrollmentCode = $env:RDEV_ENROLLMENT_CODE');
    expect(powershell).toContain('$env:RDEV_ENROLLMENT_CODE = $null');
    expect(shell).toContain('RDEV_ENROLLMENT_CODE="${RDEV_ENROLLMENT_CODE:-}"');
    expect(shell).toContain('if [ -n "$RDEV_ENROLLMENT_CODE" ]; then');
    expect(shell).toContain('RDEV_ENROLLMENT_CODE=""');
  });

  test('valid invitation renders an executable command without a second prompt', async () => {
    const source = await readFile(resolve(root, 'internal/server/static/join.html'), 'utf8');
    const invitation = `rdeve_${'a'.repeat(43)}`;
    const dom = new JSDOM(source, {
      url: `https://rdev.example/join#${invitation}`,
      runScripts: 'dangerously',
      pretendToBeVisual: true
    });

    const command = dom.window.document.getElementById('command').textContent;
    expect(command).toContain(`RDEV_ENROLLMENT_CODE='${invitation}'`);
    expect(command).toContain("RDev 'https://rdev.example' -Enroll");
    expect(command).not.toContain('Read-Host');
    dom.window.document.querySelector('[data-os="linux"]').click();
    expect(dom.window.document.getElementById('command').textContent).toContain(
      `RDEV_ENROLLMENT_CODE='${invitation}'`
    );
  });
});
