import { describe, expect, test } from 'vitest';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');

describe('AI Agent artifact bridge', () => {
  test('repository and public manifests expose the exact integration contract', async () => {
    const repository = JSON.parse(await readFile(resolve(root, 'docs/ai-agent-manifest.json'), 'utf8'));
    const published = JSON.parse(await readFile(resolve(root, 'web/public/docs/ai-agent-manifest.json'), 'utf8'));

    expect(repository.schema).toBe('rdev.ai-agent-manifest.v2');
    expect(repository.handoff.redeem.url).toBe('https://pan.feidu.fit/agent/v1/handoffs/redeem');
    expect(repository.handoff.credential_fields.device_id).toBe('data.credentials.device_id');
    expect(repository.handoff.credential_fields.rdev_ticket).toBe('data.credentials.rdev_ticket.ticket');
    expect(repository.handoff.credential_fields.developer_token).toBe('data.credentials.developer_token.token');
    expect(repository.rdev.base_url).toBe('https://r.feidu.fit');
    expect(repository.artifact_plane.base_url).toBe('https://pan.feidu.fit');
    expect(repository.artifact_plane.token_env).toBe('FEIDU_DRIVE_TOKEN');
    expect(repository.artifact_plane.lifecycle).toEqual(['none', 'hide', 'archive']);
    expect(repository.rdev.verified_windows_scp.client_version).toBe('go/v0.2.118-feidu.1');
    expect(repository.rdev.verified_windows_scp.fallback_for_other_versions).toBe('sftp');
    expect(repository.artifact_plane.download).toContain('GET /developer/v1/contents/{content_id}/download');
    expect(repository.artifact_plane.upload).toContain('POST /developer/v1/direct-upload-sessions/{session_id}/complete');

    expect(published.schema).toBe(repository.schema);
    expect(published.rdev_base_url).toBe(repository.rdev.base_url);
    expect(published.artifact_base_url).toBe(repository.artifact_plane.base_url);
    expect(published.artifact_token_env).toBe(repository.artifact_plane.token_env);
    expect(published.handoff.credential_fields).toEqual(repository.handoff.credential_fields);
    expect(published.rdev_discovery).toEqual(['GET /api/config']);
    expect(published.verified_windows_scp).toEqual(repository.rdev.verified_windows_scp);
  });

  test('published guide and reference CLI match repository content', async () => {
    const repositoryGuide = await readFile(resolve(root, 'docs/ai-agent-artifact-bridge.md'), 'utf8');
    const publishedGuide = await readFile(resolve(root, 'web/public/docs/ai-agent-artifact-bridge.md'), 'utf8');
    const repositoryCLI = await readFile(resolve(root, 'tools/feidu-drive.py'));
    const publishedCLI = await readFile(resolve(root, 'web/public/tools/feidu-drive.py'));

    expect(publishedGuide.trimEnd()).toBe(repositoryGuide.trimEnd());
    expect(publishedCLI.toString('utf8').trimEnd()).toBe(repositoryCLI.toString('utf8').trimEnd());
    expect(repositoryGuide).toContain('`content_id`');
    expect(repositoryGuide).toContain('`FEIDU_DRIVE_TOKEN`');
    expect(repositoryGuide).toContain('`/api/config`');
    expect(repositoryGuide).toContain('`operation_id`');
    expect(repositoryGuide).toContain('`go/v0.2.118-feidu.1`');
    expect(repositoryGuide).toContain('`data.credentials.device_id`');
    expect(repositoryGuide).not.toContain('curl -fsS https://r.feidu.fit/api/clients');
  });

  test('agent assets do not contain literal credentials or signed URLs', async () => {
    const paths = [
      'AGENTS.md',
      'docs/ai-agent-artifact-bridge.md',
      'docs/ai-agent-manifest.json',
      'web/public/docs/ai-agent-artifact-bridge.md',
      'web/public/docs/ai-agent-manifest.json',
      'tools/feidu-drive.py',
      'web/public/tools/feidu-drive.py'
    ];
    const combined = (await Promise.all(paths.map(path => readFile(resolve(root, path), 'utf8')))).join('\n');

    expect(combined).not.toMatch(/Authorization:\s*Bearer\s+fdpat_[A-Za-z0-9_-]{8,}/);
    expect(combined).not.toMatch(/https:\/\/[^\s]+aliyundrive[^\s]+/i);
    expect(combined).not.toMatch(/upload_url\s*[=:]\s*["']https:\/\//i);
  });

  test('repository instructions route agents to the bridge contract', async () => {
    const instructions = await readFile(resolve(root, 'AGENTS.md'), 'utf8');
    expect(instructions).toContain('docs/ai-agent-artifact-bridge.md');
    expect(instructions).toContain('docs/ai-agent-manifest.json');
    expect(instructions).toContain('FEIDU_DRIVE_TOKEN');
    expect(instructions).toContain('https://r.feidu.fit/api/config');
    expect(instructions).toContain('data.credentials.device_id');
    expect(instructions).not.toContain('https://r.feidu.fit/api/clients');
  });

  test('Windows launchers prefer the verified SCP-capable client', async () => {
    const expectedHash = '049a369042f5a371b921fa3e99cb6a0406349b3e716463a380d1dc9310a69e2e';
    const powershell = await readFile(resolve(root, 'internal/server/static/run.ps1'), 'utf8');
    const shell = await readFile(resolve(root, 'internal/server/static/run.sh'), 'utf8');

    for (const launcher of [powershell, shell]) {
      expect(launcher).toContain('/local-release?asset=');
      expect(launcher).toContain('feidu-20260903-scp2');
      expect(launcher).toContain(expectedHash);
    }
  });
});
