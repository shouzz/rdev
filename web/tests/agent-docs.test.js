import { describe, expect, test } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");

describe("AI Agent artifact bridge", () => {
  test("repository and public manifests expose the exact integration contract", async () => {
    const repository = JSON.parse(
      await readFile(resolve(root, "docs/ai-agent-manifest.json"), "utf8"),
    );
    const published = JSON.parse(
      await readFile(
        resolve(root, "web/public/docs/ai-agent-manifest.json"),
        "utf8",
      ),
    );

    expect(repository.schema).toBe("rdev.ai-agent-manifest.v4");
    expect(repository.handoff.redeem.url).toBe(
      "https://pan.feidu.fit/agent/v1/handoffs/redeem",
    );
    expect(repository.handoff.claim_input).toBe("stdin_or_hidden_prompt");
    expect(repository.handoff.credential_fields.device_id).toBe(
      "data.credentials.device_id",
    );
    expect(repository.handoff.credential_fields.rdev_ticket).toBe(
      "data.credentials.rdev_ticket.ticket",
    );
    expect(repository.handoff.credential_fields.developer_token).toBe(
      "data.credentials.developer_token.token",
    );
    expect(repository.handoff.credential_fields.agent_session_id).toBe(
      "data.credentials.agent_session.agent_session_id",
    );
    expect(repository.handoff.credential_fields.renewal_token).toBe(
      "data.credentials.agent_session.renewal_token",
    );
    expect(repository.handoff.session_duration_hours).toEqual([2, 8, 24]);
    expect(repository.agent_session.endpoints.renew).toBe(
      "POST /agent/v1/sessions/{agent_session_id}/renew",
    );
    expect(repository.agent_session.renewal_token_policy).toBe(
      "stable_until_absolute_expiry_or_revoke",
    );
    expect(repository.agent_session.renewal_response).toBe("data.session");
    expect(repository.agent_session.credential_policy).toBe(
      "values_stable_expiry_extended_in_place",
    );
    expect(repository.agent_session.state_storage.windows).toBe(
      "current-user DPAPI",
    );
    expect(repository.rdev.base_url).toBe("https://r.feidu.fit");
    expect(repository.artifact_plane.base_url).toBe("https://pan.feidu.fit");
    expect(repository.artifact_plane.token_env).toBe("FEIDU_DRIVE_TOKEN");
    expect(repository.artifact_plane.lifecycle).toEqual([
      "none",
      "hide",
      "archive",
    ]);
    expect(repository.rdev.verified_windows_scp.client_version).toBe(
      "go/v0.2.121-feidu.15",
    );
    expect(
      repository.rdev.verified_windows_scp.fallback_for_other_versions,
    ).toBe("sftp");
    expect(repository.artifact_plane.download).toContain(
      "GET /developer/v1/contents/{content_id}/download",
    );
    expect(repository.artifact_plane.upload).toContain(
      "POST /developer/v1/direct-upload-sessions/{session_id}/complete",
    );
    expect(repository.rdev.managed_enrollment.code_prefix).toBe("rdeve_");
    expect(repository.bridge.automatic_threshold_bytes).toBe(104857600);
    expect(repository.bridge.automatic_large_file.transfer_states).toEqual([
      "queued",
      "running",
      "paused",
      "completed",
      "failed",
      "cancelled",
    ]);
    expect(repository.bridge.automatic_large_file.transfer_token_prefix).toBe(
      "fdtx_",
    );
    expect(repository.bridge.automatic_large_file.transfer_generation).toBe(
      "positive_uint64_monotonic_per_transfer",
    );
    expect(repository.bridge.automatic_large_file.dispatch_acceptance).toBe(
      "device_plan_and_running_progress_acknowledged",
    );
    expect(
      repository.bridge.automatic_large_file.client_acceptance_timeout_seconds,
    ).toBe(7);
    expect(
      repository.bridge.automatic_large_file.rdev_dispatch_ack_timeout_seconds,
    ).toBe(8);

    expect(published.schema).toBe(repository.schema);
    expect(published.rdev.base_url).toBe(repository.rdev.base_url);
    expect(published.artifact_plane.base_url).toBe(
      repository.artifact_plane.base_url,
    );
    expect(published.artifact_plane.token_env).toBe(
      repository.artifact_plane.token_env,
    );
    expect(published.handoff.credential_fields).toEqual(
      repository.handoff.credential_fields,
    );
    expect(published.rdev.discovery).toEqual(["GET /api/config"]);
    expect(published.rdev.verified_windows_scp).toEqual(
      repository.rdev.verified_windows_scp,
    );
  });

  test("published guide and reference CLI match repository content", async () => {
    const repositoryGuide = await readFile(
      resolve(root, "docs/ai-agent-artifact-bridge.md"),
      "utf8",
    );
    const publishedGuide = await readFile(
      resolve(root, "web/public/docs/ai-agent-artifact-bridge.md"),
      "utf8",
    );
    const repositoryCLI = await readFile(resolve(root, "tools/feidu-drive.py"));
    const publishedCLI = await readFile(
      resolve(root, "web/public/tools/feidu-drive.py"),
    );

    expect(publishedGuide.trimEnd()).toBe(repositoryGuide.trimEnd());
    expect(publishedCLI.toString("utf8").trimEnd()).toBe(
      repositoryCLI.toString("utf8").trimEnd(),
    );
    expect(repositoryGuide).toContain("`content_id`");
    expect(repositoryGuide).toContain("`FEIDU_DRIVE_TOKEN`");
    expect(repositoryGuide).toContain("`/api/config`");
    expect(repositoryGuide).toContain("`operation_id`");
    expect(repositoryGuide).toContain("`go/v0.2.121-feidu.15`");
    expect(repositoryGuide).toContain("`data.credentials.device_id`");
    expect(repositoryGuide).not.toContain(
      "curl -fsS https://r.feidu.fit/api/clients",
    );
  });

  test("published RDev Agent Skill matches the repository source", async () => {
    const repositorySkill = await readFile(
      resolve(root, "skills/rdev-agent/SKILL.md"),
      "utf8",
    );
    const publishedSkill = await readFile(
      resolve(root, "web/public/skills/rdev-agent/SKILL.md"),
      "utf8",
    );
    const embeddedSkill = await readFile(
      resolve(root, "internal/server/static/skills/rdev-agent/SKILL.md"),
      "utf8",
    );
    const repositoryScript = await readFile(
      resolve(root, "skills/rdev-agent/scripts/rdev-agent.py"),
      "utf8",
    );
    const publishedScript = await readFile(
      resolve(root, "web/public/skills/rdev-agent/scripts/rdev-agent.py"),
      "utf8",
    );
    const embeddedScript = await readFile(
      resolve(
        root,
        "internal/server/static/skills/rdev-agent/scripts/rdev-agent.py",
      ),
      "utf8",
    );

    expect(publishedSkill.trimEnd()).toBe(repositorySkill.trimEnd());
    expect(embeddedSkill.trimEnd()).toBe(repositorySkill.trimEnd());
    expect(publishedScript.trimEnd()).toBe(repositoryScript.trimEnd());
    expect(embeddedScript.trimEnd()).toBe(repositoryScript.trimEnd());
    expect(repositorySkill).toContain(
      "data.credentials.agent_session.renewal_token",
    );
    expect(repositorySkill).toContain("size_bytes");
    expect(repositorySkill).toContain("observed_bytes_per_second");
    expect(repositorySkill).toContain("/heartbeat");
    expect(repositorySkill).toContain("/renew");
    expect(repositorySkill).toContain("/transfers");
    expect(repositorySkill).toContain("--auto-resume-attempts 0");
  });

  test("agent assets do not contain literal credentials or signed URLs", async () => {
    const paths = [
      "AGENTS.md",
      "skills/rdev-agent/SKILL.md",
      "docs/ai-agent-artifact-bridge.md",
      "docs/ai-agent-manifest.json",
      "web/public/docs/ai-agent-artifact-bridge.md",
      "web/public/docs/ai-agent-manifest.json",
      "web/public/skills/rdev-agent/SKILL.md",
      "tools/feidu-drive.py",
      "web/public/tools/feidu-drive.py",
    ];
    const combined = (
      await Promise.all(
        paths.map((path) => readFile(resolve(root, path), "utf8")),
      )
    ).join("\n");

    expect(combined).not.toMatch(
      /Authorization:\s*Bearer\s+fdpat_[A-Za-z0-9_-]{8,}/,
    );
    expect(combined).not.toMatch(/https:\/\/[^\s]+aliyundrive[^\s]+/i);
    expect(combined).not.toMatch(/upload_url\s*[=:]\s*["']https:\/\//i);
  });

  test("repository instructions route agents to the bridge contract", async () => {
    const instructions = await readFile(resolve(root, "AGENTS.md"), "utf8");
    expect(instructions).toContain("docs/ai-agent-artifact-bridge.md");
    expect(instructions).toContain("docs/ai-agent-manifest.json");
    expect(instructions).toContain("FEIDU_DRIVE_TOKEN");
    expect(instructions).toContain("https://r.feidu.fit/api/config");
    expect(instructions).toContain("data.credentials.device_id");
    expect(instructions).not.toContain("https://r.feidu.fit/api/clients");
  });

  test("launchers prefer the verified managed clients", async () => {
    const expectedRevision = "feidu-20260905-7be947e";
    const expectedWindowsHash =
      "4e24cbfe56afb8a545ea0fae145c5ea4b3ad8adfeaadecfda3501f082604b1dd";
    const expectedLinuxAMD64Hash =
      "ed23f99383f87ff1fb66c4256f4550b8e669688be0898f4d06037eac8c4a6520";
    const expectedLinuxARM64Hash =
      "dd5d27376e7efc0d5b29a8e9fa37c79a4d605cc93056e99d2150c58744126a68";
    const powershell = await readFile(
      resolve(root, "internal/server/static/run.ps1"),
      "utf8",
    );
    const shell = await readFile(
      resolve(root, "internal/server/static/run.sh"),
      "utf8",
    );

    for (const launcher of [powershell, shell]) {
      expect(launcher).toContain("/local-release?asset=");
      expect(launcher).toContain(expectedRevision);
      expect(launcher).toContain(expectedWindowsHash);
    }
    expect(shell).toContain(expectedLinuxAMD64Hash);
    expect(shell).toContain(expectedLinuxARM64Hash);
    expect(shell).toContain("client_supports_managed_enrollment");
    expect(shell).toContain("Trying managed RDev client");
  });
});
