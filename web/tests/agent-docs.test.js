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

    expect(repository.schema).toBe("rdev.ai-agent-manifest.v7");
    expect(repository.default_authentication).toBe("permanent_device_token");
    expect(repository.permanent_access.schema).toBe("rdev-device-access.v1");
    expect(repository.permanent_access.fields).toEqual([
      "schema", "device_id", "rdev_base", "api_base", "ssh_host", "ssh_port", "token",
    ]);
    expect(repository.permanent_access.additional_fields).toBe(false);
    expect(repository.permanent_access.credentials).toEqual({
      ssh_password: "token", FEIDU_DRIVE_TOKEN: "token",
    });
    expect(repository.permanent_access.expiry).toBe("none");
    expect(repository.cloud_transfers.endpoints.create).toBe("POST /developer/v1/rdev/transfers");
    expect(repository.artifact_plane.download).toContain("GET /developer/v1/contents/{content_id}/download");
    expect(repository.artifact_plane.upload).toContain("POST /developer/v1/direct-upload-sessions/{session_id}/complete");
    expect(published).toEqual(repository);
    const embedded = JSON.parse(await readFile(
      resolve(root, "internal/server/static/docs/ai-agent-manifest.json"), "utf8",
    ));
    expect(embedded).toEqual(repository);
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
    expect(repositoryGuide).toContain("`operation_id`");
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
    expect(repositorySkill).toContain("rdev-device-access.v1");
    expect(repositorySkill).toContain("--import-clipboard");
    expect(repositorySkill).toContain("--import-stdin");
    expect(repositorySkill).not.toContain("Revoke it when the task is complete");
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
    expect(instructions).not.toContain("https://r.feidu.fit/api/clients");
  });

  test("launchers prefer the verified managed clients", async () => {
    const expectedRevision = "feidu-20260905-7be947e";
    const expectedWindowsHash =
      "9a72a3dfa04696a2b2b67f13a51daa533c8dc4757dd2d92b962576d298185abd";
    const expectedLinuxAMD64Hash =
      "f096771469099050590688ca663b947b5130951d00658f325b997744de2bc212";
    const expectedLinuxARM64Hash =
      "8041966da8428b4c32d92e62576b7009d09507c999070dfa1af5f35f58fb490b";
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
