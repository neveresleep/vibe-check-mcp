import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { join } from "node:path";
import type { Finding } from "../types.js";
import { makeId } from "../utils.js";

interface NpmAuditVuln {
  name: string;
  severity: string;
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean | { name: string; version: string };
}

function mapSeverity(s: string): Finding["severity"] {
  switch (s) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH";
    case "moderate": return "MEDIUM";
    default: return "LOW";
  }
}

export async function checkDependencies(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const lockPath = join(projectPath, "package-lock.json");
  try {
    await access(lockPath);
  } catch {
    // No lock file — can't run npm audit
    return findings;
  }

  try {
    const output = await new Promise<string>((resolve, reject) => {
      execFile(
        "npm",
        ["audit", "--json"],
        { cwd: projectPath, timeout: 30000 },
        (err, stdout) => {
          // npm audit exits with non-zero when vulns found
          if (stdout) resolve(stdout);
          else reject(err);
        },
      );
    });

    const result = JSON.parse(output);
    const vulns: Record<string, NpmAuditVuln> = result.vulnerabilities ?? {};

    for (const [name, vuln] of Object.entries(vulns)) {
      if (vuln.severity === "info") continue;

      const fixInfo = typeof vuln.fixAvailable === "object"
        ? `Обновить ${vuln.fixAvailable.name} до ${vuln.fixAvailable.version}`
        : vuln.fixAvailable
          ? "npm audit fix"
          : "Проверить альтернативные пакеты";

      findings.push({
        id: makeId("dependencies"),
        checker: "dependencies",
        severity: mapSeverity(vuln.severity),
        title: `Уязвимый пакет: ${name}`,
        description: `${vuln.title}. Подробнее: ${vuln.url}`,
        fix: fixInfo,
        file: "package.json",
        line: 0,
        snippet: `${name} (${vuln.range})`,
      });
    }
  } catch {
    // npm audit failed — skip silently
  }

  return findings;
}
