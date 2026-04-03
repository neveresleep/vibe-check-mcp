#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";
import type { Finding, ScanResult, FileEntry } from "./types.js";
import { collectFiles } from "./files.js";
import { checkSecrets } from "./checkers/secrets.js";
import { checkAuth } from "./checkers/auth.js";
import { checkConfig } from "./checkers/config.js";
import { checkInjections } from "./checkers/injections.js";
import { checkHeaders } from "./checkers/headers.js";
import { checkDependencies } from "./checkers/dependencies.js";
import { checkSupabase } from "./checkers/supabase.js";

const CHECKER_MAP: Record<string, (files: FileEntry[], projectPath?: string) => Promise<Finding[]>> = {
  secrets: (files) => checkSecrets(files),
  auth: (files) => checkAuth(files),
  config: (files, path) => checkConfig(files, path),
  injections: (files) => checkInjections(files),
  headers: (files) => checkHeaders(files),
  supabase: (files) => checkSupabase(files),
};

const ALL_CHECKERS = Object.keys(CHECKER_MAP);

async function runScan(
  projectPath: string,
  checkers: string[],
  severityFilter?: string,
): Promise<ScanResult> {
  const absPath = resolve(projectPath);
  const files = await collectFiles(absPath);
  let findings: Finding[] = [];

  // Run static checkers
  for (const name of checkers) {
    const checker = CHECKER_MAP[name];
    if (checker) {
      const results = await checker(files, absPath);
      findings.push(...results);
    }
  }

  // Run dependencies checker if requested
  if (checkers.includes("dependencies")) {
    const depFindings = await checkDependencies(absPath);
    findings.push(...depFindings);
  }

  // Apply severity filter
  if (severityFilter && severityFilter !== "all") {
    const upper = severityFilter.toUpperCase();
    findings = findings.filter((f) => f.severity === upper);
  }

  // Deduplicate by file + title
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const key = `${f.file}:${f.title}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const summary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
    scanned_files: files.length,
  };

  return { summary, findings };
}

// --- MCP Server ---

const server = new McpServer({
  name: "vibe-check-mcp",
  version: "0.1.0",
});

server.tool(
  "scan_project",
  "Сканирует проект на уязвимости безопасности. Находит секреты, проблемы аутентификации, небезопасные конфигурации, инъекции и уязвимые зависимости.",
  {
    path: z.string().default(".").describe("Путь к проекту"),
    severity: z
      .enum(["critical", "high", "medium", "low", "all"])
      .optional()
      .describe("Фильтр по severity"),
    checkers: z
      .array(z.string())
      .optional()
      .describe("Какие checkers запускать: secrets, auth, config, injections, headers, supabase, dependencies"),
  },
  async ({ path, severity, checkers }) => {
    const activeCheckers = checkers?.length
      ? checkers
      : [...ALL_CHECKERS, "dependencies"];
    const result = await runScan(path, activeCheckers, severity);

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
    };
  },
);

server.tool(
  "scan_file",
  "Сканирует один файл на уязвимости.",
  {
    path: z.string().describe("Путь к файлу"),
  },
  async ({ path: filePath }) => {
    const absPath = resolve(filePath);
    let content: string;
    try {
      content = await readFile(absPath, "utf-8");
    } catch {
      return {
        content: [{ type: "text" as const, text: `Ошибка: не удалось прочитать файл ${filePath}` }],
        isError: true,
      };
    }

    const file: FileEntry = { path: filePath, content };
    const files = [file];

    let findings: Finding[] = [];
    for (const checker of Object.values(CHECKER_MAP)) {
      const results = await checker(files);
      findings.push(...results);
    }

    // Deduplicate
    const seen = new Set<string>();
    findings = findings.filter((f) => {
      const key = `${f.file}:${f.title}:${f.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(findings, null, 2) }],
    };
  },
);

server.tool(
  "check_secrets",
  "Проверяет проект только на утечки секретов и API ключей.",
  {
    path: z.string().default(".").describe("Путь к проекту"),
  },
  async ({ path }) => {
    const result = await runScan(path, ["secrets"]);

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
    };
  },
);

server.tool(
  "explain_finding",
  "Подробное объяснение уязвимости с примером фикса.",
  {
    finding: z.object({
      id: z.string(),
      checker: z.string(),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
      title: z.string(),
      description: z.string(),
      fix: z.string(),
      file: z.string(),
      line: z.number(),
      snippet: z.string(),
    }),
  },
  async ({ finding }) => {
    const severity_emoji: Record<string, string> = {
      CRITICAL: "🔴",
      HIGH: "🟠",
      MEDIUM: "🟡",
      LOW: "🔵",
    };

    const explanation = `${severity_emoji[finding.severity] ?? ""} **${finding.title}** [${finding.severity}]

**Файл:** ${finding.file}${finding.line ? `:${finding.line}` : ""}

**Что происходит:**
${finding.description}

**Как исправить:**
${finding.fix}

${finding.snippet ? `**Код:**\n\`\`\`\n${finding.snippet}\n\`\`\`` : ""}`;

    return {
      content: [{ type: "text" as const, text: explanation }],
    };
  },
);

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
