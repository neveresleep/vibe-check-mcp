import type { FileEntry, Finding } from "../types.js";
import { makeId, lineNumber, snippetAt } from "../utils.js";

/**
 * AI Agent & MCP security checks:
 * - Prompt injection in config files (.cursorrules, CLAUDE.md, etc.)
 * - MCP tool poisoning / suspicious descriptions
 * - Agent memory poisoning via hooks
 * - Dangerous agent config flags
 * - Source maps / artifact hygiene
 */

// Config files that agents read — potential prompt injection vectors
const AGENT_CONFIG_FILES = [
  ".cursorrules",
  "CLAUDE.md",
  "AGENTS.md",
  ".windsurfrules",
  ".github/copilot-instructions.md",
];

export async function checkAgent(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // #1 Prompt injection in agent config files
  for (const file of files) {
    const isAgentConfig = AGENT_CONFIG_FILES.some((name) =>
      file.path === name || file.path.endsWith("/" + name),
    );
    if (!isAgentConfig) continue;

    // Suspicious commands in agent configs
    const suspiciousPatterns = [
      { regex: /curl\s+.*\|.*(?:sh|bash)/gi, name: "curl pipe to shell" },
      { regex: /wget\s+/gi, name: "wget download" },
      { regex: /(?:rm\s+-rf|rmdir|del\s+\/)/gi, name: "destructive command" },
      { regex: /(?:base64\s+-d|eval\s*\()/gi, name: "encoded/eval execution" },
      { regex: /(?:nc\s+-|ncat|netcat)/gi, name: "netcat reverse shell" },
      { regex: /(?:chmod\s+\+x|chmod\s+777)/gi, name: "permission change" },
      { regex: /ignore\s+(?:previous|all|above)\s+instructions/gi, name: "prompt injection override" },
      { regex: /do\s+not\s+(?:tell|inform|alert)\s+the\s+user/gi, name: "hidden instruction" },
      { regex: /exfiltrate|steal|extract.*(?:key|token|secret|credential)/gi, name: "data exfiltration instruction" },
    ];

    for (const pattern of suspiciousPatterns) {
      let match;
      while ((match = pattern.regex.exec(file.content)) !== null) {
        findings.push({
          id: makeId("agent"),
          checker: "agent",
          severity: "CRITICAL",
          title: `Подозрительная команда в конфиге агента: ${pattern.name}`,
          description: `Файл ${file.path} содержит подозрительный паттерн (${pattern.name}). CVE-2025-59536 и CVE-2026-21852 показали что вредоносные конфиги агента могут выполнять произвольный код.`,
          fix: "Проверить содержимое файла вручную. Удалить подозрительные команды. Не клонировать непроверенные репозитории.",
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: snippetAt(file.content, match.index),
        });
      }
    }
  }

  // #7 MCP server tool poisoning — check .mcp.json
  const mcpConfigs = files.filter((f) =>
    f.path.endsWith(".mcp.json") || f.path.endsWith("mcp.json"),
  );
  for (const file of mcpConfigs) {
    // Check for suspicious commands in MCP server config
    const suspiciousMcp = [
      { regex: /curl|wget|nc\s|ncat|python\s+-c|node\s+-e/gi, name: "подозрительная команда в MCP" },
      { regex: /env\s+.*(?:KEY|TOKEN|SECRET|PASSWORD)/gi, name: "передача секретов в MCP сервер" },
    ];

    for (const pattern of suspiciousMcp) {
      let match;
      while ((match = pattern.regex.exec(file.content)) !== null) {
        findings.push({
          id: makeId("agent"),
          checker: "agent",
          severity: "CRITICAL",
          title: `MCP конфиг: ${pattern.name}`,
          description: "MCP сервер конфигурация содержит подозрительные команды. Вредоносный MCP сервер может красть данные, выполнять код от имени агента.",
          fix: "Проверить каждый MCP сервер вручную. Использовать только доверенные MCP серверы.",
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: snippetAt(file.content, match.index),
        });
      }
    }
  }

  // #8 Agent memory poisoning — hooks in .claude/ directory
  const claudeHooks = files.filter((f) =>
    f.path.includes(".claude/") && (f.path.endsWith(".json") || f.path.endsWith(".yml")),
  );
  for (const file of claudeHooks) {
    const hookRegex = /(?:curl|wget|nc\s|python|node\s+-e|sh\s+-c)/gi;
    let match;
    while ((match = hookRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("agent"),
        checker: "agent",
        severity: "HIGH",
        title: "Подозрительная команда в hooks агента",
        description: "Hook файлы в .claude/ выполняются автоматически. Вредоносный hook может красть данные при каждом запуске агента.",
        fix: "Проверить все hooks вручную. Удалить незнакомые команды.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  // #9 Artifact hygiene — source maps, dev files in production
  const npmignore = files.find((f) => f.path === ".npmignore");
  const packageJson = files.find((f) => f.path === "package.json");

  if (packageJson) {
    const isPublishable = /"name"\s*:/.test(packageJson.content) &&
      !/"private"\s*:\s*true/.test(packageJson.content);

    if (isPublishable && !npmignore) {
      findings.push({
        id: makeId("agent"),
        checker: "agent",
        severity: "MEDIUM",
        title: "Публикуемый пакет без .npmignore",
        description: "Без .npmignore source maps (.map), .ts исходники, тесты и конфиги могут попасть в npm пакет. В марте 2026 Claude Code CLI случайно включил 59.8 МБ source map.",
        fix: "Создать .npmignore с: *.map, *.ts (кроме .d.ts), __tests__, src/, .env*",
        file: "package.json",
        line: 0,
        snippet: "",
      });
    }

    if (npmignore) {
      if (!npmignore.content.includes(".map")) {
        findings.push({
          id: makeId("agent"),
          checker: "agent",
          severity: "HIGH",
          title: "Source map файлы не исключены из npm пакета",
          description: "*.map файлы раскрывают исходный TypeScript код. Claude Code CLI в марте 2026 утёк 512K строк через source map в npm.",
          fix: "Добавить *.map в .npmignore",
          file: ".npmignore",
          line: 0,
          snippet: "",
        });
      }
    }
  }

  // #10 Docker security — running as root, privileged
  const dockerFiles = files.filter((f) =>
    /Dockerfile$/i.test(f.path) || f.path.endsWith("docker-compose.yml") || f.path.endsWith("docker-compose.yaml"),
  );

  for (const file of dockerFiles) {
    // Dockerfile without USER directive
    if (/Dockerfile$/i.test(file.path)) {
      if (!/^USER\s+/m.test(file.content)) {
        findings.push({
          id: makeId("agent"),
          checker: "agent",
          severity: "HIGH",
          title: "Dockerfile без USER — контейнер запускается от root",
          description: "Контейнер работает от root по умолчанию. Если атакующий получает RCE — у него root-права в контейнере.",
          fix: "Добавить USER directive: USER node (или другой non-root user).",
          file: file.path,
          line: 0,
          snippet: "",
        });
      }
    }

    // privileged: true in docker-compose
    const privilegedRegex = /privileged\s*:\s*true/gi;
    let match;
    while ((match = privilegedRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("agent"),
        checker: "agent",
        severity: "CRITICAL",
        title: "Docker контейнер с privileged: true",
        description: "privileged: true даёт контейнеру полный доступ к хосту. Эквивалент root на хост-машине.",
        fix: "Убрать privileged: true. Использовать конкретные capabilities если нужно.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // Secrets directly in docker-compose
    const dockerSecretRegex = /(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*[:=]\s*["']?[A-Za-z0-9_-]{8,}/gi;
    while ((match = dockerSecretRegex.exec(file.content)) !== null) {
      // Skip if it's a reference to env var
      if (/\$\{/.test(file.content.slice(match.index - 5, match.index))) continue;

      findings.push({
        id: makeId("agent"),
        checker: "agent",
        severity: "HIGH",
        title: "Секрет захардкожен в Docker конфиге",
        description: "Секреты прямо в docker-compose.yml видны всем кто имеет доступ к репозиторию.",
        fix: "Использовать Docker secrets, .env файл (не в git), или переменные окружения из CI/CD.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  // .dockerignore check
  const hasDockerfile = dockerFiles.some((f) => /Dockerfile$/i.test(f.path));
  const hasDockerignore = files.some((f) => f.path === ".dockerignore");
  if (hasDockerfile && !hasDockerignore) {
    findings.push({
      id: makeId("agent"),
      checker: "agent",
      severity: "MEDIUM",
      title: "Dockerfile без .dockerignore",
      description: "Без .dockerignore в Docker образ попадут .env, node_modules, .git и другие ненужные файлы.",
      fix: "Создать .dockerignore с: .env, node_modules, .git, *.map, dist",
      file: "",
      line: 0,
      snippet: "",
    });
  }

  return findings;
}
