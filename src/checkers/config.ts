import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import type { FileEntry, Finding } from "../types.js";
import { makeId, isTestFile, lineNumber, snippetAt } from "../utils.js";

interface ConfigPattern {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  description: string;
  fix: string;
}

const CODE_PATTERNS: ConfigPattern[] = [
  {
    name: "CORS wildcard",
    regex: /Access-Control-Allow-Origin['":\s]*\*/i,
    severity: "HIGH",
    description: "CORS с wildcard (*) разрешает запросы с любого домена. Это опасно если есть аутентификация.",
    fix: "Указать конкретный домен: cors({ origin: 'https://myapp.com' })",
  },
  {
    name: "Debug в продакшне",
    regex: /DEBUG\s*=\s*True|NODE_ENV\s*=\s*["']?development/i,
    severity: "MEDIUM",
    description: "Debug режим в продакшн конфигурации раскрывает stack traces и внутренние данные.",
    fix: "NODE_ENV=production, DEBUG=false в продакшн окружении.",
  },
  {
    name: "Логирование секретов",
    regex: /console\.log\s*\(.*(?:password|token|secret|key)/i,
    severity: "HIGH",
    description: "Секреты в логах могут попасть в системы мониторинга и стать доступны другим.",
    fix: "Удалить. Использовать структурированный logger с redact функцией.",
  },
  {
    name: "Открытые debug эндпоинты",
    regex: /(?:router|app)\.(?:get|post)\s*\(\s*["']\/(?:test|debug|seed|admin\/seed)/i,
    severity: "HIGH",
    description: "Debug и seed эндпоинты в продакшне позволяют атакующим получить доступ к данным или сбросить БД.",
    fix: "Удалить или закрыть auth middleware перед деплоем.",
  },
];

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function checkFilesystemConfig(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check .gitignore exists
  const gitignorePath = join(projectPath, ".gitignore");
  const hasGitignore = await fileExists(gitignorePath);

  if (!hasGitignore) {
    findings.push({
      id: makeId("config"),
      checker: "config",
      severity: "HIGH",
      title: ".gitignore отсутствует",
      description: "Без .gitignore легко случайно закоммитить секреты, node_modules и другие ненужные файлы.",
      fix: "Создать .gitignore с: .env node_modules .next dist build",
      file: ".gitignore",
      line: 0,
      snippet: "",
    });
    return findings;
  }

  // Check .env in .gitignore
  const envPath = join(projectPath, ".env");
  const hasEnv = await fileExists(envPath);

  if (hasEnv) {
    try {
      const gitignoreContent = await readFile(gitignorePath, "utf-8");
      const ignoresEnv = /^\.env(?:\*|\.local)?$/m.test(gitignoreContent) || gitignoreContent.includes(".env");
      if (!ignoresEnv) {
        findings.push({
          id: makeId("config"),
          checker: "config",
          severity: "HIGH",
          title: ".env не в .gitignore",
          description: "Файл .env существует, но не добавлен в .gitignore. Секреты могут попасть в git.",
          fix: "Добавить в .gitignore: .env .env.local .env.*.local",
          file: ".gitignore",
          line: 0,
          snippet: "",
        });
      }
    } catch {
      // ignore read errors
    }
  }

  return findings;
}

export async function checkConfig(files: FileEntry[], projectPath?: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (projectPath) {
    const fsFindings = await checkFilesystemConfig(projectPath);
    findings.push(...fsFindings);
  }

  for (const file of files) {
    if (isTestFile(file.path)) continue;

    for (const pattern of CODE_PATTERNS) {
      const match = pattern.regex.exec(file.content);
      if (!match) continue;

      findings.push({
        id: makeId("config"),
        checker: "config",
        severity: pattern.severity,
        title: pattern.name,
        description: pattern.description,
        fix: pattern.fix,
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  return findings;
}
