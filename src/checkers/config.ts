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
  // #13 Hardcoded admin credentials
  {
    name: "Hardcoded admin credentials",
    regex: /(?:username|user)\s*===?\s*["']admin["'].*(?:password|pass)|(?:password|pass)\s*===?\s*["'][^"']+["']/i,
    severity: "CRITICAL",
    description: "Захардкоженные логин/пароль в коде — backdoor для любого кто прочитает исходник.",
    fix: "Удалить все hardcoded credentials. Создать admin через seeding скрипт с паролем из env.",
  },
  // #14 Unprotected admin endpoints
  {
    name: "Незащищённые admin эндпоинты",
    regex: /(?:router|app)\.(?:get|post|put|delete)\s*\(\s*["']\/api\/admin/i,
    severity: "CRITICAL",
    description: "Admin эндпоинты без auth middleware доступны любому знающему URL.",
    fix: "Добавить auth middleware на все /admin/* роуты. Проверять роль пользователя на сервере.",
  },
  // #33 Verbose error messages
  {
    name: "Stack trace в ответе клиенту",
    regex: /res\.(?:json|send)\s*\(\s*(?:err|error)(?:\.stack|\.message)?/i,
    severity: "HIGH",
    description: "Отправка stack trace клиенту раскрывает внутреннюю структуру приложения, пути к файлам, версии библиотек.",
    fix: "В продакшне — generic 'Internal server error'. Stack trace только в серверных логах.",
  },
  // #44 Sensitive data in URL params
  {
    name: "Секреты в URL параметрах",
    regex: /\?.*(?:token|apikey|api_key|secret|password)=/i,
    severity: "HIGH",
    description: "Секреты в URL логируются серверами, прокси, браузером. Утекают через Referer header.",
    fix: "Токены — только в теле POST запроса или Authorization header, не в URL.",
  },
  // #22 Mass assignment
  {
    name: "Mass assignment",
    regex: /\.(?:update|create)\s*\(\s*req\.body\s*\)/i,
    severity: "CRITICAL",
    description: "Передача req.body напрямую в update/create позволяет пользователю изменить любые поля, включая isAdmin, balance и т.д.",
    fix: "Явно указывать разрешённые поля: Model.update({ name: req.body.name, email: req.body.email })",
  },
  // #82 Hardcoded localhost
  {
    name: "Hardcoded localhost URL",
    regex: /["']https?:\/\/localhost:\d+/,
    severity: "LOW",
    description: "Захардкоженный localhost в продакшн коде — запросы будут падать.",
    fix: "Использовать process.env.API_URL или relative URLs.",
  },
  // #84 TODO security
  {
    name: "TODO с упоминанием security",
    regex: /\/\/\s*(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:auth|security|validation|sanitiz|encrypt|hash|password|token|secret)/i,
    severity: "LOW",
    description: "AI оставил TODO вместо реальной реализации security-функции. Это дыра.",
    fix: "Реализовать или завести задачу в трекере. Не оставлять security TODO в продакшне.",
  },
  // #85 Weak crypto
  {
    name: "Устаревший алгоритм шифрования",
    regex: /createCipher(?:iv)?\s*\(\s*["'](?:des|rc4|aes-128-ecb|aes-256-ecb)/i,
    severity: "LOW",
    description: "DES, RC4, AES-ECB — небезопасные устаревшие алгоритмы.",
    fix: "Использовать AES-256-GCM для симметричного шифрования.",
  },
  // #49 Prototype pollution
  {
    name: "Prototype pollution",
    regex: /(?:merge|extend|assign|deepMerge)\s*\([^)]*req\.(?:body|query|params)/i,
    severity: "HIGH",
    description: 'Мердж пользовательского ввода может привести к prototype pollution через __proto__ или constructor.prototype.',
    fix: "Фильтровать __proto__, constructor, prototype из пользовательского ввода. Использовать Object.create(null).",
  },
  // #58 System prompt in client code
  {
    name: "System prompt в клиентском коде",
    regex: /(?:system|role)\s*:\s*["'](?:You are|Act as|I want you to)/i,
    severity: "MEDIUM",
    description: "Системный промпт AI виден в JS бандле. Раскрывает бизнес-логику и инструкции.",
    fix: "Все AI-запросы только через свой бэкенд. System prompt хранить на сервере.",
  },
  // #68 Long-lived JWT
  {
    name: "Долгоживущий JWT",
    regex: /expiresIn\s*:\s*["'](?:\d+[dy]|[3-9]\d+h|[1-9]\d{2,}h)/i,
    severity: "MEDIUM",
    description: "JWT с долгим сроком жизни (дни, годы) — украденный токен работает очень долго, нет способа его отозвать.",
    fix: "Access token: 15-60 минут. Refresh token: 7-30 дней, хранить в БД.",
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
      const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : pattern.regex.flags + "g");
      let match;
      while ((match = globalRegex.exec(file.content)) !== null) {
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
  }

  return findings;
}
