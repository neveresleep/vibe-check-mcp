import type { FileEntry, Finding } from "../types.js";
import { makeId, redactSecret, isTestFile, lineNumber, snippetAt } from "../utils.js";

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  fix: string;
}

const PATTERNS: SecretPattern[] = [
  {
    name: "Supabase service role key",
    regex: /supabase[_-]?service[_-]?role[_-]?key\s*[=:]\s*["']?(eyJ[A-Za-z0-9_-]{20,})/i,
    severity: "CRITICAL",
    fix: "Перенести в env var SUPABASE_SERVICE_ROLE_KEY. Использовать только на сервере.",
  },
  {
    name: "OpenAI API key",
    regex: /sk-(?:proj-)?[A-Za-z0-9]{20,}/,
    severity: "CRITICAL",
    fix: "Отозвать на platform.openai.com/api-keys. Хранить в OPENAI_API_KEY env var.",
  },
  {
    name: "Anthropic API key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/,
    severity: "CRITICAL",
    fix: "Отозвать на console.anthropic.com. Хранить в ANTHROPIC_API_KEY env var.",
  },
  {
    name: "Stripe secret key",
    regex: /sk_live_[A-Za-z0-9]{24,}/,
    severity: "CRITICAL",
    fix: "Только на сервере. sk_live_ никогда не на фронтенде.",
  },
  {
    name: "GitHub PAT",
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/,
    severity: "CRITICAL",
    fix: "Отозвать на github.com/settings/tokens.",
  },
  {
    name: "AWS Access Key",
    regex: /AKIA[0-9A-Z]{16}/,
    severity: "CRITICAL",
    fix: "Деактивировать в AWS IAM немедленно.",
  },
  {
    name: "Private key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: "CRITICAL",
    fix: "Отозвать сертификат. Удалить из git history через git filter-repo.",
  },
  {
    name: "Database URL с паролем",
    regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]{3,}@/i,
    severity: "CRITICAL",
    fix: "Использовать DATABASE_URL из env. Ротировать пароль БД.",
  },
  {
    name: "Hardcoded password",
    regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']/i,
    severity: "HIGH",
    fix: "Перенести в env vars или secrets manager.",
  },
  {
    name: "SendGrid API key",
    regex: /SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}/,
    severity: "CRITICAL",
    fix: "Ротировать в SendGrid Dashboard. Хранить в env.",
  },
  {
    name: "Stripe publishable key (info)",
    regex: /pk_live_[A-Za-z0-9]{24,}/,
    severity: "LOW",
    fix: "pk_live_ можно на фронтенде — это нормально. Убедись что sk_live_ скрыт.",
  },
];

export async function checkSecrets(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isTestFile(file.path)) continue;

    for (const pattern of PATTERNS) {
      const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : pattern.regex.flags + "g");
      let match;
      while ((match = globalRegex.exec(file.content)) !== null) {
        findings.push({
          id: makeId("secrets"),
          checker: "secrets",
          severity: pattern.severity,
          title: pattern.name,
          description: `Найден ${pattern.name} в файле ${file.path}. Секреты в коде — это риск утечки при публикации репозитория.`,
          fix: pattern.fix,
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: redactSecret(snippetAt(file.content, match.index)),
        });
      }
    }
  }

  return findings;
}
