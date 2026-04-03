import type { FileEntry, Finding } from "../types.js";
import { makeId, isTestFile, lineNumber, snippetAt } from "../utils.js";

const CODE_EXTENSIONS = /\.(js|ts|jsx|tsx|py|go|rb|php)$/;

interface AuthPattern {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  description: string;
  fix: string;
}

const PATTERNS: AuthPattern[] = [
  {
    name: "eval() с user input",
    regex: /eval\s*\(\s*(?:req\.|request\.|params\.|body\.|input)/i,
    severity: "CRITICAL",
    description: "eval() выполняет произвольный код. Если туда попадают данные от пользователя — это RCE (удалённое выполнение кода).",
    fix: "Заменить на JSON.parse() для данных. Никогда не eval() с внешними данными.",
  },
  {
    name: "SQL конкатенация",
    regex: /["']SELECT\s.+["']\s*\+/i,
    severity: "CRITICAL",
    description: "Строковая конкатенация в SQL запросе открывает дверь для SQL injection.",
    fix: 'Использовать параметризованные запросы: db.query("SELECT * FROM users WHERE id = $1", [id])',
  },
  {
    name: "Math.random() для токенов",
    regex: /Math\.random\(\).*(?:token|secret|key)|(?:token|secret|key).*Math\.random\(\)/i,
    severity: "HIGH",
    description: "Math.random() предсказуем и не подходит для генерации секретов или токенов.",
    fix: "crypto.randomBytes(32).toString('hex') в Node.js",
  },
  {
    name: "MD5 для паролей",
    regex: /md5\s*\(.*password|password.*md5/i,
    severity: "HIGH",
    description: "MD5 сломан для хеширования паролей — легко ломается brute force.",
    fix: "Использовать bcrypt.hash(password, 12) или argon2",
  },
  {
    name: "SHA1 для паролей",
    regex: /sha1\s*\(.*password|password.*sha1/i,
    severity: "HIGH",
    description: "SHA1 не подходит для хеширования паролей — слишком быстрый.",
    fix: "Использовать bcrypt или argon2 — специально созданы для паролей",
  },
  {
    name: "JWT без указания алгоритма",
    regex: /jwt\.verify\s*\(\s*\w+\s*,\s*\w+\s*\)(?!\s*,\s*\{)/,
    severity: "CRITICAL",
    description: "Без указания алгоритма атакующий может подменить alg на 'none' и обойти проверку подписи.",
    fix: "jwt.verify(token, secret, { algorithms: ['HS256'] })",
  },
  {
    name: "pickle.loads() (Python)",
    regex: /pickle\.loads?\s*\(/i,
    severity: "CRITICAL",
    description: "pickle выполняет произвольный код при десериализации. Если данные приходят извне — это RCE.",
    fix: "Заменить на json.loads(). pickle выполняет код при десериализации.",
  },
  {
    name: "Auth bypass",
    regex: /if\s*\(.*(?:skip.{0,10}auth|bypass.{0,10}auth|auth.{0,10}disabled)/i,
    severity: "CRITICAL",
    description: "Условное отключение аутентификации — частая дыра, особенно если флаг управляется через env или query param.",
    fix: "Удалить. Аутентификация должна работать одинаково в dev и prod.",
  },
  {
    name: "Client-side admin check",
    regex: /role\s*===?\s*["']admin["']|isAdmin\s*===?\s*true/i,
    severity: "MEDIUM",
    description: "Проверка роли на клиенте легко обходится через DevTools. Роли нужно проверять на сервере.",
    fix: "Проверять роли только на сервере. Frontend — только для отображения.",
  },
  {
    name: "Cookie без httpOnly",
    regex: /res\.cookie\s*\([^)]*\)/,
    severity: "MEDIUM",
    description: "Cookie без httpOnly доступна JavaScript-у, что позволяет красть сессии через XSS.",
    fix: "res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'strict' })",
  },
];

export async function checkAuth(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!CODE_EXTENSIONS.test(file.path)) continue;
    if (isTestFile(file.path)) continue;

    for (const pattern of PATTERNS) {
      const match = pattern.regex.exec(file.content);
      if (!match) continue;

      // For cookie check — skip if httpOnly is already set
      if (pattern.name === "Cookie без httpOnly") {
        const cookieBlock = file.content.slice(match.index, match.index + 200);
        if (/httpOnly\s*:\s*true/.test(cookieBlock)) continue;
      }

      findings.push({
        id: makeId("auth"),
        checker: "auth",
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
