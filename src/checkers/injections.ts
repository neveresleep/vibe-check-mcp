import type { FileEntry, Finding } from "../types.js";
import { makeId, isTestFile, lineNumber, snippetAt } from "../utils.js";

const CODE_EXTENSIONS = /\.(js|ts|jsx|tsx|py|go|rb|php)$/;

interface InjectionPattern {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  description: string;
  fix: string;
}

const PATTERNS: InjectionPattern[] = [
  {
    name: "Command injection",
    regex: /(?:exec|execSync|spawn)\s*\(\s*["'].*\s*\+|child_process.*\+/i,
    severity: "CRITICAL",
    description: "Конкатенация строк в команде shell позволяет атакующему выполнить произвольные команды на сервере.",
    fix: "Передавать аргументы массивом: spawn('cmd', [arg1, arg2])",
  },
  {
    name: "Path traversal",
    regex: /(?:readFile|writeFile|readFileSync)\s*\([^)]*\+/i,
    severity: "CRITICAL",
    description: "Конкатенация в пути файла позволяет атакующему читать любые файлы через ../../../etc/passwd.",
    fix: "path.join(__dirname, 'uploads', path.basename(filename))",
  },
  {
    name: "SSRF",
    regex: /fetch\s*\(\s*(?:req\.|request\.query|req\.body|req\.params)/i,
    severity: "CRITICAL",
    description: "fetch() с URL от пользователя позволяет сканировать внутреннюю сеть и обращаться к метаданным облака.",
    fix: "Whitelist разрешённых доменов. Блокировать private IP ranges.",
  },
  {
    name: "XSS через innerHTML",
    regex: /\.innerHTML\s*=\s*(?!["'`])/,
    severity: "HIGH",
    description: "innerHTML с динамическими данными позволяет атакующему внедрить скрипты на страницу.",
    fix: "Использовать textContent для текста. DOMPurify.sanitize() для HTML.",
  },
  {
    name: "Open redirect",
    regex: /res\.redirect\s*\(\s*req\./i,
    severity: "HIGH",
    description: "Редирект по URL от пользователя позволяет перенаправить жертву на фишинговый сайт.",
    fix: "Whitelist допустимых URL для редиректа.",
  },
  // Template injection (backtick with user input)
  {
    name: "SQL template literal injection",
    regex: /\.query\s*\(\s*`[^`]*\$\{/i,
    severity: "CRITICAL",
    description: "Использование template literals в SQL запросах — та же SQL injection, только через backticks.",
    fix: "Использовать параметризованные запросы: db.query('SELECT ... WHERE id = $1', [id])",
  },
  // #20 Exposed .git
  {
    name: ".git доступен через web server",
    regex: /express\.static\s*\(\s*["']\.["']\s*\)|serveStatic\s*\(\s*["']\.["']/i,
    severity: "CRITICAL",
    description: "express.static('.') раздаёт все файлы включая .git — атакующий скачивает исходный код с историей.",
    fix: "Указывать конкретную папку: express.static('public'). Никогда не раздавать корень проекта.",
  },
  // dangerouslySetInnerHTML React
  {
    name: "dangerouslySetInnerHTML с user data",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    severity: "HIGH",
    description: "dangerouslySetInnerHTML в React вставляет HTML без санитизации. Если данные от пользователя — XSS.",
    fix: "Использовать DOMPurify.sanitize() перед вставкой: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(data) }}",
  },
];

export async function checkInjections(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!CODE_EXTENSIONS.test(file.path)) continue;
    if (isTestFile(file.path)) continue;

    for (const pattern of PATTERNS) {
      const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : pattern.regex.flags + "g");
      let match;
      while ((match = globalRegex.exec(file.content)) !== null) {
        findings.push({
          id: makeId("injections"),
          checker: "injections",
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
