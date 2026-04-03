import type { FileEntry, Finding } from "../types.js";
import { makeId, lineNumber, snippetAt } from "../utils.js";

export async function checkHeaders(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check if project uses helmet
  const packageJson = files.find((f) => f.path === "package.json");
  const hasHelmet = packageJson ? /"helmet"/.test(packageJson.content) : false;

  // Check for helmet usage in code
  const hasHelmetUsage = files.some((f) => /app\.use\s*\(\s*helmet\s*\(/.test(f.content));

  if (packageJson && !hasHelmet) {
    findings.push({
      id: makeId("headers"),
      checker: "headers",
      severity: "MEDIUM",
      title: "Нет helmet()",
      description: "helmet автоматически выставляет security заголовки (X-Frame-Options, CSP, и др.). Без него браузер менее защищён.",
      fix: "npm install helmet, затем app.use(helmet())",
      file: "package.json",
      line: 0,
      snippet: "",
    });
  }

  if (packageJson && !hasHelmet && !hasHelmetUsage) {
    // Check for X-Frame-Options manually set
    const hasXFrame = files.some((f) => /X-Frame-Options/i.test(f.content));
    if (!hasXFrame) {
      findings.push({
        id: makeId("headers"),
        checker: "headers",
        severity: "MEDIUM",
        title: "Нет X-Frame-Options",
        description: "Без X-Frame-Options сайт можно встроить в iframe на фишинговом сайте (clickjacking).",
        fix: "res.setHeader('X-Frame-Options', 'DENY')",
        file: "",
        line: 0,
        snippet: "",
      });
    }
  }

  for (const file of files) {
    // CORS with credentials + wildcard
    const corsRegex = /credentials.*true.*origin.*\*|origin.*\*.*credentials.*true/gis;
    let match;
    while ((match = corsRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("headers"),
        checker: "headers",
        severity: "HIGH",
        title: "CORS с credentials и wildcard",
        description: "Нельзя использовать wildcard origin (*) вместе с credentials: true. Браузер заблокирует запросы, но неправильная конфигурация говорит о проблемах с CORS.",
        fix: "Нельзя использовать wildcard origin с credentials: true. Указать конкретный домен.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // #57 Weak CSP with unsafe-inline/unsafe-eval
    const cspRegex = /Content-Security-Policy.*(?:unsafe-inline|unsafe-eval)/gi;
    while ((match = cspRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("headers"),
        checker: "headers",
        severity: "MEDIUM",
        title: "Слабая Content-Security-Policy",
        description: "CSP с unsafe-inline или unsafe-eval фактически не защищает от XSS.",
        fix: "Убрать unsafe-inline, использовать nonces или hashes для inline скриптов.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // #66 Missing SRI on external scripts
    const sriRegex = /<script\s+src=["']https?:\/\/[^"']+["'][^>]*>/gi;
    while ((match = sriRegex.exec(file.content)) !== null) {
      if (!/integrity=/.test(match[0])) {
        findings.push({
          id: makeId("headers"),
          checker: "headers",
          severity: "MEDIUM",
          title: "Внешний скрипт без Subresource Integrity",
          description: "Внешний скрипт без integrity hash — если CDN взломан, вредоносный скрипт загрузится всем пользователям.",
          fix: 'Добавить integrity="sha384-..." атрибут для внешних скриптов.',
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: snippetAt(file.content, match.index),
        });
      }
    }

    // #89 Version disclosure
    const versionRegex = /X-Powered-By/i;
    const versionMatch = versionRegex.exec(file.content);
    if (versionMatch && !/disable.*x-powered-by|removeHeader.*X-Powered-By/i.test(file.content)) {
      findings.push({
        id: makeId("headers"),
        checker: "headers",
        severity: "LOW",
        title: "Version disclosure через X-Powered-By",
        description: "X-Powered-By раскрывает фреймворк и версию. Помогает атакующим искать CVE.",
        fix: "app.disable('x-powered-by') в Express. Или использовать helmet().",
        file: file.path,
        line: lineNumber(file.content, versionMatch.index),
        snippet: snippetAt(file.content, versionMatch.index),
      });
    }
  }

  return findings;
}
