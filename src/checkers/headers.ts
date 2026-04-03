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

  // CORS with credentials + wildcard
  for (const file of files) {
    const regex = /credentials.*true.*origin.*\*|origin.*\*.*credentials.*true/is;
    const match = regex.exec(file.content);
    if (match) {
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
  }

  return findings;
}
