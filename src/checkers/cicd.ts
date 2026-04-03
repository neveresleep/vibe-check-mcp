import type { FileEntry, Finding } from "../types.js";
import { makeId, lineNumber, snippetAt } from "../utils.js";

/**
 * CI/CD & GitHub Actions security checks:
 * - Unpinned GitHub Actions
 * - Secrets in workflow logs
 * - Dangerous flags
 * - Missing lock files
 */

export async function checkCicd(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  const workflowFiles = files.filter((f) =>
    f.path.includes(".github/workflows/") && /\.ya?ml$/.test(f.path),
  );

  for (const file of workflowFiles) {
    // #5 Unpinned GitHub Actions (uses: action@main instead of @v3.2.1 or @sha)
    const unpinnedRegex = /uses:\s*["']?([^@\s"']+)@(main|master|latest|dev)["']?/g;
    let match;
    while ((match = unpinnedRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("cicd"),
        checker: "cicd",
        severity: "CRITICAL",
        title: `Unpinned GitHub Action: ${match[1]}@${match[2]}`,
        description: `Action ${match[1]} использует ветку ${match[2]} вместо фиксированной версии. Атакующий может обновить action и получить доступ к секретам CI/CD.`,
        fix: `Пинить на SHA: uses: ${match[1]}@<commit-sha>. Или минимум на версию: @v3.2.1`,
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // #12 Secrets leaked in logs via echo
    const echoSecretRegex = /echo\s+.*\$\{?\s*(?:secrets\.|[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|API_KEY))/gi;
    while ((match = echoSecretRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("cicd"),
        checker: "cicd",
        severity: "HIGH",
        title: "Секрет в echo — утечка в логи CI",
        description: "echo с секретом выведет его в логи GitHub Actions. Логи часто публичные или доступны всей команде.",
        fix: "Удалить echo. Если нужна проверка: echo '::add-mask::' + secret.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // console.log with env secrets in CI
    const consoleSecretRegex = /console\.log\s*\(.*process\.env\.(?:[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD))/gi;
    while ((match = consoleSecretRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("cicd"),
        checker: "cicd",
        severity: "HIGH",
        title: "console.log с секретом в CI",
        description: "Логирование env переменной с секретом в CI pipeline. Попадёт в логи билда.",
        fix: "Удалить. Никогда не логировать секреты в CI.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // #5 GITHUB_TOKEN with excessive permissions
    const permissionsRegex = /permissions\s*:\s*write-all|permissions\s*:\s*\n\s+contents\s*:\s*write/g;
    while ((match = permissionsRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("cicd"),
        checker: "cicd",
        severity: "HIGH",
        title: "GITHUB_TOKEN с избыточными правами",
        description: "write-all даёт токену полный доступ к репозиторию. Если action скомпрометирован — атакующий может пушить код, создавать релизы.",
        fix: "Указывать минимальные права: permissions: { contents: read }. Добавлять write только для конкретных операций.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }

    // --dangerously-skip-permissions in CI
    const dangerousRegex = /--dangerously-skip-permissions|--no-verify|--trust-all|--dangerouslyDisableSandbox/g;
    while ((match = dangerousRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("cicd"),
        checker: "cicd",
        severity: "CRITICAL",
        title: `Опасный флаг в CI: ${match[0]}`,
        description: "Флаг отключает проверки безопасности в CI pipeline. Агент получает неограниченный доступ.",
        fix: "Удалить флаг. Настроить правильные permissions вместо отключения проверок.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  // Check that lock file exists (package-lock.json or yarn.lock)
  const hasPackageJson = files.some((f) => f.path === "package.json");
  const hasLockFile = files.some((f) =>
    f.path === "package-lock.json" || f.path === "yarn.lock" || f.path === "pnpm-lock.yaml",
  );
  if (hasPackageJson && !hasLockFile) {
    findings.push({
      id: makeId("cicd"),
      checker: "cicd",
      severity: "HIGH",
      title: "Нет lock файла (package-lock.json)",
      description: "Без lock файла каждый npm install может установить разные версии зависимостей, включая уязвимые. CI/CD особенно подвержен.",
      fix: "Закоммитить package-lock.json. Использовать npm ci в CI/CD вместо npm install.",
      file: "package.json",
      line: 0,
      snippet: "",
    });
  }

  return findings;
}
