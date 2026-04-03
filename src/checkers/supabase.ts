import type { FileEntry, Finding } from "../types.js";
import { makeId, lineNumber, snippetAt } from "../utils.js";

/**
 * Supabase-specific security checks:
 * - Service role key on client side
 * - Missing RLS indicators
 * - Anon key misuse
 * - createClient with service key in browser code
 */

export async function checkSupabase(files: FileEntry[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Detect if project uses Supabase
  const usesSupabase = files.some(
    (f) => f.content.includes("@supabase/supabase-js") || f.content.includes("createClient"),
  );
  if (!usesSupabase) return findings;

  // Check for SQL migration files — look for tables without RLS
  const sqlFiles = files.filter((f) => /\.(sql)$/.test(f.path));
  for (const file of sqlFiles) {
    // Find CREATE TABLE statements
    const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)/gi;
    let tableMatch;
    while ((tableMatch = createTableRegex.exec(file.content)) !== null) {
      const tableName = tableMatch[1];
      // Skip Supabase internal tables
      if (["schema_migrations", "extensions", "buckets", "objects", "migrations"].includes(tableName)) continue;

      // Check if RLS is enabled for this table in the same file
      const rlsPattern = new RegExp(
        `ALTER\\s+TABLE\\s+(?:public\\.)?${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
        "i",
      );
      if (!rlsPattern.test(file.content)) {
        findings.push({
          id: makeId("supabase"),
          checker: "supabase",
          severity: "CRITICAL",
          title: `Таблица ${tableName} без Row Level Security`,
          description: `Таблица ${tableName} создана без ENABLE ROW LEVEL SECURITY. Любой аутентифицированный пользователь с anon key может читать и изменять все записи.`,
          fix: `ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Users see own data" ON ${tableName} FOR SELECT USING (auth.uid() = user_id);`,
          file: file.path,
          line: lineNumber(file.content, tableMatch.index),
          snippet: snippetAt(file.content, tableMatch.index),
        });
      }
    }

    // Check for RLS enabled but no policies
    const rlsEnabledRegex = /ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
    let rlsMatch;
    while ((rlsMatch = rlsEnabledRegex.exec(file.content)) !== null) {
      const tableName = rlsMatch[1];
      const policyPattern = new RegExp(`CREATE\\s+POLICY\\s+.+ON\\s+(?:public\\.)?${tableName}`, "i");
      if (!policyPattern.test(file.content)) {
        findings.push({
          id: makeId("supabase"),
          checker: "supabase",
          severity: "HIGH",
          title: `RLS включён для ${tableName}, но нет политик`,
          description: `RLS включён, но без политик таблица ${tableName} будет полностью заблокирована (deny by default). Если используется service role key для обхода — это другая проблема.`,
          fix: `Добавить политики: CREATE POLICY "policy_name" ON ${tableName} FOR SELECT USING (auth.uid() = user_id);`,
          file: file.path,
          line: lineNumber(file.content, rlsMatch.index),
          snippet: snippetAt(file.content, rlsMatch.index),
        });
      }
    }
  }

  // Check for service_role key used in client-side files
  const clientFiles = files.filter((f) =>
    /\.(jsx|tsx)$/.test(f.path) ||
    f.path.includes("components/") ||
    f.path.includes("pages/") ||
    f.path.includes("app/") && !f.path.includes("api/"),
  );

  for (const file of clientFiles) {
    // Service role key in client code
    const serviceKeyRegex = /service_?role|SUPABASE_SERVICE_ROLE/gi;
    let match;
    while ((match = serviceKeyRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("supabase"),
        checker: "supabase",
        severity: "CRITICAL",
        title: "Supabase service role key в клиентском коде",
        description: "Service role key обходит все RLS политики. В клиентском коде он доступен любому пользователю через DevTools.",
        fix: "Использовать service role key только на сервере (API routes, Edge Functions). На клиенте — только anon key.",
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  // Check for .rpc() calls without proper checks (potential RLS bypass)
  for (const file of files) {
    const rpcRegex = /\.rpc\s*\(\s*["'](\w+)["']/g;
    let match;
    while ((match = rpcRegex.exec(file.content)) !== null) {
      findings.push({
        id: makeId("supabase"),
        checker: "supabase",
        severity: "MEDIUM",
        title: `Supabase RPC вызов: ${match[1]}`,
        description: `RPC функция ${match[1]} может обходить RLS если создана с SECURITY DEFINER. Убедись что функция проверяет auth.uid().`,
        fix: `Проверить SQL функцию ${match[1]}: должна быть SECURITY INVOKER или содержать проверку auth.uid().`,
        file: file.path,
        line: lineNumber(file.content, match.index),
        snippet: snippetAt(file.content, match.index),
      });
    }
  }

  // Check for SECURITY DEFINER without auth check in SQL
  for (const file of sqlFiles) {
    const definerRegex = /SECURITY\s+DEFINER/gi;
    let match;
    while ((match = definerRegex.exec(file.content)) !== null) {
      // Look backwards for function name
      const before = file.content.slice(Math.max(0, match.index - 500), match.index);
      const funcMatch = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:public\.)?(\w+)/i.exec(before);
      const funcName = funcMatch?.[1] ?? "unknown";

      // Check if function checks auth.uid()
      const funcBody = file.content.slice(match.index, match.index + 1000);
      if (!/auth\.uid\(\)/.test(funcBody)) {
        findings.push({
          id: makeId("supabase"),
          checker: "supabase",
          severity: "HIGH",
          title: `SECURITY DEFINER без проверки auth в функции ${funcName}`,
          description: `Функция ${funcName} с SECURITY DEFINER выполняется с правами создателя, обходя RLS. Без проверки auth.uid() любой может вызвать её.`,
          fix: `Добавить проверку: IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Not authenticated'; END IF;`,
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: snippetAt(file.content, match.index),
        });
      }
    }
  }

  // Detect supabase.from().select/insert/update/delete without .eq('user_id', ...) in non-server files
  for (const file of clientFiles) {
    // .from('table').delete() without user filter — very dangerous
    const deleteRegex = /\.from\s*\(\s*["']\w+["']\s*\)\s*\.delete\s*\(\)/g;
    let match;
    while ((match = deleteRegex.exec(file.content)) !== null) {
      const after = file.content.slice(match.index, match.index + 200);
      if (!/\.eq\s*\(\s*["']user_id["']/.test(after) && !/\.match\s*\(/.test(after)) {
        findings.push({
          id: makeId("supabase"),
          checker: "supabase",
          severity: "HIGH",
          title: "Supabase delete() без фильтра по user_id",
          description: "DELETE запрос без фильтрации по пользователю на клиенте. Без RLS любой юзер может удалить все записи.",
          fix: "Добавить .eq('user_id', userId) или убедиться что RLS активен с правильными политиками.",
          file: file.path,
          line: lineNumber(file.content, match.index),
          snippet: snippetAt(file.content, match.index),
        });
      }
    }
  }

  return findings;
}
