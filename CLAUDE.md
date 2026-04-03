# vibe-check-mcp — контекст проекта для Claude Code

## Что это

MCP сервер для Claude Code который проверяет vibe-coded проекты на уязвимости безопасности.

Пользователь подключает MCP сервер к Claude Code один раз, и потом просто пишет:
"проверь мой проект на уязвимости" — Клод сам вызывает инструменты, находит проблемы,
объясняет и предлагает фиксы прямо в чате.

## Стек

- TypeScript / Node.js
- @modelcontextprotocol/sdk — официальный MCP SDK от Anthropic
- zod — валидация входных параметров
- Публикуется на npm
- Подключается через: claude mcp add vibe-check -- npx vibe-check-mcp

## Как пользователь устанавливает

```bash
# Один раз подключить к Claude Code:
claude mcp add vibe-check -- npx vibe-check-mcp

# Дальше просто работает в Claude Code — пишет:
# "проверь безопасность моего проекта"
# "есть ли утечки ключей?"
# "проверь только секреты"
```

## Структура проекта

```
vibe-check-mcp/
├── src/
│   ├── index.ts              ← MCP сервер, регистрация инструментов
│   └── checkers/
│       ├── secrets.ts        ← API ключи, токены, credentials
│       ├── auth.ts           ← broken auth, RLS, JWT, хэширование
│       ├── config.ts         ← .env, .gitignore, debug flags, CORS
│       ├── injections.ts     ← eval(), SQL, command injection, XSS
│       ├── headers.ts        ← security headers, cookies, CSP
│       └── dependencies.ts   ← уязвимые npm пакеты (npm audit)
├── package.json
├── tsconfig.json
└── README.md
```

## MCP инструменты для регистрации

### 1. scan_project
Главный инструмент. Сканирует весь проект статическим анализом.

Вход:
- path: string — путь к проекту, default "."
- severity?: "critical" | "high" | "medium" | "low" | "all"
- checkers?: string[] — ["secrets", "auth", "config"] какие checkers запускать

Выход:
- summary: { total, critical, high, medium, low, scanned_files }
- findings: Finding[]

### 2. scan_file
Сканирует один конкретный файл.

Вход: { path: string }
Выход: Finding[]

### 3. check_secrets
Только проверка секретов и API ключей — самая частая просьба.

Вход: { path: string }
Выход: Finding[] только секреты

### 4. explain_finding
Подробное объяснение конкретной находки с примером фикса.

Вход: { finding: Finding }
Выход: строка с объяснением + код фикса

## Тип Finding (TypeScript)

```typescript
interface Finding {
  id: string
  checker: string        // "secrets" | "auth" | "config" | "injections" | "headers"
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string          // короткое название проблемы
  description: string    // что происходит простым языком
  fix: string            // конкретные шаги как исправить
  file: string           // относительный путь к файлу
  line: number           // номер строки (0 если не применимо)
  snippet: string        // фрагмент кода — секреты РЕДАКТИРОВАТЬ
}
```

## Checkers — полные правила

### secrets.ts

Regex паттерны для поиска (все файлы кроме скипаемых):

```
Supabase service role key:
  /supabase[_-]?service[_-]?role[_-]?key\s*[=:]\s*["']?(eyJ[A-Za-z0-9_-]{20,})/i
  severity: CRITICAL
  fix: Перенести в env var SUPABASE_SERVICE_ROLE_KEY. Использовать только на сервере.

OpenAI API key:
  /sk-(?:proj-)?[A-Za-z0-9]{20,}/
  severity: CRITICAL
  fix: Отозвать на platform.openai.com/api-keys. Хранить в OPENAI_API_KEY env var.

Anthropic API key:
  /sk-ant-[A-Za-z0-9_-]{20,}/
  severity: CRITICAL
  fix: Отозвать на console.anthropic.com. Хранить в ANTHROPIC_API_KEY env var.

Stripe secret key:
  /sk_live_[A-Za-z0-9]{24,}/
  severity: CRITICAL
  fix: Только на сервере. sk_live_ никогда не на фронтенде.

GitHub PAT:
  /gh[pousr]_[A-Za-z0-9]{36,}/
  severity: CRITICAL
  fix: Отозвать на github.com/settings/tokens.

AWS Access Key:
  /AKIA[0-9A-Z]{16}/
  severity: CRITICAL
  fix: Деактивировать в AWS IAM немедленно.

Private key:
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/
  severity: CRITICAL
  fix: Отозвать сертификат. Удалить из git history через git filter-repo.

Database URL с паролем:
  /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]{3,}@/i
  severity: CRITICAL
  fix: Использовать DATABASE_URL из env. Ротировать пароль БД.

Hardcoded password в коде:
  /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']/i
  severity: HIGH
  fix: Перенести в env vars или secrets manager.

SendGrid API key:
  /SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}/
  severity: CRITICAL
  fix: Ротировать в SendGrid Dashboard. Хранить в env.

Stripe publishable key (info only):
  /pk_live_[A-Za-z0-9]{24,}/
  severity: LOW
  fix: pk_live_ можно на фронтенде — это нормально. Убедись что sk_live_ скрыт.
```

### auth.ts

Паттерны для .js, .ts, .jsx, .tsx, .py, .go, .rb, .php файлов:

```
eval() с user input:
  /eval\s*\(\s*(?:req\.|request\.|params\.|body\.|input)/i
  severity: CRITICAL
  fix: Заменить на JSON.parse() для данных. Никогда не eval() с внешними данными.

SQL конкатенация:
  /["']SELECT\s.+["']\s*\+/i
  severity: CRITICAL
  fix: Использовать параметризованные запросы: db.query("SELECT...", [id])

Math.random() для токенов:
  /Math\.random\(\).*(?:token|secret|key)|(?:token|secret|key).*Math\.random\(\)/i
  severity: HIGH
  fix: crypto.randomBytes(32).toString('hex') в Node.js

MD5 для паролей:
  /md5\s*\(.*password|password.*md5/i
  severity: HIGH
  fix: Использовать bcrypt.hash(password, 12) или argon2

SHA1 для паролей:
  /sha1\s*\(.*password|password.*sha1/i
  severity: HIGH
  fix: Использовать bcrypt или argon2 — специально созданы для паролей

JWT без алгоритма:
  /jwt\.verify\s*\(\s*\w+\s*,\s*\w+\s*\)(?!\s*,\s*\{)/
  severity: CRITICAL
  fix: jwt.verify(token, secret, { algorithms: ['HS256'] })

pickle.loads() Python:
  /pickle\.loads?\s*\(/i
  severity: CRITICAL
  fix: Заменить на json.loads(). pickle выполняет код при десериализации.

Auth bypass:
  /if\s*\(.*(?:skip.{0,10}auth|bypass.{0,10}auth|auth.{0,10}disabled)/i
  severity: CRITICAL
  fix: Удалить. Аутентификация должна работать одинаково в dev и prod.

Client-side admin check:
  /role\s*===?\s*["']admin["']|isAdmin\s*===?\s*true/i
  severity: MEDIUM
  fix: Проверять роли только на сервере. Frontend — только для отображения.

Cookie без httpOnly:
  /res\.cookie\s*\([^)]+\)/
  severity: MEDIUM
  fix: res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'strict' })
  note: только если в cookie нет httpOnly: true
```

### config.ts

Проверки на уровне файловой системы:

```
.env не в .gitignore:
  Проверить существует ли .env и есть ли ".env" или ".env*" в .gitignore
  severity: HIGH
  fix: Добавить в .gitignore: .env .env.local .env.*.local

.gitignore отсутствует:
  severity: HIGH
  fix: Создать .gitignore с: .env node_modules .next dist build

CORS wildcard:
  /Access-Control-Allow-Origin['":\s]*\*/i
  severity: HIGH
  fix: Указать конкретный домен: cors({ origin: 'https://myapp.com' })

Debug в продакшне:
  /DEBUG\s*=\s*True|NODE_ENV\s*=\s*["']?development/i  (только в prod конфигах)
  severity: MEDIUM
  fix: NODE_ENV=production, DEBUG=false в продакшн окружении

Логирование секретов:
  /console\.log\s*\(.*(?:password|token|secret|key)/i
  severity: HIGH
  fix: Удалить. Использовать структурированный logger с redact функцией.

Открытые debug эндпоинты:
  /(?:router|app)\.(?:get|post)\s*\(\s*["']\/(?:test|debug|seed|admin\/seed)/i
  severity: HIGH
  fix: Удалить или закрыть auth middleware перед деплоем.
```

### injections.ts

```
Command injection:
  /(?:exec|execSync|spawn)\s*\(\s*["'].*\s*\+|child_process.*\+/i
  severity: CRITICAL
  fix: Передавать аргументы массивом: spawn('cmd', [arg1, arg2])

Path traversal:
  /(?:readFile|writeFile|readFileSync)\s*\([^)]*\+/i
  severity: CRITICAL
  fix: path.join(__dirname, 'uploads', path.basename(filename))

SSRF:
  /fetch\s*\(\s*(?:req\.|request\.query|req\.body|req\.params)/i
  severity: CRITICAL
  fix: Whitelist разрешённых доменов. Блокировать private IP ranges.

XSS через innerHTML:
  /\.innerHTML\s*=\s*(?!["'`])/
  severity: HIGH
  fix: Использовать textContent для текста. DOMPurify.sanitize() для HTML.

Open redirect:
  /res\.redirect\s*\(\s*req\./i
  severity: HIGH
  fix: Whitelist допустимых URL для редиректа.
```

### headers.ts

```
Нет helmet():
  Проверить package.json на helmet и app.use(helmet()) в основном файле
  severity: MEDIUM
  fix: npm install helmet, app.use(helmet())

Нет X-Frame-Options:
  Если нет helmet и нет X-Frame-Options в коде
  severity: MEDIUM
  fix: res.setHeader('X-Frame-Options', 'DENY')

CORS с credentials и wildcard:
  /credentials.*true.*origin.*\*|origin.*\*.*credentials.*true/is
  severity: HIGH
  fix: Нельзя использовать wildcard origin с credentials: true
```

## Файлы которые всегда скипать

```typescript
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next',
  '.nuxt', 'coverage', '__pycache__', '.venv', 'venv',
  '.turbo', 'out', 'public'
])

const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
  '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
  '.pdf', '.zip', '.lock', '.map'
])

// Скипать минифицированные файлы:
if (filename.includes('.min.')) skip()

// Скипать тестовые файлы для некоторых паттернов:
// *.test.ts, *.spec.ts, __tests__/ — не репортить hardcoded values
```

## Редактирование секретов в сниппетах

ОБЯЗАТЕЛЬНО — никогда не показывать полный секрет:

```typescript
function redactSecret(line: string): string {
  return line
    .replace(/(sk-[A-Za-z0-9]{4})[A-Za-z0-9_-]{10,}/g, '$1****')
    .replace(/(eyJ[A-Za-z0-9]{4})[A-Za-z0-9_-]{10,}/g, '$1****')
    .replace(/(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, '$1****')
    .replace(/(AKIA[A-Z0-9]{4})[A-Z0-9]{12}/g, '$1****')
    .replace(/([A-Za-z0-9_-]{4})[A-Za-z0-9_-]{16,}/g, '$1****')
}
```

## Тон и стиль

Целевая аудитория — vibe-builders: люди которые строят продукты с Lovable, Bolt, Cursor, v0.dev.
Многие не знают security глубоко.

- Описания простым языком, без жаргона
- Каждый фикс — конкретные шаги, не "улучшить безопасность"
- Не пугать — объяснять почему это проблема
- Короткие сниппеты кода для фиксов где возможно

## Что НЕ делать

- Не отправлять код пользователя никуда — всё локально, никаких внешних запросов
- Не требовать API key — базовый скан полностью бесплатный
- Не давать false positives на тестовые файлы
- Не показывать полные значения секретов в выводе
- Не репортить одно и то же несколько раз для одного файла

## Источники

- Исследование 100 vibe-coded приложений → 318 уязвимостей (DEV Community, март 2025)
- Escape.tech: 5600 приложений → 2000+ уязвимостей, 400+ exposed secrets
- OWASP Top 10 Web 2025
- OWASP Top 10 LLM 2025 (LLM01-LLM10)
- Tenzai Research Dec 2025 (69 уязвимостей в 15 vibe-coded приложениях)
- Kaspersky vibe coding security report 2025
- Wiz Research, Veracode GenAI Report 2025

Полный список 100 уязвимостей с описаниями: vibe_sec_vulnerabilities.md
