let counter = 0;

export function makeId(checker: string): string {
  return `${checker}-${++counter}`;
}

export function redactSecret(line: string): string {
  return line
    .replace(/(sk-[A-Za-z0-9]{4})[A-Za-z0-9_-]{10,}/g, "$1****")
    .replace(/(eyJ[A-Za-z0-9]{4})[A-Za-z0-9_-]{10,}/g, "$1****")
    .replace(/(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, "$1****")
    .replace(/(gho_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, "$1****")
    .replace(/(ghu_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, "$1****")
    .replace(/(ghs_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, "$1****")
    .replace(/(ghr_[A-Za-z0-9]{4})[A-Za-z0-9]{10,}/g, "$1****")
    .replace(/(AKIA[A-Z0-9]{4})[A-Z0-9]{12}/g, "$1****")
    .replace(/(SG\.[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{18,}/g, "$1****")
    .replace(/(sk_live_[A-Za-z0-9]{4})[A-Za-z0-9]{20,}/g, "$1****")
    .replace(/(pk_live_[A-Za-z0-9]{4})[A-Za-z0-9]{20,}/g, "$1****")
    .replace(
      /(:\/\/[^:]+:)([^@]{4})[^@]+(@)/g,
      "$1$2****$3"
    );
}

export function isTestFile(path: string): boolean {
  return /\.(?:test|spec)\.[jt]sx?$/.test(path) || path.includes("__tests__/");
}

export function lineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

export function snippetAt(content: string, index: number): string {
  const lines = content.split("\n");
  const line = content.slice(0, index).split("\n").length - 1;
  const start = Math.max(0, line - 1);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).join("\n");
}
