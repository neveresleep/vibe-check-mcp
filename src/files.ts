import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname, basename } from "node:path";
import type { FileEntry } from "./types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next",
  ".nuxt", "coverage", "__pycache__", ".venv", "venv",
  ".turbo", "out", "public",
]);

const SKIP_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
  ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
  ".pdf", ".zip", ".lock", ".map",
]);

export async function collectFiles(dir: string): Promise<FileEntry[]> {
  const entries: FileEntry[] = [];
  await walk(dir, dir, entries);
  return entries;
}

async function walk(base: string, dir: string, out: FileEntry[]): Promise<void> {
  let items;
  try {
    items = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const item of items) {
    const full = join(dir, item.name);

    if (item.isDirectory()) {
      if (!SKIP_DIRS.has(item.name)) {
        await walk(base, full, out);
      }
      continue;
    }

    if (!item.isFile()) continue;

    const ext = extname(item.name);
    if (SKIP_EXTENSIONS.has(ext)) continue;
    if (item.name.includes(".min.")) continue;

    try {
      const info = await stat(full);
      if (info.size > 512 * 1024) continue; // skip files > 512KB
    } catch {
      continue;
    }

    try {
      const content = await readFile(full, "utf-8");
      const rel = full.slice(base.length + 1);
      out.push({ path: rel, content });
    } catch {
      // skip binary / unreadable files
    }
  }
}
