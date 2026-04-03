export interface Finding {
  id: string;
  checker: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  description: string;
  fix: string;
  file: string;
  line: number;
  snippet: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  scanned_files: number;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
}

export type Checker = (files: FileEntry[]) => Promise<Finding[]>;

export interface FileEntry {
  path: string;
  content: string;
}
