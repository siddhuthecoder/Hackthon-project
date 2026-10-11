import { randomUUID } from 'node:crypto';

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? '').toLowerCase();
  return (SEVERITY_ORDER as readonly string[]).includes(v) ? (v as Severity) : 'low';
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unexpected error';
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function unique<T>(items: readonly T[]): T[] {
  return Array.from(new Set(items));
}
