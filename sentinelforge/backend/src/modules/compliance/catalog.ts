/**
 * Static metadata about which OWASP categories the scanner actually tests — a fact about the
 * product (what checks.ts covers), kept separate from runtime data. Two families appear because
 * the demo spans both API-specific vulns (OWASP API Security Top 10) and classic web vulns
 * (OWASP Top 10 2021); mixing them into one "X/10" number would be misleading, so they're reported
 * as two separate coverage sets.
 */
export interface OwaspCategory {
  code: string;
  label: string;
  family: 'api-top-10' | 'web-top-10';
}

export const OWASP_CATALOG: Record<string, OwaspCategory> = {
  'API1:2023': { code: 'API1:2023', label: 'Broken Object Level Authorization', family: 'api-top-10' },
  'API3:2023': { code: 'API3:2023', label: 'Broken Object Property Level Authorization', family: 'api-top-10' },
  'API4:2023': { code: 'API4:2023', label: 'Unrestricted Resource Consumption', family: 'api-top-10' },
  'API5:2023': { code: 'API5:2023', label: 'Broken Function Level Authorization', family: 'api-top-10' },
  'API8:2023': { code: 'API8:2023', label: 'Security Misconfiguration', family: 'api-top-10' },
  'API10:2023': { code: 'API10:2023', label: 'Unsafe Consumption of APIs', family: 'api-top-10' },
  'A01:2021': { code: 'A01:2021', label: 'Broken Access Control', family: 'web-top-10' },
  'A03:2021': { code: 'A03:2021', label: 'Injection', family: 'web-top-10' },
  'A04:2021': { code: 'A04:2021', label: 'Insecure Design', family: 'web-top-10' },
  'A05:2021': { code: 'A05:2021', label: 'Security Misconfiguration', family: 'web-top-10' },
};

export const API_TOP_10_TOTAL = 10;
export const WEB_TOP_10_TOTAL = 10;
