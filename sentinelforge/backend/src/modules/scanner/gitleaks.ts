/**
 * Real Gitleaks integration for VULN-014 (secret committed in a plain config file). The scanner's
 * other 13 checks are direct exploit attempts (no generic SAST/DAST tool fits a business-logic or
 * auth-bypass bug — see docs/IMPLEMENTATION-STATUS.md), but a committed-secret check is exactly
 * what Gitleaks is built for, so this one uses the real tool instead of a hand-rolled regex scan.
 */
import { execFile } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface GitleaksFinding {
  ruleId: string;
  description: string;
  match: string;
  line: number;
}

const CONFIG_PATH = path.join(__dirname, '../../../gitleaks.toml');
// A fix applied through the lab-fix toggle (modules/verification/service.ts via CyberLab's
// labFix.ts) replaces every credential value with this literal marker. Findings on an otherwise
// credential-shaped line that still carries this marker are the redacted placeholder itself, not
// a live secret — Gitleaks' own allowlist mechanism matches the rule's capture group rather than
// the full value in this gitleaks version, so the marker is filtered here instead.
const FIX_MARKER = 'ROTATED_BY_SENTINELFORGE';

export class GitleaksUnavailableError extends Error {}

/** Runs the real `gitleaks` binary against the given file content and returns only findings that
 * are not the lab's own fix marker. Throws GitleaksUnavailableError if the binary isn't on PATH
 * (documented requirement: see docs/DEVELOPMENT.md / the backend Dockerfile). */
export async function runGitleaks(filename: string, content: string): Promise<GitleaksFinding[]> {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sf-gitleaks-'));
  const reportPath = path.join(dir, 'report.json');
  try {
    await fs.promises.writeFile(path.join(dir, filename), content, 'utf8');
    try {
      await execFileAsync('gitleaks', [
        'detect', '--source', dir, '--no-git', '--config', CONFIG_PATH,
        '--report-format', 'json', '--report-path', reportPath, '--exit-code', '0',
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/not found|ENOENT|not recognized/i.test(message)) {
        throw new GitleaksUnavailableError('gitleaks binary not found on PATH. Install it (see docs/DEVELOPMENT.md) or run the dockerized backend, which ships it.');
      }
      // gitleaks exits non-zero by default when leaks are found; --exit-code 0 above avoids
      // that, so any throw here is a real tool failure, not "leaks were found".
      throw err;
    }

    const raw = await fs.promises.readFile(reportPath, 'utf8').catch(() => '[]');
    const parsed = JSON.parse(raw) as { RuleID: string; Description: string; Match: string; StartLine: number }[];
    return parsed
      .filter(f => !f.Match.includes(FIX_MARKER))
      .map(f => ({ ruleId: f.RuleID, description: f.Description, match: f.Match.trim(), line: f.StartLine }));
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
