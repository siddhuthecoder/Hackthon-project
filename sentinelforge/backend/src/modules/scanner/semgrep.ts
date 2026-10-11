/**
 * Real Semgrep integration — a second genuine external AppSec tool alongside Gitleaks (see
 * docs/IMPLEMENTATION-STATUS.md "known gaps": previously only one real tool was wired in).
 * Semgrep is a SAST tool: it needs the actual source, so this runs against a read-only bind
 * mount of CyberLab's source tree (docker-compose.yml) rather than anything fetched over HTTP.
 * Custom local rule file (semgrep-rules.yml) instead of the public registry, matching the same
 * reasoning as the Gitleaks custom rule: deterministic and offline for a live demo, no dependency
 * on registry availability or rule-set drift.
 */
import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface SemgrepFinding {
  ruleId: string;
  message: string;
  file: string;
  line: number;
  snippet: string;
}

const RULES_PATH = path.join(__dirname, '../../../semgrep-rules.yml');
const CYBERLAB_SRC = process.env.SF_CYBERLAB_SRC_PATH ?? '/cyberlab-src';

export class SemgrepUnavailableError extends Error {}

/** Runs the real `semgrep` CLI against CyberLab's mounted source tree with our custom rule file.
 * Throws SemgrepUnavailableError if the binary isn't on PATH, or if the source mount isn't
 * present (both documented requirements — see docs/DEVELOPMENT.md and the backend Dockerfile). */
export async function runSemgrep(): Promise<SemgrepFinding[]> {
  if (!fs.existsSync(CYBERLAB_SRC)) {
    throw new SemgrepUnavailableError(`CyberLab source not mounted at ${CYBERLAB_SRC}. The backend container needs the read-only bind mount from docker-compose.yml.`);
  }
  let stdout: string;
  try {
    const res = await execFileAsync('semgrep', [
      '--config', RULES_PATH, '--json', '--quiet', '--no-git-ignore', CYBERLAB_SRC,
    ], { maxBuffer: 10 * 1024 * 1024 });
    stdout = res.stdout;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/not found|ENOENT|not recognized/i.test(message)) {
      throw new SemgrepUnavailableError('semgrep binary not found on PATH. Install it (see docs/DEVELOPMENT.md) or run the dockerized backend, which ships it.');
    }
    // Semgrep exits non-zero on rule errors, not merely on findings (findings are reported via
    // stdout with exit 0 for a clean rule file), so any throw here is a real tool failure.
    const stdoutFromError = (err as { stdout?: string }).stdout;
    if (!stdoutFromError) throw err;
    stdout = stdoutFromError;
  }

  const parsed = JSON.parse(stdout) as { results: { check_id: string; extra: { message: string; lines: string }; path: string; start: { line: number } }[] };
  return parsed.results.map(r => ({
    ruleId: r.check_id,
    message: r.extra.message,
    file: path.relative(CYBERLAB_SRC, r.path),
    line: r.start.line,
    snippet: r.extra.lines.trim().slice(0, 300),
  }));
}
