import fs from 'fs';
import path from 'path';
import { NextFunction, Request, Response, Router } from 'express';
import { SecurityEvent } from '../models/SecurityEvent';

// VULN-014 is a secret committed in a plain config file, not a request-handling route — there's
// nothing to rewrite in the Express router for it. "Fix" means redacting the committed secret
// values in place; "unfix" restores the original content from an in-memory backup, same
// repeatable-demo contract as every other lab-fix toggle.
const CONFIG_DIR = process.env.CONFIG_DIR || path.join(__dirname, '../../../config');
const DEMO_ENV_PATH = path.join(CONFIG_DIR, 'demo.env');
const CREDENTIAL_LINE = /^([A-Z_]*(?:SECRET|PASSWORD|KEY|TOKEN)[A-Z_]*)=(.+)$/;
let demoEnvBackup: string | null = null;

function redactDemoEnv(): void {
  const content = fs.readFileSync(DEMO_ENV_PATH, 'utf8');
  if (demoEnvBackup === null) demoEnvBackup = content;
  const redacted = content
    .split('\n')
    .map(line => (CREDENTIAL_LINE.test(line) ? line.replace(CREDENTIAL_LINE, '$1=ROTATED_BY_SENTINELFORGE') : line))
    .join('\n');
  fs.writeFileSync(DEMO_ENV_PATH, redacted, 'utf8');
}

function restoreDemoEnv(): void {
  if (demoEnvBackup !== null) {
    fs.writeFileSync(DEMO_ENV_PATH, demoEnvBackup, 'utf8');
  }
}

/**
 * Lab-only controlled fix mechanism.
 *
 * Every vulnerability in the lab already ships a secure counterpart route. A "fix" switches the
 * vulnerable route to that secure implementation by rewriting the request URL before routing.
 * State is kept in memory only, so restarting the API (or POST /api/lab/reset) restores the
 * vulnerable behaviour for repeatable demos.
 */

interface FixRule {
  vuln: string;
  method: string;
  match: RegExp;
  rewrite: (m: RegExpMatchArray, url: string) => string;
  description: string;
}

const RULES: FixRule[] = [
  { vuln: 'VULN-001', method: 'GET', match: /^\/api\/users\/(?:vulnerable\/)?(?!secure\/)([^/?]+)(\?.*)?$/, rewrite: m => `/api/users/secure/${m[1]}${m[2] ?? ''}`, description: 'Enforce object ownership on GET /api/users/:userId' },
  { vuln: 'VULN-002', method: 'GET', match: /^\/api\/orders\/(?:vulnerable\/)?(?!secure\/|export)([^/?]+)(\?.*)?$/, rewrite: m => `/api/orders/secure/${m[1]}${m[2] ?? ''}`, description: 'Enforce tenant ownership on GET /api/orders/:orderId' },
  { vuln: 'VULN-003', method: 'GET', match: /^\/api\/admin\/users\/vulnerable(\?.*)?$/, rewrite: m => `/api/admin/users${m[1] ?? ''}`, description: 'Enforce admin role on admin user listing' },
  { vuln: 'VULN-004', method: 'POST', match: /^\/api\/auth\/vulnerable-login$/, rewrite: () => '/api/auth/secure-login', description: 'Coerce login inputs to strings (block operator injection)' },
  { vuln: 'VULN-005', method: 'POST', match: /^\/api\/comments$/, rewrite: () => '/api/comments/safe', description: 'HTML-escape comment content' },
  { vuln: 'VULN-006', method: 'POST', match: /^\/api\/fetch-url$/, rewrite: () => '/api/fetch-url/secure', description: 'Restrict outbound fetch to an allowlist' },
  { vuln: 'VULN-007', method: 'GET', match: /^\/api\/files\/download(?:\/vulnerable)?(\?.*)$/, rewrite: m => `/api/files/download/secure${m[1]}`, description: 'Allowlist downloadable file names' },
  { vuln: 'VULN-008', method: 'POST', match: /^\/api\/tools\/ping(?:\/vulnerable)?$/, rewrite: () => '/api/tools/ping/secure', description: 'Validate host format, no shell metacharacters' },
  { vuln: 'VULN-010', method: 'GET', match: /^\/api\/vulnerable\/admin(\?.*)?$/, rewrite: m => `/api/vulnerable/admin/secure${m[1] ?? ''}`, description: 'Re-check the role against the database' },
  { vuln: 'VULN-011', method: 'PATCH', match: /^\/api\/users\/(?:vulnerable\/)?(?!secure\/)([^/?]+)$/, rewrite: m => `/api/users/secure/${m[1]}`, description: 'Allowlist updatable user fields' },
  { vuln: 'VULN-012', method: 'POST', match: /^\/api\/payments(?:\/vulnerable)?$/, rewrite: () => '/api/payments/secure', description: 'Server-side payment state machine and amount' },
  { vuln: 'VULN-013', method: 'POST', match: /^\/api\/files\/upload(?:\/vulnerable)?$/, rewrite: () => '/api/files/upload/secure', description: 'Validate upload extension and mime type' },
];

// VULN-009 has no secure route; the fix is a strict failed-login limiter applied in the middleware.
const STRICT_LOGIN_FAILURES = 5;
const RATE_LIMIT_FIX = { vuln: 'VULN-009', description: 'Block logins after 5 failed attempts in 5 minutes' };
const CONFIG_REDACT_FIX = { vuln: 'VULN-014', description: 'Redact committed secret values in config/demo.env' };

const fixed = new Set<string>();

export const FIXABLE = [...RULES.map(r => ({ vuln: r.vuln, description: r.description })), RATE_LIMIT_FIX, CONFIG_REDACT_FIX];

export async function labFixMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (fixed.size === 0) {
    next();
    return;
  }

  if (fixed.has(RATE_LIMIT_FIX.vuln) && req.method === 'POST' && req.url.split('?')[0] === '/api/auth/login') {
    try {
      const since = new Date(Date.now() - 5 * 60 * 1000);
      const failures = await SecurityEvent.countDocuments({ eventType: 'AUTH_FAILURE', sourceIp: req.sourceIp, timestamp: { $gte: since } });
      if (failures >= STRICT_LOGIN_FAILURES) {
        res.status(429).json({ error: 'Too many failed login attempts (strict limiter active)' });
        return;
      }
    } catch (err) {
      next(err);
      return;
    }
  }

  for (const rule of RULES) {
    if (!fixed.has(rule.vuln) || rule.method !== req.method) continue;
    const m = req.url.match(rule.match);
    if (m) {
      req.url = rule.rewrite(m, req.url);
      break;
    }
  }
  next();
}

export const labRouter = Router();

function requireLabKey(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.LAB_CONTROL_KEY;
  if (!expected) {
    res.status(503).json({ error: 'LAB_CONTROL_KEY not configured on this server' });
    return;
  }
  if (req.headers['x-lab-key'] !== expected) {
    res.status(403).json({ error: 'Lab control key required' });
    return;
  }
  next();
}

labRouter.use(requireLabKey);

labRouter.get('/state', (_req, res) => {
  res.json({ fixed: Array.from(fixed).sort(), fixable: FIXABLE });
});

// Read-only: lets SentinelForge scan/verify the committed config file over HTTP instead of
// assuming shared host filesystem access (SentinelForge's scanner and CyberLab's API run in
// separate containers with no filesystem in common).
labRouter.get('/config-file', (_req, res) => {
  try {
    const content = fs.readFileSync(DEMO_ENV_PATH, 'utf8');
    res.json({ path: 'config/demo.env', content });
  } catch (err) {
    res.status(404).json({ error: `Could not read config/demo.env: ${err instanceof Error ? err.message : 'unknown error'}` });
  }
});

labRouter.post('/fix/:vulnId', (req, res) => {
  const known = FIXABLE.some(f => f.vuln === req.params.vulnId);
  if (!known) {
    res.status(404).json({ error: `No controlled fix available for ${req.params.vulnId}` });
    return;
  }
  if (req.params.vulnId === 'VULN-014') {
    try {
      redactDemoEnv();
    } catch (err) {
      res.status(500).json({ error: `Could not redact config/demo.env: ${err instanceof Error ? err.message : 'unknown error'}` });
      return;
    }
  }
  fixed.add(req.params.vulnId);
  res.json({ vulnId: req.params.vulnId, fixed: true, fixedSet: Array.from(fixed).sort() });
});

labRouter.post('/unfix/:vulnId', (req, res) => {
  if (req.params.vulnId === 'VULN-014') {
    restoreDemoEnv();
  }
  fixed.delete(req.params.vulnId);
  res.json({ vulnId: req.params.vulnId, fixed: false, fixedSet: Array.from(fixed).sort() });
});

labRouter.post('/reset', (_req, res) => {
  restoreDemoEnv();
  fixed.clear();
  res.json({ fixedSet: [] });
});
