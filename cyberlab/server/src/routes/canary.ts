import { Router, Request, Response } from 'express';
import { logSecurityEvent } from '../services/securityLogger';

const router = Router();

/**
 * Deception/canary endpoints: paths that look like real sensitive resources (a DB backup, an
 * internal debug panel) but are never linked anywhere in the real app — no legitimate client,
 * user, or automated scan ever has a reason to call them. Any hit, authenticated or not, is by
 * definition reconnaissance or exploitation (endpoint fuzzing, source-code scraping, guessing),
 * so it is logged as a maximum-confidence CANARY_TRIGGERED event with no threshold/dedupe logic
 * needed — unlike every other detection rule, a single hit here is already certain.
 */
async function triggerCanary(req: Request, res: Response, label: string, fakeBody: Record<string, unknown>): Promise<void> {
  await logSecurityEvent({
    eventType: 'CANARY_TRIGGERED',
    severity: 'critical',
    userId: null,
    tenantId: null,
    sourceIp: req.sourceIp,
    endpoint: req.originalUrl.split('?')[0],
    method: req.method,
    userAgent: req.userAgent,
    requestId: req.requestId,
    mitreTechnique: 'T1595 Active Scanning',
    metadata: { canaryLabel: label, note: 'This endpoint is bait — no legitimate caller ever reaches it.' },
  });
  // Respond as if it were real, so the probe doesn't learn it tripped a trap.
  res.json(fakeBody);
}

router.get('/internal/db-backup.sql', (req, res) => {
  void triggerCanary(req, res, 'db-backup-download', {
    filename: 'cyberlab_backup_2026-09-14.sql', size: 48213, downloadUrl: '/api/internal/db-backup.sql?token=expired',
  });
});

router.get('/internal/.env.bak', (req, res) => {
  void triggerCanary(req, res, 'env-backup-file', { error: 'File not found' });
});

router.get('/admin/debug-console', (req, res) => {
  void triggerCanary(req, res, 'debug-console-access', { status: 'Debug console requires VPN access' });
});

export default router;
