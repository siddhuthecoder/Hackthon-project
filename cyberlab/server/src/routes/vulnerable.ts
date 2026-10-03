import { Router, Response } from 'express';
import { User } from '../models/User';
import { AuthRequest, authMiddleware } from '../middleware/auth';
import { logSecurityEvent } from '../services/securityLogger';

const router = Router();
const ADMIN_ROLES = ['SUPER_ADMIN', 'TENANT_ADMIN'];

// GET /api/vulnerable/admin (VULN-010)
// VULNERABLE: authentication is verified (valid signed token) but authorization trusts the role
// claim inside the token. The database is never consulted, so a demoted user keeps admin access
// until the token expires.
router.get('/admin', authMiddleware, async (req: AuthRequest, res: Response) => {
  if (!ADMIN_ROLES.includes(req.user!.role)) {
    await logSecurityEvent({
      eventType: 'AUTHORIZATION_FAILURE',
      severity: 'medium',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/vulnerable/admin',
      method: 'GET',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { vulnerability: 'VULN-010', jwtRole: req.user!.role, reason: 'claim_not_admin' },
    });
    res.status(403).json({ error: 'Admin claim required', authenticated: true, authorized: false });
    return;
  }

  const current = await User.findOne({ id: req.user!.userId });
  const users = await User.find({}).limit(50);
  await logSecurityEvent({
    eventType: 'ADMIN_ACTION',
    severity: current && !ADMIN_ROLES.includes(current.role) ? 'critical' : 'medium',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/vulnerable/admin',
    method: 'GET',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { vulnerability: 'VULN-010', jwtRole: req.user!.role, currentDbRole: current?.role, note: 'jwt_claim_trusted_without_db_check' },
  });
  res.json({ users: users.map(u => u.toJSON()), jwtRole: req.user!.role, currentDbRole: current?.role, warning: 'VULNERABLE_ENDPOINT_JWT_AUTH' });
});

// GET /api/vulnerable/admin/secure (SECURE: re-verifies the role against the database)
router.get('/admin/secure', authMiddleware, async (req: AuthRequest, res: Response) => {
  const current = await User.findOne({ id: req.user!.userId });
  if (!current || !current.active || !ADMIN_ROLES.includes(current.role)) {
    res.status(403).json({ error: 'Admin role required (verified server-side)', authenticated: true, authorized: false });
    return;
  }
  const users = await User.find(current.role === 'SUPER_ADMIN' ? {} : { tenantId: current.tenantId }).limit(50);
  res.json({ users: users.map(u => u.toJSON()) });
});

export default router;
