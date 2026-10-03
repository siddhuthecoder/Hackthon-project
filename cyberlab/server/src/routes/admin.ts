import { Router, Response } from 'express';
import { User } from '../models/User';
import { AuthRequest, authMiddleware, requireRole } from '../middleware/auth';
import { logSecurityEvent, logAudit } from '../services/securityLogger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// GET /api/admin/users (SECURE: admin only)
router.get('/users', authMiddleware, requireRole('SUPER_ADMIN', 'TENANT_ADMIN'), async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const users = await User.find(filter).limit(100);
  res.json(users.map(u => u.toJSON()));
});

// GET /api/admin/users (VULNERABLE: VULN-003 Broken RBAC - no role check)
router.get('/users/vulnerable', authMiddleware, async (req: AuthRequest, res: Response) => {
  // VULNERABLE: no role validation - any authenticated user can access
  const users = await User.find({}).limit(100);
  await logSecurityEvent({
    eventType: 'AUTHORIZATION_FAILURE',
    severity: 'high',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/admin/users/vulnerable',
    method: 'GET',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { vulnerability: 'VULN-003', userRole: req.user!.role, note: 'broken_rbac' },
  });
  res.json({ users: users.map(u => u.toJSON()), warning: 'VULNERABLE_ENDPOINT_BROKEN_RBAC' });
});

// POST /api/admin/users/:id/promote (SECURE)
router.post('/users/:id/promote', authMiddleware, requireRole('SUPER_ADMIN', 'TENANT_ADMIN'), async (req: AuthRequest, res: Response) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  if (req.user!.role === 'TENANT_ADMIN' && user.tenantId !== req.user!.tenantId) {
    res.status(403).json({ error: 'Cross-tenant access denied' });
    return;
  }

  const oldRole = user.role;
  user.role = req.body.role || 'MANAGER';
  await user.save();

  await logSecurityEvent({
    eventType: 'PRIVILEGE_CHANGE',
    severity: 'medium',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: `/api/admin/users/${req.params.id}/promote`,
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { targetUser: user.id, oldRole, newRole: user.role, actorRole: req.user!.role },
  });

  await logAudit(req.user!.userId, req.user!.email, 'ROLE_CHANGED', req.user!.tenantId, {
    target: user.id, targetName: user.name, oldValue: oldRole, newValue: user.role,
  });

  res.json(user.toJSON());
});

// POST /api/admin/users/:id/promote (VULNERABLE: VULN-003 - no role check)
router.post('/users/:id/promote/vulnerable', authMiddleware, async (req: AuthRequest, res: Response) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // VULNERABLE: no role check on who is promoting
  const oldRole = user.role;
  user.role = req.body.role || 'TENANT_ADMIN';
  await user.save();

  await logSecurityEvent({
    eventType: 'PRIVILEGE_CHANGE',
    severity: 'critical',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: `/api/admin/users/${req.params.id}/promote/vulnerable`,
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { vulnerability: 'VULN-003', targetUser: user.id, oldRole, newRole: user.role, promotedBy: req.user!.role, actorRole: req.user!.role },
  });

  await logAudit(req.user!.userId, req.user!.email, 'ROLE_CHANGED', req.user!.tenantId, {
    target: user.id, targetName: user.name, oldValue: oldRole, newValue: user.role,
  });

  res.json({ ...user.toJSON(), warning: 'VULNERABLE_ENDPOINT_BROKEN_RBAC' });
});

// DELETE /api/admin/users/:id (SECURE)
router.delete('/users/:id', authMiddleware, requireRole('SUPER_ADMIN', 'TENANT_ADMIN'), async (req: AuthRequest, res: Response) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  if (req.user!.role === 'TENANT_ADMIN' && user.tenantId !== req.user!.tenantId) {
    res.status(403).json({ error: 'Cross-tenant access denied' });
    return;
  }

  user.active = false;
  await user.save();

  await logSecurityEvent({
    eventType: 'ADMIN_ACTION',
    severity: 'medium',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: `/api/admin/users/${req.params.id}`,
    method: 'DELETE',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { targetUser: user.id, action: 'deactivate' },
  });

  await logAudit(req.user!.userId, req.user!.email, 'USER_UPDATED', req.user!.tenantId, {
    target: user.id, targetName: user.name, details: 'User deactivated',
  });

  res.json({ success: true });
});

// DELETE /api/admin/users/:id (VULNERABLE: VULN-003)
router.delete('/users/:id/vulnerable', authMiddleware, async (req: AuthRequest, res: Response) => {
  const user = await User.findOne({ id: req.params.id });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // VULNERABLE: no role check
  user.active = false;
  await user.save();

  await logSecurityEvent({
    eventType: 'ADMIN_ACTION',
    severity: 'critical',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: `/api/admin/users/${req.params.id}/vulnerable`,
    method: 'DELETE',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { vulnerability: 'VULN-003', targetUser: user.id, action: 'deactivate', deletedBy: req.user!.role },
  });

  res.json({ success: true, warning: 'VULNERABLE_ENDPOINT_BROKEN_RBAC' });
});

export default router;
