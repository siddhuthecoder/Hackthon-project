import { Router, Response } from 'express';
import { User } from '../models/User';
import { AuthRequest, authMiddleware, requireRole } from '../middleware/auth';
import { logSecurityEvent, logAudit } from '../services/securityLogger';

const router = Router();

const MASS_ASSIGNABLE_SAFE_FIELDS = ['name', 'email', 'phone'];

async function logUserRead(req: AuthRequest, endpoint: string, severity: 'low' | 'high', vulnerable: boolean): Promise<void> {
  await logSecurityEvent({
    eventType: 'DATA_ACCESS',
    severity,
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint,
    method: 'GET',
    userAgent: req.userAgent,
    requestId: req.requestId,
    mitreTechnique: vulnerable ? 'T1087 Account Discovery' : null,
    metadata: {
      resourceId: req.params.userId,
      resourceType: 'user',
      ...(vulnerable ? { vulnerability: 'VULN-001', note: 'no_ownership_check' } : {}),
    },
  });
}

// GET /api/users/secure/:userId (SECURE: ownership / admin check)
router.get('/secure/:userId', authMiddleware, async (req: AuthRequest, res: Response) => {
  const isOwner = req.user!.userId === req.params.userId;
  const isAdmin = req.user!.role === 'SUPER_ADMIN' || req.user!.role === 'TENANT_ADMIN';
  if (!isOwner && !isAdmin) {
    await logSecurityEvent({
      eventType: 'AUTHORIZATION_FAILURE',
      severity: 'medium',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: `/api/users/secure/${req.params.userId}`,
      method: 'GET',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { reason: 'not_owner', targetUser: req.params.userId },
    });
    res.status(403).json({ error: 'Access denied: you can only view your own profile' });
    return;
  }

  const user = await User.findOne({ id: req.params.userId });
  if (!user || (req.user!.role === 'TENANT_ADMIN' && user.tenantId !== req.user!.tenantId)) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  await logUserRead(req, `/api/users/secure/${req.params.userId}`, 'low', false);
  res.json(user.toJSON());
});

// GET /api/users (list - admins only, tenant scoped)
router.get('/', authMiddleware, requireRole('SUPER_ADMIN', 'TENANT_ADMIN', 'MANAGER'), async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const users = await User.find(filter).sort({ id: 1 }).limit(200);
  res.json(users.map(u => u.toJSON()));
});

// VULN-001 IDOR/BOLA: any authenticated user can read any user record by changing :userId
async function vulnerableGetUser(req: AuthRequest, res: Response): Promise<void> {
  const user = await User.findOne({ id: req.params.userId });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  await logUserRead(req, req.originalUrl.split('?')[0], 'high', true);
  res.json({ ...user.toJSON(), warning: 'VULNERABLE_ENDPOINT_IDOR' });
}

router.get('/vulnerable/:userId', authMiddleware, vulnerableGetUser);
router.get('/:userId', authMiddleware, vulnerableGetUser);

// PATCH /api/users/secure/:id (SECURE: allowlisted fields only)
router.patch('/secure/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  const isOwner = req.user!.userId === req.params.id;
  const isAdmin = req.user!.role === 'SUPER_ADMIN' || req.user!.role === 'TENANT_ADMIN';
  if (!isOwner && !isAdmin) {
    res.status(403).json({ error: 'Access denied' });
    return;
  }

  const update: Record<string, unknown> = {};
  for (const field of MASS_ASSIGNABLE_SAFE_FIELDS) {
    if (typeof req.body[field] === 'string') update[field] = req.body[field];
  }

  const user = await User.findOneAndUpdate({ id: req.params.id }, { $set: update }, { new: true });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const ignored = Object.keys(req.body).filter(k => !MASS_ASSIGNABLE_SAFE_FIELDS.includes(k));
  if (ignored.length > 0) {
    await logSecurityEvent({
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'medium',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: `/api/users/secure/${req.params.id}`,
      method: 'PATCH',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { reason: 'disallowed_fields_ignored', fields: ignored, vulnerability: 'VULN-011' },
    });
  }
  await logAudit(req.user!.userId, req.user!.email, 'USER_UPDATED', req.user!.tenantId, { target: user.id, targetName: user.name, details: 'Secure update' });
  res.json(user.toJSON());
});

// VULN-011 Mass assignment: every body field, including role / tenantId / isAdmin, is written to the user
async function vulnerablePatchUser(req: AuthRequest, res: Response): Promise<void> {
  const user = await User.findOne({ id: req.params.id });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const oldRole = user.role;
  const oldTenant = user.tenantId;
  const protectedKeys = ['id', '_id', 'passwordHash'];
  for (const [key, value] of Object.entries(req.body)) {
    if (protectedKeys.includes(key)) continue;
    user.set(key, value);
  }
  await user.save();

  if (oldRole !== user.role || oldTenant !== user.tenantId) {
    await logSecurityEvent({
      eventType: 'PRIVILEGE_CHANGE',
      severity: 'critical',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: req.originalUrl.split('?')[0],
      method: 'PATCH',
      userAgent: req.userAgent,
      requestId: req.requestId,
      mitreTechnique: 'T1098 Account Manipulation',
      metadata: {
        vulnerability: 'VULN-011',
        oldRole,
        newRole: user.role,
        oldTenant,
        newTenant: user.tenantId,
        actorRole: req.user!.role,
        targetUser: user.id,
        note: 'mass_assignment',
      },
    });
    await logAudit(req.user!.userId, req.user!.email, 'ROLE_CHANGED', req.user!.tenantId, {
      target: user.id,
      targetName: user.name,
      oldValue: oldRole,
      newValue: user.role,
      details: 'Changed via mass assignment (VULN-011)',
    });
  }

  res.json({ ...user.toJSON(), warning: 'VULNERABLE_ENDPOINT_MASS_ASSIGNMENT' });
}

router.patch('/vulnerable/:id', authMiddleware, vulnerablePatchUser);
router.patch('/:id', authMiddleware, vulnerablePatchUser);

export default router;
