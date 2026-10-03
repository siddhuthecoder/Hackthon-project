import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../models/User';
import { Tenant } from '../models/Tenant';
import { Session } from '../models/Session';
import { SecurityEvent } from '../models/SecurityEvent';
import { hashPassword, comparePassword, generateAccessToken, generateRefreshToken, verifyRefreshToken, createSession, revokeSession } from '../services/auth';
import { logSecurityEvent, logAudit } from '../services/securityLogger';
import { AuthRequest, authMiddleware } from '../middleware/auth';

const router = Router();

// VULN-009: weak rate limiting. Limit is keyed on the client-supplied X-Forwarded-For header (spoofable)
// and the threshold is high enough that brute force / credential stuffing still succeeds.
const WEAK_LOGIN_FAILURE_THRESHOLD = 100;
const weakLoginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ((req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'),
  message: { error: 'Too many login attempts. This is a weakly rate-limited demo endpoint.' },
});

async function checkWeakRateLimit(sourceIp: string): Promise<boolean> {
  const windowStart = new Date(Date.now() - 5 * 60 * 1000);
  const failures = await SecurityEvent.countDocuments({
    eventType: 'AUTH_FAILURE',
    sourceIp,
    timestamp: { $gte: windowStart },
  });
  return failures >= WEAK_LOGIN_FAILURE_THRESHOLD;
}

// POST /api/auth/register
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { name, email, password, tenantId } = req.body;
    if (!name || !email || !password) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    const existing = await User.findOne({ email });
    if (existing) {
      res.status(409).json({ error: 'Email already registered' });
      return;
    }

    const user = await User.create({
      id: `user-${uuidv4().slice(0, 8)}`,
      name,
      email,
      passwordHash: hashPassword(password),
      role: 'USER',
      tenantId: tenantId || 'tenant-alpha',
      active: true,
      createdAt: new Date(),
    });

    await logSecurityEvent({
      eventType: 'AUTH_SUCCESS',
      severity: 'low',
      userId: user.id,
      tenantId: user.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/register',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { action: 'register' },
    });

    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role, tenantId: user.tenantId });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login (secure)
router.post('/login', weakLoginLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: 'Missing email or password' });
      return;
    }

    if (await checkWeakRateLimit(req.sourceIp)) {
      await logSecurityEvent({
        eventType: 'RATE_LIMIT_TRIGGERED',
        severity: 'medium',
        sourceIp: req.sourceIp,
        endpoint: '/api/auth/login',
        method: 'POST',
        userAgent: req.userAgent,
        requestId: req.requestId,
        metadata: { reason: 'weak_rate_limit_triggered', threshold: WEAK_LOGIN_FAILURE_THRESHOLD, vulnerability: 'VULN-009' },
      });
      res.status(429).json({ error: 'Too many failed login attempts (demo weak rate limit triggered)' });
      return;
    }

    const user = await User.findOne({ email });
    if (!user || !user.active || !comparePassword(password, user.passwordHash)) {
      await logSecurityEvent({
        eventType: 'AUTH_FAILURE',
        severity: 'medium',
        userId: user?.id || null,
        tenantId: user?.tenantId || null,
        sourceIp: req.sourceIp,
        endpoint: '/api/auth/login',
        method: 'POST',
        userAgent: req.userAgent,
        requestId: req.requestId,
        metadata: { reason: 'invalid_credentials' },
      });

      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const payload = { userId: user.id, email: user.email, role: user.role, tenantId: user.tenantId };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await createSession(user, refreshToken, req.sourceIp, req.userAgent);
    user.lastLogin = new Date();
    await user.save();

    await logSecurityEvent({
      eventType: 'AUTH_SUCCESS',
      severity: 'low',
      userId: user.id,
      tenantId: user.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/login',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { action: 'login' },
    });

    await logSecurityEvent({
      eventType: 'SESSION_CREATED',
      severity: 'low',
      userId: user.id,
      tenantId: user.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/login',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: {},
    });

    await logAudit(user.id, user.name, 'LOGIN', user.tenantId);

    res.json({ accessToken, refreshToken, user: { id: user.id, name: user.name, email: user.email, role: user.role, tenantId: user.tenantId } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/vulnerable-login (VULN-004: NoSQL Injection)
// VULNERABLE: request body values go straight into the Mongo filter. Sending
// {"email":"alice.anderson@tenant.alpha.com","password":{"$ne":null}} matches the stored
// password field and skips the bcrypt check.
router.post('/vulnerable-login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const filter: Record<string, unknown> = { email, active: true };
    const isOperatorPayload = typeof password === 'object' && password !== null;

    let user = await User.findOne(isOperatorPayload ? { ...filter, passwordHash: password } : filter);
    if (user && !isOperatorPayload && !comparePassword(String(password), user.passwordHash)) {
      user = null;
    }

    const injected = isOperatorPayload || (typeof email === 'object' && email !== null);
    if (!user) {
      await logSecurityEvent({
        eventType: 'AUTH_FAILURE',
        severity: injected ? 'high' : 'medium',
        userId: null,
        tenantId: null,
        sourceIp: req.sourceIp,
        endpoint: '/api/auth/vulnerable-login',
        method: 'POST',
        userAgent: req.userAgent,
        requestId: req.requestId,
        mitreTechnique: 'T1110 Brute Force',
        metadata: { reason: injected ? 'nosql_injection_attempt' : 'invalid_credentials', vulnerability: 'VULN-004' },
      });
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const payload = { userId: user.id, email: user.email, role: user.role, tenantId: user.tenantId };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);
    await createSession(user, refreshToken, req.sourceIp, req.userAgent);

    await logSecurityEvent({
      eventType: 'AUTH_SUCCESS',
      severity: injected ? 'high' : 'low',
      userId: user.id,
      tenantId: user.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/vulnerable-login',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      mitreTechnique: 'T1078 Valid Accounts',
      metadata: { vulnerability: 'VULN-004', note: injected ? 'nosql_injection_login' : 'normal_login' },
    });

    res.json({ accessToken, refreshToken, user: { id: user.id, name: user.name, email: user.email, role: user.role, tenantId: user.tenantId }, warning: 'VULNERABLE_ENDPOINT' });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/secure-login (SECURE counterpart: coerces inputs to strings)
router.post('/secure-login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (typeof email !== 'string' || typeof password !== 'string') {
    await logSecurityEvent({
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/secure-login',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { reason: 'non_string_credentials_rejected', vulnerability: 'VULN-004' },
    });
    res.status(400).json({ error: 'email and password must be strings' });
    return;
  }
  const user = await User.findOne({ email, active: true });
  if (!user || !comparePassword(password, user.passwordHash)) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }
  const payload = { userId: user.id, email: user.email, role: user.role, tenantId: user.tenantId };
  res.json({ accessToken: generateAccessToken(payload), refreshToken: generateRefreshToken(payload), user: { id: user.id, name: user.name, email: user.email, role: user.role, tenantId: user.tenantId } });
});

// POST /api/auth/logout
router.post('/logout', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    await revokeSession(refreshToken);
    await logSecurityEvent({
      eventType: 'SESSION_REVOKED',
      severity: 'low',
      sourceIp: req.sourceIp,
      endpoint: '/api/auth/logout',
      method: 'POST',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: {},
    });
  }
  res.json({ success: true });
});

// POST /api/auth/refresh
router.post('/refresh', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    res.status(400).json({ error: 'Missing refresh token' });
    return;
  }

  const payload = verifyRefreshToken(refreshToken);
  if (!payload) {
    res.status(401).json({ error: 'Invalid refresh token' });
    return;
  }

  const session = await Session.findOne({ refreshToken, revoked: false });
  if (!session) {
    res.status(401).json({ error: 'Session not found' });
    return;
  }

  const newAccessToken = generateAccessToken(payload);
  res.json({ accessToken: newAccessToken });
});

// POST /api/auth/forgot-password
router.post('/forgot-password', async (req: Request, res: Response) => {
  const { email } = req.body;
  await logSecurityEvent({
    eventType: 'PASSWORD_RESET',
    severity: 'medium',
    sourceIp: req.sourceIp,
    endpoint: '/api/auth/forgot-password',
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { email, action: 'request_reset' },
  });
  res.json({ success: true, message: 'Reset link sent (demo)' });
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req: Request, res: Response) => {
  const { email, newPassword } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  user.passwordHash = hashPassword(newPassword);
  await user.save();
  await logSecurityEvent({
    eventType: 'PASSWORD_RESET',
    severity: 'medium',
    userId: user.id,
    tenantId: user.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/auth/reset-password',
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { action: 'password_changed' },
  });
  res.json({ success: true });
});

// GET /api/auth/me
router.get('/me', authMiddleware, async (req: AuthRequest, res: Response) => {
  const user = await User.findOne({ id: req.user!.userId });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({ id: user.id, userId: user.id, name: user.name, email: user.email, role: user.role, tenantId: user.tenantId, active: user.active, lastLogin: user.lastLogin });
});

export default router;
