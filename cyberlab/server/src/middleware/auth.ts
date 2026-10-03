import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/auth';
import { User } from '../models/User';

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role: string;
    tenantId: string;
  };
}

export async function authMiddleware(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  const token = authHeader.substring(7);
  const payload = verifyAccessToken(token);
  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  req.user = payload;
  next();
}

export async function optionalAuth(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const payload = verifyAccessToken(token);
    if (payload) req.user = payload;
  }
  next();
}

export function requireRole(...roles: string[]): (req: AuthRequest, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }
    next();
  };
}

export function requireTenantAccess(req: AuthRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (req.user.role === 'SUPER_ADMIN') {
    next();
    return;
  }
  const resourceTenantId = req.params.tenantId || req.body.tenantId;
  if (resourceTenantId && resourceTenantId !== req.user.tenantId) {
    res.status(403).json({ error: 'Cross-tenant access denied' });
    return;
  }
  next();
}
