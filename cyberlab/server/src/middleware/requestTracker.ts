import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logSecurityEvent } from '../services/securityLogger';

const UNTRACKED_PREFIXES = ['/health', '/api/security'];

export function requestTracker(req: Request, res: Response, next: NextFunction): void {
  req.requestId = uuidv4();
  req.sourceIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  req.userAgent = req.headers['user-agent'] || 'unknown';

  res.on('finish', () => {
    const path = req.originalUrl.split('?')[0];
    const user = (req as Request & { user?: { userId: string; tenantId: string } }).user;

    if (res.statusCode >= 500) {
      logSecurityEvent({
        eventType: 'API_ERROR',
        severity: 'high',
        userId: user?.userId ?? null,
        tenantId: user?.tenantId ?? null,
        sourceIp: req.sourceIp,
        endpoint: path,
        method: req.method,
        userAgent: req.userAgent,
        requestId: req.requestId,
        metadata: { statusCode: res.statusCode },
      }).catch(() => {});
      return;
    }

    if (!path.startsWith('/api') || UNTRACKED_PREFIXES.some(p => path.startsWith(p))) return;
    if (!user) return;

    logSecurityEvent({
      eventType: 'API_REQUEST',
      severity: 'low',
      userId: user.userId,
      tenantId: user.tenantId,
      sourceIp: req.sourceIp,
      endpoint: path,
      method: req.method,
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { statusCode: res.statusCode },
    }).catch(() => {});
  });

  next();
}

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      sourceIp: string;
      userAgent: string;
    }
  }
}
