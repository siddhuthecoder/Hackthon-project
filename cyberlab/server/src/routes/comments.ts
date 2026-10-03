import { Router, Response } from 'express';
import { User } from '../models/User';
import { Comment } from '../models/Comment';
import { AuthRequest, authMiddleware } from '../middleware/auth';
import { logSecurityEvent } from '../services/securityLogger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

async function createComment(req: AuthRequest, res: Response, safe: boolean): Promise<void> {
  const { productId, content } = req.body;
  if (typeof content !== 'string' || !content) {
    res.status(400).json({ error: 'Content required' });
    return;
  }
  const user = await User.findOne({ id: req.user!.userId });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // VULN-005: the unsafe path stores raw HTML; the UI renders it unescaped
  const comment = await Comment.create({
    id: `comment-${uuidv4().slice(0, 8)}`,
    productId: productId || 'general',
    userId: user.id,
    userName: user.name,
    tenantId: user.tenantId,
    content: safe ? escapeHtml(content) : content,
    sanitized: safe,
    createdAt: new Date(),
  });

  const looksLikeMarkup = /<[^>]+>/.test(content);
  const suspicious = looksLikeMarkup && !safe;
  await logSecurityEvent({
    eventType: suspicious ? 'SUSPICIOUS_REQUEST' : 'DATA_ACCESS',
    severity: suspicious ? 'high' : 'low',
    userId: user.id,
    tenantId: user.tenantId,
    sourceIp: req.sourceIp,
    endpoint: req.originalUrl.split('?')[0],
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    mitreTechnique: suspicious ? 'T1059.007 JavaScript' : null,
    metadata: { vulnerability: 'VULN-005', note: safe ? 'sanitized' : 'stored_xss', containsMarkup: looksLikeMarkup },
  });

  res.status(201).json(safe ? comment.toJSON() : { ...comment.toJSON(), warning: 'VULNERABLE_ENDPOINT_XSS' });
}

router.post('/safe', authMiddleware, (req: AuthRequest, res: Response) => createComment(req, res, true));
router.post('/', authMiddleware, (req: AuthRequest, res: Response) => createComment(req, res, false));

router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const comments = await Comment.find(filter).sort({ createdAt: -1 }).limit(50);
  res.json(comments.map(c => c.toJSON()));
});

export default router;
