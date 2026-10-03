import { Router, Response } from 'express';
import { Notification } from '../models/Notification';
import { AuthRequest, authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { $or: [{ tenantId: req.user!.tenantId }, { tenantId: null }] };
  const items = await Notification.find(filter).sort({ createdAt: -1 }).limit(50);
  res.json(items.map(n => n.toJSON()));
});

export default router;
