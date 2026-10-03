import { Router, Response } from 'express';
import { Customer } from '../models/Customer';
import { AuthRequest, authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const customers = await Customer.find(filter).sort({ id: 1 }).limit(500);
  res.json(customers.map(c => c.toJSON()));
});

export default router;
