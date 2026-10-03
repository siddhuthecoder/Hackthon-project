import { Router, Response } from 'express';
import { Tenant } from '../models/Tenant';
import { User } from '../models/User';
import { Product } from '../models/Product';
import { Order } from '../models/Order';
import { AuthRequest, authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { id: req.user!.tenantId };
  const tenants = await Tenant.find(filter).sort({ id: 1 });
  const result = await Promise.all(
    tenants.map(async t => {
      const [userCount, productCount, orderCount] = await Promise.all([
        User.countDocuments({ tenantId: t.id }),
        Product.countDocuments({ tenantId: t.id }),
        Order.countDocuments({ tenantId: t.id }),
      ]);
      return { id: t.id, name: t.name, plan: t.plan, createdAt: t.createdAt, userCount, productCount, orderCount };
    })
  );
  res.json(result);
});

export default router;
