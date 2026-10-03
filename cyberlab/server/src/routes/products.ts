import { Router, Response } from 'express';
import { Product } from '../models/Product';
import { AuthRequest, authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const products = await Product.find(filter).sort({ id: 1 }).limit(500);
  res.json(products.map(p => p.toJSON()));
});

router.get('/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  const product = await Product.findOne({ id: req.params.id });
  if (!product || (product.tenantId !== req.user!.tenantId && req.user!.role !== 'SUPER_ADMIN')) {
    res.status(404).json({ error: 'Product not found' });
    return;
  }
  res.json(product.toJSON());
});

export default router;
