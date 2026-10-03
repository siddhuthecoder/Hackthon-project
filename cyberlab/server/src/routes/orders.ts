import { Router, Response } from 'express';
import { Order } from '../models/Order';
import { Product } from '../models/Product';
import { AuthRequest, authMiddleware } from '../middleware/auth';
import { logSecurityEvent, logAudit } from '../services/securityLogger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

const BULK_RECORD_THRESHOLD = 100;
const MAX_LIST_LIMIT = 1000;

function tenantFilter(req: AuthRequest): Record<string, string> {
  return req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
}

async function logOrderRead(req: AuthRequest, endpoint: string, orderId: string, severity: 'low' | 'high', extra: Record<string, unknown> = {}): Promise<void> {
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
    metadata: { resourceId: orderId, resourceType: 'order', ...extra },
  });
}

// GET /api/orders/secure/:orderId (SECURE: verifies tenant ownership)
router.get('/secure/:orderId', authMiddleware, async (req: AuthRequest, res: Response) => {
  const order = await Order.findOne({ id: req.params.orderId });
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }

  if (order.tenantId !== req.user!.tenantId && req.user!.role !== 'SUPER_ADMIN') {
    await logSecurityEvent({
      eventType: 'AUTHORIZATION_FAILURE',
      severity: 'high',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: `/api/orders/secure/${req.params.orderId}`,
      method: 'GET',
      userAgent: req.userAgent,
      requestId: req.requestId,
      metadata: { reason: 'tenant_mismatch', orderTenant: order.tenantId, userTenant: req.user!.tenantId, vulnerability: 'VULN-002' },
    });
    res.status(403).json({ error: 'Access denied: order belongs to different tenant' });
    return;
  }

  await logOrderRead(req, `/api/orders/secure/${req.params.orderId}`, order.id, 'low');
  res.json(order.toJSON());
});

// GET /api/orders/export (bulk export of the caller's tenant orders)
router.get('/export', authMiddleware, async (req: AuthRequest, res: Response) => {
  const orders = await Order.find(tenantFilter(req)).sort({ createdAt: -1 });
  const endpoint = '/api/orders/export';
  const base = {
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint,
    method: 'GET',
    userAgent: req.userAgent,
    requestId: req.requestId,
  };
  await logSecurityEvent({ ...base, eventType: 'BULK_DATA_ACCESS', severity: 'high', mitreTechnique: 'T1530 Data from Cloud Storage', metadata: { recordCount: orders.length, resourceType: 'order' } });
  await logSecurityEvent({ ...base, eventType: 'DATA_EXPORT', severity: 'high', mitreTechnique: 'T1041 Exfiltration Over C2 Channel', metadata: { recordCount: orders.length, format: 'json', note: 'local_response_only' } });
  await logAudit(req.user!.userId, req.user!.email, 'DATA_EXPORT', req.user!.tenantId, { details: `Exported ${orders.length} orders` });
  res.json({ exportedAt: new Date().toISOString(), count: orders.length, orders: orders.map(o => o.toJSON()) });
});

// GET /api/orders (list - tenant scoped; no upper bound on ?limit= so bulk reads are possible)
router.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const requested = parseInt(req.query.limit as string, 10);
  const limit = Number.isFinite(requested) && requested > 0 ? Math.min(requested, MAX_LIST_LIMIT) : 50;
  const orders = await Order.find(tenantFilter(req)).sort({ createdAt: -1 }).limit(limit);

  if (orders.length >= BULK_RECORD_THRESHOLD) {
    await logSecurityEvent({
      eventType: 'BULK_DATA_ACCESS',
      severity: 'high',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint: '/api/orders',
      method: 'GET',
      userAgent: req.userAgent,
      requestId: req.requestId,
      mitreTechnique: 'T1530 Data from Cloud Storage',
      metadata: { recordCount: orders.length, resourceType: 'order', limit },
    });
  }
  res.json(orders.map(o => o.toJSON()));
});

// VULN-002 Cross-tenant data access: no tenant check, the attempt is only logged
async function vulnerableGetOrder(req: AuthRequest, res: Response): Promise<void> {
  const order = await Order.findOne({ id: req.params.orderId });
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }

  const endpoint = req.originalUrl.split('?')[0];
  const crossTenant = order.tenantId !== req.user!.tenantId && req.user!.role !== 'SUPER_ADMIN';
  if (crossTenant) {
    await logSecurityEvent({
      eventType: 'CROSS_TENANT_ACCESS_ATTEMPT',
      severity: 'critical',
      userId: req.user!.userId,
      tenantId: req.user!.tenantId,
      sourceIp: req.sourceIp,
      endpoint,
      method: 'GET',
      userAgent: req.userAgent,
      requestId: req.requestId,
      mitreTechnique: 'T1530 Data from Cloud Storage',
      metadata: { vulnerability: 'VULN-002', orderTenant: order.tenantId, userTenant: req.user!.tenantId, orderId: order.id },
    });
  }
  await logOrderRead(req, endpoint, order.id, crossTenant ? 'high' : 'low', crossTenant ? { vulnerability: 'VULN-002' } : {});
  res.json({ ...order.toJSON(), warning: 'VULNERABLE_ENDPOINT_CROSS_TENANT' });
}

router.get('/vulnerable/:orderId', authMiddleware, vulnerableGetOrder);
router.get('/:orderId', authMiddleware, vulnerableGetOrder);

// POST /api/orders (create)
router.post('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    res.status(400).json({ error: 'Items required' });
    return;
  }

  const orderItems = [];
  let total = 0;
  for (const item of items) {
    const product = await Product.findOne({ id: item.productId });
    if (!product) continue;
    const quantity = Math.max(1, Number(item.quantity) || 1);
    orderItems.push({ productId: product.id, name: product.name, quantity, price: product.price });
    total += product.price * quantity;
  }
  if (orderItems.length === 0) {
    res.status(400).json({ error: 'No valid products in order' });
    return;
  }

  const order = await Order.create({
    id: `order-${uuidv4().slice(0, 8)}`,
    orderNumber: `ORD-${Date.now()}`,
    customerId: req.user!.userId,
    customerName: req.user!.email,
    tenantId: req.user!.tenantId,
    items: orderItems,
    total: Math.round(total * 100) / 100,
    status: 'pending',
    createdAt: new Date(),
  });

  await logSecurityEvent({
    eventType: 'PAYMENT_CREATED',
    severity: 'low',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/orders',
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { orderId: order.id, total: order.total },
  });
  await logAudit(req.user!.userId, req.user!.email, 'ORDER_UPDATED', req.user!.tenantId, { target: order.id, targetName: order.orderNumber, details: 'Order created' });

  res.status(201).json(order.toJSON());
});

export default router;
