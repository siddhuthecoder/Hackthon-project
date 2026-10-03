import { Router, Response } from 'express';
import { Order } from '../models/Order';
import { Payment } from '../models/Payment';
import { AuthRequest, authMiddleware } from '../middleware/auth';
import { logSecurityEvent, logAudit } from '../services/securityLogger';
import { v4 as uuidv4 } from 'uuid';

export const paymentsRouter = Router();
export const refundsRouter = Router();

const PAYMENT_METHODS = ['card', 'bank', 'wallet'];

// GET /api/payments (list - tenant scoped via the orders the payment belongs to)
paymentsRouter.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const orderFilter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const orders = await Order.find(orderFilter).select('id');
  const payments = await Payment.find({ orderId: { $in: orders.map(o => o.id) } }).sort({ createdAt: -1 }).limit(200);
  res.json(payments.map(p => p.toJSON()));
});

// POST /api/payments/secure (SECURE: server-side state machine and server-computed amount)
paymentsRouter.post('/secure', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { orderId, method } = req.body;
  const order = await Order.findOne({ id: orderId });
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }
  if (order.tenantId !== req.user!.tenantId && req.user!.role !== 'SUPER_ADMIN') {
    res.status(403).json({ error: 'Access denied' });
    return;
  }
  if (order.status !== 'pending') {
    res.status(400).json({ error: 'Order is not in pending state' });
    return;
  }

  const payment = await Payment.create({
    id: `pay-${uuidv4().slice(0, 8)}`,
    orderId: order.id,
    amount: order.total,
    status: 'completed',
    method: PAYMENT_METHODS.includes(method) ? method : 'card',
    createdAt: new Date(),
  });
  order.status = 'paid';
  await order.save();

  await logSecurityEvent({
    eventType: 'PAYMENT_UPDATED',
    severity: 'low',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/payments/secure',
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { orderId: order.id, paymentId: payment.id, status: 'completed' },
  });
  await logAudit(req.user!.userId, req.user!.email, 'PAYMENT_UPDATED', req.user!.tenantId, { target: payment.id, targetName: order.orderNumber, details: 'Payment completed (secure)' });

  res.json({ ...payment.toJSON(), orderStatus: order.status });
});

// VULN-012 Business logic: client chooses payment status, amount and resulting order status
async function vulnerablePayment(req: AuthRequest, res: Response): Promise<void> {
  const { orderId, status, method, amount, orderStatus } = req.body;
  const order = await Order.findOne({ id: orderId });
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }

  const tamperedAmount = amount !== undefined && Number(amount) !== order.total;
  const tampered = tamperedAmount || status !== undefined || orderStatus !== undefined || order.status !== 'pending';

  const payment = await Payment.create({
    id: `pay-${uuidv4().slice(0, 8)}`,
    orderId: order.id,
    amount: amount !== undefined ? Number(amount) : order.total,
    status: status || 'completed',
    method: PAYMENT_METHODS.includes(method) ? method : 'card',
    createdAt: new Date(),
  });
  order.status = orderStatus || 'paid';
  await order.save();

  await logSecurityEvent({
    eventType: 'PAYMENT_UPDATED',
    severity: tampered ? 'high' : 'low',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: req.originalUrl.split('?')[0],
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    mitreTechnique: tampered ? 'T1565 Data Manipulation' : null,
    metadata: {
      vulnerability: 'VULN-012',
      orderId: order.id,
      paymentId: payment.id,
      status: payment.status,
      orderStatus: order.status,
      expectedAmount: order.total,
      paidAmount: payment.amount,
      ...(tampered ? { note: 'business_logic_abuse' } : {}),
    },
  });
  await logAudit(req.user!.userId, req.user!.email, 'PAYMENT_UPDATED', req.user!.tenantId, {
    target: payment.id,
    targetName: order.orderNumber,
    details: tampered ? 'Payment accepted with client-supplied fields (VULN-012)' : 'Payment completed',
  });

  res.json({ ...payment.toJSON(), orderStatus: order.status, warning: 'VULNERABLE_ENDPOINT_BUSINESS_LOGIC' });
}

paymentsRouter.post('/vulnerable', authMiddleware, vulnerablePayment);
paymentsRouter.post('/', authMiddleware, vulnerablePayment);

// POST /api/refunds
refundsRouter.post('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { orderId } = req.body;
  const order = await Order.findOne({ id: orderId });
  if (!order) {
    res.status(404).json({ error: 'Order not found' });
    return;
  }
  if (order.tenantId !== req.user!.tenantId && req.user!.role !== 'SUPER_ADMIN') {
    res.status(403).json({ error: 'Access denied' });
    return;
  }
  if (order.status !== 'paid' && order.status !== 'delivered') {
    res.status(400).json({ error: 'Order is not in a refundable state' });
    return;
  }

  const refund = await Payment.create({
    id: `refund-${uuidv4().slice(0, 8)}`,
    orderId: order.id,
    amount: order.total,
    status: 'refunded',
    method: 'card',
    createdAt: new Date(),
  });
  order.status = 'refunded';
  await order.save();

  await logSecurityEvent({
    eventType: 'REFUND_CREATED',
    severity: 'medium',
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    endpoint: '/api/refunds',
    method: 'POST',
    userAgent: req.userAgent,
    requestId: req.requestId,
    metadata: { orderId: order.id, refundId: refund.id },
  });
  await logAudit(req.user!.userId, req.user!.email, 'PAYMENT_UPDATED', req.user!.tenantId, { target: refund.id, targetName: order.orderNumber, details: 'Refund issued' });

  res.status(201).json(refund.toJSON());
});
