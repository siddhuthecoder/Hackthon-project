import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config';
import { connectDB, disconnectDB } from './services/database';
import { connectRedis, disconnectRedis } from './services/redis';
import { requestTracker } from './middleware/requestTracker';
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import orderRoutes from './routes/orders';
import { paymentsRouter, refundsRouter } from './routes/payments';
import adminRoutes from './routes/admin';
import securityRoutes from './routes/security';
import { filesRouter, fetchUrlRouter, toolsRouter } from './routes/files';
import productRoutes from './routes/products';
import tenantRoutes from './routes/tenants';
import customerRoutes from './routes/customers';
import commentRoutes from './routes/comments';
import notificationRoutes from './routes/notifications';
import vulnerableRoutes from './routes/vulnerable';
import canaryRoutes from './routes/canary';
import { labFixMiddleware, labRouter } from './services/labFix';

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(requestTracker);
app.use('/api/lab', labRouter);
app.use(labFixMiddleware);

app.get('/health', (_req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/api/health', (_req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/payments', paymentsRouter);
app.use('/api/refunds', refundsRouter);
app.use('/api/products', productRoutes);
app.use('/api/tenants', tenantRoutes);
app.use('/api/customers', customerRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/vulnerable', vulnerableRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/files', filesRouter);
app.use('/api/fetch-url', fetchUrlRouter);
app.use('/api/tools', toolsRouter);
app.use('/api', canaryRoutes);

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  if (err.message.startsWith('File type') || err.message.startsWith('LAB_SAFETY_GUARD') || err.name === 'MulterError') {
    res.status(400).json({ error: err.message });
    return;
  }
  console.error('[API] Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function start(): Promise<void> {
  await connectDB();
  await connectRedis();

  app.listen(config.port, () => {
    console.log(`[API] SentinelForge API running on port ${config.port}`);
  });
}

process.on('unhandledRejection', err => console.error('[API] Unhandled rejection:', err));

process.on('SIGINT', async () => {
  await disconnectDB();
  await disconnectRedis();
  process.exit(0);
});

start();
