import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import Fastify, { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from './config';
import { dbHealthy } from './db/connection';
import { aiRoutes } from './modules/ai/routes';
import { applicationRoutes } from './modules/applications/routes';
import { catalogRoutes } from './modules/catalog/routes';
import { authRoutes } from './modules/auth/routes';
import { complianceRoutes } from './modules/compliance/routes';
import { attackMatrixRoutes } from './modules/attack-matrix/routes';
import { socRoutes } from './modules/soc/routes';
import { digitalTwinRoutes } from './modules/digital-twin/routes';
import { findingRoutes } from './modules/findings/routes';
import { incidentRoutes } from './modules/incidents/routes';
import { labRoutes } from './modules/lab/routes';
import { streamRoutes } from './modules/stream/routes';
import { metricsRoutes } from './modules/metrics/routes';
import { reportRoutes } from './modules/reports/routes';
import { userRoutes } from './modules/users/routes';
import { responseRoutes } from './modules/response/routes';
import { threatIntelRoutes } from './modules/threatintel/routes';
import { verificationRoutes } from './modules/verification/routes';

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({ logger: { level: config.isProd ? 'info' : 'warn' } });

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: config.corsOrigin, credentials: true });
  await app.register(rateLimit, { max: 300, timeWindow: '1 minute' });
  await app.register(jwt, { secret: config.jwtSecret as string });

  app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));
  app.get('/ready', async (_req, reply) => {
    const healthy = await dbHealthy();
    if (!healthy) {
      reply.code(503).send({ status: 'not_ready', db: false });
      return;
    }
    reply.send({ status: 'ready', db: true });
  });

  await app.register(authRoutes);
  await app.register(applicationRoutes);
  await app.register(findingRoutes);
  await app.register(incidentRoutes);
  await app.register(labRoutes);
  await app.register(streamRoutes);
  await app.register(aiRoutes);
  await app.register(verificationRoutes);
  await app.register(responseRoutes);
  await app.register(threatIntelRoutes);
  await app.register(catalogRoutes);
  await app.register(reportRoutes);
  await app.register(metricsRoutes);
  await app.register(userRoutes);
  await app.register(complianceRoutes);
  await app.register(attackMatrixRoutes);
  await app.register(socRoutes);
  await app.register(digitalTwinRoutes);

  app.setErrorHandler((err: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
    request.log.error(err);
    const status = err.statusCode ?? 500;
    reply.code(status).send({ error: status === 500 ? 'Internal server error' : err.message });
  });

  return app;
}
