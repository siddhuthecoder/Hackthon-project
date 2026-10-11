/**
 * Read-only listing endpoints that the original 8-page frontend didn't need (their data was
 * reachable through an application/finding/incident detail view) but the master spec's full page
 * list calls for as standalone views: /assets, /events, /audit-logs, /remediation, /verification.
 */
import { FastifyInstance } from 'fastify';
import {
  Application, Asset, AuditLog, RemediationTask, SecurityEvent, VerificationRun,
} from '../../db/models';
import { authenticate } from '../../plugins/auth';

export async function catalogRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/assets', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const assets = await Asset.find({ applicationId: { $in: apps.map(a => a.id) } }).sort({ createdAt: -1 });
    reply.send(assets.map(a => a.toJSON()));
  });

  app.get('/api/events', { preHandler: authenticate('read') }, async (request, reply) => {
    const limit = Math.min(Number((request.query as { limit?: string }).limit) || 100, 500);
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const events = await SecurityEvent.find({ applicationId: { $in: apps.map(a => a.id) } }).sort({ timestamp: -1 }).limit(limit);
    reply.send(events.map(e => e.toJSON()));
  });

  app.get('/api/audit-logs', { preHandler: authenticate('read') }, async (request, reply) => {
    const limit = Math.min(Number((request.query as { limit?: string }).limit) || 100, 500);
    const logs = await AuditLog.find({}).sort({ timestamp: -1 }).limit(limit);
    reply.send(logs.map(l => l.toJSON()));
  });

  app.get('/api/remediation-tasks', { preHandler: authenticate('read') }, async (_request, reply) => {
    const tasks = await RemediationTask.find({}).sort({ createdAt: -1 }).limit(200);
    reply.send(tasks.map(t => t.toJSON()));
  });

  app.get('/api/verification-runs', { preHandler: authenticate('read') }, async (_request, reply) => {
    const runs = await VerificationRun.find({}).sort({ createdAt: -1 }).limit(200);
    reply.send(runs.map(r => r.toJSON()));
  });
}
