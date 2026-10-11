import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Application, Asset, Endpoint, ScanRun } from '../../db/models';
import { audit } from '../../lib/audit';
import { newId } from '../../lib/util';
import { authenticate } from '../../plugins/auth';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { computePostureMetricsForApps } from '../metrics/routes';
import { runGenericScan, runJuiceShopScan, runScan } from '../scanner/service';
import { GenericAdapter } from '../targets/generic/adapter';
import { JuiceShopAdapter } from '../targets/juiceshop/adapter';

const createSchema = z.object({
  name: z.string().min(1),
  baseUrl: z.string().url(),
  environment: z.string().default('local'),
  repository: z.string().optional(),
  adapter: z.enum(['cyberlab', 'juiceshop', 'generic']).default('cyberlab'),
  config: z.object({
    openapiUrl: z.string().url().optional(),
    authHeaderName: z.string().optional(),
    authHeaderValue: z.string().optional(),
  }).optional(),
  scanIntervalMinutes: z.number().int().positive().optional(),
});

const testConnectionSchema = z.object({
  baseUrl: z.string().url(),
  adapter: z.enum(['cyberlab', 'juiceshop', 'generic']).default('cyberlab'),
  config: z.object({
    openapiUrl: z.string().url().optional(),
    authHeaderName: z.string().optional(),
    authHeaderValue: z.string().optional(),
  }).optional(),
});

function buildAdapter(adapterKind: string, baseUrl: string, cfg: Record<string, unknown>): CyberLabAdapter | JuiceShopAdapter | GenericAdapter {
  if (adapterKind === 'juiceshop') return new JuiceShopAdapter(baseUrl);
  if (adapterKind === 'generic') return new GenericAdapter(baseUrl, cfg);
  return new CyberLabAdapter(baseUrl);
}

// Juice Shop's own real endpoints used by the 2 checks here (docs/SECOND-TARGET.md) — a smaller
// list than CyberLab's since this target exists to prove the adapter pattern, not to be a second
// full demo.
const JUICESHOP_KNOWN_ENDPOINTS: { method: string; path: string; authRequired: boolean }[] = [
  { method: 'POST', path: '/rest/user/login', authRequired: false },
  { method: 'POST', path: '/api/Users', authRequired: false },
  { method: 'GET', path: '/rest/user/whoami', authRequired: true },
  { method: 'GET', path: '/api/Users/:id', authRequired: true },
];

// Endpoints SentinelForge knows CyberLab exposes, from reading its route files directly
// (docs/CYBERLAB-INTEGRATION-MAP.md). Used to populate asset/endpoint inventory on discovery
// without guessing — these are the real routes mounted in cyberlab/server/src/index.ts.
const KNOWN_ENDPOINTS: { method: string; path: string; authRequired: boolean }[] = [
  { method: 'POST', path: '/api/auth/login', authRequired: false },
  { method: 'GET', path: '/api/auth/me', authRequired: true },
  { method: 'GET', path: '/api/users/:userId', authRequired: true },
  { method: 'GET', path: '/api/users/secure/:userId', authRequired: true },
  { method: 'PATCH', path: '/api/users/:id', authRequired: true },
  { method: 'GET', path: '/api/orders/:orderId', authRequired: true },
  { method: 'GET', path: '/api/orders/secure/:orderId', authRequired: true },
  { method: 'POST', path: '/api/payments', authRequired: true },
  { method: 'POST', path: '/api/payments/secure', authRequired: true },
  { method: 'GET', path: '/api/admin/users', authRequired: true },
  { method: 'GET', path: '/api/admin/users/vulnerable', authRequired: true },
  { method: 'GET', path: '/api/vulnerable/admin', authRequired: true },
  { method: 'POST', path: '/api/comments', authRequired: true },
  { method: 'POST', path: '/api/fetch-url', authRequired: true },
  { method: 'GET', path: '/api/files/download', authRequired: true },
  { method: 'POST', path: '/api/files/upload', authRequired: true },
  { method: 'POST', path: '/api/tools/ping', authRequired: true },
  { method: 'GET', path: '/api/security/events', authRequired: false },
  { method: 'POST', path: '/api/security/simulate/:scenarioId', authRequired: false },
];

export async function applicationRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/applications', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).sort({ createdAt: -1 });
    reply.send(apps.map(a => a.toJSON()));
  });

  app.get<{ Params: { id: string } }>('/api/applications/:id', { preHandler: authenticate('read') }, async (request, reply) => {
    const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    const [assets, endpoints, scanRuns] = await Promise.all([
      Asset.find({ applicationId: application.id }),
      Endpoint.find({ applicationId: application.id }),
      ScanRun.find({ applicationId: application.id }).sort({ startedAt: -1 }).limit(20),
    ]);
    reply.send({
      ...application.toJSON(),
      assets: assets.map(a => a.toJSON()),
      endpoints: endpoints.map(e => e.toJSON()),
      scanRuns: scanRuns.map(s => s.toJSON()),
    });
  });

  // Side-by-side posture for N targets — proves the adapter pattern visually (CyberLab vs Juice
  // Shop, or any mix including generic targets) instead of only in docs.
  app.get<{ Querystring: { ids?: string } }>('/api/applications/compare', { preHandler: authenticate('read') }, async (request, reply) => {
    const ids = (request.query.ids ?? '').split(',').map(s => s.trim()).filter(Boolean);
    if (ids.length === 0) {
      reply.code(400).send({ error: 'Provide ?ids=appId1,appId2' });
      return;
    }
    const apps = await Application.find({ _id: { $in: ids }, organizationId: request.user.org });
    const results = await Promise.all(apps.map(async a => ({
      application: a.toJSON(),
      metrics: await computePostureMetricsForApps([a.id]),
    })));
    reply.send(results);
  });

  app.get('/api/scans', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const scanRuns = await ScanRun.find({ applicationId: { $in: apps.map(a => a.id) } }).sort({ startedAt: -1 }).limit(100);
    reply.send(scanRuns.map(s => s.toJSON()));
  });

  // Live connectivity check before saving anything — real onboarding tools (Intruder.io,
  // Detectify) test the target before committing a record, instead of saving blind and finding
  // out it's unreachable on the first scan attempt.
  app.post('/api/applications/test-connection', { preHandler: authenticate('manage_apps') }, async (request, reply) => {
    const parsed = testConnectionSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const adapter = buildAdapter(parsed.data.adapter, parsed.data.baseUrl, parsed.data.config ?? {});
    const health = await adapter.getHealth();
    if (!health.ok) {
      reply.send({ ok: false, detail: health.detail });
      return;
    }
    if (parsed.data.adapter === 'generic' && parsed.data.config?.openapiUrl) {
      try {
        const endpoints = await (adapter as GenericAdapter).discoverFromOpenApi();
        reply.send({ ok: true, detail: health.detail, endpointPreviewCount: endpoints.length });
        return;
      } catch (err) {
        reply.send({ ok: false, detail: `Reachable, but OpenAPI spec could not be parsed: ${err instanceof Error ? err.message : 'unknown error'}` });
        return;
      }
    }
    reply.send({ ok: true, detail: health.detail });
  });

  app.post('/api/applications', { preHandler: authenticate('manage_apps') }, async (request, reply) => {
    const parsed = createSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const app_ = await Application.create({
      _id: newId('app'),
      organizationId: request.user.org,
      name: parsed.data.name,
      baseUrl: parsed.data.baseUrl,
      environment: parsed.data.environment,
      repository: parsed.data.repository,
      adapter: parsed.data.adapter,
      config: parsed.data.config ?? {},
      scanIntervalMinutes: parsed.data.scanIntervalMinutes,
      status: 'REGISTERED',
    });
    await audit(request.user.sub, 'APPLICATION_CREATED', 'application', app_.id, { name: app_.name });
    reply.code(201).send(app_.toJSON());
  });

  app.post<{ Params: { id: string } }>('/api/applications/:id/discover', { preHandler: authenticate('manage_apps') }, async (request, reply) => {
    const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    const isJuiceShop = application.adapter === 'juiceshop';
    const isGeneric = application.adapter === 'generic';
    const adapter = buildAdapter(application.adapter, application.baseUrl, application.config ?? {});
    const health = await adapter.getHealth();
    if (!health.ok) {
      reply.code(502).send({ error: 'Target unreachable', detail: health.detail });
      return;
    }

    let endpointList: { method: string; path: string; authRequired: boolean }[];
    if (isGeneric) {
      try {
        endpointList = await (adapter as GenericAdapter).discoverFromOpenApi();
      } catch (err) {
        reply.code(502).send({ error: err instanceof Error ? err.message : 'Could not parse OpenAPI spec' });
        return;
      }
    } else {
      endpointList = isJuiceShop ? JUICESHOP_KNOWN_ENDPOINTS : KNOWN_ENDPOINTS;
    }
    const assetName = isGeneric ? 'generic-api' : isJuiceShop ? 'juiceshop-api' : 'cyberlab-api';
    const assetId = newId('asset');
    const existingAsset = await Asset.findOneAndUpdate(
      { applicationId: application.id, kind: 'service', name: assetName },
      { $setOnInsert: { _id: assetId, applicationId: application.id, kind: 'service', name: assetName, details: { baseUrl: application.baseUrl } } },
      { upsert: true, new: true },
    );

    let created = 0;
    for (const ep of endpointList) {
      const exists = await Endpoint.findOne({ applicationId: application.id, method: ep.method, path: ep.path });
      if (exists) continue;
      await Endpoint.create({ _id: newId('ep'), applicationId: application.id, assetId: existingAsset.id, method: ep.method, path: ep.path, authRequired: ep.authRequired, source: 'discovery' });
      created += 1;
    }

    application.set({ status: 'DISCOVERED', discoveredAt: new Date(), discovered: { endpointCount: endpointList.length } });
    await application.save();
    await audit(request.user.sub, 'APPLICATION_DISCOVERED', 'application', application.id, { endpointCount: endpointList.length, created });

    reply.send({ application: application.toJSON(), endpointCount: endpointList.length, newlyCreated: created });
  });

  app.post<{ Params: { id: string } }>('/api/applications/:id/scan', { preHandler: authenticate('scan') }, async (request, reply) => {
    const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    try {
      const { scanRunId, results, diff } = application.adapter === 'juiceshop'
        ? await runJuiceShopScan(application.id, new JuiceShopAdapter(application.baseUrl), request.user.sub, application.name)
        : application.adapter === 'generic'
          ? await runGenericScan(application.id, new GenericAdapter(application.baseUrl, application.config ?? {}), request.user.sub, application.name)
          : await runScan(application.id, new CyberLabAdapter(application.baseUrl), request.user.sub, application.name);
      await audit(request.user.sub, 'SCAN_RUN', 'application', application.id, { scanRunId, vulnerable: results.filter(r => r.outcome === 'VULNERABLE').length });
      reply.send({ scanRunId, total: results.length, vulnerable: results.filter(r => r.outcome === 'VULNERABLE').length, results, diff });
    } catch (err) {
      reply.code(502).send({ error: err instanceof Error ? err.message : 'Scan failed' });
    }
  });
}
