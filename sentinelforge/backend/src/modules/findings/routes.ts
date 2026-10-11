import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Application, Correlation, Incident, RemediationTask, Vulnerability } from '../../db/models';
import { audit } from '../../lib/audit';
import { getOwnedFinding } from '../../lib/orgScope';
import { authenticate } from '../../plugins/auth';
import { rankFindingsByRisk } from './risk';

const statusSchema = z.object({ status: z.enum(['OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'FIXED', 'VERIFIED']) });

export async function findingRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/findings', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const findings = await Vulnerability.find({ applicationId: { $in: apps.map(a => a.id) } }).sort({ severity: -1, detectedAt: -1 });
    reply.send(findings.map(f => f.toJSON()));
  });

  // "Fix this first" — a single risk-ranked queue instead of three separate signals (severity,
  // EPSS, KEV) an analyst would otherwise have to mentally combine. See modules/findings/risk.ts.
  app.get('/api/findings/prioritized', { preHandler: authenticate('read') }, async (request, reply) => {
    reply.send(await rankFindingsByRisk(request.user.org));
  });

  app.get<{ Params: { id: string } }>('/api/findings/:id', { preHandler: authenticate('read') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    const correlations = await Correlation.find({ findingId: finding.id });
    const incidents = correlations.length
      ? await Incident.find({ _id: { $in: correlations.map(c => c.incidentId) } })
      : [];
    // Surfaces anything the autonomous loop (modules/autonomy/loop.ts) already proposed, so the
    // UI shows it without requiring a manual "Generate Remediation" click.
    const proposedTask = await RemediationTask.findOne({ findingId: finding.id, status: 'PROPOSED' }).sort({ createdAt: -1 });
    reply.send({
      ...finding.toJSON(),
      relatedIncidents: incidents.map(i => i.toJSON()),
      proposedRemediation: proposedTask ? proposedTask.toJSON() : null,
    });
  });

  app.patch<{ Params: { id: string } }>('/api/findings/:id', { preHandler: authenticate('scan') }, async (request, reply) => {
    const parsed = statusSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    finding.set({ status: parsed.data.status, updatedAt: new Date() });
    await finding.save();
    await audit(request.user.sub, 'FINDING_STATUS_CHANGED', 'vulnerability', finding.id, { status: parsed.data.status });
    reply.send(finding.toJSON());
  });
}
