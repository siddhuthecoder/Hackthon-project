import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AttackPath, Application, Correlation, Incident, IncidentComment, SecurityEvent, User, Vulnerability } from '../../db/models';
import { audit } from '../../lib/audit';
import { getOwnedIncident } from '../../lib/orgScope';
import { newId } from '../../lib/util';
import { authenticate } from '../../plugins/auth';
import { checkIpReputation } from '../threatintel/abuseipdb';
import { confluenceConfigured, createConfluencePage } from '../integrations/confluence';
import { buildPostmortemBody } from '../reports/postmortem';

const statusSchema = z.object({ status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']) });
const assignSchema = z.object({ userId: z.string().nullable() });
const commentSchema = z.object({ text: z.string().min(1).max(2000) });

export async function incidentRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/incidents', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const incidents = await Incident.find({ applicationId: { $in: apps.map(a => a.id) } }).sort({ detectedAt: -1 }).limit(200);
    reply.send(incidents.map(i => i.toJSON()));
  });

  app.get<{ Params: { id: string } }>('/api/incidents/:id', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const events = await SecurityEvent.find({ _id: { $in: incident.eventIds } }).sort({ timestamp: 1 });
    const correlations = await Correlation.find({ incidentId: incident.id });
    const findings = correlations.length
      ? await Vulnerability.find({ _id: { $in: correlations.map(c => c.findingId) } })
      : [];
    reply.send({
      ...incident.toJSON(),
      events: events.map(e => e.toJSON()),
      correlations: correlations.map(c => c.toJSON()),
      findings: findings.map(f => f.toJSON()),
    });
  });

  // Real IP-reputation lookup for the incident's source IP — fetched live (not cached/stored)
  // since it's about the actual attacking address, not a scan-time finding. See
  // modules/threatintel/abuseipdb.ts for why private/simulated-lab IPs report isPublic: false
  // instead of a fabricated score.
  app.get<{ Params: { id: string } }>('/api/incidents/:id/ip-reputation', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    if (!incident.sourceIp) {
      reply.send({ available: false, reason: 'Incident has no recorded source IP.' });
      return;
    }
    const reputation = await checkIpReputation(incident.sourceIp);
    if (!reputation) {
      reply.send({ available: false, reason: 'AbuseIPDB unavailable or not configured.' });
      return;
    }
    reply.send({ available: true, ...reputation });
  });

  // Publishes a real postmortem page to Confluence. Title includes the incident id + timestamp
  // because Confluence requires titles to be unique within a space (re-publishing creates a new
  // revision-in-name rather than failing).
  app.post<{ Params: { id: string } }>('/api/incidents/:id/postmortem', { preHandler: authenticate('respond') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    if (!confluenceConfigured()) {
      reply.code(400).send({ error: 'Confluence not configured (JIRA_SITE_URL/EMAIL/API_TOKEN + CONFLUENCE_SPACE_ID).' });
      return;
    }
    try {
      const body = await buildPostmortemBody(incident);
      const title = `Postmortem: ${incident.title} (${incident.id}, ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC)`;
      const page = await createConfluencePage(title, body);
      incident.set({ postmortemUrl: page.url, updatedAt: new Date() });
      await incident.save();
      await audit(request.user.sub, 'POSTMORTEM_PUBLISHED', 'incident', incident.id, { pageId: page.id });
      reply.send(page);
    } catch (err) {
      reply.code(502).send({ error: err instanceof Error ? err.message : 'Could not publish postmortem' });
    }
  });

  app.get<{ Params: { id: string } }>('/api/incidents/:id/attack-graph', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const path = await AttackPath.findOne({ incidentId: incident.id });
    if (!path) {
      reply.send({ nodes: [], edges: [], summary: '' });
      return;
    }
    reply.send(path.toJSON());
  });

  app.patch<{ Params: { id: string } }>('/api/incidents/:id', { preHandler: authenticate('respond') }, async (request, reply) => {
    const parsed = statusSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    incident.set({ status: parsed.data.status, updatedAt: new Date() });
    await incident.save();
    await audit(request.user.sub, 'INCIDENT_STATUS_CHANGED', 'incident', incident.id, { status: parsed.data.status });
    reply.send(incident.toJSON());
  });

  app.patch<{ Params: { id: string } }>('/api/incidents/:id/assign', { preHandler: authenticate('respond') }, async (request, reply) => {
    const parsed = assignSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    let assignedToName: string | undefined;
    if (parsed.data.userId) {
      const assignee = await User.findOne({ _id: parsed.data.userId, organizationId: request.user.org });
      if (!assignee) {
        reply.code(404).send({ error: 'User not found' });
        return;
      }
      assignedToName = assignee.name;
    }
    incident.set({ assignedTo: parsed.data.userId ?? undefined, assignedToName, updatedAt: new Date() });
    await incident.save();
    await audit(request.user.sub, 'INCIDENT_ASSIGNED', 'incident', incident.id, { assignedTo: parsed.data.userId });
    reply.send(incident.toJSON());
  });

  app.get<{ Params: { id: string } }>('/api/incidents/:id/comments', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const comments = await IncidentComment.find({ incidentId: incident.id }).sort({ createdAt: 1 });
    reply.send(comments.map(c => c.toJSON()));
  });

  app.post<{ Params: { id: string } }>('/api/incidents/:id/comments', { preHandler: authenticate('respond') }, async (request, reply) => {
    const parsed = commentSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const comment = await IncidentComment.create({
      _id: newId('comment'), incidentId: incident.id,
      authorId: request.user.sub, authorName: request.user.name, text: parsed.data.text,
    });
    reply.code(201).send(comment.toJSON());
  });
}
