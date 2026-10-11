import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { ResponseAction } from '../../db/models';
import { audit } from '../../lib/audit';
import { getOwnedIncident } from '../../lib/orgScope';
import { newId } from '../../lib/util';
import { authenticate } from '../../plugins/auth';
import { createJiraTicket, jiraConfigured } from '../integrations/jira';

const ACTIONS = ['revoke_session', 'disable_user', 'mark_contained', 'create_remediation_task', 'block_ip', 'isolate_asset', 'generate_ticket'] as const;
// Per spec: no destructive automatic actions; anything beyond a status note needs explicit approval.
const HIGH_IMPACT = new Set<typeof ACTIONS[number]>(['disable_user', 'block_ip', 'isolate_asset']);

const requestSchema = z.object({ action: z.enum(ACTIONS), target: z.string().optional() });

export async function responseRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Params: { id: string } }>('/api/incidents/:id/respond', { preHandler: authenticate('respond') }, async (request, reply) => {
    const parsed = requestSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }

    const highImpact = HIGH_IMPACT.has(parsed.data.action);
    let details: Record<string, unknown> = { note: highImpact ? 'Requires explicit approval before executing (simulated action, no real system is touched).' : 'Low-impact action applied immediately (simulated).' };

    if (parsed.data.action === 'generate_ticket') {
      if (jiraConfigured()) {
        try {
          const ticket = await createJiraTicket(
            `[SentinelForge] ${incident.title}`,
            `Rule: ${incident.rule}\nSubject: ${incident.subject}\nSeverity: ${incident.severity}\nSource IP: ${incident.sourceIp ?? 'unknown'}\nDetected: ${incident.detectedAt.toISOString()}`,
          );
          details = { note: 'Real Jira ticket created.', ticketKey: ticket.key, ticketUrl: ticket.url };
        } catch (err) {
          details = { note: 'Jira ticket creation failed; see error.', error: err instanceof Error ? err.message : 'unknown error' };
        }
      } else {
        details = { note: 'Jira not configured (JIRA_SITE_URL/EMAIL/API_TOKEN/PROJECT_KEY) — simulated, no real ticket created.' };
      }
    }

    const action = await ResponseAction.create({
      _id: newId('resp'),
      incidentId: incident.id,
      action: parsed.data.action,
      target: parsed.data.target,
      status: highImpact ? 'PENDING_APPROVAL' : 'EXECUTED',
      highImpact,
      details,
      requestedBy: request.user.sub,
      executedAt: highImpact ? undefined : new Date(),
    });

    if (parsed.data.action === 'mark_contained') {
      incident.set({ status: 'CONTAINED', updatedAt: new Date() });
      await incident.save();
    }

    await audit(request.user.sub, 'RESPONSE_ACTION_REQUESTED', 'incident', incident.id, { action: parsed.data.action, highImpact });
    reply.send(action.toJSON());
  });

  app.post<{ Params: { id: string } }>('/api/response-actions/:id/approve', { preHandler: authenticate('approve_action') }, async (request, reply) => {
    const action = await ResponseAction.findById(request.params.id);
    if (!action || !(await getOwnedIncident(action.incidentId, request.user.org))) {
      reply.code(404).send({ error: 'Response action not found' });
      return;
    }
    if (action.status !== 'PENDING_APPROVAL') {
      reply.code(400).send({ error: `Action is already ${action.status}` });
      return;
    }
    action.set({ status: 'EXECUTED', approvedBy: request.user.sub, executedAt: new Date() });
    await action.save();
    await audit(request.user.sub, 'RESPONSE_ACTION_APPROVED', 'incident', action.incidentId, { action: action.action });
    reply.send(action.toJSON());
  });

  app.get<{ Params: { id: string } }>('/api/incidents/:id/response-actions', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const actions = await ResponseAction.find({ incidentId: incident.id }).sort({ createdAt: -1 });
    reply.send(actions.map(a => a.toJSON()));
  });
}
