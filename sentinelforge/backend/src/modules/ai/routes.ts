import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Application, Vulnerability } from '../../db/models';
import { audit } from '../../lib/audit';
import { getOwnedFinding, getOwnedIncident } from '../../lib/orgScope';
import { authenticate } from '../../plugins/auth';
import {
  AttackPathAgent, CorrelationAgent, ReconAgent, RedTeamAgent, RemediationAgent, ThreatIntelAgent, VulnerabilityAgent,
  InvestigationAgent,
} from './agents';
import { callStructured } from './client';
import { runAgent } from './orchestrator';
import { openRemediationPr, PatchUnavailableError, RepoUnavailableError } from '../remediation/githubPr';
import { RemediationTask } from '../../db/models';
import { newId } from '../../lib/util';

const askSchema = z.object({
  question: z.string().min(1),
  incidentId: z.string().optional(),
  findingId: z.string().optional(),
  history: z.array(z.object({ question: z.string(), answer: z.string() })).max(10).optional(),
});

export async function aiRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Params: { id: string } }>('/api/findings/:id/analyze', { preHandler: authenticate('investigate') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('VulnerabilityAgent', 'vulnerability', finding.id, { findingId: finding.id }, VulnerabilityAgent);
      await Vulnerability.findByIdAndUpdate(finding.id, { aiAnalysis: { ...output, mode, generatedAt: new Date().toISOString() } });
      await audit(request.user.sub, 'FINDING_ANALYZED', 'vulnerability', finding.id, { mode });
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Finding not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/findings/:id/remediate', { preHandler: authenticate('remediate') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('RemediationAgent', 'vulnerability', finding.id, { findingId: finding.id }, RemediationAgent);
      await audit(request.user.sub, 'REMEDIATION_GENERATED', 'vulnerability', finding.id, { mode });
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Finding not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/findings/:id/open-pr', { preHandler: authenticate('apply_fix') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    try {
      const { output: plan } = await runAgent('RemediationAgent', 'vulnerability', finding.id, { findingId: finding.id }, RemediationAgent);
      const pr = await openRemediationPr(finding, plan, request.user.sub);
      await RemediationTask.create({
        _id: newId('rem'), findingId: finding.id, status: 'PROPOSED',
        plan: { vulnKey: finding.vulnKey, action: 'github-pr', prUrl: pr.url, branch: pr.branch, file: pr.file },
      });
      await audit(request.user.sub, 'REMEDIATION_PR_OPENED', 'vulnerability', finding.id, { prUrl: pr.url });
      reply.send(pr);
    } catch (err) {
      const status = err instanceof PatchUnavailableError || err instanceof RepoUnavailableError ? 400 : 502;
      reply.code(status).send({ error: err instanceof Error ? err.message : 'Could not open PR' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/findings/:id/threat-intel', { preHandler: authenticate('read') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('ThreatIntelAgent', 'vulnerability', finding.id, { findingId: finding.id }, ThreatIntelAgent);
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Finding not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/incidents/:id/investigate', { preHandler: authenticate('investigate') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('InvestigationAgent', 'incident', incident.id, { incidentId: incident.id }, InvestigationAgent);
      incident.set({ investigation: { ...output, mode, generatedAt: new Date().toISOString() }, updatedAt: new Date() });
      if (incident.status === 'OPEN') incident.set({ status: 'INVESTIGATING' });
      await incident.save();
      await audit(request.user.sub, 'INCIDENT_INVESTIGATED', 'incident', incident.id, { mode });
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Incident not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/incidents/:id/correlation', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('CorrelationAgent', 'incident', incident.id, { incidentId: incident.id }, CorrelationAgent);
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Incident not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/incidents/:id/attack-path-narrative', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    try {
      const { output, mode } = await runAgent('AttackPathAgent', 'incident', incident.id, { incidentId: incident.id }, AttackPathAgent);
      reply.send({ ...output, mode });
    } catch (err) {
      reply.code(404).send({ error: err instanceof Error ? err.message : 'Incident not found' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/applications/:id/recon', { preHandler: authenticate('read') }, async (request, reply) => {
    const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    const { output, mode } = await runAgent('ReconAgent', 'application', request.params.id, { applicationId: request.params.id }, ReconAgent);
    reply.send({ ...output, mode });
  });

  // Autonomous red-team chain narrative — see docs comment on RedTeamAgent in agents.ts for
  // exactly what's real (the cited findings) vs. narrated (the ordering/escalation story).
  app.post<{ Params: { id: string } }>('/api/applications/:id/red-team', { preHandler: authenticate('investigate') }, async (request, reply) => {
    const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    const { output, mode } = await runAgent('RedTeamAgent', 'application', application.id, { applicationId: application.id }, RedTeamAgent);
    await audit(request.user.sub, 'RED_TEAM_CHAIN_RUN', 'application', application.id, { mode, stepCount: output.chainSteps.length });
    reply.send({ ...output, mode });
  });

  app.post('/api/assistant/ask', { preHandler: authenticate('read') }, async (request, reply) => {
    const parsed = askSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const { question, incidentId, findingId, history } = parsed.data;

    const context: Record<string, unknown> = {};
    if (incidentId) {
      const incident = await getOwnedIncident(incidentId, request.user.org);
      if (incident) context.incident = incident.toJSON();
    }
    if (findingId) {
      const finding = await getOwnedFinding(findingId, request.user.org);
      if (finding) context.finding = finding.toJSON();
    }
    if (Object.keys(context).length === 0) {
      reply.code(400).send({ error: 'Provide incidentId or findingId so the assistant has real data to answer from.' });
      return;
    }
    if (history && history.length > 0) context.conversationSoFar = history;

    const { data, mode } = await callStructured<{ question: string; context: Record<string, unknown> }, { answer: string }>(
      'You are SentinelForge\'s assistant. Answer the question using ONLY the provided context JSON. If the context does not contain the answer, say so plainly instead of guessing. Return strict JSON: { "answer": string }.',
      { question, context },
      (askInput: { question: string; context: Record<string, unknown> }) => ({ answer: `Offline mode: here is the raw data for your question — ${JSON.stringify(askInput.context).slice(0, 800)}` }),
    );
    reply.send({ answer: data.answer, mode });
  });
}
