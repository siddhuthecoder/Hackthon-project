import { FastifyInstance } from 'fastify';
import { Application, Vulnerability } from '../../db/models';
import { audit } from '../../lib/audit';
import { authenticate } from '../../plugins/auth';
import { VerificationAgent } from '../ai/agents';
import { runAgent } from '../ai/orchestrator';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { applyFix, revertFix, VERIFIABLE_VULN_KEYS } from './service';

export async function verificationRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Params: { id: string } }>('/api/findings/:id/apply-fix', { preHandler: authenticate('apply_fix') }, async (request, reply) => {
    const finding = await Vulnerability.findById(request.params.id);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    const application = await Application.findOne({ _id: finding.applicationId, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    try {
      const lab = new CyberLabAdapter(application.baseUrl);
      await applyFix(finding, lab, request.user.sub);
      await audit(request.user.sub, 'FIX_APPLIED', 'vulnerability', finding.id, {});
      reply.send(finding.toJSON());
    } catch (err) {
      reply.code(502).send({ error: err instanceof Error ? err.message : 'Apply fix failed' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/findings/:id/revert-fix', { preHandler: authenticate('apply_fix') }, async (request, reply) => {
    const finding = await Vulnerability.findById(request.params.id);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    const application = await Application.findOne({ _id: finding.applicationId, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    const lab = new CyberLabAdapter(application.baseUrl);
    await revertFix(finding, lab);
    await audit(request.user.sub, 'FIX_REVERTED', 'vulnerability', finding.id, {});
    reply.send(finding.toJSON());
  });

  app.post<{ Params: { id: string } }>('/api/findings/:id/verify', { preHandler: authenticate('apply_fix') }, async (request, reply) => {
    const finding = await Vulnerability.findById(request.params.id);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    if (!VERIFIABLE_VULN_KEYS.includes(finding.vulnKey)) {
      reply.code(400).send({ error: `No verification probe implemented for ${finding.vulnKey}` });
      return;
    }
    const application = await Application.findOne({ _id: finding.applicationId, organizationId: request.user.org });
    if (!application) {
      reply.code(404).send({ error: 'Application not found' });
      return;
    }
    try {
      const { output: result } = await runAgent(
        'VerificationAgent', 'vulnerability', finding.id,
        { findingId: finding.id, applicationBaseUrl: application.baseUrl, actor: request.user.sub },
        VerificationAgent,
      );
      await audit(request.user.sub, 'FIX_VERIFIED', 'vulnerability', finding.id, { passed: result.passed });
      reply.send(result);
    } catch (err) {
      reply.code(502).send({ error: err instanceof Error ? err.message : 'Verification failed' });
    }
  });
}
