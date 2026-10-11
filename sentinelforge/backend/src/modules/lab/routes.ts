import { FastifyInstance } from 'fastify';
import { Application } from '../../db/models';
import { audit } from '../../lib/audit';
import { authenticate } from '../../plugins/auth';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { runDetection } from '../detection/service';
import { ingestEvents } from '../events/ingest';

const SCENARIOS = [
  { id: '01-bruteforce', name: 'Brute Force Login' },
  { id: '02-account-takeover', name: 'Account Takeover' },
  { id: '03-idor', name: 'IDOR Enumeration' },
  { id: '04-cross-tenant-access', name: 'Cross-Tenant Attack' },
  { id: '05-privilege-escalation', name: 'Privilege Escalation' },
  { id: '07-data-exfiltration-simulation', name: 'Data Exfiltration' },
  { id: '09-business-logic-abuse', name: 'Business Logic Attack' },
];

export async function labRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/lab/scenarios', { preHandler: authenticate('read') }, async (_request, reply) => {
    reply.send(SCENARIOS);
  });

  app.post<{ Params: { id: string; scenarioId: string } }>(
    '/api/applications/:id/simulate/:scenarioId',
    { preHandler: authenticate('simulate') },
    async (request, reply) => {
      const application = await Application.findOne({ _id: request.params.id, organizationId: request.user.org });
      if (!application) {
        reply.code(404).send({ error: 'Application not found' });
        return;
      }
      const lab = new CyberLabAdapter(application.baseUrl);
      try {
        const result = await lab.runSecurityTest(request.params.scenarioId);
        // Pull the events this simulation just generated immediately and run detection right
        // away, instead of waiting for the next poll tick, so the demo feels instant.
        await ingestEvents(application.id, lab);
        const { detections, incidents } = await runDetection(application.id);
        await audit(request.user.sub, 'SIMULATION_RUN', 'application', application.id, { scenarioId: request.params.scenarioId, detections, incidents });
        reply.send({ result, detections, incidents });
      } catch (err) {
        reply.code(502).send({ error: err instanceof Error ? err.message : 'Simulation failed' });
      }
    },
  );
}
