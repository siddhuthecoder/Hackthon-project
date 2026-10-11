import { FastifyInstance } from 'fastify';
import { IThreatIndicator, ThreatIndicator } from '../../db/models';
import { authenticate } from '../../plugins/auth';

export async function threatIntelRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/threat-intel', { preHandler: authenticate('read') }, async (_request, reply) => {
    const indicators = await ThreatIndicator.find({}).sort({ value: 1 });
    reply.send(indicators.map((i: IThreatIndicator) => i.toJSON()));
  });

  app.get<{ Params: { value: string } }>('/api/threat-intel/:value', { preHandler: authenticate('read') }, async (request, reply) => {
    const indicator = await ThreatIndicator.findOne({ kind: 'cwe', value: request.params.value });
    if (!indicator) {
      reply.code(404).send({ error: 'No threat indicator for this CWE' });
      return;
    }
    reply.send(indicator.toJSON());
  });
}
