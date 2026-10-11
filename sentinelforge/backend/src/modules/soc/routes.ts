import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate } from '../../plugins/auth';
import { runThreatHunt } from './hunt';

const huntSchema = z.object({ question: z.string().min(1).max(500) });

export async function socRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/soc/hunt', { preHandler: authenticate('read') }, async (request, reply) => {
    const parsed = huntSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: parsed.error.message });
      return;
    }
    const result = await runThreatHunt(request.user.org, parsed.data.question);
    reply.send({
      filter: result.filter,
      matchedCount: result.matchedCount,
      events: result.events.map(e => e.toJSON()),
      summary: result.summary,
      mode: result.mode,
    });
  });
}
