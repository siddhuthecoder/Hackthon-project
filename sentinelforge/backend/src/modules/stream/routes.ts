import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { config } from '../../config';
import { subscribe } from '../../lib/bus';
import { AuthUser } from '../../plugins/auth';

const querySchema = z.object({ token: z.string().min(1) });

/**
 * Server-Sent Events feed for the live SOC view. EventSource cannot set an Authorization header,
 * so the JWT is passed as a query param here only (never logged, short-lived token).
 */
export async function streamRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/stream', async (request, reply) => {
    const parsed = querySchema.safeParse(request.query);
    if (!parsed.success) {
      reply.code(400).send({ error: 'token query param required' });
      return;
    }
    try {
      app.jwt.verify<AuthUser>(parsed.data.token);
    } catch {
      reply.code(401).send({ error: 'Invalid token' });
      return;
    }

    // Writing the raw response directly (needed for a streaming SSE body) bypasses Fastify's
    // normal reply pipeline, so the @fastify/cors plugin never gets a chance to set
    // Access-Control-Allow-Origin on this response — set it by hand here.
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': config.corsOrigin,
    });
    reply.raw.write(': connected\n\n');

    const unsubscribe = subscribe(message => {
      reply.raw.write(`event: ${message.topic}\ndata: ${JSON.stringify(message)}\n\n`);
    });

    const heartbeat = setInterval(() => reply.raw.write(': ping\n\n'), 20000);

    request.raw.on('close', () => {
      clearInterval(heartbeat);
      unsubscribe();
    });
  });
}
