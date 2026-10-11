import bcrypt from 'bcryptjs';
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { User } from '../../db/models';
import { audit } from '../../lib/audit';
import { authenticate } from '../../plugins/auth';

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

export async function authRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/auth/login', async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: 'Invalid credentials payload' });
      return;
    }
    const { email, password } = parsed.data;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.active || !bcrypt.compareSync(password, user.passwordHash)) {
      await audit(null, 'LOGIN_FAILED', 'user', null, { email }, request.ip);
      reply.code(401).send({ error: 'Invalid email or password' });
      return;
    }

    const token = app.jwt.sign(
      { sub: user.id, email: user.email, name: user.name, role: user.role, org: user.organizationId },
      { expiresIn: '12h' },
    );
    await audit(user.id, 'LOGIN', 'user', user.id, {}, request.ip);
    reply.send({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  });

  app.get('/api/auth/me', { preHandler: authenticate('read') }, async (request, reply) => {
    reply.send({ user: request.user });
  });
}
