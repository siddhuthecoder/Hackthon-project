import { FastifyInstance } from 'fastify';
import { User } from '../../db/models';
import { authenticate } from '../../plugins/auth';

/** Just enough user info to populate an "assign to" dropdown — never the password hash. */
export async function userRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/org/users', { preHandler: authenticate('read') }, async (request, reply) => {
    const users = await User.find({ organizationId: request.user.org, active: true }).select('_id name email role');
    reply.send(users.map(u => ({ id: u._id, name: u.name, email: u.email, role: u.role })));
  });
}
