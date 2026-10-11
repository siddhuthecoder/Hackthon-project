import { FastifyReply, FastifyRequest } from 'fastify';

export type Role = 'admin' | 'analyst' | 'viewer';

export type Permission =
  | 'read'
  | 'scan'
  | 'simulate'
  | 'investigate'
  | 'respond'
  | 'remediate'
  | 'apply_fix'
  | 'approve_action'
  | 'manage_apps'
  | 'reset';

const PERMISSIONS: Record<Role, readonly Permission[]> = {
  admin: ['read', 'scan', 'simulate', 'investigate', 'respond', 'remediate', 'apply_fix', 'approve_action', 'manage_apps', 'reset'],
  analyst: ['read', 'scan', 'simulate', 'investigate', 'respond', 'remediate', 'manage_apps'],
  viewer: ['read'],
};

export interface AuthUser {
  sub: string;
  email: string;
  name: string;
  role: Role;
  org: string;
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: AuthUser;
    user: AuthUser;
  }
}

export function can(role: Role, permission: Permission): boolean {
  return PERMISSIONS[role]?.includes(permission) ?? false;
}

export function authenticate(permission: Permission = 'read') {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      await request.jwtVerify();
    } catch {
      reply.code(401).send({ error: 'Authentication required' });
      return;
    }
    if (!can(request.user.role, permission)) {
      reply.code(403).send({ error: `Role ${request.user.role} lacks permission: ${permission}` });
    }
  };
}
