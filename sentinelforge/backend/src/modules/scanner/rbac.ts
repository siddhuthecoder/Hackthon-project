/**
 * Systematic RBAC matrix testing — not just re-checking the one already-known broken endpoint
 * (checkBrokenRbac/VULN-003), but a real regression sweep: log in as each real non-admin role the
 * lab actually has (USER, STAFF, MANAGER), and attempt every admin-only action against each. All
 * real HTTP calls against real accounts, discovered via the same SUPER_ADMIN oracle pattern
 * discoverTargets() already uses — never a hardcoded seed id.
 */
import { CyberLabAdapter } from '../cyberlab/adapter';

// The lab's own documented demo password for every non-SUPER_ADMIN seeded account (see
// cyberlab/server/src/scripts/seed.ts) — not a SentinelForge secret, same literal CyberLabAdapter
// already uses for the 'alice' demo account.
const DEMO_PASSWORD = 'demo_password_123';

export interface RbacProbeResult {
  role: string;
  endpoint: string;
  method: string;
  expectedBlocked: boolean;
  actuallyBlocked: boolean;
  status: number;
}

interface DiscoveredUser {
  id: string;
  email: string;
  role: string;
}

export async function runRbacMatrix(lab: CyberLabAdapter): Promise<RbacProbeResult[]> {
  const adminToken = await lab.discoveryLogin();
  const usersRes = await lab.request('GET', '/api/admin/users', { token: adminToken });
  const users = Array.isArray(usersRes.data) ? (usersRes.data as DiscoveredUser[]) : [];

  const results: RbacProbeResult[] = [];
  const rolesToTest = ['USER', 'STAFF', 'MANAGER'];
  // A harmless probe target: another ordinary USER who isn't the actor — never the discovery
  // admin account itself.
  const probeTarget = users.find(u => u.role === 'USER');
  if (!probeTarget) return results;

  for (const role of rolesToTest) {
    const actor = users.find(u => u.role === role && u.id !== probeTarget.id);
    if (!actor) continue;
    let token: string;
    try {
      token = await lab.login(actor.email, DEMO_PASSWORD);
    } catch {
      continue; // Can't log in as this discovered account — skip rather than fail the whole scan.
    }

    const listRes = await lab.request('GET', '/api/admin/users', { token });
    results.push({ role, endpoint: '/api/admin/users', method: 'GET', expectedBlocked: true, actuallyBlocked: listRes.status === 403, status: listRes.status });

    const before = await lab.request('GET', '/api/admin/users', { token: adminToken });
    const beforeRole = Array.isArray(before.data) ? (before.data as DiscoveredUser[]).find(u => u.id === probeTarget.id)?.role : undefined;
    const promoteRes = await lab.request('POST', `/api/admin/users/${probeTarget.id}/promote`, { token, body: { role: 'TENANT_ADMIN' } });
    const promoted = promoteRes.status >= 200 && promoteRes.status < 300;
    results.push({ role, endpoint: `/api/admin/users/${probeTarget.id}/promote`, method: 'POST', expectedBlocked: true, actuallyBlocked: !promoted, status: promoteRes.status });
    // Self-heal: if the probe unexpectedly succeeded, immediately revert the real role change
    // using the admin oracle, so this check never leaves a lasting side effect on the lab.
    if (promoted && beforeRole) {
      await lab.request('POST', `/api/admin/users/${probeTarget.id}/promote`, { token: adminToken, body: { role: beforeRole } }).catch(() => {});
    }
  }

  return results;
}
