import { describe, expect, it } from 'vitest';
import { CHECKS } from '../src/modules/scanner/checks';
import { CyberLabAdapter } from '../src/modules/cyberlab/adapter';

// CHECKS is a fixed-order array (checks.ts), not individually exported by name — indices below
// are a known contract with that file (checkIdor=0, checkCrossTenant=1), documented here rather
// than refactoring 14 check functions into named exports for a handful of tests.
const [checkIdor, checkCrossTenant] = CHECKS;

interface MockResponse { status: number; data: unknown }

function mockAdapter(responses: Record<string, MockResponse>): CyberLabAdapter {
  return {
    request: async (_method: string, path: string) => responses[path] ?? { status: 404, data: {} },
  } as unknown as CyberLabAdapter;
}

const baseCtx = {
  aliceToken: 'fake-token',
  aliceUserId: 'user-101',
  aliceEmail: 'alice.anderson@tenant.alpha.com',
  aliceTenantId: 'tenant-alpha',
};

describe('scanner checks (VULN-001, VULN-002) — pure logic, mocked HTTP', () => {
  it('checkIdor reports VULNERABLE when both own and other profile return 200', async () => {
    const lab = mockAdapter({
      '/api/users/user-101': { status: 200, data: { id: 'user-101' } },
      '/api/users/user-102': { status: 200, data: { id: 'user-102', name: 'Bob' } },
    });
    const result = await checkIdor({ lab, ...baseCtx, targetUser: { id: 'user-102', email: 'bob@tenant.alpha.com' } });
    expect(result.outcome).toBe('VULNERABLE');
    expect(result.vulnKey).toBe('VULN-001');
  });

  it('checkIdor reports NOT_VULNERABLE when the other profile is blocked', async () => {
    const lab = mockAdapter({
      '/api/users/user-101': { status: 200, data: { id: 'user-101' } },
      '/api/users/user-102': { status: 403, data: { error: 'Access denied' } },
    });
    const result = await checkIdor({ lab, ...baseCtx, targetUser: { id: 'user-102', email: 'bob@tenant.alpha.com' } });
    expect(result.outcome).toBe('NOT_VULNERABLE');
  });

  it('checkIdor reports SKIPPED when no second user was discovered', async () => {
    const lab = mockAdapter({});
    const result = await checkIdor({ lab, ...baseCtx, targetUser: undefined });
    expect(result.outcome).toBe('SKIPPED');
  });

  it('checkCrossTenant reports VULNERABLE only when the other order belongs to a different tenant', async () => {
    const lab = mockAdapter({
      '/api/orders/order-2': { status: 200, data: { id: 'order-2', tenantId: 'tenant-beta' } },
    });
    const result = await checkCrossTenant({ lab, ...baseCtx, crossTenantOrder: { id: 'order-2', tenantId: 'tenant-beta' } });
    expect(result.outcome).toBe('VULNERABLE');
  });

  it('checkCrossTenant reports NOT_VULNERABLE when the other order is actually blocked', async () => {
    const lab = mockAdapter({
      '/api/orders/order-2': { status: 403, data: {} },
    });
    const result = await checkCrossTenant({ lab, ...baseCtx, crossTenantOrder: { id: 'order-2', tenantId: 'tenant-beta' } });
    expect(result.outcome).toBe('NOT_VULNERABLE');
  });

  it('checkCrossTenant reports SKIPPED when no cross-tenant order was discovered', async () => {
    const lab = mockAdapter({});
    const result = await checkCrossTenant({ lab, ...baseCtx, crossTenantOrder: undefined });
    expect(result.outcome).toBe('SKIPPED');
  });
});
