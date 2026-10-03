// tests/e2e/authz.test.mjs - RBAC: secure routes enforce roles, vulnerable routes don't.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, login, findUser, ADMIN, freshIp } from './helpers.mjs';

async function staffAlphaToken() {
  const staff = await findUser({ role: 'STAFF', tenantId: 'tenant-alpha' });
  assert.ok(staff, 'seed data must include a STAFF user in tenant-alpha (run scripts/seed.sh)');
  const { accessToken } = await login(staff.email, 'demo_password_123', freshIp());
  return { token: accessToken, staff };
}

test('authz: secure GET /api/admin/users denies STAFF', async () => {
  const { token } = await staffAlphaToken();
  const res = await api('/api/admin/users', { token });
  assert.equal(res.status, 403);
});

test('authz: vulnerable GET /api/admin/users/vulnerable allows STAFF (broken RBAC, VULN-003)', async () => {
  const { token } = await staffAlphaToken();
  const res = await api('/api/admin/users/vulnerable', { token });
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.body.users));
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_BROKEN_RBAC');
});

test('authz: secure DELETE /api/admin/users/:id denies STAFF', async () => {
  const { token, staff } = await staffAlphaToken();
  const res = await api(`/api/admin/users/${staff.id}`, { method: 'DELETE', token });
  assert.equal(res.status, 403);
});

test('authz: secure POST /api/admin/users/:id/promote denies STAFF', async () => {
  const { token, staff } = await staffAlphaToken();
  const res = await api(`/api/admin/users/${staff.id}/promote`, { method: 'POST', token, body: { role: 'MANAGER' } });
  assert.equal(res.status, 403);
});

test('authz: JWT-trust endpoint /api/vulnerable/admin denies a non-admin role claim', async () => {
  const { token } = await staffAlphaToken();
  const res = await api('/api/vulnerable/admin', { token });
  assert.equal(res.status, 403);
  assert.equal(res.body.authorized, false);
});

test('authz: SUPER_ADMIN can use both the vulnerable and secure admin-claim endpoints', async () => {
  const { accessToken } = await login(ADMIN.email, ADMIN.password, freshIp());
  const vuln = await api('/api/vulnerable/admin', { token: accessToken });
  assert.equal(vuln.status, 200);
  const secure = await api('/api/vulnerable/admin/secure', { token: accessToken });
  assert.equal(secure.status, 200);
});

test('authz: GET /api/users (admin list) denies plain USER role', async () => {
  const { accessToken } = await login('alice.anderson@tenant.alpha.com', 'demo_password_123', freshIp());
  const res = await api('/api/users', { token: accessToken });
  assert.equal(res.status, 403);
});
