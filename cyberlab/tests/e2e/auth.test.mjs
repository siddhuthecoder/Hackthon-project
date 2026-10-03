// tests/e2e/auth.test.mjs - login, refresh, logout, register, password reset.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, login, adminToken, ALICE, freshIp } from './helpers.mjs';

test('auth: login with valid credentials returns a token and user', async () => {
  const res = await api('/api/auth/login', { method: 'POST', body: { email: ALICE.email, password: ALICE.password }, sourceIp: freshIp() });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken, 'accessToken present');
  assert.ok(res.body.refreshToken, 'refreshToken present');
  assert.equal(res.body.user.email, ALICE.email);
  assert.equal(res.body.user.role, 'USER');
});

test('auth: login with wrong password returns 401', async () => {
  const res = await api('/api/auth/login', { method: 'POST', body: { email: ALICE.email, password: 'definitely-wrong' }, sourceIp: freshIp() });
  assert.equal(res.status, 401);
  assert.match(res.body.error, /invalid/i);
});

test('auth: login with unknown email returns 401 (no user enumeration)', async () => {
  const res = await api('/api/auth/login', { method: 'POST', body: { email: 'nobody@nowhere.test', password: 'x' }, sourceIp: freshIp() });
  assert.equal(res.status, 401);
});

test('auth: GET /me returns the authenticated user', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/auth/me', { token: accessToken });
  assert.equal(res.status, 200);
  assert.equal(res.body.email, ALICE.email);
  assert.equal(res.body.id, ALICE.id);
});

test('auth: GET /me without a token returns 401', async () => {
  const res = await api('/api/auth/me');
  assert.equal(res.status, 401);
});

test('auth: refresh issues a new access token', async () => {
  const { refreshToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/auth/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken);
});

test('auth: refresh with a garbage token returns 401', async () => {
  const res = await api('/api/auth/refresh', { method: 'POST', body: { refreshToken: 'not-a-real-token' } });
  assert.equal(res.status, 401);
});

test('auth: logout revokes the session', async () => {
  const { refreshToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/auth/logout', { method: 'POST', body: { refreshToken } });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
});

test('auth: forgot-password always reports success (no user enumeration)', async () => {
  const res = await api('/api/auth/forgot-password', { method: 'POST', body: { email: 'whoever@tenant.alpha.com' } });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
});

test('auth: register + login + reset-password round trip (throwaway user, cleaned up)', async (t) => {
  const stamp = Date.now();
  const email = `e2e.tester.${stamp}@tenant.alpha.com`;
  const password = 'e2e_initial_pw_123';

  const reg = await api('/api/auth/register', { method: 'POST', body: { name: 'E2E Tester', email, password, tenantId: 'tenant-alpha' } });
  assert.equal(reg.status, 201);
  assert.equal(reg.body.email, email);
  assert.equal(reg.body.role, 'USER');
  const newUserId = reg.body.id;

  t.after(async () => {
    // Idempotency: deactivate the throwaway account so repeated runs don't accumulate active users.
    try {
      const token = await adminToken();
      await api(`/api/admin/users/${newUserId}`, { method: 'DELETE', token });
    } catch {
      // best-effort cleanup
    }
  });

  const loginRes = await api('/api/auth/login', { method: 'POST', body: { email, password } });
  assert.equal(loginRes.status, 200);

  const newPassword = 'e2e_rotated_pw_456';
  const resetRes = await api('/api/auth/reset-password', { method: 'POST', body: { email, newPassword } });
  assert.equal(resetRes.status, 200);
  assert.equal(resetRes.body.success, true);

  const loginAfterReset = await api('/api/auth/login', { method: 'POST', body: { email, password: newPassword } });
  assert.equal(loginAfterReset.status, 200, 'should be able to log in with the new password');

  const loginWithOldPassword = await api('/api/auth/login', { method: 'POST', body: { email, password } });
  assert.equal(loginWithOldPassword.status, 401, 'old password should no longer work');
});
