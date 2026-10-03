// tests/e2e/tenancy.test.mjs - secure order lookup enforces tenant ownership;
// the vulnerable lookup and the unscoped list route do not.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, login, ALICE, freshIp } from './helpers.mjs';

test('tenancy: secure GET /api/orders/secure/:id blocks cross-tenant access (403)', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  // order-2 belongs to tenant-beta (order-N tenant = tenants[(N-1)%3]); alice is tenant-alpha.
  const res = await api('/api/orders/secure/order-2', { token: accessToken });
  assert.equal(res.status, 403);
});

test('tenancy: secure GET /api/orders/secure/:id allows same-tenant access (200)', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  // order-1 belongs to tenant-alpha.
  const res = await api('/api/orders/secure/order-1', { token: accessToken });
  assert.equal(res.status, 200);
  assert.equal(res.body.tenantId, 'tenant-alpha');
});

test('tenancy: vulnerable GET /api/orders/:id discloses cross-tenant data (200, VULN-002)', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/orders/order-2', { token: accessToken });
  assert.equal(res.status, 200);
  assert.equal(res.body.tenantId, 'tenant-beta');
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_CROSS_TENANT');
});

test('tenancy: GET /api/orders (list) is scoped to the caller tenant', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/orders?limit=500', { token: accessToken });
  assert.equal(res.status, 200);
  assert.ok(res.body.length > 0, 'tenant-alpha should have orders');
  for (const order of res.body) {
    assert.equal(order.tenantId, 'tenant-alpha', `order ${order.id} leaked another tenant`);
  }
});

test('tenancy: GET /api/products (list) is scoped to the caller tenant', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/products', { token: accessToken });
  assert.equal(res.status, 200);
  for (const product of res.body) {
    assert.equal(product.tenantId, 'tenant-alpha');
  }
});
