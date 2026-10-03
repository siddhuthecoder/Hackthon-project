// tests/e2e/seed.test.mjs - verifies the seeded dataset matches the documented
// shape (3 tenants, 30 users, 100 customers, 100 products, 200 orders, ...).
//
// The suite must be idempotent: other test files legitimately create extra rows
// (register round trip adds a user, business-logic scenarios add orders and
// payments). Seeded rows are therefore identified by their deterministic id
// scheme - user-001..user-030, order-1..order-200, pay-1..pay-50, cust-*/prod-*
// - while runtime rows use uuid-suffixed ids such as user-3f9c1a2b or order-d9af5b39.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, adminToken } from './helpers.mjs';

const TENANTS = ['tenant-alpha', 'tenant-beta', 'tenant-gamma'];
const range = (n) => Array.from({ length: n }, (_, i) => i + 1);
// Seeded users are user-101..user-130 (nine per tenant plan) plus user-001, the
// SUPER_ADMIN. Runtime registrations get uuid-suffixed ids such as user-3f9c1a2b.
const seededUsers = new Set(['user-001', ...range(30).map(n => `user-${100 + n}`)]);
const seededOrders = new Set(range(200).map(n => `order-${n}`));
const seededPayments = new Set(range(50).map(n => `pay-${n}`));

function tenantForIndex(n) {
  return TENANTS[(n - 1) % 3];
}

test('seed: 3 tenants with the expected ids', async () => {
  const token = await adminToken();
  const res = await api('/api/tenants', { token });
  assert.equal(res.status, 200);
  const ids = res.body.map(t => t.id).sort();
  assert.deepEqual(ids, TENANTS);
});

test('seed: 30 users (5 admins incl. SUPER_ADMIN, 10 MANAGER, 10 STAFF, 5 USER)', async () => {
  const token = await adminToken();
  const res = await api('/api/admin/users', { token });
  assert.equal(res.status, 200);

  const seeded = res.body.filter(u => seededUsers.has(u.id));
  assert.equal(seeded.length, 30, `expected the 30 seeded users, got ${seeded.length}`);

  const byRole = seeded.reduce((acc, u) => ({ ...acc, [u.role]: (acc[u.role] || 0) + 1 }), {});
  assert.equal((byRole.SUPER_ADMIN || 0) + (byRole.TENANT_ADMIN || 0), 5, 'expected 5 admins total');
  assert.equal(byRole.SUPER_ADMIN, 1);
  assert.equal(byRole.TENANT_ADMIN, 4);
  assert.equal(byRole.MANAGER, 10);
  assert.equal(byRole.STAFF, 10);
  assert.equal(byRole.USER, 5);
});

test('seed: admin@sentinelforge.lab is the SUPER_ADMIN', async () => {
  const token = await adminToken();
  const res = await api('/api/admin/users', { token });
  const admin = res.body.find(u => u.email === 'admin@sentinelforge.lab');
  assert.ok(admin);
  assert.equal(admin.role, 'SUPER_ADMIN');
  assert.equal(admin.id, 'user-001');
});

test('seed: 100 customers', async () => {
  const token = await adminToken();
  const res = await api('/api/customers', { token });
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 100);
});

test('seed: 100 products, tenant = tenants[(N-1)%3]', async () => {
  const token = await adminToken();
  const res = await api('/api/products', { token });
  assert.equal(res.status, 200);
  const seeded = new Map(res.body.map(p => [p.id, p]));
  for (const n of range(100)) {
    const product = seeded.get(`prod-${n}`);
    assert.ok(product, `expected seeded product prod-${n}`);
    assert.equal(product.tenantId, tenantForIndex(n), `prod-${n} tenant mismatch`);
  }
});

test('seed: 200 orders, tenant = tenants[(N-1)%3]', async () => {
  const token = await adminToken();
  const res = await api('/api/orders?limit=1000', { token });
  assert.equal(res.status, 200);

  const seeded = new Map(res.body.filter(o => seededOrders.has(o.id)).map(o => [o.id, o]));
  assert.equal(seeded.size, 200, `expected the 200 seeded orders, got ${seeded.size}`);
  for (const n of range(200)) {
    const order = seeded.get(`order-${n}`);
    assert.ok(order, `expected seeded order order-${n}`);
    assert.equal(order.tenantId, tenantForIndex(n), `order-${n} tenant mismatch`);
    assert.ok(order.orderNumber, `order-${n} should carry an orderNumber`);
  }
  assert.equal(seeded.get('order-1').tenantId, 'tenant-alpha');
  assert.equal(seeded.get('order-2').tenantId, 'tenant-beta');
  assert.equal(seeded.get('order-3').tenantId, 'tenant-gamma');
});

test('seed: 50 payments, 100 audit logs and 150 historical security events exist', async () => {
  const token = await adminToken();

  const payments = await api('/api/payments', { token });
  assert.equal(payments.status, 200);
  const seededPaymentIds = new Set(payments.body.map(p => p.id).filter(id => seededPayments.has(id)));
  assert.equal(seededPaymentIds.size, 50, `expected the 50 seeded payments, got ${seededPaymentIds.size}`);

  const auditLogs = await api('/api/security/audit-logs?limit=500');
  assert.equal(auditLogs.status, 200);
  assert.ok(auditLogs.body.length >= 100, `expected at least 100 audit logs, got ${auditLogs.body.length}`);

  const events = await api('/api/security/events?limit=500');
  assert.equal(events.status, 200);
  assert.ok(events.body.length >= 150, `expected at least 150 security events, got ${events.body.length}`);

  const demoStatus = await api('/api/security/demo-status');
  assert.equal(demoStatus.status, 200);
  assert.equal(demoStatus.body.tenantCount, 3);
  assert.equal(demoStatus.body.vulnerabilityCount, 14);
  assert.equal(demoStatus.body.attackScenarioCount, 9);
  assert.ok(demoStatus.body.userCount >= 30);
});

test('seed: 3 historical incidents are present with the documented statuses', async () => {
  const res = await api('/api/security/incidents');
  assert.equal(res.status, 200);
  const seeded = res.body.filter(i => i.id.startsWith('INC-seed'));
  assert.equal(seeded.length, 3, `expected 3 historical incidents, got ${seeded.length}`);
  const byStatus = seeded.reduce((acc, i) => ({ ...acc, [i.status]: (acc[i.status] || 0) + 1 }), {});
  assert.equal(byStatus.RESOLVED, 1);
  assert.equal(byStatus.INVESTIGATING, 1);
  assert.equal(byStatus.FALSE_POSITIVE, 1);
});

test('seed: 14 vulnerability findings and 9 detection rules', async () => {
  const findings = await api('/api/security/findings');
  assert.equal(findings.body.length, 14);
  const rules = await api('/api/security/detection-rules');
  assert.equal(rules.body.length, 9);
});
