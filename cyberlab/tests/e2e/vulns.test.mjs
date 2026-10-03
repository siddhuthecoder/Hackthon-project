// tests/e2e/vulns.test.mjs - one reproduction + one secure-block assertion per
// VULN-001..013. State-changing tests restore the roles/data they touch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, login, adminToken, findUser, ALICE, ADMIN, freshIp } from './helpers.mjs';

// ---------- VULN-001: IDOR / BOLA ----------
test('VULN-001 IDOR: vulnerable GET /api/users/:id discloses another user to a non-owner', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/users/user-102', { token: accessToken });
  assert.equal(res.status, 200);
  assert.equal(res.body.id, 'user-102');
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_IDOR');
});

test('VULN-001 IDOR: secure GET /api/users/secure/:id denies a non-owner', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/users/secure/user-102', { token: accessToken });
  assert.equal(res.status, 403);
});

// ---------- VULN-002: Cross-Tenant Access ----------
test('VULN-002 cross-tenant: vulnerable GET /api/orders/:id discloses another tenant order', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/orders/order-3', { token: accessToken }); // tenant-gamma
  assert.equal(res.status, 200);
  assert.equal(res.body.tenantId, 'tenant-gamma');
});

test('VULN-002 cross-tenant: secure GET /api/orders/secure/:id denies another tenant order', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/orders/secure/order-3', { token: accessToken });
  assert.equal(res.status, 403);
});

// ---------- VULN-003: Broken Function-Level RBAC ----------
test('VULN-003 broken RBAC: GET /api/admin/users/vulnerable allows any authenticated role', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/admin/users/vulnerable', { token: accessToken });
  assert.equal(res.status, 200);
});

test('VULN-003 broken RBAC: secure GET /api/admin/users denies plain USER role', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/admin/users', { token: accessToken });
  assert.equal(res.status, 403);
});

// ---------- VULN-004: NoSQL Injection ----------
test('VULN-004 NoSQLi: vulnerable-login authenticates with {"$ne": null} as the password', async () => {
  const res = await api('/api/auth/vulnerable-login', {
    method: 'POST',
    body: { email: ALICE.email, password: { $ne: null } },
    sourceIp: freshIp(),
  });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken);
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT');
});

test('VULN-004 NoSQLi: secure-login rejects a non-string password', async () => {
  const res = await api('/api/auth/secure-login', {
    method: 'POST',
    body: { email: ALICE.email, password: { $ne: null } },
    sourceIp: freshIp(),
  });
  assert.equal(res.status, 400);
});

// ---------- VULN-005: Stored XSS ----------
test('VULN-005 stored XSS: POST /api/comments stores raw HTML unescaped', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const payload = '<img src=x onerror="void 0">e2e-xss-probe';
  const res = await api('/api/comments', { method: 'POST', token: accessToken, body: { productId: 'prod-1', content: payload } });
  assert.equal(res.status, 201);
  assert.equal(res.body.content, payload, 'content should be stored verbatim, not sanitized');
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_XSS');
});

test('VULN-005 stored XSS: POST /api/comments/safe escapes HTML', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const payload = '<img src=x onerror="void 0">e2e-xss-probe';
  const res = await api('/api/comments/safe', { method: 'POST', token: accessToken, body: { productId: 'prod-1', content: payload } });
  assert.equal(res.status, 201);
  assert.ok(!res.body.content.includes('<img'), 'markup should be escaped');
  assert.match(res.body.content, /&lt;img/);
});

// ---------- VULN-006: SSRF ----------
test('VULN-006 SSRF: vulnerable fetch-url reaches internal-service and returns the demo secret', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/fetch-url', { method: 'POST', token: accessToken, body: { url: 'http://internal-service:8080/internal/demo-secret' } });
  assert.equal(res.status, 200);
  assert.match(res.body.data, /demo_internal_secret_123/);
});

test('VULN-006 SSRF: lab safety guard blocks requests to hosts outside the lab network', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/fetch-url', { method: 'POST', token: accessToken, body: { url: 'http://example.com' } });
  assert.equal(res.status, 403);
  assert.match(res.body.error, /LAB_SAFETY_GUARD/);
});

// ---------- VULN-007: Path Traversal ----------
test('VULN-007 path traversal: vulnerable download reads a file outside the public dir', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/files/download?file=../internal-demo.txt', { token: accessToken });
  assert.equal(res.status, 200);
  assert.match(res.body.content, /DEMO_SECRET/);
});

test('VULN-007 path traversal: secure download rejects a traversal attempt', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/files/download/secure?file=../internal-demo.txt', { token: accessToken });
  assert.equal(res.status, 403);
});

// ---------- VULN-008: Command Injection (sandboxed simulator) ----------
test('VULN-008 command injection: vulnerable ping simulates injected shell metacharacters', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/tools/ping', { method: 'POST', token: accessToken, body: { host: 'localhost; whoami' } });
  assert.equal(res.status, 200);
  assert.equal(res.body.injectionDetected, true);
  assert.match(res.body.output, /whoami|sandbox-user/);
  assert.equal(res.body.warning, 'SANDBOXED_SIMULATOR_VULN-008');
});

test('VULN-008 command injection: secure ping rejects invalid host characters', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/tools/ping/secure', { method: 'POST', token: accessToken, body: { host: 'localhost; whoami' } });
  assert.equal(res.status, 400);
});

// ---------- VULN-009: Weak Rate Limiting ----------
test('VULN-009 weak rate limit: repeated failed logins from one IP are not throttled below the 100/5min threshold', async () => {
  const ip = freshIp();
  const results = [];
  for (let i = 0; i < 12; i++) {
    const res = await api('/api/auth/login', { method: 'POST', body: { email: 'nope@attacker.test', password: `w${i}` }, sourceIp: ip });
    results.push(res.status);
  }
  assert.ok(results.every(s => s === 401), 'all 12 attempts should be rejected as invalid credentials, not rate-limited (429)');
});

test('VULN-009 weak rate limit: the login route does expose rate-limit headers (limiting infra exists, threshold is just too weak)', async () => {
  const res = await api('/api/auth/login', { method: 'POST', body: { email: ALICE.email, password: ALICE.password }, sourceIp: freshIp() });
  const hasLimitHeader = res.headers.get('ratelimit-limit') || res.headers.get('x-ratelimit-limit');
  assert.ok(hasLimitHeader, 'expected a RateLimit-* header from express-rate-limit');
});

// ---------- VULN-010: JWT claim trusted without DB re-check ----------
test('VULN-010 JWT trust: a stale admin token keeps access after the role is revoked server-side', async (t) => {
  const target = await findUser({ role: 'STAFF', tenantId: 'tenant-gamma' });
  assert.ok(target, 'seed data must include a STAFF user in tenant-gamma');
  const admin = await adminToken();

  const restore = async () => {
    await api(`/api/admin/users/${target.id}/promote`, { method: 'POST', token: admin, body: { role: target.role } });
  };
  t.after(restore);

  const promote = await api(`/api/admin/users/${target.id}/promote`, { method: 'POST', token: admin, body: { role: 'TENANT_ADMIN' } });
  assert.equal(promote.status, 200);

  const { accessToken: staleToken } = await login(target.email, 'demo_password_123', freshIp());

  // Revoke the role server-side - the already-issued JWT still claims TENANT_ADMIN.
  const demote = await api(`/api/admin/users/${target.id}/promote`, { method: 'POST', token: admin, body: { role: target.role } });
  assert.equal(demote.status, 200);

  const vulnerable = await api('/api/vulnerable/admin', { token: staleToken });
  assert.equal(vulnerable.status, 200, 'VULN-010: stale JWT claim is trusted without a DB re-check');

  const secure = await api('/api/vulnerable/admin/secure', { token: staleToken });
  assert.equal(secure.status, 403, 'secure variant re-verifies the role against the database');
});

// ---------- VULN-011: Mass Assignment ----------
test('VULN-011 mass assignment: vulnerable PATCH lets a STAFF user grant themself TENANT_ADMIN (role restored after)', async (t) => {
  const staff = await findUser({ role: 'STAFF', tenantId: 'tenant-beta' });
  assert.ok(staff, 'seed data must include a STAFF user in tenant-beta');
  const admin = await adminToken();

  t.after(async () => {
    await api(`/api/users/${staff.id}`, { method: 'PATCH', token: admin, body: { role: 'STAFF', isAdmin: false } });
  });

  const { accessToken } = await login(staff.email, 'demo_password_123', freshIp());
  const res = await api(`/api/users/${staff.id}`, { method: 'PATCH', token: accessToken, body: { role: 'TENANT_ADMIN', isAdmin: true } });
  assert.equal(res.status, 200);
  assert.equal(res.body.role, 'TENANT_ADMIN');
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_MASS_ASSIGNMENT');
});

test('VULN-011 mass assignment: secure PATCH ignores disallowed fields like role', async () => {
  const staff = await findUser({ role: 'STAFF', tenantId: 'tenant-beta' });
  assert.ok(staff);
  const { accessToken } = await login(staff.email, 'demo_password_123', freshIp());
  const res = await api(`/api/users/secure/${staff.id}`, { method: 'PATCH', token: accessToken, body: { role: 'TENANT_ADMIN', name: staff.name } });
  assert.equal(res.status, 200);
  assert.equal(res.body.role, 'STAFF', 'role field must be ignored by the allowlisted update');
});

// ---------- VULN-012: Business Logic Abuse ----------
test('VULN-012 business logic: vulnerable payment accepts a client-tampered amount and status', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const order = await api('/api/orders', { method: 'POST', token: accessToken, body: { items: [{ productId: 'prod-1', quantity: 1 }] } });
  assert.equal(order.status, 201);
  const pay = await api('/api/payments', { method: 'POST', token: accessToken, body: { orderId: order.body.id, status: 'completed', orderStatus: 'paid', amount: 0.01 } });
  assert.equal(pay.status, 200);
  assert.equal(pay.body.amount, 0.01, 'the tampered amount is accepted verbatim');
  assert.equal(pay.body.orderStatus, 'paid');
  assert.equal(pay.body.warning, 'VULNERABLE_ENDPOINT_BUSINESS_LOGIC');
});

test('VULN-012 business logic: secure payment always charges the server-computed order total', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const order = await api('/api/orders', { method: 'POST', token: accessToken, body: { items: [{ productId: 'prod-2', quantity: 2 }] } });
  assert.equal(order.status, 201);
  const pay = await api('/api/payments/secure', { method: 'POST', token: accessToken, body: { orderId: order.body.id, amount: 0.01, method: 'card' } });
  assert.equal(pay.status, 200);
  assert.equal(pay.body.amount, order.body.total, 'client-supplied amount must be ignored');
  assert.notEqual(pay.body.amount, 0.01);
});

// ---------- VULN-013: Insecure File Upload ----------
test('VULN-013 insecure upload: vulnerable endpoint accepts an .html file', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const form = new FormData();
  form.append('file', new Blob(['<html><body>e2e upload probe</body></html>'], { type: 'text/html' }), 'probe.html');
  const res = await api('/api/files/upload', { method: 'POST', token: accessToken, body: form });
  assert.equal(res.status, 201);
  assert.equal(res.body.validated, false);
  assert.equal(res.body.warning, 'VULNERABLE_ENDPOINT_FILE_UPLOAD');
});

test('VULN-013 insecure upload: secure endpoint rejects an .html file', async () => {
  const { accessToken } = await login(ALICE.email, ALICE.password, freshIp());
  const form = new FormData();
  form.append('file', new Blob(['<html><body>e2e upload probe</body></html>'], { type: 'text/html' }), 'probe.html');
  const res = await api('/api/files/upload/secure', { method: 'POST', token: accessToken, body: form });
  assert.equal(res.status, 400);
});
