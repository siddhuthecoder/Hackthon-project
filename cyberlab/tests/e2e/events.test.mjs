// tests/e2e/events.test.mjs - security events / audit logs / demo-status.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api, login, ALICE, freshIp } from './helpers.mjs';

test('events: demo-status reports the expected seeded counts', async () => {
  const res = await api('/api/security/demo-status');
  assert.equal(res.status, 200);
  assert.equal(res.body.tenantCount, 3);
  assert.equal(res.body.vulnerabilityCount, 14);
  assert.ok(res.body.userCount >= 30, `expected at least 30 seeded users, got ${res.body.userCount}`);
  assert.equal(res.body.attackScenarioCount, 9);
  assert.equal(res.body.status, 'operational');
});

test('events: an authenticated action produces a queryable DATA_ACCESS event', async () => {
  const ip = freshIp();
  const { accessToken } = await login(ALICE.email, ALICE.password, ip);
  const probe = await api('/api/users/user-104', { token: accessToken, sourceIp: ip });
  assert.equal(probe.status, 200);

  const events = await api(`/api/security/events?eventType=DATA_ACCESS&sourceIp=${ip}&limit=10`);
  assert.equal(events.status, 200);
  assert.ok(events.body.length > 0, 'expected at least one DATA_ACCESS event for this source IP');
  const match = events.body.find(e => e.metadata?.resourceId === 'user-104');
  assert.ok(match, 'expected an event recording access to user-104');
  assert.equal(match.eventType, 'DATA_ACCESS');
});

test('events: a login produces an AUTH_SUCCESS event for the caller tenant', async () => {
  const ip = freshIp();
  await login(ALICE.email, ALICE.password, ip);
  const events = await api(`/api/security/events?eventType=AUTH_SUCCESS&sourceIp=${ip}`);
  assert.equal(events.status, 200);
  assert.ok(events.body.some(e => e.userId === 'user-101'), 'expected an AUTH_SUCCESS event for user-101');
});

test('events: audit logs include LOGIN entries', async () => {
  await login(ALICE.email, ALICE.password, freshIp());
  const res = await api('/api/security/audit-logs?limit=100');
  assert.equal(res.status, 200);
  assert.ok(res.body.length > 0);
  assert.ok(res.body.some(entry => entry.action === 'LOGIN'), 'expected at least one LOGIN audit entry in the last 100');
});

test('events: GET /api/security/findings lists all 14 vulnerabilities', async () => {
  const res = await api('/api/security/findings');
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 14);
  const ids = res.body.map(f => f.id).sort();
  assert.equal(ids[0], 'VULN-001');
  assert.equal(ids[ids.length - 1], 'VULN-014');
});

test('events: GET /api/security/findings/:id returns a single finding', async () => {
  const res = await api('/api/security/findings/VULN-001');
  assert.equal(res.status, 200);
  assert.equal(res.body.id, 'VULN-001');
  assert.equal(res.body.cwe, 'CWE-639');
});

test('events: GET /api/security/detection-rules lists all 9 rules', async () => {
  const res = await api('/api/security/detection-rules');
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 9);
  assert.ok(res.body.every(r => /^RULE-00[1-9]$/.test(r.id)));
});

test('events: GET /api/security/scenarios lists all 9 attack scenarios', async () => {
  const res = await api('/api/security/scenarios');
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 9);
});

test('events: GET /api/security/attack-graph returns a seeded node/edge graph', async () => {
  const res = await api('/api/security/attack-graph');
  assert.equal(res.status, 200);
  assert.ok(res.body.nodes.length > 0);
  assert.ok(res.body.edges.length > 0);
});
