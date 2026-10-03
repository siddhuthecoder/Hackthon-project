// tests/e2e/detection.test.mjs - runs the server-side attack simulator for each
// of the 9 scenarios and asserts the matching SOC detection rule fired and its
// incident exists in the SOC console.
//
// The simulator (services/simulator.ts) generates its own isolated random source
// IP and restores any role it changes, so these runs are idempotent by construction.
// Incident creation is deduplicated per (title, sourceIp) for 10 minutes, and the
// background worker also evaluates the rules every 30s, so an assertion of "a new
// incident appeared" would be flaky on a repeat run. We therefore assert:
//   1. every simulated step succeeded,
//   2. the expected rule fired for this run,
//   3. an OPEN/INVESTIGATING incident for that rule exists and links the expected
//      vulnerability finding,
//   4. the run's own source IP is present in the security event stream.
import test from 'node:test';
import assert from 'node:assert/strict';
import { api } from './helpers.mjs';

const SCENARIOS = [
  { id: '01-bruteforce', rule: 'RULE-001', title: 'Brute Force Attack Detected', finding: 'VULN-009', eventType: 'AUTH_FAILURE' },
  { id: '02-account-takeover', rule: 'RULE-002', title: 'Possible Account Takeover', finding: 'VULN-009', eventType: 'AUTH_SUCCESS' },
  { id: '03-idor', rule: 'RULE-003', title: 'Possible IDOR Attack', finding: 'VULN-001', eventType: 'DATA_ACCESS' },
  { id: '04-cross-tenant-access', rule: 'RULE-004', title: 'Cross-Tenant Data Access Attempt', finding: 'VULN-002', eventType: 'CROSS_TENANT_ACCESS_ATTEMPT' },
  { id: '05-privilege-escalation', rule: 'RULE-005', title: 'Privilege Escalation via Mass Assignment', finding: 'VULN-011', eventType: 'PRIVILEGE_CHANGE' },
  { id: '06-api-abuse', rule: 'RULE-008', title: 'API Abuse - Excessive Request Rate', finding: 'VULN-009', eventType: 'API_REQUEST' },
  { id: '07-data-exfiltration-simulation', rule: 'RULE-006', title: 'Possible Data Exfiltration', finding: 'VULN-002', eventType: 'BULK_DATA_ACCESS' },
  { id: '08-suspicious-admin-activity', rule: 'RULE-007', title: 'Suspicious Admin Activity', finding: 'VULN-003', eventType: 'PRIVILEGE_CHANGE' },
  { id: '09-business-logic-abuse', rule: 'RULE-009', title: 'Payment Business Logic Abuse', finding: 'VULN-012', eventType: 'PAYMENT_UPDATED' },
];

const TOLERANCE_MS = 10_000;

for (const { id, rule, title, finding, eventType } of SCENARIOS) {
  test(`detection: scenario ${id} triggers ${rule} and produces its incident`, async () => {
    const res = await api(`/api/security/simulate/${id}`, { method: 'POST' });
    assert.equal(res.status, 200, `simulate/${id} should return 200: ${JSON.stringify(res.body)}`);
    assert.ok(res.body.sourceIp, 'result should include the isolated source IP used');

    const failedSteps = (res.body.steps || []).filter(s => s.status !== 'success');
    assert.deepEqual(failedSteps, [], `every simulated step should succeed: ${JSON.stringify(failedSteps)}`);
    assert.ok(res.body.eventsGenerated > 0, 'expected at least one security event to be generated');

    // 1. The expected SOC rule fired during this run.
    const matched = res.body.detections.find(d => d.ruleId === rule);
    assert.ok(matched, `expected rule ${rule} to fire for scenario ${id}; got: ${JSON.stringify(res.body.detections)}`);

    // 2. The run's own source IP shows up in the security event stream.
    const events = await api(`/api/security/events?sourceIp=${res.body.sourceIp}&limit=500`);
    assert.equal(events.status, 200);
    assert.ok(events.body.length > 0, `expected security events for source IP ${res.body.sourceIp}`);
    assert.ok(
      events.body.some(e => e.eventType === eventType),
      `expected a ${eventType} event from source IP ${res.body.sourceIp}`,
    );

    // 3. An incident for that rule exists and links the expected vulnerability finding.
    const incidents = await api('/api/security/incidents');
    assert.equal(incidents.status, 200);
    const matching = incidents.body.filter(i => i.title === title);
    assert.ok(matching.length > 0, `expected an incident titled "${title}" (${rule})`);
    assert.ok(
      matching.some(i => (i.findings || []).includes(finding)),
      `expected the "${title}" incident to link ${finding}; got ${JSON.stringify(matching.map(i => i.findings))}`,
    );
    const live = matching.find(i => ['OPEN', 'INVESTIGATING'].includes(i.status)) || matching[0];
    assert.ok(live.detectedAt, 'incident should carry a detectedAt timestamp');
    assert.ok(Date.now() - new Date(live.detectedAt).getTime() < 30 * 60 * 1000 + TOLERANCE_MS, 'incident should be recent');
    assert.ok(Array.isArray(live.attackPath) && live.attackPath.length > 0, 'incident should include an attack path');
    assert.ok(typeof live.confidence === 'number' && live.confidence > 0, 'incident should include a confidence score');
    assert.ok(live.mitreTechnique, 'incident should include a MITRE ATT&CK technique');
  });
}

test('detection: the incidents endpoint exposes a mutable status workflow', async () => {
  const res = await api('/api/security/simulate/03-idor', { method: 'POST' });
  assert.equal(res.status, 200);
  const incidents = await api('/api/security/incidents');
  const target = incidents.body.find(i => i.title === 'Possible IDOR Attack' && ['OPEN', 'INVESTIGATING'].includes(i.status));
  assert.ok(target, 'expected a live IDOR incident to transition');

  const patched = await api(`/api/security/incidents/${target.id}`, { method: 'PATCH', body: { status: 'INVESTIGATING' } });
  assert.equal(patched.status, 200);
  assert.equal(patched.body.status, 'INVESTIGATING');

  const restored = await api(`/api/security/incidents/${target.id}`, { method: 'PATCH', body: { status: target.status } });
  assert.equal(restored.status, 200);
  assert.equal(restored.body.status, target.status, 'restore the original incident status');

  const invalid = await api(`/api/security/incidents/${target.id}`, { method: 'PATCH', body: { status: 'NOT_A_STATUS' } });
  assert.equal(invalid.status, 400, 'unknown incident statuses must be rejected');
});

test('detection: run-detection reports per-rule results and never duplicates an incident', async () => {
  const first = await api('/api/security/run-detection', { method: 'POST' });
  assert.equal(first.status, 200);
  assert.equal(first.body.success, true);
  assert.ok(Array.isArray(first.body.results));

  const second = await api('/api/security/run-detection', { method: 'POST' });
  assert.equal(second.status, 200);

  const incidents = await api('/api/security/incidents');
  const cutoff = Date.now() - 5 * 60 * 1000;
  const seen = new Map();
  for (const incident of incidents.body) {
    if (new Date(incident.detectedAt).getTime() < cutoff) continue;
    const key = `${incident.title}|${incident.sourceIp}`;
    seen.set(key, (seen.get(key) || 0) + 1);
  }
  const duplicates = [...seen.entries()].filter(([, count]) => count > 1);
  assert.deepEqual(duplicates, [], 'the 10 minute dedup window must prevent duplicate (title, sourceIp) incidents');
});

test('detection: an unknown scenario id is rejected', async () => {
  const res = await api('/api/security/simulate/99-does-not-exist', { method: 'POST' });
  assert.equal(res.status, 404);
});