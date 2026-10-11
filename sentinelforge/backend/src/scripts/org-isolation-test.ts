/**
 * Adversarial self-test: proves a user in one org cannot reach another org's data through any
 * single-resource route, by actually trying — the same vuln class (BOLA/cross-tenant access)
 * this product exists to detect, turned against itself. Not a mock: creates a real throwaway
 * second org/user via Mongo, logs in as them over real HTTP, and attempts every single-resource
 * read/write against Org A's real finding/incident ids. Cleans up the throwaway org/user after.
 *
 * Usage: npm run test:org-isolation  (requires: backend on :4000, seeded, at least one app/
 * finding/incident already present from a prior scan — e.g. run after npm run test:e2e)
 */
import bcrypt from 'bcryptjs';
import axios from 'axios';
import { config } from '../config';
import { connectDb, disconnectDb } from '../db/connection';
import { Application, Incident, Organization, User, Vulnerability } from '../db/models';
import { newId } from '../lib/util';

const API = `http://localhost:${config.port}`;

function assert(cond: unknown, message: string): void {
  if (!cond) throw new Error(`ASSERTION FAILED: ${message}`);
}

async function main(): Promise<void> {
  await connectDb();
  const steps: string[] = [];
  const log = (s: string): void => {
    steps.push(s);
    console.log(`[org-isolation] ${s}`);
  };

  log('Find a real finding and incident from Org A to attack');
  const finding = await Vulnerability.findOne({});
  const incident = await Incident.findOne({});
  assert(finding, 'need at least one existing finding — run npm run test:e2e first');
  assert(incident, 'need at least one existing incident — run npm run test:e2e first');
  const orgAApp = await Application.findById(finding!.applicationId);
  assert(orgAApp, 'finding should have a resolvable application');

  log('Create a throwaway Org B + user (never through the public API — no signup route exists)');
  const orgBId = newId('org');
  const orgBUserId = newId('user');
  const orgBEmail = `isolation-test-${Date.now()}@example.com`;
  const orgBPassword = 'IsolationTest123!';
  await Organization.create({ _id: orgBId, name: 'Isolation Test Org B' });
  await User.create({
    _id: orgBUserId, organizationId: orgBId, email: orgBEmail, name: 'Isolation Test User',
    passwordHash: bcrypt.hashSync(orgBPassword, 10), role: 'admin', active: true,
  });

  try {
    log('Log in as Org B user over real HTTP');
    const loginRes = await axios.post(`${API}/api/auth/login`, { email: orgBEmail, password: orgBPassword });
    assert(loginRes.status === 200 && loginRes.data.token, 'Org B login should succeed');
    const orgBAuth = { headers: { Authorization: `Bearer ${loginRes.data.token}` } };

    const attempts: { label: string; probe: () => Promise<number> }[] = [
      { label: `GET /api/findings/${finding!.id} (Org A's finding)`, probe: async () => (await axios.get(`${API}/api/findings/${finding!.id}`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `PATCH /api/findings/${finding!.id}`, probe: async () => (await axios.patch(`${API}/api/findings/${finding!.id}`, { status: 'FALSE_POSITIVE' }, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/findings/${finding!.id}/report.pdf`, probe: async () => (await axios.get(`${API}/api/findings/${finding!.id}/report.pdf`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `POST /api/findings/${finding!.id}/analyze`, probe: async () => (await axios.post(`${API}/api/findings/${finding!.id}/analyze`, {}, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/incidents/${incident!.id} (Org A's incident)`, probe: async () => (await axios.get(`${API}/api/incidents/${incident!.id}`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `PATCH /api/incidents/${incident!.id}`, probe: async () => (await axios.patch(`${API}/api/incidents/${incident!.id}`, { status: 'RESOLVED' }, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `PATCH /api/incidents/${incident!.id}/assign`, probe: async () => (await axios.patch(`${API}/api/incidents/${incident!.id}/assign`, { userId: orgBUserId }, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `POST /api/incidents/${incident!.id}/comments`, probe: async () => (await axios.post(`${API}/api/incidents/${incident!.id}/comments`, { text: 'cross-org probe' }, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/incidents/${incident!.id}/attack-graph`, probe: async () => (await axios.get(`${API}/api/incidents/${incident!.id}/attack-graph`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/incidents/${incident!.id}/report.pdf`, probe: async () => (await axios.get(`${API}/api/incidents/${incident!.id}/report.pdf`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `POST /api/incidents/${incident!.id}/investigate`, probe: async () => (await axios.post(`${API}/api/incidents/${incident!.id}/investigate`, {}, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `POST /api/incidents/${incident!.id}/respond`, probe: async () => (await axios.post(`${API}/api/incidents/${incident!.id}/respond`, { action: 'mark_contained' }, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/incidents/${incident!.id}/ip-reputation`, probe: async () => (await axios.get(`${API}/api/incidents/${incident!.id}/ip-reputation`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `POST /api/incidents/${incident!.id}/postmortem`, probe: async () => (await axios.post(`${API}/api/incidents/${incident!.id}/postmortem`, {}, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/incidents/${incident!.id}/response-actions`, probe: async () => (await axios.get(`${API}/api/incidents/${incident!.id}/response-actions`, { ...orgBAuth, validateStatus: () => true })).status },
      { label: `GET /api/applications/${orgAApp!.id} (Org A's application)`, probe: async () => (await axios.get(`${API}/api/applications/${orgAApp!.id}`, { ...orgBAuth, validateStatus: () => true })).status },
    ];

    log(`Attempting ${attempts.length} cross-org probes as Org B against Org A's real resources`);
    for (const attempt of attempts) {
      const status = await attempt.probe();
      assert(status === 404, `${attempt.label} should 404 for a different org, got ${status}`);
      log(`  OK (404): ${attempt.label}`);
    }

    log('Confirm Org B genuinely sees its own (empty) lists, not Org A data, on list routes');
    const orgBFindings = await axios.get(`${API}/api/findings`, orgBAuth);
    assert(Array.isArray(orgBFindings.data) && orgBFindings.data.length === 0, 'Org B should see zero findings');
    const orgBIncidents = await axios.get(`${API}/api/incidents`, orgBAuth);
    assert(Array.isArray(orgBIncidents.data) && orgBIncidents.data.length === 0, 'Org B should see zero incidents');

    console.log(`\n[org-isolation] ALL ${steps.length} CHECKS PASSED — no cross-org access possible through any tested route`);
  } finally {
    await User.deleteOne({ _id: orgBUserId });
    await Organization.deleteOne({ _id: orgBId });
    await disconnectDb();
  }
}

main().catch(err => {
  console.error('\n[org-isolation] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
