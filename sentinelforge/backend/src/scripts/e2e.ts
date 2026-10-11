/**
 * End-to-end smoke test for the full hero flow, run against a live backend + CyberLab stack.
 * No mocks: every step is a real HTTP call. Exits non-zero on first failure.
 *
 * Usage: npm run test:e2e  (requires: sentinelforge backend on :4000, cyberlab on :3001, seeded)
 */
import axios from 'axios';
import { config } from '../config';

const API = `http://localhost:${config.port}`;

function assert(cond: unknown, message: string): void {
  if (!cond) throw new Error(`ASSERTION FAILED: ${message}`);
}

async function main(): Promise<void> {
  const steps: string[] = [];
  const log = (s: string): void => {
    steps.push(s);
    console.log(`[e2e] ${s}`);
  };

  if (!config.adminPassword) throw new Error('SF_ADMIN_PASSWORD not set in env');

  log('1. Login as admin');
  const loginRes = await axios.post(`${API}/api/auth/login`, { email: config.adminEmail, password: config.adminPassword });
  assert(loginRes.status === 200 && loginRes.data.token, 'admin login should return a token');
  const auth = { headers: { Authorization: `Bearer ${loginRes.data.token}` } };

  log('2. Register CyberLab application');
  const appRes = await axios.post(`${API}/api/applications`, { name: 'CyberLab E2E', baseUrl: config.cyberlab.baseUrl }, auth);
  assert(appRes.status === 201, 'application creation should return 201');
  const appId = appRes.data.id as string;

  log('3. Discover');
  const discoverRes = await axios.post(`${API}/api/applications/${appId}/discover`, {}, auth);
  assert(discoverRes.status === 200 && discoverRes.data.endpointCount > 0, 'discover should find endpoints');

  log('4. Scan (expect VULN-001 confirmed)');
  const scanRes = await axios.post(`${API}/api/applications/${appId}/scan`, {}, auth);
  assert(scanRes.status === 200, 'scan should succeed');
  const idorResult = scanRes.data.results.find((r: { vulnKey: string }) => r.vulnKey === 'VULN-001');
  assert(idorResult?.outcome === 'VULNERABLE', 'VULN-001 should be confirmed vulnerable by the scanner');

  log('5. Fetch finding');
  const findingsRes = await axios.get(`${API}/api/findings`, auth);
  const finding = findingsRes.data.find((f: { vulnKey: string }) => f.vulnKey === 'VULN-001');
  assert(finding, 'VULN-001 finding should be persisted');

  log('6. Run IDOR simulation (real attack against CyberLab)');
  const simRes = await axios.post(`${API}/api/applications/${appId}/simulate/03-idor`, {}, auth);
  assert(simRes.status === 200, 'simulation should succeed');

  log('7. Confirm an incident was created');
  const incidentsRes = await axios.get(`${API}/api/incidents`, auth);
  const incident = incidentsRes.data.find((i: { title: string }) => i.title === 'Possible IDOR Attack');
  assert(incident, 'IDOR simulation should produce a "Possible IDOR Attack" incident');

  log('8. Confirm correlation to VULN-001 and an attack graph exist');
  const incidentDetail = await axios.get(`${API}/api/incidents/${incident.id}`, auth);
  assert(incidentDetail.data.findings.some((f: { vulnKey: string }) => f.vulnKey === 'VULN-001'), 'incident should correlate to VULN-001');
  const graphRes = await axios.get(`${API}/api/incidents/${incident.id}/attack-graph`, auth);
  assert(graphRes.data.nodes.length > 0, 'attack graph should have nodes');

  log('9. AI investigate (should reference VULN-001)');
  const investigateRes = await axios.post(`${API}/api/incidents/${incident.id}/investigate`, {}, auth);
  assert(investigateRes.data.relatedVulnerabilities.includes('VULN-001'), 'investigation should name VULN-001');

  log('10. Verify BEFORE fix: still vulnerable (200)');
  const before = await axios.post(`${API}/api/findings/${finding.id}/verify`, {}, auth);
  assert(before.data.passed === false && before.data.after.status === 200, 'pre-fix verification should show 200 (still vulnerable)');

  log('11. Apply fix');
  const fixRes = await axios.post(`${API}/api/findings/${finding.id}/apply-fix`, {}, auth);
  assert(fixRes.data.status === 'FIXED', 'finding should become FIXED');

  log('12. Verify AFTER fix: blocked (403), finding VERIFIED');
  const after = await axios.post(`${API}/api/findings/${finding.id}/verify`, {}, auth);
  assert(after.data.passed === true && after.data.after.status === 403, 'post-fix verification should show 403 (blocked)');
  const findingAfter = await axios.get(`${API}/api/findings/${finding.id}`, auth);
  assert(findingAfter.data.status === 'VERIFIED', 'finding should become VERIFIED');

  log('13. Revert fix (restore repeatable demo state)');
  await axios.post(`${API}/api/findings/${finding.id}/revert-fix`, {}, auth);

  console.log(`\n[e2e] ALL ${steps.length} STEPS PASSED`);
}

main().catch(err => {
  console.error('\n[e2e] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
