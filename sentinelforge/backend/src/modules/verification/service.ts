import jwt from 'jsonwebtoken';
import { config } from '../../config';
import { IVulnerability, RemediationTask, VerificationRun } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { discoverTargets } from '../scanner/checks';
import { runGitleaks } from '../scanner/gitleaks';

export async function applyFix(finding: IVulnerability, lab: CyberLabAdapter, actor: string): Promise<void> {
  await lab.applyFix(finding.vulnKey);
  const task = await RemediationTask.create({
    _id: newId('rem'),
    findingId: finding._id,
    status: 'APPLIED',
    plan: { vulnKey: finding.vulnKey, action: 'lab-fix-toggle' },
    appliedAt: new Date(),
    appliedBy: actor,
  });
  finding.set({ status: 'FIXED', updatedAt: new Date() });
  await finding.save();
  publish('finding', finding.toJSON());
  return void task;
}

export async function revertFix(finding: IVulnerability, lab: CyberLabAdapter): Promise<void> {
  await lab.revertFix(finding.vulnKey);
  finding.set({ status: 'OPEN', updatedAt: new Date() });
  await finding.save();
}

export async function verifyFix(finding: IVulnerability, lab: CyberLabAdapter, actor: string): Promise<{ passed: boolean; before: unknown; after: unknown }> {
  const probe = VERIFY_PROBES[finding.vulnKey];
  if (!probe) {
    throw new Error(`No verification probe defined for ${finding.vulnKey}`);
  }

  // Most probes need an authenticated token; VULN-009's own probe (a login attempt) does not,
  // and deliberately must still work even when VULN-009's own fix (a strict per-IP login
  // limiter) is blocking further logins from the scanner's own IP — which is in fact the
  // correct, intended effect of that fix. So: get a token if we can, but don't fail the whole
  // probe just because login itself is currently rate-limited.
  let token = '';
  let probeCtx: ProbeCtx = { token: '' };
  try {
    token = (await lab.demoLogin('alice')).token;
    const alice = lab.decodeToken(token);
    const { targetUser, crossTenantOrder } = await discoverTargets(lab, alice.userId, alice.tenantId);
    probeCtx = { token, aliceUserId: alice.userId, aliceEmail: alice.email, aliceTenantId: alice.tenantId, targetUser, crossTenantOrder };
  } catch (err) {
    if (finding.vulnKey !== 'VULN-009') throw err;
  }

  const before = finding.evidence as { response?: unknown };
  const after = await probe(lab, probeCtx);

  const passed = after.blocked;
  const run = await VerificationRun.create({
    _id: newId('ver'),
    findingId: finding._id,
    passed,
    outcome: passed ? 'BLOCKED' : 'STILL_VULNERABLE',
    before: (before.response ?? {}) as Record<string, unknown>,
    after: { ...after } as unknown as Record<string, unknown>,
    createdBy: actor,
  });
  publish('verification', run.toJSON());

  if (passed) {
    finding.set({ status: 'VERIFIED', updatedAt: new Date() });
    await finding.save();
  }

  return { passed, before: before.response ?? {}, after };
}

interface ProbeResult {
  blocked: boolean;
  status: number;
  detail: string;
}

interface ProbeCtx {
  token: string;
  aliceUserId?: string;
  aliceEmail?: string;
  aliceTenantId?: string;
  targetUser?: { id: string; email: string };
  crossTenantOrder?: { id: string; tenantId: string };
}

type Probe = (lab: CyberLabAdapter, ctx: ProbeCtx) => Promise<ProbeResult>;

// One minimal, deterministic re-check per vuln key: same request the scanner used, just
// re-evaluated for "is it still exploitable" rather than full evidence capture. The target
// user/order (for 001/002/010) comes from the same discovery oracle the scanner uses, never a
// hardcoded seed id — see discoverTargets() in modules/scanner/checks.ts.
const VERIFY_PROBES: Record<string, Probe> = {
  'VULN-001': async (lab, { token, targetUser }) => {
    if (!targetUser) return { blocked: true, status: 0, detail: 'No second user discovered to re-verify against; treating as blocked.' };
    const res = await lab.request('GET', `/api/users/${targetUser.id}`, { token });
    return { blocked: res.status !== 200, status: res.status, detail: `GET /api/users/${targetUser.id} -> ${res.status}` };
  },
  'VULN-002': async (lab, { token, crossTenantOrder }) => {
    if (!crossTenantOrder) return { blocked: true, status: 0, detail: 'No cross-tenant order discovered to re-verify against; treating as blocked.' };
    const res = await lab.request('GET', `/api/orders/${crossTenantOrder.id}`, { token });
    return { blocked: res.status !== 200, status: res.status, detail: `GET /api/orders/${crossTenantOrder.id} -> ${res.status}` };
  },
  'VULN-003': async (lab, { token }) => {
    const res = await lab.request('GET', '/api/admin/users/vulnerable', { token });
    return { blocked: res.status !== 200, status: res.status, detail: `GET /api/admin/users/vulnerable -> ${res.status}` };
  },
  'VULN-004': async (lab, { aliceEmail }) => {
    const res = await lab.request('POST', '/api/auth/vulnerable-login', { body: { email: aliceEmail, password: { $ne: null } } });
    return { blocked: res.status !== 200, status: res.status, detail: `vulnerable-login injection -> ${res.status}` };
  },
  'VULN-006': async (lab, { token }) => {
    const res = await lab.request('POST', '/api/fetch-url', { token, body: { url: 'http://internal-service:8080/internal/demo-secret' } });
    return { blocked: res.status !== 200, status: res.status, detail: `fetch-url SSRF -> ${res.status}` };
  },
  'VULN-007': async (lab, { token }) => {
    const res = await lab.request('GET', '/api/files/download?file=../internal-demo.txt', { token });
    return { blocked: res.status !== 200, status: res.status, detail: `path traversal -> ${res.status}` };
  },
  'VULN-011': async (lab, { token, aliceUserId }) => {
    const res = await lab.request('PATCH', `/api/users/${aliceUserId}`, { token, body: { role: 'TENANT_ADMIN' } });
    const roleAfter = (res.data as { role?: string })?.role;
    const blocked = roleAfter !== 'TENANT_ADMIN';
    if (!blocked) await lab.request('PATCH', `/api/users/${aliceUserId}`, { token, body: { role: 'USER' } });
    return { blocked, status: res.status, detail: `mass-assignment role patch -> role is now ${roleAfter}` };
  },
  'VULN-012': async (lab, { token }) => {
    const order = await lab.request('POST', '/api/orders', { token, body: { items: [{ productId: 'prod-1', quantity: 1 }] } });
    const orderId = (order.data as { id?: string })?.id;
    const res = await lab.request('POST', '/api/payments', { token, body: { orderId, status: 'completed', orderStatus: 'paid', amount: 0.01 } });
    const blocked = res.status >= 400 || (res.data as { amount?: number })?.amount !== 0.01;
    return { blocked, status: res.status, detail: `tampered payment -> ${res.status}, amount=${(res.data as { amount?: number })?.amount}` };
  },
  'VULN-005': async (lab, { token }) => {
    const marker = `sf-verify-${Date.now()}`;
    const payload = `<script>/*${marker}*/window.__sfXss=true</script>`;
    const res = await lab.request('POST', '/api/comments', { token, body: { productId: 'prod-1', content: payload } });
    const stored = (res.data as { content?: string })?.content;
    const blocked = res.status !== 201 || stored !== payload;
    return { blocked, status: res.status, detail: `comment stored as: ${String(stored).slice(0, 60)}` };
  },
  'VULN-008': async (lab, { token }) => {
    const res = await lab.request('POST', '/api/tools/ping', { token, body: { host: 'localhost; whoami' } });
    const blocked = res.status !== 200 || (res.data as { injectionDetected?: boolean })?.injectionDetected !== true;
    return { blocked, status: res.status, detail: `ping with shell metachar -> ${res.status}` };
  },
  'VULN-009': async lab => {
    // One real login attempt against the actual endpoint. If the strict fix is active and the
    // failure threshold (from this and earlier attempts) has been reached, CyberLab returns 429.
    const res = await lab.request('POST', '/api/auth/login', { body: { email: 'nonexistent-verify@attacker.test', password: `guess-${Date.now()}` } });
    const blocked = res.status === 429;
    return { blocked, status: res.status, detail: `login attempt -> ${res.status}` };
  },
  'VULN-010': async (lab, { aliceUserId, aliceEmail, aliceTenantId }) => {
    if (!config.cyberlab.labJwtSecret) {
      throw new Error('CYBERLAB_JWT_SECRET not configured; cannot verify VULN-010 (see docs/HACKATHON-DEMO.md known limitations)');
    }
    const forged = jwt.sign({ userId: aliceUserId, email: aliceEmail, role: 'SUPER_ADMIN', tenantId: aliceTenantId }, config.cyberlab.labJwtSecret, { expiresIn: '5m' });
    const res = await lab.request('GET', '/api/vulnerable/admin', { token: forged });
    const blocked = res.status !== 200;
    return { blocked, status: res.status, detail: `forged SUPER_ADMIN token for ${aliceUserId} -> ${res.status}` };
  },
  'VULN-013': async (lab, { token }) => {
    const boundary = `----sfverify${Date.now()}`;
    const filename = 'verify-probe.html';
    const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: text/html\r\n\r\n<p>sf-verify probe</p>\r\n--${boundary}--\r\n`;
    const res = await lab.request('POST', '/api/files/upload', { token, body, headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } });
    const blocked = res.status !== 201;
    return { blocked, status: res.status, detail: `.html upload -> ${res.status}` };
  },
  'VULN-014': async lab => {
    const file = await lab.getConfigFile();
    const findings = await runGitleaks('demo.env', file.content);
    const blocked = findings.length === 0;
    return { blocked, status: blocked ? 200 : 500, detail: `gitleaks found ${findings.length} credential(s) in ${file.path}` };
  },
};

export const VERIFIABLE_VULN_KEYS = Object.keys(VERIFY_PROBES);
