import jwt from 'jsonwebtoken';
import { config } from '../../config';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { GitleaksUnavailableError, runGitleaks } from './gitleaks';
import { runSemgrep } from './semgrep';
import { runScaScan, ScaUnavailableError } from './sca';
import { runRbacMatrix } from './rbac';

export type CheckOutcome = 'VULNERABLE' | 'NOT_VULNERABLE' | 'SKIPPED' | 'ERROR';

export interface CheckResult {
  vulnKey: string;
  title: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cwe: string;
  owasp: string;
  endpoint: string;
  method: string;
  outcome: CheckOutcome;
  summary: string;
  description: string;
  impact: string;
  remediation: string;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
}

interface CheckContext {
  lab: CyberLabAdapter;
  aliceToken: string;
  aliceUserId: string;
  aliceEmail: string;
  aliceTenantId: string;
  /** Another real user, discovered at scan time via the stable admin oracle — not a hardcoded
   * seed id. Undefined if the current seed only has one user (gracefully skips cross-user checks). */
  targetUser?: { id: string; email: string };
  /** A real order belonging to a different tenant than Alice's, discovered the same way.
   * Undefined if the seed has only one tenant's worth of orders. */
  crossTenantOrder?: { id: string; tenantId: string };
}

type Check = (ctx: CheckContext) => Promise<CheckResult>;

function base(partial: Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'>): Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'> {
  return partial;
}

const checkIdor: Check = async ({ lab, aliceToken, aliceUserId, aliceEmail, targetUser }) => {
  const meta = base({
    vulnKey: 'VULN-001', title: 'Broken Object Level Authorization', type: 'IDOR/BOLA', severity: 'high',
    cwe: 'CWE-639', owasp: 'API1:2023', endpoint: '/api/users/:userId', method: 'GET',
    description: 'GET /api/users/:userId returns any user record for any authenticated caller, without checking that the caller owns the requested id.',
    impact: 'Any authenticated user can read every other user profile (PII: name, email, phone) by changing the id in the URL.',
    remediation: 'Require req.user.userId === params.userId, or an admin role, before returning the record (the lab already ships this as GET /api/users/secure/:userId).',
  });
  if (!targetUser) {
    return { ...meta, outcome: 'SKIPPED', summary: 'No second user discovered in the current seed data to test cross-user access against.', request: {}, response: {} };
  }
  const own = await lab.request('GET', `/api/users/${aliceUserId}`, { token: aliceToken });
  const other = await lab.request('GET', `/api/users/${targetUser.id}`, { token: aliceToken });
  const vulnerable = own.status === 200 && other.status === 200;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable
      ? `${aliceEmail} (${aliceUserId}) read ${targetUser.id}'s full profile using her own token.`
      : `Cross-user read blocked (own=${own.status}, other=${other.status}).`,
    request: { ownProfile: `GET /api/users/${aliceUserId}`, otherProfile: `GET /api/users/${targetUser.id}`, authAs: aliceEmail },
    response: { ownStatus: own.status, otherStatus: other.status, otherBody: other.data },
  };
};

const checkCrossTenant: Check = async ({ lab, aliceToken, aliceEmail, aliceTenantId, crossTenantOrder }) => {
  const meta = base({
    vulnKey: 'VULN-002', title: 'Cross-Tenant Data Access', type: 'Cross-Tenant Access', severity: 'critical',
    cwe: 'CWE-639', owasp: 'API1:2023', endpoint: '/api/orders/:orderId', method: 'GET',
    description: 'GET /api/orders/:orderId does not verify the order belongs to the caller\'s tenant.',
    impact: 'A user in Tenant Alpha can read order records (customer, items, totals) belonging to Tenant Beta or Gamma.',
    remediation: 'Check order.tenantId === req.user.tenantId (or SUPER_ADMIN) before returning (ships as GET /api/orders/secure/:orderId).',
  });
  if (!crossTenantOrder) {
    return { ...meta, outcome: 'SKIPPED', summary: 'No order from a different tenant discovered in the current seed data to test cross-tenant access against.', request: {}, response: {} };
  }
  const other = await lab.request('GET', `/api/orders/${crossTenantOrder.id}`, { token: aliceToken });
  const otherTenant = (other.data as { tenantId?: string })?.tenantId ?? crossTenantOrder.tenantId;
  const vulnerable = other.status === 200 && otherTenant !== aliceTenantId;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable
      ? `Alice (${aliceTenantId}) read ${crossTenantOrder.id} belonging to ${otherTenant}.`
      : `Cross-tenant read blocked (status=${other.status}).`,
    request: { otherOrder: `GET /api/orders/${crossTenantOrder.id}`, authAs: `${aliceEmail} (${aliceTenantId})` },
    response: { otherStatus: other.status, otherTenant, otherBody: other.data },
  };
};

const checkBrokenRbac: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-003', title: 'Broken Function Level Authorization', type: 'Broken RBAC', severity: 'high',
    cwe: 'CWE-285', owasp: 'API5:2023', endpoint: '/api/admin/users/vulnerable', method: 'GET',
    description: 'GET /api/admin/users/vulnerable lists all users without checking the caller\'s role.',
    impact: 'A regular USER account can read the full admin user directory across tenants.',
    remediation: 'Add requireRole(\'SUPER_ADMIN\",\"TENANT_ADMIN\") (ships as the secure GET /api/admin/users).',
  });
  const res = await lab.request('GET', '/api/admin/users/vulnerable', { token: aliceToken });
  const vulnerable = res.status === 200;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Non-admin user (USER role) listed admin users successfully.' : `Blocked (status=${res.status}).`,
    request: { call: 'GET /api/admin/users/vulnerable', authAs: 'alice.anderson (role=USER)' },
    response: { status: res.status, userCount: Array.isArray((res.data as { users?: unknown[] })?.users) ? (res.data as { users: unknown[] }).users.length : undefined },
  };
};

const checkNoSqlInjection: Check = async ({ lab, aliceEmail }) => {
  const meta = base({
    vulnKey: 'VULN-004', title: 'NoSQL Injection in Login', type: 'NoSQL Injection', severity: 'critical',
    cwe: 'CWE-943', owasp: 'API3:2023', endpoint: '/api/auth/vulnerable-login', method: 'POST',
    description: 'The vulnerable login builds a MongoDB filter directly from request body values. Sending an operator object as the password bypasses the bcrypt check.',
    impact: 'An attacker can authenticate as any known user email without knowing the password.',
    remediation: 'Reject non-string email/password before querying (ships as POST /api/auth/secure-login).',
  });
  const res = await lab.request('POST', '/api/auth/vulnerable-login', { body: { email: aliceEmail, password: { $ne: null } } });
  const token = (res.data as { accessToken?: string })?.accessToken;
  const vulnerable = res.status === 200 && Boolean(token);
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Operator-injection payload authenticated as ${aliceEmail} without her password.` : `Injection rejected (status=${res.status}).`,
    request: { call: 'POST /api/auth/vulnerable-login', body: { email: aliceEmail, password: '{ $ne: null }' } },
    response: { status: res.status, tokenIssued: Boolean(token) },
  };
};

const checkStoredXss: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-005', title: 'Stored Cross-Site Scripting', type: 'Stored XSS', severity: 'high',
    cwe: 'CWE-79', owasp: 'A03:2021', endpoint: '/api/comments', method: 'POST',
    description: 'POST /api/comments stores raw HTML/script content without escaping.',
    impact: 'A script payload posted as a comment is stored unescaped and would execute in another user\'s browser when the comment is rendered.',
    remediation: 'HTML-escape content before storing or before rendering (ships as the safe=true path / POST /api/comments/safe).',
  });
  const marker = `sf-scan-${Date.now()}`;
  const payload = `<script>/*${marker}*/window.__sfXss=true</script>`;
  const res = await lab.request('POST', '/api/comments', { token: aliceToken, body: { productId: 'prod-1', content: payload } });
  const stored = (res.data as { content?: string })?.content;
  const vulnerable = res.status === 201 && stored === payload;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Script payload stored byte-for-byte, unescaped.' : `Payload rejected or escaped (status=${res.status}).`,
    request: { call: 'POST /api/comments', body: { content: payload } },
    response: { status: res.status, storedContent: stored },
  };
};

const checkSsrf: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-006', title: 'Server-Side Request Forgery', type: 'SSRF', severity: 'high',
    cwe: 'CWE-918', owasp: 'API10:2023', endpoint: '/api/fetch-url', method: 'POST',
    description: 'POST /api/fetch-url makes a server-side request to any URL the caller supplies, including internal-only services.',
    impact: 'An attacker can reach internal network services (here, the internal-service container) that should not be reachable from outside.',
    remediation: 'Restrict outbound targets to an explicit allowlist (ships as POST /api/fetch-url/secure).',
  });
  const target = 'http://internal-service:8080/internal/demo-secret';
  const res = await lab.request('POST', '/api/fetch-url', { token: aliceToken, body: { url: target } });
  const vulnerable = res.status === 200 && typeof (res.data as { data?: string })?.data === 'string' && (res.data as { data: string }).data.includes('demo_internal_secret');

  // Supplementary static-analysis evidence from a real Semgrep scan of CyberLab's source
  // (non-authoritative — the live HTTP probe above is what sets `vulnerable`; this is corroborating
  // source-level evidence, same class of signal a real AppSec report would attach alongside a DAST
  // finding). Never fails the check itself if semgrep isn't available.
  let staticFindings: unknown = undefined;
  try {
    staticFindings = await runSemgrep();
  } catch (err) {
    staticFindings = { unavailable: true, reason: err instanceof Error ? err.message : 'unknown error' };
  }

  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Server fetched an internal-only endpoint and returned its body to the caller.' : `Fetch blocked (status=${res.status}).`,
    request: { call: 'POST /api/fetch-url', body: { url: target } },
    response: { status: res.status, body: res.data, staticAnalysis: { tool: 'semgrep', findings: staticFindings } },
  };
};

const checkPathTraversal: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-007', title: 'Path Traversal in File Download', type: 'Path Traversal', severity: 'high',
    cwe: 'CWE-22', owasp: 'A01:2021', endpoint: '/api/files/download', method: 'GET',
    description: 'GET /api/files/download?file= joins the requested name onto the public directory without checking the result stays inside it.',
    impact: 'A caller can read files outside the intended public directory (here, an internal-only demo file) via ../ segments.',
    remediation: 'Resolve and verify the final path stays within the sandbox before reading, or allowlist file names (ships as the /secure variant).',
  });
  const res = await lab.request('GET', '/api/files/download?file=../internal-demo.txt', { token: aliceToken });
  const vulnerable = res.status === 200 && Boolean((res.data as { content?: string })?.content);
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Traversal read a file outside the public demo-files directory.' : `Traversal blocked (status=${res.status}).`,
    request: { call: 'GET /api/files/download?file=../internal-demo.txt' },
    response: { status: res.status, traversed: (res.data as { traversed?: boolean })?.traversed },
  };
};

const checkCommandInjection: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-008', title: 'Command Injection Demo', type: 'Command Injection', severity: 'medium',
    cwe: 'CWE-78', owasp: 'A03:2021', endpoint: '/api/tools/ping', method: 'POST',
    description: 'POST /api/tools/ping builds a shell command from the host field without rejecting shell metacharacters (the lab sandboxes execution, but the endpoint itself performs no input validation).',
    impact: 'Input containing shell metacharacters (;, |, &, `, $()) is detected as an injection attempt by the endpoint itself, confirming the missing validation that a real shell call would need.',
    remediation: 'Validate the host against a strict hostname pattern before use (ships as POST /api/tools/ping/secure).',
  });
  const res = await lab.request('POST', '/api/tools/ping', { token: aliceToken, body: { host: 'localhost; whoami' } });
  const vulnerable = res.status === 200 && (res.data as { injectionDetected?: boolean })?.injectionDetected === true;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Shell-metacharacter payload accepted and processed instead of being rejected as invalid input.' : `Payload rejected (status=${res.status}).`,
    request: { call: 'POST /api/tools/ping', body: { host: 'localhost; whoami' } },
    response: { status: res.status, output: (res.data as { output?: string })?.output },
  };
};

const checkWeakRateLimit: Check = async ({ lab }) => {
  const meta = base({
    vulnKey: 'VULN-009', title: 'Weak Rate Limiting on Login', type: 'Weak Rate Limiting', severity: 'medium',
    cwe: 'CWE-307', owasp: 'API4:2023', endpoint: '/api/auth/login', method: 'POST',
    description: 'The login endpoint keys its failure counter on a client-controlled header and the threshold is high, so credential-stuffing attempts are not meaningfully throttled.',
    impact: 'An attacker can make many password guesses against a single account before being blocked.',
    remediation: 'Rate-limit by a server-trusted key with a low threshold (the lab fix applies a strict 5-failure limiter).',
  });
  let blocked = 0;
  for (let i = 0; i < 12; i += 1) {
    const res = await lab.request('POST', '/api/auth/login', { body: { email: 'nonexistent-scan@attacker.test', password: `guess-${i}-${Date.now()}` } });
    if (res.status === 429) blocked += 1;
  }
  const vulnerable = blocked === 0;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? '12 rapid failed logins, none throttled (0 HTTP 429 responses).' : `${blocked}/12 attempts throttled.`,
    request: { call: 'POST /api/auth/login x12', note: 'distinct bad passwords, same IP' },
    response: { attempts: 12, throttled: blocked },
  };
};

const checkJwtRoleTrust: Check = async ({ lab, aliceUserId, aliceEmail, aliceTenantId }) => {
  const meta = base({
    vulnKey: 'VULN-010', title: 'JWT Authorization Weakness', type: 'JWT Authorization', severity: 'high',
    cwe: 'CWE-285', owasp: 'API5:2023', endpoint: '/api/vulnerable/admin', method: 'GET',
    description: 'GET /api/vulnerable/admin trusts the role claim embedded in a valid JWT and never re-checks the user\'s current role in the database.',
    impact: 'A token minted (or leaked) with an elevated role claim grants admin access even if the account\'s real database role is non-admin.',
    remediation: 'Re-verify the caller\'s role against the database on every privileged request (ships as /api/vulnerable/admin/secure).',
  });
  if (!config.cyberlab.labJwtSecret) {
    return { ...meta, outcome: 'SKIPPED', summary: 'CYBERLAB_JWT_SECRET not configured; skipping forged-token probe.', request: {}, response: {} };
  }
  // Alice's own real id/email/tenant (whatever the current seed's "alice" demo account actually
  // is), with the role claim forged to SUPER_ADMIN — no second account needed to prove role-trust.
  const forged = jwt.sign({ userId: aliceUserId, email: aliceEmail, role: 'SUPER_ADMIN', tenantId: aliceTenantId }, config.cyberlab.labJwtSecret, { expiresIn: '5m' });
  const res = await lab.request('GET', '/api/vulnerable/admin', { token: forged });
  const vulnerable = res.status === 200 && (res.data as { currentDbRole?: string })?.currentDbRole !== 'SUPER_ADMIN';
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable
      ? `Forged token claiming SUPER_ADMIN for ${aliceUserId} was accepted; real DB role is ${(res.data as { currentDbRole?: string }).currentDbRole}.`
      : `Forged token rejected or DB role matched (status=${res.status}).`,
    request: { call: 'GET /api/vulnerable/admin', token: `forged JWT: role=SUPER_ADMIN for ${aliceUserId} (real role=USER)` },
    response: { status: res.status, jwtRole: (res.data as { jwtRole?: string })?.jwtRole, currentDbRole: (res.data as { currentDbRole?: string })?.currentDbRole },
  };
};

const checkMassAssignment: Check = async ({ lab, aliceToken, aliceUserId }) => {
  const meta = base({
    vulnKey: 'VULN-011', title: 'Mass Assignment Privilege Escalation', type: 'Mass Assignment', severity: 'high',
    cwe: 'CWE-915', owasp: 'API8:2023', endpoint: '/api/users/:id', method: 'PATCH',
    description: 'PATCH /api/users/:id writes every field in the request body to the user document, including role and tenantId.',
    impact: 'A user can PATCH their own record to grant themselves an admin role.',
    remediation: 'Allowlist updatable fields (name, email, phone) server-side (ships as PATCH /api/users/secure/:id).',
  });
  const before = await lab.request('GET', `/api/users/${aliceUserId}`, { token: aliceToken });
  const originalRole = (before.data as { role?: string })?.role ?? 'USER';
  const patch = await lab.request('PATCH', `/api/users/${aliceUserId}`, { token: aliceToken, body: { role: 'TENANT_ADMIN' } });
  const newRole = (patch.data as { role?: string })?.role;
  const vulnerable = patch.status === 200 && newRole === 'TENANT_ADMIN';
  // Self-heal: always revert so the demo/lab stays in a known state regardless of outcome.
  await lab.request('PATCH', `/api/users/${aliceUserId}`, { token: aliceToken, body: { role: originalRole } });
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Alice escalated her own role to TENANT_ADMIN via PATCH body (reverted to ${originalRole} after the check).` : `Escalation blocked (status=${patch.status}).`,
    request: { call: `PATCH /api/users/${aliceUserId}`, body: { role: 'TENANT_ADMIN' } },
    response: { status: patch.status, roleAfterPatch: newRole, revertedTo: originalRole },
  };
};

const checkBusinessLogic: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-012', title: 'Payment Business Logic Abuse', type: 'Business Logic', severity: 'high',
    cwe: 'CWE-840', owasp: 'API8:2023', endpoint: '/api/payments', method: 'POST',
    description: 'POST /api/payments accepts client-supplied amount and orderStatus instead of computing them server-side.',
    impact: 'A caller can mark an order paid while paying far less than the real total (here, 0.01 instead of the real price).',
    remediation: 'Compute amount from the order server-side and drive status through a fixed state machine (ships as POST /api/payments/secure).',
  });
  const order = await lab.request('POST', '/api/orders', { token: aliceToken, body: { items: [{ productId: 'prod-1', quantity: 1 }] } });
  const orderId = (order.data as { id?: string })?.id;
  const total = (order.data as { total?: number })?.total ?? 0;
  if (!orderId) {
    return { ...meta, outcome: 'ERROR', summary: 'Could not create a test order.', request: {}, response: { orderStatus: order.status } };
  }
  const pay = await lab.request('POST', '/api/payments', { token: aliceToken, body: { orderId, status: 'completed', orderStatus: 'paid', amount: 0.01 } });
  const paidAmount = (pay.data as { amount?: number })?.amount;
  const resultStatus = (pay.data as { orderStatus?: string })?.orderStatus;
  const vulnerable = pay.status === 200 && resultStatus === 'paid' && paidAmount === 0.01 && total > 0.01;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Order worth ${total} marked paid with a submitted amount of 0.01.` : `Tampered payment rejected (status=${pay.status}).`,
    request: { call: 'POST /api/payments', body: { orderId, status: 'completed', orderStatus: 'paid', amount: 0.01 }, realOrderTotal: total },
    response: { status: pay.status, orderStatus: resultStatus, paidAmount },
  };
};

const checkInsecureUpload: Check = async ({ lab, aliceToken }) => {
  const meta = base({
    vulnKey: 'VULN-013', title: 'Insecure File Upload', type: 'File Upload', severity: 'medium',
    cwe: 'CWE-434', owasp: 'A04:2021', endpoint: '/api/files/upload', method: 'POST',
    description: 'POST /api/files/upload accepts any file extension/mimetype (the lab blocks only host-executable extensions as a safety guard).',
    impact: 'A caller can upload a file type that should be rejected (e.g. an HTML/script file) and have it stored and served back.',
    remediation: 'Allowlist extensions and mimetypes server-side (ships as POST /api/files/upload/secure).',
  });
  const boundary = `----sfscan${Date.now()}`;
  const filename = 'scan-probe.html';
  const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: text/html\r\n\r\n<p>sf-scan probe</p>\r\n--${boundary}--\r\n`;
  const res = await lab.request('POST', '/api/files/upload', { token: aliceToken, body, headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } });
  const vulnerable = res.status === 201 && (res.data as { riskyExtension?: boolean })?.riskyExtension === true;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'A .html file upload was accepted and flagged risky by the server itself.' : `Upload rejected (status=${res.status}).`,
    request: { call: 'POST /api/files/upload', filename },
    response: { status: res.status, body: res.data },
  };
};

const checkSecretExposure: Check = async ({ lab }) => {
  const meta = base({
    vulnKey: 'VULN-014', title: 'Secret Exposure in Configuration', type: 'Secret Exposure', severity: 'medium',
    cwe: 'CWE-540', owasp: 'A05:2021', endpoint: 'config/demo.env', method: 'GET',
    description: 'A configuration file in the repository contains credential-shaped values committed as plain text, confirmed by a real Gitleaks scan (not a hand-rolled regex).',
    impact: 'Anyone with repository access (or who finds the file) obtains working-looking secrets without needing to compromise the running service.',
    remediation: 'Remove committed secrets, rotate them, and load real secrets only from a secret manager or untracked local env files.',
  });
  let file: { path: string; content: string };
  try {
    file = await lab.getConfigFile();
  } catch (err) {
    return { ...meta, outcome: 'ERROR', summary: `Could not read config file from CyberLab: ${err instanceof Error ? err.message : 'unknown error'}`, request: {}, response: {} };
  }
  try {
    const findings = await runGitleaks('demo.env', file.content);
    const vulnerable = findings.length > 0;
    return {
      ...meta,
      outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
      summary: vulnerable
        ? `Gitleaks found ${findings.length} credential-shaped line(s) in ${file.path} (rule: ${findings[0].ruleId}).`
        : `Gitleaks found no live credentials in ${file.path}.`,
      request: { file: file.path, tool: 'gitleaks' },
      response: { findings },
    };
  } catch (err) {
    if (err instanceof GitleaksUnavailableError) {
      return { ...meta, outcome: 'ERROR', summary: err.message, request: { file: file.path, tool: 'gitleaks' }, response: {} };
    }
    throw err;
  }
};

const checkDependencyVulnerabilities: Check = async () => {
  const meta = base({
    vulnKey: 'VULN-015', title: 'Vulnerable Dependencies', type: 'Vulnerable and Outdated Components', severity: 'medium',
    cwe: 'CWE-937', owasp: 'A06:2021', endpoint: 'package-lock.json', method: 'GET',
    description: 'One or more resolved npm dependencies (direct or transitive) have a known vulnerability advisory, confirmed by a real query against the OSV database.',
    impact: 'A vulnerable dependency can be exploited through whatever code path actually calls into it, even though the application\'s own code may be correct.',
    remediation: 'Upgrade the affected package(s) to a patched version; run `npm audit fix` or update the specific dependency in package.json.',
  });
  let findings;
  try {
    findings = await runScaScan();
  } catch (err) {
    if (err instanceof ScaUnavailableError) {
      return { ...meta, outcome: 'ERROR', summary: err.message, request: {}, response: {} };
    }
    throw err;
  }
  const vulnerable = findings.length > 0;
  const worstSeverity = findings.find(f => f.severity === 'critical') ? 'critical' : findings.find(f => f.severity === 'high') ? 'high' : meta.severity;
  return {
    ...meta, severity: worstSeverity as 'low' | 'medium' | 'high' | 'critical',
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable
      ? `OSV found ${findings.length} real advisory match(es) across resolved dependencies (e.g. ${findings[0].packageName}@${findings[0].version}: ${findings[0].id}).`
      : 'No known-vulnerable dependencies found by OSV among resolved packages.',
    request: { tool: 'osv.dev', source: 'package-lock.json' },
    response: { findings: findings.slice(0, 15) },
  };
};

const checkJwtAlgNone: Check = async ({ lab, aliceUserId, aliceEmail, aliceTenantId }) => {
  const meta = base({
    vulnKey: 'VULN-017', title: 'JWT Algorithm Confusion ("alg: none")', type: 'JWT Authorization', severity: 'critical',
    cwe: 'CWE-347', owasp: 'API2:2023', endpoint: '/api/auth/me', method: 'GET',
    description: 'A JWT signed with the "none" algorithm (no signature at all) is tested against a real protected endpoint — the classic CVE-2015-9235-style forgery, testing the actual jsonwebtoken library behavior rather than assuming it.',
    impact: 'If accepted, any attacker can forge a token for any user/role with no knowledge of any secret at all — complete authentication bypass.',
    remediation: 'Explicitly pass `algorithms: [\'HS256\']` (or whatever the real signing algorithm is) to every jwt.verify() call, never let it infer from the token header.',
  });
  // jsonwebtoken itself refuses to even construct an "alg: none" token via jwt.sign with a
  // truthy secret, so the unsigned token is built by hand — the exact shape a real attacker's
  // forged token would have.
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ userId: aliceUserId, email: aliceEmail, role: 'SUPER_ADMIN', tenantId: aliceTenantId })).toString('base64url');
  const forged = `${header}.${payload}.`;
  const res = await lab.request('GET', '/api/auth/me', { token: forged });
  const vulnerable = res.status === 200;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'An unsigned ("alg: none") token with a forged SUPER_ADMIN claim was accepted — complete auth bypass.' : `Unsigned token correctly rejected (status=${res.status}).`,
    request: { call: 'GET /api/auth/me', token: 'alg:none forged token, no signature' },
    response: { status: res.status },
  };
};

const checkRbacMatrix: Check = async ({ lab }) => {
  const meta = base({
    vulnKey: 'VULN-016', title: 'RBAC Regression Matrix', type: 'Broken Function Level Authorization', severity: 'critical',
    cwe: 'CWE-285', owasp: 'API5:2023', endpoint: '/api/admin/users/*', method: 'MULTIPLE',
    description: 'A systematic sweep: every real non-admin role (USER, STAFF, MANAGER) is logged in and used to attempt every admin-only action, not just the one endpoint checkBrokenRbac already covers.',
    impact: 'A role-check regression on any admin endpoint would let a non-admin account read the full user directory or grant themselves elevated privileges.',
    remediation: 'Ensure every admin route keeps its requireRole(...) middleware; this check exists to catch a future regression, not a known-missing check.',
  });
  const results = await runRbacMatrix(lab);
  if (results.length === 0) {
    return { ...meta, outcome: 'SKIPPED', summary: 'Could not discover enough distinct-role accounts to build the matrix.', request: {}, response: {} };
  }
  const breaches = results.filter(r => !r.actuallyBlocked);
  const vulnerable = breaches.length > 0;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable
      ? `${breaches.length}/${results.length} probe(s) in the role matrix were NOT blocked (e.g. ${breaches[0].role} → ${breaches[0].method} ${breaches[0].endpoint} returned ${breaches[0].status}).`
      : `All ${results.length} role-matrix probes correctly blocked (403) across USER/STAFF/MANAGER against admin-only endpoints.`,
    request: { matrix: results.map(r => `${r.role} → ${r.method} ${r.endpoint}`) },
    response: { results },
  };
};

export const CHECKS: Check[] = [
  checkIdor,
  checkCrossTenant,
  checkBrokenRbac,
  checkNoSqlInjection,
  checkStoredXss,
  checkSsrf,
  checkPathTraversal,
  checkCommandInjection,
  checkWeakRateLimit,
  checkJwtRoleTrust,
  checkMassAssignment,
  checkBusinessLogic,
  checkInsecureUpload,
  checkSecretExposure,
  checkDependencyVulnerabilities,
  checkRbacMatrix,
  checkJwtAlgNone,
];

/** Discovers a second real user and a real cross-tenant order via the lab's own SUPER_ADMIN
 * seed account (a stable oracle, independent of any VULN fix-toggle state) so the IDOR/
 * cross-tenant/JWT checks never need to hardcode specific seeded ids. Falls back to `undefined`
 * (checks then report SKIPPED, not a false ERROR) if the discovery calls themselves fail — a
 * discovery outage should never crash the whole scan. */
export async function discoverTargets(
  lab: CyberLabAdapter,
  aliceUserId: string,
  aliceTenantId: string,
): Promise<{ targetUser?: { id: string; email: string }; crossTenantOrder?: { id: string; tenantId: string } }> {
  try {
    const adminToken = await lab.discoveryLogin();
    const usersRes = await lab.request('GET', '/api/admin/users', { token: adminToken });
    const users = Array.isArray(usersRes.data) ? (usersRes.data as { id: string; email: string }[]) : [];
    const targetUser = users.find(u => u.id !== aliceUserId);

    const ordersRes = await lab.request('GET', '/api/orders?limit=100', { token: adminToken });
    const orders = Array.isArray(ordersRes.data) ? (ordersRes.data as { id: string; tenantId: string }[]) : [];
    const crossTenantOrderRecord = orders.find(o => o.tenantId !== aliceTenantId);
    const crossTenantOrder = crossTenantOrderRecord ? { id: crossTenantOrderRecord.id, tenantId: crossTenantOrderRecord.tenantId } : undefined;

    return { targetUser, crossTenantOrder };
  } catch {
    return {};
  }
}

export async function runAllChecks(lab: CyberLabAdapter): Promise<CheckResult[]> {
  const { token: aliceToken, email: aliceEmail } = await lab.demoLogin('alice');
  const alice = lab.decodeToken(aliceToken);
  const { targetUser, crossTenantOrder } = await discoverTargets(lab, alice.userId, alice.tenantId);
  const ctx: CheckContext = {
    lab, aliceToken, aliceEmail,
    aliceUserId: alice.userId, aliceTenantId: alice.tenantId,
    targetUser, crossTenantOrder,
  };
  const results: CheckResult[] = [];
  for (const check of CHECKS) {
    try {
      results.push(await check(ctx));
    } catch (err) {
      results.push({
        vulnKey: 'UNKNOWN', title: 'Check failed', type: 'ERROR', severity: 'low', cwe: '', owasp: '',
        endpoint: '', method: '', outcome: 'ERROR', summary: err instanceof Error ? err.message : 'Unexpected error',
        description: '', impact: '', remediation: '', request: {}, response: {},
      });
    }
  }
  return results;
}
