import { CheckResult } from '../../scanner/checks';
import { DiscoveredEndpoint, GenericAdapter } from './adapter';

const SECURITY_HEADERS = ['x-content-type-options', 'x-frame-options', 'strict-transport-security', 'content-security-policy'];

function base(partial: Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'>): Omit<CheckResult, 'outcome' | 'summary' | 'request' | 'response'> {
  return partial;
}

/** GEN-001: an endpoint the spec marks as requiring auth answers with a 2xx when called with no
 * credentials at all. Checks only the FIRST auth-required endpoint found — enough to demonstrate
 * the hygiene-check category live without hammering every discovered route on every scan. */
async function checkMissingAuth(adapter: GenericAdapter, endpoints: DiscoveredEndpoint[]): Promise<CheckResult> {
  const meta = base({
    vulnKey: 'GEN-001', title: 'Missing Authentication on Protected Endpoint', type: 'Broken Authentication', severity: 'high',
    cwe: 'CWE-306', owasp: 'API2:2023', endpoint: '(discovered endpoint)', method: 'GET',
    description: 'An endpoint the OpenAPI spec marks as requiring authentication accepted a request with no credentials.',
    impact: 'Any unauthenticated caller can reach a resource the API contract says should require auth.',
    remediation: 'Confirm the real deployment enforces the auth middleware the spec declares for this operation.',
  });
  const target = endpoints.find(e => e.authRequired && !e.path.includes('{'));
  if (!target) {
    return { ...meta, outcome: 'SKIPPED', summary: 'No auth-required endpoint without path parameters was discovered to test.', request: {}, response: {} };
  }
  const res = await adapter.request(target.method, target.path);
  const vulnerable = res.status >= 200 && res.status < 300;
  return {
    ...meta, endpoint: target.path, method: target.method,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `${target.method} ${target.path} (spec-flagged as requiring auth) returned ${res.status} with no credentials.` : `Correctly rejected (status=${res.status}).`,
    request: { call: `${target.method} ${target.path}`, auth: 'none' },
    response: { status: res.status },
  };
}

/** GEN-002: standard security headers missing from the base response. */
async function checkSecurityHeaders(adapter: GenericAdapter): Promise<CheckResult> {
  const meta = base({
    vulnKey: 'GEN-002', title: 'Missing Security Headers', type: 'Security Misconfiguration', severity: 'low',
    cwe: 'CWE-16', owasp: 'A05:2021', endpoint: '/', method: 'GET',
    description: 'The server does not set one or more standard defensive HTTP headers.',
    impact: 'Missing headers (clickjacking protection, MIME-sniffing protection, HSTS, CSP) remove a defense-in-depth layer against several client-side attack classes.',
    remediation: 'Set X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security and a Content-Security-Policy on all responses.',
  });
  const res = await adapter.request('GET', '/');
  const headers = Object.keys(res.headers ?? {}).map(h => h.toLowerCase());
  const missing = SECURITY_HEADERS.filter(h => !headers.includes(h));
  const vulnerable = missing.length > 0;
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? `Missing: ${missing.join(', ')}.` : 'All checked security headers present.',
    request: { call: 'GET /' },
    response: { status: res.status, missingHeaders: missing },
  };
}

/** GEN-003: a deliberately invalid path leaks a stack trace instead of a clean error body. */
async function checkVerboseErrors(adapter: GenericAdapter): Promise<CheckResult> {
  const meta = base({
    vulnKey: 'GEN-003', title: 'Verbose Error Disclosure', type: 'Information Disclosure', severity: 'medium',
    cwe: 'CWE-209', owasp: 'A05:2021', endpoint: '/__sf_generic_probe_404__', method: 'GET',
    description: 'A request to a nonexistent path returned a stack trace or internal file path instead of a clean error response.',
    impact: 'Stack traces can reveal internal file paths, framework/library versions, and code structure useful for further attacks.',
    remediation: 'Return a generic error body in production; log the real stack trace server-side only.',
  });
  const res = await adapter.request('GET', '/__sf_generic_probe_404__');
  const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '');
  const vulnerable = /node_modules|\bat\s+\S+\s*\(.*:\d+:\d+\)/.test(body);
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Response body contains stack-trace-shaped content.' : 'Clean error response, no stack trace detected.',
    request: { call: 'GET /__sf_generic_probe_404__' },
    response: { status: res.status, bodyPreview: body.slice(0, 300) },
  };
}

/** GEN-004: a wildcard CORS policy. */
async function checkPermissiveCors(adapter: GenericAdapter): Promise<CheckResult> {
  const meta = base({
    vulnKey: 'GEN-004', title: 'Permissive CORS Policy', type: 'CORS Misconfiguration', severity: 'medium',
    cwe: 'CWE-942', owasp: 'A05:2021', endpoint: '/', method: 'GET',
    description: 'The server reflects a wildcard Access-Control-Allow-Origin header.',
    impact: 'Any website can make cross-origin requests on behalf of a visitor and read the response, widening the attack surface for credential/data theft if session data is exposed this way.',
    remediation: 'Restrict Access-Control-Allow-Origin to an explicit allowlist of known frontend origins.',
  });
  const res = await adapter.request('GET', '/', { headers: { Origin: 'https://sf-cors-probe.example.com' } });
  const allowOrigin = (res.headers ?? {})['access-control-allow-origin'];
  const vulnerable = allowOrigin === '*';
  return {
    ...meta,
    outcome: vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE',
    summary: vulnerable ? 'Access-Control-Allow-Origin: * reflected for an arbitrary origin.' : `No wildcard CORS detected (header=${allowOrigin ?? 'absent'}).`,
    request: { call: 'GET / with Origin: https://sf-cors-probe.example.com' },
    response: { status: res.status, accessControlAllowOrigin: allowOrigin },
  };
}

export async function runGenericChecks(adapter: GenericAdapter, endpoints: DiscoveredEndpoint[]): Promise<CheckResult[]> {
  const checks = [
    () => checkMissingAuth(adapter, endpoints),
    () => checkSecurityHeaders(adapter),
    () => checkVerboseErrors(adapter),
    () => checkPermissiveCors(adapter),
  ];
  const results: CheckResult[] = [];
  for (const check of checks) {
    try {
      results.push(await check());
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
