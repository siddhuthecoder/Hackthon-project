// tests/e2e/helpers.mjs
// Zero-dependency helpers shared by the SentinelForge Lab e2e suite.
// Node 20+ built-ins only: fetch, FormData, Blob, node:test, node:assert.

export const BASE_URL = process.env.SENTINELFORGE_API_URL || 'http://localhost:3001';

export const ADMIN = { email: 'admin@sentinelforge.lab', password: 'admin_demo_123' };
export const ALICE = { email: 'alice.anderson@tenant.alpha.com', password: 'demo_password_123', id: 'user-101' };

let seq = 0;
/** A unique, isolated source IP per test run so SOC detections do not cross-pollinate. */
export function freshIp() {
  seq += 1;
  const run = Date.now() % 200;
  return `10.88.${run}.${seq % 250}`;
}

/**
 * Thin fetch wrapper against the API. Returns { status, body, headers }.
 * `body` is parsed as JSON when the response declares an application/json
 * content-type, otherwise it is returned as text.
 */
export async function api(path, { method = 'GET', token, body, headers = {}, sourceIp, raw = false } = {}) {
  const finalHeaders = { ...headers };
  if (token) finalHeaders.Authorization = `Bearer ${token}`;
  if (sourceIp) finalHeaders['X-Forwarded-For'] = sourceIp;
  let payload = body;
  if (body !== undefined && !raw && !(body instanceof FormData)) {
    finalHeaders['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(`${BASE_URL}${path}`, { method, headers: finalHeaders, body: payload });
  const contentType = res.headers.get('content-type') || '';
  let parsed;
  if (contentType.includes('application/json')) {
    parsed = await res.json().catch(() => null);
  } else {
    parsed = await res.text();
  }
  return { status: res.status, body: parsed, headers: res.headers };
}

/** Logs in and returns the accessToken (throws if login fails). */
export async function login(email, password, sourceIp) {
  const res = await api('/api/auth/login', { method: 'POST', body: { email, password }, sourceIp });
  if (res.status !== 200 || !res.body?.accessToken) {
    throw new Error(`login failed for ${email}: HTTP ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body;
}

let cachedAdminToken = null;
export async function adminToken() {
  if (!cachedAdminToken) {
    const { accessToken } = await login(ADMIN.email, ADMIN.password);
    cachedAdminToken = accessToken;
  }
  return cachedAdminToken;
}

/** Finds a user by role + tenant via the admin API. Returns null if none found. */
export async function findUser({ role, tenantId }) {
  const token = await adminToken();
  const res = await api('/api/admin/users', { token });
  if (res.status !== 200 || !Array.isArray(res.body)) return null;
  return res.body.find(u => (!role || u.role === role) && (!tenantId || u.tenantId === tenantId)) || null;
}

/** Waits for the API's /health endpoint to respond 200, up to timeoutMs. */
export async function waitForApi(timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`API at ${BASE_URL} did not become healthy within ${timeoutMs}ms`);
}
