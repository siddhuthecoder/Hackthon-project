import type {
  AttackGraph,
  AuditLog,
  AuthUser,
  Comment,
  Customer,
  DemoStatus,
  DetectionRule,
  Incident,
  IncidentStatus,
  Notification,
  Order,
  Payment,
  Product,
  Role,
  ScenarioInfo,
  SecurityEvent,
  SimulationResult,
  Tenant,
  User,
  Vulnerability,
} from './types';

const TOKEN_KEY = 'sf_access_token';
const DEMO_EMAIL = 'admin@sentinelforge.lab';
const DEMO_PASSWORD = 'admin_demo_123';

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: AuthUser;
}

function readToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function writeToken(token: string | null): void {
  if (typeof window === 'undefined') return;
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage unavailable; a fresh login happens on the next call
  }
}

let loginInFlight: Promise<string> | null = null;

async function parseError(res: Response): Promise<ApiError> {
  let message = `Request failed (${res.status})`;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
      message = body.error;
    }
  } catch {
    // non-JSON error body
  }
  return new ApiError(message, res.status);
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw await parseError(res);
  const data = (await res.json()) as LoginResponse;
  writeToken(data.accessToken);
  return data;
}

/** Lab convenience: sign in as the demo super admin when no token is stored. */
async function ensureToken(forceRefresh: boolean): Promise<string> {
  const existing = forceRefresh ? null : readToken();
  if (existing) return existing;
  if (!loginInFlight) {
    loginInFlight = login(DEMO_EMAIL, DEMO_PASSWORD)
      .then((r) => r.accessToken)
      .finally(() => {
        loginInFlight = null;
      });
  }
  return loginInFlight;
}

async function request<T>(path: string, method: string, body: unknown, auth: boolean, retried = false): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth) headers.Authorization = `Bearer ${await ensureToken(retried)}`;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401 && auth && !retried) {
    writeToken(null);
    return request<T>(path, method, body, auth, true);
  }
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

const get = <T>(path: string, auth = true) => request<T>(path, 'GET', undefined, auth);
const send = <T>(method: string, path: string, body: unknown, auth = true) => request<T>(path, method, body, auth);

function query(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') sp.set(k, String(v));
  });
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export const api = {
  // Authenticated
  users: () => get<User[]>('/api/users'),
  tenants: () => get<Tenant[]>('/api/tenants'),
  products: () => get<Product[]>('/api/products'),
  orders: (limit?: number) => get<Order[]>(`/api/orders${query({ limit })}`),
  payments: () => get<Payment[]>('/api/payments'),
  customers: () => get<Customer[]>('/api/customers'),
  comments: () => get<Comment[]>('/api/comments'),
  postComment: (productId: string, content: string, safe: boolean) =>
    send<Comment>('POST', safe ? '/api/comments/safe' : '/api/comments', { productId, content }),
  notifications: () => get<Notification[]>('/api/notifications'),
  adminUsers: () => get<User[]>('/api/admin/users'),
  promoteUser: (id: string, role: Role) =>
    send<User>('POST', `/api/admin/users/${encodeURIComponent(id)}/promote`, { role }),
  deactivateUser: (id: string) => send<{ success: boolean }>('DELETE', `/api/admin/users/${encodeURIComponent(id)}`, undefined),
  vulnerableAdmin: () => get<{ users: User[]; warning?: string }>('/api/vulnerable/admin'),

  // SOC (unauthenticated)
  demoStatus: () => get<DemoStatus>('/api/security/demo-status', false),
  findings: () => get<Vulnerability[]>('/api/security/findings', false),
  finding: (id: string) => get<Vulnerability>(`/api/security/findings/${encodeURIComponent(id)}`, false),
  events: (opts: { limit?: number; eventType?: string; severity?: string } = {}) =>
    get<SecurityEvent[]>(`/api/security/events${query(opts)}`, false),
  incidents: () => get<Incident[]>('/api/security/incidents', false),
  updateIncidentStatus: (id: string, status: IncidentStatus) =>
    send<Incident>('PATCH', `/api/security/incidents/${encodeURIComponent(id)}`, { status }, false),
  auditLogs: () => get<AuditLog[]>('/api/security/audit-logs', false),
  attackGraph: () => get<AttackGraph>('/api/security/attack-graph', false),
  detectionRules: () => get<DetectionRule[]>('/api/security/detection-rules', false),
  scenarios: () => get<ScenarioInfo[]>('/api/security/scenarios', false),
  runDetection: () => send<{ success: boolean; message: string }>('POST', '/api/security/run-detection', {}, false),
  simulate: (scenarioId: string) =>
    send<SimulationResult>('POST', `/api/security/simulate/${encodeURIComponent(scenarioId)}`, {}, false),
};
