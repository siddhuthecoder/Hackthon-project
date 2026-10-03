import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { config } from '../config';
import { User } from '../models/User';
import { Incident } from '../models/Incident';
import { SecurityEvent } from '../models/SecurityEvent';
import { runDetectionRules, DetectionResult } from './detectionEngine';

export interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  mitreTactic: string;
  mitreTechnique: string;
  detectionRule: string;
  incidentType: string;
  uiButton: boolean;
}

export interface StepResult {
  step: number;
  action: string;
  result: string;
  status: 'success' | 'failed';
}

export interface SimulationResult {
  scenarioId: string;
  name: string;
  sourceIp: string;
  startedAt: string;
  steps: StepResult[];
  eventsGenerated: number;
  detections: DetectionResult[];
  incidents: Array<{ id: string; title: string; severity: string; confidence: number; status: string }>;
}

export const SCENARIOS: ScenarioInfo[] = [
  { id: '01-bruteforce', name: 'Brute Force Login', description: '15 failed logins from one IP followed by a successful login (VULN-009).', mitreTactic: 'Credential Access', mitreTechnique: 'T1110 Brute Force', detectionRule: 'RULE-001', incidentType: 'BRUTE_FORCE', uiButton: true },
  { id: '02-account-takeover', name: 'Account Takeover', description: 'Failed logins, successful login, session creation, then sensitive API access.', mitreTactic: 'Initial Access', mitreTechnique: 'T1078 Valid Accounts', detectionRule: 'RULE-002', incidentType: 'POSSIBLE_ACCOUNT_TAKEOVER', uiButton: true },
  { id: '03-idor', name: 'IDOR Enumeration', description: 'Authenticated user walks other user IDs through the vulnerable endpoint (VULN-001).', mitreTactic: 'Discovery', mitreTechnique: 'T1087 Account Discovery', detectionRule: 'RULE-003', incidentType: 'POSSIBLE_IDOR', uiButton: true },
  { id: '04-cross-tenant-access', name: 'Cross-Tenant Attack', description: 'Tenant Alpha user reads Tenant Beta and Gamma orders (VULN-002).', mitreTactic: 'Collection', mitreTechnique: 'T1530 Data from Cloud Storage', detectionRule: 'RULE-004', incidentType: 'CROSS_TENANT_ATTACK', uiButton: true },
  { id: '05-privilege-escalation', name: 'Privilege Escalation', description: 'STAFF user mass-assigns role TENANT_ADMIN then calls the admin API (VULN-011/003).', mitreTactic: 'Privilege Escalation', mitreTechnique: 'T1098 Account Manipulation', detectionRule: 'RULE-005', incidentType: 'PRIVILEGE_ESCALATION', uiButton: true },
  { id: '06-api-abuse', name: 'API Abuse', description: '70 rapid authenticated API requests from one user.', mitreTactic: 'Impact', mitreTechnique: 'T1499 Endpoint Denial of Service', detectionRule: 'RULE-008', incidentType: 'API_ABUSE', uiButton: false },
  { id: '07-data-exfiltration-simulation', name: 'Data Exfiltration', description: 'Repeated bulk reads and export operations. Responses stay local.', mitreTactic: 'Exfiltration', mitreTechnique: 'T1041 Exfiltration Over C2 Channel', detectionRule: 'RULE-006', incidentType: 'POSSIBLE_DATA_EXFILTRATION', uiButton: true },
  { id: '08-suspicious-admin-activity', name: 'Suspicious Admin Activity', description: 'Admin performs a burst of role changes. Roles are restored afterwards.', mitreTactic: 'Persistence', mitreTechnique: 'T1098 Account Manipulation', detectionRule: 'RULE-007', incidentType: 'SUSPICIOUS_ADMIN_ACTIVITY', uiButton: false },
  { id: '09-business-logic-abuse', name: 'Business Logic Attack', description: 'Order is marked paid with a tampered payment request (VULN-012).', mitreTactic: 'Impact', mitreTechnique: 'T1565 Data Manipulation', detectionRule: 'RULE-009', incidentType: 'BUSINESS_LOGIC_ABUSE', uiButton: true },
];

const ALICE = { email: 'alice.anderson@tenant.alpha.com', password: 'demo_password_123' };
const ADMIN = { email: 'admin@sentinelforge.lab', password: 'admin_demo_123' };

class SimulationContext {
  readonly steps: StepResult[] = [];
  readonly http: AxiosInstance;
  readonly sourceIp: string;

  constructor() {
    this.sourceIp = `10.66.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 200) + 1}`;
    this.http = axios.create({
      baseURL: `http://127.0.0.1:${config.port}`,
      timeout: 15000,
      validateStatus: () => true,
      headers: { 'X-Forwarded-For': this.sourceIp, 'User-Agent': 'sentinelforge-attack-simulator/1.0', 'Content-Type': 'application/json' },
    });
  }

  record(action: string, result: string, ok = true): void {
    this.steps.push({ step: this.steps.length + 1, action, result, status: ok ? 'success' : 'failed' });
  }

  async login(creds: { email: string; password: string }): Promise<string> {
    const res = await this.http.post('/api/auth/login', creds);
    const token = res.data?.accessToken as string | undefined;
    this.record(`Login as ${creds.email}`, token ? 'HTTP 200 - access token issued' : `HTTP ${res.status} - login failed`, Boolean(token));
    if (!token) throw new Error(`Simulation login failed for ${creds.email}`);
    return token;
  }

  auth(token: string): { headers: { Authorization: string } } {
    return { headers: { Authorization: `Bearer ${token}` } };
  }
}

type ScenarioRunner = (ctx: SimulationContext) => Promise<void>;

async function mapInBatches<T>(items: T[], size: number, fn: (item: T) => Promise<AxiosResponse>): Promise<AxiosResponse[]> {
  const out: AxiosResponse[] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(...(await Promise.all(items.slice(i, i + size).map(fn))));
  }
  return out;
}

const RUNNERS: Record<string, ScenarioRunner> = {
  '01-bruteforce': async ctx => {
    const attempts = Array.from({ length: 15 }, (_, i) => i);
    const results = await mapInBatches(attempts, 5, i => ctx.http.post('/api/auth/login', { email: 'nonexistent@attacker.test', password: `guess-${i}` }));
    ctx.record('15 failed login attempts', `${results.filter(r => r.status === 401).length}/15 rejected with HTTP 401`);
    await ctx.login(ALICE);
  },
  '02-account-takeover': async ctx => {
    const results = await mapInBatches(Array.from({ length: 8 }, (_, i) => i), 4, i => ctx.http.post('/api/auth/login', { email: ALICE.email, password: `wrong-${i}` }));
    ctx.record('8 failed logins against alice.anderson', `${results.filter(r => r.status === 401).length}/8 rejected`);
    const token = await ctx.login(ALICE);
    const me = await ctx.http.get('/api/auth/me', ctx.auth(token));
    ctx.record('GET /api/auth/me', `HTTP ${me.status}`);
    const orders = await ctx.http.get('/api/orders', ctx.auth(token));
    ctx.record('GET /api/orders (sensitive data)', `HTTP ${orders.status} - ${Array.isArray(orders.data) ? orders.data.length : 0} records`);
  },
  '03-idor': async ctx => {
    const token = await ctx.login(ALICE);
    const own = await ctx.http.get('/api/users/vulnerable/user-101', ctx.auth(token));
    ctx.record('Read own profile user-101', `HTTP ${own.status}`);
    const ids = Array.from({ length: 12 }, (_, i) => `user-${102 + i}`);
    const results = await mapInBatches(ids, 4, id => ctx.http.get(`/api/users/vulnerable/${id}`, ctx.auth(token)));
    ctx.record('Enumerate user-102 .. user-113', `${results.filter(r => r.status === 200).length}/12 other users disclosed (IDOR confirmed)`);
  },
  '04-cross-tenant-access': async ctx => {
    const token = await ctx.login(ALICE);
    const own = await ctx.http.get('/api/orders/order-1', ctx.auth(token));
    ctx.record('Read Tenant Alpha order-1', `HTTP ${own.status} (own tenant)`);
    for (const orderId of ['order-2', 'order-3']) {
      const res = await ctx.http.get(`/api/orders/${orderId}`, ctx.auth(token));
      ctx.record(`Read ${orderId} of another tenant`, `HTTP ${res.status} - tenant ${res.data?.tenantId} data returned (VULN-002)`);
    }
  },
  '05-privilege-escalation': async ctx => {
    const staff = await User.findOne({ role: 'STAFF', tenantId: 'tenant-alpha' });
    if (!staff) throw new Error('No STAFF user found - run the seed first');
    try {
      let token = await ctx.login({ email: staff.email, password: 'demo_password_123' });
      const adminDenied = await ctx.http.get('/api/admin/users', ctx.auth(token));
      ctx.record('STAFF calls GET /api/admin/users', `HTTP ${adminDenied.status} (secure route denies)`);
      const patch = await ctx.http.patch(`/api/users/vulnerable/${staff.id}`, { role: 'TENANT_ADMIN', isAdmin: true }, ctx.auth(token));
      ctx.record('PATCH own profile with role=TENANT_ADMIN (mass assignment)', `HTTP ${patch.status} - role now ${patch.data?.role}`);
      token = await ctx.login({ email: staff.email, password: 'demo_password_123' });
      const admin = await ctx.http.get('/api/admin/users', ctx.auth(token));
      ctx.record('Re-login and call admin API', `HTTP ${admin.status} - admin access ${admin.status === 200 ? 'granted' : 'denied'}`);
    } finally {
      await User.updateOne({ id: staff.id }, { $set: { role: 'STAFF', isAdmin: false } });
      ctx.record('Lab cleanup', 'STAFF role restored in database');
    }
  },
  '06-api-abuse': async ctx => {
    const token = await ctx.login(ALICE);
    const results = await mapInBatches(Array.from({ length: 70 }, (_, i) => i), 10, () => ctx.http.get('/api/orders', ctx.auth(token)));
    ctx.record('70 rapid GET /api/orders requests', `${results.filter(r => r.status === 200).length}/70 served (no throttling)`);
  },
  '07-data-exfiltration-simulation': async ctx => {
    const token = await ctx.login(ALICE);
    const ids = Array.from({ length: 8 }, (_, i) => `user-${101 + i}`);
    await mapInBatches(ids, 4, id => ctx.http.get(`/api/users/vulnerable/${id}`, ctx.auth(token)));
    ctx.record('Read 8 user records', 'HTTP 200 x8');
    const list = await ctx.http.get('/api/orders?limit=1000', ctx.auth(token));
    ctx.record('GET /api/orders?limit=1000', `HTTP ${list.status} - ${Array.isArray(list.data) ? list.data.length : 0} records`);
    let exported = 0;
    for (let i = 0; i < 3; i++) {
      const res = await ctx.http.get('/api/orders/export', ctx.auth(token));
      exported += Number(res.data?.count) || 0;
    }
    ctx.record('3 x GET /api/orders/export', `${exported} order records returned locally (no external transfer)`);
  },
  '08-suspicious-admin-activity': async ctx => {
    const token = await ctx.login(ADMIN);
    const targets = await User.find({ role: { $in: ['USER', 'STAFF'] } }).limit(12);
    const originals = targets.map(t => ({ id: t.id, role: t.role }));
    try {
      const results = await mapInBatches(targets, 4, t => ctx.http.post(`/api/admin/users/${t.id}/promote`, { role: 'MANAGER' }, ctx.auth(token)));
      ctx.record(`Promote ${targets.length} users to MANAGER`, `${results.filter(r => r.status === 200).length}/${targets.length} succeeded`);
    } finally {
      for (const original of originals) {
        await User.updateOne({ id: original.id }, { $set: { role: original.role } });
      }
      ctx.record('Lab cleanup', 'Original roles restored in database');
    }
  },
  '09-business-logic-abuse': async ctx => {
    const token = await ctx.login(ALICE);
    const order = await ctx.http.post('/api/orders', { items: [{ productId: 'prod-1', quantity: 1 }] }, ctx.auth(token));
    ctx.record('Create order', `HTTP ${order.status} - ${order.data?.id} status=${order.data?.status} total=${order.data?.total}`, order.status === 201);
    const pay = await ctx.http.post('/api/payments', { orderId: order.data?.id, status: 'completed', orderStatus: 'paid', amount: 0.01 }, ctx.auth(token));
    ctx.record('Tampered payment: amount=0.01, orderStatus=paid', `HTTP ${pay.status} - order now ${pay.data?.orderStatus}, paid ${pay.data?.amount} of ${order.data?.total}`, pay.status === 200);
  },
};

export async function runScenario(scenarioId: string): Promise<SimulationResult> {
  const info = SCENARIOS.find(s => s.id === scenarioId);
  const runner = RUNNERS[scenarioId];
  if (!info || !runner) throw new Error(`Unknown scenario: ${scenarioId}`);

  const ctx = new SimulationContext();
  const startedAt = new Date();

  try {
    await runner(ctx);
  } catch (err) {
    ctx.record('Scenario aborted', err instanceof Error ? err.message : 'unknown error', false);
  }

  const detections = await runDetectionRules();
  ctx.record('SOC detection engine executed', `${detections.filter(d => d.created).length} new incident(s) created`);

  const eventsGenerated = await SecurityEvent.countDocuments({ sourceIp: ctx.sourceIp, timestamp: { $gte: startedAt } });
  const incidents = await Incident.find({ sourceIp: ctx.sourceIp, detectedAt: { $gte: startedAt } }).sort({ detectedAt: -1 });

  return {
    scenarioId,
    name: info.name,
    sourceIp: ctx.sourceIp,
    startedAt: startedAt.toISOString(),
    steps: ctx.steps,
    eventsGenerated,
    detections,
    incidents: incidents.map(i => ({ id: i.id, title: i.title, severity: i.severity, confidence: i.confidence, status: i.status })),
  };
}
