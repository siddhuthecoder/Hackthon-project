import axios, { AxiosInstance } from 'axios';
import jwt from 'jsonwebtoken';
import { config } from '../../config';

/**
 * Generic interface SentinelForge uses to talk to a target application. CyberLab is the first
 * (and for the hackathon, only) implementation. Keeping this interface separate means a future
 * target just needs its own adapter behind the same shape.
 */
export interface TargetAdapter {
  getHealth(): Promise<{ ok: boolean; detail?: string }>;
  login(email: string, password: string): Promise<string>;
  request(method: string, path: string, opts?: RequestOpts): Promise<AdapterResponse>;
  getEvents(since?: Date): Promise<unknown[]>;
  runSecurityTest(scenarioId: string): Promise<unknown>;
}

export interface RequestOpts {
  token?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

export interface AdapterResponse {
  status: number;
  data: unknown;
  headers: Record<string, string>;
}

// Credentials for the lab's own seeded demo accounts. These exist only inside the CyberLab demo
// seed data (fake tenants, fake users) and are documented in cyberlab/README + seed.ts; they are
// not a SentinelForge secret, so they are not required via env, but can be overridden.
const DEMO_ACCOUNTS = {
  alice: { email: 'alice.anderson@tenant.alpha.com', password: 'demo_password_123' },
  admin: { email: 'admin@sentinelforge.lab', password: 'admin_demo_123' },
};

// Fixed source IP for every request this adapter makes directly (scans, verification probes,
// lab-fix control calls). This is authorized AppSec testing traffic, not a simulated attack, so
// the detection engine (detection/rules.ts) explicitly excludes it — otherwise the scanner's own
// exploit checks would trip the same SOC rules a real attacker would, creating incidents before
// anyone has clicked "run attack". Real attacker traffic goes through CyberLab's own simulator
// (services/simulator.ts), which assigns its own randomized source IP per run.
export const SCANNER_SOURCE_IP = '10.50.0.1';

export class CyberLabAdapter implements TargetAdapter {
  private readonly http: AxiosInstance;

  constructor(baseUrl: string = config.cyberlab.baseUrl) {
    this.http = axios.create({
      baseURL: baseUrl,
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'X-Forwarded-For': SCANNER_SOURCE_IP },
    });
  }

  async getHealth(): Promise<{ ok: boolean; detail?: string }> {
    try {
      const res = await this.http.get('/health');
      return { ok: res.status === 200, detail: JSON.stringify(res.data) };
    } catch (err) {
      return { ok: false, detail: err instanceof Error ? err.message : 'unreachable' };
    }
  }

  async login(email: string, password: string): Promise<string> {
    const res = await this.http.post('/api/auth/login', { email, password });
    const token = (res.data as { accessToken?: string })?.accessToken;
    if (res.status !== 200 || !token) {
      throw new Error(`CyberLab login failed for ${email}: HTTP ${res.status}`);
    }
    return token;
  }

  async request(method: string, path: string, opts: RequestOpts = {}): Promise<AdapterResponse> {
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    const res = await this.http.request({ method, url: path, data: opts.body, headers });
    return { status: res.status, data: res.data, headers: res.headers as Record<string, string> };
  }

  async getEvents(since?: Date): Promise<unknown[]> {
    const params: Record<string, string> = { limit: '200' };
    const res = await this.http.get('/api/security/events', { params });
    const events = Array.isArray(res.data) ? res.data : [];
    if (!since) return events;
    return events.filter((e: { timestamp?: string }) => e.timestamp && new Date(e.timestamp) > since);
  }

  async runSecurityTest(scenarioId: string): Promise<unknown> {
    const res = await this.http.post(`/api/security/simulate/${scenarioId}`);
    if (res.status >= 400) throw new Error(`Simulation ${scenarioId} failed: HTTP ${res.status} ${JSON.stringify(res.data)}`);
    return res.data;
  }

  // --- lab-only controlled fix mechanism (not part of the generic TargetAdapter contract) ---

  async labState(): Promise<{ fixed: string[]; fixable: { vuln: string; description: string }[] }> {
    const res = await this.http.get('/api/lab/state', { headers: { 'x-lab-key': this.labKey() } });
    if (res.status !== 200) throw new Error(`Lab state unavailable: HTTP ${res.status}`);
    return res.data as { fixed: string[]; fixable: { vuln: string; description: string }[] };
  }

  async applyFix(vulnId: string): Promise<void> {
    const res = await this.http.post(`/api/lab/fix/${vulnId}`, {}, { headers: { 'x-lab-key': this.labKey() } });
    if (res.status !== 200) throw new Error(`Apply fix failed for ${vulnId}: HTTP ${res.status} ${JSON.stringify(res.data)}`);
  }

  async revertFix(vulnId: string): Promise<void> {
    const res = await this.http.post(`/api/lab/unfix/${vulnId}`, {}, { headers: { 'x-lab-key': this.labKey() } });
    if (res.status !== 200) throw new Error(`Revert fix failed for ${vulnId}: HTTP ${res.status}`);
  }

  async resetFixes(): Promise<void> {
    await this.http.post('/api/lab/reset', {}, { headers: { 'x-lab-key': this.labKey() } });
  }

  /** Fetches the real content of the lab's committed config file over HTTP — SentinelForge's
   * scanner and CyberLab's API run in separate containers with no shared filesystem, so this
   * replaces an earlier (broken) local-filesystem read. See docs/IMPLEMENTATION-STATUS.md. */
  async getConfigFile(): Promise<{ path: string; content: string }> {
    const res = await this.http.get('/api/lab/config-file', { headers: { 'x-lab-key': this.labKey() } });
    if (res.status !== 200) throw new Error(`Could not read lab config file: HTTP ${res.status} ${JSON.stringify(res.data)}`);
    return res.data as { path: string; content: string };
  }

  private labKey(): string {
    if (!config.cyberlab.labKey) throw new Error('LAB_CONTROL_KEY not set in SentinelForge backend env');
    return config.cyberlab.labKey;
  }

  async demoLogin(as: keyof typeof DEMO_ACCOUNTS = 'alice'): Promise<{ token: string; email: string }> {
    const creds = DEMO_ACCOUNTS[as];
    return { token: await this.login(creds.email, creds.password), email: creds.email };
  }

  /** Decodes (does not verify — we issued it or trust the lab's own signature) a CyberLab JWT to
   * read the caller's own identity, so checks can target "my own record" without a hardcoded id. */
  decodeToken(token: string): { userId: string; email: string; role: string; tenantId: string } {
    const payload = jwt.decode(token) as { userId?: string; email?: string; role?: string; tenantId?: string } | null;
    if (!payload?.userId) throw new Error('Could not decode CyberLab token payload');
    return { userId: payload.userId, email: payload.email ?? '', role: payload.role ?? '', tenantId: payload.tenantId ?? '' };
  }

  /** Logs in as the lab's own SUPER_ADMIN seed account purely to discover real existing
   * records (a second user, a cross-tenant order) at scan time — never to run the exploit
   * itself. This is a stable oracle that works regardless of CyberLab's current seed data or
   * any VULN fix-toggle state, so checks never need to hardcode specific seeded ids. */
  async discoveryLogin(): Promise<string> {
    const creds = DEMO_ACCOUNTS.admin;
    return this.login(creds.email, creds.password);
  }
}

export const cyberlab = new CyberLabAdapter();
