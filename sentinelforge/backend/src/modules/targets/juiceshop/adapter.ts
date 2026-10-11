import axios, { AxiosInstance } from 'axios';

/**
 * Second TargetAdapter implementation (OWASP Juice Shop), alongside CyberLabAdapter. Proves the
 * adapter pattern described in docs/ARCHITECTURE.md is real and not hardcoded to one lab — the
 * scanner, findings, and UI all work the same way against a completely different application,
 * with its own real, independently-confirmed vulnerabilities (not CyberLab's).
 */
export interface JsRequestOpts {
  token?: string;
  body?: unknown;
}

export interface JsResponse {
  status: number;
  data: unknown;
}

export class JuiceShopAdapter {
  private readonly http: AxiosInstance;

  constructor(baseUrl: string) {
    this.http = axios.create({ baseURL: baseUrl, timeout: 10000, validateStatus: () => true });
  }

  async getHealth(): Promise<{ ok: boolean; detail?: string }> {
    try {
      const res = await this.http.get('/rest/admin/application-version');
      return { ok: res.status === 200, detail: JSON.stringify(res.data) };
    } catch (err) {
      return { ok: false, detail: err instanceof Error ? err.message : 'unreachable' };
    }
  }

  async request(method: string, path: string, opts: JsRequestOpts = {}): Promise<JsResponse> {
    const headers: Record<string, string> = {};
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    const res = await this.http.request({ method, url: path, data: opts.body, headers });
    return { status: res.status, data: res.data };
  }

  /** Registers (idempotent-ish: ignores "already exists") and logs in a throwaway demo account,
   * so the scanner always has a legitimate low-privilege token to test with — the same pattern
   * CyberLabAdapter.demoLogin() uses. */
  async demoLogin(): Promise<{ token: string; email: string }> {
    const email = `sf-scanner-${Date.now()}@example.test`;
    const password = 'SfScanner#2026';
    await this.http.post('/api/Users', { email, password, passwordRepeat: password });
    const login = await this.http.post('/rest/user/login', { email, password });
    const token = (login.data as { authentication?: { token?: string } })?.authentication?.token;
    if (!token) throw new Error(`Juice Shop demo login failed for ${email}: HTTP ${login.status}`);
    return { token, email };
  }
}
