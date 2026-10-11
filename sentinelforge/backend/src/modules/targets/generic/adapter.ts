import axios, { AxiosInstance } from 'axios';
import { AdapterResponse, RequestOpts, TargetAdapter } from '../../cyberlab/adapter';

export interface GenericAdapterConfig {
  openapiUrl?: string;
  authHeaderName?: string;
  authHeaderValue?: string;
}

export interface DiscoveredEndpoint {
  method: string;
  path: string;
  authRequired: boolean;
}

/**
 * A config-driven adapter for targets that don't have (and shouldn't need) a purpose-built
 * adapter class — the real-world case of onboarding a company's own API by pointing at its
 * OpenAPI/Swagger spec instead of writing new code per target. Scope is deliberately bounded:
 * it has no login flow (auth is a single static header value, not a username/password exchange)
 * and no business-logic exploit checks — see modules/targets/generic/checks.ts for exactly what
 * it CAN check generically (missing auth, security headers, verbose errors, permissive CORS).
 * App-specific checks (IDOR semantics, payment tampering, etc.) still need a real adapter like
 * CyberLabAdapter or JuiceShopAdapter, which know the target's actual business logic.
 */
export class GenericAdapter implements TargetAdapter {
  private readonly http: AxiosInstance;

  constructor(private readonly baseUrl: string, private readonly config: GenericAdapterConfig = {}) {
    this.http = axios.create({ baseURL: baseUrl, timeout: 10000, validateStatus: () => true });
  }

  async getHealth(): Promise<{ ok: boolean; detail?: string }> {
    try {
      const res = await this.http.get('/');
      return { ok: res.status < 500, detail: `HTTP ${res.status}` };
    } catch (err) {
      return { ok: false, detail: err instanceof Error ? err.message : 'unreachable' };
    }
  }

  // No login flow — a generic target's auth is whatever static header the caller configured.
  async login(): Promise<string> {
    throw new Error('GenericAdapter has no login flow; configure authHeaderName/authHeaderValue instead.');
  }

  async request(method: string, path: string, opts: RequestOpts = {}): Promise<AdapterResponse> {
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    else if (this.config.authHeaderName && this.config.authHeaderValue) headers[this.config.authHeaderName] = this.config.authHeaderValue;
    const res = await this.http.request({ method, url: path, data: opts.body, headers });
    return { status: res.status, data: res.data, headers: res.headers as Record<string, string> };
  }

  // No security-event feed for an arbitrary third-party API — only CyberLab ships one.
  async getEvents(): Promise<unknown[]> {
    return [];
  }

  async runSecurityTest(): Promise<unknown> {
    throw new Error('GenericAdapter has no attack simulator (that requires a purpose-built target like CyberLab).');
  }

  /** Fetches and parses the configured OpenAPI/Swagger JSON spec into a flat endpoint list.
   * Deliberately minimal parsing (no $ref resolution, no full JSON-Schema walk) — just enough to
   * read `paths` and each path's HTTP methods + whether a `security` requirement is attached,
   * which is all the generic hygiene checks need. */
  async discoverFromOpenApi(): Promise<DiscoveredEndpoint[]> {
    if (!this.config.openapiUrl) throw new Error('No openapiUrl configured for this application.');
    const res = await axios.get(this.config.openapiUrl, { timeout: 10000 });
    const spec = res.data as { paths?: Record<string, Record<string, { security?: unknown[] }>>; security?: unknown[] };
    const globalSecurity = Array.isArray(spec.security) && spec.security.length > 0;
    const endpoints: DiscoveredEndpoint[] = [];
    for (const [path, methods] of Object.entries(spec.paths ?? {})) {
      for (const [method, operation] of Object.entries(methods)) {
        if (!['get', 'post', 'put', 'patch', 'delete'].includes(method.toLowerCase())) continue;
        const hasOwnSecurity = Array.isArray(operation?.security);
        const authRequired = hasOwnSecurity ? operation.security!.length > 0 : globalSecurity;
        endpoints.push({ method: method.toUpperCase(), path, authRequired });
      }
    }
    return endpoints;
  }
}
