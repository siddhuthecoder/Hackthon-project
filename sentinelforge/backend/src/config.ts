import { randomBytes } from 'node:crypto';
import dotenv from 'dotenv';

dotenv.config();

function str(name: string, fallback: string): string {
  const v = process.env[name];
  return v !== undefined && v !== '' ? v : fallback;
}

function num(name: string, fallback: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && process.env[name] ? v : fallback;
}

function required(name: string): string | undefined {
  const v = process.env[name];
  return v !== undefined && v !== '' ? v : undefined;
}

const nodeEnv = str('NODE_ENV', 'development');
const isProd = nodeEnv === 'production';

// JWT secret: must come from the environment in production. In local/dev, generate a
// random secret per process start if none is set, so nothing resembling a credential
// ever lives in source.
const jwtSecret = required('SF_JWT_SECRET') ?? (isProd ? undefined : randomBytes(32).toString('hex'));

// Demo account credentials are never defaulted in code. Set them via env (e.g. a local
// .env file, gitignored) before seeding; otherwise seeding fails loudly instead of
// creating a predictable account.
const adminPassword = required('SF_ADMIN_PASSWORD');
const analystPassword = required('SF_ANALYST_PASSWORD');

export const config = {
  nodeEnv,
  isProd,
  port: num('PORT', 4000),
  mongoUri: str('MONGODB_URI', 'mongodb://127.0.0.1:27017/sfplatform'),
  jwtSecret,
  corsOrigin: str('SF_CORS_ORIGIN', 'http://localhost:3000'),
  adminEmail: str('SF_ADMIN_EMAIL', 'admin@sentinelforge.ai'),
  adminPassword,
  analystEmail: str('SF_ANALYST_EMAIL', 'analyst@sentinelforge.ai'),
  analystPassword,
  cyberlab: {
    baseUrl: str('CYBERLAB_URL', 'http://localhost:3001'),
    // Lab control key: provided by whoever runs the lab stack, via env only.
    labKey: required('LAB_CONTROL_KEY'),
    // Optional: only needed for the VULN-010 (JWT role trust) probe, which forges a token to
    // demonstrate that CyberLab never re-checks the role against the database. This is the lab's
    // own documented demo secret (see cyberlab/docker-compose.yml JWT_SECRET), not a SentinelForge
    // credential. If unset, that one scanner check is skipped rather than failing the whole scan.
    labJwtSecret: required('CYBERLAB_JWT_SECRET'),
    configFile: str('CYBERLAB_CONFIG_FILE', '../../cyberlab/config/demo.env'),
    pollMs: num('CYBERLAB_POLL_MS', 1500),
    // Safety guard: SentinelForge only ever attacks these hosts.
    allowedHosts: str('SF_ALLOWED_TARGET_HOSTS', 'localhost,127.0.0.1,api,host.docker.internal').split(',').map(s => s.trim()),
  },
  ai: {
    // Provider is chosen by which key is present: OpenRouter first (it's the free-tier option),
    // then Anthropic, else offline mode. See modules/ai/client.ts.
    anthropicApiKey: str('ANTHROPIC_API_KEY', ''),
    anthropicModel: str('ANTHROPIC_MODEL', 'claude-sonnet-5-5'),
    openrouterApiKey: str('OPENROUTER_API_KEY', ''),
    openrouterModel: str('OPENROUTER_MODEL', 'cohere/north-mini-code:free'),
    maxToolRounds: num('SF_AI_MAX_TOOL_ROUNDS', 8),
  },
  detection: {
    intervalMs: num('SF_DETECTION_INTERVAL_MS', 2000),
  },
  notifications: {
    // Generic incoming-webhook URL (Slack, Discord, or any relay accepting {"text": "..."}).
    // Empty = disabled; see modules/notifications/webhook.ts.
    webhookUrl: str('WEBHOOK_URL', ''),
  },
  abuseipdb: {
    // Real IP-reputation lookups for incident sourceIp (modules/threatintel/abuseipdb.ts). Free
    // tier key from abuseipdb.com. Unset = that enrichment is skipped, never fabricated.
    apiKey: str('ABUSEIPDB_API_KEY', ''),
  },
  jira: {
    // Real ticketing integration for the generate_ticket response action. Any field unset = that
    // feature falls back to a simulated action (same no-op-if-unconfigured pattern as the webhook
    // notifier), never a crash. Token: id.atlassian.com/manage-profile/security/api-tokens.
    siteUrl: str('JIRA_SITE_URL', ''),
    email: str('JIRA_EMAIL', ''),
    apiToken: str('JIRA_API_TOKEN', ''),
    projectKey: str('JIRA_PROJECT_KEY', ''),
  },
  confluence: {
    // Same Atlassian site + credentials as Jira; only the target space differs.
    spaceId: str('CONFLUENCE_SPACE_ID', ''),
  },
  scheduler: {
    // How often the scheduler checks whether any application's scanIntervalMinutes has elapsed —
    // not the scan interval itself (that's per-application, set on Application.scanIntervalMinutes).
    checkIntervalMs: num('SF_SCHEDULER_CHECK_INTERVAL_MS', 60_000),
  },
} as const;

export function assertStartupSafe(): void {
  const missing: string[] = [];
  if (!config.jwtSecret) missing.push('SF_JWT_SECRET');
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

export function assertSeedCredentialsPresent(): void {
  const missing: string[] = [];
  if (!config.adminPassword) missing.push('SF_ADMIN_PASSWORD');
  if (!config.analystPassword) missing.push('SF_ANALYST_PASSWORD');
  if (missing.length > 0) {
    throw new Error(`Set these before seeding (e.g. in a local, gitignored .env): ${missing.join(', ')}`);
  }
}
