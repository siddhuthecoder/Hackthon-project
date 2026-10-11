# Security (of SentinelForge itself)

The master spec requires SentinelForge to practice what it preaches. What's actually implemented:

| Control | Where |
|---|---|
| Authentication | JWT (`@fastify/jwt`), issued on login, 12h expiry (`modules/auth/routes.ts`) |
| Authorization / RBAC | 3 roles (admin/analyst/viewer), explicit permission matrix (`plugins/auth.ts`), every route declares the permission it needs |
| Input validation | `zod` schemas on every request body that accepts user input (login, applications, findings, incidents, response actions, assistant) |
| Rate limiting | `@fastify/rate-limit`, 300 req/min global |
| Secure headers | `@fastify/helmet` |
| Safe errors | global error handler never leaks stack traces to the client; 500s return a generic message, everything else returns the actual validation/business error |
| Secret management | no credential-shaped literal ever committed — `SF_JWT_SECRET`, `SF_ADMIN_PASSWORD`, `SF_ANALYST_PASSWORD`, `LAB_CONTROL_KEY` are all required env vars with **no fallback default**; a dev-only JWT secret is randomly generated per process start only if explicitly not in production and none is set, never a fixed string |
| Audit logs | every sensitive action (login/failed login, app created/discovered/scanned, finding status change, fix applied/reverted/verified, incident status change, simulation run, response action requested/approved) written to `audit_logs` via `lib/audit.ts` |
| Tenant isolation | every query scopes by `organizationId` derived from the JWT, not from client input |
| Parameterized queries | Mongoose query builders throughout — no raw query strings built from user input anywhere in SentinelForge's own code |
| Secure defaults | CORS restricted to `SF_CORS_ORIGIN` (not `*`); `/ready` genuinely checks the DB connection rather than always returning 200 |

## Secret handling, specifically

Two real near-misses were caught and fixed during development (not left in):

1. An early draft of `config.ts` had literal fallback values like `'dev_only_sentinelforge_jwt_secret_change_me'` and demo passwords baked in as defaults. Rewritten so `SF_JWT_SECRET` must come from the environment in production, and **every demo credential (`SF_ADMIN_PASSWORD`, `SF_ANALYST_PASSWORD`) must be set by the operator** — the seed script refuses to run otherwise (`assertSeedCredentialsPresent`).
2. CyberLab's own `labFix.ts` (the one file SentinelForge added to CyberLab) originally defaulted its control key to `'demo_lab_control_key'` if the env var was unset. Changed to return `503` if `LAB_CONTROL_KEY` isn't configured at all, rather than falling back to a guessable value.

All `.env` files are gitignored (`cyberlab/.gitignore`, `sentinelforge/backend/.gitignore`, `sentinelforge/frontend/.gitignore` all confirmed to exclude them); `.env.example` files document variable **names** only, never values.

## Known gap

The one hardcoded secret that remains in the tree is `JWT_SECRET=demo_jwt_secret_not_for_production` in `cyberlab/docker-compose.yml` — this predates SentinelForge, belongs to CyberLab (the deliberately-vulnerable lab), and is itself one of the things the scanner is meant to be able to find (it's the value `CYBERLAB_JWT_SECRET` must be set to for the VULN-010 probe to work — using the lab's own known-fake secret against itself). It is not a SentinelForge secret and was not introduced by SentinelForge.
