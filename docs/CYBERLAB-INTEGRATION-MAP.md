# CyberLab Integration Map

What CyberLab actually provides, and exactly how SentinelForge consumes it. Written from reading `cyberlab/server/src/**` directly — nothing here is assumed.

## What CyberLab is

A multi-tenant demo SaaS (users, tenants, orders, products, payments, files, comments) built to be deliberately vulnerable for security-lab purposes. Express + TypeScript API (`cyberlab/server`), Next.js frontend, MongoDB, Redis, nginx, a separate `internal-service` container (SSRF target). Seeded with 3 tenants, 30 users, 100 customers/products, 200 orders, and 14 named vulnerabilities (`VULN-001`..`VULN-014`).

## Component → endpoint → vulnerability → SentinelForge integration

| CyberLab component | Endpoint(s) | Vulnerability | SentinelForge integration |
|---|---|---|---|
| Users | `GET /api/users/:userId`, `GET /api/users/vulnerable/:userId` vs `GET /api/users/secure/:userId` | VULN-001 BOLA/IDOR (CWE-639) | `scanner/checks.ts: checkIdor` reads own + another user's profile with one token |
| Users | `PATCH /api/users/:id` vs `PATCH /api/users/secure/:id` | VULN-011 Mass Assignment (CWE-915) | `checkMassAssignment` — PATCHes own role, confirms, self-heals (reverts) |
| Orders | `GET /api/orders/:orderId` vs `GET /api/orders/secure/:orderId` | VULN-002 Cross-Tenant Access (CWE-639) | `checkCrossTenant` |
| Admin | `GET /api/admin/users/vulnerable` vs `GET /api/admin/users` | VULN-003 Broken RBAC (CWE-285) | `checkBrokenRbac` |
| Auth | `POST /api/auth/vulnerable-login` vs `POST /api/auth/secure-login` | VULN-004 NoSQL Injection (CWE-943) | `checkNoSqlInjection` |
| Comments | `POST /api/comments` (safe flag) | VULN-005 Stored XSS (CWE-79) | `checkStoredXss` |
| Fetch URL | `POST /api/fetch-url` vs `/secure` | VULN-006 SSRF (CWE-918), targets `internal-service` container | `checkSsrf` |
| Files | `GET /api/files/download` vs `/secure` | VULN-007 Path Traversal (CWE-22) | `checkPathTraversal` |
| Tools | `POST /api/tools/ping` vs `/secure` | VULN-008 Command Injection demo, sandboxed (CWE-78) | `checkCommandInjection` |
| Auth | `POST /api/auth/login` (weak limiter) | VULN-009 Weak Rate Limiting (CWE-307) | `checkWeakRateLimit` |
| Vulnerable admin | `GET /api/vulnerable/admin` vs `/secure` | VULN-010 JWT role-trust (CWE-285) | `checkJwtRoleTrust` (forges a token with the lab's own JWT secret) |
| Payments | `POST /api/payments` vs `/secure` | VULN-012 Business Logic (CWE-840) | `checkBusinessLogic` |
| Files | `POST /api/files/upload` vs `/secure` | VULN-013 Insecure Upload (CWE-434) | `checkInsecureUpload` |
| Config | `cyberlab/config/demo.env` | VULN-014 Secret Exposure (CWE-540) | `checkSecretExposure` (reads the file directly, pattern-matches credential-shaped lines) |
| Security events | `GET /api/security/events` | n/a | `modules/events/ingest.ts` polls this, normalizes, stores into `security_events` |
| Attack scenarios | `POST /api/security/simulate/:scenarioId` (9 scenarios, see `services/simulator.ts`) | n/a | `modules/lab/routes.ts` triggers these from Security Lab UI, then immediately ingests + runs detection |
| — (added by SentinelForge) | `GET/POST /api/lab/state|fix/:id|unfix/:id|reset|config-file` | n/a | `cyberlab/server/src/services/labFix.ts` — the only CyberLab code SentinelForge added. For VULN-001..013, rewrites a vulnerable route to its already-existing secure counterpart at runtime. For VULN-014 (no route to rewrite — it's a committed config file), `fix`/`unfix` redact/restore the file's credential values instead, and `GET /config-file` serves the file's live content over HTTP so SentinelForge's scanner (running in a separate container) can read it without a shared filesystem. All guarded by `LAB_CONTROL_KEY` header (env-only, no default). `config/` is bind-mounted into the `api` container (`cyberlab/docker-compose.yml`) specifically so this works. Used by `modules/verification/service.ts` and `modules/scanner/checks.ts`. |

## What SentinelForge deliberately does NOT touch

CyberLab's own internal detection engine (`services/detectionEngine.ts`), its own seed data generation, its frontend, and its database — SentinelForge never writes to CyberLab's MongoDB directly, only talks over HTTP via `modules/cyberlab/adapter.ts`.

## One addition to CyberLab

`cyberlab/server/src/services/labFix.ts` + 3 lines in `index.ts` wiring it in. This is the only CyberLab file SentinelForge created/modified; everything else in `cyberlab/` is untouched. See `docs/IMPLEMENTATION-STATUS.md` Phase 0 for how this was verified (200→403→200 toggle test).

## Known CyberLab behavior SentinelForge depends on (so a CyberLab change could break SentinelForge)

- Fixed demo accounts: `alice.anderson@tenant.alpha.com` / `demo_password_123` (tenant-alpha, role USER, id `user-101`), `admin@sentinelforge.lab` / `admin_demo_123` (SUPER_ADMIN).
- `user-102` existing as a second tenant-alpha user (used by the VULN-010 forged-token probe).
- `order-2` belonging to a different tenant than `order-1` (used by VULN-002 checks).
- The `/vulnerable/` route prefixes existing alongside the un-prefixed vulnerable routes (both are wired to the same handler in CyberLab).
