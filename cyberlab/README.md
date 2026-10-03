# SentinelForge Lab — Security Demo Environment

A local, self-contained cybersecurity demonstration environment: a multi-tenant SaaS
API with **intentionally vulnerable endpoints**, full security telemetry, nine SOC
detection rules, an attack-graph model, and nine reproducible attack simulations.

It exists to be scanned. SentinelForge (or any SAST/SCA tool) can ingest the
machine-readable finding catalog, the SOC rule set, the raw event stream and the
scenario definitions, then correlate a live attack against the known findings —
see [`docs/HACKATHON-DEMO.md`](docs/HACKATHON-DEMO.md) for the full 18-step story.

---

## ⚠️ Safety Notice

**Read this before running anything.**

- This is an **authorized, isolated security laboratory**. Every vulnerable
  endpoint, script and test targets only `localhost` Docker services. Nothing
  here may be pointed at any system you do not own.
- **Every credential in this repository is fake.** `admin_demo_123`,
  `demo_password_123`, `DEMO_API_KEY`, `demo_internal_secret_123` and everything
  in `config/demo.env` exist only so scanners and demos have something concrete
  to find.
- **Hard safety guards are compiled into the vulnerable routes.** They are not
  optional and they are not part of any vulnerability:

  | Guard | Where | Behaviour |
  |---|---|---|
  | `LAB_SAFETY_GUARD` SSRF host allowlist | `server/src/routes/files.ts` | `POST /api/fetch-url` refuses anything outside `internal-service`, `localhost`, `127.0.0.1`, `api`, `frontend`, `nginx`. Link-local and cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`) are **never** contacted — they return `403` and log the attempt. |
  | `LAB_SAFETY_GUARD` path sandbox | `server/src/routes/files.ts` | `GET /api/files/download` refuses any resolved path outside `demo-files/`. `/etc/passwd` is never served. |
  | Upload host-executable blocklist | `server/src/routes/files.ts` | Both upload handlers reject `.exe/.dll/.bat/.sh/.ps1/.jar/.elf/…` even on the vulnerable path. |
  | Command injection simulator | `server/src/routes/files.ts` | `POST /api/tools/ping` **never executes a shell**. Shell metacharacters are parsed and answered from a lookup table of canned strings. |

  These guards mean the lab demonstrates the *class* of vulnerability (an
  attacker-supplied URL is fetched server-side; a traversal string is joined onto
  a path) without ever reaching a real internal target or a real host file.
- **Never reuse this code, its secrets or its configuration in production.** The
  vulnerable paths are the entire point of the repository.

---

## Architecture

```
                                  host
                                    │
                        ┌───────────┴───────────┐
                        │   nginx   :80         │   reverse proxy / single origin for the UI
                        └─────┬───────────┬─────┘
                              │           │
                  /  ─────────┘           └─────────  /api
                              │                          │
              ┌───────────────▼──────────┐    ┌──────────▼──────────┐
              │  frontend   (Next.js 3000)│    │  api  (Express 3001) │
              │  dashboard · users ·      │    │  13 vulnerable +    │
              │  orders · SOC console     │    │  13 secure routes    │
              └────────────────────────────┘    └───┬───────┬──────┬───┘
                                                    │       │      │
        ┌───────────────────────────────────────────┘       │      └──────────────┐
        │                          │                        │                     │
┌───────▼────────┐        ┌────────▼────────┐     ┌────────▼───────┐   ┌─────────▼────────┐
│  mongodb :27017│        │  redis  :6379   │     │ internal-svc   │   │  demo-files      │
│  app data +    │        │  security-event │     │  :8080         │   │  public/ uploads/│
│  security_     │        │  pub/sub + SOC  │     │  SSRF target   │   │  internal-demo   │
│  events        │        │  stream         │     │  (dummy data)  │   │  .txt            │
└────────────────┘        └─────────────────┘     └────────────────┘   └──────────────────┘
                                ▲
                                │  detection rules every 30s
                      ┌─────────┴──────────┐
                      │  worker (node)     │  SOC rules engine · notifications · session cleanup
                      └────────────────────┘

                      scripts/  ──▶  docker compose exec api node dist/scripts/{seed,reset}.js
                      scripts/simulate/*.sh  ──▶  curl against http://localhost:3001
                      tests/e2e/*.test.mjs  ──▶  node:test + fetch, zero dependencies
```

### Services

| Service | Port (host) | Description |
|---|---|---|
| `nginx` | 80 | Reverse proxy; serves the UI and `/api` from one origin |
| `frontend` | internal 3000 | Next.js dashboard and SOC console |
| `api` | 3001 | Express REST API — the vulnerable target |
| `worker` | – | Background detection engine, incident notifications, session cleanup |
| `mongodb` | internal 27017 | Application data + `security_events` + `incidents` |
| `redis` | internal 6379 | `security-events` pub/sub stream consumed by the worker |
| `internal-service` | internal 8080 | Deliberately reachable internal API — the SSRF demo target |

### Repository layout

| Path | Contents |
|---|---|
| `server/src/routes/` | the vulnerable and secure API surface |
| `server/src/services/detectionEngine.ts` | the nine SOC detection rules |
| `server/src/services/simulator.ts` | the nine in-process attack scenarios |
| `server/src/scripts/seed.ts`, `reset.ts` | dataset seeding and teardown |
| `scripts/` | `seed.sh`, `reset.sh`, `lib.sh`, `simulate/01..09*.sh` |
| `tests/e2e/` | zero-dependency `node:test` suite |
| `docs/` | demo script and dependency findings |
| `config/demo.env` | fake secrets — VULN-014, deliberately scannable |
| `demo-files/` | the path-traversal sandbox |
| `internal-service/` | the SSRF target service |

---

## Quick Start

```bash
docker compose up -d          # start the stack
./scripts/seed.sh             # wait for /health, then seed inside the api container
curl -s http://localhost:3001/api/security/demo-status
```

```json
{"vulnerabilityCount":14,"tenantCount":3,"userCount":30,"securityEventCount":150,
 "attackScenarioCount":9,"incidentCount":3,"status":"operational"}
```

Then open <http://localhost>.

### Docker commands

```bash
docker compose up -d                  # start everything
docker compose up -d --build api      # rebuild and restart just the API
docker compose up -d --build          # rebuild everything after a server/ change
docker compose ps                     # container state and published ports
docker compose logs -f api            # follow API logs (security events stream to stdout)
docker compose logs -f worker         # follow the SOC detection engine
docker compose restart api            # restart without rebuilding
docker compose stop                   # stop, keep the MongoDB volume
docker compose down                   # stop and remove containers
docker compose down -v                # stop and DELETE the mongodb_data volume (full wipe)
docker compose exec -T api node dist/scripts/seed.js    # seed without the wrapper script
docker compose exec -T api node dist/scripts/reset.js   # wipe without the wrapper script
docker compose exec mongodb mongosh sentinelforge --quiet --eval 'db.incidents.countDocuments()'
```

> There is no `restart:` policy, so a crashed container stays down. If a command
> in this repo ever takes the API down, `docker compose logs api` shows why and
> `docker compose up -d api` brings it back.

---

## Environment Variables

Set on the `api` and `worker` services in `docker-compose.yml`:

| Variable | Default | Used by | Description |
|---|---|---|---|
| `MONGODB_URI` | `mongodb://mongodb:27017/sentinelforge` | `server/src/config` | MongoDB connection string |
| `REDIS_URL` | `redis://redis:6379` | `server/src/config` | Redis connection string for the security-event stream |
| `JWT_SECRET` | `demo_jwt_secret_not_for_production` | `services/auth.ts` | Signs access tokens (15 min) |
| `JWT_REFRESH_SECRET` | `demo_refresh_secret_not_for_production` | `services/auth.ts` | Signs refresh tokens (7 days) |
| `INTERNAL_SERVICE_URL` | `http://internal-service:8080` | `routes/files.ts` | SSRF demo target |
| `DEMO_FILES_DIR` | `/app/demo-files` | `routes/files.ts` | Root of the path-traversal sandbox |
| `API_PORT` | `3001` | `server/src/config` | API listen port |
| `NODE_ENV` | `development` | `server/src/config` | Runtime mode |

Client-side variables:

| Variable | Default | Description |
|---|---|---|
| `SENTINELFORGE_API_URL` | `http://localhost:3001` | Base URL used by `tests/e2e/*` and `tests/run.sh`. Set to `http://localhost/api` to test through nginx. |
| `API` | `http://localhost:3001` | Base URL used by `scripts/*.sh` and `scripts/simulate/*.sh`. |
| `COMPOSE` | `docker compose` | Compose command used by the scripts. |

`config/demo.env` is **not** loaded by the application. It exists purely as a
discoverable secret file for scanners (VULN-014 / `DEPENDENCY-DEMO-001` sibling —
see [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md)).

---

## Demo Credentials

All passwords are fake and identical per role group.

| Role | Email | Password | Notes |
|---|---|---|---|
| `SUPER_ADMIN` | `admin@sentinelforge.lab` | `admin_demo_123` | `user-001`, tenant-alpha, sees every tenant |
| `TENANT_ADMIN` | 4 seeded users | `demo_password_123` | tenant-scoped admin |
| `MANAGER` | 10 seeded users | `demo_password_123` | limited management |
| `STAFF` | 10 seeded users | `demo_password_123` | operational access |
| `USER` | `alice.anderson@tenant.alpha.com` + 4 more | `demo_password_123` | `alice` is `user-101` |

Every other seeded user follows `first.last@tenant.<alpha|beta|gamma>.com`.
Find one by role:

```bash
TOKEN=$(curl -s -X POST http://localhost:3001/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinelforge.lab","password":"admin_demo_123"}' \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(d).accessToken))")

curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/admin/users \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const u=JSON.parse(d).find(x=>x.role==='STAFF'&&x.tenantId==='tenant-alpha');console.log(u.id,u.email)})"
```

### Roles

```
SUPER_ADMIN   → every tenant, all admin APIs
TENANT_ADMIN  → tenant-scoped admin APIs
MANAGER       → read/manage within the tenant
STAFF         → operational access
USER          → own data only
```

### Seeded dataset

| Entity | Count | Id scheme / notes |
|---|---|---|
| Tenants | 3 | `tenant-alpha`, `tenant-beta`, `tenant-gamma` |
| Users | 30 | `user-001` (SUPER_ADMIN) + `user-101`…`user-130` |
| Customers | 100 | `cust-1`…`cust-100`, tenant `(N-1)%3` |
| Products | 100 | `prod-1`…`prod-100`, tenant `(N-1)%3` |
| Orders | 200 | `order-1`…`order-200`, tenant `(N-1)%3` = alpha/beta/gamma |
| Payments | 50 | `pay-1`…`pay-50` |
| Vulnerabilities | 14 | `VULN-001`…`VULN-014` |
| Security events | 150 | historical baseline telemetry |
| Audit logs | 100 | historical audit trail |
| Incidents | 3 | `INC-seed0001`…`INC-seed0003` (RESOLVED / INVESTIGATING / FALSE_POSITIVE) |
| Attack graph | 1 doc, 10 nodes / 10 edges | seeded attack chain |

Role distribution across the 30 users: 1 `SUPER_ADMIN`, 4 `TENANT_ADMIN`,
10 `MANAGER`, 10 `STAFF`, 5 `USER`.

---

## API Reference

All routes are mounted under `/api` and require `Authorization: Bearer <token>`
unless marked *public*. The API is also reachable through nginx at
`http://localhost/api`.

### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health`, `/api/health` | public | Liveness probe used by `scripts/lib.sh` |

### Authentication — `server/src/routes/auth.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | public | Create a `USER` |
| `POST` | `/api/auth/login` | public | **Secure** login; weakly rate limited (VULN-009) |
| `POST` | `/api/auth/vulnerable-login` | public | **VULN-004** NoSQL injection — accepts `{"password":{"$ne":null}}` |
| `POST` | `/api/auth/secure-login` | public | **Secure** — rejects non-string credentials |
| `POST` | `/api/auth/logout` | public | Revoke a refresh token |
| `POST` | `/api/auth/refresh` | public | Exchange a refresh token for a new access token |
| `POST` | `/api/auth/forgot-password` | public | Always `200` (no user enumeration) |
| `POST` | `/api/auth/reset-password` | public | Set a new password |
| `GET` | `/api/auth/me` | bearer | Current user |

### Users & comments — `routes/users.ts`, `routes/comments.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/users/secure/:userId` | bearer | **Secure** — ownership or admin check, else `403` |
| `GET` | `/api/users/vulnerable/:userId` | bearer | **VULN-001** IDOR |
| `GET` | `/api/users/:userId` | bearer | **VULN-001** IDOR (the spec path) |
| `GET` | `/api/users` | bearer | List users — `SUPER_ADMIN`/`TENANT_ADMIN`/`MANAGER` |
| `PATCH` | `/api/users/secure/:id` | bearer | **Secure** — allowlist `name`, `email`, `phone` |
| `PATCH` | `/api/users/vulnerable/:id` | bearer | **VULN-011** mass assignment |
| `PATCH` | `/api/users/:id` | bearer | **VULN-011** mass assignment (the spec path) |
| `POST` | `/api/comments` | bearer | **VULN-005** stored XSS — raw HTML persisted |
| `POST` | `/api/comments/safe` | bearer | **Secure** — HTML escaped |
| `GET` | `/api/comments` | bearer | List comments (tenant scoped) |

### Orders & payments — `routes/orders.ts`, `routes/payments.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/orders/secure/:orderId` | bearer | **Secure** — tenant ownership enforced |
| `GET` | `/api/orders/vulnerable/:orderId` | bearer | **VULN-002** cross-tenant read |
| `GET` | `/api/orders/:orderId` | bearer | **VULN-002** cross-tenant read (the spec path) |
| `GET` | `/api/orders` | bearer | List orders, tenant scoped, `?limit` up to 1000 |
| `GET` | `/api/orders/export` | bearer | Bulk export — logs `BULK_DATA_ACCESS` + `DATA_EXPORT` |
| `POST` | `/api/orders` | bearer | Create an order (server computes the total) |
| `POST` | `/api/payments/secure` | bearer | **Secure** — server-side state machine, server-side amount |
| `POST` | `/api/payments/vulnerable` | bearer | **VULN-012** client-controlled amount/status |
| `POST` | `/api/payments` | bearer | **VULN-012** (the spec path) |
| `GET` | `/api/payments` | bearer | List payments for the caller's tenant |
| `POST` | `/api/refunds` | bearer | Refund a paid order |

### Admin & JWT — `routes/admin.ts`, `routes/vulnerable.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/admin/users` | bearer | **Secure** — `SUPER_ADMIN`/`TENANT_ADMIN`, else `403` |
| `GET` | `/api/admin/users/vulnerable` | bearer | **VULN-003** broken RBAC — any authenticated user |
| `POST` | `/api/admin/users/:id/promote` | bearer | **Secure** role change |
| `POST` | `/api/admin/users/:id/promote/vulnerable` | bearer | **VULN-003** promote with no role check |
| `DELETE` | `/api/admin/users/:id` | bearer | **Secure** deactivate |
| `DELETE` | `/api/admin/users/:id/vulnerable` | bearer | **VULN-003** deactivate with no role check |
| `GET` | `/api/vulnerable/admin` | bearer | **VULN-010** trusts the JWT `role` claim, no DB re-check |
| `GET` | `/api/vulnerable/admin/secure` | bearer | **Secure** — re-verifies the role against the database |

### Files, SSRF, tools — `routes/files.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/fetch-url/secure` | bearer | **Secure** — strict URL allowlist |
| `POST` | `/api/fetch-url/vulnerable` | bearer | **VULN-006** SSRF (lab hosts only) |
| `POST` | `/api/fetch-url` | bearer | **VULN-006** (the spec path) |
| `GET` | `/api/files/download/secure?file=` | bearer | **Secure** — allowlisted `public.txt` only |
| `GET` | `/api/files/download/vulnerable?file=` | bearer | **VULN-007** path traversal inside the sandbox |
| `GET` | `/api/files/download?file=` | bearer | **VULN-007** (the spec path) |
| `POST` | `/api/files/upload` | bearer | **VULN-013** — no extension/MIME validation |
| `POST` | `/api/files/upload/secure` | bearer | **Secure** — extension + MIME allowlist |
| `GET` | `/api/files` | bearer | List uploaded file metadata |
| `POST` | `/api/tools/ping` | bearer | **VULN-008** sandboxed command-injection simulator |
| `POST` | `/api/tools/ping/secure` | bearer | **Secure** — host format allowlist |

### Tenants, catalogue, notifications

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/tenants` | bearer | Tenants visible to the caller, with row counts |
| `GET` | `/api/products` | bearer | Product catalogue, tenant scoped |
| `GET` | `/api/products/:id` | bearer | Single product, tenant checked |
| `GET` | `/api/customers` | bearer | Customers, tenant scoped |
| `GET` | `/api/notifications` | bearer | Incident notifications raised by the worker |

### SOC / security console — `routes/security.ts`

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/security/demo-status` | public | Lab inventory: findings, tenants, users, events, incidents, scenarios |
| `GET` | `/api/security/findings` | public | All 14 vulnerability findings |
| `GET` | `/api/security/findings/:id` | public | One finding (`VULN-001`…`VULN-014`) |
| `GET` | `/api/security/events` | public | Security telemetry. Filters: `limit`, `eventType`, `severity`, `userId`, `tenantId`, `sourceIp` |
| `GET` | `/api/security/incidents` | public | Incidents, newest first |
| `PATCH` | `/api/security/incidents/:id` | public | Triage status: `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE` |
| `GET` | `/api/security/audit-logs` | public | Audit trail |
| `GET` | `/api/security/attack-graph` | public | Nodes and edges of the attack graph |
| `GET` | `/api/security/detection-rules` | public | The nine SOC rules |
| `GET` | `/api/security/scenarios` | public | The nine attack scenarios |
| `POST` | `/api/security/run-detection` | public | Evaluate every rule over the last 5 minutes of events |
| `POST` | `/api/security/simulate/:scenarioId` | public | Run one attack scenario in-process |

> The `/api/security/*` surface is intentionally unauthenticated: a scanner has to
> be able to read the catalog before it has credentials. Do not copy this pattern.

---

## Vulnerability Catalog

13 code-level vulnerabilities each have a hardened counterpart, plus one
configuration finding.

| ID | Title | Sev | Vulnerable endpoint | Secure endpoint | CWE | OWASP | MITRE ATT&CK |
|---|---|---|---|---|---|---|---|
| **VULN-001** | Broken Object Level Authorization (IDOR/BOLA) | high | `GET /api/users/:userId` | `GET /api/users/secure/:userId` | CWE-639 | API1:2023 | T1078 Valid Accounts (Initial Access) |
| **VULN-002** | Cross-Tenant Data Access | critical | `GET /api/orders/:orderId` | `GET /api/orders/secure/:orderId` | CWE-639 | API1:2023 | T1530 Data from Cloud Storage (Collection) |
| **VULN-003** | Broken Function Level Authorization | high | `GET/POST/DELETE /api/admin/users/*/vulnerable` | same paths without `/vulnerable` | CWE-285 | API5:2023 | T1078.004 Cloud Accounts (Privilege Escalation) |
| **VULN-004** | NoSQL Injection in Login | critical | `POST /api/auth/vulnerable-login` | `POST /api/auth/secure-login` | CWE-943 | API3:2023 | T1110 Brute Force (Credential Access) |
| **VULN-005** | Stored Cross-Site Scripting | high | `POST /api/comments` | `POST /api/comments/safe` | CWE-79 | A03:2021 | T1059.007 JavaScript (Execution) |
| **VULN-006** | Server-Side Request Forgery | high | `POST /api/fetch-url` | `POST /api/fetch-url/secure` | CWE-918 | API10:2023 | T1046 Network Service Discovery (Discovery) |
| **VULN-007** | Path Traversal in File Download | high | `GET /api/files/download` | `GET /api/files/download/secure` | CWE-22 | A01:2021 | T1005 Data from Local System (Collection) |
| **VULN-008** | Command Injection (sandboxed simulator) | medium | `POST /api/tools/ping` | `POST /api/tools/ping/secure` | CWE-78 | A03:2021 | T1059 Command and Scripting Interpreter (Execution) |
| **VULN-009** | Weak Rate Limiting on Login | medium | `POST /api/auth/login` | rate-limited variant | CWE-307 | API4:2023 | T1110 Brute Force (Credential Access) |
| **VULN-010** | JWT Authorization Weakness | high | `GET /api/vulnerable/admin` | `GET /api/vulnerable/admin/secure` | CWE-285 | API5:2023 | T1134 Access Token Manipulation (Privilege Escalation) |
| **VULN-011** | Mass Assignment Privilege Escalation | high | `PATCH /api/users/:id` | `PATCH /api/users/secure/:id` | CWE-915 | API8:2023 | T1078.004 Cloud Accounts (Privilege Escalation) |
| **VULN-012** | Payment Business Logic Abuse | high | `POST /api/payments` | `POST /api/payments/secure` | CWE-840 | API8:2023 | T1565 Data Manipulation (Impact) |
| **VULN-013** | Insecure File Upload | medium | `POST /api/files/upload` | `POST /api/files/upload/secure` | CWE-434 | A04:2021 | T1505.003 Web Shell (Persistence) |
| **VULN-014** | Secret Exposure in Configuration | medium | `config/demo.env` | `config/secure.env` (env vars) | CWE-540 | A05:2021 | T1552.001 Credentials in Files (Credential Access) |

Plus one supply-chain finding: **`DEPENDENCY-DEMO-001`** — `multer@^1.4.5-lts.1` in
`server/package.json` is an end-of-life dependency (CWE-1104). See
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).

Reproduce any of them:

```bash
curl -s http://localhost:3001/api/security/findings/VULN-001
curl -s http://localhost:3001/api/security/findings | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{for(const v of JSON.parse(d))console.log(v.id,v.severity,v.type,v.cwe,v.owasp)})"
```

---

## Attack Simulation Catalog

Nine scripts, each of which uses a **unique `X-Forwarded-For` in `10.77.0.0/16`**
so runs never contaminate each other, uses only `curl` plus `node` for JSON
parsing (no `jq`), and ends by calling `POST /api/security/run-detection` and
printing the incidents it produced. Every script restores any role it changes.

```bash
./scripts/simulate/01-bruteforce.sh
./scripts/simulate/02-account-takeover.sh
./scripts/simulate/03-idor.sh
./scripts/simulate/04-cross-tenant-access.sh
./scripts/simulate/05-privilege-escalation.sh
./scripts/simulate/06-api-abuse.sh
./scripts/simulate/07-data-exfiltration-simulation.sh
./scripts/simulate/08-suspicious-admin-activity.sh
./scripts/simulate/09-business-logic-abuse.sh
```

All nine at once:

```bash
for script in scripts/simulate/*.sh; do echo "### $script"; bash "$script"; done
```

| # | Scenario id | What it does | Vulnerabilities | Rule | Incident raised |
|---|---|---|---|---|---|
| 01 | `01-bruteforce` | 20 failed logins from one IP, then a successful login | VULN-009 | **RULE-001** (+RULE-002) | `Brute Force Attack Detected` |
| 02 | `02-account-takeover` | 8 failures against one account, then a success and sensitive reads | VULN-009 | **RULE-002** | `Possible Account Takeover` |
| 03 | `03-idor` | own record, then `user-102`…`user-113` | VULN-001 | **RULE-003** | `Possible IDOR Attack` |
| 04 | `04-cross-tenant-access` | Tenant Alpha reads Tenant Beta + Gamma orders | VULN-002 | **RULE-004** | `Cross-Tenant Data Access Attempt` |
| 05 | `05-privilege-escalation` | Tenant Alpha `STAFF` mass-assigns `role: TENANT_ADMIN`, then calls the admin API | VULN-011, VULN-003 | **RULE-005** | `Privilege Escalation via Mass Assignment` |
| 06 | `06-api-abuse` | 70 rapid authenticated `GET /api/orders` | VULN-009 | **RULE-008** | `API Abuse - Excessive Request Rate` |
| 07 | `07-data-exfiltration-simulation` | 30 user reads, a `?limit=1000` list, 3 exports (all local) | VULN-001, VULN-002 | **RULE-006** (+RULE-003) | `Possible Data Exfiltration` |
| 08 | `08-suspicious-admin-activity` | `SUPER_ADMIN` promotes 12 users, then reverts them | VULN-003 | **RULE-007** | `Suspicious Admin Activity` |
| 09 | `09-business-logic-abuse` | create an order, pay `0.01` with a client-forced `orderStatus: paid` | VULN-012 | **RULE-009** | `Payment Business Logic Abuse` |

The same nine scenarios are also available in-process (loopback only) at
`POST /api/security/simulate/:scenarioId`, and in the UI at
<http://localhost/security-lab/attacks>.

```bash
curl -s -X POST http://localhost:3001/api/security/simulate/03-idor \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const r=JSON.parse(d);console.log(r.scenarioId,r.sourceIp,r.eventsGenerated+' events');for(const i of r.incidents)console.log(i.id,i.title,i.severity)})"
```

---

## SOC Detection Rules

`server/src/services/detectionEngine.ts` evaluates every rule over the **last 5
minutes** of `security_events`. The worker runs it every 30 seconds; you can
force it with `POST /api/security/run-detection`. Incidents are deduplicated per
`(title, sourceIp)` for 10 minutes, so re-running a scenario never floods the
console.

| Rule | Name | Condition | Incident type | Sev | Findings | MITRE |
|---|---|---|---|---|---|---|
| **RULE-001** | Brute Force Detection | `> 10` `AUTH_FAILURE` from one source IP in 5 min | `BRUTE_FORCE` | high | VULN-009 | T1110 Brute Force |
| **RULE-002** | Account Takeover Detection | `AUTH_SUCCESS` after `> 5` failures from the same IP | `POSSIBLE_ACCOUNT_TAKEOVER` | critical | VULN-009 | T1078 Valid Accounts |
| **RULE-003** | IDOR Detection | `> 10` distinct `user` resource IDs read by one user in 5 min | `POSSIBLE_IDOR` | high | VULN-001 | T1083 File and Directory Discovery |
| **RULE-004** | Cross-Tenant Access Detection | any `CROSS_TENANT_ACCESS_ATTEMPT` | `CROSS_TENANT_ATTACK` | critical | VULN-002 | T1530 Data from Cloud Storage |
| **RULE-005** | Privilege Escalation Detection | `PRIVILEGE_CHANGE` where actor role ∈ {STAFF, USER} and new role is an admin role | `PRIVILEGE_ESCALATION` | critical | VULN-011 | T1078.004 Cloud Accounts |
| **RULE-006** | Data Exfiltration Detection | `BULK_DATA_ACCESS` summing `>= 100` records, or `>= 3` bulk events per user in 5 min | `POSSIBLE_DATA_EXFILTRATION` | critical | VULN-001, VULN-002 | T1041 Exfiltration Over C2 Channel |
| **RULE-007** | Suspicious Admin Activity | `> 10` `PRIVILEGE_CHANGE`/`ADMIN_ACTION` by one admin in 5 min | `SUSPICIOUS_ADMIN_ACTIVITY` | high | VULN-003 | T1098 Account Manipulation |
| **RULE-008** | API Abuse Detection | `> 60` `API_REQUEST` for one user in 1 min | `API_ABUSE` | medium | VULN-009 | T1499 Endpoint Denial of Service |
| **RULE-009** | Payment Business Logic Abuse | `PAYMENT_UPDATED` with `metadata.note = business_logic_abuse` | `BUSINESS_LOGIC_ABUSE` | high | VULN-012 | T1565 Data Manipulation |

Each incident records severity, status, source IP, affected users and assets, the
triggering event ids, the linked findings, an ordered `attackPath`, a confidence
score, `recommendedActions`, and the MITRE tactic/technique.

```bash
curl -s http://localhost:3001/api/security/detection-rules \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{for(const r of JSON.parse(d))console.log(r.id,r.name,'|',r.condition)})"

curl -s -X POST http://localhost:3001/api/security/run-detection

curl -s -X PATCH http://localhost:3001/api/security/incidents/INC-xxxx \
  -H 'Content-Type: application/json' -d '{"status":"INVESTIGATING"}'
```

### Security event types

```
AUTH_SUCCESS, AUTH_FAILURE, PASSWORD_RESET, SESSION_CREATED, SESSION_REVOKED
API_REQUEST, API_ERROR, AUTHORIZATION_FAILURE, PRIVILEGE_CHANGE, ADMIN_ACTION
DATA_ACCESS, BULK_DATA_ACCESS, DATA_EXPORT, CROSS_TENANT_ACCESS_ATTEMPT
FILE_UPLOAD, FILE_DOWNLOAD, SUSPICIOUS_REQUEST, SUSPICIOUS_ACTIVITY
RATE_LIMIT_TRIGGERED, CROSS_RESOURCE_ACCESS
PAYMENT_CREATED, PAYMENT_UPDATED, REFUND_CREATED, SECURITY_FINDING_TRIGGERED
```

Every event carries `timestamp`, `eventType`, `severity`, `userId`, `tenantId`,
`sourceIp`, `endpoint`, `method`, `userAgent`, `requestId`, `mitreTechnique` and
a free-form `metadata` object (which is where the `vulnerability: VULN-00x` tags
live).

---

## Database

MongoDB, database `sentinelforge`.

| Collection | Purpose | Seeded | Notable indexes |
|---|---|---|---|
| `tenants` | Multi-tenant registry | 3 | `id` (unique) |
| `users` | Accounts, roles, tenant membership | 30 | `id` (unique), `email` (unique), `tenantId` |
| `customers` | Customer records | 100 | `id` (unique), `tenantId` |
| `products` | Product catalogue | 100 | `id` (unique), `tenantId` |
| `orders` | Customer orders | 200 | `id` (unique), `customerId`, `tenantId` |
| `payments` | Payments and refunds | 50 | `id` (unique), `orderId` |
| `comments` | Product comments (XSS demo) | – | `id` (unique), `productId` |
| `files` | Upload metadata | – | `id` (unique) |
| `sessions` | Refresh-token sessions | – | `id` (unique), `userId` |
| `security_events` | SOC telemetry | 150 | `timestamp`, `eventType`, `severity`, `userId`, `tenantId`, `sourceIp`, `requestId`, compound `{eventType, sourceIp, timestamp:-1}`, compound `{userId, timestamp:-1}` |
| `audit_logs` | Business audit trail | 100 | `timestamp` |
| `vulnerabilities` | Seeded finding catalog | 14 | `id` (unique) |
| `incidents` | SOC-detected incidents | 3 | `id` (unique) |
| `notifications` | Worker-raised incident alerts | – | `id` (unique), `tenantId`, `createdAt` |
| `attack_graphs` | Attack graph nodes and edges | 1 doc | – |

The two compound indexes on `security_events` are what make the detection engine
fast enough to run every 30 seconds: rule matching is always "recent events,
filtered by event type / user / source IP, newest first".

`passwordHash` is stripped from every user response by the model's `toJSON`.

---

## Tests

A zero-dependency `node:test` suite — no Jest, no Mocha, no npm install. Requires
Node 20+ (global `fetch`) and a running, seeded lab.

```bash
./tests/run.sh                                       # waits for /health, then runs everything
node --test tests/e2e/*.test.mjs                     # same, directly
node --test tests/e2e/vulns.test.mjs                 # a single file
SENTINELFORGE_API_URL=http://localhost/api ./tests/run.sh   # through nginx
```

> Pass the glob, not the directory. Some Node builds treat a bare directory
> argument as a module path and fail with `MODULE_NOT_FOUND`; `tests/run.sh`
> always expands `tests/e2e/*.test.mjs` for you.

| File | Covers | Tests |
|---|---|---|
| `tests/e2e/helpers.mjs` | shared fetch wrapper, per-run isolated source IPs, admin/user lookup | – |
| `tests/e2e/auth.test.mjs` | login, wrong password, no user enumeration, `/me`, refresh, logout, register + password reset round trip | 10 |
| `tests/e2e/authz.test.mjs` | RBAC: secure admin routes deny `STAFF`, vulnerable ones do not; JWT-claim endpoints | 7 |
| `tests/e2e/tenancy.test.mjs` | `GET /api/orders/secure/:id` 403 cross-tenant / 200 same-tenant; list scoping | 5 |
| `tests/e2e/vulns.test.mjs` | a reproduction **and** a secure-block assertion for VULN-001…013 | 25 |
| `tests/e2e/events.test.mjs` | `demo-status`, event and audit-log queries, findings, rules, scenarios, attack graph | 9 |
| `tests/e2e/detection.test.mjs` | all nine simulate scenarios → expected rule fires, events land, incident exists and links the finding; incident triage workflow; detection dedup | 12 |
| `tests/e2e/seed.test.mjs` | the seeded dataset shape: tenants, users, customers, products, orders, payments, audit logs, events, historical incidents, findings | 9 |

**Total: 77 tests.**

The suite is idempotent. It is safe to run repeatedly against the same database:

- every test sends a unique `X-Forwarded-For` (a `10.88.x.y` address) so
  detections never cross-contaminate;
- anything that changes a role (VULN-010 demotion, VULN-011 escalation, the
  promotion round trip) restores the original value in a `t.after()` hook;
- the incident-triage test restores the status it found;
- seed assertions key on deterministic seeded ids (`user-001`, `user-101`…`130`,
  `order-1`…`200`, `pay-1`…`50`) rather than total row counts, so the extra
  orders and users other tests create do not break them;
- detection tests assert "the expected rule fired and its incident exists", not
  "a brand-new incident appeared", because incidents are deduplicated for 10
  minutes and the worker also raises them every 30 seconds.

For a guaranteed-clean slate, reset and re-seed first:

```bash
./scripts/reset.sh && ./scripts/seed.sh && node --test tests/e2e/*.test.mjs
```

---

## Reset

```bash
./scripts/reset.sh     # drops every collection inside the api container
./scripts/seed.sh      # repopulate
```

`reset.sh` waits up to 60 s for `http://localhost:3001/health` and then runs
`docker compose exec -T api node dist/scripts/reset.js`, which drops all
collections. `seed.sh` does the same and then runs `dist/scripts/seed.js`.

For a completely clean environment, including the MongoDB volume:

```bash
docker compose down -v
docker compose up -d
./scripts/seed.sh
```

Resetting is safe at any time — the lab contains nothing that is not
regenerable from `server/src/scripts/seed.ts`.

---

## Frontend Pages

| Page | URL |
|---|---|
| Dashboard | <http://localhost/dashboard> |
| Users | <http://localhost/users> |
| Tenants | <http://localhost/tenants> |
| Products | <http://localhost/products> |
| Orders | <http://localhost/orders> |
| Admin | <http://localhost/admin> |
| Security events | <http://localhost/security-events> |
| Audit logs | <http://localhost/audit-logs> |
| Incidents | <http://localhost/incidents> |
| Security lab (catalog) | <http://localhost/security-lab> |
| Attack simulation | <http://localhost/security-lab/attacks> |
| Attack graph | <http://localhost/security-lab/attack-graph> |
| XSS demo | <http://localhost/security-lab/xss-demo> |

---

## Documentation

| Document | Contents |
|---|---|
| `README.md` | this file — architecture, setup, API, catalogs, tests |
| [`docs/HACKATHON-DEMO.md`](docs/HACKATHON-DEMO.md) | the exact 18-step demo story with runnable `curl` commands |
| [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) | `DEPENDENCY-DEMO-001` (multer) and `VULN-014` (committed fake secrets) |