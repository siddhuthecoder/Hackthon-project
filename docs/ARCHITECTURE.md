# Architecture

## Two systems

```
CyberLab (target, authorized lab)          SentinelForge (the product)
  Next.js UI, Express API, MongoDB    <---  modules/cyberlab/adapter.ts (HTTP only)
  14 seeded vulnerabilities                        |
  9 attack scenarios                                v
  own event log + own detection engine     scanner / events / detection / correlation
                                                     |
                                                     v
                                            Mongo (sfplatform db) + Fastify API
                                                     |
                                                     v
                                            Next.js frontend (8 pages)
```

SentinelForge never imports or requires CyberLab code, and never writes to CyberLab's database — every interaction is a real HTTP call through `CyberLabAdapter`, exactly as a real external security tool would integrate with a real target.

## Request flow (hero loop)

```
Security Lab "Run IDOR Attack" click
  -> POST /api/applications/:id/simulate/03-idor
  -> CyberLabAdapter.runSecurityTest() -> CyberLab's own simulator (real HTTP requests)
  -> ingestEvents() pulls the new security_events CyberLab just logged
  -> runDetection() evaluates 5 rules over the last 10 minutes of events
  -> match -> Detection + Incident created
  -> correlateIncident() links it to the finding whose vulnKey the rule names
  -> buildAttackPath() builds the React Flow graph from that same data
  -> bus.publish() -> SSE -> SOC page updates live
```

## Backend module layout (`sentinelforge/backend/src`)

```
config.ts                  env loading, no credential defaults
db/
  connection.ts, models.ts  Mongoose connection + every collection's schema+interface
modules/
  auth/                    login, JWT issue/verify
  applications/            register/discover/scan an app
  cyberlab/adapter.ts       the TargetAdapter implementation for CyberLab
  scanner/                  14 real HTTP vulnerability checks + persistence
  events/ingest.ts          pull + normalize + dedupe CyberLab events
  detection/                5 rule evaluators + incident creation
  correlation/              rule -> known finding linking
  graph/                    attack graph builder (React Flow data)
  ai/
    tools.ts                named tool functions (get_vulnerability, get_incident, run_verification, ...)
    agents.ts               8 agents (Recon/Vulnerability/Investigation/Correlation/AttackPath/ThreatIntel/Remediation/Verification)
    orchestrator.ts         runAgent() — dispatches + persists AgentRun (full tool-call trail)
    client.ts               callStructured() — Claude call with offline fallback
    explainFinding.ts, investigate.ts, remediate.ts   the actual prompts + offline functions
    routes.ts               one route per agent
  threatintel/              local CWE/OWASP/CVE/EPSS/CISA-KEV-shaped reference dataset + sync
  verification/             apply-fix / revert-fix / verify (re-run the real check)
  response/                 incident response actions + approval gate
  incidents/, findings/     CRUD + detail routes
  catalog/                  assets / events / audit-logs / remediation-tasks / verification-runs listings
  stream/                   SSE live feed
  lab/                      simulate-attack trigger route
lib/                        bus (pub/sub), audit, small utils
plugins/auth.ts              RBAC permission matrix
scripts/                    seed, demo-reset, e2e
```

## Frontend layout (`sentinelforge/frontend/src`)

```
lib/api.ts        fetch wrapper (JWT from localStorage), SSE url builder
lib/auth.tsx       auth context (login/logout/me)
lib/types.ts       shared TS types mirroring backend responses
components/        Badge, Shell (nav, with a "More" dropdown for the less-used pages), AttackGraphView (React Flow)
app/
  login/
  (dashboard)/      auth-gated layout
    dashboard/ findings/ findings/[id]/ incidents/ incidents/[id]/ incidents/[id]/investigation/
    security-lab/ soc/ applications/ applications/[id]/ assets/ scans/ attack-graph/
    events/ audit-logs/ threat-intelligence/ remediation/ verification/ settings/
```

19 pages total — every one from the master spec's §33 list (`/login` through `/settings`).

## Why these choices (deviations from the original master spec, see `docs/IMPLEMENTATION-STATUS.md` for the full list)

- **MongoDB, not PostgreSQL.** Reuses the same host Mongo install already needed for local dev; document shapes (evidence blobs, event metadata) fit Mongo naturally; no relational joins needed at this scale.
- **No Redis.** An in-process EventEmitter (`lib/bus.ts`) is enough for one backend instance; SSE consumes it directly.
- **No LangGraph / multi-agent framework.** One `callStructured()` helper per AI action (explain/investigate/remediate/assistant), each with its own prompt and a deterministic offline fallback. Simpler to reason about and debug live.
- **Plain fetch, no state-management library on the frontend.** Each page owns its own data fetching; the app is small enough that this stays readable.
