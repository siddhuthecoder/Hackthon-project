# API Reference

Base URL: `http://localhost:4000`. All routes except `/health`, `/ready`, `/api/auth/login` require `Authorization: Bearer <jwt>`. Roles: `admin`, `analyst`, `viewer` — see `src/plugins/auth.ts` for the exact permission matrix.

## Health

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | `{ status: "ok", timestamp }` |
| GET | `/ready` | none | 503 if Mongo isn't connected |

## Auth

| Method | Path | Auth | Body | Notes |
|---|---|---|---|---|
| POST | `/api/auth/login` | none | `{ email, password }` | returns `{ token, user }` |
| GET | `/api/auth/me` | read | — | current user from JWT |

## Applications

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/applications` | read | list for your org |
| POST | `/api/applications` | manage_apps | `{ name, baseUrl, environment?, repository? }` |
| POST | `/api/applications/:id/discover` | manage_apps | populates assets/endpoints from the known CyberLab route list |
| POST | `/api/applications/:id/scan` | scan | runs all 14 vulnerability checks, persists findings |
| POST | `/api/applications/:id/simulate/:scenarioId` | simulate | triggers a real CyberLab attack scenario, then ingests events + runs detection immediately |

## Findings

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/findings` | read | all findings for your org, sorted by severity |
| GET | `/api/findings/:id` | read | includes `relatedIncidents` |
| PATCH | `/api/findings/:id` | scan | `{ status }` — one of OPEN/CONFIRMED/FALSE_POSITIVE/FIXED/VERIFIED |
| POST | `/api/findings/:id/analyze` | investigate | AI explain (facts/inferences/uncertainties), returns `mode: "model"\|"offline"` |
| POST | `/api/findings/:id/remediate` | remediate | AI remediation plan |
| POST | `/api/findings/:id/apply-fix` | apply_fix | flips the CyberLab lab-fix toggle, finding -> FIXED |
| POST | `/api/findings/:id/revert-fix` | apply_fix | flips it back, finding -> OPEN |
| POST | `/api/findings/:id/verify` | apply_fix | re-runs the real check; `{ passed, before, after }`; finding -> VERIFIED if passed |

## Incidents

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/incidents` | read | most recent 200 |
| GET | `/api/incidents/:id` | read | includes `events`, `correlations`, `findings` |
| PATCH | `/api/incidents/:id` | respond | `{ status }` — OPEN/INVESTIGATING/CONTAINED/RESOLVED/FALSE_POSITIVE |
| GET | `/api/incidents/:id/attack-graph` | read | React Flow `{ nodes, edges, summary }` |
| POST | `/api/incidents/:id/investigate` | investigate | AI investigation; also moves OPEN -> INVESTIGATING |
| POST | `/api/incidents/:id/respond` | respond | `{ action, target? }` — see Response Actions below |
| GET | `/api/incidents/:id/response-actions` | read | history |

## Response actions

`action` is one of: `revoke_session`, `disable_user`, `mark_contained`, `create_remediation_task`, `block_ip`, `isolate_asset`, `generate_ticket`.

High-impact actions (`disable_user`, `block_ip`, `isolate_asset`) are created `PENDING_APPROVAL` and never execute until approved. Everything else executes immediately (and is still just a recorded, simulated action — nothing touches a real system).

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/api/response-actions/:id/approve` | approve_action | moves PENDING_APPROVAL -> EXECUTED |

## Agents (threat intel / recon / correlation / attack-path narrative)

| Method | Path | Permission | Agent | Notes |
|---|---|---|---|---|
| POST | `/api/findings/:id/threat-intel` | read | ThreatIntelAgent | CWE/OWASP/CVE/EPSS/CISA-KEV-shaped local reference data for this finding |
| POST | `/api/incidents/:id/correlation` | read | CorrelationAgent | standalone correlation explanation (also included in `/investigate`) |
| POST | `/api/incidents/:id/attack-path-narrative` | read | AttackPathAgent | plain-language walkthrough of the attack graph |
| POST | `/api/applications/:id/recon` | read | ReconAgent | summarizes discovered assets/endpoints |

Every agent call is logged as an `AgentRun` document (agent name, every tool call made, final output or error) — see `docs/AI-ARCHITECTURE.md`.

## Applications (continued)

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/applications/:id` | read | detail: includes `assets[]`, `endpoints[]`, `scanRuns[]` |
| GET | `/api/scans` | read | all scan runs across your org's applications |

## Catalog (standalone listing pages)

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/assets` | read | all discovered assets across your org |
| GET | `/api/events?limit=` | read | raw ingested security events (SOC's live feed is the real-time version of this) |
| GET | `/api/audit-logs?limit=` | read | audit trail |
| GET | `/api/remediation-tasks` | read | every applied fix |
| GET | `/api/verification-runs` | read | every verify-fix click's result |

## Threat intelligence

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/threat-intel` | read | all synced indicators |
| GET | `/api/threat-intel/:value` | read | one indicator by CWE id |

## Assistant

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/api/assistant/ask` | read | `{ question, incidentId?, findingId? }` — requires at least one id so the answer is grounded in real data; refuses otherwise |

## Live feed

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/stream?token=<jwt>` | query-param JWT | Server-Sent Events. Topics: `event`, `detection`, `incident`, `scan`, `verification`, `finding`, `agent`. EventSource can't set headers, hence the query param. |

## Lab control (CyberLab-side, not SentinelForge's API)

These live on CyberLab (`http://localhost:3001`), guarded by `x-lab-key: <LAB_CONTROL_KEY>`, added specifically for SentinelForge's verification loop:

| Method | Path |
|---|---|
| GET | `/api/lab/state` |
| POST | `/api/lab/fix/:vulnId` |
| POST | `/api/lab/unfix/:vulnId` |
| POST | `/api/lab/reset` |
