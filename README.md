# SentinelForge AI

An autonomous AI security engineer that connects vulnerabilities an AppSec scan finds with attacks the SOC observes live — then proves a fix works by re-running the same attack.

```
FIND THE WEAKNESS → DETECT THE ATTACK → INVESTIGATE → CORRELATE → FIX → VERIFY
```

## Structure

- `cyberlab/` — an intentionally vulnerable demo SaaS (the authorized target). Do not modify beyond the lab-fix toggle in `cyberlab/server/src/services/labFix.ts`.
- `sentinelforge/backend/` — the SentinelForge API: CyberLab adapter, scanner, detection engine, correlation engine, attack graph, AI module, verification.
- `sentinelforge/frontend/` — the SentinelForge UI (Next.js).
- `docs/` — start with `docs/HACKATHON-DEMO.md` to run the demo and `docs/IMPLEMENTATION-STATUS.md` for exactly what's built and verified. Also: `ARCHITECTURE.md`, `API.md`, `DATABASE.md`, `AI-ARCHITECTURE.md`, `SOC.md`, `CORRELATION.md`, `ATTACK-GRAPH.md`, `REMEDIATION.md`, `VERIFICATION.md`, `SECURITY.md`, `DEVELOPMENT.md`, `CYBERLAB-INTEGRATION-MAP.md`, `HACKATHON-PITCH.md`, and `SENTINELFORGE-MASTER-SPEC.md` (the original full spec this was trimmed from).

## Quick start

See `docs/HACKATHON-DEMO.md` for full setup (dev mode or fully dockerized), credentials, and the demo script. Dev-mode short version:

```bash
cd cyberlab && docker compose up -d
cd sentinelforge/backend && npm install && npm run seed && npm run dev
cd sentinelforge/frontend && npm install && npm run dev
```

Or fully dockerized: `cd sentinelforge && docker compose up -d --build`.

Then: `npm run test:e2e` (in `sentinelforge/backend`) to run the full hero flow as one automated check, or open `http://localhost:3000` for the live UI demo.

## Status

Backend and frontend core demo flow are complete and verified live (not just unit-tested) — see `docs/IMPLEMENTATION-STATUS.md` for exactly what was built, how it was verified, and the known gaps.
