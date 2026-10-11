# SentinelForge AI — Hackathon Demo Guide

## 1. Startup

Two ways to run SentinelForge: plain `npm run dev` (faster iteration) or fully dockerized. Either way, CyberLab runs the same way.

```bash
# CyberLab (always Docker)
cd cyberlab
docker compose up -d
# requires cyberlab/.env with LAB_CONTROL_KEY set (see cyberlab/.env.example)
```

**Option A — dev mode** (needs a local MongoDB reachable at `mongodb://127.0.0.1:27017`):

```bash
cd sentinelforge/backend
npm install
npm run seed        # creates admin + analyst accounts from .env
npm run dev          # http://localhost:4000

cd sentinelforge/frontend
npm install
npm run dev           # http://localhost:3000
```

**Option B — fully dockerized:**

```bash
cd sentinelforge
docker compose up -d --build   # own Mongo + backend + frontend
docker compose exec backend node dist/db/seed.js
```

Backend reaches CyberLab via `host.docker.internal:3001` (already configured in `sentinelforge/docker-compose.yml`); no extra networking setup needed on Docker Desktop (Windows/Mac). On Linux, `extra_hosts: host-gateway` is already set in the compose file.

Required local `.env` files (gitignored, never committed):
- `cyberlab/.env` — `LAB_CONTROL_KEY`
- `sentinelforge/backend/.env` — see `.env.example`: `SF_JWT_SECRET`, `SF_ADMIN_PASSWORD`, `SF_ANALYST_PASSWORD`, `LAB_CONTROL_KEY` (must match `cyberlab/.env`), `CYBERLAB_JWT_SECRET` (= CyberLab's own `JWT_SECRET`, used only for the VULN-010 forged-token probe)

## 2. Login credentials (demo)

- Email: value of `SF_ADMIN_EMAIL` (default `admin@sentinelforge.ai`)
- Password: value of `SF_ADMIN_PASSWORD` in your local `.env`

## 3. Reset before every demo run

```bash
cd sentinelforge/backend
npm run demo:reset
```

Clears all SentinelForge data and resets CyberLab's lab-fix toggles. CyberLab's own seeded data (users, tenants, vulnerabilities) is untouched — only re-seed CyberLab (`cyberlab/server`: `npm run seed`) if you want a fully fresh lab too.

## 4. Automated end-to-end check

```bash
cd sentinelforge/backend
npm run test:e2e
```

Runs the entire hero flow as one command against the live stack: login → register app → discover → scan (asserts VULN-001 found) → simulate IDOR attack → assert incident created → assert correlation + attack graph exist → AI investigate (asserts it names VULN-001) → verify pre-fix (200) → apply fix → verify post-fix (403, VERIFIED) → revert fix. Run this before presenting to confirm everything works.

## 5. Live demo script (~3 minutes)

1. Open `http://localhost:3000`, log in.
2. **Dashboard** is empty. Click **"Connect CyberLab & Run Scan."**
   - Watch it register the app, discover endpoints, run the scanner.
   - Result: 14 findings, including VULN-001 (HIGH) and VULN-002 (CRITICAL).
3. Open **Findings → VULN-001**.
   - Show endpoint, real evidence (Alice reading Bob's profile), CWE-639, API1:2023.
   - Click **AI Analyze** — shows facts/inferences/uncertainties derived from the real evidence.
4. Open **SOC** in a second tab — live feed, currently quiet.
5. Open **Security Lab**, click **"Run IDOR Enumeration."**
   - Switch to the SOC tab: real events stream in live.
   - A detection fires, an incident is created — no manual step needed.
6. Open **Incidents → "Possible IDOR Attack."**
   - Already shows the correlation: *"consistent with exploitation of VULN-001."*
   - Click **"Investigate with AI"** — produces the full timeline, facts, attack path, recommended actions.
   - Scroll down to the **attack graph**: user → endpoint → VULN-001 → data.
7. Go back to **Findings → VULN-001**.
   - Click **Apply Fix**.
   - Click **Verify Fix**.
   - Shows **"✅ Verification PASSED — attack blocked"**, before = 200, after = 403.
   - Finding becomes `VERIFIED`.
8. (Optional) Open the correlated incident and click **Mark Contained** to show response actions.

## 6. Reset for the next run

```bash
npm run demo:reset
```

## 7. Known limitations

- AI runs in **real model mode** when `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` is set in `sentinelforge/backend/.env` (currently using a free OpenRouter model — expect ~10-20s per AI call, noticeably slower than a paid model). Without either key, it falls back to offline mode: real, data-derived output, never fabricated, just not model-generated. Every AI response is labeled `mode: "model"` or `mode: "offline"` so it's never ambiguous which one ran.
- Verification probes are implemented for **all 14** vulnerabilities, including VULN-014 (secret in a committed config file), which uses a real Gitleaks scan over HTTP rather than a route re-check. See `docs/VERIFICATION.md`.
- Detection dedupes the same rule+subject for 5 minutes, so re-running the same attack scenario twice in quick succession will not create a second incident — this is intentional (prevents incident spam), not a bug.
- No unit test suite — `npm run test:e2e` (the full live hero flow) is the only automated check.
