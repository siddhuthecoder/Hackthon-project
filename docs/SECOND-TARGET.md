# Second Target: OWASP Juice Shop

Proves the `TargetAdapter` pattern (`docs/ARCHITECTURE.md`) is real, not hardcoded to CyberLab. The same scan → persist → correlate-ready → threat-intel pipeline runs against a second, completely independent, well-known vulnerable application.

## Why Juice Shop

Public Docker image (`bkimminich/juice-shop`), no build needed, widely known OWASP benchmark app with its own real (not invented) vulnerabilities — independently confirmed by hand before any code was written (see raw evidence below).

## Real evidence gathered before writing the checks

```
$ curl -X POST http://localhost:3002/rest/user/login -d '{"email":"'"'"' or 1=1--","password":"x"}'
→ 200, valid JWT, authenticated as admin@juice-sh.op — classic SQLi login bypass (CWE-89)

$ curl http://localhost:3002/api/Users/1 -H "Authorization: Bearer <any logged-in user's token>"
→ 200, returns the admin account's full record (id, email, role) — no ownership check (CWE-639)
```

Both are genuine, well-known Juice Shop challenges ("Login Admin" and a BOLA/excessive-data-exposure class bug), not guessed.

## What was built

- `modules/targets/juiceshop/adapter.ts` — `JuiceShopAdapter`: health check, generic `request()`, and `demoLogin()` (registers + logs in a throwaway account, same pattern as `CyberLabAdapter.demoLogin()`).
- `modules/targets/juiceshop/checks.ts` — 2 real checks: `JS-001` (SQLi login bypass) and `JS-002` (IDOR user read).
- `modules/scanner/service.ts` — `runJuiceShopScan()`, sharing the exact same persist/threat-intel/publish pipeline as `runScan()` (CyberLab) via extracted `persistResults()`/`finishScan()` helpers.
- `Application.adapter` now accepts `'juiceshop'` (was always `'cyberlab'`); `POST /api/applications` takes an `adapter` field; `/discover` and `/scan` routes dispatch to the right adapter/check-set based on it.
- `sentinelforge/docker-compose.yml` — `juiceshop` service (public image, port 3002).
- Frontend: `/applications` page got a real "+ Add Application" form (name, base URL, adapter dropdown); `/applications/:id` got a "Run Scan" button.

## Verified live

Registered via the actual UI form → discovered (4 endpoints) → scanned → **2/2 real findings** (JS-001 critical, JS-002 high), confirmed both via API and by clicking through the real browser UI (`/applications`, `/applications/:id`, `/findings`).

## Scope note

This target proves extensibility; it isn't a second full demo. No detection/correlation/attack-graph wiring for Juice Shop (it has no equivalent "live attack" event stream to ingest) — findings, AI explain, and AI remediate all work on it exactly like CyberLab's, since those are adapter-agnostic by construction.
