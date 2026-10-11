# Fix Verification

This is the step the master spec calls mandatory, and it is the demo's closing beat: prove a fix actually blocks the same real attack.

## Flow

```
POST /api/findings/:id/apply-fix   -> CyberLab lab-fix toggle flips, finding -> FIXED
POST /api/findings/:id/verify      -> re-runs the real request the scanner originally used
                                       before: 200 OK (or equivalent "still works")
                                       after:  403 / rejected / blocked
                                       passed=true -> finding -> VERIFIED
POST /api/findings/:id/revert-fix  -> flips the toggle back, finding -> OPEN (demo repeatability)
```

Nothing here is simulated — `verifyFix()` (`modules/verification/service.ts`) makes a real HTTP call against the live CyberLab instance and reads the real status code back.

## Probe per vulnerability

Each probe re-runs (a minimal version of) the exact request the scanner used to prove the vuln, and defines what "blocked" means for that specific check:

| Vuln | Probe | Blocked means |
|---|---|---|
| VULN-001 | `GET /api/users/user-102` | status ≠ 200 |
| VULN-002 | `GET /api/orders/order-2` | status ≠ 200 |
| VULN-003 | `GET /api/admin/users/vulnerable` | status ≠ 200 |
| VULN-004 | NoSQL-operator login payload | status ≠ 200 (no token issued) |
| VULN-005 | post `<script>` comment | status ≠ 201 or content no longer stored byte-for-byte |
| VULN-006 | SSRF to `internal-service` | status ≠ 200 |
| VULN-007 | path traversal download | status ≠ 200 |
| VULN-008 | ping with shell metacharacters | status ≠ 200 or no longer flagged `injectionDetected` |
| VULN-009 | one failed login | status === 429 (strict limiter engaged) |
| VULN-010 | forged SUPER_ADMIN token for a real USER-role id | status ≠ 200 |
| VULN-011 | PATCH own role to TENANT_ADMIN | role unchanged after the patch |
| VULN-012 | tampered payment (amount=0.01) | status ≥ 400 or amount wasn't actually recorded as 0.01 |
| VULN-013 | upload a `.html` file | status ≠ 201 |
| VULN-014 | real Gitleaks scan of `config/demo.env`, fetched over HTTP via `GET /api/lab/config-file` | Gitleaks reports 0 findings (see below) |

**All 14 of 14 vulns** have a working verify probe (`VERIFIABLE_VULN_KEYS` in `modules/verification/service.ts`).

### VULN-014 is different: a real external tool, not a route re-check

There's no request to replay for a committed config file, so this probe instead fetches the file's live content from CyberLab (`GET /api/lab/config-file`, lab-key gated — added specifically because SentinelForge's scanner and CyberLab's API run in separate Docker containers with no shared filesystem; an earlier version of this check read the file directly off the local disk and silently errored inside Docker, see `docs/IMPLEMENTATION-STATUS.md`) and runs the actual **Gitleaks** binary against it (`modules/scanner/gitleaks.ts`), using a small custom rule (`gitleaks.toml`) since Gitleaks' default ruleset doesn't flag generic `KEY=value` assignments without a recognizable provider-key shape. Before a fix: 6 real findings. The fix (`POST /api/lab/fix/VULN-014`) redacts every credential value in the file to a literal marker; after the fix, Gitleaks reports 0.

## What gets stored

A `VerificationRun` document: `{ findingId, passed, outcome: "BLOCKED"|"STILL_VULNERABLE", before, after, createdBy }`. `before` is the original scanner evidence response; `after` is the fresh probe result — both real captured data, side by side, which is what the UI shows as "✅ Verification PASSED — attack blocked" with the actual `GET ... -> 403` detail line.

## Verified live

`npm run test:e2e` asserts steps 10–12 exactly: pre-fix verify returns `passed: false, after.status === 200`; post-fix verify returns `passed: true, after.status === 403`; finding status becomes `VERIFIED`. Also manually driven through the real UI (Apply Fix → Verify Fix buttons) — see `docs/IMPLEMENTATION-STATUS.md`.
