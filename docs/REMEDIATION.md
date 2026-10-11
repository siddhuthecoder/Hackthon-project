# Remediation

## Where it comes from

CyberLab ships a secure counterpart route for every one of its 14 vulnerabilities (e.g. `GET /api/users/secure/:userId` next to the vulnerable `GET /api/users/:userId`). SentinelForge's remediation is built on this fact rather than generating a patch from scratch:

- **`POST /api/findings/:id/remediate`** (`modules/ai/remediate.ts`) — AI explains the root cause, the secure approach, a patch summary, required tests, and verification steps. Input is the finding's own description/remediation text plus its known secure endpoint; output is structured (`rootCause, secureApproach, patchSummary, testsRequired[], verificationSteps[]`), offline-mode-safe like every other AI call (see `docs/AI-ARCHITECTURE.md`).
- **`POST /api/findings/:id/apply-fix`** (`modules/verification/service.ts: applyFix()`) — the actual controlled fix mechanism. Calls CyberLab's lab-fix toggle (`POST /api/lab/fix/:vulnId`) which rewrites the vulnerable route to its already-existing secure implementation at the Express routing layer. Records a `RemediationTask` (`status: APPLIED`), moves the finding to `FIXED`.
- **`POST /api/findings/:id/revert-fix`** — flips the toggle back (`POST /api/lab/unfix/:vulnId`), finding returns to `OPEN`. Used to keep the demo repeatable, not a real rollback mechanism.

## Why a toggle instead of editing source code

The master spec explicitly calls for "a controlled demo fix mechanism" rather than blindly modifying production code. CyberLab already contains the secure implementation as a separate route (written for teaching purposes); flipping which one is live is a safe, instant, and 100% reversible way to demonstrate "apply the fix" without SentinelForge ever writing to CyberLab's source or restarting any process. See `cyberlab/server/src/services/labFix.ts`.

## Coverage

The fix-toggle now covers all 14 vulns (`FIXABLE` in `labFix.ts`). VULN-001 through VULN-013 flip a vulnerable route to its secure counterpart; **VULN-014** (a credential-shaped line committed in `cyberlab/config/demo.env`) is different — there's no request-handling route for a static file's content, so its "fix" rewrites every credential value in the file to a literal marker and backs up the original in memory, restored on unfix/reset (same repeatable-demo contract as the route-based fixes). See `docs/VERIFICATION.md` for how each one is verified.

## Human approval

Remediation and fix-application require an authenticated user with the `apply_fix` permission (admin or analyst role) — see `src/plugins/auth.ts`. Nothing applies automatically from a detection or AI output.
