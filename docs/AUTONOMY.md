# Autonomy

The master spec's AI design principles say the final security action stays a human decision. This document covers exactly where the automatic/autonomous line sits, and what crosses it only with a human click.

## What runs automatically (no click)

`modules/autonomy/loop.ts: autoRespondToIncident()`, fired (not awaited — see below) the moment `detection/service.ts` creates a correlated incident:

1. **Auto-investigate**: `InvestigationAgent` runs immediately. The incident's `investigation` field is populated and its status moves `OPEN → INVESTIGATING` before any human opens the incident page. `investigation.triggeredBy` is set to `"autonomous"` so it's distinguishable from a manually re-run investigation.
2. **Auto-propose remediation**: for every finding the incident correlates to, `RemediationAgent` runs and a `RemediationTask` is created with `status: "PROPOSED"` and `plan.autonomous: true`. The finding detail API (`GET /api/findings/:id`) surfaces this as `proposedRemediation` so the UI shows it without the "Generate Remediation" button ever being clicked — labeled **"proposed automatically"** in the UI.

Both are best-effort: errors are caught and logged, never thrown, so a flaky AI call can't break the detection pipeline that triggered it. A human can always still click "Investigate" or "Generate Remediation" manually — nothing is lost if the autonomous pass doesn't produce one (dedupe on existing `PROPOSED` tasks prevents double-proposing on re-runs).

## Why fire-and-forget, not awaited

`runDetection()` is on the hot path of the "Run Attack" button in Security Lab — the human clicks it and waits for the HTTP response. A real AI call (especially the free OpenRouter model currently configured) can take 10-20 seconds; awaiting it inline would make that button hang uncomfortably. Instead, the incident is created and returned immediately, and the investigation/proposed-remediation populate moments later — which is arguably the more honest shape of "autonomous" anyway: it runs on its own schedule, not blocking the person who triggered the underlying event.

## Verified live

Triggered an attack via the API, **never called `/investigate` or `/remediate`**, and confirmed: the incident list showed `INVESTIGATING` status on its own; opening the incident showed the full AI investigation panel already rendered (`mode: model`, `triggeredBy: autonomous`); opening the correlated finding showed a remediation plan already present, labeled "proposed automatically". Confirmed both via direct API polling and by clicking through the real browser UI.

## What still requires a human click (never automatic)

- **Apply Fix** (`POST /api/findings/:id/apply-fix`) — flips the lab-fix toggle / redacts the secret.
- **Verify Fix** (`POST /api/findings/:id/verify`) — re-runs the real check.
- **Open Fix PR** (`POST /api/findings/:id/open-pr`) — commits and pushes to the real repository (see `docs/GITHUB-PR-AUTOMATION.md`).
- **Response actions** marked high-impact (`disable_user`, `block_ip`, `isolate_asset`) — sit `PENDING_APPROVAL` until a separate approval call.

This matches the spec's own principle exactly: *Detection: RULE ENGINE. Correlation: RULES + GRAPH + AI. Investigation: AI. Final security action: HUMAN APPROVAL.*
