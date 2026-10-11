# SentinelForge AI — Pitch

## The problem

AppSec teams find vulnerabilities. SOC teams watch for attacks. These are almost always two separate tools, two separate teams, and — critically — two separate sources of truth that never talk to each other. When an attacker exploits a vulnerability AppSec already found weeks ago, the SOC has no way of knowing that's what's happening. They see "suspicious access," not "known BOLA being exploited."

## The idea

SentinelForge connects the two. It finds a vulnerability once, through real scanning. Later, when live traffic matches the pattern of that exact vulnerability, it doesn't just flag "suspicious" — it says:

> *"This activity is consistent with exploitation of VULN-001."*

Then it closes the loop: it can apply a fix and replay the same attack to prove, with a real 403 response, that the fix actually works.

## What's real in this build (not a mockup)

- **14 real vulnerability checks** against a live multi-tenant demo app (CyberLab), each one a genuine HTTP exploit attempt with captured evidence — not a canned finding list.
- **A real attack**, triggered by a button, that generates real traffic against the real app.
- **A real detection engine** (5 rules) evaluating real ingested events, with zero overlap between the scanner's own traffic and simulated attacker traffic (a genuine bug was found and fixed here — the scanner was briefly tripping its own alarms).
- **A real correlation step** that only ever fires when a real detection rule matches a real, previously-confirmed finding on the same endpoint — never fabricated.
- **A real attack graph**, built from that same data, rendered with React Flow.
- **AI that explains, investigates, and recommends** — using only the real evidence in the database, with FACT/INFERENCE/UNCERTAINTY separated, and an honest offline fallback that's labeled as such rather than silently pretending to be a model.
- **A real fix-and-verify loop**: flip CyberLab's own already-written secure route into place, replay the exact request that was vulnerable, and watch the status code change from 200 to 403 live.
- **One command** (`npm run test:e2e`) that proves all 13 steps of this, end to end, from a clean reset, every time.

## The 3-minute demo

Scan → 14 findings appear, including a HIGH BOLA. Click "Run IDOR Attack" in the Security Lab. Switch to the live SOC feed — real events stream in. An incident appears, already correlated to the known vulnerability. Click "Investigate with AI" — it names the vulnerability and shows the real evidence timeline. Open the attack graph. Go back to the finding, click Apply Fix, click Verify Fix — 200 becomes 403 on screen, in real time.

## Honest limitations

AI runs in real model mode (a free OpenRouter model) in this build, with an automatic, honest offline fallback if a call fails — either way, output is grounded in real data, never fabricated, and clearly labeled which mode produced it. All 14 vulnerabilities now have a one-click verify probe, including the secret-in-committed-config one, which runs a real Gitleaks scan over HTTP rather than a route re-check. No unit test suite — the one automated check is a full live end-to-end run, which is arguably a higher bar to pass than mocked unit tests, but it isn't a substitute for one. The stack runs MongoDB instead of the spec's named PostgreSQL+Redis, and the AI agent architecture (8 named agents, 13 named tools, an orchestrator, a full persisted tool-call audit trail) is implemented without the specific LangGraph library underneath — the pattern is real, the dependency isn't. Of the spec's named AppSec tools, only Gitleaks was integrated (for the one vuln class it's actually built for); the other 13 vulnerabilities are purpose-built exploit checks, since generic SAST/DAST tools don't meaningfully catch business-logic or auth-bypass bugs like these without extensive custom rules of their own.

See `docs/IMPLEMENTATION-STATUS.md` for the complete, unvarnished account of what was built, what was verified live, and what wasn't finished.
