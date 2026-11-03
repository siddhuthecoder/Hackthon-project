# SentinelForge AI — Pitch

## The problem

AppSec teams find vulnerabilities. SOC teams watch for attacks. These are almost always two separate tools, two separate teams, and — critically — two separate sources of truth that never talk to each other. When an attacker exploits a vulnerability AppSec already found weeks ago, the SOC has no way of knowing that's what's happening. They see "suspicious access," not "known BOLA being exploited."

## The idea

SentinelForge connects the two, and goes further: it finds the weakness, proves it's exploitable with a real attack, detects that attack live, explains it, chains it into a realistic breach narrative, responds autonomously when the risk is high enough, fixes it, and verifies the fix — then writes the whole story down in a real ticket, a real postmortem, and a real alert.

> *"This activity is consistent with exploitation of VULN-001."*

Then it closes the loop: it can apply a fix and replay the same attack to prove, with a real 403 response, that the fix actually works.

## What's real in this build (not a mockup)

**Scanning — 17 real checks, 3 real external tools, 2 live targets**
- 14 purpose-built exploit checks against CyberLab (a live multi-tenant demo app) — IDOR, cross-tenant access, broken RBAC, NoSQL injection, stored XSS, SSRF, path traversal, mass assignment, business-logic/payment abuse, JWT role-trust, and more — each a genuine HTTP exploit attempt with captured evidence.
- **Gitleaks** (real binary) for committed secrets, **Semgrep** (real binary, custom rule) for an SSRF source pattern, **OSV** (real API) for dependency CVEs — three real external security tools, not hand-rolled regexes.
- A **systematic RBAC regression matrix**: logs in as every real non-admin role and attempts every admin-only action, not just the one known-broken endpoint.
- A real **JWT algorithm-confusion probe** (`alg: none`) against the live API.
- A **second, independent target** (OWASP Juice Shop) proving the adapter pattern is real, plus a **generic OpenAPI-driven adapter** that onboards any third-party REST API from its spec with zero new code.

**Detection & SOC**
- A real detection engine (7 rules, including a **canary/deception endpoint** that fires a zero-false-positive critical alert on the first unauthorized touch) evaluating real ingested events.
- A real correlation step that fires only when a real rule matches a real, previously-confirmed finding — including **retroactively**, if the attack happened before the scan did.
- A real attack graph (React Flow) plus a **Security Digital Twin**: one standing graph of every application, open finding, and active incident org-wide, not just per-incident.
- A **MITRE ATT&CK coverage heatmap** built from real detected techniques.
- **SOC Copilot**: ask a plain-English question ("show me every failed login in the last 24 hours"), AI translates it into a safe structured query, runs it against real events, answers from the real results.

**AI — 9 agents, real model, real audit trail**
- Explains, investigates, and recommends using only real evidence, FACT/INFERENCE/UNCERTAINTY separated, with an honest offline fallback labeled as such.
- **RedTeamAgent**: composes a real exploitation-chain narrative strictly from an application's actual open findings (never an invented vulnKey — filtered server-side even if the model tries).
- Runs on a real model (OpenRouter, free tier) with every tool call persisted to an auditable `AgentRun` record.

**Autonomous response**
- **SOAR playbooks**: when a correlated finding's real risk score (severity + EPSS + KEV + exposure) crosses a threshold, the system opens a real Jira ticket and stages a block-IP action on its own — never auto-executing the destructive step, always one human approval away.
- Real integrations: **Jira** tickets, **Confluence** postmortems (auto-+assembled from the real incident timeline), **Slack** alerts, **AbuseIPDB** IP reputation, **GitHub PRs** opened with AI-written patches.

**Governance**
- A real fix-and-verify loop for all 14 CyberLab vulnerabilities: flip the secure route into place, replay the exact request, watch 200 become 403 live.
- Risk-ranked fix queue, OWASP Top-10 compliance coverage view, multi-target posture comparison, scheduled re-scan with **regression detection** (we deliberately broke a fix behind the platform's back — it caught it within one scan cycle), SARIF/JSON export.
- A real **GitHub Actions security gate** on the project's own repo — Gitleaks, OSV, and a real build/typecheck on every PR. It has already caught three real issues on itself.
- **26 unit tests**, a 13-step live end-to-end script, and a 14-probe **cross-org isolation self-test** — which found and fixed a real IDOR in SentinelForge itself before anyone else could.

## The demo: Attack Theater

One button runs the entire loop live, no manual clicking between steps: connect target → discover → scan → launch a real attack → SOC detects it → AI investigates → attack graph renders → autonomous red-team chain analysis → locate the finding → apply the fix → verify it (200 → 403) → revert for repeatability. Every step is a real API call against the live stack, narrated as it happens.

## Honest limitations

MongoDB, not the spec's named PostgreSQL+Redis — a deliberate, confirmed choice, functionally equivalent. The 9-agent architecture (agents, named tools, orchestrator, persisted audit trail) is real but doesn't sit on the LangGraph library specifically. Three real external tools are integrated (Gitleaks, Semgrep, OSV) rather than the full Semgrep/ZAP/Nuclei/Trivy/OSV set — no cloud or container image scanning, since there's no real cloud account or Docker-socket access to scan honestly rather than fabricate results. The free-tier AI model is noticeably slower than a paid one and occasionally falls back to offline mode mid-demo — always labeled, never hidden.

See `docs/IMPLEMENTATION-STATUS.md` for the complete, unvarnished account of what was built, what was verified live, and what wasn't finished.
