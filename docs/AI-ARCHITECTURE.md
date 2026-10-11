# AI Architecture

## Design principle

AI is used only where reasoning over evidence genuinely helps a human: explaining a finding, investigating an incident, writing a remediation plan, narrating an attack graph, and answering a question about real platform data. AI is never used for detection (deterministic rules, `modules/detection/rules.ts`) or verification's pass/fail judgment (a real HTTP re-check, `modules/verification/service.ts`) — those must be reliable and reproducible, which rules out an LLM.

## The 8 agents, tools, and orchestrator

The master spec calls for a LangGraph-based `SecurityBrain` with 8 named agents, each with its own input schema, tool access, structured output, and an orchestrator that decides which to invoke. That's implemented, just not on top of the LangGraph library itself (see "Why not LangGraph" below) — every other piece is real:

- **`modules/ai/tools.ts`** — the exact named tools from the spec (`get_asset`, `get_application`, `get_endpoint`, `get_vulnerability`, `get_security_events`, `get_user`, `get_incident`, `get_related_findings`, `get_attack_path`, `query_audit_logs`, `run_authorized_security_test`, `generate_remediation`, `run_verification`, plus `get_threat_intel` and `run_security_scan`). Each is a thin, real query against SentinelForge's own database or a real action against CyberLab — never invented data.
- **`modules/ai/agents.ts`** — `ReconAgent`, `VulnerabilityAgent`, `InvestigationAgent`, `CorrelationAgent`, `AttackPathAgent`, `ThreatIntelAgent`, `RemediationAgent`, `VerificationAgent`. Each: a zod input schema, calls tools only (never raw DB access), a zod-validated structured output, and `try`/`catch` around every tool call.
- **`modules/ai/orchestrator.ts`: `runAgent()`** — every route that invokes an agent goes through this, which persists an `AgentRun` document: agent name, subject, status, every tool call made (`toolCalls[]`, each with its arguments and whether it succeeded), and the final output or error. This is the actual audit trail the spec asks for — inspect it directly in the `agent_runs` collection, not just the HTTP response.

### Which agent each route uses

| Route | Agent |
|---|---|
| `POST /api/findings/:id/analyze` | VulnerabilityAgent |
| `POST /api/findings/:id/remediate` | RemediationAgent |
| `POST /api/findings/:id/threat-intel` | ThreatIntelAgent |
| `POST /api/incidents/:id/investigate` | InvestigationAgent |
| `POST /api/incidents/:id/correlation` | CorrelationAgent |
| `POST /api/incidents/:id/attack-path-narrative` | AttackPathAgent |
| `POST /api/applications/:id/recon` | ReconAgent |
| `POST /api/findings/:id/verify` | VerificationAgent |

CorrelationAgent and InvestigationAgent both read from `get_related_findings` — a Correlation document is never created without evidence (`modules/correlation/service.ts`), so "related findings for an incident" *is* the correlation result. InvestigationAgent folds that straight into its investigation; CorrelationAgent exposes the same data standalone for a caller that wants just the correlation explanation.

## `callStructured()` — the actual model-calling layer underneath

Agents that need genuine text reasoning (VulnerabilityAgent, InvestigationAgent, RemediationAgent, AttackPathAgent) call `modules/ai/client.ts: callStructured()`:

```ts
callStructured<TInput, TOutput>(systemPrompt, input, offlineFn): Promise<{ data: TOutput, mode: 'model' | 'offline' }>
```

- **Provider precedence**: if `OPENROUTER_API_KEY` is set, calls OpenRouter's OpenAI-compatible chat completions endpoint (`config.ai.openrouterModel`, default `cohere/north-mini-code:free` — a free-tier model) via plain `fetch`. Else, if `ANTHROPIC_API_KEY` is set, calls Claude via the Anthropic SDK (`config.ai.anthropicModel`, default `claude-sonnet-5-5`). Either way, the system prompt + `input` go in, and the first `{...}` JSON block in the response is parsed out.
- If neither key is set, **or the model call/parse fails for any reason**: falls back to `offlineFn(input)`, a deterministic function that derives the same output shape directly from the real input data — no network, no invented facts.
- Every response is labeled `mode`, surfaced through the agent and the HTTP response, so nobody mistakes offline output for a model's.

Agents that are purely deterministic (ReconAgent, CorrelationAgent, ThreatIntelAgent) don't call `callStructured()` at all and report `mode: 'deterministic'` — there's no reasoning step to label as model/offline because there's no ambiguity to begin with (a tool result is just read and reshaped).

## Why not the literal LangGraph library

LangGraph adds a graph-execution runtime, checkpointing, and streaming on top of what is, for this project's actual agents, a single tool-gather-then-reason step each (none of the 8 agents here needs multi-turn tool-calling loops or branching control flow — they each do 1-3 tool calls and one reasoning call, in a fixed order). Building the graph-of-agents *pattern* (explicit tools, explicit agents, an orchestrator, persisted run history) without the specific dependency was the judgment call made here, trading the library's checkpointing/replay features for a dependency-free implementation that's easier to read end to end during a hackathon build. If an agent later needs actual multi-step autonomous tool-calling (e.g., "investigate, and if unclear, pull more audit logs and retry"), that's the point where adopting LangGraph (or an equivalent loop) would start paying for itself.

## Evidence discipline

Every prompt explicitly instructs the model (and every offline function structurally enforces, since it's just reading real fields) to separate:
- **FACT** — directly stated by the input data
- **INFERENCE** — a reasonable conclusion beyond the raw data
- **UNCERTAINTY** — something the given evidence cannot establish (e.g. "whether credentials were compromised beforehand")

This is why InvestigationAgent's output can honestly say *"This activity is consistent with exploitation of VULN-001"* — that phrase is derived from a real correlation, not hardcoded anywhere in the AI code.

## Real (model) mode — enabled

Set `OPENROUTER_API_KEY` (or `ANTHROPIC_API_KEY`) in `sentinelforge/backend/.env`. No code change needed. **Currently enabled** using a free OpenRouter model (`cohere/north-mini-code:free`). Verified live through every model-backed agent (VulnerabilityAgent, InvestigationAgent, RemediationAgent, AttackPathAgent, the assistant) and through the actual browser UI, not just the API — every response correctly shows `mode: "model"`, and the full 13-step e2e passes with it active. The free model is noticeably slower than a paid one (observed ~10-20s per call) — the offline fallback still kicks in automatically if a call is slow enough to error or fails outright, so a live demo is never blocked on it.
