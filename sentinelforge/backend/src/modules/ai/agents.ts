/**
 * The 8 agents from the master spec's "AI security brain" section. Each is a plain async
 * function (not a LangGraph graph node — see docs/AI-ARCHITECTURE.md for why) with:
 *   - an explicit input schema (zod)
 *   - tool access only through the named functions in tools.ts (never raw DB access)
 *   - structured output, validated against a zod schema before being returned
 *   - error handling (every tool call is wrapped; failures are recorded, not swallowed)
 * The orchestrator (orchestrator.ts) decides which agent to invoke and persists an AgentRun
 * record of every tool call made, so the full reasoning trail is inspectable.
 */
import { z } from 'zod';
import { callStructured } from './client';
import { explainFinding, FindingExplanation } from './explainFinding';
import { investigateIncident, Investigation } from './investigate';
import { RemediationPlan } from './remediate';
import * as tools from './tools';

export interface ToolCallRecord {
  tool: string;
  args: unknown;
  at: string;
  ok: boolean;
  error?: string;
}

export class ToolCallRecorder {
  readonly calls: ToolCallRecord[] = [];

  async run<T>(tool: string, args: unknown, fn: () => Promise<T> | T): Promise<T> {
    const at = new Date().toISOString();
    try {
      const result = await fn();
      this.calls.push({ tool, args, at, ok: true });
      return result;
    } catch (err) {
      this.calls.push({ tool, args, at, ok: false, error: err instanceof Error ? err.message : 'tool failed' });
      throw err;
    }
  }
}

export interface AgentResult<T> {
  output: T;
  mode: 'model' | 'offline' | 'deterministic';
  toolCalls: ToolCallRecord[];
}

// --- 1. ReconAgent -----------------------------------------------------------------

const reconInput = z.object({ applicationId: z.string() });
const reconOutputShape = z.object({ summary: z.string(), assetCount: z.number(), endpointCount: z.number() });
export type ReconReport = z.infer<typeof reconOutputShape> & { assets: unknown[]; endpoints: unknown[] };

export async function ReconAgent(input: z.infer<typeof reconInput>): Promise<AgentResult<ReconReport>> {
  const { applicationId } = reconInput.parse(input);
  const rec = new ToolCallRecorder();
  const application = await rec.run('get_application', { applicationId }, () => tools.get_application(applicationId));
  const assets = await rec.run('get_asset', { applicationId }, () => tools.get_asset(applicationId));
  const endpoints = await rec.run('get_endpoint', { applicationId }, () => tools.get_endpoint(applicationId));
  const summary = application
    ? `${application.name} (${application.baseUrl}): ${assets.length} asset(s), ${endpoints.length} discovered endpoint(s), status ${application.status}.`
    : 'Application not found.';
  const validated = reconOutputShape.parse({ summary, assetCount: assets.length, endpointCount: endpoints.length });
  return {
    output: { ...validated, assets: assets.map(a => a.toJSON()), endpoints: endpoints.map(e => e.toJSON()) },
    mode: 'deterministic',
    toolCalls: rec.calls,
  };
}

// --- 2. VulnerabilityAgent (explain a finding) --------------------------------------

const vulnAgentInput = z.object({ findingId: z.string() });

export async function VulnerabilityAgent(input: z.infer<typeof vulnAgentInput>): Promise<AgentResult<FindingExplanation>> {
  const { findingId } = vulnAgentInput.parse(input);
  const rec = new ToolCallRecorder();
  const finding = await rec.run('get_vulnerability', { findingId }, () => tools.get_vulnerability(findingId));
  if (!finding) throw new Error(`Finding ${findingId} not found`);
  const { data, mode } = await explainFinding(finding);
  return { output: data, mode, toolCalls: rec.calls };
}

// --- 3. InvestigationAgent -----------------------------------------------------------
// Incorporates CorrelationAgent's result directly: a Correlation document is never created
// without evidence (modules/correlation/service.ts), so "related findings" for an incident IS
// the correlation result. CorrelationAgent (below) exposes the same data standalone, for callers
// that want just the correlation explanation without a full investigation.

const investigateInput = z.object({ incidentId: z.string() });

export async function InvestigationAgent(input: z.infer<typeof investigateInput>): Promise<AgentResult<Investigation>> {
  const { incidentId } = investigateInput.parse(input);
  const rec = new ToolCallRecorder();
  const incident = await rec.run('get_incident', { incidentId }, () => tools.get_incident(incidentId));
  if (!incident) throw new Error(`Incident ${incidentId} not found`);
  const events = await rec.run('get_security_events', { incidentId }, () => tools.get_security_events(incidentId));
  const related = await rec.run('get_related_findings', { incidentId }, () => tools.get_related_findings(incidentId));
  const { data, mode } = await investigateIncident(incident, events, related.correlations, related.findings);
  return { output: data, mode, toolCalls: rec.calls };
}

// --- 4. CorrelationAgent (explains why a correlation holds, in plain language) -------

const correlationInput = z.object({ incidentId: z.string() });
const correlationOutput = z.object({ correlated: z.boolean(), reasons: z.array(z.string()), relatedVulnKeys: z.array(z.string()) });
export type CorrelationExplanation = z.infer<typeof correlationOutput>;

export async function CorrelationAgent(input: z.infer<typeof correlationInput>): Promise<AgentResult<CorrelationExplanation>> {
  const { incidentId } = correlationInput.parse(input);
  const rec = new ToolCallRecorder();
  const related = await rec.run('get_related_findings', { incidentId }, () => tools.get_related_findings(incidentId));
  const output = correlationOutput.parse({
    correlated: related.findings.length > 0,
    reasons: related.correlations.map(c => c.reason),
    relatedVulnKeys: related.findings.map(f => f.vulnKey),
  });
  return { output, mode: 'deterministic', toolCalls: rec.calls };
}

// --- 5. AttackPathAgent (natural-language walkthrough of the graph) -----------------

const attackPathInput = z.object({ incidentId: z.string() });
const attackPathOutput = z.object({ narrative: z.string(), nodeCount: z.number(), edgeCount: z.number() });
export type AttackPathNarrative = z.infer<typeof attackPathOutput>;

export async function AttackPathAgent(input: z.infer<typeof attackPathInput>): Promise<AgentResult<AttackPathNarrative>> {
  const { incidentId } = attackPathInput.parse(input);
  const rec = new ToolCallRecorder();
  const path = await rec.run('get_attack_path', { incidentId }, () => tools.get_attack_path(incidentId));
  const nodeCount = path?.nodes.length ?? 0;
  const edgeCount = path?.edges.length ?? 0;
  const { data, mode } = await callStructured<{ summary: string; nodeCount: number }, { narrative: string }>(
    'You narrate a security attack graph for a non-technical reader, in 2-3 plain sentences, using ONLY the provided summary and node count. Return strict JSON: { "narrative": string }.',
    { summary: path?.summary ?? 'No attack path recorded yet.', nodeCount },
    ({ summary }) => ({ narrative: summary }),
  );
  const output = attackPathOutput.parse({ narrative: data.narrative, nodeCount, edgeCount });
  return { output, mode, toolCalls: rec.calls };
}

// --- 6. ThreatIntelAgent -------------------------------------------------------------

const threatIntelInput = z.object({ findingId: z.string() });
const threatIntelOutput = z.object({
  cwe: z.string().nullable(), owasp: z.string().nullable(), summary: z.string(),
  epssScore: z.number().nullable(), cisaKev: z.boolean(), relatedCves: z.array(z.object({ id: z.string(), summary: z.string() })),
});
export type ThreatIntelBrief = z.infer<typeof threatIntelOutput>;

export async function ThreatIntelAgent(input: z.infer<typeof threatIntelInput>): Promise<AgentResult<ThreatIntelBrief>> {
  const { findingId } = threatIntelInput.parse(input);
  const rec = new ToolCallRecorder();
  const finding = await rec.run('get_vulnerability', { findingId }, () => tools.get_vulnerability(findingId));
  if (!finding) throw new Error(`Finding ${findingId} not found`);
  const indicator = await rec.run('get_threat_intel', { cwe: finding.cwe }, () => tools.get_threat_intel(finding.cwe));
  const output = threatIntelOutput.parse({
    cwe: finding.cwe ?? null,
    owasp: finding.owasp ?? null,
    summary: indicator?.summary ?? 'No local threat intelligence entry for this CWE.',
    epssScore: indicator?.epssScore ?? null,
    cisaKev: indicator?.cisaKev ?? false,
    relatedCves: indicator?.relatedCves ?? [],
  });
  return { output, mode: 'deterministic', toolCalls: rec.calls };
}

// --- 7. RemediationAgent -------------------------------------------------------------

const remediationInput = z.object({ findingId: z.string() });

export async function RemediationAgent(input: z.infer<typeof remediationInput>): Promise<AgentResult<RemediationPlan>> {
  const { findingId } = remediationInput.parse(input);
  const rec = new ToolCallRecorder();
  const finding = await rec.run('get_vulnerability', { findingId }, () => tools.get_vulnerability(findingId));
  if (!finding) throw new Error(`Finding ${findingId} not found`);
  const { data, mode } = await rec.run('generate_remediation', { findingId }, () => tools.generate_remediation(finding));
  return { output: data, mode, toolCalls: rec.calls };
}

// --- 8. VerificationAgent ------------------------------------------------------------

const verificationInput = z.object({ findingId: z.string(), applicationBaseUrl: z.string(), actor: z.string() });
const verificationOutput = z.object({ passed: z.boolean(), before: z.unknown(), after: z.unknown() });
export type VerificationOutcome = z.infer<typeof verificationOutput>;

export async function VerificationAgent(input: z.infer<typeof verificationInput>): Promise<AgentResult<VerificationOutcome>> {
  const { findingId, applicationBaseUrl, actor } = verificationInput.parse(input);
  const rec = new ToolCallRecorder();
  const result = await rec.run('run_verification', { findingId }, () => tools.run_verification(findingId, applicationBaseUrl, actor));
  const output = verificationOutput.parse(result);
  return { output, mode: 'deterministic', toolCalls: rec.calls };
}

// --- 9. RedTeamAgent -------------------------------------------------------------------
// Builds an exploitation-chain NARRATIVE from the application's real, independently-verified
// findings — it does not re-execute anything or discover a new stateful chain live; the 14+
// scanner checks are independent HTTP probes, not literally wired to pass output into each other.
// What's real here: every vulnKey/evidence cited must come from an actual open finding (enforced
// by the prompt + offline fallback only ever referencing `findings`); what's narrated: the ORDER
// and the "an attacker would..." reasoning connecting them into a single escalating story.

const redTeamInput = z.object({ applicationId: z.string() });
const redTeamOutput = z.object({
  chainSteps: z.array(z.object({ vulnKey: z.string(), title: z.string(), role: z.string() })),
  narrative: z.string(),
  finalImpact: z.string(),
  confidence: z.number(),
});
export type RedTeamChain = z.infer<typeof redTeamOutput>;

function offlineRedTeamChain(findings: { vulnKey: string; title: string; severity: string; impact: string }[]): RedTeamChain {
  if (findings.length === 0) {
    return { chainSteps: [], narrative: 'No open findings to chain — nothing to report.', finalImpact: 'None.', confidence: 0 };
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...findings].sort((a, b) => (order[a.severity as keyof typeof order] ?? 4) - (order[b.severity as keyof typeof order] ?? 4));
  const chainSteps = sorted.slice(0, 4).map((f, i) => ({
    vulnKey: f.vulnKey, title: f.title,
    role: i === 0 ? 'Entry point — most severe confirmed weakness' : `Step ${i + 1} — compounds prior access`,
  }));
  const narrative = `An attacker could start with ${chainSteps[0].vulnKey} (${chainSteps[0].title}), then layer in ` +
    `${chainSteps.slice(1).map(c => c.vulnKey).join(', ') || 'no further findings'} to widen impact. This is a severity-ordered ` +
    `composition of real open findings, not a literally re-executed multi-step exploit.`;
  return { chainSteps, narrative, finalImpact: sorted[0].impact, confidence: 0.5 };
}

export async function RedTeamAgent(input: z.infer<typeof redTeamInput>): Promise<AgentResult<RedTeamChain>> {
  const { applicationId } = redTeamInput.parse(input);
  const rec = new ToolCallRecorder();
  const findings = await rec.run('get_vulnerabilities_for_app', { applicationId }, () => tools.get_vulnerabilities_for_app(applicationId));
  const findingSummaries = findings.map(f => ({ vulnKey: f.vulnKey, title: f.title, severity: f.severity, impact: f.impact, endpoint: f.endpoint }));

  const { data, mode } = await callStructured<
    { findings: typeof findingSummaries },
    RedTeamChain
  >(
    'You are a red-team lead composing an exploitation-chain narrative STRICTLY from the given real, already-confirmed findings ' +
    '(never invent a vulnKey not in the list). Pick 2-4 of them, order them as a real attacker would escalate impact, and explain ' +
    'in plain language how combining them compounds the damage. Return strict JSON: { "chainSteps": [{"vulnKey": string, "title": string, "role": string}], ' +
    '"narrative": string, "finalImpact": string, "confidence": number (0-1) }. If fewer than 2 findings are given, return whatever is possible honestly.',
    { findings: findingSummaries },
    i => offlineRedTeamChain(i.findings),
  );

  // Defense in depth: even if the model invents a vulnKey, strip it before returning —
  // the UI must never show a chain step that isn't a real finding on this application.
  const realKeys = new Set(findings.map(f => f.vulnKey));
  const output = redTeamOutput.parse({ ...data, chainSteps: data.chainSteps.filter(s => realKeys.has(s.vulnKey)) });
  return { output, mode, toolCalls: rec.calls };
}
