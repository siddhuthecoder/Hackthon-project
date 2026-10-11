import { ICorrelation, IIncident, ISecurityEvent, IVulnerability } from '../../db/models';
import { callStructured } from './client';

export interface Investigation {
  summary: string;
  facts: string[];
  timeline: { at: string; what: string }[];
  relatedVulnerabilities: string[];
  attackPath: string;
  impact: string;
  inferences: string[];
  uncertainties: string[];
  recommendedActions: string[];
  confidence: number;
}

const SYSTEM_PROMPT = `You are a SOC analyst investigating one incident in an authorized local security lab.
You are given the incident, its real security events, and any correlated known vulnerability as JSON. Use ONLY that data.
Return strict JSON: { "summary": string, "facts": string[], "timeline": [{"at": string, "what": string}], "relatedVulnerabilities": string[], "attackPath": string, "impact": string, "inferences": string[], "uncertainties": string[], "recommendedActions": string[], "confidence": number (0-1) }.
Distinguish directly-observed facts from inferences. List at least one genuine uncertainty (e.g. whether credentials were compromised before this activity) unless the evidence truly rules it out. Never invent an event, user, or vulnerability not present in the input.`;

interface InvestigateInput {
  incident: { title: string; rule: string; subject: string; severity: string; confidence: number; users: string[]; assets: string[]; sourceIp?: string; mitre?: string };
  events: { timestamp: string; eventType: string; endpoint?: string; metadata: Record<string, unknown> }[];
  correlatedFindings: { vulnKey: string; title: string; endpoint: string; description: string }[];
}

function offline(input: InvestigateInput): Investigation {
  const timeline = input.events.map(e => ({ at: e.timestamp, what: `${e.eventType}${e.endpoint ? ` on ${e.endpoint}` : ''}` }));
  const facts = [
    `${input.incident.users[0] ?? input.incident.subject} triggered detection rule ${input.incident.rule} ("${input.incident.title}").`,
    `${input.events.length} security events are linked as evidence, from ${input.events[0]?.timestamp ?? 'unknown'} to ${input.events[input.events.length - 1]?.timestamp ?? 'unknown'}.`,
  ];
  const related = input.correlatedFindings.map(f => f.vulnKey);
  if (input.correlatedFindings.length > 0) {
    facts.push(`The affected endpoint matches a previously confirmed finding: ${input.correlatedFindings.map(f => `${f.vulnKey} (${f.title})`).join(', ')}.`);
  }
  const attackPath = input.correlatedFindings.length
    ? `${input.incident.sourceIp ?? 'unknown IP'} -> ${input.incident.users[0] ?? input.incident.subject} -> ${input.incident.assets[0] ?? 'endpoint'} -> ${input.correlatedFindings[0].vulnKey}`
    : `${input.incident.sourceIp ?? 'unknown IP'} -> ${input.incident.users[0] ?? input.incident.subject} -> ${input.incident.assets[0] ?? 'endpoint'}`;

  return {
    summary: input.correlatedFindings.length
      ? `This activity is consistent with exploitation of ${related.join(', ')}.`
      : `${input.incident.title}: pattern matched by rule ${input.incident.rule}; no known vulnerability has been correlated yet.`,
    facts,
    timeline,
    relatedVulnerabilities: related,
    attackPath,
    impact: input.correlatedFindings.length
      ? `If exploited at scale, this could expose data reachable via ${input.correlatedFindings[0].endpoint} beyond what ${input.incident.subject} is authorized to access.`
      : `Severity ${input.incident.severity} activity against ${input.incident.assets[0] ?? 'the affected endpoint'}; scope of impact depends on what that endpoint exposes.`,
    inferences: [`The repeated/rapid pattern captured in these events is unlikely to be normal user behavior.`],
    uncertainties: [`Whether the account itself was compromised beforehand is not established by these events alone.`],
    recommendedActions: ['Revoke the active session for the affected user', 'Review the correlated finding\'s remediation', 'Re-run verification after applying any fix'],
    confidence: input.incident.confidence,
  };
}

export async function investigateIncident(
  incident: IIncident,
  events: ISecurityEvent[],
  correlations: ICorrelation[],
  findings: IVulnerability[],
): Promise<{ data: Investigation; mode: 'model' | 'offline' }> {
  const input: InvestigateInput = {
    incident: {
      title: incident.title, rule: incident.rule, subject: incident.subject, severity: incident.severity,
      confidence: incident.confidence, users: incident.users, assets: incident.assets, sourceIp: incident.sourceIp, mitre: incident.mitre,
    },
    events: events.map(e => ({ timestamp: e.timestamp.toISOString(), eventType: e.eventType, endpoint: e.endpoint, metadata: e.metadata })),
    correlatedFindings: findings.map(f => ({ vulnKey: f.vulnKey, title: f.title, endpoint: f.endpoint, description: f.description })),
  };
  void correlations;
  return callStructured(SYSTEM_PROMPT, input, offline);
}
