import { IVulnerability } from '../../db/models';
import { callStructured } from './client';

export interface FindingExplanation {
  summary: string;
  facts: string[];
  inferences: string[];
  uncertainties: string[];
  impact: string;
  recommendations: string[];
  confidence: number;
}

const SYSTEM_PROMPT = `You are a security analyst explaining one finding from an authorized local security lab.
You are given the finding's facts and real evidence as JSON. Use ONLY that data.
Return strict JSON: { "summary": string, "facts": string[], "inferences": string[], "uncertainties": string[], "impact": string, "recommendations": string[], "confidence": number (0-1) }.
"facts" must be things directly supported by the evidence. "inferences" are reasonable conclusions beyond the raw evidence. "uncertainties" are things you cannot verify from the given data. Never invent evidence not present in the input.`;

interface FindingInput {
  vulnKey: string;
  title: string;
  type: string;
  severity: string;
  cwe?: string;
  owasp?: string;
  endpoint: string;
  method: string;
  description: string;
  impact: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

function offline(input: FindingInput): FindingExplanation {
  const facts = [
    `${input.vulnKey} is classified as ${input.type} (${input.cwe ?? 'no CWE recorded'}${input.owasp ? `, ${input.owasp}` : ''}).`,
    `Affected endpoint: ${input.method} ${input.endpoint}.`,
    input.description,
  ];
  if (input.evidence.summary) facts.push(String(input.evidence.summary));
  return {
    summary: `${input.title} (${input.severity.toUpperCase()}): ${input.description}`,
    facts,
    inferences: [`An attacker with any valid account on this application could likely repeat this request pattern to reproduce the same result.`],
    uncertainties: [`Whether this endpoint has been exploited outside of this scan is not established by the scan evidence alone — check the SOC/incidents view for live activity.`],
    impact: input.impact,
    recommendations: [input.remediation],
    confidence: 0.75,
  };
}

export async function explainFinding(finding: IVulnerability): Promise<{ data: FindingExplanation; mode: 'model' | 'offline' }> {
  const input: FindingInput = {
    vulnKey: finding.vulnKey, title: finding.title, type: finding.type, severity: finding.severity,
    cwe: finding.cwe, owasp: finding.owasp, endpoint: finding.endpoint, method: finding.method,
    description: finding.description, impact: finding.impact, remediation: finding.remediation,
    evidence: finding.evidence,
  };
  return callStructured(SYSTEM_PROMPT, input, offline);
}
