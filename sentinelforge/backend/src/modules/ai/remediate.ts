import { IVulnerability } from '../../db/models';
import { callStructured } from './client';

export interface RemediationPlan {
  rootCause: string;
  secureApproach: string;
  patchSummary: string;
  testsRequired: string[];
  verificationSteps: string[];
}

const SYSTEM_PROMPT = `You are a security engineer writing a remediation plan for one confirmed finding in an authorized local security lab.
You are given the finding, including the already-known secure endpoint the lab ships as its fix counterpart. Use ONLY that data.
Return strict JSON: { "rootCause": string, "secureApproach": string, "patchSummary": string, "testsRequired": string[], "verificationSteps": string[] }.
Never invent a different codebase or framework than what the input describes.`;

interface RemediateInput {
  vulnKey: string; title: string; type: string; endpoint: string; method: string; description: string; remediation: string;
}

function offline(input: RemediateInput): RemediationPlan {
  return {
    rootCause: input.description,
    secureApproach: input.remediation,
    patchSummary: `Apply the lab's existing secure implementation for ${input.endpoint} (already shipped alongside the vulnerable route) via SentinelForge's controlled fix toggle.`,
    testsRequired: [
      `Regression test: the legitimate owner/role can still call ${input.method} ${input.endpoint} successfully.`,
      `Security test: a different user/tenant/role is rejected with 403 on the same endpoint.`,
    ],
    verificationSteps: [`Re-run the original ${input.vulnKey} scanner check and confirm the outcome changes from VULNERABLE to NOT_VULNERABLE.`],
  };
}

export async function remediateFinding(finding: IVulnerability): Promise<{ data: RemediationPlan; mode: 'model' | 'offline' }> {
  const input: RemediateInput = {
    vulnKey: finding.vulnKey, title: finding.title, type: finding.type, endpoint: finding.endpoint,
    method: finding.method, description: finding.description, remediation: finding.remediation,
  };
  return callStructured(SYSTEM_PROMPT, input, offline);
}
