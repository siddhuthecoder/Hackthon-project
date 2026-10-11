/**
 * Real SARIF 2.1.0 export (the standard format GitHub code scanning, VS Code's SARIF viewer, and
 * most CI security gates consume) — built from real Vulnerability records, nothing templated.
 */
import { IVulnerability } from '../../db/models';

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note',
};

export interface SarifLog {
  $schema: string;
  version: string;
  runs: unknown[];
}

export function buildSarifLog(findings: IVulnerability[]): SarifLog {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; fullDescription: { text: string }; help: { text: string }; properties: { tags: string[] } }>();
  for (const f of findings) {
    if (rules.has(f.vulnKey)) continue;
    rules.set(f.vulnKey, {
      id: f.vulnKey,
      name: f.type.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      help: { text: f.remediation },
      properties: { tags: [f.cwe, f.owasp].filter((t): t is string => Boolean(t)) },
    });
  }

  const results = findings.map(f => ({
    ruleId: f.vulnKey,
    level: SEVERITY_TO_SARIF_LEVEL[f.severity] ?? 'warning',
    message: { text: `${f.title}: ${f.description}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.endpoint || 'unknown' },
        region: { startLine: 1 },
      },
    }],
    properties: { status: f.status, confidence: f.confidence },
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'SentinelForge',
          informationUri: 'https://github.com/siddhuthecoder/Hackthon-project',
          version: '1.0.0',
          rules: [...rules.values()],
        },
      },
      results,
    }],
  };
}
