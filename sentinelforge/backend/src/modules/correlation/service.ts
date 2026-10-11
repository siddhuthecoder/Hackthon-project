import { Correlation, Incident, Vulnerability } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';

/**
 * Links an incident to the finding(s) its detection rule named as evidence (RuleMatch.findings in
 * detection/rules.ts). This is the core differentiator: a live attack pattern gets tied back to a
 * specific, previously-discovered vulnerability, with the evidence that justifies the link.
 */
export async function correlateIncident(incidentId: string): Promise<number> {
  const incident = await Incident.findById(incidentId);
  if (!incident) return 0;

  // Re-derive the finding keys from the rule, since Detection.evidence.findings carries them.
  const RULE_TO_VULN: Record<string, string[]> = {
    'RULE-001': ['VULN-009'],
    'RULE-002': ['VULN-009'],
    'RULE-003': ['VULN-001'],
    'RULE-004': ['VULN-002'],
    'RULE-005': ['VULN-011'],
  };
  const vulnKeys = RULE_TO_VULN[incident.rule] ?? [];
  if (vulnKeys.length === 0) return 0;

  // Scoped to the incident's own application — matching by vulnKey alone would link an incident to
  // another application's (or another org's) finding and leak it through the incident detail view.
  const findings = await Vulnerability.find({ vulnKey: { $in: vulnKeys }, applicationId: incident.applicationId });
  let created = 0;

  for (const finding of findings) {
    const exists = await Correlation.findOne({ findingId: finding.id, incidentId: incident.id });
    if (exists) continue;

    const evidence = {
      sameEndpoint: finding.endpoint,
      incidentSubject: incident.subject,
      incidentRule: incident.rule,
      findingVulnKey: finding.vulnKey,
      findingStatus: finding.status,
      incidentEventCount: incident.eventIds.length,
    };
    const reason = `Live activity matched detection rule ${incident.rule} against ${finding.endpoint}, the same endpoint where ${finding.vulnKey} (${finding.title}) was previously confirmed by the scanner. This is consistent with exploitation of ${finding.vulnKey}.`;

    const correlation = await Correlation.create({
      _id: newId('corr'),
      findingId: finding.id,
      incidentId: incident.id,
      evidence,
      confidence: Math.min(0.97, (incident.confidence + finding.confidence) / 2 + 0.1),
      reason,
    });
    created += 1;
    publish('incident', { correlation: correlation.toJSON() });
  }

  return created;
}

export async function correlateAllRecent(): Promise<number> {
  const incidents = await Incident.find({ detectedAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
  let total = 0;
  for (const incident of incidents) total += await correlateIncident(incident.id);
  return total;
}
