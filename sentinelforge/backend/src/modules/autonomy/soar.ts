/**
 * Autonomous SOAR playbook: when an incident correlates to a finding whose risk score crosses a
 * threshold, the system reacts on its own — real Jira ticket, a distinct Slack page, and a
 * block_ip response action PRE-STAGED for human approval. It never auto-executes the high-impact
 * step itself (that stays a one-click approval, same rule every other response action follows) —
 * only the paperwork (ticket, alert, staged action) is autonomous, not the destructive part.
 */
import { Correlation, Endpoint, IIncident, IResponseAction, ResponseAction, Vulnerability } from '../../db/models';
import { HydratedDocument } from 'mongoose';
import { newId } from '../../lib/util';
import { computeRiskScore } from '../findings/risk';
import { createJiraTicket, jiraConfigured } from '../integrations/jira';
import { notifyPlaybookTriggered } from '../notifications/webhook';

const RISK_THRESHOLD = 70;

export async function runSoarPlaybook(incident: HydratedDocument<IIncident>): Promise<void> {
  if (!incident.applicationId) return;

  const correlations = await Correlation.find({ incidentId: incident.id });
  if (correlations.length === 0) return;

  const findings = await Vulnerability.find({ _id: { $in: correlations.map(c => c.findingId) }, applicationId: incident.applicationId });

  let worstScore = 0;
  let worstFinding: (typeof findings)[number] | undefined;
  for (const finding of findings) {
    const endpoint = await Endpoint.findOne({ applicationId: finding.applicationId, method: finding.method, path: finding.endpoint });
    const risk = computeRiskScore(finding, endpoint?.authRequired === false);
    if (risk.score > worstScore) {
      worstScore = risk.score;
      worstFinding = finding;
    }
  }

  if (worstScore < RISK_THRESHOLD || !worstFinding) return;

  // Idempotent: a scan can re-correlate the same incident multiple times (see
  // modules/scanner/service.ts recorrelateOpenIncidents) — never double-fire the playbook.
  const alreadyRan = await ResponseAction.findOne({ incidentId: incident.id, requestedBy: 'system:soar-playbook' });
  if (alreadyRan) return;

  let ticketUrl: string | undefined;
  let ticketKey: string | undefined;
  if (jiraConfigured()) {
    try {
      const ticket = await createJiraTicket(
        `[AUTO] ${incident.title} — risk ${worstScore}/100`,
        `Autonomous SOAR playbook triggered.\nRisk score: ${worstScore}/100\nCorrelated finding: ${worstFinding.vulnKey} — ${worstFinding.title}\nSeverity: ${worstFinding.severity}\nSource IP: ${incident.sourceIp ?? 'unknown'}\n\nA block_ip response action has been staged pending human approval.`,
      );
      ticketUrl = ticket.url;
      ticketKey = ticket.key;
    } catch {
      // A ticketing outage must never block the rest of the playbook.
    }
  }

  let stagedAction: HydratedDocument<IResponseAction> | undefined;
  if (incident.sourceIp) {
    stagedAction = await ResponseAction.create({
      _id: newId('resp'),
      incidentId: incident.id,
      action: 'block_ip',
      target: incident.sourceIp,
      status: 'PENDING_APPROVAL',
      highImpact: true,
      details: {
        note: `Autonomously staged by the SOAR playbook (risk score ${worstScore}/100 ≥ ${RISK_THRESHOLD} threshold). Still requires human approval before executing.`,
        autonomous: true,
        riskScore: worstScore,
        triggeringVulnKey: worstFinding.vulnKey,
        ticketUrl,
        ticketKey,
      },
      requestedBy: 'system:soar-playbook',
    });
  }

  await notifyPlaybookTriggered(incident.title, worstFinding.vulnKey, worstScore, ticketUrl, Boolean(stagedAction));
}
