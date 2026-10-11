/**
 * Makes the pipeline actually autonomous, not just AI-assisted-on-click. Per the master spec's
 * "AI design principles": detection stays a rule engine, investigation is AI, and the final
 * security action (applying a fix, verifying it, opening a PR) stays a human decision — this
 * module automates everything up to that line, not past it.
 *
 * Runs automatically right after an incident is created and correlated (detection/service.ts).
 * Best-effort throughout: any failure here is swallowed and logged, never thrown, so a flaky AI
 * call can't break the detection pipeline that triggered it — a human can always still click
 * "Investigate" or "Generate Remediation" manually if the autonomous pass didn't produce one.
 */
import { Correlation, Incident, RemediationTask, Vulnerability } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';
import { InvestigationAgent, RemediationAgent } from '../ai/agents';
import { runAgent } from '../ai/orchestrator';

export async function autoRespondToIncident(incidentId: string): Promise<void> {
  await autoInvestigate(incidentId).catch(err => {
    console.error(`[autonomy] auto-investigate failed for ${incidentId} (non-fatal, can still be run manually):`, err);
  });
  await autoProposeRemediation(incidentId).catch(err => {
    console.error(`[autonomy] auto-propose-remediation failed for ${incidentId} (non-fatal, can still be run manually):`, err);
  });
}

async function autoInvestigate(incidentId: string): Promise<void> {
  const { output, mode } = await runAgent('InvestigationAgent', 'incident', incidentId, { incidentId }, InvestigationAgent);
  const incident = await Incident.findById(incidentId);
  if (!incident) return;
  incident.set({
    investigation: { ...output, mode, generatedAt: new Date().toISOString(), triggeredBy: 'autonomous' },
    status: incident.status === 'OPEN' ? 'INVESTIGATING' : incident.status,
    updatedAt: new Date(),
  });
  await incident.save();
  publish('agent', { kind: 'autonomous_investigation', incidentId, mode });
  publish('incident', incident.toJSON());
}

async function autoProposeRemediation(incidentId: string): Promise<void> {
  const correlations = await Correlation.find({ incidentId });
  for (const correlation of correlations) {
    const finding = await Vulnerability.findById(correlation.findingId);
    if (!finding || finding.status !== 'OPEN') continue;

    const alreadyProposed = await RemediationTask.findOne({ findingId: finding.id, status: 'PROPOSED' });
    if (alreadyProposed) continue;

    const { output: plan, mode } = await runAgent('RemediationAgent', 'vulnerability', finding.id, { findingId: finding.id }, RemediationAgent);
    await RemediationTask.create({
      _id: newId('rem'),
      findingId: finding.id,
      status: 'PROPOSED',
      plan: { ...plan, mode, autonomous: true, incidentId },
    });
    publish('agent', { kind: 'autonomous_remediation_proposed', findingId: finding.id, mode });
    publish('finding', { findingId: finding.id, proposedRemediation: true });
  }
}
