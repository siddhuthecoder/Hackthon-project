import { Detection, Incident, SecurityEvent } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';
import { autoRespondToIncident } from '../autonomy/loop';
import { SCANNER_SOURCE_IP } from '../cyberlab/adapter';
import { correlateIncident } from '../correlation/service';
import { buildAttackPath } from '../graph/service';
import { notifyIncidentCreated } from '../notifications/webhook';
import { runSoarPlaybook } from '../autonomy/soar';
import { RULES } from './rules';

const LOOKBACK_MS = 10 * 60 * 1000;
// Re-raising the same rule+subject while an incident is still open would spam the demo; this is
// a dedupe window, not a detection threshold.
const DEDUPE_MS = 5 * 60 * 1000;

export async function runDetection(applicationId: string): Promise<{ detections: number; incidents: number }> {
  const since = new Date(Date.now() - LOOKBACK_MS);
  // Exclude SentinelForge's own scanner/verification traffic (authorized AppSec testing) from
  // detection — only simulated-attacker traffic should trigger a SOC incident. See adapter.ts.
  const events = await SecurityEvent.find({ applicationId, timestamp: { $gte: since }, sourceIp: { $ne: SCANNER_SOURCE_IP } }).sort({ timestamp: 1 });

  let detectionsCreated = 0;
  let incidentsCreated = 0;

  for (const rule of RULES) {
    const matches = rule(events);
    for (const match of matches) {
      const recentDupe = await Detection.findOne({
        rule: match.rule,
        subject: match.subject,
        detectedAt: { $gte: new Date(Date.now() - DEDUPE_MS) },
      });
      if (recentDupe) continue;

      const detectionId = newId('det');
      const detection = await Detection.create({
        _id: detectionId,
        rule: match.rule,
        subject: match.subject,
        severity: match.severity,
        confidence: match.confidence,
        evidence: { findings: match.findings, mitre: match.mitre },
        eventIds: match.eventIds,
        detectedAt: new Date(),
      });
      detectionsCreated += 1;
      publish('detection', detection.toJSON());

      const incidentId = newId('inc');
      const incident = await Incident.create({
        _id: incidentId,
        applicationId,
        title: match.title,
        rule: match.rule,
        subject: match.subject,
        severity: match.severity,
        status: 'OPEN',
        detectedAt: new Date(),
        updatedAt: new Date(),
        sourceIp: match.sourceIp,
        users: match.users,
        assets: match.assets,
        eventIds: match.eventIds,
        confidence: match.confidence,
        mitre: match.mitre,
        recommendedActions: match.recommendedActions,
      });
      await Detection.findByIdAndUpdate(detectionId, { incidentId: incident.id });
      incidentsCreated += 1;
      publish('incident', incident.toJSON());

      // Correlate against known findings and build the attack graph immediately, so the demo
      // never needs a second action to see the "known vuln + live attack" story.
      await correlateIncident(incident.id);
      await buildAttackPath(incident.id);

      // Autonomous response: investigate and (if correlated) propose remediation without a human
      // click. Deliberately NOT awaited — an AI call can take 10-20s (free model), and this
      // function is on the hot path of the "run attack" button; the human sees the incident
      // immediately, and the investigation/proposed-fix populate moments later via SSE, which is
      // the honest shape of "autonomous" (runs on its own, doesn't block the person who triggered
      // the detection).
      void autoRespondToIncident(incident.id);
      void notifyIncidentCreated(incident);
      void runSoarPlaybook(incident);
    }
  }

  return { detections: detectionsCreated, incidents: incidentsCreated };
}
