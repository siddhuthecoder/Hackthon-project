/**
 * The explicit, named tools every AI agent is restricted to. Per the master spec: "AI must not
 * invent database information" — every one of these is a thin, real query against SentinelForge's
 * own database (or, for the two "run_*" tools, a real action against CyberLab). An agent never
 * sees raw DB access; it only ever gets what comes back from calling one of these by name, and
 * every call is recorded (see `agents.ts: ToolCallRecorder`) so an `AgentRun` document shows
 * exactly what data an agent's answer was built from.
 *
 * These return live Mongoose documents, not pre-serialized JSON — agents pass them straight into
 * the existing explain/investigate/remediate functions, which expect real field types (Date
 * objects, not ISO strings). Routes that expose a tool's result over HTTP call `.toJSON()`
 * themselves at the response boundary.
 */
import {
  Application, Asset, AttackPath, AuditLog, Correlation, Endpoint, Incident, SecurityEvent, Vulnerability,
} from '../../db/models';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { buildAttackPath } from '../graph/service';
import { runScan } from '../scanner/service';
import { lookupThreatIndicator } from '../threatintel/dataset';
import { verifyFix } from '../verification/service';
import { remediateFinding } from './remediate';

export async function get_application(applicationId: string) {
  return Application.findById(applicationId);
}

export async function get_asset(applicationId: string) {
  return Asset.find({ applicationId });
}

export async function get_endpoint(applicationId: string) {
  return Endpoint.find({ applicationId });
}

export async function get_vulnerability(findingId: string) {
  return Vulnerability.findById(findingId);
}

/** Every currently-open/confirmed real finding for an application — used by RedTeamAgent to build
 * an exploitation-chain narrative strictly from findings the scanner has actually verified, never
 * an invented vulnerability. */
export async function get_vulnerabilities_for_app(applicationId: string) {
  return Vulnerability.find({ applicationId, status: { $in: ['OPEN', 'CONFIRMED'] } });
}

export async function get_security_events(incidentId: string) {
  const incident = await Incident.findById(incidentId);
  if (!incident) return [];
  return SecurityEvent.find({ _id: { $in: incident.eventIds } }).sort({ timestamp: 1 });
}

/** CyberLab users are identified by a plain id string (e.g. "user-101"); SentinelForge doesn't
 * mirror CyberLab's own user table, so this returns the id/context already captured on the
 * incident or event rather than inventing a profile lookup SentinelForge has no data for. */
export function get_user(userId: string) {
  return { id: userId, source: 'cyberlab', note: 'SentinelForge does not mirror CyberLab user records; only the id captured in events/incidents is available.' };
}

export async function get_incident(incidentId: string) {
  return Incident.findById(incidentId);
}

export async function get_related_findings(incidentId: string) {
  const correlations = await Correlation.find({ incidentId });
  if (correlations.length === 0) return { findings: [], correlations: [] };
  const findings = await Vulnerability.find({ _id: { $in: correlations.map(c => c.findingId) } });
  return { findings, correlations };
}

export async function get_attack_path(incidentId: string) {
  // Ensure it exists (idempotent — buildAttackPath upserts) before reading it back, so this tool
  // always returns real current data even if called before the detection pipeline's own build.
  await buildAttackPath(incidentId);
  return AttackPath.findOne({ incidentId });
}

export async function query_audit_logs(targetId: string, limit = 50) {
  return AuditLog.find({ targetId }).sort({ timestamp: -1 }).limit(limit);
}

export function get_threat_intel(cwe: string | undefined) {
  return lookupThreatIndicator(cwe);
}

/** Runs a real, authorized attack simulation against CyberLab — never anything else. */
export async function run_authorized_security_test(applicationBaseUrl: string, scenarioId: string) {
  const lab = new CyberLabAdapter(applicationBaseUrl);
  return lab.runSecurityTest(scenarioId);
}

/** Runs a real scan — the actual 14 HTTP exploit checks — never a canned result. Available to any
 * agent that needs fresh scan data rather than relying on the last stored scan. */
export async function run_security_scan(applicationId: string, applicationBaseUrl: string, triggeredBy: string) {
  const lab = new CyberLabAdapter(applicationBaseUrl);
  return runScan(applicationId, lab, triggeredBy);
}

/** Generates the AI remediation plan for a finding — a named tool so RemediationAgent's call to
 * it shows up in the recorded tool-call trail like every other agent action. */
export async function generate_remediation(finding: Awaited<ReturnType<typeof get_vulnerability>>) {
  if (!finding) throw new Error('generate_remediation requires a finding');
  return remediateFinding(finding);
}

/** Re-runs the real, original check for a finding and reports pass/fail from the live response. */
export async function run_verification(findingId: string, applicationBaseUrl: string, actor: string) {
  const finding = await Vulnerability.findById(findingId);
  if (!finding) throw new Error(`Unknown finding ${findingId}`);
  const lab = new CyberLabAdapter(applicationBaseUrl);
  return verifyFix(finding, lab, actor);
}
