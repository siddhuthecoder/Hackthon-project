import { HydratedDocument } from 'mongoose';
import { Application, IIncident, IVulnerability, Incident, Vulnerability } from '../db/models';

/**
 * Org-ownership guards for every single-resource lookup. Findings/incidents only carry
 * applicationId, not organizationId directly, so "does this belong to the caller's org" means
 * "does its applicationId resolve to an Application owned by that org" — the same indirection
 * modules/verification/routes.ts already used correctly; this just makes it a shared, consistently
 * applied helper instead of three copies and several routes that skipped it entirely. Returns null
 * (not 403) on a cross-org mismatch so routes can 404 — never confirm the resource exists at all.
 */

async function applicationOwnedByOrg(applicationId: string | undefined, org: string): Promise<boolean> {
  if (!applicationId) return false;
  const application = await Application.findOne({ _id: applicationId, organizationId: org }).select('_id');
  return Boolean(application);
}

export async function getOwnedFinding(id: string, org: string): Promise<HydratedDocument<IVulnerability> | null> {
  const finding = await Vulnerability.findById(id);
  if (!finding) return null;
  if (!(await applicationOwnedByOrg(finding.applicationId, org))) return null;
  return finding;
}

export async function getOwnedIncident(id: string, org: string): Promise<HydratedDocument<IIncident> | null> {
  const incident = await Incident.findById(id);
  if (!incident) return null;
  if (!(await applicationOwnedByOrg(incident.applicationId, org))) return null;
  return incident;
}
