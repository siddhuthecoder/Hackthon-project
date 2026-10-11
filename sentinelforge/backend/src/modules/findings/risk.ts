import { Application, Endpoint, IVulnerability, Vulnerability } from '../../db/models';

export interface RiskBreakdown {
  severity: number;
  epss: number;
  kev: number;
  exposure: number;
}

export interface RiskScore {
  score: number;
  breakdown: RiskBreakdown;
  exposure: 'public' | 'authenticated';
}

const SEVERITY_POINTS: Record<string, number> = { critical: 40, high: 30, medium: 15, low: 5 };

/** Composite "fix this first" score — the same four signals a real posture-management tool
 * (Wiz/Orca-style) combines, instead of making an analyst mentally merge severity, EPSS, KEV and
 * exposure themselves. Transparent by design: the breakdown is returned alongside the total, not
 * hidden behind a black-box number. Max 100 (40 severity + 20 EPSS + 25 KEV + 15 exposure). */
export function computeRiskScore(finding: IVulnerability, endpointIsPublic: boolean): RiskScore {
  const severity = SEVERITY_POINTS[finding.severity] ?? 0;

  const threatIntel = (finding.evidence as { threatIntel?: { epssScore?: number; cisaKev?: boolean } })?.threatIntel;
  const epss = Math.round((threatIntel?.epssScore ?? 0) * 20);
  const kev = threatIntel?.cisaKev ? 25 : 0;
  const exposure = endpointIsPublic ? 15 : 0;

  return {
    score: severity + epss + kev + exposure,
    breakdown: { severity, epss, kev, exposure },
    exposure: endpointIsPublic ? 'public' : 'authenticated',
  };
}

export interface RankedFinding {
  id: string;
  vulnKey: string;
  title: string;
  severity: string;
  applicationId: string;
  applicationName: string;
  risk: RiskScore;
}

/** Shared by GET /api/findings/prioritized and the executive-summary PDF. */
export async function rankFindingsByRisk(org: string): Promise<RankedFinding[]> {
  const apps = await Application.find({ organizationId: org }).select('_id name');
  const appIds = apps.map(a => a.id);
  const appNames = new Map(apps.map(a => [a.id, a.name]));

  const findings = await Vulnerability.find({ applicationId: { $in: appIds }, status: { $in: ['OPEN', 'CONFIRMED'] } });
  const endpoints = await Endpoint.find({ applicationId: { $in: appIds } });
  const endpointAuth = new Map(endpoints.map(e => [`${e.applicationId}|${e.method}|${e.path}`, e.authRequired]));

  return findings
    .map(f => {
      const authRequired = endpointAuth.get(`${f.applicationId}|${f.method}|${f.endpoint}`);
      const isPublic = authRequired === false;
      return {
        id: f.id, vulnKey: f.vulnKey, title: f.title, severity: f.severity,
        applicationId: f.applicationId, applicationName: appNames.get(f.applicationId) ?? 'unknown',
        risk: computeRiskScore(f, isPublic),
      };
    })
    .sort((a, b) => b.risk.score - a.risk.score);
}
