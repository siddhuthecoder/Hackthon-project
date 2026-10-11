/**
 * The "Security Digital Twin" — a single standing graph of the whole org's security posture:
 * every application, its real open findings, and any incident currently correlated to them. This
 * is different from the per-incident attack graph (modules/graph/service.ts), which only exists
 * once an incident has fired; this view exists continuously, built fresh from current DB state
 * on every request — not a stored/cached snapshot that could drift from reality.
 */
import { FastifyInstance } from 'fastify';
import { Application, Correlation, Incident, Vulnerability } from '../../db/models';
import { authenticate } from '../../plugins/auth';

interface TwinNode {
  id: string;
  type: 'org' | 'application' | 'vulnerability' | 'incident';
  label: string;
  metadata: Record<string, unknown>;
}
interface TwinEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}

export async function digitalTwinRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/digital-twin', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org });
    const appIds = apps.map(a => a.id);

    const findings = await Vulnerability.find({ applicationId: { $in: appIds }, status: { $in: ['OPEN', 'CONFIRMED'] } });
    const incidents = await Incident.find({ applicationId: { $in: appIds }, status: { $nin: ['RESOLVED', 'FALSE_POSITIVE'] } });
    const correlations = await Correlation.find({ findingId: { $in: findings.map(f => f.id) } });

    const nodes: TwinNode[] = [];
    const edges: TwinEdge[] = [];

    const orgNode = 'org-root';
    nodes.push({ id: orgNode, type: 'org', label: 'Organization', metadata: { applicationCount: apps.length } });

    for (const a of apps) {
      const appNode = `app-${a.id}`;
      nodes.push({ id: appNode, type: 'application', label: a.name, metadata: { adapter: a.adapter, baseUrl: a.baseUrl, status: a.status } });
      edges.push({ id: `e-${orgNode}-${appNode}`, source: orgNode, target: appNode, type: 'OWNS' });
    }

    for (const f of findings) {
      const vulnNode = `vuln-${f.id}`;
      const appNode = `app-${f.applicationId}`;
      nodes.push({ id: vulnNode, type: 'vulnerability', label: `${f.vulnKey}: ${f.title}`, metadata: { severity: f.severity, cwe: f.cwe, owasp: f.owasp, endpoint: f.endpoint } });
      edges.push({ id: `e-${appNode}-${vulnNode}`, source: appNode, target: vulnNode, type: 'HAS_FINDING' });
    }

    for (const i of incidents) {
      const incNode = `inc-${i.id}`;
      nodes.push({ id: incNode, type: 'incident', label: i.title, metadata: { severity: i.severity, status: i.status, detectedAt: i.detectedAt } });
      const relatedCorrelations = correlations.filter(c => c.incidentId === i.id);
      if (relatedCorrelations.length > 0) {
        for (const c of relatedCorrelations) {
          edges.push({ id: `e-vuln-${c.findingId}-${incNode}`, source: `vuln-${c.findingId}`, target: incNode, type: 'BEING_EXPLOITED_BY' });
        }
      } else if (i.applicationId) {
        edges.push({ id: `e-app-${i.applicationId}-${incNode}`, source: `app-${i.applicationId}`, target: incNode, type: 'AFFECTS' });
      }
    }

    reply.send({
      nodes, edges,
      summary: `${apps.length} application(s), ${findings.length} open finding(s), ${incidents.length} active incident(s) — ${correlations.length} finding(s) currently correlated to live attacks.`,
    });
  });
}
