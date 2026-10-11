import { FastifyInstance } from 'fastify';
import { Application, Correlation, Organization, SecurityEvent, Vulnerability } from '../../db/models';
import { getOwnedFinding, getOwnedIncident } from '../../lib/orgScope';
import { rankFindingsByRisk } from '../findings/risk';
import { computePostureMetricsForApps } from '../metrics/routes';
import { authenticate } from '../../plugins/auth';
import { buildExecutiveSummaryPdf, buildFindingReportPdf, buildIncidentReportPdf } from './pdf';
import { buildSarifLog } from './sarif';

export async function reportRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/reports/findings.sarif', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const findings = await Vulnerability.find({ applicationId: { $in: apps.map(a => a.id) } });
    const sarif = buildSarifLog(findings);
    reply.header('Content-Type', 'application/sarif+json');
    reply.header('Content-Disposition', 'attachment; filename="sentinelforge-findings.sarif"');
    reply.send(sarif);
  });

  app.get('/api/reports/findings.json', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const findings = await Vulnerability.find({ applicationId: { $in: apps.map(a => a.id) } });
    reply.header('Content-Disposition', 'attachment; filename="sentinelforge-findings.json"');
    reply.send(findings.map(f => f.toJSON()));
  });

  app.get('/api/reports/executive-summary.pdf', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const [metrics, topRisks, org] = await Promise.all([
      computePostureMetricsForApps(apps.map(a => a.id)),
      rankFindingsByRisk(request.user.org),
      Organization.findById(request.user.org),
    ]);
    const pdf = await buildExecutiveSummaryPdf({
      organizationName: org?.name ?? 'Organization',
      severityCounts: metrics.severityCounts,
      avgTimeToFixHours: metrics.avgTimeToFixHours,
      findingsVerified: metrics.findingsVerified,
      scanHistoryCount: metrics.scanHistory.length,
      topRisks,
    });
    reply.header('Content-Type', 'application/pdf');
    reply.header('Content-Disposition', 'attachment; filename="executive-summary.pdf"');
    reply.send(pdf);
  });

  app.get<{ Params: { id: string } }>('/api/findings/:id/report.pdf', { preHandler: authenticate('read') }, async (request, reply) => {
    const finding = await getOwnedFinding(request.params.id, request.user.org);
    if (!finding) {
      reply.code(404).send({ error: 'Finding not found' });
      return;
    }
    const pdf = await buildFindingReportPdf(finding);
    reply.header('Content-Type', 'application/pdf');
    reply.header('Content-Disposition', `attachment; filename="${finding.vulnKey}-report.pdf"`);
    reply.send(pdf);
  });

  app.get<{ Params: { id: string } }>('/api/incidents/:id/report.pdf', { preHandler: authenticate('read') }, async (request, reply) => {
    const incident = await getOwnedIncident(request.params.id, request.user.org);
    if (!incident) {
      reply.code(404).send({ error: 'Incident not found' });
      return;
    }
    const events = await SecurityEvent.find({ _id: { $in: incident.eventIds } }).sort({ timestamp: 1 });
    const correlations = await Correlation.find({ incidentId: incident.id });
    const findings = correlations.length ? await Vulnerability.find({ _id: { $in: correlations.map(c => c.findingId) } }) : [];
    const pdf = await buildIncidentReportPdf(incident, events, correlations, findings);
    reply.header('Content-Type', 'application/pdf');
    reply.header('Content-Disposition', `attachment; filename="incident-${incident.id}-report.pdf"`);
    reply.send(pdf);
  });
}
