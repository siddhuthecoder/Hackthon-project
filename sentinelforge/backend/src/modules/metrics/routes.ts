/**
 * Real, computed security-posture metrics — no invented numbers. MTTR is the actual elapsed time
 * between a finding's detection and its real verification pass, averaged over findings that have
 * genuinely been verified; the scan-history trend is the real `findingsOpen` count stored on each
 * past `ScanRun`.
 */
import { FastifyInstance } from 'fastify';
import { Application, ScanRun, VerificationRun, Vulnerability } from '../../db/models';
import { authenticate } from '../../plugins/auth';

export interface PostureMetrics {
  scanHistory: { startedAt: string; findingsOpen: number; checksTotal: number }[];
  avgTimeToFixHours: number | null;
  findingsVerified: number;
  severityCounts: Record<string, number>;
}

/** Shared by GET /api/metrics/posture, the executive-summary PDF, and the multi-target
 * comparison view — one computation over an arbitrary set of application ids. */
export async function computePostureMetricsForApps(appIds: string[]): Promise<PostureMetrics> {
  const scanRuns = await ScanRun.find({ applicationId: { $in: appIds }, status: 'COMPLETED' }).sort({ startedAt: 1 });
  const scanHistory = scanRuns.map(s => ({
    startedAt: s.startedAt.toISOString(),
    findingsOpen: s.findingsOpen,
    checksTotal: s.checksTotal,
  }));

  const verifiedFindings = await Vulnerability.find({ applicationId: { $in: appIds }, status: 'VERIFIED' });
  let totalHours = 0;
  let withVerification = 0;
  for (const finding of verifiedFindings) {
    const run = await VerificationRun.findOne({ findingId: finding.id, passed: true }).sort({ createdAt: -1 });
    if (!run) continue;
    const hours = (run.createdAt.getTime() - finding.detectedAt.getTime()) / (1000 * 60 * 60);
    if (hours >= 0) {
      totalHours += hours;
      withVerification += 1;
    }
  }
  const avgTimeToFixHours = withVerification > 0 ? totalHours / withVerification : null;

  const bySeverity = await Vulnerability.aggregate([
    { $match: { applicationId: { $in: appIds } } },
    { $group: { _id: '$severity', count: { $sum: 1 } } },
  ]);
  const severityCounts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const row of bySeverity) severityCounts[row._id] = row.count;

  return { scanHistory, avgTimeToFixHours, findingsVerified: withVerification, severityCounts };
}

export async function metricsRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/metrics/posture', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    reply.send(await computePostureMetricsForApps(apps.map(a => a.id)));
  });
}
