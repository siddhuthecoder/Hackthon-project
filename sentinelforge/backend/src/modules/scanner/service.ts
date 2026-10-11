import { Endpoint, IScanRunDiff, Incident, ScanResult, ScanRun, Vulnerability } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';
import { runSoarPlaybook } from '../autonomy/soar';
import { correlateIncident } from '../correlation/service';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { buildAttackPath } from '../graph/service';
import { notifyRegressionDetected } from '../notifications/webhook';
import { GenericAdapter } from '../targets/generic/adapter';
import { runGenericChecks } from '../targets/generic/checks';
import { JuiceShopAdapter } from '../targets/juiceshop/adapter';
import { runJuiceShopChecks } from '../targets/juiceshop/checks';
import { syncThreatIntel } from '../threatintel/service';
import { CheckResult, runAllChecks } from './checks';
import { computeScanDiff } from './diff';

/** vulnKeys currently VERIFIED for this application, captured BEFORE persisting this scan's
 * results — persisting flips a re-confirmed finding's status back to OPEN immediately, which
 * would erase the "this used to be verified" signal computeScanDiff needs for regression
 * detection if read afterward instead. */
async function snapshotVerifiedKeys(applicationId: string): Promise<Set<string>> {
  const verified = await Vulnerability.find({ applicationId, status: 'VERIFIED' }).select('vulnKey');
  return new Set(verified.map(v => v.vulnKey));
}

async function persistResults(applicationId: string, scanRunId: string, results: CheckResult[]): Promise<void> {
  for (const result of results) {
    await ScanResult.create({
      _id: newId('scanres'),
      scanRunId,
      vulnKey: result.vulnKey,
      outcome: result.outcome,
      request: result.request,
      response: result.response,
      summary: result.summary,
    });

    if (result.outcome !== 'VULNERABLE') continue;

    const existing = await Vulnerability.findOne({ applicationId, vulnKey: result.vulnKey });
    const payload = {
      title: result.title,
      type: result.type,
      severity: result.severity,
      confidence: 0.95,
      cwe: result.cwe,
      owasp: result.owasp,
      endpoint: result.endpoint,
      method: result.method,
      evidence: { request: result.request, response: result.response, summary: result.summary },
      description: result.description,
      impact: result.impact,
      remediation: result.remediation,
      updatedAt: new Date(),
      scanRunId,
    };
    if (existing) {
      // Re-confirming an existing finding on rescan; only move it back to OPEN if it had been
      // marked fixed/verified and the vulnerability is actually present again.
      const nextStatus = existing.status === 'FALSE_POSITIVE' ? 'FALSE_POSITIVE' : 'OPEN';
      existing.set({ ...payload, status: nextStatus });
      await existing.save();
    } else {
      await Vulnerability.create({ _id: newId('vuln'), applicationId, vulnKey: result.vulnKey, status: 'OPEN', detectedAt: new Date(), ...payload });
    }
  }
}

/** An attack can be detected before the vulnerability it exploits has been scanned for. Correlation
 * otherwise only runs at incident creation, so such an incident would stay unlinked forever; this
 * links any still-open incident to findings the scan just confirmed. Both calls are idempotent. */
async function recorrelateOpenIncidents(applicationId: string): Promise<void> {
  const open = await Incident.find({ applicationId, status: { $nin: ['RESOLVED', 'FALSE_POSITIVE'] } });
  for (const incident of open) {
    if ((await correlateIncident(incident.id)) > 0) {
      await buildAttackPath(incident.id);
      void runSoarPlaybook(incident);
    }
  }
}

async function finishScan(applicationId: string, applicationName: string, scanRunId: string, results: CheckResult[], diff: IScanRunDiff): Promise<void> {
  const findingsOpen = await Vulnerability.countDocuments({ applicationId, status: { $in: ['OPEN', 'CONFIRMED'] } });
  await ScanRun.findByIdAndUpdate(scanRunId, { status: 'COMPLETED', finishedAt: new Date(), checksTotal: results.length, findingsOpen, diff });
  await syncThreatIntel(applicationId);
  await recorrelateOpenIncidents(applicationId);
  publish('scan', { scanRunId, applicationId, status: 'COMPLETED', findingsOpen, checksTotal: results.length, diff });
  if (diff.regressed.length > 0) void notifyRegressionDetected(applicationName, diff.regressed);
}

export async function runScan(applicationId: string, lab: CyberLabAdapter, triggeredBy: string, applicationName = 'application'): Promise<{ scanRunId: string; results: CheckResult[]; diff: IScanRunDiff }> {
  const scanRunId = newId('scan');
  await ScanRun.create({ _id: scanRunId, applicationId, status: 'RUNNING', startedAt: new Date(), triggeredBy });
  publish('scan', { scanRunId, applicationId, status: 'RUNNING' });

  const previouslyVerified = await snapshotVerifiedKeys(applicationId);
  const results = await runAllChecks(lab);
  await persistResults(applicationId, scanRunId, results);
  const diff = await computeScanDiff(applicationId, scanRunId, results, previouslyVerified);
  await finishScan(applicationId, applicationName, scanRunId, results, diff);

  return { scanRunId, results, diff };
}

/** Same pipeline as runScan, against the second target adapter (Juice Shop) — proves the
 * scan→persist→threat-intel→publish flow isn't CyberLab-specific. See docs/SECOND-TARGET.md. */
export async function runJuiceShopScan(applicationId: string, js: JuiceShopAdapter, triggeredBy: string, applicationName = 'application'): Promise<{ scanRunId: string; results: CheckResult[]; diff: IScanRunDiff }> {
  const scanRunId = newId('scan');
  await ScanRun.create({ _id: scanRunId, applicationId, status: 'RUNNING', startedAt: new Date(), triggeredBy });
  publish('scan', { scanRunId, applicationId, status: 'RUNNING' });

  const previouslyVerified = await snapshotVerifiedKeys(applicationId);
  const results = await runJuiceShopChecks(js);
  await persistResults(applicationId, scanRunId, results);
  const diff = await computeScanDiff(applicationId, scanRunId, results, previouslyVerified);
  await finishScan(applicationId, applicationName, scanRunId, results, diff);

  return { scanRunId, results, diff };
}

/** Same pipeline against a config-driven generic target (no purpose-built adapter needed) — see
 * modules/targets/generic. Endpoints come from the DB (populated at discover time from the
 * application's OpenAPI spec), not re-fetched from the spec on every scan. */
export async function runGenericScan(applicationId: string, adapter: GenericAdapter, triggeredBy: string, applicationName = 'application'): Promise<{ scanRunId: string; results: CheckResult[]; diff: IScanRunDiff }> {
  const scanRunId = newId('scan');
  await ScanRun.create({ _id: scanRunId, applicationId, status: 'RUNNING', startedAt: new Date(), triggeredBy });
  publish('scan', { scanRunId, applicationId, status: 'RUNNING' });

  const endpoints = await Endpoint.find({ applicationId });
  const previouslyVerified = await snapshotVerifiedKeys(applicationId);
  const results = await runGenericChecks(adapter, endpoints.map(e => ({ method: e.method, path: e.path, authRequired: e.authRequired })));
  await persistResults(applicationId, scanRunId, results);
  const diff = await computeScanDiff(applicationId, scanRunId, results, previouslyVerified);
  await finishScan(applicationId, applicationName, scanRunId, results, diff);

  return { scanRunId, results, diff };
}
