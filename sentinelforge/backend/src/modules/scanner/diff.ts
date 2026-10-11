import { IScanRunDiff, ScanResult, ScanRun } from '../../db/models';
import { CheckResult } from './checks';

/**
 * Classifies this scan's vulnKeys against the application's previous completed scan, plus a
 * "regressed" category: a vulnKey that was VERIFIED (fixed and confirmed fixed) before this scan
 * ran, reappearing as vulnerable again. `previouslyVerifiedKeys` must be captured BEFORE
 * persistResults() runs — persisting a re-confirmed finding flips its status back to OPEN
 * immediately, which would erase the "it used to be verified" signal if read afterward.
 */
export async function computeScanDiff(
  applicationId: string,
  scanRunId: string,
  results: CheckResult[],
  previouslyVerifiedKeys: Set<string>,
): Promise<IScanRunDiff> {
  const currentVulnerable = new Set(results.filter(r => r.outcome === 'VULNERABLE').map(r => r.vulnKey));

  const previousRun = await ScanRun.findOne({ applicationId, status: 'COMPLETED', _id: { $ne: scanRunId } }).sort({ startedAt: -1 });
  const previousVulnerable = previousRun
    ? new Set((await ScanResult.find({ scanRunId: previousRun.id, outcome: 'VULNERABLE' })).map(r => r.vulnKey))
    : new Set<string>();

  const newKeys: string[] = [];
  const recurring: string[] = [];
  const regressed: string[] = [];
  for (const key of currentVulnerable) {
    if (previouslyVerifiedKeys.has(key)) regressed.push(key);
    else if (previousVulnerable.has(key)) recurring.push(key);
    else newKeys.push(key);
  }
  const resolved = [...previousVulnerable].filter(k => !currentVulnerable.has(k));

  return { new: newKeys, resolved, recurring, regressed };
}
