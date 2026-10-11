import { ThreatIndicator, Vulnerability } from '../../db/models';
import { newId } from '../../lib/util';
import { lookupThreatIndicator, ThreatIndicator as ThreatIndicatorShape } from './dataset';
import { checkLiveKev, fetchLiveEpss } from './liveFeeds';

/** Tries the real external feeds (EPSS, CISA KEV) for the indicator's first-listed CVE; falls
 * back to the local dataset's illustrative values on any failure/timeout. Never throws. */
async function enrichWithLiveFeeds(indicator: ThreatIndicatorShape): Promise<ThreatIndicatorShape & { liveDataFetched: boolean }> {
  const representativeCve = indicator.relatedCves[0]?.id;
  if (!representativeCve) return { ...indicator, liveDataFetched: false };

  const [epss, kev] = await Promise.all([fetchLiveEpss(representativeCve), checkLiveKev(representativeCve)]);
  const liveDataFetched = epss !== null || kev !== null;
  return {
    ...indicator,
    epssScore: epss?.score ?? indicator.epssScore,
    epssPercentile: epss?.percentile ?? indicator.epssPercentile,
    cisaKev: kev ?? indicator.cisaKev,
    liveDataFetched,
  };
}

/** Upserts the dataset (live-enriched where possible, local fallback otherwise) into the
 * `threat_indicators` collection and attaches the matching indicator to any finding that doesn't
 * have one yet, keyed by the finding's own CWE. Safe to call repeatedly (every scan) — it only
 * ever upserts, never duplicates. */
export async function syncThreatIntel(applicationId?: string): Promise<{ indicators: number; enrichedFindings: number }> {
  const filter = applicationId ? { applicationId } : {};
  const findings = await Vulnerability.find(filter);

  let indicators = 0;
  let enrichedFindings = 0;
  const seen = new Map<string, Awaited<ReturnType<typeof enrichWithLiveFeeds>>>();

  for (const finding of findings) {
    const base = lookupThreatIndicator(finding.cwe);
    if (!base) continue;

    let enriched = seen.get(base.cwe);
    if (!enriched) {
      enriched = await enrichWithLiveFeeds(base);
      seen.set(base.cwe, enriched);

      const existing = await ThreatIndicator.findOne({ kind: 'cwe', value: base.cwe });
      if (existing) {
        existing.set({ details: enriched });
        await existing.save();
      } else {
        await ThreatIndicator.create({ _id: newId('ti'), kind: 'cwe', value: base.cwe, details: enriched as unknown as Record<string, unknown> });
        indicators += 1;
      }
    }

    const currentDetails = finding.evidence as { threatIntel?: unknown };
    if (!currentDetails?.threatIntel) {
      finding.set({ evidence: { ...finding.evidence, threatIntel: enriched } });
      await finding.save();
      enrichedFindings += 1;
    }
  }

  return { indicators, enrichedFindings };
}
