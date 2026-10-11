/**
 * Real external threat intel feeds — no API key needed for either. Per the master spec: "Use
 * external sources only where practical and available... never make the entire application
 * dependent on external APIs for the core demo." Both calls here have a short timeout and the
 * caller (service.ts) falls back to the local dataset (dataset.ts) on any failure — a live demo
 * never breaks because an external feed is slow or down.
 */

const FETCH_TIMEOUT_MS = 4000;

async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

/** Real EPSS score (first.org, public, no key) for one CVE. */
export async function fetchLiveEpss(cveId: string): Promise<{ score: number; percentile: number } | null> {
  try {
    const res = await fetchWithTimeout(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`);
    if (!res.ok) return null;
    const body = await res.json() as { data?: { epss?: string; percentile?: string }[] };
    const entry = body.data?.[0];
    if (!entry?.epss) return null;
    return { score: Number(entry.epss), percentile: Number(entry.percentile) };
  } catch {
    return null;
  }
}

let kevCache: { ids: Set<string>; fetchedAt: number } | null = null;
const KEV_CACHE_TTL_MS = 60 * 60 * 1000;

/** Real CISA Known Exploited Vulnerabilities catalog (public JSON, no key). Cached in-process
 * for an hour since it's a ~1.7MB download and the catalog doesn't change minute to minute. */
async function getKevCatalog(): Promise<Set<string> | null> {
  if (kevCache && Date.now() - kevCache.fetchedAt < KEV_CACHE_TTL_MS) return kevCache.ids;
  try {
    const res = await fetchWithTimeout('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (!res.ok) return null;
    const body = await res.json() as { vulnerabilities?: { cveID: string }[] };
    const ids = new Set((body.vulnerabilities ?? []).map(v => v.cveID));
    kevCache = { ids, fetchedAt: Date.now() };
    return ids;
  } catch {
    return null;
  }
}

export async function checkLiveKev(cveId: string): Promise<boolean | null> {
  const ids = await getKevCatalog();
  if (!ids) return null;
  return ids.has(cveId);
}
