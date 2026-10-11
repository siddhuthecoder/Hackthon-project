/**
 * Real dependency/SCA scanning via the OSV API (osv.dev — Google-run, free, no key, covers npm/
 * PyPI/Go/etc from GitHub Security Advisories + more). Reads CyberLab's actual package-lock.json
 * (bind-mounted read-only, same pattern as the Semgrep source mount) and queries OSV's batch
 * endpoint with every real resolved package+version — never a hand-maintained CVE list.
 */
import fs from 'fs';

export interface DependencyVuln {
  packageName: string;
  version: string;
  id: string;
  summary: string;
  severity: string;
}

const LOCKFILE_PATH = process.env.SF_CYBERLAB_LOCKFILE_PATH ?? '/cyberlab-root/package-lock.json';
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';

export class ScaUnavailableError extends Error {}

interface ResolvedPackage {
  name: string;
  version: string;
}

function parseLockfile(content: string): ResolvedPackage[] {
  const lock = JSON.parse(content) as { packages?: Record<string, { version?: string }> };
  const packages: ResolvedPackage[] = [];
  for (const [key, meta] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith('node_modules/') || !meta.version) continue;
    const name = key.replace(/^node_modules\//, '');
    packages.push({ name, version: meta.version });
  }
  return packages;
}

function severityFromOsv(vuln: { database_specific?: { severity?: string } }): string {
  return vuln.database_specific?.severity?.toLowerCase() ?? 'unknown';
}

/** Scans every real resolved dependency (direct + transitive) in CyberLab's lockfile against the
 * real OSV vulnerability database. Returns only genuinely matched advisories — never invented. */
export async function runScaScan(): Promise<DependencyVuln[]> {
  if (!fs.existsSync(LOCKFILE_PATH)) {
    throw new ScaUnavailableError(`Lockfile not mounted at ${LOCKFILE_PATH}. The backend container needs the read-only bind mount from docker-compose.yml.`);
  }
  const packages = parseLockfile(await fs.promises.readFile(LOCKFILE_PATH, 'utf8'));
  if (packages.length === 0) return [];

  const batchRes = await fetch(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries: packages.map(p => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) }),
  });
  if (!batchRes.ok) throw new ScaUnavailableError(`OSV batch query failed: HTTP ${batchRes.status}`);
  const batch = (await batchRes.json()) as { results: { vulns?: { id: string }[] }[] };

  const hits: { pkg: ResolvedPackage; vulnId: string }[] = [];
  batch.results.forEach((result, i) => {
    for (const v of result.vulns ?? []) hits.push({ pkg: packages[i], vulnId: v.id });
  });
  if (hits.length === 0) return [];

  // Batch mode only returns ids; fetch each real advisory's summary/severity (capped — a lockfile
  // with hundreds of hits would otherwise mean hundreds of serial requests on every scan).
  const capped = hits.slice(0, 25);
  const details = await Promise.all(capped.map(async h => {
    try {
      const res = await fetch(`${OSV_VULN_URL}/${h.vulnId}`);
      if (!res.ok) return null;
      const vuln = (await res.json()) as { summary?: string; severity?: { type: string; score: string }[]; database_specific?: { severity?: string } };
      return {
        packageName: h.pkg.name, version: h.pkg.version, id: h.vulnId,
        summary: vuln.summary ?? 'No summary available.', severity: severityFromOsv(vuln),
      };
    } catch {
      return null;
    }
  }));

  return details.filter((d): d is DependencyVuln => d !== null);
}
