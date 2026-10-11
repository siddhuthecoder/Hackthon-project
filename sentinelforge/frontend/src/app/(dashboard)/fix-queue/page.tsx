'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { RankedFinding } from '@/lib/types';

function scoreColor(score: number): string {
  if (score >= 70) return 'text-red-400';
  if (score >= 40) return 'text-amber-400';
  return 'text-emerald-400';
}

export default function FixQueuePage(): React.ReactElement {
  const [findings, setFindings] = useState<RankedFinding[] | null>(null);

  useEffect(() => {
    api.get<RankedFinding[]>('/api/findings/prioritized').then(setFindings);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Fix This First</h1>
        <p className="text-slate-500 text-sm mt-1">
          One ranked list instead of three separate signals — severity, EPSS exploit-prediction, CISA KEV, and whether the
          endpoint is public, combined into a single risk score (0–100).
        </p>
      </div>

      {!findings && <p className="text-slate-500">Loading…</p>}
      {findings && findings.length === 0 && <p className="text-slate-500">No open findings — clean posture.</p>}

      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {findings?.map((f, i) => (
          <a key={f.id} href={`/findings/${f.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-slate-800/50">
            <div className="flex items-center gap-4">
              <span className="text-slate-600 font-mono text-sm w-6">#{i + 1}</span>
              <div>
                <p className="font-medium">{f.vulnKey} — {f.title}</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {f.applicationName} · {f.severity} · {f.risk.exposure === 'public' ? 'public endpoint' : 'authenticated endpoint'}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className={`text-2xl font-bold ${scoreColor(f.risk.score)}`}>{f.risk.score}</p>
              <p className="text-xs text-slate-500">
                sev {f.risk.breakdown.severity} + epss {f.risk.breakdown.epss} + kev {f.risk.breakdown.kev} + exp {f.risk.breakdown.exposure}
              </p>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}
