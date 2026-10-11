'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { ComplianceCoverage, OwaspCategoryCoverage } from '@/lib/types';

function CoverageGroup({ title, data }: { title: string; data: { tested: number; total: number; categories: OwaspCategoryCoverage[] } }): React.ReactElement {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-semibold">{title}</h2>
        <span className="text-sm text-slate-400">{data.tested}/{data.total} categories tested</span>
      </div>
      <div className="divide-y divide-slate-800">
        {data.categories.map(c => (
          <div key={c.code} className="flex items-center justify-between py-2 text-sm">
            <div>
              <span className="font-mono text-xs text-slate-500">{c.code}</span>
              <span className="ml-2">{c.label}</span>
            </div>
            <div className="flex gap-3 items-center">
              {c.openFindings > 0
                ? <span className="text-xs bg-red-900/40 text-red-400 px-2 py-0.5 rounded font-semibold">{c.openFindings} open</span>
                : <span className="text-xs bg-emerald-900/40 text-emerald-400 px-2 py-0.5 rounded font-semibold">clean</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function CompliancePage(): React.ReactElement {
  const [coverage, setCoverage] = useState<ComplianceCoverage | null>(null);

  useEffect(() => {
    api.get<ComplianceCoverage>('/api/compliance/coverage').then(setCoverage);
  }, []);

  if (!coverage) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-4xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Compliance Coverage</h1>
        <p className="text-slate-500 text-sm mt-1">Which OWASP categories the scanner actually tests, and what's currently open in each.</p>
      </div>
      <CoverageGroup title="OWASP API Security Top 10 (2023)" data={coverage.apiTop10} />
      <CoverageGroup title="OWASP Top 10 (2021)" data={coverage.webTop10} />
    </div>
  );
}
