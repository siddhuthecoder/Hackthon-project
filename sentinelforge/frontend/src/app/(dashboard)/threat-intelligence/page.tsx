'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface ThreatIndicator {
  id: string;
  kind: string;
  value: string;
  details: {
    cweName: string;
    owasp: string;
    owaspName: string;
    summary: string;
    epssScore: number;
    epssPercentile: number;
    cisaKev: boolean;
    relatedCves: { id: string; summary: string }[];
    mitreTechniques: string[];
  };
}

export default function ThreatIntelligencePage(): React.ReactElement {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);

  useEffect(() => {
    api.get<ThreatIndicator[]>('/api/threat-intel').then(setIndicators);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Threat Intelligence</h1>
      <p className="text-slate-500 text-sm">Local reference dataset (CWE/OWASP/CVE/EPSS/CISA KEV-shaped) synced after every scan. See docs/AI-ARCHITECTURE.md for how this is sourced.</p>
      <div className="space-y-3">
        {indicators.map(ind => (
          <div key={ind.id} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <p className="font-semibold">{ind.value} — {ind.details.cweName}</p>
              {ind.details.cisaKev && <span className="text-xs bg-red-900/60 text-red-200 px-2 py-0.5 rounded">CISA KEV</span>}
            </div>
            <p className="text-sm text-slate-400 mt-1">{ind.details.owasp}: {ind.details.owaspName}</p>
            <p className="text-sm text-slate-300 mt-2">{ind.details.summary}</p>
            <p className="text-xs text-slate-500 mt-2">EPSS: {(ind.details.epssScore * 100).toFixed(0)}% (percentile {(ind.details.epssPercentile * 100).toFixed(0)})</p>
            <div className="mt-2 space-y-1">
              {ind.details.relatedCves.map(c => (
                <p key={c.id} className="text-xs text-slate-400">{c.id}: {c.summary}</p>
              ))}
            </div>
          </div>
        ))}
        {indicators.length === 0 && <p className="text-slate-500 text-sm">No threat intel synced yet — run a scan first.</p>}
      </div>
    </div>
  );
}
