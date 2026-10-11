'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Application, PostureMetrics } from '@/lib/types';

interface ComparedApp {
  application: Application;
  metrics: PostureMetrics;
}

export default function ComparePage(): React.ReactElement {
  const [apps, setApps] = useState<Application[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [compared, setCompared] = useState<ComparedApp[] | null>(null);

  useEffect(() => {
    api.get<Application[]>('/api/applications').then(a => {
      setApps(a);
      setSelected(a.slice(0, 2).map(x => x.id));
    });
  }, []);

  useEffect(() => {
    if (selected.length === 0) { setCompared(null); return; }
    api.get<ComparedApp[]>(`/api/applications/compare?ids=${selected.join(',')}`).then(setCompared);
  }, [selected]);

  const toggle = (id: string): void => {
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  };

  return (
    <div className="max-w-5xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Compare Targets</h1>
        <p className="text-slate-500 text-sm mt-1">Side-by-side posture — the same adapter-agnostic pipeline run against any number of targets.</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {apps.map(a => (
          <button
            key={a.id}
            onClick={() => toggle(a.id)}
            className={`text-sm px-3 py-1.5 rounded border ${selected.includes(a.id) ? 'bg-emerald-900/40 border-emerald-700 text-emerald-300' : 'bg-slate-800 border-slate-700 text-slate-400'}`}
          >
            {a.name} ({a.adapter})
          </button>
        ))}
      </div>

      <div className={`grid gap-4 ${compared && compared.length > 1 ? 'grid-cols-2' : 'grid-cols-1'}`}>
        {compared?.map(c => {
          const open = Object.values(c.metrics.severityCounts).reduce((x, y) => x + y, 0);
          return (
            <div key={c.application.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <div>
                <h2 className="font-semibold">{c.application.name}</h2>
                <p className="text-xs text-slate-500">{c.application.baseUrl} · adapter: {c.application.adapter}</p>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="bg-slate-800 rounded p-2">
                  <p className="text-slate-500 text-xs">Open findings</p>
                  <p className="text-xl font-bold">{open}</p>
                </div>
                <div className="bg-slate-800 rounded p-2">
                  <p className="text-slate-500 text-xs">Critical / High</p>
                  <p className="text-xl font-bold text-red-400">{(c.metrics.severityCounts.critical ?? 0) + (c.metrics.severityCounts.high ?? 0)}</p>
                </div>
                <div className="bg-slate-800 rounded p-2">
                  <p className="text-slate-500 text-xs">Avg time to fix</p>
                  <p className="text-xl font-bold">{c.metrics.avgTimeToFixHours != null ? `${Math.round(c.metrics.avgTimeToFixHours * 10) / 10}h` : '—'}</p>
                </div>
                <div className="bg-slate-800 rounded p-2">
                  <p className="text-slate-500 text-xs">Scans run</p>
                  <p className="text-xl font-bold">{c.metrics.scanHistory.length}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {(!compared || compared.length === 0) && <p className="text-slate-500 text-sm">Select at least one target above.</p>}
    </div>
  );
}
