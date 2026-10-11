'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { StatusBadge } from '@/components/Badge';

interface ScanRun {
  id: string;
  applicationId: string;
  status: string;
  startedAt: string;
  finishedAt?: string;
  checksTotal: number;
  findingsOpen: number;
}

export default function ScansPage(): React.ReactElement {
  const [scans, setScans] = useState<ScanRun[]>([]);

  useEffect(() => {
    api.get<ScanRun[]>('/api/scans').then(setScans);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Scans</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {scans.map(s => (
          <div key={s.id} className="flex items-center justify-between px-5 py-4">
            <div>
              <p className="font-medium">{new Date(s.startedAt).toLocaleString()}</p>
              <p className="text-sm text-slate-500">{s.checksTotal} checks · {s.findingsOpen} open findings</p>
            </div>
            <div className="flex items-center gap-2">
              <StatusBadge status={s.status} />
              <a href={`/applications/${s.applicationId}`} className="text-xs text-emerald-400 hover:underline">app →</a>
            </div>
          </div>
        ))}
        {scans.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No scans yet.</p>}
      </div>
    </div>
  );
}
