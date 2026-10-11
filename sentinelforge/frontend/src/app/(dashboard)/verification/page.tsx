'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface VerificationRun {
  id: string;
  findingId: string;
  passed: boolean;
  outcome: string;
  after: { status?: number; detail?: string };
  createdAt: string;
}

export default function VerificationPage(): React.ReactElement {
  const [runs, setRuns] = useState<VerificationRun[]>([]);

  useEffect(() => {
    api.get<VerificationRun[]>('/api/verification-runs').then(setRuns);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Verification</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {runs.map(r => (
          <div key={r.id} className="flex items-center justify-between px-5 py-4">
            <div>
              <a href={`/findings/${r.findingId}`} className="font-medium text-slate-200 hover:text-emerald-400">{r.findingId}</a>
              <p className="text-sm text-slate-500">{r.after?.detail ?? r.outcome} · {new Date(r.createdAt).toLocaleString()}</p>
            </div>
            <span className={`text-xs px-2 py-1 rounded font-semibold ${r.passed ? 'bg-emerald-900/50 text-emerald-300' : 'bg-red-900/50 text-red-300'}`}>
              {r.passed ? '✅ BLOCKED' : '❌ STILL VULNERABLE'}
            </span>
          </div>
        ))}
        {runs.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No verification runs yet. Click Verify Fix on a finding page.</p>}
      </div>
    </div>
  );
}
