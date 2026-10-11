'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Finding } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';

export default function FindingsPage(): React.ReactElement {
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    api.get<Finding[]>('/api/findings').then(setFindings);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Findings</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {findings.map(f => (
          <a key={f.id} href={`/findings/${f.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-slate-800/50">
            <div>
              <p className="font-medium">{f.vulnKey} — {f.title}</p>
              <p className="text-sm text-slate-500">{f.method} {f.endpoint} · {f.cwe} {f.owasp}</p>
            </div>
            <div className="flex gap-2 items-center">
              <SeverityBadge severity={f.severity} />
              <StatusBadge status={f.status} />
            </div>
          </a>
        ))}
        {findings.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No findings yet. Run a scan from the Dashboard.</p>}
      </div>
    </div>
  );
}
