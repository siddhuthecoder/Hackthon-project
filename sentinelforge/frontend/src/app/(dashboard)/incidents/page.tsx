'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Incident } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';

export default function IncidentsPage(): React.ReactElement {
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    api.get<Incident[]>('/api/incidents').then(setIncidents);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Incidents</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {incidents.map(i => (
          <a key={i.id} href={`/incidents/${i.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-slate-800/50">
            <div>
              <p className="font-medium">{i.title}</p>
              <p className="text-sm text-slate-500">{i.rule} · subject: {i.subject} · {new Date(i.detectedAt).toLocaleString()}</p>
            </div>
            <div className="flex gap-2 items-center">
              <SeverityBadge severity={i.severity} />
              <StatusBadge status={i.status} />
            </div>
          </a>
        ))}
        {incidents.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No incidents yet. Run an attack from Security Lab.</p>}
      </div>
    </div>
  );
}
