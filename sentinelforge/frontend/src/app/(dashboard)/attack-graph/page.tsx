'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { AttackGraph, Incident } from '@/lib/types';
import { AttackGraphView } from '@/components/AttackGraphView';
import { SeverityBadge } from '@/components/Badge';

export default function AttackGraphPage(): React.ReactElement {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [graph, setGraph] = useState<AttackGraph | null>(null);

  useEffect(() => {
    api.get<Incident[]>('/api/incidents').then(list => {
      setIncidents(list);
      if (list.length > 0) setSelected(list[0].id);
    });
  }, []);

  useEffect(() => {
    if (!selected) return;
    api.get<AttackGraph>(`/api/incidents/${selected}/attack-graph`).then(setGraph);
  }, [selected]);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Attack Graph</h1>
      <p className="text-slate-500 text-sm">Pick an incident to see the real attack path SentinelForge built from its evidence.</p>

      <div className="flex gap-2 flex-wrap">
        {incidents.map(i => (
          <button
            key={i.id}
            onClick={() => setSelected(i.id)}
            className={`px-3 py-1.5 rounded text-sm ${selected === i.id ? 'bg-emerald-700 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}`}
          >
            {i.title} <SeverityBadge severity={i.severity} />
          </button>
        ))}
        {incidents.length === 0 && <p className="text-slate-500 text-sm">No incidents yet. Run an attack from Security Lab.</p>}
      </div>

      {graph && (
        <div>
          <p className="text-sm text-slate-400 mb-2">{graph.summary}</p>
          {graph.nodes.length > 0 ? <AttackGraphView graph={graph} /> : <p className="text-slate-500 text-sm">No graph data for this incident yet.</p>}
        </div>
      )}
    </div>
  );
}
