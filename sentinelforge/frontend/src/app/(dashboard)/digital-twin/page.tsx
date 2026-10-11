'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { AttackGraph } from '@/lib/types';
import { AttackGraphView } from '@/components/AttackGraphView';

export default function DigitalTwinPage(): React.ReactElement {
  const [graph, setGraph] = useState<AttackGraph | null>(null);

  useEffect(() => {
    api.get<AttackGraph>('/api/digital-twin').then(setGraph);
  }, []);

  if (!graph) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-6xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Security Digital Twin</h1>
        <p className="text-slate-500 text-sm mt-1">
          A standing model of the whole organization — every application, its real open findings, and any incident currently
          exploiting one — rebuilt fresh from live data on every load, not a cached snapshot.
        </p>
      </div>
      <p className="text-sm text-slate-300 bg-slate-900 border border-slate-800 rounded-xl p-4">{graph.summary}</p>
      <AttackGraphView graph={graph} />
    </div>
  );
}
