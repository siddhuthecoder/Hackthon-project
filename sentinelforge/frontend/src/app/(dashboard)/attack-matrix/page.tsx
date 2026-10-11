'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface Technique {
  id: string;
  name: string;
  tactic: string;
  observedCount: number;
  exampleIncidentTitle?: string;
}

interface AttackMatrix {
  tacticOrder: string[];
  techniques: Technique[];
  observedTechniques: number;
  totalTechniques: number;
}

function heatColor(count: number): string {
  if (count === 0) return 'bg-slate-800/60 text-slate-600';
  if (count >= 5) return 'bg-red-900/70 text-red-200 border-red-700';
  if (count >= 2) return 'bg-amber-900/60 text-amber-200 border-amber-700';
  return 'bg-amber-950/40 text-amber-300 border-amber-900';
}

export default function AttackMatrixPage(): React.ReactElement {
  const [matrix, setMatrix] = useState<AttackMatrix | null>(null);

  useEffect(() => {
    api.get<AttackMatrix>('/api/attack-matrix').then(setMatrix);
  }, []);

  if (!matrix) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-6xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">MITRE ATT&CK Coverage</h1>
        <p className="text-slate-500 text-sm mt-1">
          {matrix.observedTechniques}/{matrix.totalTechniques} tagged techniques have real detected activity. A simplified
          single-tactic-per-technique grid (several real techniques span multiple tactics).
        </p>
      </div>

      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${matrix.tacticOrder.length}, minmax(140px, 1fr))` }}>
        {matrix.tacticOrder.map(tactic => (
          <div key={tactic} className="space-y-2">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide border-b border-slate-800 pb-1">{tactic}</p>
            {matrix.techniques.filter(t => t.tactic === tactic).map(t => (
              <div
                key={t.id}
                title={t.exampleIncidentTitle ? `${t.observedCount} incident(s), e.g. "${t.exampleIncidentTitle}"` : 'No activity observed yet'}
                className={`rounded border px-2 py-2 text-xs ${heatColor(t.observedCount)}`}
              >
                <p className="font-mono font-semibold">{t.id}</p>
                <p className="leading-snug">{t.name}</p>
                {t.observedCount > 0 && <p className="mt-1 font-bold">{t.observedCount} detected</p>}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
