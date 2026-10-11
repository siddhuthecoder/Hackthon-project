'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface Asset {
  id: string;
  applicationId: string;
  kind: string;
  name: string;
  details: Record<string, unknown>;
  createdAt: string;
}

export default function AssetsPage(): React.ReactElement {
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    api.get<Asset[]>('/api/assets').then(setAssets);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Assets</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {assets.map(a => (
          <div key={a.id} className="flex items-center justify-between px-5 py-4">
            <div>
              <p className="font-medium">{a.name}</p>
              <p className="text-sm text-slate-500">{a.kind} · {JSON.stringify(a.details)}</p>
            </div>
            <a href={`/applications/${a.applicationId}`} className="text-xs text-emerald-400 hover:underline">view application →</a>
          </div>
        ))}
        {assets.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No assets discovered yet. Run discovery from the Dashboard.</p>}
      </div>
    </div>
  );
}
