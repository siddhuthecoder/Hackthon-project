'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { StatusBadge } from '@/components/Badge';

interface RemediationTask {
  id: string;
  findingId: string;
  status: string;
  plan: Record<string, unknown>;
  appliedAt?: string;
  appliedBy?: string;
  createdAt: string;
}

export default function RemediationPage(): React.ReactElement {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);

  useEffect(() => {
    api.get<RemediationTask[]>('/api/remediation-tasks').then(setTasks);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Remediation</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {tasks.map(t => (
          <div key={t.id} className="flex items-center justify-between px-5 py-4">
            <div>
              <a href={`/findings/${t.findingId}`} className="font-medium text-slate-200 hover:text-emerald-400">{String(t.plan.vulnKey ?? t.findingId)}</a>
              <p className="text-sm text-slate-500">{t.appliedAt ? `applied ${new Date(t.appliedAt).toLocaleString()}` : new Date(t.createdAt).toLocaleString()}</p>
            </div>
            <StatusBadge status={t.status} />
          </div>
        ))}
        {tasks.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No remediation applied yet. Apply a fix from a finding page.</p>}
      </div>
    </div>
  );
}
