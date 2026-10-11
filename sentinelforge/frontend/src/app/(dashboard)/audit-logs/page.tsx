'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  details: Record<string, unknown>;
}

export default function AuditLogsPage(): React.ReactElement {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);

  useEffect(() => {
    api.get<AuditLogEntry[]>('/api/audit-logs?limit=300').then(setLogs);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Audit Logs</h1>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800 max-h-[70vh] overflow-y-auto font-mono text-sm">
        {logs.map(l => (
          <div key={l.id} className="px-4 py-2 flex justify-between">
            <span>{l.action}{l.targetType ? ` · ${l.targetType}:${l.targetId}` : ''}{l.actor ? ` · by ${l.actor}` : ''}</span>
            <span className="text-slate-500">{new Date(l.timestamp).toLocaleString()}</span>
          </div>
        ))}
        {logs.length === 0 && <p className="text-slate-500 px-4 py-3">No audit entries yet.</p>}
      </div>
    </div>
  );
}
