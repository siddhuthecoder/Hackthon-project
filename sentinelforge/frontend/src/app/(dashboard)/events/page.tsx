'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { SecurityEvent } from '@/lib/types';

export default function EventsPage(): React.ReactElement {
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  useEffect(() => {
    api.get<SecurityEvent[]>('/api/events?limit=300').then(setEvents);
  }, []);

  return (
    <div className="max-w-5xl space-y-4">
      <h1 className="text-2xl font-bold">Events</h1>
      <p className="text-slate-500 text-sm">Raw security events ingested from CyberLab. See SOC for the live stream.</p>
      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800 max-h-[70vh] overflow-y-auto font-mono text-sm">
        {events.map(e => (
          <div key={e.id} className="px-4 py-2 flex justify-between">
            <span>{e.eventType}{e.endpoint ? ` · ${e.endpoint}` : ''}{e.userId ? ` · ${e.userId}` : ''}</span>
            <span className="text-slate-500">{new Date(e.timestamp).toLocaleString()}</span>
          </div>
        ))}
        {events.length === 0 && <p className="text-slate-500 px-4 py-3">No events ingested yet.</p>}
      </div>
    </div>
  );
}
