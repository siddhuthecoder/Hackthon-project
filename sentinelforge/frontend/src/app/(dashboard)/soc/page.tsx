'use client';

import { useEffect, useRef, useState } from 'react';
import { streamUrl } from '@/lib/api';
import { ThreatHuntPanel } from '@/components/ThreatHuntPanel';

interface LiveMessage {
  topic: string;
  at: string;
  data: Record<string, unknown>;
}

const TOPIC_COLOR: Record<string, string> = {
  event: 'text-slate-300',
  detection: 'text-amber-400',
  incident: 'text-red-400',
  scan: 'text-sky-400',
  verification: 'text-emerald-400',
};

export default function SocPage(): React.ReactElement {
  const [messages, setMessages] = useState<LiveMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource(streamUrl());
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const topics = ['event', 'detection', 'incident', 'scan', 'verification'];
    const handler = (ev: MessageEvent): void => {
      try {
        const msg = JSON.parse(ev.data) as LiveMessage;
        setMessages(prev => [msg, ...prev].slice(0, 200));
      } catch {
        // ignore malformed frames
      }
    };
    for (const topic of topics) es.addEventListener(topic, handler);

    return () => {
      es.close();
    };
  }, []);

  return (
    <div className="max-w-4xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">SOC — Live Feed</h1>
        <span className={`text-xs px-2 py-1 rounded ${connected ? 'bg-emerald-900/50 text-emerald-300' : 'bg-red-900/50 text-red-300'}`}>
          {connected ? '● Live' : '○ Disconnected'}
        </span>
      </div>
      <ThreatHuntPanel />
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-sm h-[70vh] overflow-y-auto">
        {messages.length === 0 && <p className="text-slate-600">Waiting for activity — run a simulation from Security Lab.</p>}
        {messages.map((m, i) => (
          <div key={i} className="py-1 border-b border-slate-900 last:border-0">
            <span className="text-slate-600">{new Date(m.at).toLocaleTimeString()}</span>{' '}
            <span className={TOPIC_COLOR[m.topic] ?? 'text-slate-300'}>[{m.topic.toUpperCase()}]</span>{' '}
            <span className="text-slate-400">{summarize(m)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function summarize(m: LiveMessage): string {
  const d = m.data as Record<string, unknown>;
  if (m.topic === 'event') return `${d.eventType ?? ''} ${d.endpoint ?? ''} (${d.userId ?? d.sourceIp ?? ''})`;
  if (m.topic === 'detection') return `${d.rule ?? ''} — subject ${d.subject ?? ''}`;
  if (m.topic === 'incident') return `${d.title ?? ''} (${d.severity ?? ''})`;
  if (m.topic === 'scan') return `scan ${d.status ?? ''} — ${d.findingsOpen ?? ''} open findings`;
  if (m.topic === 'verification') return `passed=${d.passed}`;
  return JSON.stringify(d).slice(0, 120);
}
