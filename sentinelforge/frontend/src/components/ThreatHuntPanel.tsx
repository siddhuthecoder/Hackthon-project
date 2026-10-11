'use client';

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';

interface HuntEvent {
  id: string;
  timestamp: string;
  eventType: string;
  severity: string;
  sourceIp?: string;
  endpoint?: string;
  userId?: string;
}

interface HuntResult {
  filter: Record<string, unknown>;
  matchedCount: number;
  events: HuntEvent[];
  summary: string;
  mode: string;
}

const EXAMPLES = [
  'show me every failed login in the last 24 hours',
  'any cross-tenant access attempts this week?',
  'who triggered the canary endpoint?',
];

/** SOC Copilot — natural-language threat hunting across ALL recorded events, not one incident.
 * Translates the question to a safe structured filter server-side (see modules/soc/hunt.ts),
 * runs a real query, and grounds the summary in the real matched rows. */
export function ThreatHuntPanel(): React.ReactElement {
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<HuntResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hunt = async (q?: string): Promise<void> => {
    const text = (q ?? question).trim();
    if (!text) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<HuntResult>('/api/soc/hunt', { question: text });
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Hunt failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h2 className="font-semibold mb-1">SOC Copilot — Threat Hunting</h2>
      <p className="text-xs text-slate-500 mb-3">Ask in plain English. Searches every recorded security event, not just one incident.</p>
      <div className="flex gap-2 mb-2">
        <input
          value={question}
          onChange={e => setQuestion(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') hunt(); }}
          placeholder="e.g. show me every failed login in the last 24 hours"
          className="flex-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm"
        />
        <button onClick={() => hunt()} disabled={busy || !question.trim()} className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy ? 'Hunting…' : 'Hunt'}
        </button>
      </div>
      <div className="flex gap-2 flex-wrap mb-3">
        {EXAMPLES.map(ex => (
          <button key={ex} onClick={() => { setQuestion(ex); hunt(ex); }} className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-400 px-2 py-1 rounded">
            {ex}
          </button>
        ))}
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      {result && (
        <div className="space-y-2 border-t border-slate-800 pt-3">
          <p className="text-sm text-slate-200">{result.summary}</p>
          <p className="text-xs text-slate-500">
            {result.matchedCount} matching event(s) · mode: {result.mode}
          </p>
          <div className="max-h-56 overflow-y-auto divide-y divide-slate-800">
            {result.events.slice(0, 30).map(e => (
              <div key={e.id} className="py-1 text-xs flex justify-between">
                <span className="text-slate-400">{e.eventType} {e.endpoint ?? ''} {e.sourceIp ? `· ${e.sourceIp}` : ''}</span>
                <span className="text-slate-600">{new Date(e.timestamp).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
