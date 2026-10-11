'use client';

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';

interface ChatTurn {
  question: string;
  answer: string;
  mode?: string;
}

interface AssistantChatProps {
  incidentId?: string;
  findingId?: string;
}

/** A real multi-turn chat panel over the existing /api/assistant/ask endpoint — previously that
 * endpoint only had a one-shot button UI. Keeps the conversation in local state and resends it as
 * `history` on each question, so follow-ups ("what should I do about that?") have context. */
export function AssistantChat({ incidentId, findingId }: AssistantChatProps): React.ReactElement {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ask = async (): Promise<void> => {
    const q = question.trim();
    if (!q) return;
    setBusy(true);
    setError(null);
    setQuestion('');
    try {
      const res = await api.post<{ answer: string; mode: string }>('/api/assistant/ask', {
        question: q,
        incidentId,
        findingId,
        history: turns.map(t => ({ question: t.question, answer: t.answer })),
      });
      setTurns(t => [...t, { question: q, answer: res.answer, mode: res.mode }]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Assistant failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h2 className="font-semibold mb-3">Ask the AI</h2>
      <div className="space-y-3 mb-4 max-h-80 overflow-y-auto">
        {turns.map((t, i) => (
          <div key={i} className="space-y-1">
            <p className="text-sm text-slate-400"><span className="text-slate-500">You:</span> {t.question}</p>
            <p className="text-sm text-slate-200"><span className="text-emerald-400">Assistant:</span> {t.answer}</p>
          </div>
        ))}
        {turns.length === 0 && <p className="text-slate-500 text-sm">Ask anything about this {incidentId ? 'incident' : 'finding'} — answers are grounded in its real data only.</p>}
      </div>
      {error && <p className="text-red-400 text-sm mb-2">{error}</p>}
      <div className="flex gap-2">
        <input
          value={question}
          onChange={e => setQuestion(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') ask(); }}
          placeholder="e.g. what's the real-world impact of this?"
          className="flex-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm"
        />
        <button
          onClick={ask}
          disabled={busy || !question.trim()}
          className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
        >
          {busy ? 'Thinking…' : 'Ask'}
        </button>
      </div>
    </div>
  );
}
