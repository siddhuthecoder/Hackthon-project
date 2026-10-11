'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { IncidentDetail } from '@/lib/types';

interface Investigation {
  summary: string;
  facts: string[];
  timeline: { at: string; what: string }[];
  relatedVulnerabilities: string[];
  attackPath: string;
  impact: string;
  inferences: string[];
  uncertainties: string[];
  recommendedActions: string[];
  confidence: number;
  mode: string;
}

export default function InvestigationPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<IncidentDetail>(`/api/incidents/${id}`).then(inc => {
      setIncident(inc);
      if (inc.investigation) setInvestigation(inc.investigation as unknown as Investigation);
    });
  }, [id]);

  const investigate = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      setInvestigation(await api.post(`/api/incidents/${id}/investigate`));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Investigation failed');
    } finally {
      setBusy(false);
    }
  };

  if (!incident) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Investigation: {incident.title}</h1>
        <a href={`/incidents/${id}`} className="text-sm text-emerald-400 hover:underline">← back to incident</a>
      </div>

      <button onClick={investigate} disabled={busy} className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
        {busy ? 'Investigating…' : investigation ? 'Re-run Investigation' : 'Investigate with AI'}
      </button>
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {investigation ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Summary</h2>
            <span className="text-xs text-slate-500">mode: {investigation.mode}</span>
          </div>
          <p className="text-emerald-300">{investigation.summary}</p>

          <Section title="Facts" items={investigation.facts} />
          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase mb-1">Timeline</h3>
            <ul className="text-sm text-slate-300 space-y-0.5">
              {investigation.timeline.map((t, i) => <li key={i}>{new Date(t.at).toLocaleTimeString()} — {t.what}</li>)}
            </ul>
          </div>
          <p className="text-sm"><span className="text-slate-500">Attack path: </span>{investigation.attackPath}</p>
          <p className="text-sm"><span className="text-slate-500">Impact: </span>{investigation.impact}</p>
          <Section title="Inferences" items={investigation.inferences} />
          <Section title="Uncertainties" items={investigation.uncertainties} />
          <Section title="Recommended Actions" items={investigation.recommendedActions} />
          <p className="text-sm text-slate-400">Confidence: {Math.round(investigation.confidence * 100)}%</p>
        </div>
      ) : (
        <p className="text-slate-500 text-sm">No investigation yet.</p>
      )}
    </div>
  );
}

function Section({ title, items }: { title: string; items: string[] }): React.ReactElement | null {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <h3 className="text-xs font-semibold text-slate-500 uppercase mb-1">{title}</h3>
      <ul className="list-disc list-inside text-sm text-slate-300 space-y-0.5">
        {items.map((item, i) => <li key={i}>{item}</li>)}
      </ul>
    </div>
  );
}
