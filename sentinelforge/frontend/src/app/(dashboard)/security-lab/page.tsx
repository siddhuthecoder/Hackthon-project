'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import { Application, Scenario } from '@/lib/types';

interface SimResult {
  result: { steps: { step: number; action: string; result: string; status: string }[] };
  detections: number;
  incidents: number;
}

export default function SecurityLabPage(): React.ReactElement {
  const [apps, setApps] = useState<Application[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ scenarioId: string; data: SimResult } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<Application[]>('/api/applications').then(setApps);
    api.get<Scenario[]>('/api/lab/scenarios').then(setScenarios);
  }, []);

  const run = async (scenarioId: string): Promise<void> => {
    const app = apps[0];
    if (!app) {
      setError('Connect an application on the Dashboard first.');
      return;
    }
    setBusy(scenarioId);
    setError(null);
    try {
      const data = await api.post<SimResult>(`/api/applications/${app.id}/simulate/${scenarioId}`);
      setLastResult({ scenarioId, data });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Simulation failed');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Security Lab</h1>
        <p className="text-slate-500 text-sm mt-1">
          Run a controlled, authorized attack simulation against CyberLab only. Every click generates real
          events, triggers real detection rules, and may create a real incident.
        </p>
      </div>

      {apps.length === 0 && <p className="text-amber-400 text-sm">No application connected. Go to the Dashboard first.</p>}

      <div className="grid grid-cols-2 gap-3">
        {scenarios.map(s => (
          <button
            key={s.id}
            onClick={() => run(s.id)}
            disabled={busy === s.id || apps.length === 0}
            className="text-left bg-slate-900 border border-slate-800 hover:border-emerald-700 disabled:opacity-50 rounded-xl p-4"
          >
            <p className="font-semibold">{busy === s.id ? 'Running…' : `Run ${s.name}`}</p>
            <p className="text-xs text-slate-500 mt-1">{s.id}</p>
          </button>
        ))}
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {lastResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
          <h2 className="font-semibold">Result: {lastResult.scenarioId}</h2>
          <p className="text-sm text-slate-400">{lastResult.data.detections} detection(s), {lastResult.data.incidents} incident(s) created.</p>
          <ol className="text-sm text-slate-300 space-y-1 mt-2">
            {lastResult.data.result.steps.map(step => (
              <li key={step.step} className={step.status === 'failed' ? 'text-red-400' : ''}>
                {step.step}. {step.action} — {step.result}
              </li>
            ))}
          </ol>
          {lastResult.data.incidents > 0 && (
            <a href="/incidents" className="inline-block mt-2 text-emerald-400 hover:underline text-sm">View incident →</a>
          )}
        </div>
      )}
    </div>
  );
}
