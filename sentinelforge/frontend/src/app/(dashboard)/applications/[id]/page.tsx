'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { api } from '@/lib/api';
import { Application, ScanRunDiff } from '@/lib/types';
import { StatusBadge } from '@/components/Badge';

interface AppDetail extends Application {
  assets: { id: string; kind: string; name: string }[];
  endpoints: { id: string; method: string; path: string; authRequired: boolean }[];
  scanRuns: { id: string; status: string; startedAt: string; checksTotal: number; findingsOpen: number; diff?: ScanRunDiff }[];
}

interface ReconReport {
  summary: string;
  mode: string;
}

interface RedTeamChain {
  chainSteps: { vulnKey: string; title: string; role: string }[];
  narrative: string;
  finalImpact: string;
  confidence: number;
  mode: string;
}

export default function ApplicationDetailPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>();
  const [app, setApp] = useState<AppDetail | null>(null);
  const [recon, setRecon] = useState<ReconReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<{ total: number; vulnerable: number } | null>(null);
  const [redTeam, setRedTeam] = useState<RedTeamChain | null>(null);

  const load = async (): Promise<void> => {
    setApp(await api.get<AppDetail>(`/api/applications/${id}`));
  };

  useEffect(() => {
    load();
  }, [id]);

  const runRecon = async (): Promise<void> => {
    setBusy('recon');
    try {
      setRecon(await api.post<ReconReport>(`/api/applications/${id}/recon`));
    } finally {
      setBusy(null);
    }
  };

  const runScan = async (): Promise<void> => {
    setBusy('scan');
    try {
      const result = await api.post<{ total: number; vulnerable: number }>(`/api/applications/${id}/scan`);
      setScanResult({ total: result.total, vulnerable: result.vulnerable });
      await load();
    } finally {
      setBusy(null);
    }
  };

  const runRedTeam = async (): Promise<void> => {
    setBusy('red-team');
    try {
      setRedTeam(await api.post<RedTeamChain>(`/api/applications/${id}/red-team`));
    } finally {
      setBusy(null);
    }
  };

  if (!app) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">{app.name}</h1>
        <StatusBadge status={app.status} />
      </div>
      <p className="text-slate-500">{app.baseUrl}</p>

      <div className="flex gap-3">
        <button onClick={runScan} disabled={busy !== null} className="bg-amber-700 hover:bg-amber-600 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy === 'scan' ? 'Scanning…' : 'Run Scan'}
        </button>
        <button onClick={runRecon} disabled={busy !== null} className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy === 'recon' ? 'Running…' : 'AI Recon Summary'}
        </button>
        <button onClick={runRedTeam} disabled={busy !== null} className="bg-red-800 hover:bg-red-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy === 'red-team' ? 'Analyzing…' : '🤖 Red Team Chain Analysis'}
        </button>
      </div>

      {redTeam && (
        <div className="bg-slate-900 border border-red-900/50 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Autonomous Exploitation Chain</h2>
            <span className="text-xs text-slate-500">mode: {redTeam.mode} · confidence {Math.round(redTeam.confidence * 100)}%</span>
          </div>
          <p className="text-xs text-slate-500">
            Narrative built strictly from this application&apos;s real, independently-confirmed findings — not a literal re-executed multi-step exploit.
          </p>
          {redTeam.chainSteps.length === 0 ? (
            <p className="text-sm text-slate-400">No open findings to chain.</p>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              {redTeam.chainSteps.map((s, i) => (
                <div key={s.vulnKey} className="flex items-center gap-2">
                  <a href="/findings" className="bg-red-950/50 border border-red-800 rounded px-3 py-2 text-xs hover:bg-red-900/50">
                    <p className="font-mono font-semibold text-red-300">{s.vulnKey}</p>
                    <p className="text-slate-400">{s.title}</p>
                    <p className="text-slate-500 mt-0.5">{s.role}</p>
                  </a>
                  {i < redTeam.chainSteps.length - 1 && <span className="text-red-700">→</span>}
                </div>
              ))}
            </div>
          )}
          <p className="text-sm text-slate-300">{redTeam.narrative}</p>
          <p className="text-sm"><span className="text-slate-500">Final impact: </span>{redTeam.finalImpact}</p>
        </div>
      )}
      {scanResult && (
        <p className="text-sm text-slate-400">Last scan: {scanResult.vulnerable}/{scanResult.total} checks confirmed vulnerable. <a href="/findings" className="text-emerald-400 hover:underline">View findings →</a></p>
      )}
      {recon && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-sm">
          <p>{recon.summary}</p>
          <p className="text-xs text-slate-500 mt-1">mode: {recon.mode}</p>
        </div>
      )}

      <div>
        <h2 className="font-semibold mb-2">Attack Surface — Endpoints ({app.endpoints.length})</h2>
        <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800 max-h-64 overflow-y-auto">
          {app.endpoints.map(e => (
            <div key={e.id} className="px-4 py-2 text-sm flex justify-between items-center">
              <span className="font-mono">{e.method} {e.path}</span>
              <span className={`text-xs px-2 py-0.5 rounded font-semibold ${e.authRequired ? 'bg-slate-800 text-slate-400' : 'bg-amber-900/40 text-amber-400'}`}>
                {e.authRequired ? 'authenticated' : 'public — no auth'}
              </span>
            </div>
          ))}
          {app.endpoints.length === 0 && <p className="text-slate-500 text-sm px-4 py-3">No endpoints discovered yet.</p>}
        </div>
      </div>

      <div>
        <h2 className="font-semibold mb-2">Scan Runs ({app.scanRuns.length})</h2>
        <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
          {app.scanRuns.map(s => (
            <div key={s.id} className="px-4 py-2 text-sm">
              <div className="flex justify-between">
                <span>{new Date(s.startedAt).toLocaleString()} · {s.status}</span>
                <span className="text-slate-500">{s.findingsOpen}/{s.checksTotal} vulnerable</span>
              </div>
              {s.diff && (s.diff.new.length > 0 || s.diff.resolved.length > 0 || s.diff.regressed.length > 0) && (
                <div className="mt-1 flex gap-3 text-xs">
                  {s.diff.new.length > 0 && <span className="text-amber-400">+{s.diff.new.length} new</span>}
                  {s.diff.resolved.length > 0 && <span className="text-emerald-400">−{s.diff.resolved.length} resolved</span>}
                  {s.diff.regressed.length > 0 && <span className="text-red-400">⚠ {s.diff.regressed.length} regressed: {s.diff.regressed.join(', ')}</span>}
                </div>
              )}
            </div>
          ))}
          {app.scanRuns.length === 0 && <p className="text-slate-500 text-sm px-4 py-3">No scans yet.</p>}
        </div>
      </div>
    </div>
  );
}
