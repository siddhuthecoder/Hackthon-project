'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import { Application, TestConnectionResult } from '@/lib/types';
import { StatusBadge } from '@/components/Badge';

type Adapter = 'cyberlab' | 'juiceshop' | 'generic';
type WizardStep = 'form' | 'tested' | 'adding';

export default function ApplicationsPage(): React.ReactElement {
  const [apps, setApps] = useState<Application[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [step, setStep] = useState<WizardStep>('form');
  const [name, setName] = useState('OWASP Juice Shop');
  const [baseUrl, setBaseUrl] = useState('http://host.docker.internal:3002');
  const [adapter, setAdapter] = useState<Adapter>('juiceshop');
  const [openapiUrl, setOpenapiUrl] = useState('');
  const [authHeaderName, setAuthHeaderName] = useState('Authorization');
  const [authHeaderValue, setAuthHeaderValue] = useState('');
  const [scanIntervalMinutes, setScanIntervalMinutes] = useState('');
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);

  const load = async (): Promise<void> => {
    setApps(await api.get<Application[]>('/api/applications'));
  };

  useEffect(() => {
    load();
  }, []);

  const buildConfig = (): Record<string, string> | undefined => {
    if (adapter !== 'generic') return undefined;
    const cfg: Record<string, string> = {};
    if (openapiUrl) cfg.openapiUrl = openapiUrl;
    if (authHeaderName && authHeaderValue) { cfg.authHeaderName = authHeaderName; cfg.authHeaderValue = authHeaderValue; }
    return cfg;
  };

  const testConnection = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      const result = await api.post<TestConnectionResult>('/api/applications/test-connection', { baseUrl, adapter, config: buildConfig() });
      setTestResult(result);
      if (result.ok) setStep('tested');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Connection test failed');
    } finally {
      setBusy(false);
    }
  };

  const addAndDiscoverAndScan = async (): Promise<void> => {
    setStep('adding');
    setBusy(true);
    setError(null);
    setProgress([]);
    try {
      setProgress(p => [...p, 'Registering application…']);
      const created = await api.post<Application>('/api/applications', {
        name, baseUrl, adapter, config: buildConfig(),
        scanIntervalMinutes: scanIntervalMinutes ? Number(scanIntervalMinutes) : undefined,
      });
      setProgress(p => [...p, 'Discovering attack surface…']);
      const discovered = await api.post<{ endpointCount: number }>(`/api/applications/${created.id}/discover`);
      setProgress(p => [...p, `Discovered ${discovered.endpointCount} endpoint(s). Running first scan…`]);
      const scan = await api.post<{ total: number; vulnerable: number }>(`/api/applications/${created.id}/scan`);
      setProgress(p => [...p, `Scan complete: ${scan.vulnerable}/${scan.total} checks confirmed vulnerable.`]);
      await load();
      setShowForm(false);
      setStep('form');
      setTestResult(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not add application');
      setStep('tested');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-5xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Applications</h1>
        <button
          onClick={() => { setShowForm(s => !s); setStep('form'); setTestResult(null); setError(null); }}
          className="bg-slate-800 hover:bg-slate-700 rounded px-3 py-1.5 text-sm font-semibold"
        >
          {showForm ? 'Cancel' : '+ Add Application'}
        </button>
      </div>

      {showForm && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <p className="text-sm text-slate-400">
            Onboard a new target: connect → test → discover → scan, one guided flow. Pick <strong>juiceshop</strong> (OWASP Juice Shop),{' '}
            <strong>cyberlab</strong> (another CyberLab instance), or <strong>generic</strong> (any REST API with an OpenAPI/Swagger spec — no custom adapter needed).
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Name</label>
              <input className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" value={name} onChange={e => setName(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Adapter</label>
              <select
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm"
                value={adapter}
                onChange={e => { setAdapter(e.target.value as Adapter); setStep('form'); setTestResult(null); }}
              >
                <option value="juiceshop">juiceshop (OWASP Juice Shop)</option>
                <option value="cyberlab">cyberlab</option>
                <option value="generic">generic (OpenAPI-driven, any REST API)</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Base URL</label>
            <input className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" value={baseUrl} onChange={e => { setBaseUrl(e.target.value); setStep('form'); setTestResult(null); }} />
          </div>

          {adapter === 'generic' && (
            <div className="grid grid-cols-3 gap-3 border-t border-slate-800 pt-3">
              <div className="col-span-3">
                <label className="block text-xs text-slate-400 mb-1">OpenAPI/Swagger spec URL</label>
                <input className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" placeholder="https://api.example.com/openapi.json" value={openapiUrl} onChange={e => { setOpenapiUrl(e.target.value); setStep('form'); setTestResult(null); }} />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Auth header name</label>
                <input className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" value={authHeaderName} onChange={e => setAuthHeaderName(e.target.value)} />
              </div>
              <div className="col-span-2">
                <label className="block text-xs text-slate-400 mb-1">Auth header value (optional — static token)</label>
                <input className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" type="password" value={authHeaderValue} onChange={e => setAuthHeaderValue(e.target.value)} />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs text-slate-400 mb-1">Re-scan automatically every (minutes, optional — leave blank for manual-only)</label>
            <input type="number" min={1} className="w-48 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm" value={scanIntervalMinutes} onChange={e => setScanIntervalMinutes(e.target.value)} />
          </div>

          {error && <p className="text-red-400 text-sm">{error}</p>}

          {testResult && (
            <p className={`text-sm ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
              {testResult.ok ? '✓ Reachable' : '✗ Unreachable'} — {testResult.detail}
              {testResult.endpointPreviewCount != null && ` — ${testResult.endpointPreviewCount} endpoint(s) found in spec`}
            </p>
          )}

          {progress.length > 0 && (
            <ul className="text-sm text-slate-400 space-y-1 font-mono">
              {progress.map((line, i) => <li key={i}>› {line}</li>)}
            </ul>
          )}

          <div className="flex gap-3">
            {step === 'form' && (
              <button onClick={testConnection} disabled={busy} className="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
                {busy ? 'Testing…' : 'Test Connection'}
              </button>
            )}
            {step === 'tested' && (
              <button onClick={addAndDiscoverAndScan} disabled={busy} className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
                {busy ? 'Working…' : 'Add → Discover → Scan'}
              </button>
            )}
          </div>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {apps.map(a => (
          <a key={a.id} href={`/applications/${a.id}`} className="flex items-center justify-between px-5 py-4 hover:bg-slate-800/50">
            <div>
              <p className="font-medium">{a.name} <span className="text-xs text-slate-500 font-normal">({a.adapter})</span></p>
              <p className="text-sm text-slate-500">
                {a.baseUrl} · {a.discovered?.endpointCount ?? 0} endpoints
                {a.scanIntervalMinutes ? ` · auto-rescans every ${a.scanIntervalMinutes}min` : ''}
              </p>
            </div>
            <StatusBadge status={a.status} />
          </a>
        ))}
        {apps.length === 0 && <p className="text-slate-500 text-sm px-5 py-4">No applications registered yet. Add one above.</p>}
      </div>
    </div>
  );
}
