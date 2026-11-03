'use client';

import { useEffect, useState } from 'react';
import { api, ApiError, downloadFile } from '@/lib/api';
import { Application, Finding, Incident } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { PostureTrendChart } from '@/components/PostureTrendChart';

interface PostureMetrics {
  scanHistory: { startedAt: string; findingsOpen: number; checksTotal: number }[];
  avgTimeToFixHours: number | null;
  findingsVerified: number;
}

export default function DashboardPage(): React.ReactElement {
  const [apps, setApps] = useState<Application[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<PostureMetrics | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const downloadExecSummary = async (): Promise<void> => {
    setReportBusy(true);
    setReportError(null);
    try {
      await downloadFile('/api/reports/executive-summary.pdf', 'executive-summary.pdf');
    } catch (err) {
      setReportError(err instanceof ApiError ? err.message : 'Download failed');
    } finally {
      setReportBusy(false);
    }
  };

  const load = async (): Promise<void> => {
    const [a, f, i, m] = await Promise.all([
      api.get<Application[]>('/api/applications'),
      api.get<Finding[]>('/api/findings'),
      api.get<Incident[]>('/api/incidents'),
      api.get<PostureMetrics>('/api/metrics/posture'),
    ]);
    setApps(a);
    setFindings(f);
    setIncidents(i);
    setMetrics(m);
  };

  useEffect(() => {
    load();
  }, []);

  const addAndScan = async (): Promise<void> => {
    setBusy(true);
    setLog([]);
    try {
      setLog(l => [...l, 'Registering CyberLab School SaaS…']);
      const app = await api.post<Application>('/api/applications', { name: 'CyberLab School SaaS', baseUrl: 'http://host.docker.internal:3001' });
      setLog(l => [...l, 'Discovering endpoints…']);
      const discovered = await api.post<{ endpointCount: number }>(`/api/applications/${app.id}/discover`);
      setLog(l => [...l, `Discovered ${discovered.endpointCount} endpoints. Running security scan…`]);
      const scan = await api.post<{ total: number; vulnerable: number }>(`/api/applications/${app.id}/scan`);
      setLog(l => [...l, `Scan complete: ${scan.vulnerable}/${scan.total} checks confirmed vulnerable.`]);
      await load();
    } catch (err) {
      setLog(l => [...l, `Error: ${err instanceof Error ? err.message : 'unknown'}`]);
    } finally {
      setBusy(false);
    }
  };

  const bySeverity = (sev: string): number => findings.filter(f => f.severity === sev && f.status !== 'VERIFIED').length;
  const openIncidents = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING');

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Posture</h1>
        {apps.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              onClick={downloadExecSummary}
              disabled={reportBusy}
              className="bg-transparent border border-slate-700 hover:bg-slate-800 disabled:opacity-50 rounded px-3 py-1.5 text-sm font-semibold"
            >
              {reportBusy ? 'Preparing…' : 'Download Executive Summary'}
            </button>
          </div>
        )}
      </div>
      {reportError && <p className="text-red-400 text-sm">{reportError}</p>}

      {apps.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-slate-400 mb-4">No application connected yet. Connect CyberLab to discover and scan it.</p>
          <button
            onClick={addAndScan}
            disabled={busy}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
          >
            {busy ? 'Working…' : 'Connect CyberLab & Run Scan'}
          </button>
          {log.length > 0 && (
            <ul className="mt-4 text-sm text-slate-400 space-y-1 font-mono">
              {log.map((line, i) => <li key={i}>› {line}</li>)}
            </ul>
          )}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-5 gap-4">
            <StatCard label="Critical" value={bySeverity('critical')} tone="critical" />
            <StatCard label="High" value={bySeverity('high')} tone="high" />
            <StatCard label="Open Incidents" value={openIncidents.length} tone="high" />
            <StatCard label="Applications" value={apps.length} tone="low" />
            <StatCard
              label="Avg Time to Fix"
              value={metrics?.avgTimeToFixHours != null ? Math.round(metrics.avgTimeToFixHours * 10) / 10 : 0}
              tone="low"
              suffix={metrics?.avgTimeToFixHours != null ? 'h' : ' (none verified yet)'}
            />
          </div>

          {metrics && metrics.scanHistory.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="font-semibold mb-1">Security Posture Trend</h2>
              <p className="text-xs text-slate-500 mb-2">Open findings across {metrics.scanHistory.length} real scan run(s)</p>
              <PostureTrendChart data={metrics.scanHistory} />
            </div>
          )}

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="font-semibold mb-3">Recent Incidents</h2>
            {incidents.slice(0, 5).map(i => (
              <div key={i.id} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                <a href={`/incidents/${i.id}`} className="text-slate-200 hover:text-emerald-400">{i.title}</a>
                <div className="flex gap-2 items-center">
                  <span className="text-xs text-slate-500">{i.subject}</span>
                  <SeverityBadge severity={i.severity} />
                  <StatusBadge status={i.status} />
                </div>
              </div>
            ))}
            {incidents.length === 0 && <p className="text-slate-500 text-sm">No incidents yet. Run an attack from Security Lab.</p>}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="font-semibold mb-3">Top Findings</h2>
            {findings.slice(0, 5).map(f => (
              <div key={f.id} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                <a href={`/findings/${f.id}`} className="text-slate-200 hover:text-emerald-400">{f.vulnKey} — {f.title}</a>
                <div className="flex gap-2 items-center">
                  <SeverityBadge severity={f.severity} />
                  <StatusBadge status={f.status} />
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ label, value, tone, suffix }: { label: string; value: number; tone: 'critical' | 'high' | 'low'; suffix?: string }): React.ReactElement {
  const color = tone === 'critical' ? 'text-red-400' : tone === 'high' ? 'text-orange-400' : 'text-emerald-400';
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <p className="text-slate-500 text-sm">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}{suffix && <span className="text-sm text-slate-500 font-normal ml-1">{suffix}</span>}</p>
    </div>
  );
}
