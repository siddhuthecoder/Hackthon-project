'use client';

import { useRef, useState } from 'react';
import { api } from '@/lib/api';
import { Application } from '@/lib/types';

interface Step {
  label: string;
  status: 'pending' | 'running' | 'done' | 'error';
  detail?: string;
}

const sleep = (ms: number): Promise<void> => new Promise(r => setTimeout(r, ms));

/** One button, the full hero loop narrated in sequence, every call a real request against the
 * live stack — no canned data, no fake timers standing in for real work. Pacing between steps is
 * presentation only; nothing here is simulated that isn't already a real feature elsewhere. */
export default function AttackTheaterPage(): React.ReactElement {
  const [steps, setSteps] = useState<Step[]>([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const run = async (): Promise<void> => {
    setRunning(true);
    const local: Step[] = [];
    setSteps(local);
    let idx = 0;

    const addStep = (label: string): number => {
      local.push({ label, status: 'running' });
      setSteps([...local]);
      return local.length - 1;
    };
    const finishStep = (i: number, detail: string, ok = true): void => {
      local[i] = { ...local[i], status: ok ? 'done' : 'error', detail };
      setSteps([...local]);
    };

    try {
      idx = addStep('Connecting to target (CyberLab School SaaS)');
      let app: Application;
      const existing = await api.get<Application[]>('/api/applications');
      const found = existing.find(a => a.adapter === 'cyberlab');
      if (found) {
        app = found;
      } else {
        app = await api.post<Application>('/api/applications', { name: 'Attack Theater Run', baseUrl: 'http://host.docker.internal:3001' });
      }
      finishStep(idx, `Target: ${app.name} (${app.baseUrl})`);
      await sleep(600);

      idx = addStep('Discovering attack surface');
      const disc = await api.post<{ endpointCount: number }>(`/api/applications/${app.id}/discover`);
      finishStep(idx, `${disc.endpointCount} endpoints discovered`);
      await sleep(600);

      idx = addStep('Scanning for real vulnerabilities (14 live exploit checks)');
      const scan = await api.post<{ total: number; vulnerable: number }>(`/api/applications/${app.id}/scan`);
      finishStep(idx, `${scan.vulnerable}/${scan.total} checks confirmed vulnerable`);
      await sleep(800);

      idx = addStep('🔴 Launching real IDOR attack simulation against the live target');
      await api.post(`/api/applications/${app.id}/simulate/03-idor`);
      finishStep(idx, 'Attack executed — real HTTP requests sent');
      await sleep(1500);

      idx = addStep('SOC detection pipeline picking up the live attack');
      let incident: { id: string; title: string } | undefined;
      for (let attempt = 0; attempt < 6 && !incident; attempt += 1) {
        await sleep(1000);
        const incidents = await api.get<{ id: string; title: string; detectedAt: string }[]>('/api/incidents');
        incident = incidents.find(i => i.title === 'Possible IDOR Attack');
      }
      if (!incident) throw new Error('No incident detected — the SOC pipeline may still be processing.');
      finishStep(idx, `Incident created: "${incident.title}"`);
      await sleep(600);

      idx = addStep('AI investigating the incident live');
      const investigation = await api.post<{ summary: string; mode: string }>(`/api/incidents/${incident.id}/investigate`);
      finishStep(idx, `"${investigation.summary}" (mode: ${investigation.mode})`);
      await sleep(800);

      idx = addStep('Rendering the real attack graph');
      const graph = await api.get<{ nodes: unknown[]; summary: string }>(`/api/incidents/${incident.id}/attack-graph`);
      finishStep(idx, `${graph.nodes.length} nodes — ${graph.summary}`);
      await sleep(800);

      idx = addStep('🤖 Running autonomous red-team chain analysis');
      const redTeam = await api.post<{ narrative: string; chainSteps: unknown[] }>(`/api/applications/${app.id}/red-team`);
      finishStep(idx, redTeam.chainSteps.length > 0 ? redTeam.narrative : 'Not enough findings for a chain yet.');
      await sleep(1000);

      idx = addStep('Locating the correlated finding to fix');
      const findings = await api.get<{ id: string; vulnKey: string; status: string }[]>('/api/findings');
      const finding = findings.find(f => f.vulnKey === 'VULN-001');
      if (!finding) throw new Error('VULN-001 finding not found.');
      finishStep(idx, `${finding.vulnKey} — currently ${finding.status}`);
      await sleep(600);

      idx = addStep('Applying the real fix');
      await api.post(`/api/findings/${finding.id}/apply-fix`);
      finishStep(idx, 'Fix applied to the live target');
      await sleep(800);

      idx = addStep('Verifying the fix with a real re-attack attempt');
      const verify = await api.post<{ passed: boolean; after: { status: number } }>(`/api/findings/${finding.id}/verify`);
      finishStep(idx, verify.passed ? `✅ Blocked — attack now returns HTTP ${verify.after.status}` : '❌ Still vulnerable', verify.passed);
      await sleep(600);

      idx = addStep('Reverting fix (repeatable demo state)');
      await api.post(`/api/findings/${finding.id}/revert-fix`);
      finishStep(idx, 'Done — ready to run again');
    } catch (err) {
      finishStep(idx, err instanceof Error ? err.message : 'Unexpected error', false);
    } finally {
      setRunning(false);
      setTimeout(() => logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' }), 100);
    }
  };

  return (
    <div className="max-w-3xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Attack Theater</h1>
        <p className="text-slate-500 text-sm mt-1">
          One button, the whole system working end to end — real scan, real attack, real AI investigation, real autonomous
          chain analysis, real fix, real verification. Every step below is a genuine API call, not a script.
        </p>
      </div>

      <button
        onClick={run}
        disabled={running}
        className="bg-red-700 hover:bg-red-600 disabled:opacity-50 rounded px-6 py-3 text-base font-bold w-full"
      >
        {running ? '▶ Running…' : '▶ Run Full Attack Theater'}
      </button>

      <div ref={logRef} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3 max-h-[60vh] overflow-y-auto">
        {steps.length === 0 && <p className="text-slate-600 text-sm">Press the button. Every step runs for real.</p>}
        {steps.map((s, i) => (
          <div key={i} className="flex gap-3">
            <span className="mt-0.5">
              {s.status === 'running' && <span className="inline-block w-4 h-4 rounded-full border-2 border-amber-400 border-t-transparent animate-spin" />}
              {s.status === 'done' && <span className="text-emerald-400">✓</span>}
              {s.status === 'error' && <span className="text-red-400">✗</span>}
            </span>
            <div>
              <p className={`text-sm font-medium ${s.status === 'error' ? 'text-red-400' : 'text-slate-200'}`}>{s.label}</p>
              {s.detail && <p className="text-xs text-slate-500 mt-0.5">{s.detail}</p>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
