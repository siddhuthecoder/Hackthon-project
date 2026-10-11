'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { api, ApiError, downloadFile } from '@/lib/api';
import { Finding } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { AssistantChat } from '@/components/AssistantChat';

interface Explanation {
  summary: string;
  facts: string[];
  inferences: string[];
  uncertainties: string[];
  impact: string;
  recommendations: string[];
  confidence: number;
  mode: string;
}

interface RemediationPlan {
  rootCause: string;
  secureApproach: string;
  patchSummary: string;
  testsRequired: string[];
  verificationSteps: string[];
  mode: string;
  autonomous?: boolean;
}

interface VerifyResult {
  passed: boolean;
  before: unknown;
  after: { status: number; detail: string; blocked: boolean };
}

interface PrResult {
  url: string;
  branch: string;
  file: string;
}

export default function FindingDetailPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [pr, setPr] = useState<PrResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async (): Promise<void> => {
    const data = await api.get<Finding & { proposedRemediation?: { plan: RemediationPlan & { autonomous?: boolean } } | null }>(`/api/findings/${id}`);
    setFinding(data);
    if (data.aiAnalysis) setExplanation(data.aiAnalysis as unknown as Explanation);
    if (data.proposedRemediation?.plan && !plan) setPlan(data.proposedRemediation.plan);
  };

  useEffect(() => {
    load();
  }, [id]);

  const run = async (key: string, fn: () => Promise<void>): Promise<void> => {
    setBusy(key);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Action failed');
    } finally {
      setBusy(null);
    }
  };

  if (!finding) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">{finding.vulnKey} — {finding.title}</h1>
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
        </div>
        <p className="text-slate-500 mt-1">{finding.method} {finding.endpoint} · {finding.cwe} {finding.owasp}</p>
      </div>

      <Section title="Description">{finding.description}</Section>
      <Section title="Impact">{finding.impact}</Section>
      <Section title="Evidence">
        <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-xs overflow-x-auto">{JSON.stringify(finding.evidence, null, 2)}</pre>
      </Section>

      {finding.relatedIncidents && finding.relatedIncidents.length > 0 && (
        <Section title="Related Incidents">
          <ul className="space-y-1">
            {finding.relatedIncidents.map(i => (
              <li key={i.id}><a href={`/incidents/${i.id}`} className="text-emerald-400 hover:underline">{i.title}</a></li>
            ))}
          </ul>
        </Section>
      )}

      <div className="flex gap-3 flex-wrap">
        <ActionButton
          label="AI Analyze"
          busy={busy === 'analyze'}
          onClick={() => run('analyze', async () => setExplanation(await api.post(`/api/findings/${id}/analyze`)))}
        />
        <ActionButton
          label="Generate Remediation"
          busy={busy === 'remediate'}
          onClick={() => run('remediate', async () => setPlan(await api.post(`/api/findings/${id}/remediate`)))}
        />
        <ActionButton
          label="Apply Fix"
          tone="warn"
          busy={busy === 'fix'}
          onClick={() => run('fix', async () => { await api.post(`/api/findings/${id}/apply-fix`); await load(); })}
        />
        <ActionButton
          label="Verify Fix"
          tone="primary"
          busy={busy === 'verify'}
          onClick={() => run('verify', async () => { setVerify(await api.post(`/api/findings/${id}/verify`)); await load(); })}
        />
        <ActionButton
          label="Revert (demo reset)"
          tone="ghost"
          busy={busy === 'revert'}
          onClick={() => run('revert', async () => { await api.post(`/api/findings/${id}/revert-fix`); setVerify(null); await load(); })}
        />
        <ActionButton
          label="Open Fix PR (real GitHub)"
          tone="warn"
          busy={busy === 'pr'}
          onClick={() => run('pr', async () => setPr(await api.post(`/api/findings/${id}/open-pr`)))}
        />
        <ActionButton
          label="Download PDF Report"
          tone="ghost"
          busy={busy === 'report'}
          onClick={() => run('report', () => downloadFile(`/api/findings/${id}/report.pdf`, `${finding.vulnKey}-report.pdf`))}
        />
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {pr && (
        <div className="border border-emerald-700 bg-emerald-950/30 rounded-xl p-5">
          <h2 className="font-semibold mb-2">✅ Pull request opened</h2>
          <p className="text-sm text-slate-300">Branch <code>{pr.branch}</code>, patching <code>{pr.file}</code>.</p>
          <a href={pr.url} target="_blank" rel="noreferrer" className="text-emerald-400 hover:underline text-sm">{pr.url}</a>
        </div>
      )}

      {verify && (
        <div className={`border rounded-xl p-5 ${verify.passed ? 'border-emerald-700 bg-emerald-950/30' : 'border-red-700 bg-red-950/30'}`}>
          <h2 className="font-semibold mb-2">{verify.passed ? '✅ Verification PASSED — attack blocked' : '❌ Still vulnerable'}</h2>
          <p className="text-sm text-slate-300">{verify.after.detail}</p>
        </div>
      )}

      {explanation && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">AI Analysis</h2>
            <span className="text-xs text-slate-500">mode: {explanation.mode}</span>
          </div>
          <p>{explanation.summary}</p>
          <FactList title="Facts" items={explanation.facts} />
          <FactList title="Inferences" items={explanation.inferences} />
          <FactList title="Uncertainties" items={explanation.uncertainties} />
          <p className="text-sm text-slate-400">Confidence: {Math.round(explanation.confidence * 100)}%</p>
        </div>
      )}

      {plan && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Remediation Plan{plan.autonomous && <span className="ml-2 text-xs bg-sky-900/60 text-sky-300 px-2 py-0.5 rounded">proposed automatically</span>}</h2>
            <span className="text-xs text-slate-500">mode: {plan.mode}</span>
          </div>
          <p><span className="text-slate-500">Root cause: </span>{plan.rootCause}</p>
          <p><span className="text-slate-500">Secure approach: </span>{plan.secureApproach}</p>
          <p><span className="text-slate-500">Patch: </span>{plan.patchSummary}</p>
          <FactList title="Tests required" items={plan.testsRequired} />
          <FactList title="Verification steps" items={plan.verificationSteps} />
        </div>
      )}

      <AssistantChat findingId={id} />
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }): React.ReactElement {
  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-400 mb-1">{title}</h2>
      <div className="text-slate-200">{children}</div>
    </div>
  );
}

function FactList({ title, items }: { title: string; items: string[] }): React.ReactElement | null {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <p className="text-xs font-semibold text-slate-500 uppercase mb-1">{title}</p>
      <ul className="list-disc list-inside text-sm text-slate-300 space-y-0.5">
        {items.map((item, i) => <li key={i}>{item}</li>)}
      </ul>
    </div>
  );
}

function ActionButton({
  label, onClick, busy, tone = 'default',
}: { label: string; onClick: () => void; busy: boolean; tone?: 'default' | 'primary' | 'warn' | 'ghost' }): React.ReactElement {
  const styles: Record<string, string> = {
    default: 'bg-slate-800 hover:bg-slate-700',
    primary: 'bg-emerald-600 hover:bg-emerald-500',
    warn: 'bg-amber-700 hover:bg-amber-600',
    ghost: 'bg-transparent border border-slate-700 hover:bg-slate-800',
  };
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={`${styles[tone]} disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold`}
    >
      {busy ? 'Working…' : label}
    </button>
  );
}
