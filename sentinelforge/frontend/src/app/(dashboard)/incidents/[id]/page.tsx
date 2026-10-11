'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { api, ApiError, downloadFile } from '@/lib/api';
import { AttackGraph, IncidentComment, IncidentDetail, IpReputation, OrgUser } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { AttackGraphView } from '@/components/AttackGraphView';
import { AssistantChat } from '@/components/AssistantChat';

interface ResponseActionItem {
  id: string;
  action: string;
  target?: string;
  status: string;
  highImpact: boolean;
  createdAt: string;
  approvedBy?: string;
  requestedBy?: string;
  details?: { note?: string; ticketKey?: string; ticketUrl?: string; error?: string; riskScore?: number };
}

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

export default function IncidentDetailPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [actions, setActions] = useState<ResponseActionItem[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [comments, setComments] = useState<IncidentComment[]>([]);
  const [orgUsers, setOrgUsers] = useState<OrgUser[]>([]);
  const [commentText, setCommentText] = useState('');
  const [ipReputation, setIpReputation] = useState<IpReputation | null>(null);

  const load = async (): Promise<void> => {
    const [inc, g, acts, cmts, users, ipRep] = await Promise.all([
      api.get<IncidentDetail>(`/api/incidents/${id}`),
      api.get<AttackGraph>(`/api/incidents/${id}/attack-graph`),
      api.get<ResponseActionItem[]>(`/api/incidents/${id}/response-actions`),
      api.get<IncidentComment[]>(`/api/incidents/${id}/comments`),
      api.get<OrgUser[]>('/api/org/users'),
      api.get<IpReputation>(`/api/incidents/${id}/ip-reputation`),
    ]);
    setIncident(inc);
    setGraph(g);
    setActions(acts);
    setComments(cmts);
    setIpReputation(ipRep);
    setOrgUsers(users);
    if (inc.investigation) setInvestigation(inc.investigation as unknown as Investigation);
  };

  useEffect(() => {
    load();
  }, [id]);

  const investigate = async (): Promise<void> => {
    setBusy('investigate');
    setError(null);
    try {
      setInvestigation(await api.post(`/api/incidents/${id}/investigate`));
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Investigation failed');
    } finally {
      setBusy(null);
    }
  };

  const respond = async (action: string, target?: string): Promise<void> => {
    setBusy(action);
    setError(null);
    try {
      await api.post(`/api/incidents/${id}/respond`, { action, target });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Action failed');
    } finally {
      setBusy(null);
    }
  };

  const approve = async (actionId: string): Promise<void> => {
    setBusy(`approve-${actionId}`);
    setError(null);
    try {
      await api.post(`/api/response-actions/${actionId}/approve`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Approval failed');
    } finally {
      setBusy(null);
    }
  };

  const assign = async (userId: string): Promise<void> => {
    setBusy('assign');
    setError(null);
    try {
      await api.patch(`/api/incidents/${id}/assign`, { userId: userId || null });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Assign failed');
    } finally {
      setBusy(null);
    }
  };

  const postComment = async (): Promise<void> => {
    if (!commentText.trim()) return;
    setBusy('comment');
    setError(null);
    try {
      await api.post(`/api/incidents/${id}/comments`, { text: commentText.trim() });
      setCommentText('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Comment failed');
    } finally {
      setBusy(null);
    }
  };

  if (!incident) return <p className="text-slate-500">Loading…</p>;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">{incident.title}</h1>
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
        </div>
        <p className="text-slate-500 mt-1">
          Rule {incident.rule} · subject {incident.subject} · {incident.sourceIp} · {new Date(incident.detectedAt).toLocaleString()}
        </p>
        {incident.postmortemUrl && (
          <a href={incident.postmortemUrl} target="_blank" rel="noreferrer" className="text-xs text-emerald-400 hover:underline block mt-1">
            Postmortem published to Confluence →
          </a>
        )}
        {ipReputation && (
          <p className="text-xs mt-1">
            {!ipReputation.available && <span className="text-slate-600">IP reputation: {ipReputation.reason}</span>}
            {ipReputation.available && ipReputation.isPublic === false && <span className="text-slate-600">IP reputation: private/internal address, no public reputation data</span>}
            {ipReputation.available && ipReputation.isPublic && (
              <span className={ipReputation.abuseConfidenceScore && ipReputation.abuseConfidenceScore > 25 ? 'text-red-400' : 'text-emerald-400'}>
                AbuseIPDB: {ipReputation.abuseConfidenceScore}% confidence of abuse · {ipReputation.totalReports} report(s)
                {ipReputation.countryCode ? ` · ${ipReputation.countryCode}` : ''}{ipReputation.isp ? ` · ${ipReputation.isp}` : ''}
              </span>
            )}
          </p>
        )}
        <div className="flex items-center gap-2 mt-2">
          <span className="text-sm text-slate-500">Assigned to:</span>
          <select
            value={incident.assignedTo ?? ''}
            onChange={e => assign(e.target.value)}
            disabled={busy === 'assign'}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm"
          >
            <option value="">Unassigned</option>
            {orgUsers.map(u => (
              <option key={u.id} value={u.id}>{u.name}</option>
            ))}
          </select>
        </div>
      </div>

      {incident.findings.length > 0 && (
        <div className="bg-emerald-950/30 border border-emerald-800 rounded-xl p-4">
          <p className="text-sm text-emerald-300 font-semibold mb-1">Correlated Known Vulnerability</p>
          {incident.correlations.map(c => (
            <p key={c.id} className="text-sm text-slate-300">{c.reason}</p>
          ))}
          <div className="flex gap-2 mt-2">
            {incident.findings.map(f => (
              <a key={f.id} href={`/findings/${f.id}`} className="text-xs bg-slate-800 px-2 py-1 rounded hover:bg-slate-700">{f.vulnKey}</a>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-3 flex-wrap">
        <button onClick={investigate} disabled={busy === 'investigate'} className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy === 'investigate' ? 'Investigating…' : 'Investigate with AI'}
        </button>
        <a href={`/incidents/${id}/investigation`} className="bg-transparent border border-slate-700 hover:bg-slate-800 rounded px-4 py-2 text-sm font-semibold inline-block">
          Full Investigation Page
        </a>
        <button onClick={() => respond('revoke_session')} disabled={busy === 'revoke_session'} className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          Revoke Session
        </button>
        <button onClick={() => respond('mark_contained')} disabled={busy === 'mark_contained'} className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          Mark Contained
        </button>
        <button
          onClick={() => respond('block_ip', incident.sourceIp)}
          disabled={busy === 'block_ip' || !incident.sourceIp}
          className="bg-amber-800 hover:bg-amber-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
          title="High-impact action — requires approval before it executes"
        >
          Block IP (needs approval)
        </button>
        <button onClick={() => respond('generate_ticket')} disabled={busy === 'generate_ticket'} className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold">
          {busy === 'generate_ticket' ? 'Creating…' : 'Create Jira Ticket'}
        </button>
        <button
          onClick={async () => {
            setBusy('postmortem');
            setError(null);
            try {
              await api.post(`/api/incidents/${id}/postmortem`);
              await load();
            } catch (err) {
              setError(err instanceof ApiError ? err.message : 'Publish failed');
            } finally {
              setBusy(null);
            }
          }}
          disabled={busy === 'postmortem'}
          className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
        >
          {busy === 'postmortem' ? 'Publishing…' : 'Publish Postmortem (Confluence)'}
        </button>
        <button
          onClick={async () => {
            setBusy('report');
            setError(null);
            try {
              await downloadFile(`/api/incidents/${id}/report.pdf`, `incident-${id}-report.pdf`);
            } catch (err) {
              setError(err instanceof ApiError ? err.message : 'Download failed');
            } finally {
              setBusy(null);
            }
          }}
          disabled={busy === 'report'}
          className="bg-transparent border border-slate-700 hover:bg-slate-800 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
        >
          {busy === 'report' ? 'Preparing…' : 'Download PDF Report'}
        </button>
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {actions.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="font-semibold mb-3">Response Actions</h2>
          <div className="divide-y divide-slate-800">
            {actions.map(a => (
              <div key={a.id} className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm text-slate-200">
                    {a.action}{a.target ? ` → ${a.target}` : ''}
                    {a.requestedBy === 'system:soar-playbook' && (
                      <span className="ml-2 text-xs bg-purple-900/60 text-purple-300 px-2 py-0.5 rounded">
                        🤖 autonomous{a.details?.riskScore ? ` · risk ${a.details.riskScore}` : ''}
                      </span>
                    )}
                  </p>
                  <p className="text-xs text-slate-500">{new Date(a.createdAt).toLocaleString()}{a.highImpact ? ' · high-impact' : ''}</p>
                  {a.details?.ticketUrl && (
                    <a href={a.details.ticketUrl} target="_blank" rel="noreferrer" className="text-xs text-emerald-400 hover:underline">
                      {a.details.ticketKey} (real Jira ticket) →
                    </a>
                  )}
                  {a.details?.note && !a.details.ticketUrl && (
                    <p className="text-xs text-slate-600">{a.details.note}</p>
                  )}
                </div>
                {a.status === 'PENDING_APPROVAL' ? (
                  <button
                    onClick={() => approve(a.id)}
                    disabled={busy === `approve-${a.id}`}
                    className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-3 py-1 text-xs font-semibold"
                  >
                    {busy === `approve-${a.id}` ? 'Approving…' : 'Approve'}
                  </button>
                ) : (
                  <StatusBadge status={a.status} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {investigation && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">AI Investigation</h2>
            <span className="text-xs text-slate-500">mode: {investigation.mode}</span>
          </div>
          <p className="text-emerald-300 font-medium">{investigation.summary}</p>
          <List title="Facts" items={investigation.facts} />
          <p className="text-sm"><span className="text-slate-500">Attack path: </span>{investigation.attackPath}</p>
          <p className="text-sm"><span className="text-slate-500">Impact: </span>{investigation.impact}</p>
          <List title="Inferences" items={investigation.inferences} />
          <List title="Uncertainties" items={investigation.uncertainties} />
          <List title="Recommended Actions" items={investigation.recommendedActions} />
          <p className="text-sm text-slate-400">Confidence: {Math.round(investigation.confidence * 100)}%</p>
        </div>
      )}

      {graph && graph.nodes.length > 0 && (
        <div>
          <h2 className="font-semibold mb-2">Attack Graph</h2>
          <p className="text-sm text-slate-400 mb-2">{graph.summary}</p>
          <AttackGraphView graph={graph} />
        </div>
      )}

      <div>
        <h2 className="font-semibold mb-2">Event Timeline ({incident.events.length})</h2>
        <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800 max-h-80 overflow-y-auto">
          {incident.events.map(e => (
            <div key={e.id} className="px-4 py-2 text-sm flex justify-between">
              <span className="text-slate-300">{e.eventType}{e.endpoint ? ` · ${e.endpoint}` : ''}</span>
              <span className="text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      </div>
      <AssistantChat incidentId={id} />

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="font-semibold mb-3">Comments</h2>
        <div className="space-y-3 mb-4 max-h-80 overflow-y-auto">
          {comments.map(c => (
            <div key={c.id} className="text-sm">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-200">{c.authorName}</span>
                <span className="text-xs text-slate-500">{new Date(c.createdAt).toLocaleString()}</span>
              </div>
              <p className="text-slate-300 whitespace-pre-wrap">{c.text}</p>
            </div>
          ))}
          {comments.length === 0 && <p className="text-slate-500 text-sm">No comments yet.</p>}
        </div>
        <div className="flex gap-2">
          <input
            value={commentText}
            onChange={e => setCommentText(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') postComment(); }}
            placeholder="Add a comment…"
            className="flex-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={postComment}
            disabled={busy === 'comment' || !commentText.trim()}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded px-4 py-2 text-sm font-semibold"
          >
            Post
          </button>
        </div>
      </div>
    </div>
  );
}

function List({ title, items }: { title: string; items: string[] }): React.ReactElement | null {
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
