'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { IncidentStatus } from '@/lib/types';
import { AlertTriangle, ChevronDown, ChevronUp, Target, Lightbulb } from 'lucide-react';

const severityColors: Record<string, string> = {
  critical: 'border-destructive/40 text-destructive bg-destructive/5',
  high: 'border-warning/40 text-warning bg-warning/5',
  medium: 'border-info/40 text-info bg-info/5',
  low: 'border-success/40 text-success bg-success/5',
};

const statusColors: Record<string, string> = {
  OPEN: 'border-destructive/40 text-destructive',
  INVESTIGATING: 'border-warning/40 text-warning',
  CONTAINED: 'border-info/40 text-info',
  RESOLVED: 'border-success/40 text-success',
  FALSE_POSITIVE: 'border-muted-foreground/40 text-muted-foreground',
};

const STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

export default function IncidentsPage() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const incidentsQ = useApi(() => api.incidents(), [], 5000);
  const rulesQ = useApi(() => api.detectionRules(), []);

  if (incidentsQ.loading || rulesQ.loading) return <LoadingState label="Loading incidents..." />;
  const err = incidentsQ.error ?? rulesQ.error;
  if (err || !incidentsQ.data || !rulesQ.data) {
    return <ErrorState message={err ?? 'No data'} onRetry={() => { incidentsQ.reload(); rulesQ.reload(); }} />;
  }
  const incidents = incidentsQ.data;
  const detectionRules = rulesQ.data;

  const changeStatus = async (id: string, status: IncidentStatus) => {
    setActionError(null);
    try {
      await api.updateIncidentStatus(id, status);
      incidentsQ.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Status update failed');
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-destructive" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Security Incidents</h1>
            <p className="text-muted-foreground text-sm">Incidents detected by SOC rules engine</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Open', value: incidents.filter(i => i.status === 'OPEN').length, color: 'text-destructive' },
          { label: 'Investigating', value: incidents.filter(i => i.status === 'INVESTIGATING').length, color: 'text-warning' },
          { label: 'Contained', value: incidents.filter(i => i.status === 'CONTAINED').length, color: 'text-info' },
          { label: 'Total', value: incidents.length, color: 'text-primary' },
        ].map(stat => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {actionError && <ErrorState message={actionError} />}
      {incidents.length === 0 && <p className="text-sm text-muted-foreground">No incidents yet. Run an attack simulation to generate some.</p>}

      <div className="space-y-3">
        {incidents.map(inc => (
          <Card key={inc.id} className={`${severityColors[inc.severity]} border`}>
            <CardHeader
              className="cursor-pointer"
              onClick={() => setExpanded(expanded === inc.id ? null : inc.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <AlertTriangle className={`w-5 h-5 ${inc.severity === 'critical' ? 'text-destructive' : 'text-warning'}`} />
                  <div>
                    <CardTitle className="text-base">{inc.title}</CardTitle>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] font-mono text-muted-foreground">{inc.id}</span>
                      <span className="text-[10px] text-muted-foreground">{inc.detectedAt}</span>
                      <span className="text-[10px] text-muted-foreground">IP: {inc.sourceIp}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[10px] ${statusColors[inc.status]}`}>{inc.status}</Badge>
                  <Badge variant="outline" className={`text-[10px] ${severityColors[inc.severity]}`}>{inc.severity}</Badge>
                  {expanded === inc.id ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                </div>
              </div>
            </CardHeader>
            {expanded === inc.id && (
              <CardContent className="space-y-4 pt-0 border-t border-border">
                <div>
                  <div className="text-xs font-medium mb-1.5 flex items-center gap-1.5"><Target className="w-3.5 h-3.5" /> Attack Path</div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {inc.attackPath.map((step, i, arr) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <span className="text-xs px-2 py-1 rounded-md bg-muted/50 border border-border">{step}</span>
                        {i < arr.length - 1 && <span className="text-muted-foreground text-xs">→</span>}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs font-medium mb-1.5">Assets Affected</div>
                    <div className="space-y-1">
                      {inc.assets.map(a => (
                        <div key={a} className="text-xs font-mono px-2 py-1 rounded-md bg-muted/30 border border-border">{a}</div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs font-medium mb-1.5">Linked Findings</div>
                    <div className="space-y-1">
                      {inc.findings.map(f => (
                        <Badge key={f} variant="outline" className="text-[10px] font-mono">{f}</Badge>
                      ))}
                    </div>
                  </div>
                </div>

                <div>
                  <div className="text-xs font-medium mb-1.5 flex items-center gap-1.5"><Lightbulb className="w-3.5 h-3.5" /> Recommended Actions</div>
                  <ul className="space-y-1">
                    {inc.recommendedActions.map((a, i) => (
                      <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                        <span className="text-success mt-0.5">•</span>
                        {a}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs font-medium mb-1">Confidence Score</div>
                    <Progress value={inc.confidence * 100} className="h-2" />
                    <div className="text-[10px] text-muted-foreground mt-1">{(inc.confidence * 100).toFixed(0)}%</div>
                  </div>
                  <div>
                    <div className="text-xs font-medium mb-1">MITRE ATT&CK</div>
                    <div className="text-xs text-muted-foreground">{inc.mitreTactic}</div>
                    <div className="text-[10px] font-mono text-muted-foreground">{inc.mitreTechnique}</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-2">
                  <span className="text-xs font-medium">Status</span>
                  <Select value={inc.status} onValueChange={(v) => void changeStatus(inc.id, v as IncidentStatus)}>
                    <SelectTrigger className="w-[200px] h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {STATUSES.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            )}
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">SOC Detection Rules</CardTitle>
          <CardDescription>Rules engine that triggers incident creation</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {detectionRules.map(rule => (
            <div key={rule.id} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border">
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs font-mono text-muted-foreground">{rule.id}</span>
                <Badge variant="outline" className={`text-[9px] ${severityColors[rule.severity]}`}>{rule.severity}</Badge>
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">{rule.name}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{rule.description}</div>
                <div className="text-[10px] font-mono text-muted-foreground mt-1 bg-muted/50 px-2 py-1 rounded">{rule.condition}</div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Badge variant="secondary" className="text-[9px]">{rule.incidentType}</Badge>
                {rule.enabled && <div className="w-2 h-2 rounded-full bg-success" />}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
