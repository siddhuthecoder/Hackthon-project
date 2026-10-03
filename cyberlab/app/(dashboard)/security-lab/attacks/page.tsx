'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import type { SimulationResult } from '@/lib/types';
import { Play, XCircle, CheckCircle2, AlertCircle, Loader2, Terminal, Activity, ShieldAlert } from 'lucide-react';

const BUTTON_LABELS: Record<string, string> = {
  '01-bruteforce': 'Simulate Brute Force',
  '02-account-takeover': 'Simulate Account Takeover',
  '03-idor': 'Simulate IDOR',
  '04-cross-tenant-access': 'Simulate Cross-Tenant Attack',
  '05-privilege-escalation': 'Simulate Privilege Escalation',
  '06-api-abuse': 'Simulate API Abuse',
  '07-data-exfiltration-simulation': 'Simulate Data Exfiltration',
  '08-suspicious-admin-activity': 'Simulate Suspicious Admin Activity',
  '09-business-logic-abuse': 'Simulate Business Logic Attack',
};

const statusColor = (status: string) =>
  status === 'OPEN' ? 'border-destructive/40 text-destructive' :
  status === 'INVESTIGATING' ? 'border-warning/40 text-warning' :
  status === 'CONTAINED' ? 'border-info/40 text-info' :
  'border-success/40 text-success';

export default function AttackSimulationPage() {
  const scenariosQ = useApi(() => api.scenarios(), []);
  const incidentsQ = useApi(() => api.incidents(), [], 5000);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [completed, setCompleted] = useState<ReadonlyArray<string>>([]);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const runSimulation = async (scenarioId: string) => {
    setRunningId(scenarioId);
    setSimError(null);
    setResult(null);
    try {
      const res = await api.simulate(scenarioId);
      setResult(res);
      setCompleted((prev) => (prev.includes(scenarioId) ? prev : [...prev, scenarioId]));
      incidentsQ.reload();
    } catch (e) {
      setSimError(e instanceof Error ? e.message : 'Simulation failed');
    } finally {
      setRunningId(null);
    }
  };

  if (scenariosQ.loading) return <LoadingState label="Loading scenarios..." />;
  if (scenariosQ.error || !scenariosQ.data) {
    return <ErrorState message={scenariosQ.error ?? 'No data'} onRetry={scenariosQ.reload} />;
  }
  const scenarios = scenariosQ.data;
  const incidents = incidentsQ.data ?? [];
  const busy = runningId !== null;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center justify-center">
            <Terminal className="w-5 h-5 text-destructive" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Attack Simulation</h1>
            <p className="text-muted-foreground text-sm">Run real controlled attacks against the local lab API</p>
          </div>
        </div>
      </div>

      <Card className="border-warning/20 bg-warning/5">
        <CardContent className="p-4 flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-warning shrink-0" />
          <p className="text-sm text-muted-foreground">
            Simulations send real requests to this lab API only (loopback). Each run generates security events,
            triggers SOC detection rules, and creates incidents. A run can take a few seconds.
          </p>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((scenario) => {
          const isRunning = runningId === scenario.id;
          const isComplete = completed.includes(scenario.id);
          return (
            <Card key={scenario.id} className={`transition-all duration-200 ${
              isRunning ? 'border-destructive/40 glow-destructive' :
              isComplete ? 'border-success/30' : 'hover:border-primary/30'
            }`}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-muted-foreground">{scenario.id}</span>
                    {isComplete && <CheckCircle2 className="w-3.5 h-3.5 text-success" />}
                  </div>
                  <Badge variant="outline" className="text-[10px]">{scenario.incidentType}</Badge>
                </div>
                <CardTitle className="text-sm mt-1">{scenario.name}</CardTitle>
                <CardDescription className="text-xs leading-relaxed">{scenario.description}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                  <Badge variant="secondary" className="text-[9px] font-mono">{scenario.mitreTechnique.split(' ')[0]}</Badge>
                  <span className="truncate">{scenario.mitreTactic}</span>
                </div>
                <div className="text-[10px] text-muted-foreground">
                  <span className="text-warning">Detection:</span> {scenario.detectionRule}
                </div>
                <Button
                  size="sm"
                  className="w-full"
                  variant={isComplete ? 'outline' : 'default'}
                  onClick={() => void runSimulation(scenario.id)}
                  disabled={busy}
                >
                  {isRunning ? (
                    <><Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> Running...</>
                  ) : (
                    <><Play className="w-3.5 h-3.5 mr-1.5" /> {BUTTON_LABELS[scenario.id] ?? `Simulate ${scenario.name}`}</>
                  )}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {simError && <ErrorState message={simError} />}

      {result && (
        <Card className="border-primary/30">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" />
                Simulation Output: {result.name}
              </CardTitle>
              <Badge className="bg-success text-success-foreground">
                <CheckCircle2 className="w-3 h-3 mr-1" /> Complete
              </Badge>
            </div>
            <CardDescription>
              Source IP {result.sourceIp} · started {result.startedAt}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              {result.steps.map((step) => (
                <div key={step.step} className="flex items-start gap-3 p-2.5 rounded-lg bg-muted/30">
                  <div className="mt-0.5">
                    {step.status === 'success' ? (
                      <CheckCircle2 className="w-4 h-4 text-success" />
                    ) : (
                      <XCircle className="w-4 h-4 text-destructive" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-muted-foreground">Step {step.step}</span>
                      <span className="text-sm">{step.action}</span>
                    </div>
                    <div className={`text-xs mt-0.5 ${step.status === 'success' ? 'text-success' : 'text-destructive'}`}>
                      {step.result}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-border space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <Activity className="w-4 h-4 text-primary" />
                <span className="text-muted-foreground">Security Events Generated: {result.eventsGenerated}</span>
              </div>

              <div>
                <div className="text-xs font-medium mb-1.5">Detections ({result.detections.length})</div>
                {result.detections.length === 0 && <div className="text-xs text-muted-foreground">No rules fired.</div>}
                <div className="space-y-1">
                  {result.detections.map((d, i) => (
                    <div key={`${d.ruleId}-${i}`} className="flex items-center gap-2 text-xs">
                      <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                      <span className="font-mono text-muted-foreground">{d.ruleId}</span>
                      <span>{d.title}</span>
                      <span className="text-muted-foreground">{d.sourceIp}</span>
                      <Badge variant="outline" className="text-[9px]">{d.created ? 'new incident' : 'existing'}</Badge>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="text-xs font-medium mb-1.5">Incidents ({result.incidents.length})</div>
                {result.incidents.length === 0 && <div className="text-xs text-muted-foreground">No incidents created.</div>}
                <div className="space-y-2">
                  {result.incidents.map((inc) => (
                    <div key={inc.id} className="flex items-center gap-3 p-2.5 rounded-lg border border-border">
                      <AlertCircle className={`w-4 h-4 shrink-0 ${inc.severity === 'critical' ? 'text-destructive' : 'text-warning'}`} />
                      <Link href="/incidents" className="text-sm font-medium hover:underline">{inc.title}</Link>
                      <span className="text-[10px] font-mono text-muted-foreground">{inc.id}</span>
                      <div className="flex-1 max-w-[160px]">
                        <Progress value={inc.confidence * 100} className="h-1.5" />
                      </div>
                      <span className="text-[10px] text-muted-foreground">{(inc.confidence * 100).toFixed(0)}%</span>
                      <Badge variant="outline" className={`text-[10px] ${statusColor(inc.status)}`}>{inc.status}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Incidents</CardTitle>
          <CardDescription>
            Live from the API (refreshes every 5s). <Link href="/incidents" className="underline">View all incidents</Link>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {incidentsQ.error && <ErrorState message={incidentsQ.error} onRetry={incidentsQ.reload} />}
          {incidents.length === 0 && !incidentsQ.error && (
            <p className="text-sm text-muted-foreground">No incidents yet.</p>
          )}
          {incidents.slice(0, 8).map((inc) => (
            <div key={inc.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
              <AlertCircle className={`w-4 h-4 shrink-0 ${inc.severity === 'critical' ? 'text-destructive' : 'text-warning'}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{inc.title}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">{inc.id}</span>
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  {inc.sourceIp} · {inc.detectedAt.slice(11, 19)} · {(inc.confidence * 100).toFixed(0)}% confidence
                </div>
              </div>
              <Badge variant="outline" className={`text-[10px] shrink-0 ${statusColor(inc.status)}`}>{inc.status}</Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
