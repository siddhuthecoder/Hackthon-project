'use client';

import { Shield, Users, Building2, AlertTriangle, Activity, Bug, TrendingUp, Server, Database, Cpu } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import type { SecurityEvent, Vulnerability } from '@/lib/types';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid, BarChart, Bar } from 'recharts';

const POLL_MS = 5000;

function buildTimeline(events: SecurityEvent[]) {
  const now = Date.now();
  const buckets = Array.from({ length: 24 }, (_, i) => {
    const start = new Date(now - (23 - i) * 3600_000);
    return { hour: `${String(start.getHours()).padStart(2, '0')}:00`, startMs: now - (23 - i + 1) * 3600_000, events: 0, critical: 0 };
  });
  return buckets.map((b) => {
    const inBucket = events.filter((e) => {
      const ts = new Date(e.timestamp).getTime();
      return ts > b.startMs && ts <= b.startMs + 3600_000;
    });
    return { hour: b.hour, events: inBucket.length, critical: inBucket.filter((e) => e.severity === 'critical').length };
  });
}

function buildSeverity(vulns: Vulnerability[]) {
  const count = (s: string) => vulns.filter((v) => v.severity === s).length;
  return [
    { name: 'Critical', count: count('critical'), fill: 'hsl(var(--destructive))' },
    { name: 'High', count: count('high'), fill: 'hsl(var(--warning))' },
    { name: 'Medium', count: count('medium'), fill: 'hsl(var(--info))' },
    { name: 'Low', count: count('low'), fill: 'hsl(var(--success))' },
  ];
}

export default function DashboardPage() {
  const status = useApi(() => api.demoStatus(), [], POLL_MS);
  const eventsQ = useApi(() => api.events({ limit: 500 }), [], POLL_MS);
  const incidentsQ = useApi(() => api.incidents(), [], POLL_MS);
  const findingsQ = useApi(() => api.findings(), []);

  if (status.loading || eventsQ.loading || incidentsQ.loading || findingsQ.loading) {
    return <LoadingState label="Loading live dashboard..." />;
  }
  const firstError = status.error ?? eventsQ.error ?? incidentsQ.error ?? findingsQ.error;
  if (firstError || !status.data || !eventsQ.data || !incidentsQ.data || !findingsQ.data) {
    return <ErrorState message={firstError ?? 'No data'} onRetry={() => { status.reload(); eventsQ.reload(); incidentsQ.reload(); findingsQ.reload(); }} />;
  }

  const labStats = status.data;
  const eventTimelineData = buildTimeline(eventsQ.data);
  const severityData = buildSeverity(findingsQ.data);
  const recentEvents = eventsQ.data.slice(0, 8);
  const recentIncidents = incidentsQ.data.filter((i) => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').slice(0, 3);
  const stats = [
    { label: 'Vulnerabilities', value: labStats.vulnerabilityCount, icon: Bug, color: 'text-destructive', bg: 'bg-destructive/10', border: 'border-destructive/20' },
    { label: 'Tenants', value: labStats.tenantCount, icon: Building2, color: 'text-primary', bg: 'bg-primary/10', border: 'border-primary/20' },
    { label: 'Users', value: labStats.userCount, icon: Users, color: 'text-success', bg: 'bg-success/10', border: 'border-success/20' },
    { label: 'Security Events', value: labStats.securityEventCount, icon: Activity, color: 'text-warning', bg: 'bg-warning/10', border: 'border-warning/20' },
    { label: 'Incidents', value: labStats.incidentCount, icon: AlertTriangle, color: 'text-destructive', bg: 'bg-destructive/10', border: 'border-destructive/20' },
    { label: 'Attack Scenarios', value: labStats.attackScenarioCount, icon: TrendingUp, color: 'text-info', bg: 'bg-info/10', border: 'border-info/20' },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security Operations Dashboard</h1>
        <p className="text-muted-foreground text-sm mt-1">Overview of the SentinelForge Lab environment</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} className={`${stat.bg} ${stat.border} border`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <Icon className={`w-5 h-5 ${stat.color}`} />
                </div>
                <div className="text-2xl font-bold">{stat.value}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{stat.label}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Security Events (24h)</CardTitle>
            <CardDescription>Event volume over the last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={eventTimelineData}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--destructive))" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="hsl(var(--destructive))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="hour" stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="events" stroke="hsl(var(--primary))" strokeWidth={2} fill="url(#eventGradient)" />
                <Area type="monotone" dataKey="critical" stroke="hsl(var(--destructive))" strokeWidth={2} fill="url(#criticalGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Vulnerability Severity</CardTitle>
            <CardDescription>Distribution by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Security Events</CardTitle>
            <CardDescription>Latest security telemetry from the lab</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentEvents.map((evt) => (
              <div key={evt.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                <div className={`w-2 h-2 rounded-full shrink-0 ${
                  evt.severity === 'critical' ? 'bg-destructive' :
                  evt.severity === 'high' ? 'bg-warning' :
                  evt.severity === 'medium' ? 'bg-info' : 'bg-success'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-medium truncate">{evt.eventType}</span>
                    <span className="text-[10px] text-muted-foreground">{evt.endpoint}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground">{evt.sourceIp} · {evt.timestamp.slice(11, 19)}</div>
                </div>
                <Badge variant="outline" className={`text-[10px] shrink-0 ${
                  evt.severity === 'critical' ? 'border-destructive/40 text-destructive' :
                  evt.severity === 'high' ? 'border-warning/40 text-warning' :
                  evt.severity === 'medium' ? 'border-info/40 text-info' : 'border-success/40 text-success'
                }`}>
                  {evt.severity}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Active Incidents</CardTitle>
            <CardDescription>Currently open security incidents</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {recentIncidents.map((inc) => (
              <div key={inc.id} className="p-3 rounded-lg border border-border bg-muted/30 hover:bg-muted/50 transition-colors">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className={`w-4 h-4 shrink-0 ${
                      inc.severity === 'critical' ? 'text-destructive' : 'text-warning'
                    }`} />
                    <span className="text-sm font-medium">{inc.title}</span>
                  </div>
                  <Badge variant="outline" className={`text-[10px] shrink-0 ${
                    inc.status === 'OPEN' ? 'border-destructive/40 text-destructive' :
                    inc.status === 'INVESTIGATING' ? 'border-warning/40 text-warning' :
                    'border-success/40 text-success'
                  }`}>
                    {inc.status}
                  </Badge>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                  <span>{inc.id}</span>
                  <span>{inc.sourceIp}</span>
                  <span>Confidence: {(inc.confidence * 100).toFixed(0)}%</span>
                </div>
                <div className="mt-2">
                  <Progress value={inc.confidence * 100} className="h-1" />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Server className="w-5 h-5 text-primary" />
            </div>
            <div>
              <div className="text-sm font-medium">Services</div>
              <div className="text-xs text-muted-foreground">API {labStats.status}</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-success/10 border border-success/20 flex items-center justify-center">
              <Database className="w-5 h-5 text-success" />
            </div>
            <div>
              <div className="text-sm font-medium">MongoDB</div>
              <div className="text-xs text-muted-foreground">{labStats.securityEventCount} events stored</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-warning/10 border border-warning/20 flex items-center justify-center">
              <Cpu className="w-5 h-5 text-warning" />
            </div>
            <div>
              <div className="text-sm font-medium">Redis</div>
              <div className="text-xs text-muted-foreground">Live polling every 5s</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
