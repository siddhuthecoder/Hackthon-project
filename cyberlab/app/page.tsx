'use client';

import Link from 'next/link';
import { Shield, ArrowRight, Bug, Activity, Network, AlertTriangle, Server, Database, Cpu, Lock, Terminal, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';

export default function Home() {
  const statusQ = useApi(() => api.demoStatus(), [], 5000);
  const findingsQ = useApi(() => api.findings(), []);
  const labStats = statusQ.data;
  const vulnerabilities = findingsQ.data ?? [];
  const dash = (n: number | undefined) => (n === undefined ? '-' : n);

  return (
    <div className="min-h-screen bg-background grid-bg">
      <div className="max-w-5xl mx-auto px-6 py-16">
        <div className="text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-primary/30 bg-primary/5 text-xs text-primary">
            <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse-slow" />
            Authorized Security Testing Environment
          </div>

          <div className="flex justify-center">
            <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center glow-primary">
              <Shield className="w-8 h-8 text-primary" />
            </div>
          </div>

          <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
            SentinelForge <span className="text-primary text-glow-primary">Lab</span>
          </h1>

          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            A local cybersecurity demonstration environment with intentionally vulnerable endpoints,
            security telemetry, SOC detection rules, and attack simulation — for testing AI vulnerability scanning.
          </p>

          <div className="flex items-center justify-center gap-3 pt-2">
            <Link href="/dashboard">
              <Button size="lg" className="gap-2">
                Enter Dashboard <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link href="/security-lab">
              <Button size="lg" variant="outline" className="gap-2">
                <Bug className="w-4 h-4" /> View Vulnerabilities
              </Button>
            </Link>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-16">
          {[
            { icon: Bug, label: 'Vulnerabilities', value: dash(labStats?.vulnerabilityCount), color: 'text-destructive' },
            { icon: AlertTriangle, label: 'Incidents', value: dash(labStats?.incidentCount), color: 'text-warning' },
            { icon: Activity, label: 'Security Events', value: dash(labStats?.securityEventCount), color: 'text-info' },
            { icon: Server, label: 'Tenants', value: dash(labStats?.tenantCount), color: 'text-primary' },
            { icon: Network, label: 'Attack Scenarios', value: dash(labStats?.attackScenarioCount), color: 'text-success' },
            { icon: Database, label: 'Users', value: dash(labStats?.userCount), color: 'text-primary' },
          ].map(stat => {
            const Icon = stat.icon;
            return (
              <Card key={stat.label} className="hover:border-primary/30 transition-all">
                <CardContent className="p-4 flex items-center gap-3">
                  <Icon className={`w-5 h-5 ${stat.color}`} />
                  <div>
                    <div className="text-xl font-bold">{stat.value}</div>
                    <div className="text-xs text-muted-foreground">{stat.label}</div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="mt-12">
          <h2 className="text-lg font-semibold mb-4 text-center">Vulnerability Catalog</h2>
          {findingsQ.error && <p className="text-center text-sm text-destructive mb-3">{findingsQ.error}</p>}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {vulnerabilities.map(v => (
              <Link key={v.id} href="/security-lab">
                <Card className="hover:border-primary/30 transition-all p-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full shrink-0 ${
                      v.severity === 'critical' ? 'bg-destructive' :
                      v.severity === 'high' ? 'bg-warning' :
                      v.severity === 'medium' ? 'bg-info' : 'bg-success'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-muted-foreground">{v.id}</span>
                        <span className="text-sm font-medium truncate">{v.title}</span>
                      </div>
                      <div className="text-[10px] text-muted-foreground truncate">{v.type} · {v.cwe}</div>
                    </div>
                    <Badge variant="outline" className={`text-[9px] shrink-0 ${
                      v.severity === 'critical' ? 'border-destructive/40 text-destructive' :
                      v.severity === 'high' ? 'border-warning/40 text-warning' :
                      'border-info/40 text-info'
                    }`}>{v.severity}</Badge>
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        </div>

        <div className="mt-12 flex items-center justify-center gap-6 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5"><Terminal className="w-3.5 h-3.5" /> Local Docker Only</div>
          <div className="flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> No External Targets</div>
          <div className="flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" /> Fake Credentials</div>
        </div>
      </div>
    </div>
  );
}
