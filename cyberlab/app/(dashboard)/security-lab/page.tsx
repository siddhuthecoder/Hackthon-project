'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Shield, ShieldAlert, ShieldCheck, Bug, ArrowRight, Code, Lock, FileWarning, FlaskConical } from 'lucide-react';
import Link from 'next/link';

const severityColors: Record<string, string> = {
  critical: 'border-destructive/40 text-destructive bg-destructive/5',
  high: 'border-warning/40 text-warning bg-warning/5',
  medium: 'border-info/40 text-info bg-info/5',
  low: 'border-success/40 text-success bg-success/5',
};

export default function SecurityLabPage() {
  const findingsQ = useApi(() => api.findings(), []);
  if (findingsQ.loading) return <LoadingState label="Loading findings..." />;
  if (findingsQ.error || !findingsQ.data) return <ErrorState message={findingsQ.error ?? 'No data'} onRetry={findingsQ.reload} />;
  const vulnerabilities = findingsQ.data;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
            <FlaskConical className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Security Lab</h1>
            <p className="text-muted-foreground text-sm">{vulnerabilities.length} live findings for testing and demonstration</p>
          </div>
        </div>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-4 flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-primary shrink-0" />
          <p className="text-sm text-muted-foreground">
            This is an authorized security testing environment. All vulnerabilities are intentionally seeded for defensive testing.
            Every vulnerability has both a <span className="text-success font-medium">secure</span> and <span className="text-destructive font-medium">vulnerable</span> endpoint.
          </p>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {vulnerabilities.map((vuln) => (
          <Card key={vuln.id} className="hover:border-primary/30 transition-all duration-200 group">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Bug className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs font-mono text-muted-foreground">{vuln.id}</span>
                </div>
                <Badge variant="outline" className={`text-[10px] ${severityColors[vuln.severity]}`}>
                  {vuln.severity.toUpperCase()}
                </Badge>
              </div>
              <CardTitle className="text-base mt-2 group-hover:text-primary transition-colors">{vuln.title}</CardTitle>
              <CardDescription className="text-xs">{vuln.type}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground leading-relaxed">{vuln.description}</p>

              <div className="space-y-1.5 pt-2 border-t border-border">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground w-16 shrink-0">Endpoint</span>
                  <code className="font-mono text-[11px] text-foreground/80 truncate">{vuln.endpoint}</code>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground w-16 shrink-0">CWE</span>
                  <code className="font-mono text-[11px] text-foreground/80">{vuln.cwe}</code>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground w-16 shrink-0">OWASP</span>
                  <code className="font-mono text-[11px] text-foreground/80">{vuln.owasp}</code>
                </div>
                {vuln.mitreTechnique && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-muted-foreground w-16 shrink-0">MITRE</span>
                    <code className="font-mono text-[11px] text-foreground/80">{vuln.mitreTechnique}</code>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2 pt-2">
                <div className="flex items-center gap-1.5 text-xs text-success">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Secure path</span>
                </div>
                <ArrowRight className="w-3 h-3 text-muted-foreground" />
                <div className="flex items-center gap-1.5 text-xs text-destructive">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Vulnerable path</span>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <Badge variant="outline" className="text-[10px] font-mono">{vuln.status}</Badge>
                <span className="text-[10px] text-muted-foreground ml-auto">{vuln.method}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="border-warning/20 bg-warning/5">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-warning" />
            Attack Simulation
          </CardTitle>
          <CardDescription>Run controlled attack scenarios against the lab</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3">
            <Link
              href="/security-lab/attacks"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              Go to Attack Simulator
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/security-lab/xss-demo"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-destructive/40 text-destructive text-sm font-medium hover:bg-destructive/10 transition-colors"
            >
              XSS Demo (VULN-005)
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
