'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import type { AttackGraph } from '@/lib/types';
import { Network, ArrowRight, Circle, Database, User, Globe, Server, Bug, Shield, Building2 } from 'lucide-react';

const nodeIcons: Record<string, typeof User> = {
  USER: User,
  IP: Globe,
  DEVICE: Server,
  API: Server,
  ENDPOINT: Network,
  VULNERABILITY: Bug,
  ASSET: Shield,
  DATABASE: Database,
  TENANT: Building2,
};

const nodeColors: Record<string, string> = {
  USER: 'text-primary bg-primary/10 border-primary/30',
  IP: 'text-warning bg-warning/10 border-warning/30',
  VULNERABILITY: 'text-destructive bg-destructive/10 border-destructive/30',
  ENDPOINT: 'text-info bg-info/10 border-info/30',
  DATABASE: 'text-success bg-success/10 border-success/30',
  TENANT: 'text-primary bg-primary/10 border-primary/30',
  ASSET: 'text-warning bg-warning/10 border-warning/30',
};

const edgeLabels: Record<string, string> = {
  AUTHENTICATED: 'authenticated',
  EXPLOITED: 'exploited',
  TARGETED: 'targeted',
  BELONGS_TO: 'belongs to',
  ACCESSED: 'accessed',
  ACCESSES: 'accesses',
  ESCALATED_TO: 'escalated to',
};

function buildAttackPath(graph: AttackGraph): string[] {
  const hasIncoming = new Set(graph.edges.map(e => e.to));
  const start = graph.nodes.find(n => !hasIncoming.has(n.id) && graph.edges.some(e => e.from === n.id)) ?? graph.nodes[0];
  const labelOf = (id: string) => graph.nodes.find(n => n.id === id)?.label ?? id;
  const visited = new Set<string>();
  const path: string[] = [];
  let current: string | undefined = start?.id;
  while (current && !visited.has(current)) {
    visited.add(current);
    path.push(labelOf(current));
    const next = graph.edges.find(e => e.from === current && !visited.has(e.to));
    current = next?.to;
  }
  return path;
}

export default function AttackGraphPage() {
  const graphQ = useApi(() => api.attackGraph(), [], 10000);
  if (graphQ.loading) return <LoadingState label="Loading attack graph..." />;
  if (graphQ.error || !graphQ.data) return <ErrorState message={graphQ.error ?? 'No data'} onRetry={graphQ.reload} />;
  const attackGraph = graphQ.data;
  const attackPath = attackGraph.attackPath && attackGraph.attackPath.length > 0 ? attackGraph.attackPath : buildAttackPath(attackGraph);

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Network className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Attack Graph</h1>
            <p className="text-muted-foreground text-sm">Visual representation of the seeded attack chain</p>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Seeded Attack Chain</CardTitle>
          <CardDescription>
            {attackGraph.nodes.length} nodes, {attackGraph.edges.length} edges (live from /api/security/attack-graph)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {attackGraph.nodes.map((node) => {
              const Icon = nodeIcons[node.type] || Circle;
              const edges = attackGraph.edges.filter(e => e.from === node.id);
              return (
                <div key={node.id} className="flex items-start gap-4">
                  <div className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg border ${nodeColors[node.type] || 'text-muted-foreground bg-muted/30 border-border'} min-w-[200px]`}>
                    <Icon className="w-4 h-4 shrink-0" />
                    <div>
                      <div className="text-sm font-medium">{node.label}</div>
                      <div className="text-[10px] opacity-70 uppercase tracking-wider">{node.type}</div>
                    </div>
                  </div>
                  {edges.length > 0 && (
                    <div className="flex-1 space-y-2 pt-1">
                      {edges.map((edge, i) => {
                        const target = attackGraph.nodes.find(n => n.id === edge.to);
                        const TargetIcon = target ? (nodeIcons[target.type] || Circle) : Circle;
                        return (
                          <div key={i} className="flex items-center gap-2 animate-slide-in">
                            <ArrowRight className="w-3.5 h-3.5 text-muted-foreground" />
                            <Badge variant="secondary" className="text-[10px] font-mono">{edgeLabels[edge.type] ?? edge.type}</Badge>
                            <ArrowRight className="w-3.5 h-3.5 text-muted-foreground" />
                            <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border ${nodeColors[target?.type ?? ''] || 'text-muted-foreground bg-muted/30 border-border'}`}>
                              <TargetIcon className="w-3 h-3 shrink-0" />
                              <span className="text-xs">{target?.label}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Attack Path Analysis</CardTitle>
          <CardDescription>The complete attack path the future SentinelForge AI should discover</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2">
            {attackPath.map((step, i, arr) => (
              <div key={step} className="flex items-center gap-2">
                <div className={`px-3 py-1.5 rounded-md text-xs font-medium border ${
                  i === 0 ? 'border-warning/40 text-warning bg-warning/5' :
                  i === arr.length - 1 ? 'border-destructive/40 text-destructive bg-destructive/5' :
                  'border-primary/30 text-primary bg-primary/5'
                }`}>
                  {step}
                </div>
                {i < arr.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-muted-foreground" />}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Node Legend</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(nodeColors).map(([type, color]) => {
              const Icon = nodeIcons[type] || Circle;
              return (
                <div key={type} className="flex items-center gap-2">
                  <div className={`flex items-center justify-center w-7 h-7 rounded-md border ${color}`}>
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-xs">{type}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Edge Legend</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(edgeLabels).map(([type, label]) => (
              <div key={type} className="flex items-center gap-2">
                <Badge variant="secondary" className="text-[10px] font-mono">{label}</Badge>
                <span className="text-xs text-muted-foreground">{type}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
