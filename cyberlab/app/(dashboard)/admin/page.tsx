'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { useState } from 'react';
import type { Role } from '@/lib/types';
import { Settings, Shield, ShieldAlert, ShieldCheck, UserCog, AlertTriangle, CheckCircle2, Lock } from 'lucide-react';

const roleColors: Record<string, string> = {
  SUPER_ADMIN: 'border-destructive/40 text-destructive bg-destructive/5',
  TENANT_ADMIN: 'border-warning/40 text-warning bg-warning/5',
  MANAGER: 'border-info/40 text-info bg-info/5',
  STAFF: 'border-primary/40 text-primary bg-primary/5',
  USER: 'border-muted-foreground/40 text-muted-foreground',
};

const ROLES: Role[] = ['SUPER_ADMIN', 'TENANT_ADMIN', 'MANAGER', 'STAFF', 'USER'];

export default function AdminPage() {
  const usersQ = useApi(() => api.adminUsers(), []);
  const tenantsQ = useApi(() => api.tenants(), []);
  const findingsQ = useApi(() => api.findings(), []);
  const incidentsQ = useApi(() => api.incidents(), [], 5000);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  if (usersQ.loading || tenantsQ.loading || findingsQ.loading || incidentsQ.loading) {
    return <LoadingState label="Loading admin panel..." />;
  }
  const err = usersQ.error ?? tenantsQ.error ?? findingsQ.error ?? incidentsQ.error;
  if (err || !usersQ.data || !tenantsQ.data || !findingsQ.data || !incidentsQ.data) {
    return <ErrorState message={err ?? 'No data'} onRetry={() => { usersQ.reload(); tenantsQ.reload(); findingsQ.reload(); incidentsQ.reload(); }} />;
  }
  const users = usersQ.data;
  const tenants = tenantsQ.data;
  const vulnerabilities = findingsQ.data;
  const incidents = incidentsQ.data;
  const openVulns = vulnerabilities.filter(v => v.status === 'OPEN');

  const runAction = async (id: string, action: () => Promise<unknown>) => {
    setBusyId(id);
    setActionError(null);
    try {
      await action();
      usersQ.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Action failed');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center justify-center">
            <Settings className="w-5 h-5 text-destructive" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Admin Panel</h1>
            <p className="text-muted-foreground text-sm">Administrative controls and security posture</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-success/20 bg-success/5">
          <CardContent className="p-4 flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-success" />
            <div>
              <div className="text-sm font-medium">Secure Endpoints</div>
              <div className="text-xs text-muted-foreground">{vulnerabilities.length} protected paths</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-destructive/20 bg-destructive/5">
          <CardContent className="p-4 flex items-center gap-3">
            <ShieldAlert className="w-8 h-8 text-destructive" />
            <div>
              <div className="text-sm font-medium">Vulnerable Endpoints</div>
              <div className="text-xs text-muted-foreground">{openVulns.length} open vulnerabilities</div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-warning/20 bg-warning/5">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-warning" />
            <div>
              <div className="text-sm font-medium">Active Incidents</div>
              <div className="text-xs text-muted-foreground">{incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING').length} require attention</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><UserCog className="w-4 h-4" /> User Management ({users.length})</CardTitle>
          <CardDescription>Live users from /api/admin/users. Promote or deactivate accounts.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {actionError && <ErrorState message={actionError} />}
          {users.map(u => (
            <div key={u.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
              <Avatar className="w-9 h-9"><AvatarFallback className="text-xs bg-muted">{u.name.charAt(0)}</AvatarFallback></Avatar>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">{u.name}</div>
                <div className="text-[10px] text-muted-foreground">{u.email}</div>
              </div>
              <Badge variant="outline" className={`text-[10px] ${roleColors[u.role]}`}>{u.role}</Badge>
              <span className="text-xs text-muted-foreground hidden md:block">{tenants.find(t => t.id === u.tenantId)?.name || u.tenantId}</span>
              <Select
                value={u.role}
                disabled={busyId === u.id}
                onValueChange={(role) => void runAction(u.id, () => api.promoteUser(u.id, role as Role))}
              >
                <SelectTrigger className="w-[140px] h-8 text-xs"><SelectValue placeholder="Promote" /></SelectTrigger>
                <SelectContent>
                  {ROLES.map(r => <SelectItem key={r} value={r}>{r}</SelectItem>)}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                variant="ghost"
                className="text-xs text-destructive"
                disabled={busyId === u.id || !u.active}
                onClick={() => void runAction(u.id, () => api.deactivateUser(u.id))}
              >
                {u.active ? 'Deactivate' : 'Inactive'}
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><Shield className="w-4 h-4" /> Security Posture</CardTitle>
          <CardDescription>Authorization model status</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-success" />
              <span className="text-sm">JWT Authentication</span>
            </div>
            <Badge variant="outline" className="text-[10px] border-success/40 text-success">Active</Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-success" />
              <span className="text-sm">RBAC Role Validation</span>
            </div>
            <Badge variant="outline" className="text-[10px] border-success/40 text-success">Secure Path</Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-warning" />
              <span className="text-sm">Rate Limiting</span>
            </div>
            <Badge variant="outline" className="text-[10px] border-warning/40 text-warning">Weak (VULN-009)</Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-destructive" />
              <span className="text-sm">Object-Level Authorization</span>
            </div>
            <Badge variant="outline" className="text-[10px] border-destructive/40 text-destructive">Vulnerable (VULN-001)</Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-destructive" />
              <span className="text-sm">Tenant Isolation</span>
            </div>
            <Badge variant="outline" className="text-[10px] border-destructive/40 text-destructive">Vulnerable (VULN-002)</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
