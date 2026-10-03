'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Users, Search } from 'lucide-react';

const roleColors: Record<string, string> = {
  SUPER_ADMIN: 'border-destructive/40 text-destructive bg-destructive/5',
  TENANT_ADMIN: 'border-warning/40 text-warning bg-warning/5',
  MANAGER: 'border-info/40 text-info bg-info/5',
  STAFF: 'border-primary/40 text-primary bg-primary/5',
  USER: 'border-muted-foreground/40 text-muted-foreground',
};

export default function UsersPage() {
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [tenantFilter, setTenantFilter] = useState('all');

  const usersQ = useApi(() => api.users(), []);
  const tenantsQ = useApi(() => api.tenants(), []);
  const users = usersQ.data;
  const tenants = tenantsQ.data;

  const filtered = useMemo(() => {
    return (users ?? []).filter(u => {
      if (roleFilter !== 'all' && u.role !== roleFilter) return false;
      if (tenantFilter !== 'all' && u.tenantId !== tenantFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return u.name.toLowerCase().includes(s) || u.email.toLowerCase().includes(s) || u.id.includes(s);
      }
      return true;
    });
  }, [users, search, roleFilter, tenantFilter]);

  if (usersQ.loading || tenantsQ.loading) return <LoadingState label="Loading users..." />;
  const err = usersQ.error ?? tenantsQ.error;
  if (err || !users || !tenants) return <ErrorState message={err ?? 'No data'} onRetry={() => { usersQ.reload(); tenantsQ.reload(); }} />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-success/10 border border-success/20 flex items-center justify-center">
            <Users className="w-5 h-5 text-success" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Users</h1>
            <p className="text-muted-foreground text-sm">{users.length} users across {tenants.length} tenants</p>
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input placeholder="Search users..." value={search} onChange={e => setSearch(e.target.value)} className="pl-9" />
            </div>
            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-full md:w-[160px]"><SelectValue placeholder="Role" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                <SelectItem value="SUPER_ADMIN">Super Admin</SelectItem>
                <SelectItem value="TENANT_ADMIN">Tenant Admin</SelectItem>
                <SelectItem value="MANAGER">Manager</SelectItem>
                <SelectItem value="STAFF">Staff</SelectItem>
                <SelectItem value="USER">User</SelectItem>
              </SelectContent>
            </Select>
            <Select value={tenantFilter} onValueChange={setTenantFilter}>
              <SelectTrigger className="w-full md:w-[160px]"><SelectValue placeholder="Tenant" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tenants</SelectItem>
                {tenants.map(t => <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">User</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">ID</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Role</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Tenant</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Status</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Last Login</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(u => (
                  <tr key={u.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <Avatar className="w-8 h-8"><AvatarFallback className="text-xs bg-muted">{u.name.charAt(0)}</AvatarFallback></Avatar>
                        <div>
                          <div className="text-sm font-medium">{u.name}</div>
                          <div className="text-[10px] text-muted-foreground">{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3"><span className="text-xs font-mono text-muted-foreground">{u.id}</span></td>
                    <td className="px-4 py-3"><Badge variant="outline" className={`text-[10px] ${roleColors[u.role]}`}>{u.role}</Badge></td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{tenants.find(t => t.id === u.tenantId)?.name || u.tenantId}</span></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${u.active ? 'bg-success' : 'bg-muted-foreground'}`} />
                        <span className="text-xs">{u.active ? 'Active' : 'Inactive'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{u.lastLogin ? u.lastLogin.slice(0, 16).replace('T', ' ') : 'Never'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
