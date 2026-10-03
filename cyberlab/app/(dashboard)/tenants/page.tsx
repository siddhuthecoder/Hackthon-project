'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Building2, Users, Package, ShoppingCart, CheckCircle2 } from 'lucide-react';

const planColors: Record<string, string> = {
  enterprise: 'border-primary/40 text-primary bg-primary/5',
  pro: 'border-info/40 text-info bg-info/5',
  free: 'border-muted-foreground/40 text-muted-foreground',
};

export default function TenantsPage() {
  const tenantsQ = useApi(() => api.tenants(), []);
  const usersQ = useApi(() => api.users().catch(() => []), []);
  if (tenantsQ.loading || usersQ.loading) return <LoadingState label="Loading tenants..." />;
  if (tenantsQ.error || !tenantsQ.data) return <ErrorState message={tenantsQ.error ?? 'No data'} onRetry={tenantsQ.reload} />;
  const tenants = tenantsQ.data;
  const users = usersQ.data ?? [];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Building2 className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Tenants</h1>
            <p className="text-muted-foreground text-sm">Multi-tenant SaaS environment</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {tenants.map(tenant => {
          const tenantUsers = users.filter(u => u.tenantId === tenant.id);
          return (
            <Card key={tenant.id} className="hover:border-primary/30 transition-all">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
                      <Building2 className="w-4 h-4 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{tenant.name}</CardTitle>
                      <span className="text-[10px] font-mono text-muted-foreground">{tenant.id}</span>
                    </div>
                  </div>
                  <Badge variant="outline" className={`text-[10px] ${planColors[tenant.plan]}`}>{tenant.plan}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="text-xs text-muted-foreground">Created {tenant.createdAt.slice(0, 10)}</div>
                <div className="grid grid-cols-3 gap-2">
                  <div className="text-center p-2 rounded-lg bg-muted/30">
                    <Users className="w-3.5 h-3.5 text-muted-foreground mx-auto mb-1" />
                    <div className="text-lg font-bold">{tenant.userCount}</div>
                    <div className="text-[10px] text-muted-foreground">Users</div>
                  </div>
                  <div className="text-center p-2 rounded-lg bg-muted/30">
                    <Package className="w-3.5 h-3.5 text-muted-foreground mx-auto mb-1" />
                    <div className="text-lg font-bold">{tenant.productCount}</div>
                    <div className="text-[10px] text-muted-foreground">Products</div>
                  </div>
                  <div className="text-center p-2 rounded-lg bg-muted/30">
                    <ShoppingCart className="w-3.5 h-3.5 text-muted-foreground mx-auto mb-1" />
                    <div className="text-lg font-bold">{tenant.orderCount}</div>
                    <div className="text-[10px] text-muted-foreground">Orders</div>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground mb-1">Role Distribution</div>
                  <div className="space-y-1">
                    {['TENANT_ADMIN', 'MANAGER', 'STAFF', 'USER'].map(role => {
                      const count = tenantUsers.filter(u => u.role === role).length;
                      const pct = tenantUsers.length > 0 ? (count / tenantUsers.length) * 100 : 0;
                      return (
                        <div key={role} className="flex items-center gap-2">
                          <span className="text-[10px] w-20 text-muted-foreground">{role.replace('TENANT_', '')}</span>
                          <Progress value={pct} className="h-1.5 flex-1" />
                          <span className="text-[10px] w-6 text-right">{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Tenant Isolation Model</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
            <CheckCircle2 className="w-5 h-5 text-success shrink-0" />
            <p className="text-sm text-muted-foreground">
              Each tenant's data is logically isolated. The secure API verifies <code className="font-mono text-xs text-foreground">order.tenantId === currentUser.tenantId</code>.
              The vulnerable path (VULN-002) allows cross-tenant access by omitting this check.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
