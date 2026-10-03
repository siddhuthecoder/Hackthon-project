'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { ShoppingCart, Search } from 'lucide-react';

const statusColors: Record<string, string> = {
  pending: 'border-warning/40 text-warning',
  paid: 'border-success/40 text-success',
  shipped: 'border-info/40 text-info',
  delivered: 'border-success/40 text-success',
  cancelled: 'border-destructive/40 text-destructive',
  refunded: 'border-muted-foreground/40 text-muted-foreground',
};

export default function OrdersPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [tenantFilter, setTenantFilter] = useState('all');

  const ordersQ = useApi(() => api.orders(200), []);
  const tenantsQ = useApi(() => api.tenants(), []);
  const orders = ordersQ.data;
  const tenants = tenantsQ.data;

  const filtered = useMemo(() => {
    return (orders ?? []).filter(o => {
      if (statusFilter !== 'all' && o.status !== statusFilter) return false;
      if (tenantFilter !== 'all' && o.tenantId !== tenantFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return o.orderNumber.toLowerCase().includes(s) || o.customerName.toLowerCase().includes(s) || o.id.includes(s);
      }
      return true;
    });
  }, [orders, search, statusFilter, tenantFilter]);

  if (ordersQ.loading || tenantsQ.loading) return <LoadingState label="Loading orders..." />;
  const err = ordersQ.error ?? tenantsQ.error;
  if (err || !orders || !tenants) return <ErrorState message={err ?? 'No data'} onRetry={() => { ordersQ.reload(); tenantsQ.reload(); }} />;

  const totalRevenue = filtered.filter(o => o.status === 'paid' || o.status === 'delivered').reduce((s, o) => s + o.total, 0);

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-warning/10 border border-warning/20 flex items-center justify-center">
            <ShoppingCart className="w-5 h-5 text-warning" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Orders</h1>
            <p className="text-muted-foreground text-sm">{orders.length} orders across all tenants</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card><CardContent className="p-4"><div className="text-2xl font-bold text-primary">{filtered.length}</div><div className="text-xs text-muted-foreground mt-0.5">Total Orders</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-2xl font-bold text-success">${totalRevenue.toFixed(0)}</div><div className="text-xs text-muted-foreground mt-0.5">Revenue</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-2xl font-bold text-warning">{filtered.filter(o => o.status === 'pending').length}</div><div className="text-xs text-muted-foreground mt-0.5">Pending</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-2xl font-bold text-info">{filtered.filter(o => o.status === 'shipped').length}</div><div className="text-xs text-muted-foreground mt-0.5">Shipped</div></CardContent></Card>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input placeholder="Search orders..." value={search} onChange={e => setSearch(e.target.value)} className="pl-9" />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full md:w-[150px]"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="paid">Paid</SelectItem>
                <SelectItem value="shipped">Shipped</SelectItem>
                <SelectItem value="delivered">Delivered</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
                <SelectItem value="refunded">Refunded</SelectItem>
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
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Order #</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Customer</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Items</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Total</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Status</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Tenant</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 50).map(o => (
                  <tr key={o.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3"><span className="text-xs font-mono font-medium">{o.orderNumber}</span></td>
                    <td className="px-4 py-3"><span className="text-sm">{o.customerName}</span></td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{o.items.length} item(s)</span></td>
                    <td className="px-4 py-3"><span className="text-sm font-mono">${o.total.toFixed(2)}</span></td>
                    <td className="px-4 py-3"><Badge variant="outline" className={`text-[10px] ${statusColors[o.status]}`}>{o.status}</Badge></td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{tenants.find(t => t.id === o.tenantId)?.name || o.tenantId}</span></td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{o.createdAt.slice(0, 10)}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length > 50 && (
            <div className="p-3 text-center text-xs text-muted-foreground border-t border-border">
              Showing 50 of {filtered.length} orders
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
