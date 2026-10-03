'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Package, Search } from 'lucide-react';

export default function ProductsPage() {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [tenantFilter, setTenantFilter] = useState('all');

  const productsQ = useApi(() => api.products(), []);
  const tenantsQ = useApi(() => api.tenants(), []);
  const products = productsQ.data;
  const tenants = tenantsQ.data;

  const categories = Array.from(new Set((products ?? []).map(p => p.category)));

  const filtered = useMemo(() => {
    return (products ?? []).filter(p => {
      if (categoryFilter !== 'all' && p.category !== categoryFilter) return false;
      if (tenantFilter !== 'all' && p.tenantId !== tenantFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return p.name.toLowerCase().includes(s) || p.description.toLowerCase().includes(s) || p.id.includes(s);
      }
      return true;
    });
  }, [products, search, categoryFilter, tenantFilter]);

  if (productsQ.loading || tenantsQ.loading) return <LoadingState label="Loading products..." />;
  const err = productsQ.error ?? tenantsQ.error;
  if (err || !products || !tenants) return <ErrorState message={err ?? 'No data'} onRetry={() => { productsQ.reload(); tenantsQ.reload(); }} />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-info/10 border border-info/20 flex items-center justify-center">
            <Package className="w-5 h-5 text-info" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Products</h1>
            <p className="text-muted-foreground text-sm">{products.length} products in catalog</p>
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input placeholder="Search products..." value={search} onChange={e => setSearch(e.target.value)} className="pl-9" />
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-full md:w-[160px]"><SelectValue placeholder="Category" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {categories.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
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
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Product</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">ID</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Category</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Price</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Stock</th>
                  <th className="text-xs font-medium text-muted-foreground px-4 py-3">Tenant</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 50).map(p => (
                  <tr key={p.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="text-sm font-medium">{p.name}</div>
                      <div className="text-[10px] text-muted-foreground truncate max-w-xs">{p.description}</div>
                    </td>
                    <td className="px-4 py-3"><span className="text-xs font-mono text-muted-foreground">{p.id}</span></td>
                    <td className="px-4 py-3"><Badge variant="secondary" className="text-[10px]">{p.category}</Badge></td>
                    <td className="px-4 py-3"><span className="text-sm font-mono">${p.price.toFixed(2)}</span></td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-mono ${p.stock < 20 ? 'text-warning' : 'text-muted-foreground'}`}>{p.stock}</span>
                    </td>
                    <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{tenants.find(t => t.id === p.tenantId)?.name || p.tenantId}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length > 50 && (
            <div className="p-3 text-center text-xs text-muted-foreground border-t border-border">
              Showing 50 of {filtered.length} products
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
