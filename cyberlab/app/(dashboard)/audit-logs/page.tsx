'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { ScrollText, Search } from 'lucide-react';

export default function AuditLogsPage() {
  const [search, setSearch] = useState('');

  const logsQ = useApi(() => api.auditLogs(), []);
  const auditLogs = logsQ.data;

  const filtered = useMemo(() => {
    return (auditLogs ?? [])
      .filter(l => {
        if (!search) return true;
        const s = search.toLowerCase();
        return l.actorName.toLowerCase().includes(s) ||
          l.action.toLowerCase().includes(s) ||
          (l.targetName?.toLowerCase().includes(s) ?? false);
      });
  }, [auditLogs, search]);

  if (logsQ.loading) return <LoadingState label="Loading audit logs..." />;
  if (logsQ.error || !auditLogs) return <ErrorState message={logsQ.error ?? 'No data'} onRetry={logsQ.reload} />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-info/10 border border-info/20 flex items-center justify-center">
            <ScrollText className="w-5 h-5 text-info" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Audit Logs</h1>
            <p className="text-muted-foreground text-sm">Track all administrative and user actions</p>
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search by actor, action, target..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 max-w-md"
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Audit Trail ({filtered.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1 max-h-[600px] overflow-y-auto scrollbar-thin">
            {filtered.map(log => (
              <div key={log.id} className="flex items-start gap-3 p-3 rounded-lg hover:bg-muted/30 transition-colors border border-transparent hover:border-border">
                <div className="w-7 h-7 rounded-full bg-muted flex items-center justify-center shrink-0 text-[10px] font-mono">
                  {log.actorName.charAt(0)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium">{log.actorName}</span>
                    <Badge variant="secondary" className="text-[10px] font-mono">{log.action}</Badge>
                    {log.targetName && (
                      <>
                        <span className="text-[10px] text-muted-foreground">→</span>
                        <span className="text-xs text-muted-foreground">{log.targetName}</span>
                      </>
                    )}
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-3 flex-wrap">
                    <span>{log.id}</span>
                    <span>{log.timestamp}</span>
                    <span>Tenant: {log.tenantId}</span>
                    {log.oldValue && log.newValue && (
                      <span className="text-warning">{log.oldValue} → {log.newValue}</span>
                    )}
                    {log.details && <span className="text-info">{log.details}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
