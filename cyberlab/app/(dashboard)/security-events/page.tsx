'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Search, Activity, Filter } from 'lucide-react';

const severityColors: Record<string, string> = {
  critical: 'border-destructive/40 text-destructive',
  high: 'border-warning/40 text-warning',
  medium: 'border-info/40 text-info',
  low: 'border-success/40 text-success',
};

export default function SecurityEventsPage() {
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');

  const eventsQ = useApi(() => api.events({ limit: 500 }), [], 5000);
  const securityEvents = eventsQ.data;

  const filtered = useMemo(() => {
    return (securityEvents ?? [])
      .filter(e => {
        if (eventTypeFilter !== 'all' && e.eventType !== eventTypeFilter) return false;
        if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
        if (search) {
          const s = search.toLowerCase();
          return e.endpoint.toLowerCase().includes(s) ||
            e.sourceIp.includes(s) ||
            e.eventType.toLowerCase().includes(s) ||
            (e.userId?.includes(s) ?? false);
        }
        return true;
      });
  }, [securityEvents, search, eventTypeFilter, severityFilter]);

  if (eventsQ.loading) return <LoadingState label="Loading security events..." />;
  if (eventsQ.error || !securityEvents) return <ErrorState message={eventsQ.error ?? 'No data'} onRetry={eventsQ.reload} />;

  const eventTypes = Array.from(new Set(securityEvents.map(e => e.eventType)));

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-warning/10 border border-warning/20 flex items-center justify-center">
            <Activity className="w-5 h-5 text-warning" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Security Events</h1>
            <p className="text-muted-foreground text-sm">Live security telemetry (refreshes every 5s)</p>
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by endpoint, IP, event type..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={eventTypeFilter} onValueChange={setEventTypeFilter}>
              <SelectTrigger className="w-full md:w-[200px]">
                <Filter className="w-3.5 h-3.5 mr-2" />
                <SelectValue placeholder="Event Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {eventTypes.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full md:w-[150px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Events', value: securityEvents.length, color: 'text-primary' },
          { label: 'Critical', value: securityEvents.filter(e => e.severity === 'critical').length, color: 'text-destructive' },
          { label: 'High', value: securityEvents.filter(e => e.severity === 'high').length, color: 'text-warning' },
          { label: 'Medium', value: securityEvents.filter(e => e.severity === 'medium').length, color: 'text-info' },
        ].map(stat => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Event Log ({filtered.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1 max-h-[600px] overflow-y-auto scrollbar-thin">
            {filtered.map(evt => (
              <div key={evt.id} className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-muted/30 transition-colors border border-transparent hover:border-border">
                <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                  evt.severity === 'critical' ? 'bg-destructive' :
                  evt.severity === 'high' ? 'bg-warning' :
                  evt.severity === 'medium' ? 'bg-info' : 'bg-success'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-medium">{evt.eventType}</span>
                    <Badge variant="outline" className={`text-[9px] ${severityColors[evt.severity]}`}>{evt.severity}</Badge>
                    <span className="text-[10px] font-mono text-muted-foreground">{evt.method}</span>
                    <span className="text-[10px] font-mono text-muted-foreground truncate">{evt.endpoint}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-3 flex-wrap">
                    <span>{evt.id}</span>
                    <span>{evt.timestamp}</span>
                    <span>IP: {evt.sourceIp}</span>
                    {evt.userId && <span>User: {evt.userId}</span>}
                    {evt.tenantId && <span>Tenant: {evt.tenantId}</span>}
                    <span>ReqID: {evt.requestId}</span>
                    {evt.mitreTechnique && <span className="font-mono">MITRE: {evt.mitreTechnique}</span>}
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
