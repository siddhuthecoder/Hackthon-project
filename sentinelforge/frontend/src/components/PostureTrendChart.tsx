'use client';

import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

interface ScanHistoryPoint {
  startedAt: string;
  findingsOpen: number;
  checksTotal: number;
}

export function PostureTrendChart({ data }: { data: ScanHistoryPoint[] }): React.ReactElement {
  const chartData = data.map(d => ({
    time: new Date(d.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    findingsOpen: d.findingsOpen,
  }));

  if (chartData.length < 2) {
    return <p className="text-slate-500 text-sm">Run at least 2 scans to see a trend.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="findingsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f87171" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
        <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', fontSize: 12 }} />
        <Area type="monotone" dataKey="findingsOpen" stroke="#f87171" fill="url(#findingsGradient)" strokeWidth={2} name="Open findings" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
