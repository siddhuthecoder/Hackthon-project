const SEVERITY_CLASSES: Record<string, string> = {
  low: 'bg-slate-700 text-slate-200',
  medium: 'bg-amber-700/60 text-amber-200',
  high: 'bg-orange-700/60 text-orange-200',
  critical: 'bg-red-700/70 text-red-100',
};

export function SeverityBadge({ severity }: { severity: string }): React.ReactElement {
  const cls = SEVERITY_CLASSES[severity.toLowerCase()] ?? 'bg-slate-700 text-slate-200';
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${cls}`}>{severity}</span>;
}

const STATUS_CLASSES: Record<string, string> = {
  OPEN: 'bg-red-900/50 text-red-200',
  INVESTIGATING: 'bg-amber-900/50 text-amber-200',
  CONTAINED: 'bg-sky-900/50 text-sky-200',
  RESOLVED: 'bg-emerald-900/50 text-emerald-200',
  FALSE_POSITIVE: 'bg-slate-700 text-slate-300',
  CONFIRMED: 'bg-orange-900/50 text-orange-200',
  FIXED: 'bg-sky-900/50 text-sky-200',
  VERIFIED: 'bg-emerald-900/50 text-emerald-200',
};

export function StatusBadge({ status }: { status: string }): React.ReactElement {
  const cls = STATUS_CLASSES[status] ?? 'bg-slate-700 text-slate-300';
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{status}</span>;
}
