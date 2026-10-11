'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const PRIMARY_NAV = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/attack-theater', label: 'Attack Theater' },
  { href: '/findings', label: 'Findings' },
  { href: '/incidents', label: 'Incidents' },
  { href: '/security-lab', label: 'Security Lab' },
  { href: '/soc', label: 'SOC' },
];

const MORE_NAV = [
  { href: '/applications', label: 'Applications' },
  { href: '/fix-queue', label: 'Fix Queue' },
  { href: '/assets', label: 'Assets' },
  { href: '/scans', label: 'Scans' },
  { href: '/compare', label: 'Compare Targets' },
  { href: '/compliance', label: 'Compliance' },
  { href: '/attack-graph', label: 'Attack Graph' },
  { href: '/attack-matrix', label: 'ATT&CK Matrix' },
  { href: '/digital-twin', label: 'Digital Twin' },
  { href: '/events', label: 'Events' },
  { href: '/audit-logs', label: 'Audit Logs' },
  { href: '/threat-intelligence', label: 'Threat Intelligence' },
  { href: '/remediation', label: 'Remediation' },
  { href: '/verification', label: 'Verification' },
  { href: '/settings', label: 'Settings' },
];

export function Shell({ children }: { children: React.ReactNode }): React.ReactElement {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <span className="font-bold tracking-tight text-lg">SentinelForge<span className="text-emerald-400"> AI</span></span>
          <nav className="flex gap-4 text-sm items-center">
            {PRIMARY_NAV.map(item => (
              <Link
                key={item.href}
                href={item.href}
                className={pathname.startsWith(item.href) ? 'text-emerald-400 font-medium' : 'text-slate-400 hover:text-slate-200'}
              >
                {item.label}
              </Link>
            ))}
            <details className="relative">
              <summary className="cursor-pointer text-slate-400 hover:text-slate-200 list-none">More ▾</summary>
              <div className="absolute left-0 mt-2 bg-slate-900 border border-slate-800 rounded-lg shadow-xl py-1 w-48 z-10">
                {MORE_NAV.map(item => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`block px-3 py-1.5 text-sm ${pathname.startsWith(item.href) ? 'text-emerald-400' : 'text-slate-300 hover:bg-slate-800'}`}
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            </details>
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          {user && <span>{user.name} · {user.role}</span>}
          <button onClick={logout} className="text-slate-500 hover:text-slate-200">Log out</button>
        </div>
      </header>
      <main className="p-6">{children}</main>
    </div>
  );
}
