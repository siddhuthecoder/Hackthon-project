'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, LayoutDashboard, Users, Building2, Package, ShoppingCart, Settings, AlertTriangle, FileText, ScrollText, FlaskConical, Bug, Network, Activity, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/users', label: 'Users', icon: Users },
  { href: '/tenants', label: 'Tenants', icon: Building2 },
  { href: '/products', label: 'Products', icon: Package },
  { href: '/orders', label: 'Orders', icon: ShoppingCart },
  { href: '/admin', label: 'Admin', icon: Settings },
  { href: '/security-events', label: 'Security Events', icon: Activity },
  { href: '/audit-logs', label: 'Audit Logs', icon: ScrollText },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/security-lab', label: 'Security Lab', icon: FlaskConical },
  { href: '/security-lab/attacks', label: 'Attack Sim', icon: Bug },
  { href: '/security-lab/xss-demo', label: 'XSS Demo', icon: ShieldAlert },
  { href: '/security-lab/attack-graph', label: 'Attack Graph', icon: Network },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-60 border-r border-border bg-card/50 backdrop-blur-sm flex flex-col">
      <div className="flex items-center gap-2.5 px-5 h-16 border-b border-border">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-primary/10 border border-primary/30">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight">SentinelForge</span>
          <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Security Lab</span>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto scrollbar-thin py-3 px-3">
        <div className="space-y-0.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href || (item.href !== '/dashboard' && pathname?.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 group',
                  active
                    ? 'bg-primary/10 text-primary border border-primary/20'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/50 border border-transparent'
                )}
              >
                <Icon className={cn('w-4 h-4 shrink-0 transition-colors', active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')} />
                <span className="truncate">{item.label}</span>
              </Link>
            );
          })}
        </div>
      </nav>

      <div className="px-4 py-3 border-t border-border">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse-slow" />
          <span>Lab Environment Active</span>
        </div>
      </div>
    </aside>
  );
}
