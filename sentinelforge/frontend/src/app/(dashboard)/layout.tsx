'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Shell } from '@/components/Shell';

export default function DashboardLayout({ children }: { children: React.ReactNode }): React.ReactElement | null {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.replace('/login');
  }, [loading, user, router]);

  if (loading) return <div className="min-h-screen bg-slate-950 text-slate-500 flex items-center justify-center">Loading…</div>;
  if (!user) return null;

  return <Shell>{children}</Shell>;
}
