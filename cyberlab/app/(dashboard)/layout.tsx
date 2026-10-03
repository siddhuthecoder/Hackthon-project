import { Sidebar } from '@/components/sidebar';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background grid-bg">
      <Sidebar />
      <main className="ml-60 min-h-screen">
        <div className="p-6 lg:p-8 max-w-[1600px] mx-auto">{children}</div>
      </main>
    </div>
  );
}
