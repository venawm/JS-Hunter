'use client';

import { DashboardProvider } from '@/contexts/dashboard-context';

import { Workspace } from '@/components/dashboard/workspace';
import { Sidebar } from '@/components/dashboard/sidebar-input';

export default function Page() {
  return (
    <DashboardProvider>
      <div className="flex min-h-screen bg-slate-50 font-sans">
        <Sidebar />
        <Workspace />
      </div>
    </DashboardProvider>
  );
}