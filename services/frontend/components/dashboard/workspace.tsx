'use client';

import { useState } from 'react';
import { Bug, Fingerprint, Network } from 'lucide-react';
import { useDashboardContext } from '@/contexts/dashboard-context';
import { useDashboardData } from '@/hooks/use-dashboard-data';
import { Card } from '@/components/ui/card';
import { FindingsTable } from './findings-table';
import { SourceViewer } from './source-viewer';
import { adminAction } from '@/lib/api';

export function Workspace() {
  const { data } = useDashboardData();
  const { selectedTarget, setSelectedTarget, triggerRefresh } = useDashboardContext();
  const [view, setView] = useState<'list' | 'source'>('list');
  const [fileToView, setFileToView] = useState('');

  const handleClear = async () => {
    if (!selectedTarget) return;
    if (confirm(`Clear all findings for ${selectedTarget}?`)) {
      const target = data.targets.find(t => t.domain === selectedTarget);
      if (target) await adminAction('clear_project', { targetId: target.id });
      triggerRefresh();
    }
  };

  return (
    <main className="flex-1 ml-80 p-12 min-h-screen bg-slate-50/50">
      {/* Header */}
      <div className="flex items-center justify-between mb-10">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">Security Workspace</h2>
          <p className="text-slate-500 text-sm">Target: {selectedTarget || 'None'}</p>
        </div>
        <div className="flex gap-4">
          <select 
            value={selectedTarget} 
            onChange={e => setSelectedTarget(e.target.value)}
            className="bg-white border border-slate-200 text-slate-700 py-2 px-4 rounded-lg shadow-sm focus:border-indigo-500 outline-none font-medium min-w-[200px]"
          >
            {data.targets.map(t => <option key={t.id} value={t.domain}>{t.domain}</option>)}
          </select>
          {selectedTarget && (
            <button onClick={handleClear} className="text-red-600 hover:text-red-800 text-sm font-medium px-4">Clear Data</button>
          )}
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-3 gap-6 mb-10">
        <Metric title="Critical Risks" value={data.metrics.critical} icon={<Bug className="text-red-500" />} />
        <Metric title="Intel Matches" value={data.metrics.intel} icon={<Fingerprint className="text-blue-500" />} />
        <Metric title="Shadow Endpoints" value={data.metrics.shadow} icon={<Network className="text-indigo-500" />} />
      </div>

      {/* Content Switcher */}
      <div className="flex gap-6 border-b border-slate-200 mb-8">
        <Tab label="Vulnerabilities" active={view === 'list'} onClick={() => setView('list')} />
        <Tab label="Source Viewer" active={view === 'source'} onClick={() => setView('source')} />
      </div>

      {view === 'list' ? (
        <FindingsTable data={data.findings} onSelectFile={(f) => { setFileToView(f); setView('source'); }} />
      ) : (
        <SourceViewer domain={selectedTarget} filename={fileToView} />
      )}
    </main>
  );
}

function Metric({ title, value, icon }: any) {
  return (
    <Card className="flex items-center justify-between p-6">
      <div>
        <p className="text-slate-500 text-xs font-bold uppercase tracking-wider mb-1">{title}</p>
        <p className="text-3xl font-bold text-slate-900">{value}</p>
      </div>
      <div className="h-12 w-12 bg-slate-50 rounded-full flex items-center justify-center">{icon}</div>
    </Card>
  );
}

function Tab({ label, active, onClick }: any) {
  return (
    <button onClick={onClick} className={`pb-4 text-sm font-semibold transition-all border-b-2 ${active ? 'text-indigo-600 border-indigo-600' : 'text-slate-500 border-transparent hover:text-slate-700'}`}>
      {label}
    </button>
  );
}