'use client';

import { useState } from 'react';
import { Play, Trash2, ShieldCheck, Globe, Code2, Loader2 } from 'lucide-react';
import { useDashboardContext } from '@/contexts/dashboard-context';
import { triggerScan, adminAction } from '@/lib/api';

export function Sidebar() {
  const { triggerRefresh } = useDashboardContext();
  const [form, setForm] = useState({ project: '', code: '' });
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!form.project || !form.code) return;
    setLoading(true);
    try {
      await triggerScan({ domain: form.project, filename: `scan_${Date.now()}.js`, code: form.code });
      setForm(p => ({ ...p, code: '' })); // Clear code only
      triggerRefresh();
    } finally { setLoading(false); }
  };

  const handleWipe = async () => {
    if (confirm("Nuclear Wipe?")) {
      await adminAction('wipe_db');
      window.location.reload();
    }
  };

  return (
    <aside className="w-80 bg-white border-r border-slate-200 flex flex-col h-screen fixed z-40">
      <div className="p-6 pb-2 flex items-center gap-3">
        <div className="h-10 w-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-200">
          <ShieldCheck className="text-white h-6 w-6" />
        </div>
        <div>
          <h1 className="font-bold text-lg text-slate-900">JS Hunter</h1>
        </div>
      </div>

      <div className="flex-1 px-6 py-4 space-y-6 overflow-hidden flex flex-col">
        <InputGroup label="Target" icon={<Globe size={12} />}>
          <input 
            className="w-full bg-slate-50 border border-slate-200 rounded-lg p-3 text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none font-medium"
            placeholder="e.g. acme-corp"
            value={form.project}
            onChange={e => setForm(f => ({ ...f, project: e.target.value }))}
          />
        </InputGroup>
        
        <InputGroup label="Source Code" icon={<Code2 size={12} />} className="flex-1 flex flex-col">
          <textarea 
            className="w-full h-full bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none resize-none"
            placeholder="// Paste JS..."
            value={form.code}
            onChange={e => setForm(f => ({ ...f, code: e.target.value }))}
          />
        </InputGroup>
      </div>

      <div className="p-6 border-t border-slate-100 space-y-3">
        <button onClick={handleScan} disabled={loading} className="w-full h-11 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg flex items-center justify-center gap-2 transition-all shadow-md disabled:opacity-70">
          {loading ? <Loader2 className="animate-spin h-4 w-4" /> : <Play className="h-4 w-4 fill-current" />}
          {loading ? "Analyzing..." : "Start Scan"}
        </button>
        <button onClick={handleWipe} className="w-full py-2 text-slate-400 hover:text-red-600 text-xs font-medium flex items-center justify-center gap-2">
          <Trash2 size={12} /> Reset Database
        </button>
      </div>
    </aside>
  );
}

function InputGroup({ label, icon, children, className }: any) {
  return (
    <div className={className}>
      <label className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2 mb-2">{icon} {label}</label>
      {children}
    </div>
  );
}