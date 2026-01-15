'use client';

import { ArrowRight } from 'lucide-react';
import { Finding } from '@/lib/types';
import { SeverityBadge } from '../ui/badge-severity';


interface Props {
  data: Finding[];
  onSelectFile: (url: string) => void;
}

export function FindingsTable({ data, onSelectFile }: Props) {
  if (data.length === 0) {
    return <div className="p-12 text-center text-slate-400 italic bg-white rounded-xl border border-slate-200">No vulnerabilities detected. System clean.</div>;
  }

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-50 text-slate-500 font-semibold border-b border-slate-100">
          <tr>
            <th className="px-6 py-4 w-20">ID</th>
            <th className="px-6 py-4">Type</th>
            <th className="px-6 py-4">Severity</th>
            <th className="px-6 py-4">Evidence</th>
            <th className="px-6 py-4">Location</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {data.map((f) => (
            <tr key={f.id} className="hover:bg-slate-50/50 transition-colors group">
              <td className="px-6 py-4 text-slate-400 font-mono text-xs">#{f.id}</td>
              <td className="px-6 py-4 font-semibold text-slate-700">{f.type}</td>
              <td className="px-6 py-4"><SeverityBadge level={f.severity} /></td>
              <td className="px-6 py-4">
                <code className="bg-slate-50 text-slate-600 px-2 py-1 rounded border border-slate-200 text-xs font-mono block truncate max-w-[400px]" title={f.evidence}>
                  {f.evidence}
                </code>
              </td>
              <td className="px-6 py-4">
                <button onClick={() => onSelectFile(f.url)} className="text-indigo-600 hover:text-indigo-800 font-medium text-xs flex items-center gap-1 hover:underline">
                  {f.url}:{f.line} <ArrowRight className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-all" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}