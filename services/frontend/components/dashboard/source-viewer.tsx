'use client';

import { useEffect, useState } from 'react';
import { fetchSourceCode } from '@/lib/api';

export function SourceViewer({ domain, filename }: { domain: string; filename: string }) {
  const [code, setCode] = useState('Loading...');

  console.log(domain,filename)

  useEffect(() => {
    if (!domain || !filename) return;
    fetchSourceCode(domain, filename).then(d => setCode(d.content || '// Empty file')).catch(() => setCode('// Error loading file'));
  }, [domain, filename]);

  return (
    <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm h-[calc(100vh-250px)] flex flex-col">
      <div className="bg-slate-50 border-b border-slate-200 px-4 py-3 flex items-center gap-2">
        <span className="text-xs font-bold text-slate-400 uppercase">Viewer</span>
        <span className="text-slate-300">/</span>
        <span className="text-sm font-mono text-indigo-600 font-medium">{filename}</span>
      </div>
      <div className="flex-1 overflow-auto p-0">
        <pre className="text-xs font-mono text-slate-600 leading-relaxed p-6">
          {code}
        </pre>
      </div>
    </div>
  );
}