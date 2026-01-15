import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export async function GET(request: Request) {
  // Prevent caching for live dashboard updates
  const headers = { 'Cache-Control': 'no-store, max-age=0' };
  
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  try {
    // 1. Get Targets
    const targetsRes = await query('SELECT * FROM targets ORDER BY id DESC');
    const targets = targetsRes.rows;

    let findings: any[] = [];
    let metrics = { critical: 0, intel: 0, shadow: 0 };

    // 2. Get Findings if a domain is selected
    if (domain) {
      const target = targets.find((t: any) => t.domain === domain);
      if (target) {
        const sql = `
          SELECT f.id, f.type, f.severity, f.evidence, f.line, a.url 
          FROM findings f 
          JOIN assets a ON f.asset_id = a.id 
          WHERE a.target_id = $1
          ORDER BY f.id DESC
        `;
        const res = await query(sql, [target.id]);
        findings = res.rows;

        // Calculate Metrics
        metrics.critical = findings.filter((f: any) => f.severity === 'CRITICAL').length;
        metrics.intel = findings.filter((f: any) => f.type === 'INTEL_MATCH').length;
        metrics.shadow = findings.filter((f: any) => f.type.includes('SHADOW')).length;
      }
    }

    return NextResponse.json({ targets, findings, metrics }, { headers });
  } catch (error) {
    console.error("DB Error:", error);
    return NextResponse.json({ error: 'DB Error' }, { status: 500, headers });
  }
}