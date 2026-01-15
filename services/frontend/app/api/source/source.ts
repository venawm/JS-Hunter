import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import fs from 'fs';
import path from 'path';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');
  const filename = searchParams.get('filename');

  if (!domain || !filename) return NextResponse.json({ error: 'Missing params' }, { status: 400 });

  try {
    const sql = `
      SELECT a.local_path 
      FROM assets a 
      JOIN targets t ON a.target_id = t.id 
      WHERE t.domain = $1 AND a.url = $2
      LIMIT 1
    `;
    const res = await query(sql, [domain, filename]);
    
    if (res.rows.length === 0) return NextResponse.json({ error: 'Asset not found' }, { status: 404 });
    
    // Ensure path is treated as absolute inside the container
    const filePath = path.resolve(res.rows[0].local_path);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf-8');
      // Limit line count for performance
      const lines = content.split('\n').slice(0, 5000).join('\n');
      return NextResponse.json({ content: lines });
    }
    
    return NextResponse.json({ error: 'File not found on disk' }, { status: 404 });
  } catch (error) {
    console.error("Source Read Error:", error);
    return NextResponse.json({ error: 'Server Error' }, { status: 500 });
  }
}