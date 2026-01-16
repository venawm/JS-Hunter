import { NextResponse } from 'next/server';
import { Pool } from 'pg';
import zlib from 'zlib';
import { promisify } from 'util';
import { query } from '@/lib/db';

// Promisify zlib functions for better async handling
const inflateAsync = promisify(zlib.inflate);



export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');
  const filename = searchParams.get('filename');

  if (!domain || !filename) {
    return NextResponse.json({ error: 'Missing params' }, { status: 400 });
  }

  try {
    // 1. Efficient SQL Join
    // Get the compressed content by joining Targets -> Assets -> SourceFiles
    const sql = `
      SELECT s.content_compressed
      FROM source_files s
      JOIN assets a ON a.source_hash = s.hash
      JOIN targets t ON a.target_id = t.id
      WHERE t.domain = $1 AND a.url = $2
      LIMIT 1
    `;
    
    const res = await query(sql, [domain, filename]);
    
    if (res.rows.length === 0) {
      return NextResponse.json({ 
        content: '// Source code not found in database.\n// It may have been cleaned up or the scan failed.' 
      });
    }
    
    // 2. Decompression
    // Python's zlib.compress() uses DEFLATE algorithm
    // We need to use inflate (not inflateSync or unzip)
    const compressedBuffer = Buffer.from(res.rows[0].content_compressed);
    
    try {
      // Use inflate to match Python's zlib.compress/decompress
      const decompressed = await inflateAsync(compressedBuffer);
      const content = decompressed.toString('utf-8');

      return NextResponse.json({ content });
      
    } catch (decompressError) {
      console.error("Decompression Error:", decompressError);
      
      // Fallback: Try with inflateRaw in case of different compression format
      try {
        const decompressed = zlib.inflateRawSync(compressedBuffer);
        const content = decompressed.toString('utf-8');
        return NextResponse.json({ content });
      } catch (fallbackError) {
        console.error("Fallback Decompression Failed:", fallbackError);
        return NextResponse.json({ 
          error: 'Failed to decompress source code',
          details: 'The stored data may be corrupted or in an unexpected format'
        }, { status: 500 });
      }
    }

  } catch (error) {
    console.error("Source Retrieval Error:", error);
    return NextResponse.json({ 
      error: 'Database Read Failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}