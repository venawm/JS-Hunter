import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    
    // 'api' refers to the service name in docker-compose
    const pythonApiUrl = 'http://api:8000/blackops/manual';

    const res = await fetch(pythonApiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`Python API responded with ${res.status}`);
    }
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Scan Error:", error);
    return NextResponse.json({ error: 'Failed to contact Scanner' }, { status: 500 });
  }
}