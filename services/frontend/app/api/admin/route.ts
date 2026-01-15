import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export async function POST(request: Request) {
  try {
    const { action, id, targetId } = await request.json();

    if (action === 'wipe_db') {
      await query("TRUNCATE targets, assets, findings RESTART IDENTITY CASCADE;");
      return NextResponse.json({ message: "Database Wiped" });
    }

    if (action === 'delete_finding' && id) {
      await query("DELETE FROM findings WHERE id = $1", [id]);
      return NextResponse.json({ message: `Finding ${id} deleted` });
    }

    if (action === 'clear_project' && targetId) {
      await query(`
        DELETE FROM findings 
        WHERE asset_id IN (SELECT id FROM assets WHERE target_id = $1)
      `, [targetId]);
      return NextResponse.json({ message: "Project findings cleared" });
    }

    return NextResponse.json({ error: "Invalid Action" }, { status: 400 });
  } catch (error) {
    console.error("Admin Action Error:", error);
    return NextResponse.json({ error: "Database Error" }, { status: 500 });
  }
}