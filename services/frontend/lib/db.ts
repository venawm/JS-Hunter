import { Pool } from 'pg';

const pool = new Pool({
  connectionString: "postgresql://titan:forge_password@db:5432/titan_core"
,
});

export const query = async (text: string, params?: any[]) => {
  return pool.query(text, params);
};