export async function fetchDashboard(domain?: string) {
  const params = new URLSearchParams(domain ? { domain } : {});
  const res = await fetch(`/api/dashboard?${params}`);
  if (!res.ok) throw new Error("Failed to fetch dashboard data");
  return res.json();
}

export async function fetchSourceCode(domain: string, filename: string) {
  const res = await fetch(`/api/source?domain=${domain}&filename=${filename}`);
  if (!res.ok) throw new Error("Failed to fetch source");
  return res.json();
}

export async function triggerScan(payload: { domain: string; filename: string; code: string }) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Scan failed");
  return res.json();
}

export async function adminAction(action: string, payload: any = {}) {
  await fetch('/api/admin', {
    method: 'POST',
    body: JSON.stringify({ action, ...payload }),
  });
}