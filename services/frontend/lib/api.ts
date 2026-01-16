export async function fetchDashboard(domain?: string) {
  const params = new URLSearchParams(domain ? { domain } : {});
  const res = await fetch(`/api/dashboard?${params}`);
  if (!res.ok) throw new Error("Failed to fetch dashboard data");
  return res.json();
}

export async function fetchSourceCode(domain: string, filename: string) {
  const params = new URLSearchParams({ domain, filename });
  const res = await fetch(`/api/source?${params}`);
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || "Failed to fetch source");
  }
  return res.json();
}

export async function triggerScan(payload: { domain: string; filename: string; code: string }) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || "Scan failed");
  }
  return res.json();
}

export async function adminAction(action: string, payload: any = {}) {
  const res = await fetch('/api/admin', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ action, ...payload }),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || "Admin action failed");
  }
  return res.json();
}