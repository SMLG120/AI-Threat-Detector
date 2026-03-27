const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

export const api = {
  getStats: () => get<any>("/api/dashboard/stats"),
  getLogs: (page = 1, threatLevel?: string) =>
    get<any>(
      `/api/logs/?page=${page}&limit=50${threatLevel ? `&threat_level=${threatLevel}` : ""}`
    ),
  getAlerts: () => get<any>("/api/threats/alerts"),
  ingestLog: (data: unknown) => post<any>("/api/logs/ingest", data),
  retrain: () => post<any>("/api/models/retrain", {}),
  modelStatus: () => get<any>("/api/models/status"),
};
