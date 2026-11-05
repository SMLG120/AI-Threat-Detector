// Same-origin by default: the reverse proxy serves the UI and routes /api + /ws.
const BASE = import.meta.env.VITE_API_URL ?? "";
const KEY_STORAGE = "aiwaf_api_key";

export const auth = {
  getKey: () => sessionStorage.getItem(KEY_STORAGE),
  setKey: (key: string) => sessionStorage.setItem(KEY_STORAGE, key),
  clear: () => {
    sessionStorage.removeItem(KEY_STORAGE);
    window.dispatchEvent(new Event("aiwaf:unauthorized"));
  },
};

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-API-Key": auth.getKey() ?? "" };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    auth.clear();
    throw new Error("Unauthorized");
  }
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

export const api = {
  getStats: () => request<any>("GET", "/api/dashboard/stats"),
  getLogs: (page = 1, threatLevel?: string) =>
    request<any>(
      "GET",
      `/api/logs/?page=${page}&limit=50${threatLevel ? `&threat_level=${threatLevel}` : ""}`
    ),
  getAlerts: () => request<any>("GET", "/api/threats/alerts"),
  retrain: () => request<any>("POST", "/api/models/retrain", {}),
  modelStatus: () => request<any>("GET", "/api/models/status"),
  labelLog: (id: string, isMalicious: boolean) =>
    request<any>("PATCH", `/api/logs/${id}/label`, { is_malicious: isMalicious }),
};
