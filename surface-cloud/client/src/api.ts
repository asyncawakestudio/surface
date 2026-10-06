import type { Domain, Scan, ScanDetail, ScanDiff } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.error ?? `Request failed (${res.status})`);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  listDomains: () => request<Domain[]>("/api/domains"),
  listScans: (domain: string) =>
    request<Scan[]>(`/api/scans?domain=${encodeURIComponent(domain)}&limit=100`),
  getScan: (id: number) => request<ScanDetail>(`/api/scans/${id}`),
  getDiff: (id: number) => request<ScanDiff>(`/api/scans/${id}/diff`),
  createScan: (domain: string) =>
    request<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  pauseScan: (id: number) => request<Scan>(`/api/scans/${id}/pause`, { method: "POST" }),
};
