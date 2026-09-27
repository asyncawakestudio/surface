import type { Scan, ScanDetail } from "./types";

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
  listScans: () => request<Scan[]>("/api/scans"),
  getScan: (id: number) => request<ScanDetail>(`/api/scans/${id}`),
  createScan: (domain: string) =>
    request<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  deleteScan: (id: number) =>
    request<void>(`/api/scans/${id}`, { method: "DELETE" }),
};
