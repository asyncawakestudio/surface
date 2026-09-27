import { useState } from "react";
import { api } from "./api";
import { usePoll } from "./hooks";
import { isActive, type Scan, type ScanDetail } from "./types";
import ScanForm from "./components/ScanForm";
import ScanList from "./components/ScanList";
import ScanDetailView from "./components/ScanDetail";

export default function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const anyActive = scans.some(isActive);
  const selected = scans.find((s) => s.id === selectedId);

  usePoll(
    () =>
      api
        .listScans()
        .then((list) => {
          setScans(list);
          setError(null);
          setSelectedId((cur) => cur ?? list[0]?.id ?? null);
        })
        .catch((e: Error) => setError(e.message)),
    anyActive ? 3000 : 15000,
  );

  // Refetch the detail when the selection changes and whenever the selected
  // scan's status/stage moves, so results appear as soon as it completes.
  usePoll(
    () => {
      if (selectedId === null) return setDetail(null);
      api
        .getScan(selectedId)
        .then(setDetail)
        .catch((e: Error) => setError(e.message));
    },
    selected && isActive(selected) ? 3000 : null,
    [selectedId, selected?.status, selected?.stage],
  );

  const handleCreated = (scan: Scan) => {
    setScans((prev) => [scan, ...prev]);
    setSelectedId(scan.id);
  };

  const handleDeleted = (id: number) => {
    setScans((prev) => prev.filter((s) => s.id !== id));
    setSelectedId((cur) => (cur === id ? null : cur));
    setDetail(null);
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-screen-2xl flex-col gap-4 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div className="flex items-center gap-3">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-white">Surface</h1>
              <p className="text-xs text-slate-400">How exposed are you?</p>
            </div>
          </div>
          <ScanForm onCreated={handleCreated} />
        </div>
      </header>

      {error && (
        <div className="border-b border-rose-900/50 bg-rose-950/40 px-6 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="mx-auto flex w-full max-w-screen-2xl flex-1 flex-col lg:flex-row">
        <aside className="border-slate-800 lg:w-80 lg:shrink-0 lg:border-r">
          <ScanList scans={scans} selectedId={selectedId} onSelect={setSelectedId} />
        </aside>
        <main className="min-w-0 flex-1 p-4 sm:p-6">
          {detail ? (
            <ScanDetailView scan={detail} onDeleted={handleDeleted} />
          ) : (
            <EmptyState hasScans={scans.length > 0} />
          )}
        </main>
      </div>
    </div>
  );
}

function EmptyState({ hasScans }: { hasScans: boolean }) {
  return (
    <div className="flex h-full min-h-80 flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 text-center">
      <p className="text-slate-300">{hasScans ? "Select a scan" : "No scans yet"}</p>
      <p className="mt-1 text-sm text-slate-500">
        Enter a domain above to map its subdomains, DNS records and TLS certificates.
      </p>
    </div>
  );
}
