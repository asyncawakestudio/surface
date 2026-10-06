import { useState } from "react";
import { api } from "./api";
import { usePoll } from "./hooks";
import { isActive, type Domain, type Scan, type ScanDetail, type ScanDiff } from "./types";
import ScanForm from "./components/ScanForm";
import ConfigManager from "./components/ConfigManager";
import DomainList from "./components/DomainList";
import ScanHistory from "./components/ScanHistory";
import ScanDetailView from "./components/ScanDetail";

export default function App() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  // null follows the domain's latest scan.
  const [pinnedScanId, setPinnedScanId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showConfigs, setShowConfigs] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = () => setRefreshKey((k) => k + 1);
  const onError = (e: Error) => setError(e.message);

  const anyActive = domains.some((d) => isActive(d.latest));
  const selectedScanId = pinnedScanId ?? scans[0]?.id ?? null;
  const selectedScan = scans.find((s) => s.id === selectedScanId);

  usePoll(
    () =>
      api
        .listDomains()
        .then((list) => {
          setDomains(list);
          setError(null);
          setSelectedDomain((cur) => cur ?? list[0]?.domain ?? null);
        })
        .catch(onError),
    anyActive ? 3000 : 15000,
    [refreshKey],
  );

  usePoll(
    () => {
      if (!selectedDomain) return setScans([]);
      api
        .listScans(selectedDomain)
        .then((list) => {
          // Ignore responses for a domain that is no longer selected.
          if (list[0]?.domain === selectedDomain) setScans(list);
        })
        .catch(onError);
    },
    anyActive ? 3000 : 15000,
    [selectedDomain, refreshKey],
  );

  // Refetch the detail when the selection changes and whenever the selected
  // scan's status/stage moves, so results appear as soon as it completes.
  usePoll(
    () => {
      if (selectedScanId === null) return setDetail(null);
      api.getScan(selectedScanId).then(setDetail).catch(onError);
    },
    selectedScan && isActive(selectedScan) ? 3000 : null,
    [selectedScanId, selectedScan?.status, selectedScan?.stage],
  );

  usePoll(
    () => {
      setDiff(null);
      if (selectedScanId === null || selectedScan?.status !== "completed") return;
      api.getDiff(selectedScanId).then(setDiff).catch(onError);
    },
    null,
    [selectedScanId, selectedScan?.status],
  );

  const selectDomain = (domain: string) => {
    if (domain === selectedDomain) return;
    setSelectedDomain(domain);
    setScans([]);
    setPinnedScanId(null);
    setDetail(null);
  };

  const handleCreated = (scan: Scan) => {
    selectDomain(scan.domain);
    setPinnedScanId(null);
    refresh();
  };

  const handlePause = async (scan: Scan) => {
    try {
      await api.pauseScan(scan.id);
    } catch (e) {
      onError(e as Error);
    }
    refresh();
  };

  const handleScanAgain = async (domain: string) => {
    try {
      handleCreated(await api.createScan(domain));
    } catch (e) {
      onError(e as Error);
    }
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
          <div className="flex items-end gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Quick scan</span>
              <ScanForm onCreated={handleCreated} />
            </div>
            <button
              onClick={() => setShowConfigs(true)}
              className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 transition hover:border-cyan-600 hover:text-white"
            >
              Configured scans
            </button>
          </div>
        </div>
      </header>

      {showConfigs && <ConfigManager onClose={() => setShowConfigs(false)} />}

      {error && (
        <div className="flex items-center justify-between border-b border-rose-900/50 bg-rose-950/40 px-6 py-2 text-sm text-rose-300">
          {error}
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200" aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      <div className="mx-auto flex w-full max-w-screen-2xl flex-1 flex-col lg:flex-row">
        <aside className="border-slate-800 lg:w-80 lg:shrink-0 lg:border-r">
          <DomainList domains={domains} selected={selectedDomain} onSelect={selectDomain} />
        </aside>
        <main className="min-w-0 flex-1 space-y-6 p-4 sm:p-6">
          {selectedDomain && scans.length > 0 && (
            <ScanHistory
              scans={scans}
              selectedId={selectedScanId}
              onSelect={(id) => setPinnedScanId(id === scans[0]?.id ? null : id)}
            />
          )}
          {detail && detail.domain === selectedDomain ? (
            <ScanDetailView
              scan={detail}
              diff={diff?.base && diff.base.domain === detail.domain ? diff : null}
              isLatest={detail.id === scans[0]?.id}
              onPause={handlePause}
              onScanAgain={handleScanAgain}
            />
          ) : (
            !selectedDomain && <EmptyState />
          )}
        </main>
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex h-full min-h-80 flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 text-center">
      <p className="text-slate-300">No scans yet</p>
      <p className="mt-1 text-sm text-slate-500">
        Enter a domain above to map its subdomains, DNS records and TLS certificates.
      </p>
    </div>
  );
}
