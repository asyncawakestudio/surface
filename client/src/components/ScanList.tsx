import { formatRelative } from "../format";
import type { Scan } from "../types";
import StatusBadge from "./StatusBadge";

interface Props {
  scans: Scan[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export default function ScanList({ scans, selectedId, onSelect }: Props) {
  return (
    <div className="p-4">
      <h2 className="mb-3 px-2 text-xs font-semibold tracking-wider text-slate-500 uppercase">
        Scans
      </h2>
      {scans.length === 0 ? (
        <p className="px-2 text-sm text-slate-500">Nothing here yet.</p>
      ) : (
        <ul className="flex gap-2 overflow-x-auto pb-2 lg:flex-col lg:gap-1 lg:overflow-visible lg:pb-0">
          {scans.map((s) => (
            <li key={s.id} className="shrink-0 lg:shrink">
              <button
                onClick={() => onSelect(s.id)}
                className={`w-56 rounded-lg px-3 py-2.5 text-left transition lg:w-full ${
                  s.id === selectedId
                    ? "bg-slate-800/80 ring-1 ring-slate-700"
                    : "hover:bg-slate-900"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-sm text-white">{s.domain}</span>
                  <StatusBadge status={s.status} />
                </div>
                <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                  <span>
                    {s.status === "running" && s.stage
                      ? `${s.stage}…`
                      : `${s.counts.subdomains} hosts · ${s.counts.tls_certs} certs`}
                  </span>
                  <span>{formatRelative(s.created_at)}</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
