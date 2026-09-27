import type { Scan, ScanStatus } from "../types";

const dot: Record<ScanStatus, string> = {
  queued: "bg-slate-400",
  running: "bg-cyan-400 animate-pulse",
  paused: "bg-amber-400",
  completed: "bg-emerald-400",
  failed: "bg-rose-400",
};

interface Props {
  scans: Scan[]; // newest first
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export default function ScanHistory({ scans, selectedId, onSelect }: Props) {
  return (
    <nav aria-label="Scan history">
      <h3 className="mb-2 text-xs font-semibold tracking-wider text-slate-500 uppercase">
        History
      </h3>
      <ol className="flex gap-2 overflow-x-auto pb-1">
        {scans.map((s, i) => (
          <li key={s.id} className="shrink-0">
            <button
              onClick={() => onSelect(s.id)}
              title={s.status}
              className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs transition ${
                s.id === selectedId
                  ? "border-cyan-700 bg-cyan-950/40 text-white"
                  : "border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${dot[s.status]}`} />
              {new Date(s.created_at).toLocaleString(undefined, {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })}
              {i === 0 && <span className="text-slate-500">latest</span>}
            </button>
          </li>
        ))}
      </ol>
    </nav>
  );
}
