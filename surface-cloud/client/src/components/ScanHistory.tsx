import type { Scan, ScanStatus } from "../types";

const statusMark: Record<ScanStatus, string> = {
  queued: "·",
  running: "…",
  paused: "‖",
  completed: "✓",
  failed: "✕",
};

function labelFor(s: Scan, latest: boolean): string {
  const when = new Date(s.created_at).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${statusMark[s.status]} ${when} — ${s.status}${latest ? " (latest)" : ""}`;
}

interface Props {
  scans: Scan[]; // newest first
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export default function ScanHistory({ scans, selectedId, onSelect }: Props) {
  return (
    <div className="flex items-center gap-3">
      <label htmlFor="scan-history" className="text-xs font-semibold tracking-wider text-slate-500 uppercase">
        History
      </label>
      <select
        id="scan-history"
        value={selectedId ?? ""}
        onChange={(e) => onSelect(Number(e.target.value))}
        className="max-w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:border-cyan-500 focus:outline-none"
      >
        {scans.map((s, i) => (
          <option key={s.id} value={s.id}>
            {labelFor(s, i === 0)}
          </option>
        ))}
      </select>
      <span className="text-xs text-slate-500">
        {scans.length} scan{scans.length === 1 ? "" : "s"}
      </span>
    </div>
  );
}
