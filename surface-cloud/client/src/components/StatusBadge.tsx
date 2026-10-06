import type { ScanStatus } from "../types";

const styles: Record<ScanStatus, string> = {
  queued: "bg-slate-800 text-slate-300 ring-slate-700",
  running: "bg-cyan-950 text-cyan-300 ring-cyan-800",
  paused: "bg-amber-950 text-amber-300 ring-amber-800",
  completed: "bg-emerald-950 text-emerald-300 ring-emerald-800",
  failed: "bg-rose-950 text-rose-300 ring-rose-800",
};

export default function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[status]}`}
    >
      {status === "running" && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />
      )}
      {status}
    </span>
  );
}
