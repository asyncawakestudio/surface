import { useState, type FormEvent } from "react";
import { api } from "../api";
import type { Scan } from "../types";

export default function ScanForm({ onCreated }: { onCreated: (scan: Scan) => void }) {
  const [domain, setDomain] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      onCreated(await api.createScan(domain.trim()));
      setDomain("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex w-full flex-col gap-1 sm:w-auto">
      <div className="flex gap-2">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          aria-label="Domain to scan"
          className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/30 focus:outline-none sm:w-72"
        />
        <button
          type="submit"
          disabled={submitting || !domain.trim()}
          className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Starting…" : "Scan"}
        </button>
      </div>
      {error && <p className="text-xs text-rose-400">{error}</p>}
    </form>
  );
}
