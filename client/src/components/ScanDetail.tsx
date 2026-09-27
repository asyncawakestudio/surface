import { useMemo, useState } from "react";
import { api } from "../api";
import { daysUntil, formatDuration, formatRelative } from "../format";
import { isActive, type ScanDetail as Detail } from "../types";
import StatusBadge from "./StatusBadge";
import SubdomainTable from "./SubdomainTable";
import DnsTable from "./DnsTable";
import CertTable from "./CertTable";

const STAGES = [
  { key: "subdomains", label: "Subdomains", tool: "subfinder" },
  { key: "dns", label: "DNS", tool: "dnsx" },
  { key: "tls", label: "TLS", tool: "tlsx" },
] as const;

type Tab = "subdomains" | "dns" | "tls";

interface Props {
  scan: Detail;
  onDeleted: (id: number) => void;
}

export default function ScanDetail({ scan, onDeleted }: Props) {
  const [tab, setTab] = useState<Tab>("subdomains");
  const [deleting, setDeleting] = useState(false);

  const certIssues = useMemo(
    () =>
      scan.tls_certs.filter(
        (c) => c.expired || c.self_signed || c.mismatched || daysUntil(c.not_after) < 30,
      ).length,
    [scan.tls_certs],
  );
  const resolvedHosts = useMemo(
    () =>
      new Set(
        scan.dns_records.filter((r) => r.type === "A" || r.type === "AAAA").map((r) => r.host),
      ).size,
    [scan.dns_records],
  );

  async function remove() {
    if (!confirm(`Delete scan of ${scan.domain}?`)) return;
    setDeleting(true);
    try {
      await api.deleteScan(scan.id);
      onDeleted(scan.id);
    } catch (e) {
      alert((e as Error).message);
      setDeleting(false);
    }
  }

  const active = isActive(scan);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="font-mono text-2xl font-semibold text-white">{scan.domain}</h2>
            <StatusBadge status={scan.status} />
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Scan #{scan.id} · started {formatRelative(scan.created_at)} · took{" "}
            {formatDuration(scan.started_at, scan.finished_at)}
          </p>
        </div>
        <button
          onClick={remove}
          disabled={active || deleting}
          className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:border-rose-700 hover:text-rose-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Delete
        </button>
      </div>

      {scan.error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 px-4 py-3 text-sm text-rose-300">
          {scan.error}
        </div>
      )}

      {active && <Pipeline stage={scan.stage} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Subdomains" value={scan.subdomains.length} />
        <Stat label="Resolved hosts" value={resolvedHosts} />
        <Stat label="DNS records" value={scan.dns_records.length} />
        <Stat label="TLS certificates" value={scan.tls_certs.length} />
        <Stat label="Cert issues" value={certIssues} tone={certIssues > 0 ? "warn" : "ok"} />
      </div>

      {!active && (
        <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
          <nav className="flex gap-1 border-b border-slate-800 px-2">
            {(
              [
                ["subdomains", "Subdomains", scan.subdomains.length],
                ["dns", "DNS records", scan.dns_records.length],
                ["tls", "TLS certificates", scan.tls_certs.length],
              ] as const
            ).map(([key, label, count]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`-mb-px border-b-2 px-3 py-3 text-sm transition ${
                  tab === key
                    ? "border-cyan-400 text-white"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                {label}
                <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">
                  {count}
                </span>
              </button>
            ))}
          </nav>
          {tab === "subdomains" && (
            <SubdomainTable
              subdomains={scan.subdomains}
              records={scan.dns_records}
              certs={scan.tls_certs}
            />
          )}
          {tab === "dns" && <DnsTable records={scan.dns_records} />}
          {tab === "tls" && <CertTable certs={scan.tls_certs} />}
        </section>
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "warn" }) {
  const color =
    tone === "warn" ? "text-amber-300" : tone === "ok" ? "text-emerald-300" : "text-white";
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
      <p className="text-xs text-slate-400">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

function Pipeline({ stage }: { stage: string | null }) {
  const current = STAGES.findIndex((s) => s.key === stage);
  return (
    <ol className="grid grid-cols-3 gap-3">
      {STAGES.map((s, i) => {
        const state = current === -1 ? "pending" : i < current ? "done" : i === current ? "active" : "pending";
        return (
          <li
            key={s.key}
            className={`rounded-xl border px-4 py-3 ${
              state === "active"
                ? "border-cyan-700 bg-cyan-950/40"
                : state === "done"
                  ? "border-emerald-900 bg-emerald-950/20"
                  : "border-slate-800 bg-slate-900/40"
            }`}
          >
            <div className="flex items-center gap-2 text-sm font-medium text-white">
              {state === "active" && (
                <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
              )}
              {state === "done" && <span className="text-emerald-400">✓</span>}
              {s.label}
            </div>
            <p className="mt-0.5 font-mono text-xs text-slate-500">{s.tool}</p>
          </li>
        );
      })}
    </ol>
  );
}
