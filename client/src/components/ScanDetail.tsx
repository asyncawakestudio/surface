import { useEffect, useMemo, useState } from "react";
import { daysUntil, formatDuration, formatRelative } from "../format";
import {
  certKey,
  dnsKey,
  isActive,
  type Scan,
  type ScanDetail as Detail,
  type ScanDiff,
} from "../types";
import StatusBadge from "./StatusBadge";
import SubdomainTable from "./SubdomainTable";
import DnsTable from "./DnsTable";
import CertTable from "./CertTable";
import IpdrTable from "./IpdrTable";
import ChangesPanel, { changeCount } from "./ChangesPanel";

const STAGES = [
  { key: "subdomains", label: "Subdomains", tool: "subfinder" },
  { key: "dns", label: "DNS", tool: "dnsx" },
  { key: "ipinfo", label: "IPDR", tool: "ipinfo.io" },
  { key: "tls", label: "TLS", tool: "tlsx" },
] as const;

type Tab = "changes" | "subdomains" | "dns" | "ipdr" | "tls";
type Compared = Extract<ScanDiff, { base: Scan }>;

interface Props {
  scan: Detail;
  /** Diff against the previous completed scan; null if there isn't one. */
  diff: Compared | null;
  isLatest: boolean;
  onPause: (scan: Scan) => Promise<void>;
  onScanAgain: (domain: string) => Promise<void>;
}

export default function ScanDetail({ scan, diff, isLatest, onPause, onScanAgain }: Props) {
  const [tab, setTab] = useState<Tab>("subdomains");
  const [busy, setBusy] = useState(false);

  // Open on the changes when there are any, once per scan.
  const changes = diff ? changeCount(diff) : 0;
  useEffect(() => {
    setTab(changes > 0 ? "changes" : "subdomains");
  }, [scan.id, changes > 0]);

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

  const added = useMemo(
    () => ({
      subdomains: new Set(diff?.subdomains.added.map((s) => s.host)),
      dns: new Set(diff?.dns_records.added.map(dnsKey)),
      certs: new Set([
        ...(diff?.tls_certs.added.map(certKey) ?? []),
        ...(diff?.tls_certs.changed.map((c) => certKey(c.after)) ?? []),
      ]),
      ips: new Set(diff?.ip_info.added.map((i) => i.ip)),
      ipsChanged: new Set(diff?.ip_info.changed.map((c) => c.ip)),
    }),
    [diff],
  );

  const act = (fn: () => Promise<void>) => async () => {
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };

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
            {diff && <> · compared with scan #{diff.base.id} from {formatRelative(diff.base.created_at)}</>}
          </p>
        </div>
        <div className="flex gap-2">
          {active ? (
            <button
              onClick={act(() => onPause(scan))}
              disabled={busy}
              className="rounded-lg border border-amber-800 px-3 py-1.5 text-sm text-amber-300 transition hover:bg-amber-950/50 disabled:opacity-50"
            >
              {busy ? "Pausing…" : "Pause"}
            </button>
          ) : (
            isLatest && (
              <button
                onClick={act(() => onScanAgain(scan.domain))}
                disabled={busy}
                className="rounded-lg bg-cyan-500 px-3 py-1.5 text-sm font-medium text-slate-950 transition hover:bg-cyan-400 disabled:opacity-50"
              >
                {busy ? "Starting…" : "Scan again"}
              </button>
            )
          )}
        </div>
      </div>

      {scan.status === "paused" && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
          Paused{scan.stage ? ` during the ${scan.stage} stage` : ""}. The tools can't pick up
          partway through a stage, so <span className="font-medium">Scan again</span> starts a new
          scan from the beginning. This one stays in the history.
        </div>
      )}
      {scan.error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 px-4 py-3 text-sm text-rose-300">
          {scan.error}
        </div>
      )}

      {active && <Pipeline stage={scan.stage} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat
          label="Subdomains"
          value={scan.subdomains.length}
          delta={diff && [diff.subdomains.added.length, diff.subdomains.removed.length]}
        />
        <Stat label="Resolved hosts" value={resolvedHosts} />
        <Stat
          label="DNS records"
          value={scan.dns_records.length}
          delta={diff && [diff.dns_records.added.length, diff.dns_records.removed.length]}
        />
        <Stat
          label="TLS certificates"
          value={scan.tls_certs.length}
          delta={diff && [diff.tls_certs.added.length, diff.tls_certs.removed.length]}
        />
        <Stat label="Cert issues" value={certIssues} tone={certIssues > 0 ? "warn" : "ok"} />
      </div>

      {scan.status === "completed" && (
        <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
          <nav className="flex gap-1 overflow-x-auto border-b border-slate-800 px-2">
            {(
              [
                ...(diff ? [["changes", "Changes", changes] as const] : []),
                ["subdomains", "Subdomains", scan.subdomains.length],
                ["dns", "DNS records", scan.dns_records.length],
                ["ipdr", "IPDR", scan.ip_info.length],
                ["tls", "TLS certificates", scan.tls_certs.length],
              ] as const
            ).map(([key, label, count]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`-mb-px border-b-2 px-3 py-3 text-sm whitespace-nowrap transition ${
                  tab === key
                    ? "border-cyan-400 text-white"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                {label}
                <span
                  className={`ml-2 rounded px-1.5 py-0.5 text-xs ${
                    key === "changes" && count > 0
                      ? "bg-amber-950 text-amber-300"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {count}
                </span>
              </button>
            ))}
          </nav>
          {tab === "changes" && diff && <ChangesPanel diff={diff} />}
          {tab === "subdomains" && (
            <SubdomainTable
              subdomains={scan.subdomains}
              records={scan.dns_records}
              certs={scan.tls_certs}
              added={added.subdomains}
            />
          )}
          {tab === "dns" && <DnsTable records={scan.dns_records} added={added.dns} />}
          {tab === "ipdr" && <IpdrTable
              records={scan.ip_info}
              dns={scan.dns_records}
              added={added.ips}
              changed={added.ipsChanged}
            />}
          {tab === "tls" && <CertTable certs={scan.tls_certs} added={added.certs} />}
        </section>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
  delta,
}: {
  label: string;
  value: number;
  tone?: "ok" | "warn";
  delta?: [added: number, removed: number] | null;
}) {
  const color =
    tone === "warn" ? "text-amber-300" : tone === "ok" ? "text-emerald-300" : "text-white";
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
      <p className="text-xs text-slate-400">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</p>
      {delta && (delta[0] > 0 || delta[1] > 0) && (
        <p className="mt-0.5 text-xs tabular-nums">
          {delta[0] > 0 && <span className="text-emerald-400">+{delta[0]}</span>}
          {delta[0] > 0 && delta[1] > 0 && <span className="text-slate-600"> / </span>}
          {delta[1] > 0 && <span className="text-rose-400">−{delta[1]}</span>}
        </p>
      )}
    </div>
  );
}

function Pipeline({ stage }: { stage: string | null }) {
  const current = STAGES.findIndex((s) => s.key === stage);
  return (
    <ol className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {STAGES.map((s, i) => {
        const state =
          current === -1 ? "pending" : i < current ? "done" : i === current ? "active" : "pending";
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
