import type { ReactNode } from "react";
import { formatDate } from "../format";
import type { IpInfo, Scan, ScanDiff } from "../types";
import { Chip } from "./Table";

type Compared = Extract<ScanDiff, { base: Scan }>;

export function changeCount(d: Compared): number {
  return (
    d.subdomains.added.length +
    d.subdomains.removed.length +
    d.subdomains.no_longer_reported.length +
    d.dns_records.added.length +
    d.dns_records.removed.length +
    d.tls_certs.added.length +
    d.tls_certs.removed.length +
    d.tls_certs.changed.length +
    d.ip_info.added.length +
    d.ip_info.removed.length +
    d.ip_info.changed.length
  );
}

export default function ChangesPanel({ diff }: { diff: Compared }) {
  if (changeCount(diff) === 0) {
    return (
      <p className="px-4 py-10 text-center text-slate-400">
        Nothing changed since scan #{diff.base.id}.
      </p>
    );
  }

  const { subdomains, dns_records, tls_certs, ip_info } = diff;

  return (
    <div className="divide-y divide-slate-800">
      <Section
        title="Subdomains"
        added={subdomains.added.length}
        removed={subdomains.removed.length}
        stale={subdomains.no_longer_reported.length}
      >
        {subdomains.added.map((s) => (
          <Row key={`+${s.host}`} kind="added">
            {s.host}
          </Row>
        ))}
        {subdomains.removed.map((s) => (
          <Row key={`-${s.host}`} kind="removed">
            {s.host}
          </Row>
        ))}
        {subdomains.no_longer_reported.map((s) => (
          <Row key={`?${s.host}`} kind="stale">
            {s.host}{" "}
            <span className="text-xs text-slate-500">
              no source reported it this scan (kept, last seen via {s.sources.join(", ") || "unknown"})
            </span>
          </Row>
        ))}
      </Section>

      <Section title="DNS records" added={dns_records.added.length} removed={dns_records.removed.length}>
        {[
          ...dns_records.added.map((r) => ({ r, kind: "added" as const })),
          ...dns_records.removed.map((r) => ({ r, kind: "removed" as const })),
        ]
          .sort((a, b) => a.r.host.localeCompare(b.r.host) || a.r.type.localeCompare(b.r.type))
          .map(({ r, kind }) => (
            <Row key={`${kind}${r.host}${r.type}${r.value}`} kind={kind}>
              {r.host} <Chip>{r.type}</Chip>{" "}
              <span className="break-all text-slate-400">{r.value}</span>
            </Row>
          ))}
      </Section>

      <Section
        title="TLS certificates"
        added={tls_certs.added.length}
        removed={tls_certs.removed.length}
        changed={tls_certs.changed.length}
      >
        {tls_certs.changed.map(({ before, after }) => (
          <Row key={`~${after.host}:${after.port}`} kind="changed">
            {after.host}:{after.port}
            <span className="block pl-0 text-xs text-slate-400">
              {before.issuer_cn || "?"}, expires {formatDate(before.not_after)} → {after.issuer_cn || "?"},
              expires {formatDate(after.not_after)}
            </span>
          </Row>
        ))}
        {tls_certs.added.map((c) => (
          <Row key={`+${c.host}:${c.port}`} kind="added">
            {c.host}:{c.port} <span className="text-slate-400">({c.issuer_cn})</span>
          </Row>
        ))}
        {tls_certs.removed.map((c) => (
          <Row key={`-${c.host}:${c.port}`} kind="removed">
            {c.host}:{c.port} <span className="text-slate-400">({c.issuer_cn})</span>
          </Row>
        ))}
      </Section>

      <Section
        title="IPDR"
        added={ip_info.added.length}
        removed={ip_info.removed.length}
        changed={ip_info.changed.length}
        changedLabel="changed"
      >
        {ip_info.changed.map((c) => (
          <Row key={`~${c.ip}`} kind="changed">
            {c.ip}
            <span className="mt-1 block space-y-0.5 text-xs">
              {c.fields.map((f) => (
                <span key={f.field} className="block">
                  <span className="text-slate-500">{f.field}: </span>
                  <span className="text-rose-300/80 line-through">{f.before || "∅"}</span>
                  <span className="text-slate-500"> → </span>
                  <span className="text-emerald-300">{f.after || "∅"}</span>
                </span>
              ))}
            </span>
          </Row>
        ))}
        {ip_info.added.map((i) => (
          <Row key={`+${i.ip}`} kind="added">
            {i.ip} <IpSummary info={i} />
          </Row>
        ))}
        {ip_info.removed.map((i) => (
          <Row key={`-${i.ip}`} kind="removed">
            {i.ip} <IpSummary info={i} />
          </Row>
        ))}
      </Section>
      {!ip_info.compared && (
        <p className="px-4 py-3 text-xs text-slate-500">
          IPDR not compared: scan #{diff.base.id} ran before IP lookups were added.
        </p>
      )}
    </div>
  );
}

function IpSummary({ info }: { info: IpInfo }) {
  if (info.error) return <span className="text-xs text-amber-400">({info.error})</span>;
  const org = typeof info.data?.org === "string" ? info.data.org : "";
  const place = [info.data?.city, info.data?.country].filter((v) => typeof v === "string" && v).join(", ");
  const text = [org, place].filter(Boolean).join(" · ");
  return text ? <span className="text-slate-400">({text})</span> : null;
}

function Section({
  title,
  added,
  removed,
  changed = 0,
  stale = 0,
  changedLabel = "replaced",
  children,
}: {
  title: string;
  added: number;
  removed: number;
  changed?: number;
  stale?: number;
  changedLabel?: string;
  children: ReactNode;
}) {
  if (added + removed + changed + stale === 0) return null;
  return (
    <section className="px-4 py-4">
      <h4 className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
        {title}
        {added > 0 && <Chip tone="emerald">+{added} new</Chip>}
        {removed > 0 && <Chip tone="rose">−{removed} gone</Chip>}
        {changed > 0 && (
          <Chip tone="amber">
            {changed} {changedLabel}
          </Chip>
        )}
        {stale > 0 && <Chip>{stale} no longer reported</Chip>}
      </h4>
      <ul className="space-y-1">{children}</ul>
    </section>
  );
}

const marks = {
  added: { sign: "+", color: "text-emerald-400" },
  removed: { sign: "−", color: "text-rose-400" },
  changed: { sign: "~", color: "text-amber-400" },
  stale: { sign: "?", color: "text-slate-500" },
};

function Row({ kind, children }: { kind: keyof typeof marks; children: ReactNode }) {
  const m = marks[kind];
  return (
    <li className="flex gap-2 font-mono text-sm text-slate-200">
      <span className={`w-3 shrink-0 ${m.color}`}>{m.sign}</span>
      <span className={`min-w-0 ${kind === "removed" ? "text-slate-500 line-through" : ""}`}>
        {children}
      </span>
    </li>
  );
}
