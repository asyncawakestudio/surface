import { Fragment, useMemo, useState } from "react";
import type { DnsRecord, IpInfo } from "../types";
import { Chip, EmptyRow, NewChip, SearchBar, Table } from "./Table";

// Common ipinfo fields first, in a sensible reading order; any other keys
// the plan returns follow alphabetically.
const PREFERRED = [
  "hostname",
  "org",
  "asn.asn",
  "asn.name",
  "asn.domain",
  "asn.route",
  "asn.type",
  "city",
  "region",
  "country",
  "postal",
  "loc",
  "timezone",
  "company.name",
  "company.domain",
  "company.type",
  "privacy.vpn",
  "privacy.proxy",
  "privacy.tor",
  "privacy.relay",
  "privacy.hosting",
  "privacy.service",
  "anycast",
  "bogon",
];
const HIDDEN = new Set(["ip", "readme"]);

/** Flattens nested objects into dot-separated keys ("asn.name"). */
function flatten(value: unknown, prefix = "", out: Record<string, string> = {}) {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  } else if (prefix) {
    out[prefix] = Array.isArray(value)
      ? value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ")
      : value === null || value === undefined
        ? ""
        : String(value);
  }
  return out;
}

interface Props {
  records: IpInfo[];
  dns: DnsRecord[];
  /** IPs not in the previous scan, and IPs whose ipinfo data changed. */
  added?: Set<string>;
  changed?: Set<string>;
}

export default function IpdrTable({ records, dns, added, changed }: Props) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const hostsByIp = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const r of dns) {
      if (r.type !== "A" && r.type !== "AAAA") continue;
      m.set(r.value, [...(m.get(r.value) ?? []), r.host]);
    }
    return m;
  }, [dns]);

  const rows = useMemo(
    () => records.map((r) => ({ ...r, flat: r.data ? flatten(r.data) : {} })),
    [records],
  );

  const columns = useMemo(() => {
    const keys = new Set<string>();
    for (const r of rows) for (const k of Object.keys(r.flat)) if (!HIDDEN.has(k)) keys.add(k);
    const preferred = PREFERRED.filter((k) => keys.has(k));
    const rest = [...keys].filter((k) => !PREFERRED.includes(k)).sort();
    return [...preferred, ...rest];
  }, [rows]);

  const q = query.toLowerCase();
  const visible = rows.filter(
    (r) =>
      !q ||
      r.ip.includes(q) ||
      (hostsByIp.get(r.ip) ?? []).some((h) => h.includes(q)) ||
      Object.values(r.flat).some((v) => v.toLowerCase().includes(q)) ||
      r.error?.toLowerCase().includes(q),
  );
  const failed = records.filter((r) => r.error).length;
  const cols = columns.length + 2;

  return (
    <>
      <SearchBar value={query} onChange={setQuery} placeholder="Filter IP, host, org, country…">
        <span className="text-xs text-slate-500">
          Data from ipinfo.io
          {failed > 0 && <span className="text-amber-400"> · {failed} lookup{failed === 1 ? "" : "s"} failed</span>}
        </span>
      </SearchBar>
      <Table head={["IP", "Hosts", ...columns]}>
        {visible.length === 0 && (
          <EmptyRow cols={cols} text={records.length ? "No results" : "No public IPs resolved"} />
        )}
        {visible.map((r) => {
          const hosts = hostsByIp.get(r.ip) ?? [];
          return (
            <Fragment key={r.ip}>
              <tr
                onClick={() => setOpen(open === r.ip ? null : r.ip)}
                className="cursor-pointer align-top hover:bg-slate-800/30"
              >
                <td className="px-4 py-2 font-mono whitespace-nowrap text-white">
                  <span className="mr-1 inline-block w-3 text-slate-500">{open === r.ip ? "▾" : "▸"}</span>
                  {r.ip}
                  <NewChip show={!!added?.has(r.ip)} />
                  {changed?.has(r.ip) && (
                    <span className="ml-2 align-middle" title="ipinfo data differs from the previous scan; see Changes">
                      <Chip tone="amber">changed</Chip>
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-slate-400" title={hosts.join("\n")}>
                  {hosts.slice(0, 2).join(", ")}
                  {hosts.length > 2 && <span className="text-slate-500"> +{hosts.length - 2}</span>}
                </td>
                {r.error ? (
                  <td colSpan={columns.length} className="px-4 py-2 text-xs text-amber-400">
                    {r.error}
                  </td>
                ) : (
                  columns.map((c) => (
                    <td key={c} className="max-w-64 truncate px-4 py-2 text-xs text-slate-300" title={r.flat[c]}>
                      {r.flat[c] || <span className="text-slate-600">—</span>}
                    </td>
                  ))
                )}
              </tr>
              {open === r.ip && (
                <tr className="bg-slate-950/60">
                  <td colSpan={cols} className="px-4 py-4">
                    {hosts.length > 0 && (
                      <p className="mb-3 text-xs text-slate-400">
                        <span className="text-slate-500">Hosts: </span>
                        <span className="font-mono">{hosts.join(", ")}</span>
                      </p>
                    )}
                    <pre className="max-h-96 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                      {r.data ? JSON.stringify(r.data, null, 2) : r.error}
                    </pre>
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </Table>
    </>
  );
}
