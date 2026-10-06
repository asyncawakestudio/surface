import { useMemo, useState } from "react";
import type { DnsRecord, Subdomain, TlsCert } from "../types";
import { Chip, EmptyRow, NewChip, SearchBar, Table } from "./Table";

interface Props {
  subdomains: Subdomain[];
  records: DnsRecord[];
  certs: TlsCert[];
  /** Hosts that weren't in the previous scan. */
  added?: Set<string>;
}

export default function SubdomainTable({ subdomains, records, certs, added }: Props) {
  const [query, setQuery] = useState("");
  const [resolvedOnly, setResolvedOnly] = useState(false);
  const [reportedOnly, setReportedOnly] = useState(false);

  const ipsByHost = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const r of records) {
      if (r.type !== "A" && r.type !== "AAAA") continue;
      m.set(r.host, [...(m.get(r.host) ?? []), r.value]);
    }
    return m;
  }, [records]);

  const tlsHosts = useMemo(() => new Set(certs.map((c) => c.host)), [certs]);

  const carriedOver = subdomains.filter((s) => s.carried_over).length;
  const rows = subdomains.filter(
    (s) =>
      s.host.includes(query.toLowerCase()) &&
      (!resolvedOnly || ipsByHost.has(s.host)) &&
      (!reportedOnly || !s.carried_over),
  );

  return (
    <>
      <SearchBar value={query} onChange={setQuery} placeholder="Filter hosts…">
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input
            type="checkbox"
            checked={resolvedOnly}
            onChange={(e) => setResolvedOnly(e.target.checked)}
            className="accent-cyan-500"
          />
          Resolved only
        </label>
        {carriedOver > 0 && (
          <label
            className="flex items-center gap-2 text-sm text-slate-400"
            title="Hide subdomains that no source reported this scan but that earlier scans found"
          >
            <input
              type="checkbox"
              checked={reportedOnly}
              onChange={(e) => setReportedOnly(e.target.checked)}
              className="accent-cyan-500"
            />
            Hide {carriedOver} carried over
          </label>
        )}
      </SearchBar>
      <Table head={["Host", "Addresses", "TLS", "Sources"]}>
        {rows.length === 0 && <EmptyRow cols={4} />}
        {rows.map((s) => {
          const ips = ipsByHost.get(s.host) ?? [];
          return (
            <tr key={s.host} className="hover:bg-slate-800/30">
              <td className="px-4 py-2 font-mono text-white">
                {s.host}
                <NewChip show={!!added?.has(s.host)} />
                {s.carried_over && (
                  <span
                    className="ml-2 align-middle"
                    title="No source reported this host in this scan; it was found by an earlier scan"
                  >
                    <Chip>carried over</Chip>
                  </span>
                )}
              </td>
              <td className="px-4 py-2 font-mono text-xs text-slate-400">
                {ips.length ? ips.join(", ") : <span className="text-slate-600">unresolved</span>}
              </td>
              <td className="px-4 py-2">
                {tlsHosts.has(s.host) ? <Chip tone="emerald">443</Chip> : <span className="text-slate-600">—</span>}
              </td>
              <td className="px-4 py-2">
                <div className={`flex flex-wrap gap-1 ${s.carried_over ? "opacity-50" : ""}`}>
                  {s.sources.map((src) => (
                    <Chip key={src}>{src}</Chip>
                  ))}
                </div>
              </td>
            </tr>
          );
        })}
      </Table>
    </>
  );
}
