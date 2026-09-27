import { useMemo, useState } from "react";
import type { DnsRecord, Subdomain, TlsCert } from "../types";
import { Chip, EmptyRow, SearchBar, Table } from "./Table";

interface Props {
  subdomains: Subdomain[];
  records: DnsRecord[];
  certs: TlsCert[];
}

export default function SubdomainTable({ subdomains, records, certs }: Props) {
  const [query, setQuery] = useState("");
  const [resolvedOnly, setResolvedOnly] = useState(false);

  const ipsByHost = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const r of records) {
      if (r.type !== "A" && r.type !== "AAAA") continue;
      m.set(r.host, [...(m.get(r.host) ?? []), r.value]);
    }
    return m;
  }, [records]);

  const tlsHosts = useMemo(() => new Set(certs.map((c) => c.host)), [certs]);

  const rows = subdomains.filter(
    (s) =>
      s.host.includes(query.toLowerCase()) && (!resolvedOnly || ipsByHost.has(s.host)),
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
      </SearchBar>
      <Table head={["Host", "Addresses", "TLS", "Sources"]}>
        {rows.length === 0 && <EmptyRow cols={4} />}
        {rows.map((s) => {
          const ips = ipsByHost.get(s.host) ?? [];
          return (
            <tr key={s.host} className="hover:bg-slate-800/30">
              <td className="px-4 py-2 font-mono text-white">{s.host}</td>
              <td className="px-4 py-2 font-mono text-xs text-slate-400">
                {ips.length ? ips.join(", ") : <span className="text-slate-600">unresolved</span>}
              </td>
              <td className="px-4 py-2">
                {tlsHosts.has(s.host) ? <Chip tone="emerald">443</Chip> : <span className="text-slate-600">—</span>}
              </td>
              <td className="px-4 py-2">
                <div className="flex flex-wrap gap-1">
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
