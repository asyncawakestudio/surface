import { useMemo, useState } from "react";
import type { PortScan } from "../types";
import { Chip, EmptyRow, SearchBar, Table } from "./Table";

// Well-known ports get a service hint next to the number.
const SERVICES: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  445: "smb",
  587: "smtp",
  993: "imaps",
  995: "pop3s",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
};

export default function PortsTable({ scans }: { scans: PortScan[] }) {
  const [query, setQuery] = useState("");
  const [openOnly, setOpenOnly] = useState(true);

  const totalOpen = useMemo(
    () => scans.reduce((n, s) => n + s.ports.length, 0),
    [scans],
  );

  const q = query.toLowerCase();
  const rows = scans.filter((s) => {
    if (openOnly && s.ports.length === 0) return false;
    if (!q) return true;
    return (
      s.ip.includes(q) ||
      s.hosts.some((h) => h.includes(q)) ||
      s.ports.some((p) => String(p.port).includes(q) || SERVICES[p.port]?.includes(q))
    );
  });

  return (
    <>
      <SearchBar value={query} onChange={setQuery} placeholder="Filter IP, host or port…">
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input
            type="checkbox"
            checked={openOnly}
            onChange={(e) => setOpenOnly(e.target.checked)}
            className="accent-cyan-500"
          />
          Open ports only
        </label>
        <span className="text-xs text-slate-500">
          {totalOpen} open across {scans.length} IPv4 host{scans.length === 1 ? "" : "s"}
        </span>
      </SearchBar>
      <Table head={["IPv4", "Hosts", "Open ports"]}>
        {rows.length === 0 && (
          <EmptyRow cols={3} text={scans.length ? "No matching hosts" : "No IPv4 addresses scanned"} />
        )}
        {rows.map((s) => (
          <tr key={s.ip} className="align-top hover:bg-slate-800/30">
            <td className="px-4 py-2 font-mono whitespace-nowrap text-white">{s.ip}</td>
            <td className="px-4 py-2 font-mono text-xs text-slate-400" title={s.hosts.join("\n")}>
              {s.hosts.slice(0, 2).join(", ")}
              {s.hosts.length > 2 && <span className="text-slate-500"> +{s.hosts.length - 2}</span>}
            </td>
            <td className="px-4 py-2">
              {s.ports.length === 0 ? (
                <span className="text-slate-600">none</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {s.ports.map((p) => (
                    <Chip key={`${p.port}/${p.protocol}`} tone="emerald">
                      {p.port}
                      {SERVICES[p.port] && <span className="text-emerald-500/70"> {SERVICES[p.port]}</span>}
                    </Chip>
                  ))}
                </div>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
}
