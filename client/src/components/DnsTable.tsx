import { useMemo, useState } from "react";
import type { DnsRecord } from "../types";
import { Chip, EmptyRow, SearchBar, Table } from "./Table";

const typeTone = {
  A: "cyan",
  AAAA: "cyan",
  CNAME: "violet",
  MX: "amber",
  NS: "emerald",
  TXT: "slate",
  CAA: "rose",
} as const;

export default function DnsTable({ records }: { records: DnsRecord[] }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState<string | null>(null);

  const types = useMemo(() => [...new Set(records.map((r) => r.type))].sort(), [records]);

  const q = query.toLowerCase();
  const rows = records.filter(
    (r) =>
      (!type || r.type === type) &&
      (r.host.includes(q) || r.value.toLowerCase().includes(q)),
  );

  return (
    <>
      <SearchBar value={query} onChange={setQuery} placeholder="Filter host or value…">
        <div className="flex flex-wrap gap-1">
          {[null, ...types].map((t) => (
            <button
              key={t ?? "all"}
              onClick={() => setType(t)}
              className={`rounded-md px-2 py-1 text-xs transition ${
                type === t ? "bg-slate-700 text-white" : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              {t ?? "All"}
            </button>
          ))}
        </div>
      </SearchBar>
      <Table head={["Host", "Type", "Value"]}>
        {rows.length === 0 && <EmptyRow cols={3} />}
        {rows.map((r, i) => (
          <tr key={`${r.host}-${r.type}-${i}`} className="hover:bg-slate-800/30">
            <td className="px-4 py-2 font-mono whitespace-nowrap text-white">{r.host}</td>
            <td className="px-4 py-2">
              <Chip tone={typeTone[r.type as keyof typeof typeTone] ?? "slate"}>{r.type}</Chip>
            </td>
            <td className="px-4 py-2 font-mono text-xs break-all text-slate-300">{r.value}</td>
          </tr>
        ))}
      </Table>
    </>
  );
}
