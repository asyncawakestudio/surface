import { formatRelative } from "../format";
import type { Domain } from "../types";
import StatusBadge from "./StatusBadge";

interface Props {
  domains: Domain[];
  selected: string | null;
  onSelect: (domain: string) => void;
}

export default function DomainList({ domains, selected, onSelect }: Props) {
  return (
    <div className="p-4">
      <h2 className="mb-3 px-2 text-xs font-semibold tracking-wider text-slate-500 uppercase">
        Domains
      </h2>
      {domains.length === 0 ? (
        <p className="px-2 text-sm text-slate-500">Nothing here yet.</p>
      ) : (
        <ul className="flex gap-2 overflow-x-auto pb-2 lg:flex-col lg:gap-1 lg:overflow-visible lg:pb-0">
          {domains.map(({ domain, scan_count, latest }) => (
            <li key={domain} className="shrink-0 lg:shrink">
              <button
                onClick={() => onSelect(domain)}
                className={`w-56 rounded-lg px-3 py-2.5 text-left transition lg:w-full ${
                  domain === selected
                    ? "bg-slate-800/80 ring-1 ring-slate-700"
                    : "hover:bg-slate-900"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-sm text-white">{domain}</span>
                  <StatusBadge status={latest.status} />
                </div>
                <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                  <span>
                    {latest.status === "running" && latest.stage
                      ? `${latest.stage}…`
                      : `${scan_count} scan${scan_count === 1 ? "" : "s"}`}
                  </span>
                  <span>{formatRelative(latest.created_at)}</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
