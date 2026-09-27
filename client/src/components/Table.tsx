import type { ReactNode } from "react";

export function SearchBar({
  value,
  onChange,
  placeholder,
  children,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-white placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none sm:w-72"
      />
      {children}
    </div>
  );
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="max-h-[36rem] overflow-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-slate-900 text-xs tracking-wider text-slate-400 uppercase">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-4 py-2.5 font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/70">{children}</tbody>
      </table>
    </div>
  );
}

export function EmptyRow({ cols, text = "No results" }: { cols: number; text?: string }) {
  return (
    <tr>
      <td colSpan={cols} className="px-4 py-10 text-center text-slate-500">
        {text}
      </td>
    </tr>
  );
}

export function Chip({ children, tone = "slate" }: { children: ReactNode; tone?: keyof typeof tones }) {
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs ring-1 ring-inset ${tones[tone]}`}>
      {children}
    </span>
  );
}

const tones = {
  slate: "bg-slate-800/60 text-slate-300 ring-slate-700",
  cyan: "bg-cyan-950/60 text-cyan-300 ring-cyan-900",
  emerald: "bg-emerald-950/60 text-emerald-300 ring-emerald-900",
  amber: "bg-amber-950/60 text-amber-300 ring-amber-900",
  rose: "bg-rose-950/60 text-rose-300 ring-rose-900",
  violet: "bg-violet-950/60 text-violet-300 ring-violet-900",
};

export function NewChip({ show }: { show: boolean }) {
  return show ? (
    <span className="ml-2 align-middle">
      <Chip tone="emerald">new</Chip>
    </span>
  ) : null;
}
