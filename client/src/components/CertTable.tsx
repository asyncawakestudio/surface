import { Fragment, useState, type ReactNode } from "react";
import { daysUntil, formatDate } from "../format";
import type { TlsCert } from "../types";
import { Chip, EmptyRow, SearchBar, Table } from "./Table";

export default function CertTable({ certs }: { certs: TlsCert[] }) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const q = query.toLowerCase();
  const rows = certs.filter(
    (c) =>
      c.host.includes(q) ||
      c.subject_cn.toLowerCase().includes(q) ||
      c.issuer_cn.toLowerCase().includes(q),
  );

  return (
    <>
      <SearchBar value={query} onChange={setQuery} placeholder="Filter host, subject or issuer…" />
      <Table head={["Host", "Subject", "Issuer", "Expires", "TLS", "Flags"]}>
        {rows.length === 0 && <EmptyRow cols={6} />}
        {rows.map((c) => {
          const key = `${c.host}:${c.port}`;
          const days = daysUntil(c.not_after);
          return (
            <Fragment key={key}>
              <tr
                onClick={() => setOpen(open === key ? null : key)}
                className="cursor-pointer hover:bg-slate-800/30"
              >
                <td className="px-4 py-2 font-mono whitespace-nowrap text-white">
                  <span className="mr-1 inline-block w-3 text-slate-500">{open === key ? "▾" : "▸"}</span>
                  {c.host}
                  <span className="text-slate-500">:{c.port}</span>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-slate-300">{c.subject_cn || "—"}</td>
                <td className="px-4 py-2 text-slate-300">
                  {c.issuer_cn}
                  {c.issuer_org.length > 0 && (
                    <span className="block text-xs text-slate-500">{c.issuer_org.join(", ")}</span>
                  )}
                </td>
                <td className="px-4 py-2 whitespace-nowrap">
                  <span className={expiryColor(days, c.expired)}>{formatDate(c.not_after)}</span>
                  <span className="block text-xs text-slate-500">
                    {c.expired || days < 0 ? "expired" : `${days} days`}
                  </span>
                </td>
                <td className="px-4 py-2 text-xs whitespace-nowrap text-slate-400">{c.tls_version}</td>
                <td className="px-4 py-2">
                  <div className="flex flex-wrap gap-1">
                    {c.expired && <Chip tone="rose">expired</Chip>}
                    {c.self_signed && <Chip tone="rose">self-signed</Chip>}
                    {c.mismatched && <Chip tone="amber">mismatched</Chip>}
                    {c.wildcard && <Chip tone="violet">wildcard</Chip>}
                    {!c.expired && !c.self_signed && !c.mismatched && days >= 30 && (
                      <Chip tone="emerald">ok</Chip>
                    )}
                  </div>
                </td>
              </tr>
              {open === key && (
                <tr className="bg-slate-950/60">
                  <td colSpan={6} className="px-4 py-4">
                    <dl className="grid gap-x-8 gap-y-3 text-xs sm:grid-cols-2">
                      <Field label="IP">{c.ip}</Field>
                      <Field label="Cipher">{c.cipher}</Field>
                      <Field label="Valid from">{formatDate(c.not_before)}</Field>
                      <Field label="Serial">{c.serial}</Field>
                      <Field label="SHA-256 fingerprint" wide>
                        {c.fingerprint_sha256}
                      </Field>
                      <Field label={`Subject alternative names (${c.sans.length})`} wide>
                        <div className="flex flex-wrap gap-1">
                          {c.sans.map((s) => (
                            <Chip key={s}>{s}</Chip>
                          ))}
                        </div>
                      </Field>
                    </dl>
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

function Field({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? "sm:col-span-2" : ""}>
      <dt className="text-slate-500">{label}</dt>
      <dd className="mt-0.5 font-mono break-all text-slate-300">{children || "—"}</dd>
    </div>
  );
}

function expiryColor(days: number, expired: boolean) {
  if (expired || days < 0) return "text-rose-400";
  if (days < 30) return "text-amber-300";
  return "text-slate-300";
}
