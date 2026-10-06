import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Frequency, ScanConfig, ScanConfigInput } from "../types";

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function browserTz(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function emptyInput(): ScanConfigInput {
  return {
    name: "",
    domains: [],
    frequency: "manual",
    time_of_day: "09:00",
    weekday: 1,
    day_of_month: 1,
    timezone: browserTz(),
    options: { skip_ipdr: false, skip_ports: false, skip_certs: false, port_type: "", port_spec: "", port_rate: 0 },
    enabled: true,
  };
}

function toInput(c: ScanConfig): ScanConfigInput {
  const { id: _id, created_at, updated_at, last_run_at, next_run_at, ...rest } = c;
  void _id, created_at, updated_at, last_run_at, next_run_at;
  return { ...rest, weekday: c.weekday ?? 1, day_of_month: c.day_of_month ?? 1 };
}

export default function ConfigManager({ onClose }: { onClose: () => void }) {
  const [configs, setConfigs] = useState<ScanConfig[]>([]);
  const [editing, setEditing] = useState<{ id: number | null; input: ScanConfigInput } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () =>
    api.listConfigs().then(setConfigs).catch((e: Error) => setError(e.message));
  useEffect(() => {
    refresh();
  }, []);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setError(null);
    try {
      if (editing.id === null) await api.createConfig(editing.input);
      else await api.updateConfig(editing.id, editing.input);
      setEditing(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const act = (fn: () => Promise<unknown>) => async () => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 sm:p-8">
      <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-950 shadow-xl">
        <header className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-white">Configured scans</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white" aria-label="Close">
            ✕
          </button>
        </header>

        {error && <div className="border-b border-rose-900/50 bg-rose-950/40 px-5 py-2 text-sm text-rose-300">{error}</div>}

        <div className="max-h-[75vh] overflow-y-auto p-5">
          {editing ? (
            <ConfigForm
              input={editing.input}
              isNew={editing.id === null}
              busy={busy}
              onChange={(input) => setEditing({ ...editing, input })}
              onCancel={() => setEditing(null)}
              onSave={save}
            />
          ) : (
            <>
              <button
                onClick={() => setEditing({ id: null, input: emptyInput() })}
                className="mb-4 rounded-lg bg-cyan-500 px-3 py-1.5 text-sm font-medium text-slate-950 hover:bg-cyan-400"
              >
                + New configuration
              </button>
              {configs.length === 0 ? (
                <p className="text-sm text-slate-500">No configured scans yet.</p>
              ) : (
                <ul className="space-y-2">
                  {configs.map((c) => (
                    <li key={c.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="font-medium text-white">
                            {c.name}
                            {!c.enabled && <span className="ml-2 text-xs text-slate-500">(disabled)</span>}
                          </p>
                          <p className="truncate font-mono text-xs text-slate-400">{c.domains.join(", ")}</p>
                          <p className="mt-1 text-xs text-slate-500">
                            {describeSchedule(c)}
                            {c.next_run_at && ` · next ${new Date(c.next_run_at).toLocaleString()}`}
                          </p>
                        </div>
                        <div className="flex shrink-0 gap-2 text-xs">
                          <button onClick={act(() => api.runConfig(c.id))} disabled={busy} className="rounded border border-slate-700 px-2 py-1 text-cyan-300 hover:bg-slate-800 disabled:opacity-50">
                            Run now
                          </button>
                          <button onClick={() => setEditing({ id: c.id, input: toInput(c) })} className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:bg-slate-800">
                            Edit
                          </button>
                          <button
                            onClick={() => confirm(`Delete "${c.name}"?`) && act(() => api.deleteConfig(c.id))()}
                            className="rounded border border-slate-700 px-2 py-1 text-rose-300 hover:bg-rose-950/40"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function describeSchedule(c: ScanConfig): string {
  switch (c.frequency) {
    case "daily":
      return `Daily at ${c.time_of_day} ${c.timezone}`;
    case "weekly":
      return `Weekly on ${WEEKDAYS[c.weekday ?? 0]} at ${c.time_of_day} ${c.timezone}`;
    case "monthly":
      return `Monthly on day ${c.day_of_month} at ${c.time_of_day} ${c.timezone}`;
    default:
      return "Manual (run on demand)";
  }
}

function ConfigForm({
  input,
  isNew,
  busy,
  onChange,
  onCancel,
  onSave,
}: {
  input: ScanConfigInput;
  isNew: boolean;
  busy: boolean;
  onChange: (i: ScanConfigInput) => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  const set = <K extends keyof ScanConfigInput>(k: K, v: ScanConfigInput[K]) => onChange({ ...input, [k]: v });
  const setOpt = (patch: Partial<ScanConfigInput["options"]>) => onChange({ ...input, options: { ...input.options, ...patch } });
  const domainsText = useMemo(() => input.domains.join("\n"), [input.domains]);

  const field = "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-white focus:border-cyan-500 focus:outline-none";

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-white">{isNew ? "New configuration" : "Edit configuration"}</h3>

      <label className="block">
        <span className="mb-1 block text-xs text-slate-400">Name</span>
        <input className={field} value={input.name} onChange={(e) => set("name", e.target.value)} placeholder="Production assets" />
      </label>

      <label className="block">
        <span className="mb-1 block text-xs text-slate-400">Domains (one per line)</span>
        <textarea
          className={`${field} h-24 font-mono`}
          value={domainsText}
          onChange={(e) => set("domains", e.target.value.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean))}
          placeholder={"example.com\napi.example.com"}
        />
      </label>

      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <span className="mb-1 block text-xs text-slate-400">Frequency</span>
          <select className={field} value={input.frequency} onChange={(e) => set("frequency", e.target.value as Frequency)}>
            <option value="manual">Manual</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </label>
        {input.frequency !== "manual" && (
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Time of day</span>
            <input type="time" className={field} value={input.time_of_day} onChange={(e) => set("time_of_day", e.target.value)} />
          </label>
        )}
        {input.frequency === "weekly" && (
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Day of week</span>
            <select className={field} value={input.weekday ?? 1} onChange={(e) => set("weekday", Number(e.target.value))}>
              {WEEKDAYS.map((d, i) => (
                <option key={d} value={i}>
                  {d}
                </option>
              ))}
            </select>
          </label>
        )}
        {input.frequency === "monthly" && (
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Day of month</span>
            <input type="number" min={1} max={31} className={field} value={input.day_of_month ?? 1} onChange={(e) => set("day_of_month", Number(e.target.value))} />
          </label>
        )}
        {input.frequency !== "manual" && (
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Timezone (IANA)</span>
            <input className={field} value={input.timezone} onChange={(e) => set("timezone", e.target.value)} placeholder="UTC" />
          </label>
        )}
      </div>

      <fieldset className="rounded-lg border border-slate-800 p-3">
        <legend className="px-1 text-xs text-slate-400">Stages to include</legend>
        <div className="flex flex-wrap gap-4 text-sm text-slate-300">
          {([
            ["IPDR", "skip_ipdr"],
            ["Ports", "skip_ports"],
            ["Certificates", "skip_certs"],
          ] as const).map(([label, key]) => (
            <label key={key} className="flex items-center gap-2">
              <input type="checkbox" className="accent-cyan-500" checked={!input.options[key]} onChange={(e) => setOpt({ [key]: !e.target.checked })} />
              {label}
            </label>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">Subdomains and DNS always run.</p>
      </fieldset>

      {!input.options.skip_ports && (
        <div className="grid grid-cols-3 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Port mode</span>
            <select className={field} value={input.options.port_type} onChange={(e) => setOpt({ port_type: e.target.value })}>
              <option value="">default</option>
              <option value="connect">connect</option>
              <option value="syn">syn</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Ports</span>
            <input className={field} value={input.options.port_spec} onChange={(e) => setOpt({ port_spec: e.target.value })} placeholder="- (all)" />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs text-slate-400">Rate (pkt/s)</span>
            <input type="number" min={0} className={field} value={input.options.port_rate || ""} onChange={(e) => setOpt({ port_rate: Number(e.target.value) })} placeholder="default" />
          </label>
        </div>
      )}

      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" className="accent-cyan-500" checked={input.enabled} onChange={(e) => set("enabled", e.target.checked)} />
        Enabled (scheduler runs it)
      </label>

      <div className="flex justify-end gap-2 pt-2">
        <button onClick={onCancel} className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800">
          Cancel
        </button>
        <button onClick={onSave} disabled={busy} className="rounded-lg bg-cyan-500 px-4 py-1.5 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50">
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}
