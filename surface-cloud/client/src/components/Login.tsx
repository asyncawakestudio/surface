import { useState, type FormEvent } from "react";
import { api } from "../api";
import type { User } from "../types";

export default function Login({ onAuthed }: { onAuthed: (u: User) => void }) {
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function sendCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { expires_in_minutes } = await api.requestCode(email.trim());
      setStep("code");
      setNote(`We emailed a code to ${email.trim()}. It expires in ${expires_in_minutes} minutes.`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onAuthed(await api.verifyCode(email.trim(), code.trim()));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const input =
    "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/30 focus:outline-none";
  const button =
    "w-full rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50";

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <div className="mb-5 flex items-center gap-3">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <div>
            <h1 className="text-lg font-semibold text-white">Surface</h1>
            <p className="text-xs text-slate-400">Sign in with your email</p>
          </div>
        </div>

        {error && <p className="mb-3 rounded-md bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</p>}
        {note && <p className="mb-3 text-xs text-slate-400">{note}</p>}

        {step === "email" ? (
          <form onSubmit={sendCode} className="space-y-3">
            <input
              type="email"
              required
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              aria-label="Email address"
              className={input}
            />
            <button type="submit" disabled={busy || !email.trim()} className={button}>
              {busy ? "Sending…" : "Send code"}
            </button>
          </form>
        ) : (
          <form onSubmit={verify} className="space-y-3">
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              required
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              aria-label="Login code"
              className={`${input} text-center font-mono tracking-[0.3em]`}
            />
            <button type="submit" disabled={busy || !code.trim()} className={button}>
              {busy ? "Verifying…" : "Verify & sign in"}
            </button>
            <button
              type="button"
              onClick={() => {
                setStep("email");
                setCode("");
                setNote(null);
                setError(null);
              }}
              className="w-full text-xs text-slate-400 hover:text-slate-200"
            >
              Use a different email
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
