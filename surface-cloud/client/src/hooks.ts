import { useEffect, useRef } from "react";

/**
 * Calls fn immediately and then every `ms` milliseconds. Pass null to pause.
 * The latest fn is always used, so callers don't need to memoize it.
 */
export function usePoll(fn: () => void, ms: number | null, deps: unknown[] = []) {
  const saved = useRef(fn);
  saved.current = fn;

  useEffect(() => {
    saved.current();
    if (ms === null) return;
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [ms, ...deps]);
}
