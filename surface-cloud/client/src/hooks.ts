import { useEffect, useRef } from "react";

/**
 * Calls fn immediately and then every `ms` milliseconds, but only while the
 * tab is visible. When the tab is hidden the timer is paused; when it becomes
 * visible again fn runs once immediately and the timer resumes. Pass ms = null
 * to disable polling entirely. The latest fn is always used, so callers don't
 * need to memoize it.
 */
export function usePoll(fn: () => void, ms: number | null, deps: unknown[] = []) {
  const saved = useRef(fn);
  saved.current = fn;

  useEffect(() => {
    if (ms === null) return;

    let id: ReturnType<typeof setInterval> | undefined;
    const stop = () => {
      if (id !== undefined) {
        clearInterval(id);
        id = undefined;
      }
    };
    const start = () => {
      stop();
      saved.current();
      id = setInterval(() => saved.current(), ms);
    };
    const onVisibility = () => {
      if (document.hidden) stop();
      else start();
    };

    if (!document.hidden) start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, ...deps]);
}
