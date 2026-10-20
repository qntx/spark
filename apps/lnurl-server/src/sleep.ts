/**
 * Resolves after `ms` or when `signal` aborts, whichever comes first. The abort listener is removed
 * when the timer fires normally and the timer is cleared on abort, so repeated calls never
 * accumulate listeners or pending timers.
 */
export async function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
