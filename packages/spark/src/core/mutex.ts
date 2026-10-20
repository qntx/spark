/**
 * A promise-chain mutex: `run` starts `fn` only after every previously queued task settled, so
 * tasks execute strictly in submission order. A rejected task does not poison the queue; results
 * and errors pass through unchanged. NOT re-entrant — a task running `run` on the same mutex
 * deadlocks itself.
 */
export type Mutex = {
  readonly run: <T>(fn: () => Promise<T>) => Promise<T>;
};

const noop = (): void => undefined;

export function createMutex(): Mutex {
  let tail: Promise<void> = Promise.resolve();
  return {
    run: async <T>(fn: () => Promise<T>): Promise<T> => {
      const previous = tail;
      let release = noop;
      tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await fn();
      } finally {
        release();
      }
    },
  };
}
