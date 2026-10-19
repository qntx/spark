/** The `setTimeout`-backed sleep used wherever a caller may inject its own `sleep`. */
export async function defaultSleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}
