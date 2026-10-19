// Control characters in server-supplied text can forge log lines and terminal
// sequences; drop them and bound the length before embedding it in errors.
// oxlint-disable-next-line no-control-regex -- control characters are the point
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/g;

/** Server-supplied error text made safe to embed in an error message. */
export function serverErrorText(text: string): string {
  const cleaned = text.replace(CONTROL, "");
  return cleaned.length <= 256 ? cleaned : `${cleaned.slice(0, 256)}\u2026`;
}
