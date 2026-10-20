// NIP-57 zap support: appendix-D validation of kind-9734 requests, kind-9735 receipt
// construction/signing, and relay publishing with retries. Ported from Breez
// crates/breez-sdk/lnurl/src/routes.rs (`validate_nostr_zap_request`) and zap.rs
// (`publish_zap_receipt`) @956ff90.
//
// SSRF note: the `relays` tag is payer-controlled and this server connects to whatever it names,
// so `isAcceptedRelayUrl` only admits `wss://` on plausibly public hosts — no localhost names, no
// IPv6 literals, no IPv4 literals in private/reserved ranges. A public DNS name can still resolve
// to a private address (DNS rebinding); operators must mitigate that residual at the network
// layer — see README.

import type { Pool } from "@qntx/nostr";
import type { Event, Tag, Keys } from "@qntx/nostr/core";
import {
  finalizeEvent,
  firstTagValue,
  isHex32,
  validateSignedEvent,
  verifyEvent,
} from "@qntx/nostr/core";
import type { LightningAddressInvoice } from "@qntx/spark/server";

import type { LnurlStore } from "./store.ts";

export const ZAP_REQUEST_KIND = 9734;
export const ZAP_RECEIPT_KIND = 9735;
/** Payer-supplied `nostr` invoice-callback parameter cap (Breez MAX_NOSTR_EVENT_SIZE). */
export const MAX_NOSTR_EVENT_SIZE = 32_768;
/** Most relays a receipt is ever published to. */
export const MAX_NOSTR_RELAYS = 10;
/** Receipt-publish retries across poll rounds before the receipt is dropped. */
export const ZAP_RECEIPT_MAX_ATTEMPTS = 5;

function fail(reason: string): never {
  throw new Error(`invalid nostr event: ${reason}`);
}

function parseSignedEvent(json: string): Event {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    fail("not JSON");
  }
  if (!validateSignedEvent(raw)) {
    fail("malformed fields");
  }
  return raw;
}

function tagsNamed(event: Event, name: string): ReadonlyArray<Tag> {
  return event.tags.filter((tag) => tag[0] === name);
}

/**
 * NIP-57 appendix D: the zap request must be a valid signed kind 9734 with exactly one `p` tag
 * (64-hex), at most one `e`/`a`, a `relays` tag, an `amount` tag matching `amountMsat` when
 * present, and at most one `P` tag which must name the receipt signer. Throws on every rule.
 */
export function validateZapRequest(
  json: string,
  amountMsat: number,
  receiptPublicKey: string,
): void {
  if (json.length > MAX_NOSTR_EVENT_SIZE) {
    fail("too large");
  }
  const event = parseSignedEvent(json);
  if (event.kind !== ZAP_REQUEST_KIND) {
    fail("not a zap request");
  }
  if (!verifyEvent(event)) {
    fail("does not verify");
  }
  if (event.tags.length === 0) {
    fail("missing tags");
  }
  const pTags = tagsNamed(event, "p");
  if (pTags.length !== 1 || pTags[0]?.[1] === undefined || !isHex32(pTags[0][1])) {
    fail("missing or multiple 'p' tags");
  }
  if (tagsNamed(event, "e").length > 1) {
    fail("multiple 'e' tags");
  }
  if (tagsNamed(event, "a").length > 1) {
    fail("multiple 'a' tags");
  }
  if (tagsNamed(event, "relays").length === 0) {
    fail("missing relay tag");
  }
  const amountTag = firstTagValue(event.tags, "amount");
  if (amountTag !== undefined) {
    const millisats = Number(amountTag);
    if (!Number.isSafeInteger(millisats) || millisats !== amountMsat) {
      fail("amount does not match");
    }
  }
  const pinned = tagsNamed(event, "P");
  if (pinned.length > 1) {
    fail("multiple 'P' tags");
  }
  const pinnedSigner = pinned[0]?.[1];
  if (pinnedSigner !== undefined && pinnedSigner !== receiptPublicKey) {
    fail("'P' tag is not the receipt signer");
  }
}

/**
 * A dotted-quad IPv4 host is public only outside the private/reserved ranges (0/8, 10/8, 100.64/10,
 * 127/8, 169.254/16, 172.16/12, 192.168/16, 198.18/15, 224/4+). Returns undefined when `host` is
 * not an IPv4 literal.
 */
function isPublicIpv4(host: string): boolean | undefined {
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/u.test(part))) {
    return undefined;
  }
  const [a = 0, b = 0] = parts.map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) {
    return false;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return false;
  }
  if (a === 169 && b === 254) {
    return false;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return false;
  }
  if (a === 192 && b === 168) {
    return false;
  }
  if (a === 198 && b >= 18 && b <= 19) {
    return false;
  }
  return true;
}

/**
 * The payer names receipt relays, so only `wss://` URLs with a plausibly public host are
 * publishable targets: no `ws://`, no localhost (or `*.localhost`), no IPv6 literals and no
 * private/reserved IPv4 literals. The WHATWG parser normalizes hex/octal/integer IPv4 spellings to
 * dotted-quad, so those forms are rejected by the same rule.
 */
function isAcceptedRelayUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "wss:") {
    return false;
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/u, "");
  if (host === "" || host.includes(":")) {
    return false;
  }
  if (host === "localhost" || host.endsWith(".localhost")) {
    return false;
  }
  return isPublicIpv4(host) !== false;
}

function zapRequestRelays(request: Event): string[] {
  const relaysTag = request.tags.find((tag) => tag[0] === "relays");
  if (relaysTag === undefined) {
    return [];
  }
  return relaysTag.slice(1).filter(isAcceptedRelayUrl).slice(0, MAX_NOSTR_RELAYS);
}

export type BuiltZapReceipt = {
  readonly event: Event;
  readonly relays: ReadonlyArray<string>;
};

/**
 * Builds and signs the kind-9735 receipt for a settled zap invoice: `p` (the request's zap target),
 * `P` (the zapper's pubkey), `e`/`a` copied, `bolt11`, `description` (the request JSON exactly as
 * the invoice's description hash committed to it) and `preimage`.
 */
export function buildZapReceipt(options: {
  readonly zapRequestJson: string;
  readonly invoice: string;
  readonly preimageHex: string;
  readonly keys: Keys;
  readonly now: number;
}): BuiltZapReceipt {
  const request = parseSignedEvent(options.zapRequestJson);
  const [pTag] = tagsNamed(request, "p");
  const copied = ["e", "a"].flatMap((name) => {
    const [tag] = tagsNamed(request, name);
    return tag === undefined ? [] : [[...tag]];
  });
  const tags: string[][] = [
    ...(pTag === undefined ? [] : [[...pTag]]),
    ["P", request.pubkey],
    ...copied,
    ["bolt11", options.invoice],
    ["description", options.zapRequestJson],
    ["preimage", options.preimageHex],
  ];
  const event = finalizeEvent(
    {
      kind: ZAP_RECEIPT_KIND,
      content: "",
      tags,
      created_at: Math.floor(options.now / 1000),
    },
    options.keys,
  );
  return { event, relays: zapRequestRelays(request) };
}

/**
 * One publish round: queues receipts for the newly settled zap invoices, then publishes every
 * stored receipt under the attempt cap to its relays. A receipt that no relay accepts keeps its
 * failure recorded and is retried on the next round. Never throws — outcomes go to `log`.
 */
export async function publishZapReceipts(options: {
  readonly store: LnurlStore;
  readonly keys: Keys;
  readonly pool: Pool;
  readonly settled: ReadonlyArray<LightningAddressInvoice>;
  readonly publishTimeoutMs?: number;
  readonly now?: number;
  readonly log?: (message: string) => void;
}): Promise<void> {
  const { store, keys, pool, settled } = options;
  const log = options.log ?? (() => undefined);
  const now = options.now ?? Date.now();

  await Promise.all(
    settled.map(async (invoice) => {
      if (invoice.zapRequest === undefined || invoice.preimageHex === undefined) {
        return;
      }
      try {
        const receipt = buildZapReceipt({
          zapRequestJson: invoice.zapRequest,
          invoice: invoice.invoice,
          preimageHex: invoice.preimageHex,
          keys,
          now,
        });
        await store.putZapReceipt(
          invoice.paymentHash,
          JSON.stringify(receipt.event),
          receipt.relays,
        );
      } catch (error) {
        log(`zap receipt build failed for ${invoice.paymentHash}: ${String(error)}`);
      }
    }),
  );

  const pending = await store.pendingZapReceipts(ZAP_RECEIPT_MAX_ATTEMPTS);
  await Promise.all(
    pending.map(async (receipt) => {
      if (receipt.relays.length === 0) {
        await store.recordZapReceiptFailure(receipt.paymentHash, "no relays in zap request");
        return;
      }
      let raw: unknown;
      try {
        raw = JSON.parse(receipt.eventJson);
      } catch {
        await store.recordZapReceiptFailure(receipt.paymentHash, "stored event is not JSON");
        return;
      }
      if (!validateSignedEvent(raw)) {
        await store.recordZapReceiptFailure(receipt.paymentHash, "stored event malformed");
        return;
      }
      try {
        const results = await pool.publish(receipt.relays, raw, {
          timeoutMs: options.publishTimeoutMs ?? 10_000,
        });
        const ok = results.filter((r) => r.status === "ok").length;
        if (ok > 0) {
          await store.markZapReceiptPublished(receipt.paymentHash);
          log(
            `zap receipt ${receipt.paymentHash} published to ${ok}/${receipt.relays.length} relays`,
          );
        } else {
          const detail = results
            .map((r) =>
              r.status === "failed" ? `${r.url}: ${r.error.message}` : `${r.url}: ${r.status}`,
            )
            .join("; ");
          await store.recordZapReceiptFailure(receipt.paymentHash, detail || "no relay accepted");
        }
      } catch (error) {
        await store.recordZapReceiptFailure(receipt.paymentHash, String(error));
      }
    }),
  );
}
