// Hono binding for the framework-agnostic LightningAddressServer handlers. Routes mirror the
// Breez LNURL server (crates/breez-sdk/lnurl/src/main.rs): register/unregister on
// /lnurlpay/{pubkey}, LUD-06/12/16/21 GETs under /lnurlp and /.well-known/lnurlp.

import type { Context } from "hono";
import { Hono } from "hono";
import { cors } from "hono/cors";

import type { LightningAddressServer } from "@qntx/spark/server";

/** Register/unregister JSON bodies are small; anything bigger is rejected up front. */
export const MAX_BODY_BYTES = 16_384;

async function respond(result: Promise<{ status: number; body: unknown }>): Promise<Response> {
  const { status, body } = await result;
  // LNURL payloads (including string bodies) serialize as JSON, matching the Breez server.
  return Response.json(body, { status });
}

type JsonBody =
  | { readonly ok: true; readonly body: unknown }
  | { readonly ok: false; readonly status: 400 | 413 };

/** Parses the request JSON bounded by {@link MAX_BODY_BYTES}; reports 413/400 on bad input. */
async function readJsonBody(c: Context): Promise<JsonBody> {
  const text = await c.req.text();
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) {
    return { ok: false, status: 413 };
  }
  try {
    return { ok: true, body: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, status: 400 };
  }
}

function invoiceParams(c: Context): {
  amount: unknown;
  comment?: string;
  nostr?: string;
} {
  const rawAmount = c.req.query("amount");
  const amount = rawAmount === undefined ? undefined : Number(rawAmount);
  const comment = c.req.query("comment");
  const nostr = c.req.query("nostr");
  return {
    // A non-integer amount is passed through so the handler's own validation answers it.
    amount: amount !== undefined && Number.isSafeInteger(amount) ? amount : rawAmount,
    ...(comment === undefined ? {} : { comment }),
    ...(nostr === undefined ? {} : { nostr }),
  };
}

export function createLnurlApp(server: LightningAddressServer): Hono {
  const app = new Hono();

  app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "DELETE", "OPTIONS"] }));

  // Body size cap for the write routes (register/unregister carry small signed statements).
  app.post("/lnurlpay/:pubkey", async (c) => {
    const body = await readJsonBody(c);
    if (!body.ok) {
      const reason = body.status === 413 ? "body too large" : "invalid JSON body";
      return c.json({ status: "ERROR", reason }, body.status);
    }
    return respond(server.register(c.req.param("pubkey"), body.body));
  });

  app.delete("/lnurlpay/:pubkey", async (c) => {
    const body = await readJsonBody(c);
    if (!body.ok) {
      const reason = body.status === 413 ? "body too large" : "invalid JSON body";
      return c.json({ status: "ERROR", reason }, body.status);
    }
    return respond(server.unregister(c.req.param("pubkey"), body.body));
  });

  // `verify` is also a valid username — its invoice callback is a static path registered
  // before /lnurlp/:name/invoice and /lnurlp/verify/:hash so it can never be captured.
  app.get("/lnurlp/verify/invoice", async (c) =>
    respond(server.invoice("verify", invoiceParams(c))),
  );
  app.get("/lnurlp/verify/:hash", async (c) => respond(server.verify(c.req.param("hash"))));

  app.get("/.well-known/lnurlp/:name", async (c) =>
    respond(server.payRequest(c.req.param("name"))),
  );
  app.get("/lnurlp/:name", async (c) => respond(server.payRequest(c.req.param("name"))));
  app.get("/lnurlp/:name/invoice", async (c) =>
    respond(server.invoice(c.req.param("name"), invoiceParams(c))),
  );

  app.get("/health", (c) => c.body(null, 200));

  return app;
}
