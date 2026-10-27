// Hono binding for the framework-agnostic LightningAddressServer handlers. Routes mirror the
// Breez LNURL server (crates/breez-sdk/lnurl/src/main.rs): register/unregister on
// /lnurlpay/{pubkey}, LUD-06/12/16/21 GETs under /lnurlp and /.well-known/lnurlp.

import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";

import type { LightningAddressServer } from "@qntx/spark/server";

/** Register/unregister JSON bodies are small; anything bigger is rejected before it is read. */
export const MAX_BODY_BYTES = 16_384;

async function respond(result: Promise<{ status: number; body: unknown }>): Promise<Response> {
  const { status, body } = await result;
  // LNURL payloads (including string bodies) serialize as JSON, matching the Breez server.
  return Response.json(body, { status });
}

type JsonBody = { readonly ok: true; readonly body: unknown } | { readonly ok: false };

/** Parses the request JSON — the bodyLimit middleware has already bounded the size. */
async function readJsonBody(c: Context): Promise<JsonBody> {
  try {
    return { ok: true, body: (await c.req.json()) as unknown };
  } catch {
    return { ok: false };
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

export function createLnurlApp(
  server: LightningAddressServer,
  readiness?: { readonly ready: () => Promise<void> },
): Hono {
  const app = new Hono();

  app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "DELETE", "OPTIONS"] }));

  // Body size cap for the write routes (register/unregister carry small signed statements) —
  // enforced before the body is buffered, not after.
  app.use(
    "/lnurlpay/:pubkey",
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) => c.json({ status: "ERROR", reason: "body too large" }, 413),
    }),
  );

  app.post("/lnurlpay/:pubkey", async (c) => {
    const body = await readJsonBody(c);
    if (!body.ok) {
      return c.json({ status: "ERROR", reason: "invalid JSON body" }, 400);
    }
    return respond(server.register(c.req.param("pubkey"), body.body));
  });

  app.delete("/lnurlpay/:pubkey", async (c) => {
    const body = await readJsonBody(c);
    if (!body.ok) {
      return c.json({ status: "ERROR", reason: "invalid JSON body" }, 400);
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
  // Readiness probes the store: an unreachable dependency reports 503, a healthy one 200.
  if (readiness !== undefined) {
    app.get("/ready", async (c) => {
      try {
        await readiness.ready();
        return c.body(null, 200);
      } catch {
        return c.body(null, 503);
      }
    });
  }

  return app;
}
