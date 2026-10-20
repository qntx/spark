import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  lightningAddressDescriptionHash,
  lightningAddressMessage,
  lightningAddressMessageDigest,
} from "../src/core/lightning-address.ts";
import type { LightningAddressStatement } from "../src/core/lightning-address.ts";
import { SparkInputError, SparkRequestError } from "../src/errors/index.ts";
import { registerLightningAddress, unregisterLightningAddress } from "../src/lnurl/index.ts";
import type { LightningAddressSigning } from "../src/lnurl/index.ts";

const SECRET = hexToBytes(`${"0".repeat(62)}03`);
const PUBKEY = secp256k1.getPublicKey(SECRET);
const PUBKEY_HEX = bytesToHex(PUBKEY);
const NOW_MS = 1_700_000_000_000;

type CapturedRequest = { url: string; method: string; body: Record<string, unknown> };

/** A signer-shaped stub that records the statement and signs it for real. */
function signingStub(): {
  signer: LightningAddressSigning;
  statements: LightningAddressStatement[];
} {
  const statements: LightningAddressStatement[] = [];
  return {
    statements,
    signer: {
      identityPublicKey: async () => Promise.resolve(PUBKEY),
      signIdentity: async (statement) => {
        statements.push(statement);
        const digest = lightningAddressMessageDigest(lightningAddressMessage(statement));
        return Promise.resolve(
          secp256k1.sign(digest, SECRET, { format: "der", prehash: false, lowS: true }),
        );
      },
    },
  };
}

function fakeFetch(response: { status: number; body?: string }): {
  fetch: typeof globalThis.fetch;
  requests: CapturedRequest[];
} {
  const requests: CapturedRequest[] = [];
  const fetch = (async (
    input: Parameters<typeof globalThis.fetch>[0],
    init?: Parameters<typeof globalThis.fetch>[1],
  ) => {
    requests.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>,
    });
    return Promise.resolve(new Response(response.body ?? "", { status: response.status }));
  }) as typeof globalThis.fetch;
  return { fetch, requests };
}

describe("registerLightningAddress", () => {
  test("signs the v2 statement and POSTs it to /lnurlpay/{pubkey}", async () => {
    const { signer, statements } = signingStub();
    const { fetch, requests } = fakeFetch({
      status: 200,
      body: JSON.stringify({ lnurl: "lnurl1xxx", lightning_address: "Alice@example.com" }),
    });
    const result = await registerLightningAddress({
      fetch,
      serverUrl: "https://lnserver.example.com",
      domain: "Example.COM",
      username: "Alice",
      description: "Pay to alice",
      signer,
      now: () => NOW_MS,
    });
    expect(result).toStrictEqual({ lnurl: "lnurl1xxx", lightningAddress: "Alice@example.com" });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toBe(`https://lnserver.example.com/lnurlpay/${PUBKEY_HEX}`);
    expect(requests[0]!.method).toBe("POST");
    expect(requests[0]!.body).toStrictEqual({
      username: "alice",
      signature: requests[0]!.body["signature"],
      timestamp: 1_700_000_000,
      description: "Pay to alice",
    });
    // Domain and username are lowercased inside the signed statement.
    expect(statements).toStrictEqual([
      {
        kind: "lightning-address",
        action: "register",
        domain: "example.com",
        username: "alice",
        description: "Pay to alice",
        timestamp: 1_700_000_000,
      },
    ]);
    // The body signature verifies over the canonical v2 message.
    const message = `breez-lnurl:v2\nregister\nexample.com\nalice\n${lightningAddressDescriptionHash(
      "Pay to alice",
    )}\n1700000000`;
    expect(
      secp256k1.verify(
        hexToBytes(requests[0]!.body["signature"] as string),
        lightningAddressMessageDigest(message),
        PUBKEY,
        { format: "der", prehash: false },
      ),
    ).toBe(true);
  });

  test("surfaces a non-2xx as http_<status> with sanitized server text", async () => {
    const { signer } = signingStub();
    const { fetch } = fakeFetch({ status: 409, body: '"name already taken\nForged"' });
    const error = await registerLightningAddress({
      fetch,
      serverUrl: "https://lnserver.example.com",
      domain: "example.com",
      username: "alice",
      description: "d",
      signer,
      now: () => NOW_MS,
    }).then(
      () => {
        throw new Error("should have thrown");
      },
      (error: unknown) => error as SparkRequestError,
    );
    expect(error).toBeInstanceOf(SparkRequestError);
    expect(error.code).toBe("http_409");
    expect(error.message).toContain("name already taken");
    expect(error.message).not.toContain("\n");
  });

  test("rejects a clearnet http serverUrl before any fetch", async () => {
    const { signer } = signingStub();
    const { fetch, requests } = fakeFetch({ status: 200 });
    await expect(
      registerLightningAddress({
        fetch,
        serverUrl: "http://lnserver.example.com",
        domain: "example.com",
        username: "alice",
        description: "d",
        signer,
      }),
    ).rejects.toThrow(SparkInputError);
    expect(requests).toHaveLength(0);
  });
});

describe("unregisterLightningAddress", () => {
  test("signs the unregister statement and DELETEs /lnurlpay/{pubkey}", async () => {
    const { signer, statements } = signingStub();
    const { fetch, requests } = fakeFetch({ status: 200 });
    await unregisterLightningAddress({
      fetch,
      serverUrl: "https://lnserver.example.com",
      domain: "example.com",
      username: "Alice",
      signer,
      now: () => NOW_MS,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.method).toBe("DELETE");
    expect(requests[0]!.url).toBe(`https://lnserver.example.com/lnurlpay/${PUBKEY_HEX}`);
    expect(requests[0]!.body).toStrictEqual({
      username: "alice",
      signature: requests[0]!.body["signature"],
      timestamp: 1_700_000_000,
    });
    expect(statements[0]).toStrictEqual({
      kind: "lightning-address",
      action: "unregister",
      domain: "example.com",
      username: "alice",
      timestamp: 1_700_000_000,
    });
  });
});
