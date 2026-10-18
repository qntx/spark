import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { SparkInputError, SparkRequestError } from "../src/errors/index.ts";
import { parseLnurlAuth, resolveLnurl, submitLnurlAuth } from "../src/lnurl/index.ts";
import type { LnurlAuthRequest } from "../src/lnurl/index.ts";
import { queryParams } from "../src/lnurl/url.ts";
import { createLnurlAuthSigner } from "../src/signer/index.ts";

// vectors/lnurl-auth.json case 0 — the signer's LUD-05 derivation.
const ROOT_KEY =
  "073c09c9d514a456addfb05479736383270d120ae88f20bd841f48e0457cec8c1605e57d7613bb1d44d1bd18b1d44b5f60f21eae739f57eedda920623bc98d85";
const K1 = "e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e";
const LOGIN_URL = `https://auth.example.com/login?tag=login&k1=${K1}&action=register`;

function fetchJson(body: Record<string, unknown>): typeof globalThis.fetch {
  return async () => Promise.resolve(Response.json(body));
}

function neverFetch(): typeof globalThis.fetch {
  return async () => Promise.reject(new Error("fetch must not be called for tag=login"));
}

// --- parseLnurlAuth ---------------------------------------------------------

test("parses an LNURL-auth url", () => {
  const request = parseLnurlAuth(LOGIN_URL);
  expect(request).toStrictEqual({
    tag: "login",
    url: LOGIN_URL,
    k1: K1,
    action: "register",
    domain: "auth.example.com",
  });
});

test("lowercases the host into domain and omits a missing action", () => {
  const request = parseLnurlAuth(`https://AUTH.Example.COM/x?tag=login&k1=${K1.toUpperCase()}`);
  expect(request.domain).toBe("auth.example.com");
  expect(request.k1).toBe(K1);
  expect("action" in request).toBe(false);
});

test("accepts all LUD-04 action values", () => {
  for (const action of ["register", "login", "link", "auth"]) {
    expect(parseLnurlAuth(`https://a.com/?tag=login&k1=${K1}&action=${action}`).action).toBe(
      action,
    );
  }
});

test.each([
  ["missing tag", `https://a.com/?k1=${K1}`],
  ["wrong tag", `https://a.com/?tag=pay&k1=${K1}`],
  ["missing k1", "https://a.com/?tag=login"],
  ["short k1", `https://a.com/?tag=login&k1=${K1.slice(2)}`],
  ["non-hex k1", `https://a.com/?tag=login&k1=${"zz".repeat(32)}`],
  ["bad action", `https://a.com/?tag=login&k1=${K1}&action=pay`],
  ["bad escape", `https://a.com/?tag=login&k1=${K1}%`],
  ["not a url", "not a url"],
])("rejects %s", (_title, url) => {
  expect(() => parseLnurlAuth(url)).toThrow(SparkInputError);
});

// --- resolveLnurl ------------------------------------------------------------

test("resolves tag=login without fetching", async () => {
  const lnurl = bech32.encode("lnurl", bech32.toWords(utf8ToBytes(LOGIN_URL)), false);
  const resolved = await resolveLnurl(lnurl, { fetch: neverFetch() });
  expect(resolved).toStrictEqual(parseLnurlAuth(LOGIN_URL));
});

test("resolves a bare login url without fetching", async () => {
  const resolved = await resolveLnurl(LOGIN_URL, { fetch: neverFetch() });
  expect(resolved).toStrictEqual(parseLnurlAuth(LOGIN_URL));
});

// --- submitLnurlAuth --------------------------------------------------------

const AUTH: LnurlAuthRequest = parseLnurlAuth(LOGIN_URL);

test("submits sig+key preserving existing query params", async () => {
  const calls: string[] = [];
  const fetch: typeof globalThis.fetch = async (input) => {
    calls.push(String(input));
    return Promise.resolve(Response.json({ status: "OK" }));
  };
  const signer = createLnurlAuthSigner({ rootKey: hexToBytes(ROOT_KEY) });
  await submitLnurlAuth(AUTH, { fetch, signer });
  signer.dispose();

  expect(calls).toHaveLength(1);
  const params = queryParams(calls[0]!.split("?").slice(1).join("?"));
  expect(params.get("tag")).toBe("login");
  expect(params.get("k1")).toBe(K1);
  expect(params.get("action")).toBe("register");
  const key = params.get("key")!;
  const sig = params.get("sig")!;
  expect(key).toHaveLength(66);
  // The service verifies the DER signature over the raw k1 digest (LUD-04 step 3).
  expect(
    secp256k1.verify(hexToBytes(sig), hexToBytes(K1), hexToBytes(key), {
      prehash: false,
      format: "der",
    }),
  ).toBe(true);
  expect(key).toBe(
    bytesToHex(
      await createLnurlAuthSigner({ rootKey: hexToBytes(ROOT_KEY) }).linkingKey("auth.example.com"),
    ),
  );
});

test("maps auth failures", async () => {
  const signer = {
    sign: async () =>
      Promise.resolve({ linkingKey: new Uint8Array(33), signature: new Uint8Array(64) }),
  };
  await expect(
    submitLnurlAuth(AUTH, {
      fetch: fetchJson({ status: "ERROR", reason: "invalid sig" }),
      signer,
    }),
  ).rejects.toThrow(SparkRequestError);
  await expect(
    submitLnurlAuth(AUTH, { fetch: fetchJson({ status: "ERROR", reason: "invalid sig" }), signer }),
  ).rejects.toMatchObject({ code: "lnurl_error" });
  await expect(
    submitLnurlAuth(AUTH, { fetch: fetchJson({ status: "UNKNOWN" }), signer }),
  ).rejects.toMatchObject({ code: "unexpected_response" });
  await expect(submitLnurlAuth(AUTH, { fetch: fetchJson({}), signer })).rejects.toMatchObject({
    code: "unexpected_response",
  });
});
