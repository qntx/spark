import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { describe, expect, test } from "vite-plus/test";

import {
  FrostAggregateRequestSchema,
  FrostAggregateResponseSchema,
  FrostSignRequestSchema,
  FrostSignResponseSchema,
} from "../src/proto/gen/qntx_spark_ffi_pb.ts";

const VECTORS = fileURLToPath(new URL("../../../vectors/", import.meta.url));

type Doc = { cases: Array<{ request: string; response: string }> };

async function load(name: string): Promise<Doc> {
  return JSON.parse(await readFile(`${VECTORS}${name}`, "utf8")) as Doc;
}

function unhex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Cross-language field-number check: every request/response the Rust side
// (hand-written prost structs) produced in the vectors must decode and
// re-encode byte-identically with the protobuf-es generated schemas.
describe("qntx_spark_ffi protobuf-es parity", () => {
  test("FrostSignRequest/FrostSignResponse round-trips every vector byte-identically", async () => {
    const { cases } = await load("ffi-sign.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const [index, c] of cases.entries()) {
      const request = unhex(c.request);
      const decoded = fromBinary(FrostSignRequestSchema, request);
      expect(decoded.jobs.length).toBeGreaterThan(0);
      expect(toBinary(FrostSignRequestSchema, decoded), `case ${index}`).toStrictEqual(request);

      const response = unhex(c.response);
      const decodedResponse = fromBinary(FrostSignResponseSchema, response);
      expect(decodedResponse.signatureShares).toHaveLength(decoded.jobs.length);
      for (const share of decodedResponse.signatureShares) {
        expect(share).toHaveLength(32);
      }
      expect(toBinary(FrostSignResponseSchema, decodedResponse), `case ${index}`).toStrictEqual(
        response,
      );
    }
  });

  test("FrostAggregateRequest/FrostAggregateResponse round-trips every vector byte-identically", async () => {
    const { cases } = await load("ffi-aggregate.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const [index, c] of cases.entries()) {
      const request = unhex(c.request);
      const decoded = fromBinary(FrostAggregateRequestSchema, request);
      expect(decoded.jobs.length).toBeGreaterThan(0);
      expect(toBinary(FrostAggregateRequestSchema, decoded), `case ${index}`).toStrictEqual(
        request,
      );

      const response = unhex(c.response);
      const decodedResponse = fromBinary(FrostAggregateResponseSchema, response);
      expect(decodedResponse.signatures).toHaveLength(decoded.jobs.length);
      for (const signature of decodedResponse.signatures) {
        expect(signature).toHaveLength(64);
      }
      expect(
        toBinary(FrostAggregateResponseSchema, decodedResponse),
        `case ${index}`,
      ).toStrictEqual(response);
    }
  });
});
