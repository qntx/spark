import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { createClient } from "@connectrpc/connect";
import type { Client } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { connectOperator } from "../src/connection/index.ts";
import { createDecrementedTimelockRefundTxs } from "../src/core/bitcoin/index.ts";
import { uuidv7 } from "../src/core/uuid.ts";
import { ChallengeSchema, SparkAuthnService } from "../src/proto/gen/spark_authn_pb.ts";
import type { SparkService } from "../src/proto/gen/spark_pb.ts";
import { CancelTransferRequestSchema } from "../src/proto/gen/spark_pb.ts";
import { mapTransfer, prepareTransferPackage, queryTransferById } from "../src/transfer/index.ts";
import { required } from "./support/fakes.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  leavesUntil,
  LOCAL_OPERATORS,
  localFetch,
  localWallet,
  sleep,
} from "./support/local.ts";

const EXPIRY_MS = 90_000;
// Expiry plus a bit over two 1-minute cancel_expired_transfers task cycles.
const PROBE_UNTIL_EXTRA_MS = 150_000;

/** Re-queries the transfer every ~30 s until `untilMs`, logging each observed status. */
async function pollTransferStatus(
  spark: Client<typeof SparkService>,
  transferId: string,
  expiryMs: number,
  untilMs: number,
): Promise<string> {
  await sleep(Math.min(30_000, Math.max(0, untilMs - Date.now())));
  const found = await queryTransferById({ spark, network: "regtest", transferId });
  const status = found?.status ?? "MISSING";
  console.log(`t+${Math.round((Date.now() - expiryMs) / 1000)}s past expiry: status=${status}`);
  if (Date.now() >= untilMs) {
    return status;
  }
  return pollTransferStatus(spark, transferId, expiryMs, untilMs);
}

/** True when the gRPC-web response is not a success (HTTP error or non-zero grpc-status). */
function grpcWebRejected(response: Response, grpcStatus: string | null): boolean {
  return !response.ok || (grpcStatus !== null && grpcStatus !== "0");
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO transfer expiry", () => {
  // Regression: a send commits as SENDER_KEY_TWEAKED, which the cancel task never touches, and
  // the sender-facing cancel_transfer RPC is disabled — an expired committed transfer must stay
  // claimable indefinitely.
  test("an expired committed transfer stays SENDER_KEY_TWEAKED and claimable", async () => {
    const a = await localWallet(randomBytes(32));
    const b = await localWallet(randomBytes(32));

    const address = await a.client.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    const miner = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [1, miner]);
    const transaction = hexToBytes((await bitcoinRpc("getrawtransaction", [txid])) as string);
    const leaf = await claimUntilAccepted(a.client, transaction, Date.now() + CLAIM_DEADLINE_MS);
    await leavesUntil(a.client, Date.now() + CLAIM_DEADLINE_MS);
    console.log("funded leaf:", leaf.id, leaf.valueSats, "sats");

    const coordinator = required(LOCAL_OPERATORS[0], "coordinator");
    const fetchFn = localFetch();
    const connection = connectOperator(coordinator, {
      signer: a.signer,
      fetch: fetchFn,
      random: (length) => randomBytes(length),
    });
    const receiverIdentityPublicKey = await b.signer.identityPublicKey();
    const ownerIdentityPublicKey = await a.signer.identityPublicKey();

    const transferId = uuidv7((length) => randomBytes(length));
    const transferPackage = await prepareTransferPackage({
      spark: connection.spark,
      signer: a.signer,
      network: "regtest",
      operators: LOCAL_OPERATORS,
      threshold: 2,
      transferId,
      leaves: [{ leaf, receiverIdentityPublicKey }],
      buildRefunds: (entry, sequence) => ({
        refunds: createDecrementedTimelockRefundTxs({
          nodeTx: entry.leaf.nodeTx,
          directNodeTx: entry.leaf.directTx,
          sequence,
          receivingPublicKey: entry.receiverIdentityPublicKey,
          network: "regtest",
        }),
      }),
    });

    const expiryMs = Date.now() + EXPIRY_MS;
    const response = await connection.spark.start_transfer_v2({
      transferId,
      ownerIdentityPublicKey,
      receiverIdentityPublicKey,
      transferPackage,
      sparkInvoice: "",
      expiryTime: timestampFromDate(new Date(expiryMs)),
    });
    const sent = mapTransfer(required(response.transfer, "start_transfer_v2 transfer"));
    await a.store.deleteExitChains([leaf.id]);
    console.log(
      `sent ${transferId} status=${sent.status} ` +
        `expiry=${new Date(required(sent.expiryTimeMs, "transfer expiry")).toISOString()}`,
    );
    expect(sent.status).toBe("SENDER_KEY_TWEAKED");
    expect(sent.expiryTimeMs).toBe(expiryMs);

    // Past expiry + two cancel-task cycles the transfer must still be committed.
    const status = await pollTransferStatus(
      connection.spark,
      transferId,
      expiryMs,
      expiryMs + PROBE_UNTIL_EXTRA_MS,
    );
    expect(status).toBe("SENDER_KEY_TWEAKED");

    // The sender-facing cancel_transfer RPC is disabled on the SO; record the rejection. The
    // request is authenticated first so the response is about the method, not the session.
    const transport = createGrpcWebTransport({
      baseUrl: coordinator.address,
      fetch: fetchFn,
      useBinaryFormat: true,
    });
    const authn = createClient(SparkAuthnService, transport);
    const challengeResponse = await authn.get_challenge({ publicKey: ownerIdentityPublicKey });
    const challenge = required(challengeResponse.protectedChallenge?.challenge, "challenge");
    const challengeSignature = await a.signer.signIdentity({
      kind: "so-challenge",
      challenge: toBinary(ChallengeSchema, challenge),
    });
    const verified = await authn.verify_challenge({
      protectedChallenge: challengeResponse.protectedChallenge,
      signature: challengeSignature,
      publicKey: ownerIdentityPublicKey,
    });

    // gRPC-web frame: 1-byte flag + 4-byte big-endian length + the serialized request.
    const cancelMessage = toBinary(
      CancelTransferRequestSchema,
      create(CancelTransferRequestSchema, {
        transferId,
        senderIdentityPublicKey: ownerIdentityPublicKey,
      }),
    );
    const cancelFrame = new Uint8Array(5 + cancelMessage.length);
    new DataView(cancelFrame.buffer).setUint32(1, cancelMessage.length);
    cancelFrame.set(cancelMessage, 5);
    const cancelResponse = await fetchFn(
      `${coordinator.address}/spark.SparkService/cancel_transfer`,
      {
        method: "POST",
        headers: {
          "content-type": "application/grpc-web+proto",
          "x-grpc-web": "1",
          authorization: `Bearer ${verified.sessionToken}`,
        },
        body: cancelFrame,
      },
    );
    const cancelGrpcStatus = cancelResponse.headers.get("grpc-status");
    console.log(
      `cancel_transfer: HTTP ${cancelResponse.status} grpc-status=${cancelGrpcStatus} ` +
        `grpc-message=${cancelResponse.headers.get("grpc-message")} ` +
        `body=${await cancelResponse.text()}`,
    );
    expect(grpcWebRejected(cancelResponse, cancelGrpcStatus)).toBe(true);

    // The receiver still claims; its balance rises by the leaf value.
    const claimed = await claimPendingUntil(b.client, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed.map((l) => l.id)).toContain(leaf.id);
    await expect(b.client.balance()).resolves.toBe(leaf.valueSats);
    await expect(a.client.balance()).resolves.toBe(0);
    console.log(`B claimed ${claimed.length} leaf(s); B balance ${leaf.valueSats}`);

    a.client.close();
    b.client.close();
    a.signer.dispose();
    b.signer.dispose();
  }, 480_000);
});
