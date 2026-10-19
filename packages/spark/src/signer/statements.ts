import { fromBinary } from "@bufbuild/protobuf";
import type { DescMessage, MessageShape } from "@bufbuild/protobuf";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { taprootKeySpendSighash } from "../core/bitcoin/sighash.ts";
import { hashSparkInvoice } from "../core/hashing/invoice.ts";
import {
  QuoteReason,
  QuoteRole,
  hashTransferManifest,
  quoteEnvelopeDigest,
  receiveAttestorTarget,
} from "../core/hashing/manifest.ts";
import {
  authnChallengeDigest,
  claimPackageDigest,
  instantStaticDepositStatementDigest,
  sspChallengeDigest,
  staticDepositStatementDigest,
  transferPackageDigest,
  watchtowerRecoveryStatementDigest,
} from "../core/hashing/statements.ts";
import { hashPartialTokenTransaction } from "../core/hashing/token.ts";
import { protoInvoiceToPlain } from "../core/invoice.ts";
import { sparkNetworkFromProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
import { ChallengeSchema } from "../proto/gen/spark_authn_pb.ts";
import {
  ClaimPackageSchema,
  SparkInvoiceFieldsSchema,
  TransferManifestSchema,
  TransferPackageSchema,
} from "../proto/gen/spark_pb.ts";
import { PartialTokenTransactionSchema } from "../proto/gen/spark_token_pb.ts";
import { randomBytes, unreachable } from "./backend.ts";
import type { IdentityStatement } from "./types.ts";

/** The wire format {@link signDigest} produces for a statement digest. */
export type StatementFormat = "der" | "compact" | "schnorr";

/** What statement digests need from the signer: identity key material and the network. */
export type StatementContext = {
  readonly identityPoint: ReturnType<typeof secp256k1.Point.fromBytes>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
};

/**
 * Computes the digest for a statement from its complete protocol content, plus the signature format
 * upstream emits for that statement kind (DER ECDSA unless noted).
 */
export function statementDigest(
  statement: IdentityStatement,
  context: StatementContext,
): { digest: Uint8Array; format: StatementFormat } {
  if (statement.kind === "so-challenge") {
    const challenge = decode(ChallengeSchema, statement.challenge, "so challenge");
    if (challenge.$unknown !== undefined) {
      throw new SparkInputError("so challenge: unknown fields are not allowed");
    }
    const point = decodePoint(challenge.publicKey, "challenge.publicKey");
    if (!point.equals(context.identityPoint)) {
      throw new SparkInputError(
        "so challenge: challenge targets a different public key than the signer identity",
      );
    }
    return { digest: authnChallengeDigest(challenge), format: "der" };
  }
  if (statement.kind === "ssp-challenge") {
    return {
      digest: sspChallengeDigest(statement.protectedChallenge, context.identityPublicKey),
      format: "der",
    };
  }
  if (statement.kind === "transfer-package") {
    const pkg = decode(TransferPackageSchema, statement.package, "transfer package");
    return { digest: transferPackageDigest(statement.transferId, pkg), format: "der" };
  }
  if (statement.kind === "claim-package") {
    const pkg = decode(ClaimPackageSchema, statement.package, "claim package");
    return {
      digest: claimPackageDigest(statement.transferId, pkg.keyTweakPackage),
      format: "der",
    };
  }
  if (statement.kind === "static-deposit-claim") {
    return {
      digest: staticDepositStatementDigest({
        transactionId: bytesToHex(statement.txid),
        outputIndex: statement.vout,
        network: statement.network,
        requestType: "fixed",
        creditAmountSats: statement.creditAmountSats,
        payload: hexField(statement.sspSignature, "static-deposit-claim sspSignature"),
      }),
      format: "der",
    };
  }
  if (statement.kind === "static-deposit-refund") {
    return {
      digest: staticDepositStatementDigest({
        transactionId: bytesToHex(statement.txid),
        outputIndex: statement.vout,
        network: statement.network,
        requestType: "refund",
        creditAmountSats: statement.amount,
        payload: taprootKeySpendSighash(statement.target),
      }),
      format: "der",
    };
  }
  if (statement.kind === "instant-static-deposit") {
    return {
      digest: instantStaticDepositStatementDigest({
        network: statement.network,
        creditAmountSats: statement.creditAmountSats,
        secondaryCreditAmountSats: statement.secondaryCreditAmountSats,
        destinationAddress: statement.destinationAddress,
        satsValue: statement.satsValue,
        sspSignature: statement.sspSignature,
      }),
      format: "der",
    };
  }
  if (statement.kind === "watchtower-recovery") {
    return {
      digest: watchtowerRecoveryStatementDigest(
        statement.network,
        statement.leafId,
        taprootKeySpendSighash(statement.target),
      ),
      format: "der",
    };
  }
  if (statement.kind === "receive-quote") {
    const manifest = decode(TransferManifestSchema, statement.manifest, "receive quote");
    if (sparkNetworkFromProto(manifest.network) !== statement.network) {
      throw new SparkInputError(
        "receive quote: manifest network does not match the statement network",
      );
    }
    return {
      digest: quoteEnvelopeDigest({
        network: manifest.network,
        manifestHash: hashTransferManifest(manifest),
        reason: QuoteReason.RECEIVE,
        role: QuoteRole.ATTESTOR,
        target: receiveAttestorTarget(statement.paymentHash),
      }),
      format: "der",
    };
  }
  if (statement.kind === "spark-invoice") {
    const proto = decode(SparkInvoiceFieldsSchema, statement.invoice, "spark invoice");
    const invoice = protoInvoiceToPlain(proto);
    return {
      digest: hashSparkInvoice(invoice, context.identityPublicKey, context.network),
      format: "schnorr",
    };
  }
  if (statement.kind === "token-transaction") {
    const partial = decode(
      PartialTokenTransactionSchema,
      statement.partialTransaction,
      "token transaction",
    );
    return { digest: hashPartialTokenTransaction(partial), format: "schnorr" };
  }
  return unreachable("unexpected statement kind");
}

/** Signs `digest` in `format`: low-S ECDSA (`der`/`compact`) or BIP-340 (`schnorr`). */
export function signDigest(
  digest: Uint8Array,
  format: StatementFormat,
  secretKey: Uint8Array,
  random: (length: number) => Uint8Array,
): Uint8Array {
  if (format === "schnorr") {
    return schnorr.sign(digest, secretKey, randomBytes(random, 32));
  }
  return ecdsaSign(digest, secretKey, format);
}

export function ecdsaSign(
  digest: Uint8Array,
  secretKey: Uint8Array,
  format: "der" | "compact",
): Uint8Array {
  return secp256k1.sign(digest, secretKey, { format, prehash: false, lowS: true });
}

function decode<Desc extends DescMessage>(
  schema: Desc,
  bytes: Uint8Array,
  name: string,
): MessageShape<Desc> {
  try {
    return fromBinary(schema, bytes);
  } catch (error) {
    throw new SparkInputError(`${name}: failed to decode protobuf`, { cause: error });
  }
}

function hexField(hex: string, field: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
    throw new SparkInputError(`${field}: expected a hex string`);
  }
  return hexToBytes(hex);
}

function decodePoint(
  bytes: Uint8Array,
  name: string,
): ReturnType<typeof secp256k1.Point.fromBytes> {
  try {
    return secp256k1.Point.fromBytes(bytes);
  } catch (error) {
    throw new SparkInputError(`${name}: invalid secp256k1 public key`, { cause: error });
  }
}
