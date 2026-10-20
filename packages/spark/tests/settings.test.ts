import type { Client } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { SparkError } from "../src/errors/index.ts";
import type {
  SparkService,
  UpdateWalletSettingRequest,
  WalletSetting,
} from "../src/proto/gen/spark_pb.ts";
import { queryWalletSettings, updateWalletPrivate } from "../src/settings/index.ts";

const OWNER = secp256k1.getPublicKey(new Uint8Array(32).fill(3), true);
const OTHER = secp256k1.getPublicKey(new Uint8Array(32).fill(4), true);

function walletSetting(owner: Uint8Array, privateEnabled: boolean): WalletSetting {
  return {
    $typeName: "spark.WalletSetting",
    ownerIdentityPublicKey: owner,
    privateEnabled,
  };
}

function fakeSpark(handlers: {
  query?: () => { walletSetting?: WalletSetting };
  update?: (req: UpdateWalletSettingRequest) => { walletSetting?: WalletSetting };
}): {
  spark: Client<typeof SparkService>;
  updates: UpdateWalletSettingRequest[];
} {
  const updates: UpdateWalletSettingRequest[] = [];
  const spark = {
    query_wallet_setting: async () => {
      await Promise.resolve();
      return handlers.query?.() ?? {};
    },
    update_wallet_setting: async (req: UpdateWalletSettingRequest) => {
      updates.push(req);
      await Promise.resolve();
      return handlers.update?.(req) ?? {};
    },
  } as unknown as Client<typeof SparkService>;
  return { spark, updates };
}

describe("wallet settings", () => {
  test("an absent wallet_setting maps to the public default", async () => {
    const { spark } = fakeSpark({ query: () => ({}) });
    await expect(queryWalletSettings({ spark, identityPublicKey: OWNER })).resolves.toStrictEqual({
      privateEnabled: false,
    });
  });

  test("a stored setting maps privateEnabled for its owner", async () => {
    const { spark } = fakeSpark({ query: () => ({ walletSetting: walletSetting(OWNER, true) }) });
    await expect(queryWalletSettings({ spark, identityPublicKey: OWNER })).resolves.toStrictEqual({
      privateEnabled: true,
    });
  });

  test("a setting owned by another identity is rejected", async () => {
    const { spark } = fakeSpark({ query: () => ({ walletSetting: walletSetting(OTHER, true) }) });
    await expect(queryWalletSettings({ spark, identityPublicKey: OWNER })).rejects.toThrow(
      SparkError,
    );
  });

  test("setPrivate sends private_enabled and returns the updated setting", async () => {
    const { spark, updates } = fakeSpark({
      update: (req) => ({
        walletSetting: walletSetting(OWNER, req.privateEnabled === true),
      }),
    });
    await expect(
      updateWalletPrivate({ spark, identityPublicKey: OWNER, privateEnabled: true }),
    ).resolves.toStrictEqual({ privateEnabled: true });
    await expect(
      updateWalletPrivate({ spark, identityPublicKey: OWNER, privateEnabled: false }),
    ).resolves.toStrictEqual({ privateEnabled: false });
    // private_enabled is a proto3 optional: it must be present even when false, or the SO
    // rejects the update as empty.
    expect(updates.map((req) => req.privateEnabled)).toStrictEqual([true, false]);
  });

  test("a response owned by another identity is rejected", async () => {
    const { spark } = fakeSpark({ update: () => ({ walletSetting: walletSetting(OTHER, true) }) });
    await expect(
      updateWalletPrivate({ spark, identityPublicKey: OWNER, privateEnabled: true }),
    ).rejects.toThrow(SparkError);
  });
});
