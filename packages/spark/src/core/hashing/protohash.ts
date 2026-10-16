import type { DescField, DescMessage, Message } from "@bufbuild/protobuf";
import { ScalarType } from "@bufbuild/protobuf";
import { isReflectList, isReflectMap, isReflectMessage, reflect } from "@bufbuild/protobuf/reflect";
import type { ReflectList, ReflectMap, ReflectMessage } from "@bufbuild/protobuf/reflect";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import { compareBytes, uint64be } from "../bytes.ts";

// Upstream reference: signer/spark-token-primitives/src/protohash/*
// (buildonspark/spark@0b3a32a), itself a port of spark/common/protohash (Go
// objecthash/protoreflecthash). The TypeScript SDK's proto-hash.ts implements
// the same algorithm over ts-proto metadata; this implementation is written
// directly against protobuf-es v2 reflection and follows the Rust crate, whose
// behavior the cross-language vectors in spark/testdata pin byte-for-byte.
//
// Non-obvious semantics copied from the Rust port:
// - Only set fields are hashed, and additionally any field whose value equals
//   the type default is skipped — including explicit-presence fields set to a
//   zero value and message fields whose sub-message has no set fields at all
//   (a zero Timestamp therefore never reaches the digest).
// - A repeated field hashing to an empty list, or a map hashing to no entries,
//   makes the enclosing field disappear; the same propagation applies to
//   google.protobuf.Value elements that hash to nothing.
// - Map entries carrying a null google.protobuf.Value are skipped; a map whose
//   surviving entries hash to nothing makes the whole map hash None.
// - Floats canonicalize NaN to 0x7FF8000000000001 and -0 to +0; proto float is
//   promoted to f64 by numeric value before hashing.

const BOOL_TAG = utf8ToBytes("b");
const MAP_TAG = utf8ToBytes("d");
const FLOAT_TAG = utf8ToBytes("f");
const INT_TAG = utf8ToBytes("i");
const LIST_TAG = utf8ToBytes("l");
const BYTES_TAG = utf8ToBytes("r");
const STRING_TAG = utf8ToBytes("u");

const NAN_BITS = 0x7f_f8_00_00_00_00_00_01n;
const MAX_UINT64 = 0xff_ff_ff_ff_ff_ff_ff_ffn;

const WKT_PREFIX = "google.protobuf.";

const TOP_LEVEL_REJECTED = new Set([
  "google.protobuf.Value",
  "google.protobuf.ListValue",
  "google.protobuf.BoolValue",
  "google.protobuf.Int32Value",
  "google.protobuf.Int64Value",
  "google.protobuf.UInt32Value",
  "google.protobuf.UInt64Value",
  "google.protobuf.FloatValue",
  "google.protobuf.DoubleValue",
  "google.protobuf.StringValue",
  "google.protobuf.BytesValue",
]);

function expectNumber(value: unknown, context: string): number {
  if (typeof value !== "number") {
    throw new SparkInputError(`protohash: ${context} expected a number`);
  }
  return value;
}

function expectInteger(value: unknown, context: string): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    return BigInt(value);
  }
  throw new SparkInputError(`protohash: ${context} expected an integer`);
}

function expectString(value: unknown, context: string): string {
  if (typeof value !== "string") {
    throw new SparkInputError(`protohash: ${context} expected a string`);
  }
  return value;
}

function expectBytes(value: unknown, context: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new SparkInputError(`protohash: ${context} expected bytes`);
  }
  return value;
}

function expectReflectMessage(value: unknown, context: string): ReflectMessage {
  if (!isReflectMessage(value)) {
    throw new SparkInputError(`protohash: ${context} expected a message`);
  }
  return value;
}

function expectReflectList(value: unknown, context: string): ReflectList {
  if (!isReflectList(value)) {
    throw new SparkInputError(`protohash: ${context} expected a list`);
  }
  return value;
}

function expectReflectMap(value: unknown, context: string): ReflectMap {
  if (!isReflectMap(value)) {
    throw new SparkInputError(`protohash: ${context} expected a map`);
  }
  return value;
}

function tagged(tag: Uint8Array, value: Uint8Array): Uint8Array {
  const h = sha256.create();
  h.update(tag);
  h.update(value);
  return h.digest();
}

function hashBool(v: boolean): Uint8Array {
  return tagged(BOOL_TAG, v ? utf8ToBytes("1") : utf8ToBytes("0"));
}

function hashU64(v: bigint): Uint8Array {
  const bytes = uint64be(v & MAX_UINT64);
  return tagged(INT_TAG, bytes);
}

function hashF64(v: number): Uint8Array {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  if (Number.isNaN(v)) {
    view.setBigUint64(0, NAN_BITS, false);
  } else {
    // -0 normalizes to +0 before taking the bits, matching the Rust port.
    view.setFloat64(0, v === 0 ? 0 : v, false);
  }
  return tagged(FLOAT_TAG, bytes);
}

function hashString(v: string): Uint8Array {
  return tagged(STRING_TAG, utf8ToBytes(v));
}

function hashBytes(v: Uint8Array): Uint8Array {
  return tagged(BYTES_TAG, v);
}

function hashFieldKey(number: number): Uint8Array {
  return hashU64(BigInt(number));
}

const INTEGER_SCALAR_TYPES = new Set<ScalarType>([
  ScalarType.INT32,
  ScalarType.SINT32,
  ScalarType.SFIXED32,
  ScalarType.INT64,
  ScalarType.SINT64,
  ScalarType.SFIXED64,
  ScalarType.UINT32,
  ScalarType.FIXED32,
  ScalarType.UINT64,
  ScalarType.FIXED64,
]);

function hashScalar(scalar: ScalarType, value: unknown): Uint8Array {
  if (scalar === ScalarType.BOOL) {
    return hashBool(value === true);
  }
  if (scalar === ScalarType.DOUBLE) {
    return hashF64(expectNumber(value, "double"));
  }
  if (scalar === ScalarType.FLOAT) {
    // proto float promotes to f64 through f32 storage, like Rust `as f64`.
    return hashF64(Math.fround(expectNumber(value, "float")));
  }
  if (INTEGER_SCALAR_TYPES.has(scalar)) {
    return hashU64(expectInteger(value, "integer scalar"));
  }
  if (scalar === ScalarType.STRING) {
    return hashString(expectString(value, "string"));
  }
  return hashBytes(expectBytes(value, "bytes"));
}

function hashEnum(value: unknown): Uint8Array {
  return hashU64(expectInteger(value, "enum"));
}

function isScalarDefault(scalar: ScalarType, value: unknown): boolean {
  switch (scalar) {
    case ScalarType.BOOL:
      return value === false;
    case ScalarType.STRING:
      return value === "";
    case ScalarType.BYTES:
      return value instanceof Uint8Array && value.length === 0;
    case ScalarType.DOUBLE:
    case ScalarType.FLOAT:
      // JS `===` treats -0 as 0, matching Rust `==` on f64.
      return value === 0;
    default:
      return value === 0 || value === 0n;
  }
}

function isEmptyMessage(message: ReflectMessage): boolean {
  for (const field of message.desc.fields) {
    if (message.isSet(field)) {
      return false;
    }
  }
  return true;
}

function isDefaultValue(field: DescField, value: unknown): boolean {
  switch (field.fieldKind) {
    case "scalar":
      return isScalarDefault(field.scalar, value);
    case "enum":
      return value === (field.getDefaultValue() ?? 0);
    case "message":
      return isReflectMessage(value) && isEmptyMessage(value);
    default:
      return false;
  }
}

function hashSingular(field: DescField, value: unknown): Uint8Array | undefined {
  switch (field.fieldKind) {
    case "scalar":
      return hashScalar(field.scalar, value);
    case "enum":
      return hashEnum(value);
    case "message":
      return hashMessage(expectReflectMessage(value, field.name));
    default:
      return undefined;
  }
}

/** Hashes a repeated element or a map key/value against the element kind of `field`. */
function hashElement(field: DescField, value: unknown): Uint8Array | undefined {
  if (field.fieldKind === "list") {
    switch (field.listKind) {
      case "scalar":
        return hashScalar(field.scalar, value);
      case "enum":
        return hashEnum(value);
      case "message":
        return hashMessage(expectReflectMessage(value, field.name));
    }
  }
  if (field.fieldKind === "map") {
    switch (field.mapKind) {
      case "scalar":
        return hashScalar(field.scalar, value);
      case "enum":
        return hashEnum(value);
      case "message":
        return hashMessage(expectReflectMessage(value, field.name));
    }
  }
  return hashSingular(field, value);
}

function hashList(field: DescField, value: unknown): Uint8Array | undefined {
  const list = expectReflectList(value, field.name);
  if (list.size === 0) {
    return undefined;
  }
  const h = sha256.create();
  h.update(LIST_TAG);
  for (const item of list) {
    const itemHash = hashElement(field, item);
    if (itemHash !== undefined) {
      h.update(itemHash);
    }
  }
  return h.digest();
}

function hashMap(field: DescField, mapValue: unknown): Uint8Array | undefined {
  if (field.fieldKind !== "map") {
    throw new SparkInputError(`protohash: ${field.name} is not a map field`);
  }
  const map = expectReflectMap(mapValue, field.name);
  const entries: Array<{ k: Uint8Array; v: Uint8Array }> = [];
  for (const [key, value] of map.entries()) {
    if (isGoogleValueNull(value)) {
      continue;
    }
    const kHash = hashScalar(field.mapKey, key);
    const vHash = hashElement(field, value);
    if (vHash === undefined) {
      return undefined;
    }
    entries.push({ k: kHash, v: vHash });
  }
  if (entries.length === 0) {
    return undefined;
  }
  entries.sort((a, b) => compareBytes(a.k, b.k));
  const h = sha256.create();
  h.update(MAP_TAG);
  for (const entry of entries) {
    h.update(entry.k);
    h.update(entry.v);
  }
  return h.digest();
}

function hashFieldValue(field: DescField, value: unknown): Uint8Array | undefined {
  if (field.fieldKind === "list") {
    return hashList(field, value);
  }
  if (field.fieldKind === "map") {
    return hashMap(field, value);
  }
  return hashSingular(field, value);
}

// ---------------------------------------------------------------------------
// google.protobuf well-known types
// ---------------------------------------------------------------------------

type GoogleValueKind =
  | "any"
  | "bool"
  | "int32"
  | "int64"
  | "uint32"
  | "uint64"
  | "float"
  | "double"
  | "string"
  | "struct"
  | "timestamp"
  | "duration"
  | "list"
  | "value";

function googleValueKind(typeName: string): GoogleValueKind | undefined {
  switch (typeName) {
    case "google.protobuf.Any":
      return "any";
    case "google.protobuf.BoolValue":
      return "bool";
    case "google.protobuf.Int32Value":
      return "int32";
    case "google.protobuf.Int64Value":
      return "int64";
    case "google.protobuf.UInt32Value":
      return "uint32";
    case "google.protobuf.UInt64Value":
      return "uint64";
    case "google.protobuf.FloatValue":
      return "float";
    case "google.protobuf.DoubleValue":
      return "double";
    case "google.protobuf.StringValue":
      return "string";
    case "google.protobuf.Struct":
      return "struct";
    case "google.protobuf.Timestamp":
      return "timestamp";
    case "google.protobuf.Duration":
      return "duration";
    case "google.protobuf.ListValue":
      return "list";
    case "google.protobuf.Value":
      return "value";
    default:
      // Notably absent upstream: google.protobuf.BytesValue and
      // google.protobuf.Empty hash as regular messages.
      return undefined;
  }
}

function fieldByName(desc: DescMessage, name: string): DescField {
  const field = desc.fields.find((f) => f.name === name);
  if (field === undefined) {
    throw new SparkInputError(`protohash: missing field ${name} on ${desc.typeName}`);
  }
  return field;
}

/** Listed fields hashed in the given order under "l", defaults included. */
function hashFieldsByNames(message: ReflectMessage, names: ReadonlyArray<string>): Uint8Array {
  const h = sha256.create();
  h.update(LIST_TAG);
  for (const name of names) {
    const field = fieldByName(message.desc, name);
    const valueHash = hashSingular(field, message.get(field));
    if (valueHash !== undefined) {
      h.update(valueHash);
    }
  }
  return h.digest();
}

function hashWrapper(message: ReflectMessage): Uint8Array {
  const field = fieldByName(message.desc, "value");
  const hashed = hashSingular(field, message.get(field));
  if (hashed === undefined) {
    throw new SparkInputError(`protohash: ${message.desc.typeName} value is not hashable`);
  }
  return hashed;
}

function hashStruct(message: ReflectMessage): Uint8Array {
  const field = fieldByName(message.desc, "fields");
  const map = expectReflectMap(message.get(field), "struct fields");
  const entries: Array<{ k: Uint8Array; v: Uint8Array }> = [];
  for (const [key, value] of map.entries()) {
    const kHash = hashString(expectString(key, "struct key"));
    if (isGoogleValueNull(value)) {
      continue;
    }
    const vHash = hashMessage(expectReflectMessage(value, "struct value"));
    if (vHash !== undefined) {
      entries.push({ k: kHash, v: vHash });
    }
  }
  entries.sort((a, b) => compareBytes(a.k, b.k));
  const h = sha256.create();
  h.update(MAP_TAG);
  for (const entry of entries) {
    h.update(entry.k);
    h.update(entry.v);
  }
  return h.digest();
}

function hashGoogleList(message: ReflectMessage): Uint8Array | undefined {
  const field = fieldByName(message.desc, "values");
  return hashList(field, message.get(field));
}

function hashGoogleValue(message: ReflectMessage): Uint8Array | undefined {
  const active = activeKindField(message, "kind");
  if (active === undefined) {
    throw new SparkInputError("protohash: google.protobuf.Value has no kind set");
  }
  const value = message.get(active);
  switch (active.name) {
    case "number_value":
      return hashF64(expectNumber(value, "number_value"));
    case "string_value":
      return hashString(expectString(value, "string_value"));
    case "bool_value":
      return hashBool(value === true);
    case "struct_value":
      return hashStruct(expectReflectMessage(value, "struct_value"));
    case "list_value":
      return hashGoogleList(expectReflectMessage(value, "list_value"));
    case "null_value":
      throw new SparkInputError("protohash: null google.protobuf.Value cannot be hashed");
    default:
      throw new SparkInputError(`protohash: unexpected google.protobuf.Value kind`);
  }
}

function activeKindField(message: ReflectMessage, name: string | undefined): DescField | undefined {
  if (name === undefined) {
    return undefined;
  }
  const oneof = message.desc.oneofs.find((o) => o.name === name);
  if (oneof === undefined) {
    return undefined;
  }
  return message.oneofCase(oneof);
}

function isGoogleValueNull(value: unknown): boolean {
  if (!isReflectMessage(value) || value.desc.typeName !== "google.protobuf.Value") {
    return false;
  }
  const active = activeKindField(value, "kind");
  return active === undefined || active.name === "null_value";
}

const WRAPPER_KINDS = new Set<GoogleValueKind>([
  "bool",
  "int32",
  "int64",
  "uint32",
  "uint64",
  "float",
  "double",
  "string",
]);

function hashGoogleValueMessage(
  kind: GoogleValueKind,
  message: ReflectMessage,
): Uint8Array | undefined {
  if (kind === "any") {
    const typeUrl = message.get(fieldByName(message.desc, "type_url"));
    throw new SparkInputError(
      `protohash: Any is not supported (type_url ${typeof typeUrl === "string" ? typeUrl : "?"})`,
    );
  }
  if (WRAPPER_KINDS.has(kind)) {
    return hashWrapper(message);
  }
  if (kind === "struct") {
    return hashStruct(message);
  }
  if (kind === "timestamp" || kind === "duration") {
    return hashFieldsByNames(message, ["seconds", "nanos"]);
  }
  if (kind === "list") {
    return hashGoogleList(message);
  }
  return hashGoogleValue(message);
}

function hashMessage(message: ReflectMessage): Uint8Array | undefined {
  const { typeName } = message.desc;
  if (typeName.startsWith(WKT_PREFIX)) {
    const kind = googleValueKind(typeName);
    if (kind !== undefined) {
      return hashGoogleValueMessage(kind, message);
    }
  }

  const fieldHashes: Array<{ number: number; k: Uint8Array; v: Uint8Array }> = [];
  for (const field of message.desc.fields) {
    if (!message.isSet(field)) {
      continue;
    }
    const value = message.get(field);
    if (isDefaultValue(field, value)) {
      continue;
    }
    const vHash = hashFieldValue(field, value);
    if (vHash === undefined) {
      continue;
    }
    fieldHashes.push({ number: field.number, k: hashFieldKey(field.number), v: vHash });
  }
  fieldHashes.sort((a, b) => a.number - b.number);

  const h = sha256.create();
  h.update(MAP_TAG);
  for (const entry of fieldHashes) {
    h.update(entry.k);
    h.update(entry.v);
  }
  return h.digest();
}

/**
 * Protoreflecthash over a protobuf-es message: the deterministic SHA-256 digest Go's
 * `protohash.Hash` and Rust `spark-token-primitives` produce identically. Top-level
 * `google.protobuf` scalar/value wrapper types are rejected (they have no field-number context);
 * every other message hashes to 32 bytes. Unknown fields are ignored.
 */
export function hashProto(schema: DescMessage, message: Message): Uint8Array {
  const reflected = reflect(schema, message);
  const { typeName } = reflected.desc;
  if (TOP_LEVEL_REJECTED.has(typeName)) {
    throw new SparkInputError(`protohash: top-level ${typeName} is not hashable`);
  }
  const digest = hashMessage(reflected);
  if (digest === undefined) {
    throw new SparkInputError(`protohash: nothing to hash in ${typeName}`);
  }
  return digest;
}
