/**
 * leaf.ts
 *
 * Canonical leaf encoding for commitment-mode receipts.
 *
 * Each leaf is a JCS-canonicalized JSON object with three fields:
 *   { "name": <field_name>, "salt": <base64url salt>, "value": <field_value> }
 *
 * The leaf bytes are then hashed with RFC 6962 domain separation
 * (see merkle.ts). Including the field name in the leaf binds the
 * commitment to a specific field, preventing cross-field substitution
 * attacks where the same (salt, value) commitment could be claimed
 * to belong to a different field.
 *
 * Leaves are sorted by byte-lexicographic order of the UTF-8 encoded
 * field name. No locale, no case folding, no Unicode normalization.
 * Two implementations that disagree on sort order produce different
 * roots; this rule eliminates that source of interop failure.
 */

import { jcs } from "./primitives.js";

/** Base64url encode without padding (RFC 4648 §5). */
export function base64urlNoPad(bytes: Uint8Array): string {
  // Use Buffer if available (Node), else btoa fallback.
  // The implementation must be deterministic across platforms.
  const std =
    typeof Buffer !== "undefined"
      ? Buffer.from(bytes).toString("base64")
      : btoa(String.fromCharCode(...bytes));
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url decode without padding. */
export function base64urlDecode(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * A single committed field, before encoding to a leaf.
 * The value retains its original JSON type (string, number, boolean,
 * object, array, null), preserved through JCS.
 */
export interface CommittedField {
  name: string;
  salt: Uint8Array;
  value: unknown;
}

/**
 * Encode a committed field as canonical leaf bytes.
 * Returns the JCS bytes ready to feed into hashLeaf().
 */
export function encodeLeaf(field: CommittedField): Uint8Array {
  const obj = {
    name: field.name,
    salt: base64urlNoPad(field.salt),
    value: field.value,
  };
  const canonical = jcs(obj);
  return new TextEncoder().encode(canonical);
}

/**
 * Sort committed fields into canonical Merkle-leaf order.
 *
 * Order: byte-lexicographic over the UTF-8 encoding of `name`.
 * MUST NOT apply locale-aware collation or case folding.
 *
 * Returns a new array; does not mutate the input.
 */
export function sortFields<T extends { name: string }>(fields: T[]): T[] {
  const encoder = new TextEncoder();
  const decorated = fields.map((f) => ({
    field: f,
    nameBytes: encoder.encode(f.name),
  }));
  decorated.sort((a, b) => compareBytes(a.nameBytes, b.nameBytes));
  return decorated.map((d) => d.field);
}

/** Lexicographic compare of two byte sequences. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Helper: build the canonical (sorted) leaf-bytes list from a set of
 * committed fields. Combine with merkle.ts to produce a root and proofs.
 */
export function leavesFromFields(fields: CommittedField[]): {
  sorted: CommittedField[];
  leafBytes: Uint8Array[];
} {
  const sorted = sortFields(fields);
  const leafBytes = sorted.map(encodeLeaf);
  return { sorted, leafBytes };
}
