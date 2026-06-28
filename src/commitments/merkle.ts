/**
 * merkle.ts
 *
 * RFC 6962-style Merkle tree with explicit one-byte domain separation.
 *
 * Domain separation (RFC 6962 §2.1):
 *   leaf_hash     = SHA-256(0x00 || leaf_bytes)
 *   internal_hash = SHA-256(0x01 || left_child_hash || right_child_hash)
 *
 * Without domain separation a leaf hash could collide with an internal
 * node hash, allowing forged inclusion proofs. The 0x00 / 0x01 prefix
 * is the standard fix used by Certificate Transparency, Sigstore Rekor,
 * and every other production Merkle log.
 *
 * Non-power-of-two leaf counts are handled by recursive split on the
 * largest power of two strictly less than n (RFC 6962 §2.1). This
 * matches Certificate Transparency's tree shape exactly. No padding.
 *
 * This module is byte-compatible with draft-farley-acta-signed-receipts-03
 * §commitment-mode and with RFC 6962 SHA-256 trees.
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

/** Domain-separation byte for a Merkle leaf, per RFC 6962 §2.1. */
export const DOMAIN_LEAF = 0x00;

/** Domain-separation byte for a Merkle internal node, per RFC 6962 §2.1. */
export const DOMAIN_INTERNAL = 0x01;

/**
 * A Merkle inclusion proof for a single leaf.
 *
 * The siblings array lists the sibling hashes encountered while walking
 * from the leaf up to the root. Each sibling is hex-encoded SHA-256.
 * The (index, treeSize) pair determines whether the current node is
 * left or right at each level during verification.
 */
export interface MerkleProof {
  /** Zero-based index of the leaf in the canonically-sorted leaf list. */
  index: number;
  /** Total number of leaves in the tree. */
  treeSize: number;
  /** Sibling hashes from leaf upward, hex-encoded SHA-256 (lowercase). */
  siblings: string[];
}

/**
 * Hash a leaf with RFC 6962 domain separation.
 * @param leafBytes the canonical leaf byte sequence (no prefix)
 * @returns 32-byte SHA-256 of (0x00 || leafBytes)
 */
export function hashLeaf(leafBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(leafBytes.length + 1);
  buf[0] = DOMAIN_LEAF;
  buf.set(leafBytes, 1);
  return sha256(buf);
}

/**
 * Hash an internal node with RFC 6962 domain separation.
 * @param left  32-byte left-child hash
 * @param right 32-byte right-child hash
 * @returns 32-byte SHA-256 of (0x01 || left || right)
 */
export function hashInternal(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(left.length + right.length + 1);
  buf[0] = DOMAIN_INTERNAL;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

/**
 * Compute the Merkle root over a list of pre-hashed leaves.
 * Follows RFC 6962 §2.1 recursive split: at each level, the largest
 * power of two strictly less than n becomes the left subtree size.
 *
 * @param leafHashes ordered list of 32-byte leaf hashes (already
 *   prefixed with DOMAIN_LEAF; use {@link hashLeaf} to produce them)
 * @returns 32-byte Merkle root
 */
export function merkleRoot(leafHashes: Uint8Array[]): Uint8Array {
  if (leafHashes.length === 0) {
    throw new Error("merkleRoot: cannot compute root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const n = leafHashes.length;
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRoot(leafHashes.slice(0, k));
  const right = merkleRoot(leafHashes.slice(k));
  return hashInternal(left, right);
}

/**
 * Generate an inclusion proof for the leaf at the given index.
 * Follows the RFC 6962 §2.1.1 PATH algorithm.
 *
 * @param leafHashes the canonically-ordered leaf hashes
 * @param index zero-based leaf index
 * @returns inclusion proof
 */
export function generateProof(
  leafHashes: Uint8Array[],
  index: number,
): MerkleProof {
  if (leafHashes.length === 0) {
    throw new Error("generateProof: empty tree");
  }
  if (index < 0 || index >= leafHashes.length) {
    throw new Error(
      `generateProof: index ${index} out of range [0, ${leafHashes.length})`,
    );
  }
  const siblings: Uint8Array[] = [];
  collectPath(leafHashes, index, siblings);
  return {
    index,
    treeSize: leafHashes.length,
    siblings: siblings.map((s) => bytesToHex(s)),
  };
}

/**
 * Recursive PATH function from RFC 6962 §2.1.1.
 *
 * For tree T(D) with |D| = n:
 *   PATH(m, D) = []                                           if n = 1
 *   PATH(m, D) = PATH(m, D[0..k]) || MTH(D[k..n])             if m < k
 *   PATH(m, D) = PATH(m-k, D[k..n]) || MTH(D[0..k])           if m >= k
 * where k = largest power of 2 strictly less than n.
 *
 * Note: siblings are appended bottom-up (closest sibling first).
 */
function collectPath(
  leaves: Uint8Array[],
  index: number,
  out: Uint8Array[],
): void {
  if (leaves.length === 1) return;
  const n = leaves.length;
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    collectPath(leaves.slice(0, k), index, out);
    out.push(merkleRoot(leaves.slice(k)));
  } else {
    collectPath(leaves.slice(k), index - k, out);
    out.push(merkleRoot(leaves.slice(0, k)));
  }
}

/**
 * Verify a Merkle inclusion proof against an expected root.
 *
 * @param expectedRootHex hex-encoded expected Merkle root
 * @param leafHash 32-byte leaf hash (already domain-separated; use
 *   {@link hashLeaf} to produce it from leaf bytes)
 * @param proof inclusion proof produced by {@link generateProof}
 * @returns true iff the proof reconstructs the expected root
 */
export function verifyProof(
  expectedRootHex: string,
  leafHash: Uint8Array,
  proof: MerkleProof,
): boolean {
  if (proof.index < 0 || proof.index >= proof.treeSize) return false;
  if (proof.treeSize === 1) {
    return (
      proof.siblings.length === 0 &&
      bytesToHex(leafHash).toLowerCase() === expectedRootHex.toLowerCase()
    );
  }
  // Recursive top-down reconstruction. Siblings were appended bottom-up
  // during generation (deepest first, outermost last), so verification
  // consumes them from the END of the array, peeling off the outermost
  // sibling at each level and recursing into the subtree containing
  // the leaf.
  let result: Uint8Array;
  try {
    result = reconstructRoot(
      leafHash,
      proof.index,
      proof.treeSize,
      proof.siblings,
    );
  } catch {
    return false;
  }
  return bytesToHex(result).toLowerCase() === expectedRootHex.toLowerCase();
}

/**
 * Recursively reconstruct the Merkle root from a leaf hash, its index,
 * the tree size, and the inclusion-proof siblings.
 *
 * Siblings are consumed from the END (last appended = outermost level).
 * This mirrors the recursive PATH algorithm in {@link generateProof}.
 */
function reconstructRoot(
  leafHash: Uint8Array,
  index: number,
  treeSize: number,
  siblings: string[],
): Uint8Array {
  if (treeSize === 1) {
    if (siblings.length !== 0) {
      throw new Error("reconstructRoot: extra siblings at single-leaf level");
    }
    return leafHash;
  }
  if (siblings.length === 0) {
    throw new Error("reconstructRoot: ran out of siblings before single-leaf");
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  const outermostSibling = hexToBytes(siblings[siblings.length - 1]);
  const innerSiblings = siblings.slice(0, -1);
  if (index < k) {
    // Leaf is in the left subtree.
    const leftHash = reconstructRoot(leafHash, index, k, innerSiblings);
    return hashInternal(leftHash, outermostSibling);
  } else {
    // Leaf is in the right subtree.
    const rightHash = reconstructRoot(
      leafHash,
      index - k,
      treeSize - k,
      innerSiblings,
    );
    return hashInternal(outermostSibling, rightHash);
  }
}

/**
 * Largest power of two strictly less than n. Defined for n >= 2.
 * For n=2 returns 1; n=3 returns 2; n=4 returns 2; n=5 returns 4;
 * n=8 returns 4; etc.
 */
function largestPowerOfTwoLessThan(n: number): number {
  if (n < 2) {
    throw new Error(`largestPowerOfTwoLessThan: n must be >= 2 (got ${n})`);
  }
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
