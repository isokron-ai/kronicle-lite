/**
 * Binary Merkle tree over event hashes for checkpoints.
 *
 * leaf  = sha256( canonicalize({seq, this_hash}) )
 * node  = sha256( left || right )           (raw 32-byte concatenation)
 * odd node at a level is promoted unchanged; the root of a single leaf is
 * that leaf's hash. Leaves are in ascending seq order.
 */

import { canonicalize } from '../crypto/canonical.js';
import { bytesToHex, sha256Bytes } from '../crypto/hash.js';

export interface MerkleLeaf {
  seq: number;
  this_hash: string;
}

export function leafHash(leaf: MerkleLeaf): Uint8Array {
  return sha256Bytes(canonicalize({ seq: leaf.seq, this_hash: leaf.this_hash }));
}

export function merkleRoot(leaves: readonly MerkleLeaf[]): Uint8Array {
  if (leaves.length === 0) throw new Error('merkle: empty leaf set has no root');
  let level: Uint8Array[] = leaves.map(leafHash);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      if (right) {
        const joined = new Uint8Array(left.length + right.length);
        joined.set(left, 0);
        joined.set(right, left.length);
        next.push(sha256Bytes(joined));
      } else {
        next.push(left);
      }
    }
    level = next;
  }
  return level[0]!;
}

export function merkleRootHex(leaves: readonly MerkleLeaf[]): string {
  return bytesToHex(merkleRoot(leaves));
}
