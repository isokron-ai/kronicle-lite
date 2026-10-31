import { sha256Hex } from '../crypto/hash.js';

/**
 * The genesis string is public. prev_hash of the first event (seq 1) is
 * sha256 of this string, so anyone holding a copy of the database can
 * verify the chain from seq 1 without any secret.
 */
export const GENESIS_STRING = 'kronicle-lite-genesis-v1';
export const GENESIS_HASH: string = sha256Hex(GENESIS_STRING);
