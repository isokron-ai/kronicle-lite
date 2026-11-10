/**
 * SSH signatures (0.11.0): `ssh-keygen -Y sign` output checked against an
 * allowed-signers entry, as `ssh-keygen -Y verify` does, in-process (no
 * ssh-keygen needed). `verify-audit` uses it for the human sign-off on a
 * reproduced finding (`reproduction_signed`, docs/AUDIT.md).
 *
 * Format: OpenSSH PROTOCOL.sshsig. The armored blob is
 *   "SSHSIG" ‖ uint32 1 ‖ string publickey ‖ string namespace ‖ string reserved ‖ string hash_alg ‖ string signature
 * and the key signs
 *   "SSHSIG" ‖ string namespace ‖ string reserved ‖ string hash_alg ‖ string H(message)
 * with H sha256 or sha512. Keys: ssh-ed25519, and sk-ssh-ed25519@openssh.com
 * (a FIDO hardware key, which signs sha256(application) ‖ flags ‖ counter ‖
 * sha256(that), and must assert user presence). Other key types are refused.
 *
 * Allowed signers (ssh-keygen(1) ALLOWED SIGNERS): `principals [options] keytype base64 [comment]`.
 * Principals are comma-separated patterns (`*`, `?`); the options honoured are
 * `namespaces="…"`, `valid-after="…"` and `valid-before="…"`; an entry with
 * `cert-authority` or an unknown option never matches (certificates are not supported).
 */

import { createHash } from 'node:crypto';

import { verifyEd25519Strict } from '../anchor/ed25519-strict.js';

const MAGIC = Buffer.from('SSHSIG');
const ED25519 = 'ssh-ed25519';
const SK_ED25519 = 'sk-ssh-ed25519@openssh.com';
const KEY_TYPES = new Set([ED25519, SK_ED25519, 'ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ecdsa-sha2-nistp256@openssh.com']);
/** Largest armored signature read (an Ed25519 one is about 300 bytes). */
export const MAX_SSHSIG_BYTES = 16 * 1024;

class Reader {
  private pos = 0;
  constructor(private readonly b: Buffer) {}
  u32(): number {
    if (this.pos + 4 > this.b.length) throw new Error('truncated');
    const v = this.b.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }
  byte(): number {
    if (this.pos + 1 > this.b.length) throw new Error('truncated');
    return this.b[this.pos++]!;
  }
  string(): Buffer {
    const n = this.u32();
    if (n > this.b.length - this.pos) throw new Error('truncated');
    const v = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  raw(n: number): Buffer {
    if (n > this.b.length - this.pos) throw new Error('truncated');
    const v = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  done(): boolean {
    return this.pos === this.b.length;
  }
}

const sshString = (b: Buffer | string): Buffer => {
  const v = typeof b === 'string' ? Buffer.from(b, 'utf8') : b;
  const n = Buffer.alloc(4);
  n.writeUInt32BE(v.length);
  return Buffer.concat([n, v]);
};

/** SHA256:<base64, no padding> of a public key blob, as ssh-keygen -l prints it. */
export const sshKeyFingerprint = (blob: Buffer): string => `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;

/** The raw 32-byte Ed25519 key in an ssh-ed25519 or sk-ssh-ed25519 public key blob; null for anything else. */
export function ed25519OfSshKey(blob: Buffer): Buffer | null {
  try {
    const r = new Reader(blob);
    const type = r.string().toString('utf8');
    if (type !== ED25519 && type !== SK_ED25519) return null;
    const pk = r.string();
    if (type === SK_ED25519) r.string();
    return r.done() && pk.length === 32 ? Buffer.from(pk) : null;
  } catch {
    return null;
  }
}

const spkiPem = (raw: Buffer): string =>
  `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]).toString('base64')}\n-----END PUBLIC KEY-----\n`;

export interface AllowedSigner {
  line: number;
  principals: string[];
  namespaces: string[] | null;
  valid_after: Date | null;
  valid_before: Date | null;
  key_type: string;
  key: Buffer;
  /** Why the entry can never match (cert-authority, an unknown option, a malformed time), or null. */
  unusable: string | null;
}

/** Split on unquoted whitespace (double quotes group, as in authorized_keys). */
function fields(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (const ch of line) {
    if (ch === '"') quoted = !quoted;
    if (!quoted && (ch === ' ' || ch === '\t')) {
      if (cur) out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** Split options on unquoted commas. */
function splitOptions(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (const ch of s) {
    if (ch === '"') quoted = !quoted;
    if (!quoted && ch === ',') {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out.filter(Boolean);
}

/** ssh-keygen's YYYYMMDD[HHMM[SS]][Z] (local time without Z; read as UTC here, so write the Z). */
function sshTime(v: string): Date | null {
  const m = /^(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(\d{2})?)?Z?$/.exec(v);
  if (!m) return null;
  const d = new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +(m[4] ?? 0), +(m[5] ?? 0), +(m[6] ?? 0)));
  return Number.isFinite(d.getTime()) ? d : null;
}

/** Parse an allowed-signers file. Lines that are not entries are skipped with their reason. */
export function parseAllowedSigners(text: string): { entries: AllowedSigner[]; problems: string[] } {
  const entries: AllowedSigner[] = [];
  const problems: string[] = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const f = fields(line);
    if (f.length < 3) {
      problems.push(`line ${i + 1}: expected "principals [options] keytype key"`);
      continue;
    }
    const principals = f[0]!.replace(/^"|"$/g, '').split(',').filter(Boolean);
    let k = 1;
    let options: string[] = [];
    if (!KEY_TYPES.has(f[1]!)) {
      options = splitOptions(f[1]!);
      k = 2;
    }
    const key_type = f[k];
    const b64 = f[k + 1];
    if (!key_type || !b64 || !KEY_TYPES.has(key_type)) {
      problems.push(`line ${i + 1}: unknown key type ${key_type ?? '(none)'}`);
      continue;
    }
    const key = Buffer.from(b64, 'base64');
    let unusable: string | null = null;
    let namespaces: string[] | null = null;
    let valid_after: Date | null = null;
    let valid_before: Date | null = null;
    for (const o of options) {
      const eq = o.indexOf('=');
      const name = (eq < 0 ? o : o.slice(0, eq)).toLowerCase();
      const val = eq < 0 ? '' : o.slice(eq + 1).replace(/^"|"$/g, '');
      if (name === 'namespaces') namespaces = val.split(',').filter(Boolean);
      else if (name === 'valid-after' || name === 'valid-before') {
        const t = sshTime(val);
        if (t === null) unusable = `${name} "${val}" is not YYYYMMDD[HHMM[SS]]Z`;
        else if (name === 'valid-after') valid_after = t;
        else valid_before = t;
      } else unusable = name === 'cert-authority' ? 'cert-authority entries are not supported' : `unknown option ${name}`;
    }
    entries.push({ line: i + 1, principals, namespaces, valid_after, valid_before, key_type, key, unusable });
  }
  return { entries, problems };
}

const glob = (pattern: string, s: string): boolean =>
  new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`).test(s);

/** Does `principal` match an entry's principal list (OpenSSH match_pattern_list: `!` negates)? */
function principalMatches(list: string[], principal: string): boolean {
  let hit = false;
  for (const p of list) {
    if (p.startsWith('!')) {
      if (glob(p.slice(1), principal)) return false;
    } else if (glob(p, principal)) hit = true;
  }
  return hit;
}

export interface SshSignatureCheck {
  ok: boolean;
  problem: string | null;
  key_type: string | null;
  /** SHA256:… of the signing key (ssh-keygen -l). */
  fingerprint: string | null;
  /** The raw Ed25519 key that signed, when ok. */
  ed25519: Buffer | null;
  /** The allowed-signers line that matched. */
  line: number | null;
}

/**
 * Verify an armored SSH signature over `message` in `namespace`, by a key the allowed-signers
 * text lists for `principal` (valid at `at` when the entry bounds it). Never throws.
 */
export function verifySshSignature(armored: string | Buffer, message: Buffer | string, o: { namespace: string; principal: string; allowed_signers: string; at?: Date }): SshSignatureCheck {
  const res: SshSignatureCheck = { ok: false, problem: null, key_type: null, fingerprint: null, ed25519: null, line: null };
  const bad = (why: string) => ({ ...res, problem: why });
  try {
    const text = (typeof armored === 'string' ? armored : armored.toString('utf8')).trim();
    if (text.length > MAX_SSHSIG_BYTES) return bad('the signature is larger than 16 KiB');
    const m = /^-----BEGIN SSH SIGNATURE-----\r?\n([A-Za-z0-9+/=\r\n]+?)\r?\n-----END SSH SIGNATURE-----$/.exec(text);
    if (!m) return bad('not an armored SSH signature (-----BEGIN SSH SIGNATURE-----)');
    const blob = Buffer.from(m[1]!.replace(/\s+/g, ''), 'base64');
    const r = new Reader(blob);
    if (!r.raw(6).equals(MAGIC)) return bad('not an SSHSIG blob');
    if (r.u32() !== 1) return bad('unsupported SSHSIG version');
    const pub = Buffer.from(r.string());
    const ns = r.string().toString('utf8');
    const reserved = r.string();
    const hashAlg = r.string().toString('utf8');
    const sigBlob = r.string();
    if (!r.done()) return bad('trailing bytes after the SSHSIG blob');
    const pr = new Reader(pub);
    const keyType = pr.string().toString('utf8');
    res.key_type = keyType;
    res.fingerprint = sshKeyFingerprint(pub);
    if (keyType !== ED25519 && keyType !== SK_ED25519) return bad(`key type ${keyType} is not supported (use an Ed25519 key: ssh-ed25519 or sk-ssh-ed25519@openssh.com)`);
    const pk = pr.string();
    const application = keyType === SK_ED25519 ? pr.string() : null;
    if (!pr.done() || pk.length !== 32) return bad('malformed public key in the signature');
    if (ns !== o.namespace) return bad(`signed in namespace "${ns}", not "${o.namespace}"`);
    if (reserved.length !== 0) return bad('the reserved field is not empty');
    if (hashAlg !== 'sha256' && hashAlg !== 'sha512') return bad(`hash algorithm ${hashAlg} is not sha256 or sha512`);
    const sr = new Reader(Buffer.from(sigBlob));
    const sigType = sr.string().toString('utf8');
    if (sigType !== keyType) return bad(`signature type ${sigType} does not match the key type ${keyType}`);
    const sig = sr.string();
    let flags = 0;
    let counter: Buffer = Buffer.alloc(0);
    if (keyType === SK_ED25519) {
      flags = sr.byte();
      counter = sr.raw(4);
    }
    if (!sr.done() || sig.length !== 64) return bad('malformed signature blob');

    // The key must be listed for the principal, in this namespace, at this time.
    const { entries } = parseAllowedSigners(o.allowed_signers);
    const listed = entries.filter((e) => e.key_type === keyType && e.key.equals(pub) && principalMatches(e.principals, o.principal));
    if (listed.length === 0) return bad(`key ${res.fingerprint} is not in the allowed signers for ${o.principal}`);
    const usable = listed.find((e) => e.unusable === null && (e.namespaces === null || e.namespaces.some((n) => glob(n, o.namespace))) && (!o.at || ((e.valid_after === null || o.at >= e.valid_after) && (e.valid_before === null || o.at < e.valid_before))));
    if (!usable) {
      const e = listed[0]!;
      return bad(e.unusable ?? (e.namespaces !== null && !e.namespaces.some((n) => glob(n, o.namespace)) ? `allowed signers line ${e.line} does not allow namespace "${o.namespace}"` : `allowed signers line ${e.line} is not valid at ${o.at?.toISOString() ?? '?'}`));
    }
    res.line = usable.line;

    const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    const h = createHash(hashAlg).update(msg).digest();
    let signed = Buffer.concat([MAGIC, sshString(ns), sshString(reserved), sshString(hashAlg), sshString(h)]);
    if (keyType === SK_ED25519) {
      if ((flags & 0x01) === 0) return bad('the hardware key did not assert user presence');
      signed = Buffer.concat([createHash('sha256').update(application!).digest(), Buffer.from([flags]), counter, createHash('sha256').update(signed).digest()]);
    }
    if (!verifyEd25519Strict(spkiPem(Buffer.from(pk)), signed, Buffer.from(sig).toString('base64'))) return bad(`the signature does not verify under ${res.fingerprint}`);
    return { ...res, ok: true, ed25519: Buffer.from(pk) };
  } catch (err) {
    return bad(`malformed SSH signature: ${(err as Error).message}`);
  }
}

/**
 * Build an armored SSH signature (what `ssh-keygen -Y sign` writes) from an Ed25519 signing
 * function: for library callers and tests that hold the key in-process.
 */
export function sshSign(message: Buffer | string, o: { namespace: string; public_key: Buffer; sign: (data: Buffer) => Buffer; hash?: 'sha256' | 'sha512' }): string {
  const hashAlg = o.hash ?? 'sha512';
  const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const pub = Buffer.concat([sshString(ED25519), sshString(o.public_key)]);
  const signed = Buffer.concat([MAGIC, sshString(o.namespace), sshString(''), sshString(hashAlg), sshString(createHash(hashAlg).update(msg).digest())]);
  const sig = Buffer.concat([sshString(ED25519), sshString(o.sign(signed))]);
  const v = Buffer.alloc(4);
  v.writeUInt32BE(1);
  const blob = Buffer.concat([MAGIC, v, sshString(pub), sshString(o.namespace), sshString(''), sshString(hashAlg), sshString(sig)]);
  return `-----BEGIN SSH SIGNATURE-----\n${blob.toString('base64').replace(/(.{70})/g, '$1\n').replace(/\n$/, '')}\n-----END SSH SIGNATURE-----\n`;
}

/** The allowed-signers line for an Ed25519 key (`principal namespaces="…" ssh-ed25519 AAAA…`). */
export function allowedSignerLine(principal: string, public_key: Buffer, namespace?: string): string {
  const blob = Buffer.concat([sshString(ED25519), sshString(public_key)]);
  return `${principal}${namespace ? ` namespaces="${namespace}"` : ''} ${ED25519} ${blob.toString('base64')}\n`;
}
