/**
 * RFC 3161 timestamp tokens, verified in-process with node:crypto (no
 * openssl, no dependency). Used by `verify-audit` (each anchor receipt's
 * sha256 is stamped by independent timestamp authorities) and by
 * `audit stamp` (build a request, check the reply).
 *
 * A token verifies when, at the check time:
 *   1. the reply status is granted (or grantedWithMods) and carries a token;
 *   2. the token is CMS SignedData over id-ct-TSTInfo with exactly one signer;
 *   3. TSTInfo.messageImprint is the hash of the stamped bytes;
 *   4. the signed attributes carry contentType = id-ct-TSTInfo, messageDigest
 *      = hash(TSTInfo), and an ESS signing-certificate (v1 or v2) naming the
 *      signer certificate; the signature over the signed attributes verifies
 *      with the signer certificate's key (RSA PKCS#1 v1.5, RSA-PSS, ECDSA or
 *      Ed25519; SHA-1 refused);
 *   5. the signer certificate has the timeStamping extended key usage and was
 *      valid at genTime;
 *   6. a path exists from the signer, through CA certificates embedded in the
 *      token, to one of the trusted roots, every certificate valid at the
 *      check time (now by default, or genTime).
 *
 * Path building prefers the trusted roots: at each step it first asks whether
 * a trusted root issued the current certificate, and only then looks at the
 * certificates the token embeds. DigiCert tokens embed "DigiCert Trusted Root
 * G4" cross-signed by the retired "Assured ID Root CA"; OpenSSL with a full
 * system bundle follows that cross-certificate and fails with "unable to get
 * local issuer". Here the G4 intermediate's issuer is found among the trusted
 * roots first, so the cross-certificate is never used.
 *
 * Not checked: revocation (CRL/OCSP need the network; verification is
 * offline), TSA policy OIDs, and the accuracy field (genTime is reported as
 * is).
 */

import { createHash, randomBytes, verify as cryptoVerify, X509Certificate, constants as cryptoConstants, type KeyObject } from 'node:crypto';

import {
  children,
  DerError,
  derBool,
  derInt,
  derNull,
  derOctets,
  derOid,
  derSeq,
  expect,
  integerBytes,
  parseDer,
  readOid,
  readSmallInt,
  readTime,
  TAG,
  ctx,
  type Tlv,
} from './der.js';

export const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaPss: '1.2.840.113549.1.1.10',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  ed25519: '1.3.101.112',
} as const;

const HASHES: Record<string, 'sha1' | 'sha256' | 'sha384' | 'sha512'> = {
  [OID.sha1]: 'sha1',
  [OID.sha256]: 'sha256',
  [OID.sha384]: 'sha384',
  [OID.sha512]: 'sha512',
};

/** Largest timestamp reply read from disk or the network (real ones are 5-8 KB). */
export const MAX_TSR_BYTES = 256 * 1024;
/** Longest certificate path accepted (signer + intermediates + root). */
const MAX_PATH = 8;

export interface TimestampInfo {
  /** genTime, ISO 8601. */
  gen_time: string;
  hash_algorithm: string;
  /** messageImprint.hashedMessage, hex. */
  imprint: string;
  serial: string;
  policy: string;
  /** TSTInfo nonce, hex, when present. */
  nonce: string | null;
}

export interface TimestampVerification {
  ok: boolean;
  problem: string | null;
  info: TimestampInfo | null;
  /** Subject common name (or full subject) of the signing certificate. */
  signer: string | null;
  /** The trusted root the path ended at. */
  root: string | null;
  /** SHA-256 fingerprint of that root (hex, lowercase). */
  root_sha256: string | null;
  /** The time certificate validity was checked at, ISO 8601. */
  checked_at: string | null;
}

export interface VerifyTimestampOptions {
  /** The bytes that were stamped (the imprint is recomputed with the token's hash algorithm). */
  message: Buffer | string;
  /** Trusted TSA roots (PEM or X509Certificate). */
  roots: readonly (string | X509Certificate)[];
  /** Certificate validity is checked at this time: now (default), genTime, or a given Date. */
  at?: 'now' | 'gentime' | Date;
  /** Clock for 'now' (tests). */
  now?: Date;
}

const cn = (c: X509Certificate): string => c.subject.split('\n').find((l) => l.startsWith('CN='))?.slice(3) ?? c.subject.replace(/\n/g, ', ');
const fingerprint256 = (c: X509Certificate): string => c.fingerprint256.replace(/:/g, '').toLowerCase();

function algOid(t: Tlv | undefined, what: string): { oid: string; params: Tlv | undefined } {
  const k = children(expect(t, TAG.SEQUENCE, what));
  return { oid: readOid(expect(k[0], TAG.OID, `${what} algorithm`)), params: k[1] };
}

function hashName(oid: string, what: string): 'sha1' | 'sha256' | 'sha384' | 'sha512' {
  const h = HASHES[oid];
  if (!h) throw new DerError(`${what}: unsupported hash algorithm ${oid}`);
  return h;
}

/** The TimeStampToken (ContentInfo) of a TimeStampResp, or the input when it already is a token. */
function tokenOf(top: Tlv): Tlv {
  const k = children(expect(top, TAG.SEQUENCE, 'timestamp reply'));
  // A bare token is a ContentInfo: SEQUENCE { OID, [0] … }.
  if (k[0]?.tag === TAG.OID) return top;
  const status = children(expect(k[0], TAG.SEQUENCE, 'PKIStatusInfo'));
  const s = readSmallInt(expect(status[0], TAG.INTEGER, 'PKIStatus'));
  if (s !== 0 && s !== 1) throw new DerError(`the TSA did not grant the request (PKIStatus ${s})`);
  return expect(k[1], TAG.SEQUENCE, 'timeStampToken');
}

interface ParsedToken {
  tstInfoDer: Buffer;
  info: TimestampInfo;
  genTime: Date;
  imprintAlg: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  certs: { cert: X509Certificate; der: Buffer; issuer: Buffer; serial: Buffer; ski: Buffer | null }[];
  signer: {
    sid: { issuer: Buffer; serial: Buffer } | { ski: Buffer };
    digestAlg: 'sha1' | 'sha256' | 'sha384' | 'sha512';
    signedAttrs: Tlv;
    sigAlg: { oid: string; params: Tlv | undefined };
    signature: Buffer;
  };
}

/** issuer Name DER, serial and subjectKeyIdentifier of a certificate (TBSCertificate fields). */
function certIds(certDer: Buffer): { issuer: Buffer; serial: Buffer; ski: Buffer | null } {
  const tbs = children(expect(children(parseDer(certDer))[0], TAG.SEQUENCE, 'TBSCertificate'));
  let i = tbs[0]?.tag === ctx(0) ? 1 : 0; // [0] version
  const serial = integerBytes(expect(tbs[i++], TAG.INTEGER, 'certificate serial'));
  i++; // signature AlgorithmIdentifier
  const issuer = expect(tbs[i], TAG.SEQUENCE, 'certificate issuer').bytes;
  let ski: Buffer | null = null;
  const ext = tbs.find((t) => t.tag === ctx(3));
  if (ext) {
    for (const e of children(expect(children(ext)[0], TAG.SEQUENCE, 'extensions'))) {
      const f = children(e);
      if (readOid(f[0]!) === '2.5.29.14') {
        const os = f[f.length - 1]!;
        ski = Buffer.from(expect(parseDer(Buffer.from(os.value)), TAG.OCTET_STRING, 'subjectKeyIdentifier').value);
      }
    }
  }
  return { issuer: Buffer.from(issuer), serial: Buffer.from(serial), ski };
}

function parseToken(token: Tlv): ParsedToken {
  const ci = children(token);
  if (readOid(expect(ci[0], TAG.OID, 'contentType')) !== OID.signedData) throw new DerError('the token is not CMS SignedData');
  const sd = children(expect(children(expect(ci[1], ctx(0), 'SignedData wrapper'))[0], TAG.SEQUENCE, 'SignedData'));
  let i = 0;
  expect(sd[i++], TAG.INTEGER, 'SignedData version');
  expect(sd[i++], TAG.SET, 'digestAlgorithms');
  const eci = children(expect(sd[i++], TAG.SEQUENCE, 'encapContentInfo'));
  if (readOid(expect(eci[0], TAG.OID, 'eContentType')) !== OID.tstInfo) throw new DerError('the signed content is not a TSTInfo');
  const eContent = expect(children(expect(eci[1], ctx(0), 'eContent wrapper'))[0], TAG.OCTET_STRING, 'eContent');
  const tstInfoDer = Buffer.from(eContent.value);
  const certs: ParsedToken['certs'] = [];
  if (sd[i]?.tag === ctx(0)) {
    for (const c of children(sd[i++]!)) {
      if (c.tag !== TAG.SEQUENCE) continue; // other CertificateChoices (attribute certificates) are not used
      const derBytes = Buffer.from(c.bytes);
      certs.push({ cert: new X509Certificate(derBytes), der: derBytes, ...certIds(derBytes) });
    }
  }
  if (sd[i]?.tag === ctx(1)) i++; // crls
  const signerInfos = children(expect(sd[i], TAG.SET, 'signerInfos'));
  if (signerInfos.length !== 1) throw new DerError(`the token has ${signerInfos.length} signers; RFC 3161 requires exactly one`);
  const si = children(expect(signerInfos[0], TAG.SEQUENCE, 'SignerInfo'));
  let j = 1; // version
  const sidT = si[j++]!;
  let sid: ParsedToken['signer']['sid'];
  if (sidT.tag === TAG.SEQUENCE) {
    const s = children(sidT);
    sid = { issuer: Buffer.from(expect(s[0], TAG.SEQUENCE, 'sid issuer').bytes), serial: Buffer.from(integerBytes(expect(s[1], TAG.INTEGER, 'sid serial'))) };
  } else if (sidT.tag === 0x80) {
    sid = { ski: Buffer.from(sidT.value) };
  } else throw new DerError('SignerInfo.sid is neither issuerAndSerialNumber nor subjectKeyIdentifier');
  const digestAlg = hashName(algOid(si[j++], 'SignerInfo.digestAlgorithm').oid, 'SignerInfo.digestAlgorithm');
  const signedAttrs = expect(si[j++], ctx(0), 'signedAttrs');
  const sigAlg = algOid(si[j++], 'SignerInfo.signatureAlgorithm');
  const signature = Buffer.from(expect(si[j++], TAG.OCTET_STRING, 'signature').value);

  // TSTInfo
  const t = children(expect(parseDer(tstInfoDer), TAG.SEQUENCE, 'TSTInfo'));
  let k = 1; // version
  const policy = readOid(expect(t[k++], TAG.OID, 'TSTInfo.policy'));
  const mi = children(expect(t[k++], TAG.SEQUENCE, 'messageImprint'));
  const imprintAlg = hashName(algOid(mi[0], 'messageImprint.hashAlgorithm').oid, 'messageImprint');
  const imprint = Buffer.from(expect(mi[1], TAG.OCTET_STRING, 'messageImprint.hashedMessage').value);
  const serial = integerBytes(expect(t[k++], TAG.INTEGER, 'TSTInfo.serialNumber'));
  const genTime = readTime(expect(t[k++], TAG.GENERALIZED_TIME, 'TSTInfo.genTime'));
  let nonce: string | null = null;
  for (; k < t.length; k++) if (t[k]!.tag === TAG.INTEGER) nonce = integerBytes(t[k]!).toString('hex');
  return {
    tstInfoDer,
    genTime,
    imprintAlg,
    info: { gen_time: genTime.toISOString(), hash_algorithm: imprintAlg, imprint: imprint.toString('hex'), serial: serial.toString('hex'), policy, nonce },
    certs,
    signer: { sid, digestAlg, signedAttrs, sigAlg, signature },
  };
}

/** Parse a reply (or bare token) without verifying anything: genTime, imprint, nonce. Throws DerError. */
export function inspectTimestamp(der: Buffer): TimestampInfo {
  return parseToken(tokenOf(parseDer(der))).info;
}

function verifySignedAttrs(p: ParsedToken, key: KeyObject): void {
  const attrs = new Map<string, Tlv[]>();
  for (const a of children(p.signer.signedAttrs)) {
    const f = children(expect(a, TAG.SEQUENCE, 'signed attribute'));
    const oid = readOid(expect(f[0], TAG.OID, 'attribute type'));
    if (attrs.has(oid)) throw new DerError(`signed attribute ${oid} appears twice`);
    attrs.set(oid, children(expect(f[1], TAG.SET, `attribute ${oid} values`)));
  }
  const ct = attrs.get(OID.contentType)?.[0];
  if (!ct || readOid(ct) !== OID.tstInfo) throw new DerError('signed contentType is not id-ct-TSTInfo');
  const md = attrs.get(OID.messageDigest)?.[0];
  if (!md || md.tag !== TAG.OCTET_STRING) throw new DerError('signed attributes lack messageDigest');
  if (!createHash(p.signer.digestAlg).update(p.tstInfoDer).digest().equals(md.value)) throw new DerError('messageDigest does not match the TSTInfo (the token content was altered)');

  const toVerify = Buffer.from(p.signer.signedAttrs.bytes);
  toVerify[0] = TAG.SET; // the signature covers the attributes as a SET OF (RFC 5652 §5.4)
  const { oid, params } = p.signer.sigAlg;
  let ok: boolean;
  const sig = p.signer.signature;
  const rsaHash: Record<string, string> = { [OID.sha256WithRSA]: 'sha256', [OID.sha384WithRSA]: 'sha384', [OID.sha512WithRSA]: 'sha512' };
  const ecHash: Record<string, string> = { [OID.ecdsaSha256]: 'sha256', [OID.ecdsaSha384]: 'sha384', [OID.ecdsaSha512]: 'sha512' };
  if (oid === OID.ed25519) {
    ok = cryptoVerify(null, toVerify, key, sig);
  } else if (oid === OID.rsaEncryption || rsaHash[oid]) {
    const h = rsaHash[oid] ?? p.signer.digestAlg;
    if (h === 'sha1') throw new DerError('SHA-1 signatures are not accepted');
    ok = cryptoVerify(h, toVerify, { key, padding: cryptoConstants.RSA_PKCS1_PADDING }, sig);
  } else if (oid === OID.rsaPss) {
    let h = 'sha1';
    let salt = 20;
    for (const f of params && params.tag === TAG.SEQUENCE ? children(params) : []) {
      if (f.tag === ctx(0)) h = hashName(algOid(children(f)[0], 'PSS hashAlgorithm').oid, 'PSS hashAlgorithm');
      if (f.tag === ctx(2)) salt = readSmallInt(expect(children(f)[0], TAG.INTEGER, 'PSS saltLength'));
    }
    if (h === 'sha1') throw new DerError('SHA-1 signatures are not accepted');
    ok = cryptoVerify(h, toVerify, { key, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: salt }, sig);
  } else if (ecHash[oid] || oid === OID.ecPublicKey) {
    const h = ecHash[oid] ?? p.signer.digestAlg;
    if (h === 'sha1') throw new DerError('SHA-1 signatures are not accepted');
    ok = cryptoVerify(h, toVerify, key, sig);
  } else {
    throw new DerError(`unsupported signature algorithm ${oid}`);
  }
  if (!ok) throw new DerError('the TSA signature does not verify');
}

function essCertHash(p: ParsedToken): { alg: 'sha1' | 'sha256' | 'sha384' | 'sha512'; hash: Buffer } {
  const attrs = new Map<string, Tlv>();
  for (const a of children(p.signer.signedAttrs)) {
    const f = children(a);
    const v = children(f[1]!)[0];
    if (v) attrs.set(readOid(f[0]!), v);
  }
  const v2 = attrs.get(OID.signingCertificateV2);
  if (v2) {
    const first = children(expect(children(expect(v2, TAG.SEQUENCE, 'SigningCertificateV2'))[0], TAG.SEQUENCE, 'certs'))[0];
    const id = children(expect(first, TAG.SEQUENCE, 'ESSCertIDv2'));
    if (id[0]?.tag === TAG.SEQUENCE) return { alg: hashName(algOid(id[0], 'ESSCertIDv2.hashAlgorithm').oid, 'ESSCertIDv2'), hash: Buffer.from(expect(id[1], TAG.OCTET_STRING, 'certHash').value) };
    return { alg: 'sha256', hash: Buffer.from(expect(id[0], TAG.OCTET_STRING, 'certHash').value) };
  }
  const v1 = attrs.get(OID.signingCertificate);
  if (v1) {
    const first = children(expect(children(expect(v1, TAG.SEQUENCE, 'SigningCertificate'))[0], TAG.SEQUENCE, 'certs'))[0];
    return { alg: 'sha1', hash: Buffer.from(expect(children(expect(first, TAG.SEQUENCE, 'ESSCertID'))[0], TAG.OCTET_STRING, 'certHash').value) };
  }
  throw new DerError('signed attributes carry no ESS signing-certificate (RFC 3161 §2.4.1)');
}

const validAt = (c: X509Certificate, t: Date): boolean => Date.parse(c.validFrom) <= t.getTime() && t.getTime() <= Date.parse(c.validTo);
const extKeyUsage = (c: X509Certificate): string[] => ((c as unknown as { extKeyUsage?: string[] }).extKeyUsage ?? c.keyUsage ?? []) as string[];
const issuedBy = (child: X509Certificate, parent: X509Certificate): boolean => {
  try {
    return child.checkIssued(parent) && child.verify(parent.publicKey);
  } catch {
    return false;
  }
};

export function verifyTimestamp(der: Buffer, opts: VerifyTimestampOptions): TimestampVerification {
  const out: TimestampVerification = { ok: false, problem: null, info: null, signer: null, root: null, root_sha256: null, checked_at: null };
  try {
    if (der.length > MAX_TSR_BYTES) throw new DerError(`timestamp reply is ${der.length} bytes; the limit is ${MAX_TSR_BYTES}`);
    const p = parseToken(tokenOf(parseDer(der)));
    out.info = p.info;
    const message = typeof opts.message === 'string' ? Buffer.from(opts.message, 'utf8') : opts.message;
    if (createHash(p.imprintAlg).update(message).digest('hex') !== p.info.imprint) throw new DerError('messageImprint is not the hash of the stamped bytes');
    if (p.imprintAlg === 'sha1') throw new DerError('a SHA-1 messageImprint is not accepted');

    const sid = p.signer.sid;
    const signer = p.certs.find((c) => ('ski' in sid ? c.ski !== null && c.ski.equals(sid.ski) : c.issuer.equals(sid.issuer) && c.serial.equals(sid.serial)));
    if (!signer) throw new DerError('the token does not embed its signing certificate (request it with certReq)');
    out.signer = cn(signer.cert);
    verifySignedAttrs(p, signer.cert.publicKey);
    const ess = essCertHash(p);
    if (!createHash(ess.alg).update(signer.der).digest().equals(ess.hash)) throw new DerError('the ESS signing-certificate does not name the signing certificate');
    if (!extKeyUsage(signer.cert).includes(OID.timeStamping)) throw new DerError(`signing certificate ${out.signer} lacks the timeStamping extended key usage`);
    if (!validAt(signer.cert, p.genTime)) throw new DerError(`genTime ${p.info.gen_time} is outside the signing certificate's validity (${signer.cert.validFrom} to ${signer.cert.validTo})`);

    const at = opts.at instanceof Date ? opts.at : opts.at === 'gentime' ? p.genTime : (opts.now ?? new Date());
    out.checked_at = at.toISOString();
    const roots = opts.roots.map((r) => (typeof r === 'string' ? new X509Certificate(r) : r));
    if (roots.length === 0) throw new DerError('no trusted TSA roots');
    const path: X509Certificate[] = [signer.cert];
    let anchor: X509Certificate | null = null;
    for (let cur = signer.cert; path.length <= MAX_PATH; ) {
      const same = roots.find((r) => r.raw.equals(cur.raw));
      if (same) {
        anchor = same;
        path.pop();
        break;
      }
      const byRoot = roots.find((r) => issuedBy(cur, r));
      if (byRoot) {
        anchor = byRoot;
        break;
      }
      const next = p.certs.find((c) => c.cert.ca && !path.some((x) => x.raw.equals(c.cert.raw)) && issuedBy(cur, c.cert));
      if (!next) break;
      path.push(next.cert);
      cur = next.cert;
    }
    if (!anchor) throw new DerError(`signing certificate ${out.signer} does not chain to a trusted TSA root`);
    out.root = cn(anchor);
    out.root_sha256 = fingerprint256(anchor);
    for (const c of [...path, anchor]) {
      if (!validAt(c, at)) throw new DerError(`certificate ${cn(c)} is not valid at ${at.toISOString()} (valid ${c.validFrom} to ${c.validTo})`);
    }
    for (const c of path.slice(1)) if (!c.ca) throw new DerError(`intermediate ${cn(c)} is not a CA certificate`);
    out.ok = true;
  } catch (err) {
    out.problem = err instanceof Error ? err.message : String(err);
  }
  return out;
}

// ───────────────────────────── requests ─────────────────────────────

/** A TimeStampReq (DER) over sha256(message) with a fresh nonce and certReq, plus the nonce (hex). */
export function timestampRequest(message: Buffer | string): { der: Buffer; nonce: string; digest: string } {
  const digest = createHash('sha256').update(typeof message === 'string' ? Buffer.from(message, 'utf8') : message).digest();
  const nonce = randomBytes(8);
  nonce[0] = nonce[0]! & 0x7f || 0x01; // positive, minimal
  const der = derSeq(derInt(1), derSeq(derSeq(derOid(OID.sha256), derNull()), derOctets(digest)), derInt(nonce), derBool(true));
  return { der, nonce: nonce.toString('hex'), digest: digest.toString('hex') };
}

/** Check a TSA reply against the request it answers: granted, same imprint, same nonce. Returns its info. */
export function checkTimestampReply(reply: Buffer, req: { nonce: string; digest: string }): TimestampInfo {
  if (reply.length > MAX_TSR_BYTES) throw new DerError(`timestamp reply is ${reply.length} bytes; the limit is ${MAX_TSR_BYTES}`);
  const info = inspectTimestamp(reply);
  if (info.imprint !== req.digest) throw new DerError('the reply stamps a different digest than requested');
  if (info.nonce !== req.nonce) throw new DerError('the reply nonce does not match the request');
  return info;
}

/** SHA-256 fingerprint (hex, lowercase) of a PEM certificate. */
export function certificateFingerprint(pem: string): string {
  return fingerprint256(new X509Certificate(pem));
}
