/**
 * A throwaway RFC 3161 timestamp authority for tests: a root CA and a TSA
 * signing certificate (ECDSA P-256), built with the DER writer in
 * src/audit/der.ts, and tokens over any bytes. `serveTsa` answers
 * application/timestamp-query POSTs like Sectigo / DigiCert do.
 * Nothing here is used outside tests; the keys live in memory only.
 */

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { createServer } from 'node:http';

import { children, derBits, derGeneralizedTime, derInt, derOctets, derOid, derSeq, derSet, derUtf8, derX509Time, der, derBool, parseDer, readOid, integerBytes, TAG, ctx } from '../../src/audit/der.js';
import { OID } from '../../src/audit/rfc3161.js';

const ecdsaAlg = () => derSeq(derOid(OID.ecdsaSha256));
const name = (cn: string) => derSeq(derSet(derSeq(derOid('2.5.4.3'), derUtf8(cn))));
const ext = (oid: string, critical: boolean, value: Buffer) => derSeq(derOid(oid), ...(critical ? [derBool(true)] : []), derOctets(value));

export interface TestCert {
  der: Buffer;
  pem: string;
  key: KeyObject;
  subject: Buffer;
  serial: Buffer;
}

let serialCounter = 1000;

export function makeCert(o: {
  cn: string;
  issuer?: TestCert;
  ca?: boolean;
  timeStamping?: boolean;
  notBefore?: Date;
  notAfter?: Date;
}): TestCert {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const subject = name(o.cn);
  const serial = Buffer.from((serialCounter++).toString(16).padStart(8, '0'), 'hex');
  const exts: Buffer[] = [];
  if (o.ca) exts.push(ext('2.5.29.19', true, derSeq(derBool(true))));
  else exts.push(ext('2.5.29.19', true, derSeq()));
  if (o.timeStamping) exts.push(ext('2.5.29.37', true, derSeq(derOid(OID.timeStamping))));
  const tbs = derSeq(
    der(ctx(0), derInt(2)),
    derInt(serial),
    ecdsaAlg(),
    o.issuer ? o.issuer.subject : subject,
    derSeq(derX509Time(o.notBefore ?? new Date('2020-01-01T00:00:00Z')), derX509Time(o.notAfter ?? new Date('2090-01-01T00:00:00Z'))),
    subject,
    spki,
    der(ctx(3), derSeq(...exts)),
  );
  const sig = sign('sha256', tbs, o.issuer ? o.issuer.key : privateKey);
  const certDer = derSeq(tbs, ecdsaAlg(), derBits(sig));
  const pem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
  return { der: certDer, pem, key: privateKey, subject, serial };
}

export interface TestTsa {
  root: TestCert;
  signer: TestCert;
  /** A TimeStampResp over `message` (or over a given sha256 digest). */
  stamp(message: Buffer | string, o?: { genTime?: Date; nonce?: Buffer; digest?: Buffer; noEss?: boolean }): Buffer;
}

export function makeTsa(o: { name?: string; signerNotAfter?: Date; signerNotBefore?: Date; timeStamping?: boolean } = {}): TestTsa {
  const root = makeCert({ cn: `${o.name ?? 'Test'} TSA Root`, ca: true });
  const signer = makeCert({
    cn: `${o.name ?? 'Test'} TSA Signer`,
    issuer: root,
    timeStamping: o.timeStamping ?? true,
    ...(o.signerNotBefore ? { notBefore: o.signerNotBefore } : {}),
    ...(o.signerNotAfter ? { notAfter: o.signerNotAfter } : {}),
  });
  return {
    root,
    signer,
    stamp(message, s = {}) {
      const digest = s.digest ?? createHash('sha256').update(typeof message === 'string' ? Buffer.from(message, 'utf8') : message).digest();
      const tstInfo = derSeq(
        derInt(1),
        derOid('1.3.6.1.4.1.99999.1'),
        derSeq(derSeq(derOid(OID.sha256)), derOctets(digest)),
        derInt(serialCounter++),
        derGeneralizedTime(s.genTime ?? new Date()),
        ...(s.nonce ? [derInt(s.nonce)] : []),
      );
      const attrs = [
        derSeq(derOid(OID.contentType), derSet(derOid(OID.tstInfo))),
        derSeq(derOid(OID.messageDigest), derSet(derOctets(createHash('sha256').update(tstInfo).digest()))),
        ...(s.noEss ? [] : [derSeq(derOid(OID.signingCertificateV2), derSet(derSeq(derSeq(derSeq(derOctets(createHash('sha256').update(signer.der).digest()))))))]),
      ];
      const signedAttrsSet = derSet(...attrs);
      const sig = sign('sha256', signedAttrsSet, signer.key);
      const signerInfo = derSeq(
        derInt(1),
        derSeq(root.subject, derInt(signer.serial)),
        derSeq(derOid(OID.sha256)),
        der(ctx(0), ...attrs),
        ecdsaAlg(),
        derOctets(sig),
      );
      const signedData = derSeq(derInt(3), derSet(derSeq(derOid(OID.sha256))), derSeq(derOid(OID.tstInfo), der(ctx(0), derOctets(tstInfo))), der(ctx(0), signer.der, root.der), derSet(signerInfo));
      const token = derSeq(derOid(OID.signedData), der(ctx(0), signedData));
      return derSeq(derSeq(derInt(0)), token);
    },
  };
}

/** Parse a TimeStampReq: its sha256 digest and nonce. */
function parseRequest(body: Buffer): { digest: Buffer; nonce: Buffer | undefined } {
  const k = children(parseDer(body));
  const mi = children(k[1]!);
  const nonceT = k.slice(2).find((t) => t.tag === TAG.INTEGER);
  if (readOid(children(mi[0]!)[0]!) !== OID.sha256) throw new Error('test TSA: sha256 only');
  return { digest: Buffer.from(mi[1]!.value), nonce: nonceT ? Buffer.from(integerBytes(nonceT)) : undefined };
}

/** HTTP TSA on 127.0.0.1. `mode` lets a test break replies. */
export async function serveTsa(tsa: TestTsa, mode: { reply?: 'ok' | 'wrong-nonce' | 'rejected' | 'http-500' } = {}): Promise<{ url: string; requests: number; stop(): Promise<void> }> {
  const state = { requests: 0 };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      state.requests++;
      if (mode.reply === 'http-500') {
        res.writeHead(500).end();
        return;
      }
      if (mode.reply === 'rejected') {
        res.writeHead(200, { 'content-type': 'application/timestamp-reply' }).end(derSeq(derSeq(derInt(2))));
        return;
      }
      const { digest, nonce } = parseRequest(Buffer.concat(chunks));
      const n = mode.reply === 'wrong-nonce' ? Buffer.from('01020304', 'hex') : nonce;
      res.writeHead(200, { 'content-type': 'application/timestamp-reply' }).end(tsa.stamp('', { digest, ...(n ? { nonce: n } : {}) }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}/`,
    get requests() {
      return state.requests;
    },
    stop: () => new Promise<void>((r) => server.close(() => r())),
  };
}
