/** TSA root certificate files (moved from package.ts so the verify-audit CLI does not load the packaging code). */

import { readdirSync } from 'node:fs';

/** The certificate files of a TSA roots directory (*.pem, *.crt), sorted. */
export const pemFileNames = (dir: string): string[] => readdirSync(dir).filter((f) => /\.(pem|crt)$/i.test(f)).sort();

/** The PEM certificates in one file's text, named after the file (one TSA per file). */
export function pemsFromText(file: string, text: string): { name: string; pem: string }[] {
  const name = file.replace(/\.(pem|crt)$/i, '');
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)].map((m) => ({ name, pem: m[0] + '\n' }));
}
