/**
 * Secret guard (0.6.0). Ported from IsoKron's sextant-scrub: two INDEPENDENT
 * deterministic rulesets, no LLM.
 *
 *  - Write time (`scanForSecrets` / `redactSecrets`): runs before anything is
 *    chained. High precision, so a refusal is worth reading: provider token
 *    shapes, private-key blocks with a body, connection strings and bearer
 *    headers with a real-looking credential, sensitive env assignments with a
 *    real-looking value. Obvious placeholders (`<password>`, `${VAR}`,
 *    `your-api-key`, AWS `…EXAMPLE` keys) pass.
 *  - Read time (`scrubForRead`): runs on text about to be served. Broader and
 *    written separately (it assumes the write ruleset has a bug), so it also
 *    catches what got in anyway: pre-0.6.0 data, `import --allow-secrets`.
 *
 * Why refuse instead of "tombstone it later": the chain is append-only and the
 * whole put is hashed into it. A tombstone hides a block from recall; the
 * secret stays in the events table, every export and every backup, and
 * removing it breaks verification by design (THREAT-MODEL.md).
 *
 * IsoKron's entropy detector and CLI grammars are deliberately not ported:
 * they were built for argv / telemetry, and on Markdown prose and code they
 * flag URLs and identifiers. Findings never carry the matched text.
 */

export type SecretPolicy = 'refuse' | 'redact' | 'allow';

export interface SecretFinding {
  /** Which input field (markdown, title, new_content, reason, or `seq N` on import). */
  field: string;
  detector: string;
  /** 1-based line of the match within the field. */
  line: number;
}

interface Detector {
  id: string;
  description: string;
  re: RegExp;
  /** Index of the capture group holding the credential; it must not look like a placeholder. */
  valueGroup?: number;
  /** Extra check on the whole match (e.g. requires a digit). */
  accept?: (match: string) => boolean;
}

const hasDigit = (s: string) => /[0-9]/.test(s);
const hasUpperAndDigit = (s: string) => /[A-Z]/.test(s) && /[0-9]/.test(s);
/** A value that is a literal credential rather than a reference, a number or an expression. */
const looksLikeCredential = (raw: string) => {
  const v = raw.trim().replace(/^['"]|['"]$/g, '');
  return /[0-9]/.test(v) && /[A-Za-z]/.test(v) && !/[().]|environ|getenv|^\$|^%|secrets?\./i.test(v);
};

/** Values documentation uses in place of a real credential. */
const PLACEHOLDER =
  /^(?:<[^>]*>|\$\{\{[^}]*\}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{[^}]*\}\}|%[A-Za-z_]+%|\*+|x+|X+|\.{3,}|…|password|passwd|pass|pwd|secret|changeme|example|placeholder|redacted|your[-_a-z]*|my[-_a-z]*|<redacted>|\[REDACTED[^\]]*\])$/i;

function isPlaceholder(v: string): boolean {
  const t = v.replace(/^['"]|['"]$/g, '');
  return PLACEHOLDER.test(t) || /example|placeholder|your[-_]|changeme|REDACTED/i.test(t);
}

/** Write-time ruleset (refuse / redact). Order matters: specific shapes before generic ones. */
export const WRITE_DETECTORS: readonly Detector[] = [
  {
    id: 'private_key',
    description: 'PEM / OpenSSH / PGP private key with a body',
    re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----\s*\n(?:[A-Za-z0-9+/=:\- ]*\n){0,8}?[A-Za-z0-9+/=]{40,}[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  { id: 'aws_access_key', description: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, accept: (m) => !m.includes('EXAMPLE') },
  {
    id: 'aws_secret_key',
    description: 'AWS secret access key in context',
    re: /\baws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi,
    valueGroup: 1,
  },
  { id: 'github_token', description: 'GitHub token (ghp_/gho_/ghu_/ghs_/ghr_, github_pat_)', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g },
  { id: 'gitlab_token', description: 'GitLab personal access token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'anthropic_key', description: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{24,}/g, accept: hasDigit },
  { id: 'openai_key', description: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, accept: (m) => !m.startsWith('sk-ant-') && hasUpperAndDigit(m) },
  { id: 'slack_token', description: 'Slack token', re: /\bxox[abeoprs]-[0-9A-Za-z-]{10,}/g, accept: hasDigit },
  { id: 'stripe_key', description: 'Stripe secret / restricted key', re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { id: 'google_api_key', description: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'npm_token', description: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'vault_token', description: 'HashiCorp Vault token', re: /\bhvs\.[A-Za-z0-9_-]{24,}/g },
  { id: 'doppler_token', description: 'Doppler token', re: /\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{32,}/g },
  { id: 'jwt', description: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}/g },
  {
    id: 'connection_string',
    description: 'URL with an embedded password (postgres://user:pass@…)',
    re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`<>]+:([^\s@/'"`]+)@[^\s'"`]+/gi,
    valueGroup: 1,
  },
  {
    id: 'bearer_token',
    description: 'Authorization: Bearer / Basic credential',
    re: /\b(?:Bearer|Basic)\s+([A-Za-z0-9_\-.~+/]{20,}=*)/g,
    valueGroup: 1,
    accept: (m) => hasDigit(m.replace(/^\S+\s+/, '')),
  },
  {
    id: 'env_secret',
    description: 'Sensitive env assignment (…PASSWORD=, …TOKEN=, …SECRET=, …API_KEY=) with a real-looking value',
    re: /^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*[ \t]*[:=][ \t]*(['"]?[^\s'"#]{8,}['"]?)/gm,
    valueGroup: 1,
    accept: (m) => looksLikeCredential(m.slice(m.search(/[:=]/) + 1)),
  },
  {
    id: 'config_secret',
    description: 'Sensitive config key (password: / secret = / api_key: …) with a real-looking value',
    re: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret)["']?[ \t]*[:=][ \t]*(['"]?[^\s'"#,;]{8,}['"]?)/gi,
    valueGroup: 1,
    accept: (m) => looksLikeCredential(m.slice(m.search(/[:=]/) + 1)),
  },
];

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

interface Match {
  detector: string;
  start: number;
  end: number;
}

function matchAll(text: string, detectors: readonly Detector[]): Match[] {
  const out: Match[] = [];
  for (const d of detectors) {
    d.re.lastIndex = 0;
    for (const m of text.matchAll(d.re)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      if (d.valueGroup !== undefined && isPlaceholder(m[d.valueGroup] ?? '')) continue;
      if (d.accept && !d.accept(m[0])) continue;
      // An earlier (more specific) detector already covers this span.
      if (out.some((o) => start < o.end && end > o.start)) continue;
      out.push({ detector: d.id, start, end });
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

/** Write-time scan. Returns one finding per match (field defaults to `text`); never the matched text. */
export function scanForSecrets(text: string, field = 'text'): SecretFinding[] {
  return matchAll(text, WRITE_DETECTORS).map((m) => ({ field, detector: m.detector, line: lineOf(text, m.start) }));
}

/** Replace every write-time match with `[REDACTED:<detector>]`. */
export function redactSecrets(text: string, field = 'text'): { text: string; findings: SecretFinding[] } {
  const matches = matchAll(text, WRITE_DETECTORS);
  if (matches.length === 0) return { text, findings: [] };
  let out = '';
  let pos = 0;
  for (const m of matches) {
    out += text.slice(pos, m.start) + `[REDACTED:${m.detector}]`;
    pos = m.end;
  }
  out += text.slice(pos);
  return { text: out, findings: matches.map((m) => ({ field, detector: m.detector, line: lineOf(text, m.start) })) };
}

export class SecretDetectedError extends Error {
  override readonly name = 'SecretDetectedError';
  readonly code = 'secret_detected' as const;
  constructor(
    readonly findings: SecretFinding[],
    what: string,
    overrideHint: string,
  ) {
    const list = findings
      .slice(0, 10)
      .map((f) => `${f.detector} (${f.field === 'text' ? '' : `${f.field} `}line ${f.line})`)
      .join(', ');
    super(
      `secret_detected: refusing to chain ${what}: ${list}${findings.length > 10 ? ` and ${findings.length - 10} more` : ''}. ` +
        `The chain is append-only: a tombstone hides a block but cannot erase a chained secret from the events, exports or backups. ` +
        `Remove it (use a reference such as \${ENV_VAR}), or ${overrideHint} to store a redacted copy.`,
    );
  }
}

/**
 * Apply a policy to the free-text fields of one write. `refuse` throws
 * SecretDetectedError (nothing has been chained yet); `redact` returns the
 * fields with every match replaced; `allow` passes them through (embedding
 * API only: tests and deliberate imports).
 */
export function guardFields<T extends Record<string, string>>(
  fields: T,
  policy: SecretPolicy,
  what: string,
  overrideHint = 'pass redact_secrets: true (CLI --redact-secrets)',
): { fields: T; redactions: SecretFinding[] } {
  if (policy === 'allow') return { fields, redactions: [] };
  const findings: SecretFinding[] = [];
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (policy === 'redact') {
      const r = redactSecrets(v, k);
      out[k] = r.text;
      findings.push(...r.findings);
    } else {
      out[k] = v;
      findings.push(...scanForSecrets(v, k));
    }
  }
  if (findings.length > 0 && policy === 'refuse') throw new SecretDetectedError(findings, what, overrideHint);
  return { fields: out as T, redactions: findings };
}

// ───────────────────────────── read time ─────────────────────────────

/**
 * Read-time ruleset: written separately from the write one and broader
 * (bare key armor lines, any URL userinfo password, shorter tokens). It masks;
 * it never refuses.
 */
const READ_RULES: readonly { id: string; re: RegExp; valueGroup?: number; needDigit?: boolean }[] = [
  { id: 'private_key_armor', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----)?/g },
  { id: 'aws_access_key_id', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g },
  { id: 'github_token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/g },
  { id: 'gitlab_token', re: /\bglpat-[A-Za-z0-9_-]{16,}/g },
  { id: 'api_key_sk', re: /\bsk-(?:ant-|proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}/g },
  { id: 'slack_token', re: /\bxox[abeoprs]-[0-9A-Za-z-]{8,}/g },
  { id: 'stripe_key', re: /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{12,}/g },
  { id: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{30,}/g },
  { id: 'npm_token', re: /\bnpm_[A-Za-z0-9]{30,}/g },
  { id: 'vault_token', re: /\bhvs\.[A-Za-z0-9_-]{16,}/g },
  { id: 'doppler_token', re: /\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{16,}/g },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { id: 'url_password', re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`<>]+:([^\s@/'"`]+)@/gi, valueGroup: 1 },
  { id: 'auth_header', re: /\b(?:Bearer|Basic|Token)\s+([A-Za-z0-9_\-.~+/]{16,}=*)/g, valueGroup: 1, needDigit: true },
  { id: 'npmrc_auth', re: /(?:_authToken|_password|_auth)\s*=\s*([^\s"']{8,})/g, valueGroup: 1, needDigit: true },
];

/** Mask read-time matches as `[REDACTED:read:<id>]`. `detectors` lists the rules that fired (deduplicated). */
export function scrubForRead(text: string): { text: string; detectors: string[] } {
  const fired = new Set<string>();
  let out = text;
  for (const r of READ_RULES) {
    r.re.lastIndex = 0;
    out = out.replace(r.re, (m: string, ...groups: unknown[]) => {
      if (r.valueGroup !== undefined) {
        const v = groups[r.valueGroup - 1];
        if (typeof v !== 'string' || isPlaceholder(v) || (r.needDigit === true && !/[0-9]/.test(v))) return m;
      }
      if (r.id === 'aws_access_key_id' && m.includes('EXAMPLE')) return m;
      fired.add(r.id);
      return `[REDACTED:read:${r.id}]`;
    });
  }
  return { text: out, detectors: [...fired] };
}

/** Deep read-time scrub of every string in a JSON-like value. */
export function scrubDeep<T>(value: T, fired: Set<string> = new Set()): { value: T; detectors: string[] } {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const r = scrubForRead(v);
      for (const d of r.detectors) fired.add(d);
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return { value: walk(value) as T, detectors: [...fired] };
}

/** Write-time scan of every string in a JSON-like value; `field` is `<prefix>.<path>`. */
export function scanValue(value: unknown, prefix: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const walk = (v: unknown, path: string) => {
    if (typeof v === 'string') out.push(...scanForSecrets(v, path));
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
    else if (v !== null && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
  };
  walk(value, prefix);
  return out;
}
