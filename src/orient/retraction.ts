/**
 * Retraction classifier: which events since the cursor mean "something you
 * may have relied on is now wrong" — corrections, not just news.
 *
 * Precedence: explicit map → suffix rule → not a retraction. The suffix rule
 * (.tombstoned / .superseded / .retracted) catches event types added later
 * without a code change. Pure function: same events (and block texts) in,
 * same list out.
 *
 * Severity: safety (object is invalid for future reads) > behavioral (an
 * authoritative position changed) > informational.
 */

import type { ChainEvent } from '../chain/index.js';
import { isInstructionSlug } from '../docs/documents.js';
import { snippet, wordDiff } from './textdiff.js';

export type RetractionSeverity = 'safety' | 'behavioral' | 'informational';
/**
 * `instruction` (0.4.0, additive): a supersession or tombstone of a block in
 * an instruction document (slug under `instructions/` or `memory/`): a
 * CLAUDE.md, AGENTS.md, rule file or auto-memory index changed on disk and
 * was re-imported. Severity follows the underlying event.
 */
export type RetractionKind = 'tombstone' | 'supersession' | 'retraction' | 'instruction';
export const RETRACTION_KINDS = ['tombstone', 'supersession', 'retraction', 'instruction'] as const;

export interface Retraction {
  seq: number;
  event_type: string;
  kind: RetractionKind;
  severity: RetractionSeverity;
  block_id: string | null;
  doc_slug: string | null;
  successor_block_id: string | null;
  reason: string | null;
  /** "You previously relied on X; current truth is Y. Reconcile before proceeding." */
  reason_line: string;
  /**
   * 0.5.0, additive: the words that changed, when the store still has the
   * blocks. `old_text` / `new_text` are bounded snippets (≤ 160 chars),
   * `diff` a word diff (`[-old-]{+new+}`, ≤ 400 chars); `new_text` and
   * `diff` are null for a removal. All null for events without block text.
   */
  heading_path: string[] | null;
  old_text: string | null;
  new_text: string | null;
  diff: string | null;
}

/** Block text for a retraction, from the projection (orient passes one in). */
export interface BlockText {
  content: string;
  heading_path: string[];
}
export type BlockTextLookup = (block_id: string) => BlockText | null;

const EXPLICIT: Readonly<Record<string, { kind: RetractionKind; severity: RetractionSeverity }>> = Object.freeze({
  'block.tombstoned': { kind: 'tombstone', severity: 'safety' },
  'document.tombstoned': { kind: 'tombstone', severity: 'safety' },
  'block.superseded': { kind: 'supersession', severity: 'behavioral' },
});

const SUFFIX_RULES: ReadonlyArray<{ suffix: string; kind: RetractionKind; severity: RetractionSeverity }> =
  Object.freeze([
    { suffix: '.tombstoned', kind: 'tombstone', severity: 'safety' },
    { suffix: '.superseded', kind: 'supersession', severity: 'behavioral' },
    { suffix: '.retracted', kind: 'retraction', severity: 'behavioral' },
  ]);

const SEVERITY_ORDER: Record<RetractionSeverity, number> = { safety: 0, behavioral: 1, informational: 2 };

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export function buildReasonLine(asserted: string, current_truth: string): string {
  return `You previously relied on "${asserted}"; current truth is "${current_truth}". Reconcile before proceeding.`;
}

function where(doc_slug: string | null, heading_path: string[] | null): string {
  const hp = heading_path && heading_path.length > 0 ? ` › ${heading_path.join(' › ')}` : '';
  return doc_slug ? ` (${doc_slug}${hp})` : hp ? ` (${hp.slice(3)})` : '';
}

export function classifyRetraction(ev: ChainEvent, lookup?: BlockTextLookup): Retraction | null {
  const rule = EXPLICIT[ev.event_type] ?? SUFFIX_RULES.find((r) => ev.event_type.endsWith(r.suffix)) ?? null;
  if (!rule) return null;
  const p = ev.payload;
  const block_id = str(p['block_id']) ?? str(p['id']) ?? str(p['target_id']);
  const doc_slug = str(p['doc_slug']) ?? str(p['slug']);
  const successor_block_id = str(p['successor_block_id']);
  const reason = str(p['reason']);
  const oldB = block_id && lookup ? lookup(block_id) : null;
  const newB = successor_block_id && lookup ? lookup(successor_block_id) : null;
  const text = {
    heading_path: oldB?.heading_path ?? newB?.heading_path ?? null,
    old_text: oldB ? snippet(oldB.content) : null,
    new_text: oldB && newB ? snippet(newB.content) : null,
    diff: oldB && newB ? wordDiff(oldB.content, newB.content) : null,
  };
  const base = { seq: ev.seq, event_type: ev.event_type, block_id, doc_slug, successor_block_id, reason, ...text };
  const instruction = isInstructionSlug(doc_slug) && rule.kind !== 'retraction';
  // With the words in hand, say them: "you relied on <old>; it is now <new>".
  if (oldB && (rule.kind === 'tombstone' || (rule.kind === 'supersession' && newB))) {
    const loc = where(doc_slug, text.heading_path);
    // Auto-generated put reasons ("replaced in revision 3") add nothing to the words.
    const why = reason && !/^(replaced|removed) in revision \d+$/.test(reason) ? reason : null;
    const asserted = `${instruction ? 'instruction ' : ''}"${text.old_text}"${loc}`;
    let truth: string;
    if (rule.kind === 'supersession') {
      truth = `"${text.new_text}" (seq ${ev.seq}${why ? `, ${why}` : ''})${instruction ? '; follow the new text' : ''}`;
    } else {
      truth = instruction
        ? `REMOVED from ${doc_slug} at seq ${ev.seq}${why ? ` (${why})` : ''}; stop following it`
        : `TOMBSTONED at seq ${ev.seq}${why ? ` (${why})` : ''}; do not read or build on it`;
    }
    return {
      ...base,
      kind: instruction ? 'instruction' : rule.kind,
      severity: rule.severity,
      reason_line: `You previously relied on ${asserted}; current truth is ${truth}. Reconcile before proceeding.`,
    };
  }
  return { ...base, ...classifyBare(ev, rule, block_id, doc_slug, successor_block_id, reason) };
}

function classifyBare(
  ev: ChainEvent,
  rule: { kind: RetractionKind; severity: RetractionSeverity },
  block_id: string | null,
  doc_slug: string | null,
  successor_block_id: string | null,
  reason: string | null,
): { kind: RetractionKind; severity: RetractionSeverity; reason_line: string } {
  const subject = ev.event_type.split('.')[0] ?? ev.event_type;
  const tail = block_id ? ` ${block_id}` : '';
  const where = doc_slug ? ` in ${doc_slug}` : '';
  let asserted: string;
  let truth: string;
  if (isInstructionSlug(doc_slug) && rule.kind !== 'retraction') {
    asserted = `instruction ${subject}${tail}${where} (assumed in force)`;
    truth =
      rule.kind === 'tombstone'
        ? `instruction ${subject}${tail} was REMOVED from ${doc_slug}${reason ? ` — ${reason}` : ''}; stop following it`
        : `instruction ${subject}${tail} was CHANGED${successor_block_id ? ` (now ${successor_block_id})` : ''} in ${doc_slug}; re-read kronicle://docs/${encodeURIComponent(doc_slug!)} and follow the current text`;
    return { kind: 'instruction', severity: rule.severity, reason_line: buildReasonLine(asserted, truth) };
  }
  switch (rule.kind) {
    case 'tombstone':
      asserted = `${subject}${tail}${where} (assumed live)`;
      truth = `${subject}${tail} is TOMBSTONED${reason ? ` — ${reason}` : ''}; do not read or build on it`;
      break;
    case 'supersession':
      asserted = `${subject}${tail}${where} (assumed current)`;
      truth = `${subject}${tail} is SUPERSEDED${successor_block_id ? ` by ${successor_block_id}` : ''}${reason ? ` — ${reason}` : ''}; fetch the successor before relying on prior content`;
      break;
    case 'retraction':
    default:
      asserted = `${subject}${tail}${where} (assumed asserted)`;
      truth = `${subject}${tail} is RETRACTED${reason ? ` — ${reason}` : ''}`;
      break;
  }
  return { kind: rule.kind, severity: rule.severity, reason_line: buildReasonLine(asserted, truth) };
}

/** Severity-ordered (safety first), then by seq. Duplicates are not collapsed. */
export function computeRetractions(events: readonly ChainEvent[], lookup?: BlockTextLookup): Retraction[] {
  const out: Retraction[] = [];
  for (const ev of events) {
    const r = classifyRetraction(ev, lookup);
    if (r) out.push(r);
  }
  out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.seq - b.seq);
  return out;
}
