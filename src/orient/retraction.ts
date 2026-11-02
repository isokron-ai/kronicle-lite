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
import type { StaleSource } from '../lineage/lineage.js';
import { isInstructionSlug, REORDERED_RE } from '../docs/documents.js';
import { classifyEdit, type FormatRule } from './cosmetic.js';
import { snippet, wordDiff } from './textdiff.js';

export type RetractionSeverity = 'safety' | 'behavioral' | 'informational';
/**
 * `instruction` (0.4.0, additive): a supersession or tombstone of a block in
 * an instruction document (slug under `instructions/` or `memory/`): a
 * CLAUDE.md, AGENTS.md, rule file or auto-memory index changed on disk and
 * was re-imported. Severity follows the underlying event.
 */
/**
 * `derived` (unreleased, additive): a note derived from a block that changed
 * in this window (docs/FORMAT.md §3.10). `doc_slug` / `old_text` are the
 * NOTE's; `derived_from_change` names the source change; `diff` is the
 * source's word diff. Not a chain event of its own: `seq` / `event_type` are
 * the source change's.
 */
export type RetractionKind = 'tombstone' | 'supersession' | 'retraction' | 'instruction' | 'derived';
export const RETRACTION_KINDS = ['tombstone', 'supersession', 'retraction', 'instruction', 'derived'] as const;

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
  /**
   * Unreleased, additive: true when this supersession is FORMAT-ONLY: old
   * and new raw text are identical up to line endings, trailing whitespace,
   * reflow inside a paragraph and blank lines (0.8.1; docs/FORMAT.md §3.8). Orient lists those under
   * `format_only_edits` instead of `retractions` unless asked
   * (`include_format_only`). Presentation only: nothing else changes.
   */
  format_only: boolean;
  /** With format_only: what differed (`whitespace` or `markup`). */
  format_rules?: FormatRule[];
  /**
   * Unreleased, additive: presentation hint. `likely_typo` = one ordinary
   * word one letter off. A label on a normal retraction: it never changes
   * severity, delivery or the reconcile instruction.
   */
  hint?: 'likely_typo';
  /**
   * Unreleased, additive: set when the block now sits under a different
   * heading path (moved section, renamed or re-levelled ancestor heading).
   * `heading_path` is the old path.
   */
  new_heading_path?: string[];
  /** Unreleased, with kind `derived`: the source change that made the note stale. */
  derived_from_change?: StaleSource;
}

/** Block text for a retraction, from the projection (orient passes one in). */
export interface BlockText {
  content: string;
  heading_path: string[];
  /** Block kind (heading | paragraph | code); code blocks only tolerate whitespace edits. */
  kind?: string;
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
  // A block that changed section is a change even when its words did not.
  const moved = oldB && newB && oldB.heading_path.join('\u0000') !== newB.heading_path.join('\u0000') ? newB.heading_path : null;
  // 0.8.1: the same text in the same section is a reorder (planRevision 1a): order is meaning.
  const reordered = rule.kind === 'supersession' && oldB !== null && newB !== null && !moved && oldB.content === newB.content && reason !== null && REORDERED_RE.test(reason);
  const contentDiff = oldB && newB ? wordDiff(oldB.content, newB.content) : null;
  const sectionDiff = moved ? `section: ${wordDiff(oldB!.heading_path.join(' › '), moved.join(' › '))}` : null;
  const orderDiff = reordered ? `order: same text, new position within ${oldB!.heading_path.join(' › ') || '(top)'}` : null;
  const text = {
    heading_path: oldB?.heading_path ?? newB?.heading_path ?? null,
    old_text: oldB ? snippet(oldB.content) : null,
    new_text: oldB && newB ? snippet(newB.content) : null,
    diff: orderDiff ?? (sectionDiff && oldB!.content === newB!.content ? sectionDiff : sectionDiff ? `${sectionDiff}; ${contentDiff}` : contentDiff),
  };
  const edit = rule.kind === 'supersession' && oldB && newB && !moved && !reordered ? classifyEdit(oldB.content, newB.content, oldB.kind ?? newB.kind) : null;
  const format_only = edit?.format_only === true;
  const hint = !format_only && edit?.hint ? edit.hint : null;
  const base = {
    seq: ev.seq,
    event_type: ev.event_type,
    block_id,
    doc_slug,
    successor_block_id,
    reason,
    ...text,
    format_only,
    ...(format_only ? { format_rules: edit!.rules } : {}),
    ...(hint ? { hint } : {}),
    ...(moved ? { new_heading_path: moved } : {}),
  };
  const instruction = isInstructionSlug(doc_slug) && rule.kind !== 'retraction';
  if (format_only) {
    return {
      ...base,
      kind: instruction ? 'instruction' : rule.kind,
      severity: 'informational',
      reason_line: `Format-only edit (${edit!.rules.join(', ')}) of "${text.old_text}"${where(doc_slug, text.heading_path)} at seq ${ev.seq}: identical raw text up to whitespace and reflow; nothing to reconcile.`,
    };
  }
  // With the words in hand, say them: "you relied on <old>; it is now <new>".
  if (oldB && (rule.kind === 'tombstone' || (rule.kind === 'supersession' && newB))) {
    const loc = where(doc_slug, text.heading_path);
    // Auto-generated put reasons ("replaced in revision 3") add nothing to the words.
    const why = reason && !/^(replaced|removed|reordered) in revision \d+$/.test(reason) ? reason : null;
    const asserted = `${instruction ? 'instruction ' : ''}"${text.old_text}"${loc}`;
    let truth: string;
    if (reordered) {
      truth = `the same text MOVED within ${doc_slug ?? 'the document'} › ${oldB.heading_path.join(' › ') || '(top)'} (seq ${ev.seq}): the order of that section changed; re-read it in its new order`;
    } else if (rule.kind === 'supersession' && moved) {
      const now = oldB.content === newB!.content ? 'the same text' : `"${text.new_text}"`;
      truth = `${now} MOVED to ${doc_slug ?? 'the document'} › ${moved.join(' › ') || '(top)'} (seq ${ev.seq}): re-read it in its new section`;
    } else if (rule.kind === 'supersession') {
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
      reason_line: `You previously relied on ${asserted}; current truth is ${truth}. Reconcile before proceeding.${hint ? ' (Hint: likely a typo fix.)' : ''}`,
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
