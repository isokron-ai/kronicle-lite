/**
 * Retraction classifier: which events since the cursor mean "something you
 * may have relied on is now wrong" — corrections, not just news.
 *
 * Precedence: explicit map → suffix rule → not a retraction. The suffix rule
 * (.tombstoned / .superseded / .retracted) catches event types added later
 * without a code change. Pure function: same events in, same list out.
 *
 * Severity: safety (object is invalid for future reads) > behavioral (an
 * authoritative position changed) > informational.
 */

import type { ChainEvent } from '../chain/index.js';
import { isInstructionSlug } from '../docs/documents.js';

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
}

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

export function classifyRetraction(ev: ChainEvent): Retraction | null {
  const rule = EXPLICIT[ev.event_type] ?? SUFFIX_RULES.find((r) => ev.event_type.endsWith(r.suffix)) ?? null;
  if (!rule) return null;
  const p = ev.payload;
  const block_id = str(p['block_id']) ?? str(p['id']) ?? str(p['target_id']);
  const doc_slug = str(p['doc_slug']) ?? str(p['slug']);
  const successor_block_id = str(p['successor_block_id']);
  const reason = str(p['reason']);
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
    return {
      seq: ev.seq,
      event_type: ev.event_type,
      kind: 'instruction',
      severity: rule.severity,
      block_id,
      doc_slug,
      successor_block_id,
      reason,
      reason_line: buildReasonLine(asserted, truth),
    };
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
  return {
    seq: ev.seq,
    event_type: ev.event_type,
    kind: rule.kind,
    severity: rule.severity,
    block_id,
    doc_slug,
    successor_block_id,
    reason,
    reason_line: buildReasonLine(asserted, truth),
  };
}

/** Severity-ordered (safety first), then by seq. Duplicates are not collapsed. */
export function computeRetractions(events: readonly ChainEvent[]): Retraction[] {
  const out: Retraction[] = [];
  for (const ev of events) {
    const r = classifyRetraction(ev);
    if (r) out.push(r);
  }
  out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.seq - b.seq);
  return out;
}
