/**
 * Markdown rendering of a SystemState (the text block of get_system_state
 * and `kronicle-lite orient` without --json). Kept free of the MCP SDK so the
 * CLI hook path loads fast.
 */

import type { SystemState } from './orient.js';

/**
 * True when a briefing has nothing to say beyond "carry on": a verified
 * cursor, no events in scope, nothing retracted, drifted or failing. Such a
 * briefing renders as a one-line pulse (≤ 300 bytes).
 */
export function isQuietBriefing(s: SystemState): boolean {
  const presented = s.recovery.method === 'presented' || s.recovery.method === 'presented_compact';
  return (
    presented &&
    s.focus !== 'pulse' &&
    s.recovery.cursor_error === null &&
    !s.drift_banner.surfaced &&
    (s.integrity?.ok ?? true) &&
    (s.delta?.events_since ?? 0) === 0 &&
    (s.retractions?.length ?? 0) === 0 &&
    (s.format_only_edits?.length ?? 0) === 0 &&
    (s.carried_notes?.length ?? 0) === 0 &&
    (s.source_drift?.length ?? 0) === 0 &&
    (s.scope?.hidden_retractions ?? 0) === 0 &&
    (s.pending_count ?? 0) === 0
  );
}

/** Unreleased: the pending (unreconciled) lines, at most `max`. */
export function pendingLines(s: Pick<SystemState, 'pending' | 'pending_count'>, max = 8): string[] {
  const items = s.pending ?? [];
  if (items.length === 0) return [];
  const out = items.slice(0, max).map((p) => {
    const what = p.kind === 'derived' ? `note ${(p.derived_notes ?? []).join(', ')} derived from ${p.doc_slug ?? 'a block'}` : `${p.doc_slug ?? 'a document'}${p.heading_path.length > 0 ? ` › ${p.heading_path.join(' › ')}` : ''}`;
    const change = p.current === null ? `you read "${p.old_text ?? p.read.block_id}"; REMOVED` : p.diff ? `changed: ${p.diff}` : `"${p.old_text}" → "${p.new_text}"`;
    return `- **[${p.severity}]** ${what}${p.seq ? ` (seq ${p.seq})` : ''}: ${change}. ${p.resolve}.`;
  });
  const more = (s.pending_count ?? items.length) - Math.min(items.length, max);
  if (more > 0) out.push(`- …and ${more} more (kronicle-lite pending --actor <you> --json lists them).`);
  return out;
}

export function renderSystemStateMarkdown(s: SystemState): string {
  const integrityLine = s.integrity && !s.integrity.ok ? `**INTEGRITY FAILURE: ${s.integrity.problem}. The store was edited outside kronicle-lite; run \`kronicle-lite verify-chain\`.**` : null;
  // Unreleased (next): the per-turn answer when nothing changed is one line.
  if (isQuietBriefing(s)) {
    const other = s.head.seq > s.recovery.from_seq ? ` in this project (head seq ${s.head.seq})` : '';
    return `kronicle-lite: no change since seq ${s.recovery.from_seq}${other}. Proceed; next cursor: \`${s.cursor_compact}\``;
  }
  if (s.focus === 'pulse') {
    const out = [`kronicle-lite pulse: head seq ${s.head.seq}. ${s.drift_banner.line}`];
    if (integrityLine) out.unshift(integrityLine);
    if (s.recovery.cursor_error) out.push(`Your cursor was rejected (${s.recovery.cursor_error}); position recovered server-side (${s.recovery.method}).`);
    if (s.drift_banner.surfaced) out.push('Call get_system_state with focus=recent_changes before acting.');
    if ((s.pending_count ?? 0) > 0) out.push(`Pending (${s.pending_count}): changes to what you read, not yet re-read at the current version — re-read before acting:`, ...pendingLines(s, 3));
    out.push(`Next cursor: \`${s.cursor_compact}\``);
    return out.join('\n');
  }

  const lines: string[] = [];
  const shortHash = s.head.hash.slice(0, 12);
  lines.push(`# kronicle-lite orient — head seq ${s.head.seq} (${shortHash}…)`);
  lines.push('');
  if (integrityLine) lines.push(`> ${integrityLine}`);
  if (s.drift_banner.surfaced) lines.push(`> **${s.drift_banner.line}**`);
  else lines.push(`> ${s.drift_banner.line}`);
  // 0.5.0: no "never anchored" line until there is an anchor to talk about.
  const anchored = anchorLine(s);
  if (anchored) lines.push(`> ${anchored}`);
  lines.push('');
  lines.push(`**cursor_compact:** \`${s.cursor_compact}\`  `);
  lines.push(`**recovery:** ${s.recovery.method} — ${s.recovery.reason}`);

  if (s.retractions && s.retractions.length > 0) {
    lines.push('');
    lines.push(`## Retractions (${s.retractions.length}) — reconcile before acting`);
    for (const r of s.retractions) {
      lines.push(`- **[${r.severity}]** seq ${r.seq} \`${r.event_type}\` ${r.doc_slug ? `(${r.doc_slug}) ` : ''}${r.reason_line}`);
      if (r.diff) lines.push(`  - changed: ${r.diff}`);
      else if (r.old_text && !r.new_text) lines.push(`  - removed: ${r.old_text}`);
    }
  } else if (s.retractions) {
    lines.push('');
    // 0.6.0: a hidden scope degrades "none" — it was not reviewed, not cleared.
    lines.push(s.scope?.verdict === 'partial' ? '## Retractions: none in this project (partial view)' : '## Retractions: none');
  }
  const cosmetic = s.format_only_edits ?? [];
  if (cosmetic.length > 0) {
    const rules = [...new Set(cosmetic.flatMap((c) => c.rules))].join(', ');
    lines.push(`_${cosmetic.length} format-only edit(s) recorded (${rules}; same Markdown structure, identical text): nothing to reconcile (include_format_only: true lists them)._`);
  }
  if (s.scope && s.scope.hidden_retractions > 0) {
    lines.push(`_${s.scope.hidden_retractions} retraction(s) from other projects hidden and not reviewed (all_projects: true shows them)._`);
  }

  if ((s.pending_count ?? 0) > 0) {
    lines.push('');
    lines.push(`## Pending (${s.pending_count}) — re-read the current version before acting (an older version does not clear a newer change)`);
    lines.push(...pendingLines(s));
  }

  if (s.carried_notes && s.carried_notes.length > 0) {
    lines.push('');
    lines.push(`## Your notes since seq ${s.recovery.from_seq}`);
    for (const n of s.carried_notes) {
      lines.push(`- \`${n.doc_slug}\` (seq ${n.seq}${n.truncated ? `, first ${n.text.length} of ${n.total_chars} chars → kronicle://docs/${encodeURIComponent(n.doc_slug)}` : ''}):`);
      for (const l of n.text.split('\n')) lines.push(`  ${l}`);
      for (const t of n.stale_terms) lines.push(`  - this note repeats \`${t.term}\`, changed at seq ${t.seq}${t.now ? ` (now: "${t.now}")` : ' (removed)'}`);
    }
  }

  if (s.source_drift && s.source_drift.length > 0) {
    lines.push('');
    lines.push(`## Source drift (${s.source_drift.length}) — the bound file changed; re-read it before relying on the stored copy`);
    for (const d of s.source_drift) {
      const stat = d.diff_stat ? ` (+${d.diff_stat.insertions} −${d.diff_stat.deletions})` : '';
      lines.push(
        `- \`${d.slug}\` ← ${d.path}: ${d.state === 'missing' ? 'file deleted' : `blob ${d.bound_blob_sha.slice(0, 12)} → ${d.working_blob_sha?.slice(0, 12) ?? '?'}`}${stat}; bound at ${d.bound_commit ? d.bound_commit.slice(0, 12) : 'no commit'}, HEAD ${d.head_commit ? d.head_commit.slice(0, 12) : 'none'}`,
      );
    }
  }

  // Unreleased (next): with a verified cursor the agent already has the store's
  // shape; the digest (still in structuredContent) is shown on cold or recovered starts.
  const presented = s.recovery.method === 'presented' || s.recovery.method === 'presented_compact';
  if (s.digest && !presented) {
    lines.push('');
    lines.push('## Digest');
    lines.push(
      `${s.digest.documents} document(s), ${s.digest.live_blocks} live block(s), ${s.digest.checkpoints} checkpoint(s). Genesis \`${s.digest.genesis_hash.slice(0, 12)}…\`.`,
    );
    for (const d of s.digest.recent_documents) {
      lines.push(`- \`${d.slug}\` — ${d.title} (rev ${d.revision}, ${d.updated_at}) → kronicle://docs/${encodeURIComponent(d.slug)}`);
    }
  }

  if (s.delta) {
    const cosmeticSeqs = new Map(cosmetic.map((c) => [c.seq, c]));
    lines.push('');
    lines.push(`## Delta: ${s.delta.events_since} event(s) since seq ${s.delta.from_seq}${s.scope?.hidden_events ? ` (+${s.scope.hidden_events} in other projects, not shown)` : ''}`);
    // Cosmetic supersessions are counted as what they are, not as retractions.
    const byType: Record<string, number> = { ...s.delta.by_type };
    for (const ce of cosmetic) {
      const t = s.delta.entries.find((e) => e.kind === 'event' && e.seq === ce.seq)?.event_type ?? 'block.superseded';
      if ((byType[t] ?? 0) > 0) byType[t] = byType[t]! - 1;
      if (byType[t] === 0) delete byType[t];
      byType['format_only_edit'] = (byType['format_only_edit'] ?? 0) + 1;
    }
    const types = Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .map(([t, n]) => `${t}×${n}`)
      .join(', ');
    if (types) lines.push(`by type: ${types}`);
    const c = s.delta.coverage;
    if (c.demoted_by_budget.length > 0) lines.push(`_budget: ${c.demoted_by_budget.join(', ')} rolled up to fit ${c.estimated_tokens} tokens_`);
    if (c.truncated) lines.push('_truncated to the most recent entries_');
    for (const e of s.delta.entries) {
      if (e.kind === 'event') {
        const ce = cosmeticSeqs.get(e.seq);
        if (ce) lines.push(`- seq ${e.seq} format-only edit (${ce.rules.join(', ')}) in ${ce.doc_slug ?? 'a document'} by ${e.actor_id}`);
        else lines.push(`- seq ${e.seq} \`${e.event_type}\` by ${e.actor_id} @ ${e.occurred_at} — ${summarizePayload(e.payload)}`);
      } else {
        lines.push(`- seq ${e.first_seq}–${e.last_seq} \`${e.event_type}\` ×${e.count} (rolled up${e.rendered_via === 'budget' ? ' by budget' : ''}); last: ${summarizePayload(e.sample.payload)}`);
      }
    }
  }

  lines.push('');
  lines.push('## Next');
  for (const n of s.next_steps) lines.push(`- ${n}`);
  lines.push('');
  lines.push(`<details><summary>full cursor</summary>\n\n\`${s.cursor}\`\n\n</details>`);
  return lines.join('\n');
}

/** One banner line for the latest hosted anchor (local record, no network). */
export function anchorLine(s: Pick<SystemState, 'anchor'>): string | null {
  const a = s.anchor;
  if (!a) return null;
  return `anchored ${a.events_since} ${a.events_since === 1 ? 'event' : 'events'} ago (${a.status}, [${a.from_seq}, ${a.to_seq}] at ${a.received_at})`;
}

function summarizePayload(p: Record<string, unknown>): string {
  const keys = ['slug', 'doc_slug', 'title', 'revision', 'block_id', 'successor_block_id', 'reason', 'kind', 'cause'];
  const parts: string[] = [];
  for (const k of keys) {
    const v = p[k];
    if (v === undefined || v === null) continue;
    parts.push(`${k}=${typeof v === 'string' ? JSON.stringify(v.length > 80 ? v.slice(0, 80) + '…' : v) : String(v)}`);
  }
  if (parts.length === 0) {
    const s = JSON.stringify(p);
    return s.length > 120 ? s.slice(0, 120) + '…' : s;
  }
  return parts.join(' ');
}
