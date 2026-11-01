/** Helpers for the format-only property and mutation tests. */

import { KronicleLite } from '../../src/store.js';

export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Compatibility and combining characters NFKC/NFC would fold, plus a no-break space. */
const UNICODE = ['²', 'ﬁ', 'Ａ', '①', '́', 'é', ' ', '‐'];

export function mutate(text: string, r: () => number): string {
  const positions = [...text].map((c, i) => (/\s/.test(c) ? -1 : i)).filter((i) => i >= 0);
  const chars = [...text];
  for (;;) {
    const i = positions[Math.floor(r() * positions.length)]!;
    const op = Math.floor(r() * 3);
    const orig = chars[i]!;
    const pool = ['-', String(Math.floor(r() * 10)), ...UNICODE];
    if (/\p{L}/u.test(orig)) pool.push(orig === orig.toLowerCase() ? orig.toUpperCase() : orig.toLowerCase());
    const c = pool[Math.floor(r() * pool.length)]!;
    const out = [...chars];
    if (op === 0) out.splice(i, 1);
    else if (op === 1) out.splice(i, 1, c);
    else out.splice(i, 0, c);
    const s = out.join('');
    if (s !== text) return s;
  }
}

export function reported(oldMd: string, newMd: string) {
  const kl = new KronicleLite({ memory: true });
  try {
    kl.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: oldMd, actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: newMd, actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'retractions' });
    return { retractions: s.retractions!.length, formatOnly: s.format_only_edits!.length, created: s.delta!.by_type['block.created'] ?? 0, events: s.delta!.events_since };
  } finally {
    kl.close();
  }
}
