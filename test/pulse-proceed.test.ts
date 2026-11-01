/**
 * A pulse never lists retractions, so its next_steps must never read as a
 * clean bill when something changed. Regression for the release re-run
 * finding: agents deployed a stale target after a pulse said "Within
 * threshold; proceed".
 */

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';

const md = (t: string) => `# Runbook\n\n## Deploy\n\nDeploy with --target ${t}.\n`;
const saysProceed = (steps: string[]) => steps.some((s) => /\bproceed\b/i.test(s) && !/do not/i.test(s));

describe('pulse next_steps', () => {
  it('says proceed only when nothing changed', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: md('staging-a'), actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    const quiet = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'pulse' });
    expect(saysProceed(quiet.next_steps)).toBe(true);
    kl.close();
  });

  it('never says proceed after a change, even below the drift threshold and with no pending actor', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: md('staging-a'), actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: md('staging-b'), actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'pulse' });
    expect(s.drift_banner.surfaced).toBe(false);
    expect(saysProceed(s.next_steps)).toBe(false);
    expect(s.next_steps.join(' ')).toMatch(/focus=retractions/);
    kl.close();
  });
});
