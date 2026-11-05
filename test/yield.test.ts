import { describe, expect, it } from 'vitest';

// Guards test/helpers/yield.ts: a macrotask scheduled during a synchronous test must run
// before the next test starts (what lets vitest's RPC replies in between sync tests).
describe('event loop yields between tests', () => {
  let ran = false;
  it('schedules a macrotask and blocks synchronously', () => {
    setTimeout(() => {
      ran = true;
    }, 0);
    const until = Date.now() + 20;
    while (Date.now() < until) {
      // busy-wait: no await, no event-loop turn inside the test
    }
    expect(ran).toBe(false);
  });
  it('sees it ran before this test started', () => {
    expect(ran).toBe(true);
  });
});
