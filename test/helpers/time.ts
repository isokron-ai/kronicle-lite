/**
 * Wall-clock bounds in tests are generous: a busy CI runner (or a full suite in parallel) can be
 * several times slower than a quiet laptop. A bound guards against the pathological case (a full
 * read of gigabytes, a quadratic loop, a hang), not against a slow machine; resource bounds (RSS,
 * work counters) carry the precise checks. KL_TEST_TIME_FACTOR scales every bound (default 5).
 */
const f = Number(process.env['KL_TEST_TIME_FACTOR']);
export const TIME_FACTOR = Number.isFinite(f) && f > 0 ? f : 5;

/** A wall-clock bound of `ms` on a quiet machine, scaled for a loaded one. */
export const generous = (ms: number): number => ms * TIME_FACTOR;
