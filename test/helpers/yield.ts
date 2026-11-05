import { afterEach } from 'vitest';

// why: a test file made of synchronous tests (spawnSync-heavy shim suites run 60 s+ on
// macOS runners) never returns to the event loop, so the worker cannot read the main
// process's reply to its batched onTaskUpdate RPC and vitest reports
// `[vitest-worker]: Timeout calling "onTaskUpdate"` (exit 1, every test green). One
// macrotask turn after each test lets the reply in.
afterEach(() => new Promise<void>((resolve) => setTimeout(resolve, 1)));
