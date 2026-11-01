/**
 * Cosmetic vs semantic edit classifier (orient/cosmetic.ts).
 *
 * Rule under test: nothing that changes a word, number, date or identifier
 * is cosmetic. Cosmetic set: nine of the ten agent-memory-bench benign-edit
 * templates plus reflow, case, emphasis, quote/dash style and exact review
 * stamps. The bench's typo_fix template is a semantic `likely_typo`
 * (delivered, informational). Semantic set: numbers, hosts, paths, flags,
 * versions, code, negations, word swaps, typo-shaped name/unit changes.
 * The end-to-end adversarial corpus is test/stress-corpus.test.ts.
 */

import { describe, expect, it } from 'vitest';

import { classifyEdit, editDistance } from '../src/orient/cosmetic.js';

// [template, before, after] — the bench's Notes lines, verbatim.
const BENCH_BENIGN: [string, string, string][] = [
  ['whitespace_trim', 'Escalations follow the paging policy.   ', 'Escalations follow the paging policy.'],
  ['whitespace_double', 'Status updates go to the  incident channel.', 'Status updates go to the incident channel.'],
  ['line_ending_norm', 'Postmortems are blameless.\r\nOwners file follow-ups.', 'Postmortems are blameless.\nOwners file follow-ups.'],
  ['comma_list', 'Operators, responders and support engineers join the bridge.', 'Operators, responders, and support engineers join the bridge.'],
  ['smart_quote', 'Use the “safe” profile for drills.', 'Use the "safe" profile for drills.'],
  ['numbered_list_renumber', '1) Open the runbook.\n2) Follow the checklist.\n3) Acknowledge the page.', '1. Open the runbook.\n2. Follow the checklist.\n3. Acknowledge the page.'],
  ['markdown_emphasis', 'Never *skip* the canary stage.', 'Never _skip_ the canary stage.'],
  ['missing_period', 'Silence alerts only with a ticket', 'Silence alerts only with a ticket.'],
  ['hyphenation', 'Send an e-mail summary after each drill.', 'Send an email summary after each drill.'],
];

const MORE_COSMETIC: [string, string, string][] = [
  ['reflow', 'Deploys go to the canary first and\nthen to every region in order.', 'Deploys go to the canary first\nand then to every region in order.'],
  ['case', 'NEVER skip the canary stage.', 'Never skip the canary stage.'],
  ['bold', 'Run the **full** suite before merging.', 'Run the full suite before merging.'],
  ['review stamp', 'Last reviewed: 2026-10-01', 'Last reviewed: 2026-11-01'],
  ['review stamp, month name', '_Last updated October 3, 2026_', '_Last updated November 1, 2026_'],
  ['review stamp in a block', 'Owners: platform team.\nLast reviewed 2026-09-30.', 'Owners: platform team.\nLast reviewed 2026-10-31.'],
  ['dash style', 'Stop \u2014 then restart.', 'Stop - then restart.'],
  ['space before period', 'The runbook lives in the ops wiki.', 'The runbook lives in the ops wiki .'],
  ['bullet marker', '- Page the on-call.\n- Open a bridge.', '* Page the on-call.\n* Open a bridge.'],
  ['curly apostrophe', 'Don’t page twice.', "Don't page twice."],
  ['code span untouched', 'Run `migrate --online` after the deploy', 'Run `migrate --online` after the deploy.'],
];

// Delivered as retractions with likely_typo (informational), never hidden.
const LIKELY_TYPO: [string, string, string][] = [
  ['bench typo_fix template', 'Operators recieve alerts via the dispatcher.', 'Operators receive alerts via the dispatcher.'],
  ['typo, long word', 'Requests are authenticated by the gateway.', 'Requests are authentciated by the gateway.'],
  ['transposition', 'Check the dashbaord before you merge.', 'Check the dashboard before you merge.'],
];

const SEMANTIC: [string, string, string][] = [
  ['two typos', 'The recieve queue is monitered by ops.', 'The receive queue is monitored by ops.'],
  ['stamp line with other words', '_Last updated October 3, 2026 by the platform team._', '_Last updated November 1, 2026 by the platform team._'],
  ['cluster in code span', 'Deploys go to the cluster `stg-west-3` first.', 'Deploys go to the cluster `qa-east-7` first.'],
  ['host, bare', 'Deploys go through legacy-amber-42.internal.', 'Deploys go through legacy-amber-43.internal.'],
  ['region, bare', 'Deploy to us-east first.', 'Deploy to us-west first.'],
  ['number', 'Run rollback within 15 minutes of a failed deploy.', 'Run rollback within 30 minutes of a failed deploy.'],
  ['number word', 'Run rollback within fifteen minutes.', 'Run rollback within fifty minutes.'],
  ['path', 'Never edit files under src/auth.', 'Never edit files under src/billing.'],
  ['flag', 'Run migrations with --online.', 'Run migrations with --offline.'],
  ['flag spelling', 'Run migrations with --dry-run first.', 'Run migrations with --dryrun first.'],
  ['flag in code span', 'Run `migrate --online`.', 'Run `migrate --offline`.'],
  ['version', 'Pin node 20.11.1 in CI.', 'Pin node 22.11.1 in CI.'],
  ['url', 'Status page: https://status.example.com/a', 'Status page: https://status.example.com/b'],
  ['host order', 'Fail over from db-a.internal to db-b.internal.', 'Fail over from db-b.internal to db-a.internal.'],
  ['negation swap', 'Always run the tests before deploying.', 'Never run the tests before deploying.'],
  ['negation removed', 'Do not deploy on Fridays.', 'Do deploy on Fridays.'],
  ['enable/unable', 'The cache is enable by default.', 'The cache is unable by default.'],
  ['primary/replica', 'Reads go to the primary database.', 'Reads go to the replica database.'],
  ['required/optional', 'Approval is required for prod.', 'Approval is optional for prod.'],
  ['word swap', 'Owners file follow-ups.', 'Owners skip follow-ups.'],
  ['now/not', 'Deploys are now gated.', 'Deploys are not gated.'],
  ['words added', 'Page the on-call.', 'Page the on-call and the manager.'],
  ['three typos', 'Alpha bravo charlie delta echo.', 'Alpah bravo charile detla echo.'],
  ['date that is not a stamp', 'The deploy freeze starts 2026-12-01.', 'The deploy freeze starts 2026-12-15.'],
  ['stamp line, other words changed', 'Last reviewed 2026-10-01: deploy to prod.', 'Last reviewed 2026-11-01: deploy to dev.'],
  ['strikethrough', 'Use the canary stage.', 'Use the ~~canary~~ stage.'],
];

// 0.7.0 release blocker (cc-anchor contract tests): one-character changes in
// values, flags and commands were hidden as typos. Each of these must alarm.
const MUST_ALARM: [string, string, string][] = [
  ['staging-a → staging-b on a command line', 'Deploy with ./bin/deploy --target staging-a.', 'Deploy with ./bin/deploy --target staging-b.'],
  ['staging-a → staging-b in prose', 'Deploys go to staging-a first.', 'Deploys go to staging-b first.'],
  ['staging-a → stagingb (hyphen dropped, letter changed)', 'Deploys go to staging-a first.', 'Deploys go to stagingb first.'],
  ['us-east-1 → us-east-2', 'The primary region is us-east-1.', 'The primary region is us-east-2.'],
  ['v1 → v2', 'Call the v1 API for exports.', 'Call the v2 API for exports.'],
  ['port 8080 → 8081', 'The service listens on port 8080.', 'The service listens on port 8081.'],
  ['prod1 → prod2', 'Deploys land on prod1 first.', 'Deploys land on prod2 first.'],
  ['--target a → b', 'Run deploy --target a after the build.', 'Run deploy --target b after the build.'],
  ['--target=a → =b', 'Run deploy --target=alpha.', 'Run deploy --target=alpho.'],
  ['do → don\'t', 'Always do run the migration first.', "Always don't run the migration first."],
  ['must → must not', 'You must restart the worker.', 'You must not restart the worker.'],
  ['--dry-run removed', 'Run the migration with --dry-run first.', 'Run the migration first.'],
  ['enable → disable', 'Set the flag to enable caching.', 'Set the flag to disable caching.'],
  ['one character inside backticks', 'Run `deploy -a` after the build.', 'Run `deploy -b` after the build.'],
  ['one character inside backticks, word', 'Run `make deploys` now.', 'Run `make deploy` now.'],
  ['one-letter word change on a command line', 'Run ./scripts/sync --mode mirror nightly.', 'Run ./scripts/sync --mode mirrer nightly.'],
  ['one-letter word change after a $ prompt', '$ deploy production carefully', '$ deploy productoin carefully'],
  ['quoted argument', 'Use the "blue" pool for deploys.', 'Use the "blur" pool for deploys.'],
  ['short word typo-like change', 'Deploy to the east pool.', 'Deploy to the eest pool.'],
  ['first letter changed', 'Restart the worker gracefully.', 'Restart the worker fracefully.'],
];

describe('classifyEdit', () => {
  it.each(BENCH_BENIGN)('bench benign template %s is cosmetic', (_t, a, b) => {
    const c = classifyEdit(a, b);
    expect(c.semantic_reason).toBeNull();
    expect(c.cosmetic).toBe(true);
  });

  it.each(MORE_COSMETIC)('%s is cosmetic', (_t, a, b) => {
    expect(classifyEdit(a, b)).toMatchObject({ cosmetic: true, semantic_reason: null });
  });

  it.each(SEMANTIC)('%s is semantic', (_t, a, b) => {
    const c = classifyEdit(a, b);
    expect(c.cosmetic).toBe(false);
    expect(c.semantic_reason).toEqual(expect.any(String));
  });

  it.each(LIKELY_TYPO)('%s is semantic, labelled likely_typo', (_t, a, b) => {
    expect(classifyEdit(a, b)).toMatchObject({ cosmetic: false, likely_typo: true });
  });

  it.each(MUST_ALARM)('must alarm: %s', (_t, a, b) => {
    const c = classifyEdit(a, b);
    expect(c.cosmetic, JSON.stringify(c)).toBe(false);
  });

  it('names the rules that explain a cosmetic edit', () => {
    expect(classifyEdit('Use a non-blocking client.', 'Use a nonblocking client.').rules).toEqual(['hyphenation']);
    expect(classifyEdit('Rotate keys quarterly.', 'Rotate keys quarterly!').rules).toEqual(['punctuation']);
    expect(classifyEdit('Use the “safe” profile.', 'Use the "safe" profile.').rules).toEqual(['quotes']);
    expect(classifyEdit('Last reviewed: 2026-10-01', 'Last reviewed: 2026-11-01').rules).toEqual(['review_stamp']);
    expect(classifyEdit('a  b', 'a b').rules).toEqual(['whitespace']);
  });

  it('code blocks tolerate only line endings and trailing whitespace', () => {
    expect(classifyEdit('```sh\nmake deploy  \n```', '```sh\nmake deploy\n```', 'code').cosmetic).toBe(true);
    expect(classifyEdit('```sh\nmake  deploy\n```', '```sh\nmake deploy\n```', 'code').cosmetic).toBe(false);
    expect(classifyEdit('```yaml\na:\n  b: 1\n```', '```yaml\na:\nb: 1\n```', 'code').cosmetic).toBe(false);
  });

  it('editDistance counts a transposition as one edit', () => {
    expect(editDistance('recieve', 'receive')).toBe(1);
    expect(editDistance('east', 'west')).toBe(2);
    expect(editDistance('kitten', 'sitting')).toBe(3);
  });
});
