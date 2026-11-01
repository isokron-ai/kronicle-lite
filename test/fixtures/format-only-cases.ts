/**
 * Shared cases for the format-only classifier tests (cosmetic, stress corpus,
 * property and mutation tests).
 */

export const FORMAT_ONLY: [string, string, string][] = [
  ['double space (bench whitespace_double)', 'Status updates go to the  incident channel.', 'Status updates go to the incident channel.'],
  ['reflow', 'Deploys go to the canary first and\nthen to every region in order.', 'Deploys go to the canary first\nand then to every region in order.'],
  ['emphasis * ↔ _ (bench markdown_emphasis)', 'Never *skip* the canary stage.', 'Never _skip_ the canary stage.'],
  ['strong ** ↔ __', 'Run the **full** suite.', 'Run the __full__ suite.'],
  ['bullet - ↔ *', '- Page the on-call.\n- Open a bridge.', '* Page the on-call.\n* Open a bridge.'],
  ['ordered delimiter ) ↔ . (bench numbered_list_renumber)', '1) Open the runbook.\n2) Follow the checklist.\n3) Acknowledge the page.', '1. Open the runbook.\n2. Follow the checklist.\n3. Acknowledge the page.'],
  ['renumbering after the first item', '1. Open the runbook.\n2. Follow the checklist.', '1. Open the runbook.\n1. Follow the checklist.'],
  ['whitespace around inline code', 'Run `make deploy`  now.', 'Run `make deploy` now.'],
  ['link text reflow', 'See [the deploy\nguide](https://x.example/deploy) first.', 'See [the deploy guide](https://x.example/deploy) first.'],
];

export const MUST_ALARM: [string, string, string][] = [
  // the 0.7.0 release blocker and its siblings
  ['staging-a → staging-b on a command line', 'Deploy with ./bin/deploy --target staging-a.', 'Deploy with ./bin/deploy --target staging-b.'],
  ['staging-a → staging-b in prose', 'Deploys go to staging-a first.', 'Deploys go to staging-b first.'],
  ['us-east-1 → us-east-2', 'The primary region is us-east-1.', 'The primary region is us-east-2.'],
  ['v1 → v2', 'Call the v1 API for exports.', 'Call the v2 API for exports.'],
  ['port 8080 → 8081', 'The service listens on port 8080.', 'The service listens on port 8081.'],
  ['prod1 → prod2', 'Deploys land on prod1 first.', 'Deploys land on prod2 first.'],
  ['--target a → b', 'Run deploy --target a after the build.', 'Run deploy --target b after the build.'],
  ['do → don\'t', 'Always do run the migration first.', "Always don't run the migration first."],
  ['must → must not', 'You must restart the worker.', 'You must not restart the worker.'],
  ['--dry-run removed', 'Run the migration with --dry-run first.', 'Run the migration first.'],
  ['enable → disable', 'Set the flag to enable caching.', 'Set the flag to disable caching.'],
  ['one character inside backticks', 'Run `deploy -a` after the build.', 'Run `deploy -b` after the build.'],
  ['one-letter word change on a command line', 'Run ./scripts/sync --mode mirror nightly.', 'Run ./scripts/sync --mode mirrer nightly.'],
  // every former heuristic is gone
  ['hyphen dropped (node-a → nodea)', 'Send traffic to node-a.', 'Send traffic to nodea.'],
  ['case (bucket names are case-sensitive)', 'The bucket name is Archive.', 'The bucket name is archive.'],
  ['typo-shaped name (Karen → Karin)', 'Page Karen for database incidents.', 'Page Karin for database incidents.'],
  ['bench typo_fix (delivered, hint only)', 'Operators recieve alerts via the dispatcher.', 'Operators receive alerts via the dispatcher.'],
  ['review stamp date', 'Last reviewed: 2026-10-01', 'Last reviewed: 2026-11-01'],
  ['NFKC (2³ → 23)', 'Allow up to 2³ retries per job.', 'Allow up to 23 retries per job.'],
  ['NFC (composed vs decomposed é)', 'Ask René first.', 'Ask René first.'],
  ['smart quotes', 'Use the "blue" pool.', 'Use the “blue” pool.'],
  ['trailing period', 'Silence alerts only with a ticket', 'Silence alerts only with a ticket.'],
  ['Oxford comma', 'Operators, responders and support engineers join.', 'Operators, responders, and support engineers join.'],
  ['dash style', 'Stop - then restart.', 'Stop — then restart.'],
  ['non-breaking space', 'Wait 30 s between retries.', 'Wait 30 s between retries.'],
  ['emphasis removed', '**Never** deploy on Fridays.', 'Never deploy on Fridays.'],
  ['list start number', '1. Open the runbook.\n2. Follow it.', '2. Open the runbook.\n3. Follow it.'],
  ['bullet → ordered', '- Open the runbook.', '1. Open the runbook.'],
  ['link target', 'See [the guide](https://x.example/a).', 'See [the guide](https://x.example/b).'],
  ['raw HTML', 'Press <kbd>Enter</kbd> to confirm.', 'Press <kbd>Return</kbd> to confirm.'],
  ['table (opaque)', '| a | b |\n|---|---|\n| 1 | 2 |', '| a | b |\n|---|---|\n| 1 |  2 |'],
  ['block quote (opaque)', '> Do not deploy  on Fridays.', '> Do not deploy on Fridays.'],
  ['paragraph → list', 'Page the on-call.', '- Page the on-call.'],
];

// [id, label, old, new, note]   label: S = semantic (must retract), C = cosmetic (should stay quiet)
export const CORPUS: [string, 'S' | 'C', string, string, string][] = [
  // --- known bug under fix (hyphen-joined identifier, one letter) ---
  ['S01', 'S', 'Run the deploy with --target staging-a first.', 'Run the deploy with --target staging-b first.', 'hyphenated target id a->b'],
  ['S02', 'S', 'Send traffic to node-a during the window.', 'Send traffic to node-b during the window.', 'hyphenated host a->b'],
  ['S03', 'S', 'Fail over to the staging-east cluster.', 'Fail over to the staging-west cluster.', 'east/west inside hyphenated name'],
  ['S04', 'S', 'Pin the bucket to the europe-west location.', 'Pin the bucket to the europe-east location.', 'region inside hyphenated name'],
  ['S05', 'S', 'Deploy to the northeast region only.', 'Deploy to the northwest region only.', 'compound region word'],
  ['S06', 'S', 'Run backups from the southeast datacenter.', 'Run backups from the southwest datacenter.', 'compound region word'],
  // --- units / magnitudes in words ---
  ['S07', 'S', 'Cap uploads at 100 megabytes per request.', 'Cap uploads at 100 megabits per request.', 'bytes->bits (8x)'],
  ['S08', 'S', 'Throttle the link to 10 gigabytes per second.', 'Throttle the link to 10 gigabits per second.', 'bytes->bits'],
  ['S09', 'S', 'Retain audit logs for eight days.', 'Retain audit logs for eighty days.', 'number word eight->eighty'],
  ['S10', 'S', 'Allow up to 2³ retries per job.', 'Allow up to 23 retries per job.', 'NFKC superscript: 8 -> 23'],
  ['S11', 'S', 'Max body size is 10⁶ bytes.', 'Max body size is 106 bytes.', 'NFKC superscript: 1e6 -> 106'],
  // --- protocol / product names ---
  ['S12', 'S', 'The health check must use http on the internal port.', 'The health check must use https on the internal port.', 'http->https'],
  ['S13', 'S', 'Relay outbound mail over smtp only.', 'Relay outbound mail over smtps only.', 'smtp->smtps'],
  ['S14', 'S', 'Point the reporting job at the mysql replica.', 'Point the reporting job at the mssql replica.', 'different DBMS'],
  ['S15', 'S', 'Export the audit trail as json for the auditors.', 'Export the audit trail as jsonl for the auditors.', 'format change'],
  // --- names / identifiers without punctuation ---
  ['S16', 'S', 'Escalate incidents to Mark before paging anyone else.', 'Escalate incidents to Mary before paging anyone else.', 'different person'],
  ['S17', 'S', 'Page Karen for database incidents.', 'Page Karin for database incidents.', 'different person'],
  ['S18', 'S', 'Deploy into the payments namespace.', 'Deploy into the payment namespace.', 'different k8s namespace'],
  ['S19', 'S', 'Truncate the sessions table nightly.', 'Truncate the session table nightly.', 'different table'],
  ['S20', 'S', 'Cut releases from the stable branch.', 'Cut releases from the stale branch.', 'different branch'],
  ['S21', 'S', 'Delete the backup after the restore test.', 'Delete the backups after the restore test.', 'one vs all'],
  // --- review-stamp masking hides real dates ---
  ['S22', 'S', 'As of 2026-12-01 deploys to production are frozen.', 'As of 2026-11-01 deploys to production are frozen.', 'effective date of a freeze (as-of line)'],
  ['S23', 'S', 'Last reviewed 2026-10-01; the signing certificate expires 2026-12-01.', 'Last reviewed 2026-10-01; the signing certificate expires 2026-11-02.', 'expiry date on a stamp line'],
  ['S24', 'S', 'Revised cutover date: 2026-12-01.', 'Revised cutover date: 2026-11-15.', 'cutover date on a "Revised" line'],
  ['S25', 'S', '- Updated retention: delete backups after Nov 30, 2026', '- Updated retention: delete backups after Nov 3, 2026', 'list item starting with Updated'],
  ['S26', 'S', 'Reviewed on 2026-10-01. Maintenance window: Dec 5, 2026.', 'Reviewed on 2026-10-01. Maintenance window: Nov 5, 2026.', 'window date shares the stamp line'],
  // --- punctuation that carries meaning ---
  ['S27', 'S', 'Is a migration needed? No. Deploy directly.', 'Is a migration needed? No deploy directly.', 'sentence break flips meaning (borderline)'],
  // --- controls: things the classifier must already catch ---
  ['S28', 'S', 'Deploys go to the staging cluster `stg-west-2` first.', 'Deploys go to the staging cluster `stg-east-1` first.', 'code span (control)'],
  ['S29', 'S', 'Never deploy on Fridays.', 'Always deploy on Fridays.', 'negation word (control)'],
  ['S30', 'S', 'Timeouts are 30 ms.', 'Timeouts are 30 s.', 'unit ms->s (control)'],
  ['S31', 'S', 'Use us-east for the primary.', 'Use us-west for the primary.', 'us-east->us-west (control)'],
  ['S32', 'S', 'Set the offset to +5 hours.', 'Set the offset to -5 hours.', 'sign flip (control)'],
  ['S33', 'S', 'Alert when load > 80 percent.', 'Alert when load < 80 percent.', 'comparison flip (control)'],
  ['S34', 'S', 'Do not deploy on Friday.', 'Do now deploy on Friday.', 'not->now (control)'],
  ['S35', 'S', 'Order: build, test, deploy.', 'Order: deploy, test, build.', 'order swap (control)'],
  ['S36', 'S', 'Run with sudo.', 'Run without sudo.', 'with/without (control)'],
  ['S37', 'S', 'Connect to db01.internal on port 5432.', 'Connect to db01.internal on port 5433.', 'port (control)'],
  ['S38', 'S', 'Use pnpm, not npm.', 'Use npm, not pnpm.', 'swap (control)'],
  // --- cosmetic set (should be quiet) ---
  ['C01', 'C', 'Deploys go to the staging cluster first.', 'Deploys go to the staging cluster first.  ', 'trailing whitespace'],
  ['C02', 'C', 'Deploys go to the staging cluster first.', 'Deploys go  to the staging\ncluster first.', 'reflow'],
  ['C03', 'C', 'Use the "blue" pool for canaries.', 'Use the “blue” pool for canaries.', 'smart quotes'],
  ['C04', 'C', 'Rotate keys quarterly.', 'Rotate keys quarterly!', 'punctuation'],
  ['C05', 'C', 'Rotate the keys every quater.', 'Rotate the keys every quarter.', 'typo fix'],
  ['C06', 'C', 'Last reviewed: 2026-09-01', 'Last reviewed: 2026-10-01', 'review stamp'],
  ['C07', 'C', '**Never** deploy on Fridays.', 'Never deploy on Fridays.', 'emphasis'],
  ['C08', 'C', 'Use a non-blocking client.', 'Use a nonblocking client.', 'hyphenation'],
  ['C09', 'C', 'deploys go to the staging cluster first.', 'Deploys go to the staging cluster first.', 'case'],
  ['C10', 'C', 'Recieve alerts in the oncall channel.', 'Receive alerts in the oncall channel.', 'transposition typo'],
  ['C11', 'C', 'Check the dashbaord before you merge.', 'Check the dashboard before you merge.', 'typo'],
  ['C12', 'C', 'Wait for the green build, then merge.', 'Wait for the green build; then merge.', 'comma->semicolon'],
  ['C13', 'C', 'Reviewed on 2026-09-01.', 'Reviewed on 2026-10-15.', 'review stamp variant'],
  ['C14', 'C', 'The runbook lives in the ops wiki.', 'The runbook lives in the ops wiki .', 'space before period'],
  ['C15', 'C', 'Use the staging cluster - then prod.', 'Use the staging cluster — then prod.', 'dash style'],
  ['C16', 'C', 'Wait 1,000 ms between retries.', 'Wait 1000 ms between retries.', 'thousands separator (false alarm is acceptable)'],
  ['C17', 'C', 'Ask in the #ops channel.', 'Ask in the #ops channel!', 'punctuation next to protected token'],
  ['C18', 'C', 'Deploys go to the staging cluster first.', 'Deploys go to the Staging cluster first.', 'case on meaning word'],
];

/** Real-shaped runbooks for the property and mutation tests: prose, identifiers, URLs, numbers, dates, code. */
export const RUNBOOKS: string[] = [
  `# amber-api deploy runbook

## Deploy target

Deploys of amber-api go to the cluster \`stg-west-3\` first, then to prod-eu-1.
Run ./bin/deploy --target staging-a --timeout 30s from the release branch.

## Rollback

1. Run \`rollback --last\` within 15 minutes of a failed deploy.
2. Page Karen (on-call) and post in #ops-incidents.
3. Check https://status.example.com/amber before you retry.

## Database

The primary database is db01.internal:5432; the replica is db02.internal.
Never run migrations with --online during the freeze (2026-12-01 to 2026-12-15).

## Notes

- Operators receive alerts via the dispatcher.
- Use the **canary** stage for _every_ release.
- Last reviewed: 2026-10-01

\`\`\`sh
./bin/deploy --target staging-a --dry-run
\`\`\`
`,
  `# Payments service

Requests are authenticated by the gateway at api.example.com/v2/payments.
Cap uploads at 100 megabytes; retain audit logs for eight days.
Escalate to Mark before paging anyone else; see [the escalation guide](https://wiki.example.com/esc#tier-2).

## Config

Set PAYMENTS_MODE=live only in us-east-1. The JSON export goes to s3://audit-bucket/exports/.
Throttle at 10 gigabits per second; http health checks hit port 8080.
`,
];
