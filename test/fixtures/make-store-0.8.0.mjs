/* global process, console */
// Generator of test/fixtures/store-0.8.0.db.gz and store-0.8.0.answers.json (test/scale.test.ts), run
// with the published kronicle-lite 0.8.0 (= main 7e50702): a small store whose read log 0.8.0 never
// pruned (repeat recalls, document reads, writes; an actor with receipts only, as a 0.7.0 recall
// leaves them), then sources changed, and what 0.8.0 answered for it.
//   KL=<kronicle-lite 0.8.0 package dir> node test/fixtures/make-store-0.8.0.mjs OUT
//   gzip -9 -c OUT/data/kronicle-lite.db > test/fixtures/store-0.8.0.db.gz
//   cp OUT/answers-0.8.0.json test/fixtures/store-0.8.0.answers.json
import { mkdirSync, writeFileSync } from 'node:fs'; import { join } from 'node:path'; import { pathToFileURL } from 'node:url';
const { KronicleLite } = await import(pathToFileURL(join(process.env.KL, 'dist/index.js')).href);
const out = process.argv[2]; const dataDir = join(out, 'data'); mkdirSync(dataDir, { recursive: true });
const kl = new KronicleLite({ dataDir });
const md = (port, owner) => `# Deploy\n\nDeploy with port ${port}.\n\n## Owner\n\nOwner is ${owner}.\n\n## Notes\n\nRollback with make undo.\n`;
kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md(8080, 'team-a'), actor_id: 'w' });
kl.docs.putDocument({ slug: 'db', title: 'DB', markdown: '# DB\n\nPrimary is db-1.\n\n## Backups\n\nNightly at 02:00.\n', actor_id: 'w' });
kl.docs.putDocument({ slug: 'cache', title: 'Cache', markdown: '# Cache\n\nTTL is 60s.\n', actor_id: 'w' });
for (let i = 0; i < 10; i++) for (const q of ['deploy port', 'owner', 'primary db', 'backups nightly', 'cache ttl']) kl.recall.recall({ query: q, top_k: 5, actor_id: 'agent' });
const dep = kl.docs.getDocument('deploy');
for (let i = 0; i < 5; i++) kl.lineage.recordDocumentRead('agent', dep.doc_id, 'document');
// "old": receipts only (as a 0.7.0 recall leaves them): recall, then drop its read-log rows.
for (let i = 0; i < 10; i++) kl.recall.recall({ query: 'primary db', top_k: 5, actor_id: 'old' });
kl.db.prepare(`DELETE FROM reads WHERE actor_id = 'old'`).run();
// The agent writes a note (its own write rows), then the sources change.
for (let i = 0; i < 3; i++) kl.docs.putDocument({ slug: 'agent-note', title: 'Note', markdown: `# Note\n\nWe deploy on 8080 (v${i}).\n`, actor_id: 'agent', infer_lineage: false });
kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md(9090, 'team-a'), actor_id: 'w' });
kl.docs.putDocument({ slug: 'db', title: 'DB', markdown: '# DB\n\nPrimary is db-2.\n', actor_id: 'w' });
const answers = {
  version: '0.8.0',
  pending: Object.fromEntries(['agent', 'old', 'w', 'fresh'].map((a) => [a, kl.lineage.pending(a, { limit: 50 })])),
  reads_rows: kl.db.prepare('select count(*) n from reads').get().n,
  receipts_rows: kl.db.prepare('select count(*) n from receipts').get().n,
  infer_agent: kl.lineage.infer('agent', '1970-01-01T00:00:00.000Z', null),
  readers: kl.lineage.readersOf(kl.db.prepare('select block_id from blocks order by block_id').all().map((r) => r.block_id)),
};
kl.db.pragma("wal_checkpoint(TRUNCATE)"); kl.db.exec("VACUUM"); kl.close();
writeFileSync(join(out, 'answers-0.8.0.json'), JSON.stringify(answers, null, 2) + '\n');
console.log(answers.reads_rows, answers.receipts_rows, Object.fromEntries(Object.entries(answers.pending).map(([k, v]) => [k, v.count])));
