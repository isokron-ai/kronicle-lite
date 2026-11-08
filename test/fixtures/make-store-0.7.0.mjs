/* global process, console */
// Generator of test/fixtures/store-0.7.0.db.gz (test/upgrade-old-stores.test.ts), run with the
// published kronicle-lite 0.7.0: documents, a supersession, a tombstone, recalls (receipts), a
// checkpoint. 0.7.0 has no doc_lineage, doc_lineage_gaps or reads tables (0.8.0 / 0.8.1).
//   KL=<kronicle-lite 0.7.0 package dir> node test/fixtures/make-store-0.7.0.mjs OUT
//   gzip -9 -c OUT/data/kronicle-lite.db > test/fixtures/store-0.7.0.db.gz
import { mkdirSync } from 'node:fs'; import { join } from 'node:path'; import { pathToFileURL } from 'node:url';
const { KronicleLite } = await import(pathToFileURL(join(process.env.KL, 'dist/index.js')).href);
const out = process.argv[2]; const dataDir = join(out, 'data'); mkdirSync(dataDir, { recursive: true });
const kl = new KronicleLite({ dataDir });
const md = (port) => `# Deploy\n\nDeploy with port ${port}.\n\n## Owner\n\nOwner is team-a.\n\n## Notes\n\nRollback with make undo.\n`;
kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md(8080), actor_id: 'w' });
kl.docs.putDocument({ slug: 'db', title: 'DB', markdown: '# DB\n\nPrimary is db-1.\n\n## Backups\n\nNightly at 02:00.\n', actor_id: 'w' });
for (const q of ['deploy port', 'owner', 'primary db']) kl.recall.recall({ query: q, top_k: 5, actor_id: 'agent' });
kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md(9090), actor_id: 'w' });
const notes = kl.docs.getDocument('db');
const live = kl.db.prepare('select block_id from blocks where doc_id = ? and superseded_by is null and tombstoned_at is null order by ordinal').all(notes.doc_id);
kl.docs.tombstoneBlock({ block_id: live[live.length - 1].block_id, reason: 'retired', actor_id: 'w' });
kl.chain.checkpoint(1, kl.chain.head().seq);
kl.db.pragma('wal_checkpoint(TRUNCATE)'); kl.db.exec('VACUUM'); kl.close();
console.log('ok');
