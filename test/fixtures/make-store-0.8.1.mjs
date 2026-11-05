/* global process, console */
// Generator of test/fixtures/store-0.8.1.db.gz (test/upgrade-081.test.ts), run with kronicle-lite
// 0.8.1 (= main 3df5fea): a small store with documents, a supersession, recalls (receipts and read
// log), a checkpoint-free chain, as 0.8.1 leaves it: no 0.9.0 tables (blobs, audit_*, apply_*).
//   KL=<kronicle-lite 0.8.1 package dir> node test/fixtures/make-store-0.8.1.mjs OUT
//   gzip -9 -c OUT/data/kronicle-lite.db > test/fixtures/store-0.8.1.db.gz
import { mkdirSync } from 'node:fs'; import { join } from 'node:path'; import { pathToFileURL } from 'node:url';
const { KronicleLite } = await import(pathToFileURL(join(process.env.KL, 'dist/index.js')).href);
const out = process.argv[2]; const dataDir = join(out, 'data'); mkdirSync(dataDir, { recursive: true });
const kl = new KronicleLite({ dataDir });
const a = kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: '# Deploy\n\nDeploy with port 8080.\n\n## Owner\n\nOwner is team-a.\n', actor_id: 'w' });
kl.docs.putDocument({ slug: 'db', title: 'DB', markdown: '# DB\n\nPrimary is db-1.\n', actor_id: 'w' });
kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
kl.docs.supersedeBlock({ block_id: a.blocks.find((b) => b.kind === 'paragraph').block_id, new_content: 'Deploy with port 9090.', reason: 'moved', actor_id: 'w' });
kl.db.pragma('wal_checkpoint(TRUNCATE)'); kl.db.exec('VACUUM');
const tables = kl.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).all().map((r) => r.name);
kl.close();
console.log(tables.join(','));
