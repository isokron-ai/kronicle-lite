import { describe, expect, it } from 'vitest';

import { Chain } from '../src/chain/index.js';
import { blake3Hex } from '../src/crypto/hash.js';
import { openDatabase } from '../src/db/open.js';
import { DocumentError, DocumentStore } from '../src/docs/documents.js';
import { parseMarkdown, renderBlocks } from '../src/docs/parser.js';

function fresh() {
  const { db, identity } = openDatabase({ memory: true });
  const chain = new Chain(db, identity.signer);
  const docs = new DocumentStore(db, chain);
  return { db, chain, docs };
}

const MD = `# Deploy notes

Use blue/green for the API.

## Database

Run migrations before the cutover.

\`\`\`sh
npm run migrate
\`\`\`

- step one
- step two
`;

describe('parseMarkdown', () => {
  it('splits headings, paragraphs, code fences and lists deterministically', () => {
    const blocks = parseMarkdown(MD);
    expect(blocks.map((b) => b.kind)).toEqual([
      'heading',
      'paragraph',
      'heading',
      'paragraph',
      'code',
      'paragraph',
    ]);
    expect(blocks[2]!.heading_path).toEqual(['Deploy notes', 'Database']);
    expect(blocks[2]!.level).toBe(2);
    expect(blocks[4]!.content).toBe('```sh\nnpm run migrate\n```');
    expect(blocks[1]!.content_hash).toBe(blake3Hex('Use blue/green for the API.'));
    expect(parseMarkdown(MD)).toEqual(blocks);
    expect(parseMarkdown('')).toEqual([]);
    expect(parseMarkdown('a\r\nb\r\n\r\nc  ')).toHaveLength(2);
  });

  it('renders blocks back to markdown that re-parses to the same blocks', () => {
    const blocks = parseMarkdown(MD);
    const md2 = renderBlocks(blocks);
    expect(parseMarkdown(md2).map((b) => b.content_hash)).toEqual(blocks.map((b) => b.content_hash));
  });
});

describe('putDocument', () => {
  it('creates a document, blocks and chain events', () => {
    const { docs, chain } = fresh();
    const r = docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD, actor_id: 'a' });
    expect(r.revision).toBe(1);
    expect(r.blocks).toHaveLength(6);
    expect(r.blocks.every((b) => b.status === 'created')).toBe(true);
    expect(r.events).toBe(7); // document.put + 6 block.created
    expect(chain.head().seq).toBe(7);
    expect(r.head).toEqual(chain.head());
    const types = chain.range(1, 7).map((e) => e.event_type);
    expect(types[0]).toBe('document.put');
    expect(types.slice(1).every((t) => t === 'block.created')).toBe(true);
    expect(docs.liveBlocks(r.doc_id)).toHaveLength(6);
    expect(docs.getRevisionMarkdown(r.doc_id, 1)).toContain('blue/green');
  });

  it('rejects bad slugs', () => {
    const { docs } = fresh();
    expect(() => docs.putDocument({ slug: 'Bad Slug', title: 't', markdown: 'x', actor_id: 'a' })).toThrow(
      DocumentError,
    );
  });

  it('re-put carries unchanged blocks, supersedes changed ones, tombstones removed ones', () => {
    const { docs } = fresh();
    const r1 = docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD, actor_id: 'a' });
    const changed = MD.replace('Run migrations before the cutover.', 'Run migrations AFTER the cutover.').replace(
      '- step one\n- step two\n',
      '',
    );
    const r2 = docs.putDocument({ slug: 'deploy', title: 'Deploy v2', markdown: changed, actor_id: 'a' });
    expect(r2.revision).toBe(2);
    const unchanged = r2.blocks.filter((b) => b.status === 'unchanged');
    const created = r2.blocks.filter((b) => b.status === 'created');
    const tomb = r2.blocks.filter((b) => b.status === 'tombstoned');
    expect(unchanged).toHaveLength(4);
    expect(created).toHaveLength(1);
    expect(created[0]!.supersedes).toBe(r1.blocks[3]!.block_id);
    expect(tomb).toHaveLength(1);
    expect(tomb[0]!.block_id).toBe(r1.blocks[5]!.block_id);
    // ids of unchanged blocks preserved
    expect(unchanged.map((b) => b.block_id).sort()).toEqual(
      [0, 1, 2, 4].map((i) => r1.blocks[i]!.block_id).sort(),
    );
    const old = docs.getBlock(r1.blocks[3]!.block_id)!;
    expect(old.valid_to).not.toBeNull();
    expect(old.superseded_by).toBe(created[0]!.block_id);
    const removed = docs.getBlock(r1.blocks[5]!.block_id)!;
    expect(removed.tombstoned_at).not.toBeNull();
    expect(removed.tombstone_reason).toBe('removed in revision 2');
    expect(docs.liveBlocks(r1.doc_id)).toHaveLength(5);
    expect(docs.getDocument('deploy')!.title).toBe('Deploy v2');
  });

  it('idempotency_key replays without new events', () => {
    const { docs, chain } = fresh();
    const r1 = docs.putDocument({ slug: 'd', title: 't', markdown: 'hello', actor_id: 'a', idempotency_key: 'k' });
    const r2 = docs.putDocument({ slug: 'd', title: 't', markdown: 'other', actor_id: 'a', idempotency_key: 'k' });
    expect(r2.revision).toBe(1);
    expect(r2.events).toBe(0);
    expect(chain.head().seq).toBe(r1.head.seq);
  });
});

describe('supersedeBlock / tombstoneBlock', () => {
  it('supersedes a live block, bumps the revision and re-renders', () => {
    const { docs, chain } = fresh();
    const r = docs.putDocument({ slug: 'd', title: 't', markdown: MD, actor_id: 'a' });
    const target = r.blocks[1]!;
    const s = docs.supersedeBlock({
      block_id: target.block_id,
      new_content: 'Use canary releases for the API.',
      reason: 'policy change',
      actor_id: 'a',
    });
    expect(s.old_block_id).toBe(target.block_id);
    expect(s.revision).toBe(2);
    expect(s.content_hash).toBe(blake3Hex('Use canary releases for the API.'));
    expect(chain.head()).toEqual(s.head);
    const walk = docs.supersessionWalk(target.block_id);
    expect(walk.map((b) => b.block_id)).toEqual([target.block_id, s.new_block_id]);
    expect(docs.getRevisionMarkdown(r.doc_id, 2)).toContain('canary');
    expect(docs.getRevisionMarkdown(r.doc_id, 2)).toContain('# Deploy notes');
    const types = chain.since(r.head.seq).map((e) => e.event_type);
    expect(types).toEqual(['block.created', 'block.superseded', 'document.revised']);
    // Superseding the stale block again is refused.
    expect(() =>
      docs.supersedeBlock({ block_id: target.block_id, new_content: 'x', reason: 'r', actor_id: 'a' }),
    ).toThrow(/superseded by/);
  });

  it('tombstones a live block with a reason', () => {
    const { docs, chain } = fresh();
    const r = docs.putDocument({ slug: 'd', title: 't', markdown: MD, actor_id: 'a' });
    const t = docs.tombstoneBlock({ block_id: r.blocks[5]!.block_id, reason: 'obsolete', actor_id: 'a' });
    expect(t.revision).toBe(2);
    const b = docs.getBlock(r.blocks[5]!.block_id)!;
    expect(b.tombstoned_at).not.toBeNull();
    expect(b.tombstone_reason).toBe('obsolete');
    expect(docs.liveBlocks(r.doc_id)).toHaveLength(5);
    expect(chain.since(r.head.seq).map((e) => e.event_type)).toEqual(['block.tombstoned', 'document.revised']);
    expect(() => docs.tombstoneBlock({ block_id: b.block_id, reason: 'again', actor_id: 'a' })).toThrow(
      /tombstoned/,
    );
    expect(() => docs.tombstoneBlock({ block_id: 'nope', reason: 'x', actor_id: 'a' })).toThrow(/no block/);
  });

  it('chain still verifies after a mix of writes', () => {
    const { docs, chain } = fresh();
    const r = docs.putDocument({ slug: 'd', title: 't', markdown: MD, actor_id: 'a' });
    docs.supersedeBlock({ block_id: r.blocks[1]!.block_id, new_content: 'new', reason: 'r', actor_id: 'a' });
    docs.tombstoneBlock({ block_id: r.blocks[5]!.block_id, reason: 'r', actor_id: 'a' });
    docs.putDocument({ slug: 'd', title: 't', markdown: '# Only heading', actor_id: 'a' });
    expect(chain.verify().ok).toBe(true);
  });
});
