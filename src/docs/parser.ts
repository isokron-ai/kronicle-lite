/**
 * Small, deterministic Markdown → blocks splitter.
 *
 * Rules (intentionally simple; this is not a CommonMark parser):
 *   - `#`..`######` at line start opens a heading block and updates the
 *     heading path.
 *   - A fenced code block (``` or ~~~) is one block, fence included.
 *   - Otherwise, runs of non-blank lines are one block (paragraph, list,
 *     table, quote — we do not distinguish).
 *   - Line endings normalized to `\n`; trailing whitespace per line trimmed;
 *     blocks trimmed. Empty input yields zero blocks.
 *
 * content_hash = BLAKE3-256 of the block's UTF-8 content (after the
 * normalization above). The heading path is NOT part of the hash: the same
 * paragraph under a renamed heading keeps its address.
 */

import { blake3Hex } from '../crypto/hash.js';

export type BlockKind = 'heading' | 'paragraph' | 'code';

export interface ParsedBlock {
  ordinal: number;
  kind: BlockKind;
  /** Ancestor headings (inclusive for heading blocks), joined with " > " when stored. */
  heading_path: string[];
  /** Heading level 1-6 for heading blocks; 0 otherwise. */
  level: number;
  content: string;
  content_hash: string;
}

const HEADING_RE = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const FENCE_RE = /^(`{3,}|~{3,})/;

export function normalizeMarkdown(markdown: string): string {
  return markdown
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/g, ''))
    .join('\n');
}

export function parseMarkdown(markdown: string): ParsedBlock[] {
  const lines = normalizeMarkdown(markdown).split('\n');
  const blocks: ParsedBlock[] = [];
  const headingStack: { level: number; text: string }[] = [];
  let para: string[] = [];

  const flushPara = () => {
    if (para.length === 0) return;
    const content = para.join('\n').trim();
    para = [];
    if (content.length === 0) return;
    push('paragraph', content, 0);
  };

  const push = (kind: BlockKind, content: string, level: number) => {
    blocks.push({
      ordinal: blocks.length,
      kind,
      heading_path: headingStack.map((h) => h.text),
      level,
      content,
      content_hash: blake3Hex(content),
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const fence = FENCE_RE.exec(line);
    if (fence) {
      flushPara();
      const marker = fence[1]!;
      const closeRe = new RegExp(`^${marker[0]}{${marker.length},}\\s*$`);
      const buf = [line];
      i++;
      for (; i < lines.length; i++) {
        buf.push(lines[i]!);
        if (closeRe.test(lines[i]!)) break;
      }
      push('code', buf.join('\n').trim(), 0);
      continue;
    }
    const h = HEADING_RE.exec(line);
    if (h) {
      flushPara();
      const level = h[1]!.length;
      const text = h[2]!.trim();
      while (headingStack.length > 0 && headingStack[headingStack.length - 1]!.level >= level) {
        headingStack.pop();
      }
      headingStack.push({ level, text });
      push('heading', text, level);
      continue;
    }
    if (line.trim().length === 0) {
      flushPara();
      continue;
    }
    para.push(line);
  }
  flushPara();
  return blocks;
}

/** Render live blocks back to Markdown (used after single-block supersession). */
export function renderBlocks(
  blocks: readonly { kind: BlockKind; level: number; content: string }[],
): string {
  return blocks
    .map((b) => (b.kind === 'heading' ? `${'#'.repeat(Math.max(1, b.level))} ${b.content}` : b.content))
    .join('\n\n')
    .concat('\n');
}
