/**
 * Block-level source check (0.6.0): does the document's recorded source file
 * hold this block's exact text right now? This is the only evidence that lets
 * a recall hit reach can_act (docs/HONESTY.md). It reads the file and parses
 * it with the same splitter `put` used, then looks for a block of the same
 * kind and content hash. No git process is spawned.
 *
 * Where the file is:
 *   git binding         <repo_root>/<path>
 *   absolute path       as recorded
 *   ~/…                 under the home directory
 *   relative + project  <project.root>/<path> (instruction files)
 *   relative, no root   unknown → `unchecked` (document-level provenance only)
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

import type { DocumentSource } from '../docs/documents.js';
import { parseMarkdown } from '../docs/parser.js';
import type { SourceCheck } from './honesty.js';

/** Same bound as instruction import. */
const MAX_SOURCE_BYTES = 4 * 1024 * 1024;

type FileState = { state: 'missing' | 'unavailable' | 'unchecked' } | { state: 'read'; blocks: Set<string> };

export function sourceFileOf(source: DocumentSource): string | null {
  const g = source.git;
  if (g && typeof g.repo_root === 'string' && typeof g.path === 'string') return join(g.repo_root, ...g.path.split('/'));
  const p = source.path;
  if (typeof p !== 'string' || p.length === 0) return null;
  if (isAbsolute(p)) return p;
  if (p.startsWith('~/')) return join(homedir(), ...p.slice(2).split('/'));
  const root = source.project?.root;
  if (typeof root === 'string' && isAbsolute(root)) return join(root, ...p.split('/'));
  return null;
}

/** One instance per recall call: each source file is read at most once. */
export class SourceChecker {
  private readonly files = new Map<string, FileState>();

  check(source: DocumentSource, block: { kind: string; content_hash: string }): SourceCheck {
    const file = sourceFileOf(source);
    if (file === null) return 'unchecked';
    let st = this.files.get(file);
    if (!st) {
      st = this.load(file, source);
      this.files.set(file, st);
    }
    if (st.state !== 'read') return st.state;
    return st.blocks.has(`${block.kind}\n${block.content_hash}`) ? 'match' : 'not_in_source';
  }

  private load(file: string, source: DocumentSource): FileState {
    // The repository (or the file's directory) itself is gone: we cannot tell
    // whether the file was deleted or this store moved machines.
    const base = source.git?.repo_root ?? dirname(file);
    if (!existsSync(base)) return { state: 'unavailable' };
    let size: number;
    try {
      const s = statSync(file);
      if (!s.isFile()) return { state: 'missing' };
      size = s.size;
    } catch {
      return { state: 'missing' };
    }
    if (size > MAX_SOURCE_BYTES) return { state: 'unavailable' };
    try {
      const text = readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
      return { state: 'read', blocks: new Set(parseMarkdown(text).map((b) => `${b.kind}\n${b.content_hash}`)) };
    } catch {
      return { state: 'unavailable' };
    }
  }
}
