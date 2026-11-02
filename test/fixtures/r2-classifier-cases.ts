/**
 * agent-memory-bench hardening round 2, track 1 (branch `hardening-retractions`
 * @ c0bdadc, `stress/kl/r2-classifier-cases.mjs`), adopted verbatim: 69
 * single-block edits placed under "# Runbook".
 *   S = a real change for an agent that reads the raw Markdown (must be a retraction),
 *   C = benign (quiet is allowed, not required).
 * Exceptions under the 0.8.1 rule are listed in test/stress-corpus.test.ts.
 */

const ZW = '​';
const long = (n: number, w: string) => Array.from({ length: n }, (_, i) => `${w}${i}`).join(' ');
export const R2_CORPUS: [string, 'S' | 'C', string, string, string][] = [
  // ── ordered lists: numbers the parser drops but CommonMark (or the raw text) keeps ──
  ['L01', 'S', '1. Drain the node\n2) Upgrade the kernel', '1. Drain the node\n7) Upgrade the kernel', 'delimiter switch starts a new CM list: start 2 -> 7'],
  ['L02', 'S', 'Open these ports:\n8080. web\n9090. admin', 'Open these ports:\n8080. web\n9091. admin', 'numbered lines cannot interrupt a paragraph in CM: port 9090 -> 9091'],
  ['L03', 'S', '1. Prepare\n   2. sub step', '1. Prepare\n   5. sub step', 'nested ordered sublist start 2 -> 5'],
  ['L04', 'S', 'Firewall rules:\n443) https\n8443) admin', 'Firewall rules:\n443) https\n9443) admin', 'paragraph + numbered lines: 8443 -> 9443'],
  ['L05', 'S', 'Back off between retries\n5. seconds, then\n30. seconds, then give up', 'Back off between retries\n5. seconds, then\n60. seconds, then give up', 'hard-wrapped prose: 30 -> 60 seconds'],
  ['L06', 'S', 'Retention by tier:\n1. 7 days\n2. 30 days', 'Retention by tier:\n1. 7 days\n2. 90 days', 'control: list item text change'],
  ['L07', 'S', '- step one\n- step two', '- step two\n- step one', 'control: list items reordered'],
  ['L08', 'S', '- a\n- b', '- a\n  - b', 'control: re-nesting a bullet'],
  ['L09', 'S', 'Keep these releases:\n2024. lts\n2026. current', 'Keep these releases:\n2024. lts\n2025. current', 'year-numbered lines after a paragraph: 2026 -> 2025'],
  ['L10', 'S', '1. drain\n1. upgrade\n1. uncordon', '1. drain\n3. upgrade\n2. uncordon', 'raw numbering contradicts order (CM renders 1,2,3 both)'],
  ['L11', 'C', '1. drain\n2. upgrade', '1) drain\n2) upgrade', 'benign: delimiter style for the whole list'],
  ['L12', 'C', '- drain\n- upgrade', '* drain\n* upgrade', 'benign: bullet style'],
  ['L13', 'S', '- [ ] rotate keys\n- [x] snapshot db', '- [x] rotate keys\n- [x] snapshot db', 'task list checkbox flipped'],
  // ── emphasis markers that are not markup in CommonMark (globs, identifiers) ──
  ['E01', 'S', 'Delete /tmp/*/cache/* nightly.', 'Delete /tmp/_/cache/_ nightly.', 'glob * -> literal _ (CM: both emphasis)'],
  ['E02', 'S', 'Never edit __init__.py by hand.', 'Never edit **init**.py by hand.', 'dunder file name -> bold markers'],
  ['E03', 'S', 'Purge keys matching *session* only.', 'Purge keys matching _session_ only.', 'redis glob pattern vs underscores'],
  ['E04', 'S', 'Grant s3:Get* and s3:List* on logs.', 'Grant s3:Get_ and s3:List_ on logs.', 'IAM wildcard actions'],
  ['E05', 'S', 'Allow hosts web-*-prod and *-canary.', 'Allow hosts web-_-prod and _-canary.', 'host globs'],
  ['E06', 'S', 'Set PATTERN=*.log* for rotation.', 'Set PATTERN=_.log_ for rotation.', 'env value glob'],
  ['E07', 'S', 'x = 2*3*4 on the budget sheet', 'x = 2_3_4 on the budget sheet', 'arithmetic stars'],
  ['E08', 'C', 'This is *important*.', 'This is _important_.', 'benign: emphasis marker style'],
  ['E09', 'S', 'Run as *root* only.', 'Run as **root** only.', 'em -> strong (tree change, control)'],
  ['E10', 'S', 'Remove the *.bak and *.tmp files.', 'Remove the _.bak and _.tmp files.', 'file globs with spaces'],
  ['E11', 'S', 'Match a*b*c in the regex field.', 'Match a_b_c in the regex field.', 'intraword *'],
  // ── whitespace that carries meaning ──
  ['W01', 'S', 'Separator is two spaces:  between fields', 'Separator is two spaces: between fields', 'whitespace run is the content'],
  ['W02', 'C', 'Use the key "a b" (two spaces).', 'Use the key "a b" (two spaces).', 'control: identical'],
  ['W03', 'S', 'Run deploy\\\n--force after review', 'Run deploy\\ --force after review', 'backslash hard break vs literal backslash'],
  ['W04', 'C', 'Restart the web tier\nafter the deploy.', 'Restart the web tier after the deploy.', 'benign: reflow'],
  ['W05', 'C', 'Restart  the web tier.', 'Restart the web tier.', 'benign: double space'],
  ['W06', 'S', 'Indent\twith a tab in Makefiles.', 'Indent with a tab in Makefiles.', 'tab described in prose -> space'],
  ['W07', 'S', 'Use the NBSP form.', 'Use the NBSP form.', 'NBSP -> space (not collapsed by design)'],
  // ── unicode: zero-width, homoglyphs, RTL, CJK, combining ──
  ['U01', 'S', `Deploy to prod${ZW}-eu.`, 'Deploy to prod-eu.', 'zero-width space removed'],
  ['U02', 'S', 'Deploy to staging.', 'Deploy to ѕtaging.', 'Cyrillic dze homoglyph'],
  ['U03', 'S', 'Pay to account ‏123‎ only.', 'Pay to account ‏124‎ only.', 'RTL marks around number'],
  ['U04', 'S', '本番環境へのデプロイは金曜日禁止。', '本番環境へのデプロイは月曜日禁止。', 'CJK weekday change'],
  ['U05', 'S', 'café', 'café', 'NFC vs NFD (bytes differ)'],
  ['U06', 'S', 'Use ＡＰＩ v2.', 'Use API v2.', 'fullwidth letters'],
  ['U07', 'S', 'ابدأ النشر يوم الأحد', 'ابدأ النشر يوم الاثنين', 'Arabic weekday change'],
  ['U08', 'S', 'Limit is 10 000 rows.', 'Limit is 10 000 rows.', 'thin space thousands separator'],
  ['U09', 'S', 'Deploy now', 'Deploy now', 'U+2028 line separator inside text'],
  ['U10', 'S', `Token prefix is sk${ZW}${ZW}live.`, `Token prefix is sk${ZW}live.`, 'zero-width count'],
  // ── links, reference links, images, autolinks, HTML ──
  ['K01', 'S', 'See [runbook](https://a.example/r1).', 'See [runbook](https://a.example/r2).', 'link target'],
  ['K02', 'S', 'See [runbook][r].\n\n[r]: https://a.example/r1', 'See [runbook][r].\n\n[r]: https://a.example/r2', 'reference definition (separate block)'],
  ['K03', 'S', '![arch](img/v1.png)', '![arch](img/v2.png)', 'image source'],
  ['K04', 'S', 'Mail <ops@a.example> first.', 'Mail <sec@a.example> first.', 'autolink'],
  ['K05', 'S', 'Status: <span>green</span>', 'Status: <span>red</span>', 'inline html text'],
  ['K06', 'S', 'See [runbook](https://a.example/r1 "v1").', 'See [runbook](https://a.example/r1 "v2").', 'link title'],
  ['K07', 'S', '[prod](https://a.example) is primary', '[stage](https://a.example) is primary', 'link text'],
  // ── tables, quotes, front matter, setext, thematic breaks, code ──
  ['T01', 'S', '| host | port |\n|---|---|\n| web | 80 |', '| host | port |\n|---|---|\n| web | 8080 |', 'pipe table cell'],
  ['T02', 'S', 'host | port\n:-- | --\nweb | 80', 'host | port\n:-- | --\nweb | 8080', 'table without leading pipe'],
  ['T03', 'S', '> Never force-push main.', '> Always force-push main.', 'block quote'],
  ['T04', 'S', '---\nenv: prod\n---', '---\nenv: stage\n---', 'front matter-ish (thematic breaks)'],
  ['T05', 'S', 'Allowed\n=', 'Allowed\n-', 'setext h1 -> h2 (single char underline)'],
  ['T06', 'S', '```sh\ndeploy --target a\n```', '```sh\ndeploy --target b\n```', 'fenced code'],
  ['T07', 'S', '```sh\ndeploy\n```', '```bash\ndeploy\n```', 'fence info string'],
  ['T08', 'S', '~~~\nrm -rf /tmp/a\n~~~', '~~~\nrm -rf /tmp/b\n~~~', 'tilde fence'],
  ['T09', 'S', '```\nmake  deploy\n```', '```\nmake deploy\n```', 'whitespace inside code'],
  ['T10', 'S', 'Run `deploy  --fast`.', 'Run `deploy --fast`.', 'whitespace inside inline code'],
  ['T11', 'S', '    rm -rf build/a', '    rm -rf build/b', 'indented code'],
  ['T12', 'S', '* * *\nkeep', '- - -\nkeep', 'thematic break style + text'],
  // ── escapes / html entities ──
  ['X01', 'S', 'Use \\*.log here.', 'Use \\_.log here.', 'escaped glob star -> escaped underscore'],
  ['X02', 'S', 'Value is &lt;10&gt;.', 'Value is &lt;11&gt;.', 'entity-wrapped value'],
  ['X03', 'S', 'Use &amp;&amp; between commands.', 'Use || between commands.', 'entity vs pipes'],
  ['X04', 'S', 'Copy A &#x2192; B.', 'Copy B &#x2192; A.', 'numeric entity, swapped operands'],
  // ── Windows/mixed line endings (normalized before hashing; must still see the change) ──
  ['N01', 'S', 'Line one\r\nport 80', 'Line one\nport 8080', 'CRLF -> LF plus real change'],
  ['N02', 'C', 'Line one\r\nport 80', 'Line one\nport 80', 'benign: CRLF -> LF only'],
  ['N03', 'S', 'mode a\rmode b', 'mode a\rmode c', 'bare CR'],
  // ── very long lines ──
  ['V01', 'S', `${long(600, 'w')} target=a`, `${long(600, 'w')} target=b`, '600-word line, change at the end'],
  ['V02', 'C', `${long(600, 'w')}`, `${long(300, 'w')}\n${long(600, 'w').split(' ').slice(300).join(' ')}`, 'benign: reflow of a 600-word line'],
];
