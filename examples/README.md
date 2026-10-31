# Client configuration examples

All of these launch `kronicle-lite serve` over stdio. Data lives in
`~/.kronicle-lite` by default; pass `--data-dir` to put it elsewhere, and
`--actor <id>` to label the agent (cursors are bound to the actor id).

## Claude Code

```sh
claude mcp add kronicle-lite -- npx -y kronicle-lite serve
# or, per project, with its own data dir:
claude mcp add kronicle-lite -- npx -y kronicle-lite serve --data-dir ./.kronicle-lite --actor claude-code
```

Or copy `examples/.mcp.json` into your project root. To install the orient
skill for Claude Code, copy `skills/orient/` to `.claude/skills/orient/`
and add the line from `examples/.claude/CLAUDE.md` to your `CLAUDE.md`.

## Cursor

`.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "kronicle-lite": {
      "command": "npx",
      "args": ["-y", "kronicle-lite", "serve", "--actor", "cursor"]
    }
  }
}
```

## Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kronicle-lite": {
      "command": "npx",
      "args": ["-y", "kronicle-lite", "serve", "--actor", "claude-desktop"]
    }
  }
}
```

## Any MCP client

The server speaks MCP over stdio. `tools/list` returns eight tools; the
`kronicle://docs/{slug}` resource template exposes current document
revisions as Markdown. See the README for the tool reference.
