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

## Codex / GitHub Copilot

See the README: `~/.codex/config.toml` `[mcp_servers.kronicle-lite]` for
Codex; repository Settings → Copilot → MCP servers (`"type": "local"` with a
`tools` allowlist) for Copilot.

## Streamable HTTP

```sh
kronicle-lite serve --http            # 127.0.0.1:7417/mcp, bearer in ~/.kronicle-lite/http-bearer.token
```

Client config (any client that speaks MCP 2026-07-28 over HTTP):

```json
{ "mcpServers": { "kronicle-lite": { "url": "http://127.0.0.1:7417/mcp", "headers": { "Authorization": "Bearer <token>" } } } }
```

## Any MCP client

The server speaks MCP 2026-07-28 over stdio (dual-era: 2025 `initialize`
clients are served too) and over HTTP (2026-07-28 only). `tools/list`
returns nine tools, each with an `outputSchema`; the `kronicle://docs/{slug}`
resource template exposes current document revisions as Markdown. See the
README for the tool reference.
