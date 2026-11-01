# Agent wake contract (kronicle-lite)

Before material work: call `get_system_state` with your previous `cursor` as
`since_cursor`. Honor the drift banner; reconcile retractions BEFORE acting.
Trust the chain over your own memory or a compaction summary.

Pulse before every world-changing command — deploy, migrate, publish,
`git push`, anything that sends, pays or deletes: call `get_system_state` with
your cursor first, even mid-task, and reconcile anything it retracts before
running the command. (A push hook covers the gaps between tool calls; this
line is the rule where there is no hook. See docs/PUSH.md.)

Manual re-ground: type the bare word `orient` to fire the orient skill
(`.claude/skills/orient/SKILL.md`).

Keep receipts from `recall()` with any claim you derive; `verify()` them before
building on the claim again.
