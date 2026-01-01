@.yah/CLAUDE.md

<!-- yah:hack-board:start -->
## hack-board — board orientation lives in the tool, not here

This workspace uses the **hack-board** — source-embedded tickets via `@yah:` annotations, no separate issue tracker. The full SDLC (Rule01–Rule12 + Col01, lifecycle, annotation forms, ID rules, etc.) used to live inline in this file and is now served on demand from the `yah` binary itself.

**In a yah-aware session** (`mcp__yah__board_*` / `board.*` tools loaded): call `board.rules`, `board.ticket_prompt`, `board.status`. Per-ticket pickup prompts (`board.ticket_prompt` / `yah board tickets --prompt <ID>`) embed the rules for that ticket's situation.

**In a foreign session** (no yah MCP — vanilla Claude Code or another harness launched directly in this workspace): run `/yah-foreign` (slash command, installed at `.claude/commands/yah-foreign.md`), or fetch the same orientation via CLI:

```bash
yah board prompt yah-foreign   # full orientation
yah board rules                # Rule01–Rule12 + Col01 only
yah board prompt               # list all embedded prompts
```

If `yah` isn't on PATH, fall back to `./target/debug/yah` or `./target/release/yah`.
<!-- yah:hack-board:end -->
