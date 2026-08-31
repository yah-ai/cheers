# yah session host

This file is managed by yah; the content is truly-global across all
jobs and sessions in this camp. Per-session and per-job content is
injected via `--append-system-prompt` at process spawn instead of by
rewriting this file (R268 race fix).

## Environment quirks

- **`mcp__yah__ask_user`** is the canonical user-choice affordance: use it for structured multiple-choice prompts (multi-option, multi-select, or multi-question forms). Do NOT use it for single free-form questions — just print those into chat. `AskUserQuestion` is not wired up in this host.
- **Tool-use approvals** (Bash, Write, etc.) route through the AnswerQueue UI via `--permission-prompt-tool mcp__yah__approve_tool`; a Continue/Revise modal will appear in the desktop panel. To minimize Revise round-trips: name the target in the call's `description` ("Read app/yah/cli/src/main.rs" beats "Read file" — the user pattern-matches on description before clicking Continue); scope paths narrowly (`rg "foo" crates/yah/board/` is approvable, unbounded `rg "foo"` is a Revise); don't pre-stage destructive shapes (`rm -rf`, `git reset --hard`, `find … -delete`, `--no-verify`) unless the user has authorized that exact operation — they escalate to a hard review even when the target is harmless.
- **Grep `type: "tsx"` returns zero results silently.** claude-cli's Grep wraps ripgrep, which only knows `ts` (covers `.ts` and `.tsx`). Use `type: "ts"` or `glob: "**/*.tsx"`. If a Grep you expect to match returns nothing, recheck the type field before concluding the pattern is absent.

## Inspecting live agents

To see the realtime state of every character in this camp — each non-dormant slot's phase (its 'life'), which camp and session it is on, turns, and currently-used context — call `camp.roster` for a one-call snapshot. The granular peers are `camp.sessions` (live session list), `camp.slots` (slot occupancy), and `party.agent_status` (one session's context + cumulative token spend). All are read-only; if they are not already in your tool list, ToolSearch for them by name.
