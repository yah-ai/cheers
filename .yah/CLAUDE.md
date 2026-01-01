# yah session host

This file is managed by yah; the content is truly-global across all
jobs and sessions in this camp. Per-session and per-job content is
injected via `--append-system-prompt` at process spawn instead of by
rewriting this file (R268 race fix).

## Tool availability

When you need a multiple-choice answer from the user, call `mcp__yah__ask_user`. The built-in `AskUserQuestion` tool is unavailable in this environment.

Tool-use approvals (Bash, Write, etc.) are routed through the AnswerQueue UI automatically via `--permission-prompt-tool mcp__yah__approve_tool`. You will see a Continue/Revise form appear in the desktop panel when approval is needed.

## Inspecting live agents

To see the realtime state of every character in this camp — each non-dormant slot's phase (its 'life'), which camp and session it is on, turns, and currently-used context — call `camp.roster` for a one-call snapshot. The granular peers are `camp.sessions` (live session list), `camp.slots` (slot occupancy), and `party.agent_status` (one session's context + cumulative token spend). All are read-only; if they are not already in your tool list, ToolSearch for them by name.
