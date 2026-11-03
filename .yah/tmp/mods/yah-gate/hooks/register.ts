import type { Register } from 'claude-code'

// yah-gate: shipped by yah-runner-pv (src/gate.rs embeds this file) and loaded
// with `claude -p --plugin-dir`. It replaces `--permission-prompt-tool`.
//
// Core decides first. Its deny stands. Its `ask` AND its `allow` both go to
// the host's endpoint, an HTTP server on the Unix socket named by
// YAH_GATE_SOCK, with `core_decision` saying which: the host runs its full
// gate on an ask and only the camp-boundary check on an allow (a core allow
// is claude's own read-only/in-project verdict, which cannot see the camp).
// This keeps the camp boundary in one owner, the host gate, rather than
// split between it and a PreToolUse hook `ask` (R824-B10). A hook `ask` does
// reach this mod as core's `ask`; the 2026-10-07 outside-camp hangs were the
// host's decider dying behind it (see gate.rs `poll`), not the hook.
//
// `$.http.fetch` aborts at 30s and a person may take minutes, so the endpoint
// holds each request under that and answers `pending`; we ask again with the
// same tool_use_id until it decides. A hook's own 10s budget does not count
// time spent inside `$` calls.
//
// Fail closed: no socket, a bad answer, an interrupt or a throw is a deny.

type Verdict = { decision: 'allow' | 'deny' | 'pending'; reason?: string }

let minted = 0

export const register: Register = on => {
  on('tool.check', async ($, e, next) => {
    const core = await next(e)
    if (core.decision === 'deny') return core
    const sock = await $.env.get('YAH_GATE_SOCK')
    if (!sock) return { decision: 'deny', reason: 'yah-gate: YAH_GATE_SOCK is unset' }
    const body = JSON.stringify({
      tool: e.tool,
      input: e.input,
      tool_use_id: e.tool_use_id ?? `query-${Date.now()}-${++minted}`,
      agent_id: e.agentId,
      core_decision: core.decision === 'allow' ? 'allow' : 'ask',
      core_reason: core.reason,
    })
    for (;;) {
      if (next.signal.aborted) return { decision: 'deny', reason: 'yah-gate: interrupted' }
      const res = await $.http.fetch('http://yah/tool-check', {
        method: 'POST',
        socketPath: sock,
        headers: { 'content-type': 'application/json' },
        body,
      })
      if (!res.ok) return { decision: 'deny', reason: `yah-gate: endpoint answered ${res.status}` }
      const v = JSON.parse(res.text) as Verdict
      if (v.decision === 'allow') return { decision: 'allow', reason: v.reason }
      if (v.decision === 'deny') return { decision: 'deny', reason: v.reason ?? 'denied' }
      if (v.decision !== 'pending') return { decision: 'deny', reason: 'yah-gate: unreadable verdict' }
    }
  }).catch(() => ({ decision: 'deny', reason: 'yah-gate: the approval endpoint failed' }))
}
