# AgentAegis for Codex

This adapter installs AgentAegis as Codex command hooks.

It wires these Codex hook events:

- `UserPromptSubmit`: scans user prompts and injects prompt guard context.
- `PreToolUse`: blocks risky `Bash`, `apply_patch`/edit, and MCP tool calls.
- `PermissionRequest`: denies approval requests that AgentAegis would block.
- `PostToolUse`: scans tool output before it is used as model context.
- `SessionStart`: adds baseline prompt guard context.
- `Stop` / `SubagentStop`: clears AgentAegis session state.

Install:

```bash
bash adapters/codex/install.sh
```

Then restart Codex and open `/hooks` to review/trust the new hook definitions if prompted.

Runtime files are copied to `~/.codex/agent-aegis`, state is stored in
`~/.codex/agent-aegis-state`, and hooks are merged into `~/.codex/hooks.json`.

Keep Codex approvals and sandboxing enabled for host-side defense in depth.
AgentAegis hook denies stack with Codex's own approval/sandbox decisions.
