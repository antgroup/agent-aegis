# AgentAegis for Claude Code

This adapter installs AgentAegis as Claude Code command hooks.

It wires these Claude Code hook events:

- `UserPromptSubmit`: scans user prompts and adds safety context.
- `PreToolUse`: blocks risky Bash, file edit, and MCP tool calls.
- `PermissionRequest`: applies the same tool policy at permission prompts.
- `PostToolUse`: scans tool output for prompt injection and exfiltration cues.
- `SessionStart`: adds baseline prompt guard context.

Install:

```bash
bash adapters/claude-code/install.sh
```

Then restart Claude Code. Runtime files are copied to `~/.claude/agent-aegis`,
state is stored in `~/.claude/agent-aegis-state`, and hooks are merged into
`~/.claude/settings.json`.
