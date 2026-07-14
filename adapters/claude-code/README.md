# AgentAegis for Claude Code

This adapter installs AgentAegis as Claude Code command hooks.

It wires these Claude Code hook events:

- `UserPromptSubmit`: scans user prompts, blocks dispatch-guard violations, and adds safety context.
- `PreToolUse`: blocks risky Bash, file edit, and MCP tool calls.
- `PostToolUse`: scans tool output for prompt injection and exfiltration cues, then adds warning context.
- `SessionStart`: adds baseline prompt guard context.
- `Stop` / `SubagentStop`: clears AgentAegis session state.

Install:

```bash
bash adapters/claude-code/install.sh
```

Then restart Claude Code. Runtime files are copied to `~/.claude/agent-aegis`,
state is stored in `~/.claude/agent-aegis-state`, and hooks are merged into
`~/.claude/settings.json`.
Runtime state is persisted in the state directory so short-lived hook processes
can share run/session context for multi-step defenses.

Claude Code blocking is enforced through `PreToolUse`; completed tool output
cannot be undone by `PostToolUse`, so AgentAegis reports risky output as
additional context for the next model step.
