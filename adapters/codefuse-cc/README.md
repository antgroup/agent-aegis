# AgentAegis for CodeFuse CC

This adapter installs AgentAegis as a Claude-compatible plugin for the
`cfuse --cc` engine. CodeFuse generates a runtime `--settings` payload and does
not retain custom command hooks merged directly into its settings file, so this
adapter intentionally uses the plugin mechanism instead.

It wires these events:

- `UserPromptSubmit`: scans user prompts, blocks dispatch-guard violations, and adds safety context.
- `PreToolUse`: blocks risky Bash, file edit, and MCP tool calls.
- `PostToolUse` / `PostToolUseFailure`: scans tool output and records tool results.
- `SessionStart`: adds baseline prompt guard context.
- `Stop` / `SubagentStop`: clears AgentAegis session state.

Prerequisites are Node.js 20 or newer and CodeFuse CLI with the CC engine.

Install:

```bash
bash adapters/codefuse-cc/install.sh
```

The installer builds AgentAegis, stages the plugin under
`~/.codefuse/agent-aegis-plugin`, and registers it with the CC engine's plugin
manager. Configuration is preserved at `~/.codefuse/agent-aegis/config.yaml`,
and runtime state is stored in `~/.codefuse/agent-aegis-state`.

Verify the persistent installation:

```bash
cfuse --skip-update --cc plugin list
cfuse --skip-update --cc -p "Reply with OK"
```

The plugin must be listed as enabled. A normal `cfuse --cc` invocation then
loads AgentAegis without requiring `--plugin-dir`.
