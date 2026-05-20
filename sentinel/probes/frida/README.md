# Frida probe

User-space syscall observer for the sentinel pipeline (M4, observe-only).

## When this runs

The probe is **opt-in**. It only starts when the runtime config sets:

```yaml
# OpenClaw: openclaw.plugin.json -> userConfig
probes:
  frida:
    enabled: true
    # optional subset; default = full POSIX set
    targets: [execve, openat, connect]
```

With the default config the loader does nothing — `npm install` does not
require `frida` and the bundle ships clean.

## Platform support

| Platform | M4 status | Notes |
|---|---|---|
| Linux | supported | Needs `CAP_SYS_PTRACE` or root on most distros. |
| macOS | supported | Needs codesign / SIP off / `com.apple.security.cs.debugger` entitlement. |
| Windows | placeholder | `agent-win.js` exists; native hook code is a future PR. |

## How to actually try it

1. Install Frida: `npm install --include=optional frida`.
2. Enable the probe in OpenClaw's plugin config.
3. Start OpenClaw. Look for two log lines:
   - `[claw-aegis] sentinel started: 1 probes, 2 judges …`
   - `[frida] attached pid=<N>, requested=execve,openat,connect`
   - `[frida.agent] ready; hooks installed: execve,openat,connect`
4. Trigger a syscall from inside the agent's Node process (a direct
   `child_process.execFileSync` call counts because the libc symbol is
   invoked in-process). Check
   `<stateDir>/sentinel/probe-events/events-YYYY-MM-DD.jsonl` for the
   captured event and any `verdict` records the native judge emitted.

## Scope reminder

M4 only attaches to the **OpenClaw main process**. Syscalls inside
child processes spawned by tools are out of scope and will be covered by the
eBPF probe in M5. Frida enforce-mode (blocking syscalls based on judge
verdicts) is a separate milestone (M4.5).
