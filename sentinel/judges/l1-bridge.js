const JUDGE_ID = "l1-bridge";
/**
 * A Judge that delegates to the existing L1 engine for `tool_call` events.
 *
 * Probe-originated events (Frida/eBPF) are NOT routed through L1 — those go
 * to the native judge, which knows how to read syscall args. L1 was designed
 * around tool-call intent and has no concept of an `execve`/`openat` event.
 */
export function createL1BridgeJudge(engine, opts = {}) {
    const severity = opts.severity ?? "high";
    return {
        id: JUDGE_ID,
        async judge(event) {
            if (event.syscall !== "tool_call")
                return null;
            const toolName = readString(event.args.toolName) ?? event.toolName;
            if (!toolName)
                return null;
            const params = readObject(event.args.params);
            let result;
            try {
                result = engine.checkToolCall(toolName, params, event.runId, event.sessionKey);
            }
            catch (err) {
                // Let aggregator's onJudgeError surface this; abstaining is safer than
                // synthesizing a verdict from an undefined engine state.
                throw err;
            }
            if (!result || !result.block)
                return null;
            return {
                action: "block",
                severity,
                reason: result.reason ?? "blocked by L1 engine",
                judgeId: result.defense ? `${JUDGE_ID}:${result.defense}` : JUDGE_ID,
                confidence: 1,
            };
        },
    };
}
function readString(v) {
    return typeof v === "string" ? v : undefined;
}
function readObject(v) {
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
}
