/**
 * JSON-RPC stdio server for AgentAegis.
 *
 * Protocol: line-delimited JSON on stdin/stdout.
 *   Request:  {"id":1, "method":"check_before_tool", "params":{...}}
 *   Response: {"id":1, "result":{...}}
 *   Error:    {"id":1, "error":{"message":"...", "code":-32000}}
 *
 * All diagnostic logging goes to stderr so it never corrupts the protocol.
 *
 * Usage:
 *   node rpc-server.js              # interactive stdio mode
 *   echo '{"id":1,...}' | node rpc-server.js   # single-shot pipe mode
 */
import { createInterface } from "node:readline";
import { AegisRpcRuntime } from "./rpc-handlers.js";
const runtime = new AegisRpcRuntime();
const rl = createInterface({
    input: process.stdin,
    terminal: false,
});
function writeLine(obj) {
    process.stdout.write(JSON.stringify(obj) + "\n");
}
rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed)
        return;
    let parsed;
    try {
        parsed = JSON.parse(trimmed);
    }
    catch {
        writeLine({
            id: null,
            error: { message: "Parse error: invalid JSON", code: -32700 },
        });
        return;
    }
    const request = parsed;
    const id = request.id ?? null;
    if (typeof request.method !== "string") {
        writeLine({
            id,
            error: { message: "Invalid request: missing method", code: -32600 },
        });
        return;
    }
    const response = await runtime.dispatch({
        id: id,
        method: request.method,
        params: request.params ?? {},
    });
    writeLine(response);
});
async function shutdown() {
    try {
        await runtime.stop();
    }
    catch {
        // best-effort — stop sentinel probes (and their subprocesses) before exit
    }
    process.exit(0);
}
rl.on("close", () => {
    void shutdown();
});
process.on("SIGTERM", () => {
    void shutdown();
});
process.on("SIGINT", () => {
    void shutdown();
});
