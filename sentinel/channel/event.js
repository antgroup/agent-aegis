import { randomUUID } from "node:crypto";
import { EVENT_SCHEMA_VERSION, } from "./schema.js";
export function createProbeEvent(input) {
    return {
        schema: EVENT_SCHEMA_VERSION,
        id: input.id ?? randomUUID(),
        timestamp: input.timestamp ?? Date.now(),
        source: input.source,
        syscall: input.syscall,
        pid: input.pid,
        args: input.args,
        sessionKey: input.sessionKey,
        runId: input.runId,
        toolName: input.toolName,
        meta: input.meta,
    };
}
