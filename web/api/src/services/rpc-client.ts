/**
 * JSON-RPC client for communicating with AegisRpcRuntime.
 *
 * This client spawns the rpc-server.js as a subprocess and communicates
 * via line-delimited JSON over stdin/stdout.
 */

import { spawn, ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";

export type RpcRequest = {
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
};

export type RpcResponse = {
  id: number | string;
  result?: unknown;
  error?: { message: string; code?: number };
};

export class AegisRpcClient {
  private process: ChildProcess | null = null;
  private requestId = 0;
  private pendingRequests = new Map<
    number | string,
    { resolve: (value: RpcResponse) => void; reject: (reason: Error) => void }
  >();
  private ready = false;
  private readyCallbacks: (() => void)[] = [];
  private rpcServerPath: string;

  constructor(rpcServerPath: string) {
    this.rpcServerPath = rpcServerPath;
  }

  start(): void {
    if (this.process) {
      return;
    }

    this.process = spawn("node", [this.rpcServerPath], {
      stdio: ["pipe", "pipe", "inherit"],
    });

    const rl = createInterface({
      input: this.process.stdout!,
      terminal: false,
    });

    rl.on("line", (line) => {
      this.handleResponse(line);
    });

    this.process.on("exit", (code) => {
      console.error(`[aegis-rpc-client] RPC server exited with code ${code}`);
      this.process = null;
      this.ready = false;
    });

    this.process.on("error", (err) => {
      console.error(`[aegis-rpc-client] RPC server error:`, err);
      this.rejectAllPending(err);
    });
  }

  stop(): void {
    if (this.process) {
      this.process.kill("SIGTERM");
      this.process = null;
    }
    this.ready = false;
    this.rejectAllPending(new Error("RPC client stopped"));
  }

  private rejectAllPending(error: Error): void {
    for (const [, { reject }] of this.pendingRequests) {
      reject(error);
    }
    this.pendingRequests.clear();
  }

  private handleResponse(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const response = JSON.parse(trimmed) as RpcResponse;
      const pending = this.pendingRequests.get(response.id);
      if (pending) {
        this.pendingRequests.delete(response.id);
        pending.resolve(response);
      }
    } catch {
      // Ignore parse errors (might be log output)
    }
  }

  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    if (!this.process?.stdin) {
      throw new Error("RPC client not started");
    }

    const id = ++this.requestId;
    const request: RpcRequest = { id, method, params };

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, {
        resolve: (response) => {
          if (response.error) {
            reject(new Error(response.error.message));
          } else {
            resolve(response.result);
          }
        },
        reject,
      });

      this.process!.stdin!.write(JSON.stringify(request) + "\n");
    });
  }

  async init(config: {
    config: Record<string, unknown>;
    stateDir: string;
    pluginRootDir: string;
    skillRoots?: string[];
    protectedRoots?: string[];
  }): Promise<void> {
    await this.call("init", config);
    this.ready = true;
    this.flushReadyCallbacks();
  }

  private flushReadyCallbacks(): void {
    for (const cb of this.readyCallbacks) {
      cb();
    }
    this.readyCallbacks = [];
  }

  async whenReady(): Promise<void> {
    if (this.ready) return;
    return new Promise((resolve) => {
      this.readyCallbacks.push(resolve);
    });
  }

  isReady(): boolean {
    return this.ready;
  }

  async getConfig(): Promise<Record<string, unknown>> {
    return this.call("get_config", {}) as Promise<Record<string, unknown>>;
  }

  async scanSkills(params: { roots: string[] }): Promise<{ scanned: number }> {
    return this.call("scan_skills", params) as Promise<{ scanned: number }>;
  }
}
