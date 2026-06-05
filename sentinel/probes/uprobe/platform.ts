import fs from "node:fs";
import os from "node:os";

export interface UprobeSupport {
  supported: boolean;
  platform: NodeJS.Platform;
  /** Linux kernel version string (informational). */
  kernel?: string;
  /** Detected libc path used as default uprobe attach target. */
  defaultLibc?: string;
  reason?: string;
}

const LIBC_CANDIDATES = [
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/lib/aarch64-linux-gnu/libc.so.6",
  "/lib64/libc.so.6",
  "/usr/lib/libc.so.6",
  "/lib/libc.musl-x86_64.so.1",
  "/lib/libc.musl-aarch64.so.1",
];

/**
 * Uprobes are Linux-only. We additionally probe for a libc path because the
 * BCC runner needs to attach by absolute path — distros vary widely. Caller
 * can override via UprobeProbeOptions.libcPath when our guess is wrong.
 */
export function detectUprobeSupport(
  platform: NodeJS.Platform = process.platform,
): UprobeSupport {
  if (platform !== "linux") {
    return {
      supported: false,
      platform,
      reason: `uprobe probe needs Linux; got ${platform}`,
    };
  }
  const defaultLibc = LIBC_CANDIDATES.find((p) => {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  });
  return {
    supported: true,
    platform,
    kernel: os.release(),
    defaultLibc,
  };
}
