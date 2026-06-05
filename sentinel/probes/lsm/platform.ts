import fs from "node:fs";
import os from "node:os";

export interface LsmSupport {
  supported: boolean;
  platform: NodeJS.Platform;
  kernel?: string;
  /** Whether `bpf` appears in the active LSMs (/sys/kernel/security/lsm). */
  bpfLsmActive?: boolean;
  reason?: string;
}

const LSM_SYSFS = "/sys/kernel/security/lsm";

/**
 * eBPF LSM hooks require:
 *  - Linux kernel ≥ 5.7 with CONFIG_BPF_LSM=y
 *  - bpf listed in /sys/kernel/security/lsm at boot (kernel.lsm sysctl /
 *    cmdline `lsm=...,bpf`)
 *
 * Caller is expected to gate registration on this. If unsupported, the probe
 * loader logs an info and returns silently so sentinel keeps running.
 */
export function detectLsmSupport(
  platform: NodeJS.Platform = process.platform,
): LsmSupport {
  if (platform !== "linux") {
    return {
      supported: false,
      platform,
      reason: `LSM probe needs Linux; got ${platform}`,
    };
  }
  const kernel = os.release();
  if (!kernelAtLeast(kernel, 5, 7)) {
    return {
      supported: false,
      platform,
      kernel,
      reason: `LSM probe needs kernel ≥ 5.7; got ${kernel}`,
    };
  }
  let bpfLsmActive = false;
  try {
    const content = fs.readFileSync(LSM_SYSFS, "utf-8");
    bpfLsmActive = content
      .split(",")
      .map((s) => s.trim())
      .includes("bpf");
  } catch {
    return {
      supported: false,
      platform,
      kernel,
      reason: `could not read ${LSM_SYSFS}; kernel may lack CONFIG_BPF_LSM`,
    };
  }
  if (!bpfLsmActive) {
    return {
      supported: false,
      platform,
      kernel,
      bpfLsmActive,
      reason: `bpf is not in active LSMs; enable via kernel cmdline lsm=...,bpf or sysctl kernel.lsm`,
    };
  }
  return { supported: true, platform, kernel, bpfLsmActive };
}

function kernelAtLeast(release: string, major: number, minor: number): boolean {
  // os.release() returns e.g. "6.5.0-15-generic" — parse the numeric prefix.
  const m = release.match(/^(\d+)\.(\d+)/);
  if (!m) return true; // unknown format → don't gate
  const maj = parseInt(m[1], 10);
  const min = parseInt(m[2], 10);
  if (maj > major) return true;
  if (maj < major) return false;
  return min >= minor;
}
