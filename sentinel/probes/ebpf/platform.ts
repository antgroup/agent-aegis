import os from "node:os";

export interface EbpfSupport {
  supported: boolean;
  platform: NodeJS.Platform;
  /** Linux kernel version string (informational only; eBPF feature gating left to BCC). */
  kernel?: string;
  reason?: string;
}

/**
 * eBPF is Linux-only. We do not gate on kernel version here — BCC's runtime
 * verifier will reject programs that need newer kernel features. Reporting
 * the kernel string is purely informational.
 */
export function detectEbpfSupport(platform: NodeJS.Platform = process.platform): EbpfSupport {
  if (platform !== "linux") {
    return { supported: false, platform, reason: `eBPF probe needs Linux; got ${platform}` };
  }
  return { supported: true, platform, kernel: os.release() };
}
