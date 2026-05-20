import os from "node:os";
/**
 * eBPF is Linux-only. We do not gate on kernel version here — BCC's runtime
 * verifier will reject programs that need newer kernel features. Reporting
 * the kernel string is purely informational.
 */
export function detectEbpfSupport(platform = process.platform) {
    if (platform !== "linux") {
        return { supported: false, platform, reason: `eBPF probe needs Linux; got ${platform}` };
    }
    return { supported: true, platform, kernel: os.release() };
}
