/**
 * Shared security-relevant path and network patterns.
 *
 * Used by both the M11 CausalChainDetector and the M11.5 FeatureExtractor /
 * BehavioralSnapshot so that detection and feature extraction agree on what
 * counts as "sensitive" or "external."
 */
/** Sensitive paths that indicate credential / secret access. */
export const SENSITIVE_PATTERNS = [
    /\/etc\/shadow\b/i,
    /\/etc\/passwd\b/i,
    /\/etc\/ssh\b/i,
    /\/\.ssh\b/i,
    /\/\.env\b/i,
    /\/\.aws\b/i,
    /\/\.gcp\b/i,
    /\/\.kube\b/i,
];
/** Writable directories commonly used for payload staging. */
export const WRITABLE_DIR_PATTERNS = [
    /\/tmp\//i,
    /\/var\/tmp\//i,
    /\/dev\/shm\//i,
    /\/tmp$/i,
    /\/var\/tmp$/i,
    /\/dev\/shm$/i,
];
/**
 * Check if a network address looks external (not loopback or RFC-1918 private).
 * Returns `true` for addresses that are NOT in private/loopback ranges.
 */
export function isExternalAddr(addr) {
    if (addr.startsWith("127.") || addr === "0.0.0.0" || addr === "::1")
        return false;
    if (addr.startsWith("10."))
        return false;
    if (addr.startsWith("172.")) {
        // 172.16.0.0 – 172.31.255.255
        const second = parseInt(addr.split(".")[1] ?? "0", 10);
        if (second >= 16 && second <= 31)
            return false;
    }
    if (addr.startsWith("192.168."))
        return false;
    return true;
}
