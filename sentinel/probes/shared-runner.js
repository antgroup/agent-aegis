import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
/**
 * Absolute path to the unified libbpf CO-RE runner binary (M8).
 *
 * A single Go binary with `--mode={ebpf,uprobe,lsm}`, built from
 * `probes/lsm/runner/Makefile` into `dist/sentinel-runner`. It embeds both
 * BPF objects (`exec.bpf.o`, `lsm.bpf.o`) and replaces the per-mode BCC Python
 * runners on production Linux.
 */
export const UNIFIED_RUNNER_BIN = path.join(HERE, "lsm", "runner", "dist", "sentinel-runner");
/**
 * Return the unified runner path if it has been built, else `null`.
 *
 * The ebpf/uprobe loaders call this to prefer the native CO-RE binary over the
 * legacy BCC Python runner whenever it is available — without requiring an
 * explicit `runnerBin` in config. When the binary has not been built (e.g. dev
 * machines, CI without the Go toolchain), the loaders fall back to Python.
 *
 * @param exists Injectable existence check — defaults to `fs.existsSync`. Lets
 *   tests exercise the prefer/fallback branches deterministically.
 */
export function resolveUnifiedRunner(exists = fs.existsSync) {
    return exists(UNIFIED_RUNNER_BIN) ? UNIFIED_RUNNER_BIN : null;
}
