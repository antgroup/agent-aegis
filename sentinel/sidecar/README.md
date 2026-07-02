# Per-agent sentinel sidecar (L2/L3 kernel defense)

L2/L3 (the eBPF/uprobe/LSM kernel defense) runs as a **per-agent sidecar**: each
agent gets its OWN install dir, OWN config, OWN launcher, and its events flow into
THAT agent's state dir — so OpenClaw's and Hermes's kernel defense are fully
independent (different `sensitivePaths`, different mode, different events/WebUI),
exactly like their L1 defenses already are.

Why a sidecar (not inside the L1 plugin): eBPF needs **root**, and OpenClaw's
plugin scanner blocks `child_process`. So the probes can't live in the installed
plugin — they ship as a separate root-run component.

> Note: the raw eBPF probe is **system-wide** (one probe sees all syscalls). In a
> normal deployment you run ONE runtime per box, so each agent's sidecar is
> self-contained. Running both sidecars on one box = two probes both observing the
> whole machine (double overhead); fine for testing, not ideal for production.

## Install (per agent)

```bash
# from the cloned repo (needs: npm run build done, or it builds)
bash adapters/install-sentinel.sh openclaw   # -> ~/.openclaw/agent-aegis-sentinel/
bash adapters/install-sentinel.sh hermes     # -> ~/.hermes/agent-aegis-sentinel/
```

Each install gets: `sentinel/` (the subsystem), `config.json` (this agent's
dedicated config, with `stateDir` pointing at that agent's events dir), and
`start-sentinel.sh`.

## Configure

Edit `<install>/config.json` (or use the WebUI Config page → **Kernel Defense
(L2/L3)** section, which edits this file):

```json
{
  "stateDir": "/root/.openclaw/plugins/agent-aegis",
  "nativeJudge": { "mode": "observe", "sensitivePaths": ["/etc/shadow"], "scratchDirs": [] },
  "probes": { "ebpf": { "enabled": true }, "uprobe": { "enabled": false }, "lsm": { "enabled": false, "minSeverity": "high" } }
}
```

- `nativeJudge.mode`: `observe` (detect + log + WebUI, never block) or `enforce`.
- `ebpf`/`uprobe` are **observe-only**; **`lsm` is the only in-kernel enforce**
  (needs `nativeJudge.mode: enforce` + kernel ≥5.7 + BTF + `bpf` in
  `/sys/kernel/security/lsm`).
- `stateDir` must match the agent's WebUI `AEGIS_STATE_DIR` so L1 + L2/L3 events
  show together in that agent's Events page (the installer sets it).

Changes apply on the **next sidecar restart** (no hot reload).

## Launch (root)

```bash
sudo bash ~/.openclaw/agent-aegis-sentinel/start-sentinel.sh
# or: sudo node ~/.openclaw/agent-aegis-sentinel/sentinel/sidecar/run.mjs \
#        --config ~/.openclaw/agent-aegis-sentinel/config.json
```

Prereqs: Linux + root + BCC (`bpfcc-tools python3-bpfcc`) + `/sys/kernel/debug`
mounted. Probes fail-open (log, don't crash).

## WebUI config page

Each agent's WebUI Config page now has a **Kernel Defense (L2/L3)** section that
reads/writes this dedicated config via `GET/PUT /api/v1/sentinel-config`. The API
finds the file via `AEGIS_SENTINEL_CONFIG` (defaults by runtime:
`~/.openclaw/agent-aegis-sentinel/config.json` or the Hermes equivalent). After
saving, **restart the sidecar** for changes to take effect.
