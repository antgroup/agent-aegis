# AgentAegis

<p align="center"> 
  <a href="README.md">English</a>
  |
  <a href="README_zh.md">简体中文</a>
</p>


> AgentAegis builds a multi-dimensional, defense-in-depth runtime security architecture for OpenClaw-style agents, implementing five-layer defense across the full lifecycle of LLM agents in various Claw environments — from initialization to execution — covering security and reliability risks in agent execution services, including skill poisoning, memory contamination, intent misalignment, malicious execution, and resource exhaustion. As a lightweight built-in security plugin, AgentAegis proactively triggers defense mechanisms at critical OpenClaw stages to dynamically safeguard agent runtime security. It also provides configurable risk identification and response policies for security operators to flexibly and extensibly address agent runtime threats, as well as sensitive file and skill asset protection for everyday users to safeguard personal privacy and assets.
> 



---

## 💫 Architecture

<p align="center">
  <img src="https://github.com/user-attachments/assets/b44e3807-4b4b-4dc8-a6ac-c6b8d24501a2" alt="AgentAegis Architecture" width="100%" />
</p>

AgentAegis builds a multi-dimensional, defense-in-depth architecture for OpenClaw, forming a complete security closed loop across the full lifecycle from initialization to execution. The system consists of five core defense layers:

- **Foundation Scan Layer** — Ensures the trustworthiness of the underlying environment, establishing a solid security foundation from the initialization stage.
- **Perception Input Layer** — Strictly filters and audits both internal and external instructions, intercepting malicious injections and high-risk requests.
- **Cognitive State Layer** — Monitors the agent's internal state in real time, preventing memory corruption and context contamination.
- **Decision Alignment Layer** — Validates intent during the logic generation phase to ensure output decisions align with the user's true intent. Ambiguous instructions require secondary user confirmation to eliminate intent deviation risks.
- **Execution Control Layer** — Enforces permission management before final operations, ensuring all instructions execute within controlled security boundaries.

Through this layered, progressive mechanism, AgentAegis ensures that OpenClaw possesses fine-grained risk mitigation capabilities at every critical link in the chain, neutralizing potential threats before they materialize. Furthermore, as a built-in security plugin — unlike passive defense mechanisms such as prompt-based or skill-based defenses — AgentAegis can proactively trigger defense mechanisms at critical OpenClaw stages, dynamically safeguarding runtime security.

---

## 🚀 Quick Start

AgentAegis runs on two agent runtimes. Each section below is self-contained: **install → enable → start the WebUI**.

### For OpenClaw — `openclaw@latest`

**Prerequisites:** Node.js ≥ 20 and the latest OpenClaw CLI.

```bash
npm install -g openclaw@latest
openclaw --version
```

**1.** Clone and build the plugin (it ships as TypeScript):

```bash
git clone https://github.com/antgroup/AgentAegis.git
cd AgentAegis
npm install && npm run build
```

**2.** Install it into OpenClaw — this copies the plugin to `~/.openclaw/extensions/agent-aegis`:

```bash
openclaw plugins install ./AgentAegis
```

> ℹ️ The kernel probes (`sentinel/probes/{ebpf,uprobe,lsm}`) are **not** part of this
> package — they need root and spawn helpers via `node:child_process`, which
> OpenClaw's plugin scanner blocks. The L1 tool-call defenses install and run
> normally; the kernel layer (L2/L3) installs separately as a **per-agent sidecar**
> (see *Kernel-Level Defense → Enable* below).

**3.** Trust it and restart the gateway so it loads. Add `agent-aegis` to `plugins.allow` in `~/.openclaw/openclaw.json`, then verify:

```bash
openclaw plugins list      # agent-aegis -> enabled
```

**4.** (Optional) Tune defenses via the `userConfig` block in `openclaw.plugin.json` — roll out in `observe`, then promote high-confidence defenses to `enforce`:

```json
{
  "allDefensesEnabled": true,
  "defaultBlockingMode": "observe",
  "selfProtectionMode": "enforce",
  "commandBlockMode": "enforce",
  "memoryGuardMode": "enforce",
  "exfiltrationGuardMode": "enforce"
}
```

**5.** Start the WebUI (served from the installed plugin's `web/` directory):

```bash
# macOS / Linux
cd ~/.openclaw/extensions/agent-aegis/web
# Windows: cd %USERPROFILE%\.openclaw\extensions\agent-aegis\web
npm install && npm run build && npm start
```

Open `http://localhost:3800`.

### For Hermes Agent — `hermes-agent@latest`

**Prerequisites:** Node.js ≥ 20, Python 3, and the latest Hermes Agent installed (`hermes --version`).

**1.** Clone and run the automated installer. It builds the engine + WebUI and installs everything to `~/.hermes/plugins/agent-aegis` (engine, RPC server, config, state dir):

```bash
git clone https://github.com/antgroup/AgentAegis.git
cd AgentAegis
bash adapters/hermes/install.sh
```

**2.** Enable the plugin — use the CLI (it writes `plugins.enabled` in `~/.hermes/config.yaml`):

```bash
hermes plugins enable agent-aegis
hermes plugins list                 # agent-aegis -> enabled
```

> Equivalent manual edit (instead of the CLI): add `agent-aegis` under `plugins.enabled` in `~/.hermes/config.yaml`.

**(Optional) Let AgentAegis own blocking.** AgentAegis's defenses work regardless of Hermes's own approval mode — the two are independent. But if Hermes `approvals.mode` is `manual`/`smart`, a dangerous operation gets prompted by **both** Hermes and AgentAegis (double prompts), and `manual` can hang in non-interactive runs. To make AgentAegis the single gate, set `approvals.mode: off` in `~/.hermes/config.yaml`:

```yaml
approvals:
  mode: off
```

Keep `manual` if you deliberately want Hermes's human approval as an extra layer.

**3.** Restart Hermes. Review defense settings in `~/.hermes/plugins/agent-aegis/config.yaml`.

**4.** Start the WebUI with the standalone launcher (run from the cloned repo):

```bash
cd AgentAegis
./start-web-hermes.sh
```

Open `http://localhost:3800`. Alternatively, set `webPort: 3800` in `~/.hermes/plugins/agent-aegis/config.yaml` to start the WebUI automatically alongside the agent.

---

## ⚠️ Operational notes

- **Config changes require a restart.** Both runtimes read the defense config only at startup. After editing the config file (`config.yaml` for Hermes, `openclaw.plugin.json` for OpenClaw) or changing settings in the WebUI, restart the agent — a running session keeps the old config. (For Hermes, make sure the old `rpc-server.js` child process has exited before restarting.)
- **`observe` logs, `enforce` blocks.** A defense in `observe` mode records detections but lets the action through; only `enforce` actually blocks. Roll out in `observe`, then promote high-confidence defenses to `enforce`.
- **Hermes must load plugins to defend.** Use the gateway / interactive chat — `hermes -z` (oneshot) loads no plugins, so no defense runs. On startup the log should report `N high-risk tools wrapped` with N > 0, which is what arms tool-call blocking. Set `approvals.mode: off` to let AgentAegis own blocking.

---

## ✨ Features

### Runtime Defense

AgentAegis provides a set of built-in runtime defenses that cover the full agent lifecycle. These defenses detect and mitigate threats automatically without requiring additional configuration.

- **Five-Layer Defense-in-Depth** — Covers intent scanning, tool call governance, tool result inspection, asset protection, and output safeguarding across nine OpenClaw lifecycle hooks.
- **Skill Poisoning Defense** — Scans skill content at startup and continuously, detecting malicious payloads that attempt to bypass approval, disable safety controls, or tamper with protected assets.
- **Memory Contamination Guard** — Rejects suspicious or oversized writes to persistent memory stores (`memory_store`, `MEMORY.md`, `SOUL.md`, `memory/`), preventing persistent prompt poisoning across sessions.
- **Intent & Prompt Safety** — Detects jailbreak attempts, secret-exfiltration requests, and plugin-tampering intent in user messages, then injects safety context into prompts to influence subsequent model reasoning.
- **Tool Call Governance** — Blocks high-risk shell commands, encoded/obfuscated payloads, write-then-execute chains, repeated mutation loops, and SSRF/exfiltration chains before tool execution.
- **Tool Result Inspection** — Treats external tool outputs as untrusted input, scanning for prompt-injection, secret-request, and escalation patterns before they affect the next reasoning step.
- **Output Redaction** — Masks API keys, tokens, and similar sensitive values before assistant output is sent or stored.

### Advanced Configurable Defense

Beyond the built-in runtime defenses, AgentAegis gives security operators and end users a configurable control surface for advanced risk management and asset protection.

- **Configurable Security Operations** — Operators can enable all defenses globally with `allDefensesEnabled`, set a fleet-wide baseline with `defaultBlockingMode`, and override individual controls such as `selfProtectionMode`, `commandBlockMode`, `memoryGuardMode`, and `exfiltrationGuardMode`. Each defense supports `enforce`, `observe`, and `off` modes, enabling staged rollout from monitoring to active blocking. Operators can also define `protectedPaths`, `protectedSkills`, and `protectedPlugins` to match the assets that matter in their environment, and use `startupSkillScan` to identify risky skills early. Detections are surfaced as runtime observations, blocked actions, and promoted prompt warnings, giving defenders actionable signals for triage and response.
- **Sensitive Files and Skill Asset Protection** — Sensitive files and directories can be added to `protectedPaths` to block or observe unauthorized reads, writes, deletes, and tampering. High-value skills and important plugins can be registered via `protectedSkills` and `protectedPlugins` to prevent deletion, overwrite, or patch-based mutation of skill and plugin assets. Self-protection reduces the chance that the agent disables its own defenses or silently rewrites security configuration. For personal users, this means safer handling of private notes, documents, and custom skills; for organizations, it means stronger protection for operational runbooks, audit plugins, and security-critical configuration.

---

## 🛠️ Project Structure

```
AgentAegis/
├── index.ts                    # OpenClaw plugin entry — registers lifecycle hooks
├── runtime-api.ts              # OpenClaw plugin API type definitions
├── rpc-server.ts               # JSON-RPC server exposing the engine (driven by the Hermes bridge)
├── rpc-handlers.ts             # RPC method handlers (check_before_tool, check_user_input, …)
├── __init__.py                 # Hermes proxy entry — delegates to adapters/hermes/
├── openclaw.plugin.json        # OpenClaw manifest (config schema + UI hints)
├── plugin.yaml                 # Hermes plugin manifest
├── package.json                # Package metadata (@openclaw/agent-aegis)
├── start-web-hermes.sh         # Standalone Hermes WebUI launcher
│
├── src/                        # Detection engine — shared by both runtimes
│   ├── engine.ts               # Core defense engine + defense-event logging
│   ├── handlers.ts             # Lifecycle hook handlers / runtime logic
│   ├── rules.ts                # Detection rules and scanning logic
│   ├── security-strategies.ts  # Defense strategy definitions and patterns
│   ├── command-obfuscation.ts  # Shell command obfuscation detection
│   ├── encoding-guard.ts       # Encoded payload detection
│   ├── scan-service.ts         # Skill scanning service with queue management
│   ├── scan-worker.ts          # Per-skill scan worker
│   ├── state.ts                # In-memory and persisted state management
│   ├── config.ts               # Configuration resolution and constants
│   └── types.ts                # Core domain types (TurnSecurityState, etc.)
│
├── adapters/                   # Per-runtime adapters & installers
│   ├── install-sentinel.sh     # Per-agent L2/L3 sidecar installer (openclaw | hermes)
│   └── hermes/                 # Hermes Agent adapter (Python ↔ Node bridge)
│       ├── __init__.py         # Plugin register() — wires hooks + wraps tools
│       ├── bridge.py           # Spawns rpc-server.js; JSON-RPC over stdio
│       ├── tool_wrappers.py    # Wraps high-risk tools for in-flight blocking
│       ├── paths.py            # Resolves plugin / state / config paths
│       ├── web-server.py       # Manages the WebUI subprocess
│       ├── install.sh          # Automated Hermes (L1) installer
│       ├── plugin.yaml         # Hermes manifest
│       └── config.yaml         # Default defense config template
│
├── sentinel/                   # Framework-agnostic L2/L3 kernel-defense subsystem
│   ├── channel/                # Probe events + append-only JSONL store + pub-sub
│   ├── judges/                 # Decision logic (native judge: sensitive-path / kernel-escape)
│   ├── probes/                 # Syscall sources — ebpf/ (tracepoint), uprobe/ (libc), lsm/ (enforce)
│   ├── runtime/                # Agent-framework abstraction (noop / openclaw / hermes adapters)
│   ├── sidecar/                # Per-agent standalone runner (run.mjs + config.example.json)
│   ├── bootstrap.ts            # Wires probes + judges from config
│   └── index.ts                # startSentinel(runtime) + SentinelHandle
│
├── web/                        # WebUI management panel
│   ├── shared/                 # Shared types, Zod schemas, defense group metadata
│   ├── api/                    # Express backend (routes: config / sentinel-config / status / events / skills)
│   └── frontend/               # React + Vite + TailwindCSS frontend (Dashboard, Config, Events, Skills)
│
└── docs/                       # WebUI screenshots
```

---

## 🛡️ Kernel-Level Defense — eBPF / Sentinel (experimental, Linux)

The defenses above run at **L1** — the agent's tool-call layer (prompt / tool /
tool-result hooks). The framework-agnostic `sentinel/` subsystem adds deeper
layers that watch raw **syscalls**, so it catches threats that never pass
through the agent's tool registry: obfuscated `execve` payloads, sub-process
file access, and direct kernel-level exfiltration.

| Layer | Probe | What it sees |
|---|---|---|
| **L1** | tool-call hooks | agent-level tool intent (always on) |
| **L2** | `uprobe` | user-space libc / OpenSSL symbols (`execve`, `openat`, `connect`, `SSL_read/write`) |
| **L3** | `ebpf` tracepoints | system-wide syscalls (observe) |
| **L3** | `lsm` (LSM-BPF) | in-kernel **enforce** — denies high-severity verdicts before the syscall completes |

Captured syscalls are scored by the **native judge** (`sentinel/judges/native.ts`):
sensitive-path access (e.g. any read of `/etc/shadow`), `execve` from scratch
dirs (`/tmp`, `/dev/shm`, `/var/tmp`), and process-tree anomalies. Every event +
verdict is persisted as JSONL and forwarded to the **WebUI Events page**.

### Modes

- **observe** (default) — detect, log, and surface to the WebUI, but never
  intercept (the operation runs). Safe for rollout / data collection.
- **enforce** — the `lsm` probe denies high-severity syscalls in-kernel.

### Enable — per-agent sidecar (recommended)

Because eBPF needs **root** and OpenClaw's plugin scanner blocks
`child_process`, the kernel probes can't live inside the installed L1 plugin.
They ship instead as a **per-agent sidecar**: each agent gets its OWN install
dir, OWN config, OWN launcher, and its events flow into THAT agent's state dir —
so OpenClaw's and Hermes's kernel defense stay as independent as their L1
defenses already are.

```bash
# install the L2/L3 sidecar for a runtime (builds sentinel/ if needed)
bash adapters/install-sentinel.sh openclaw   # -> ~/.openclaw/agent-aegis-sentinel/
bash adapters/install-sentinel.sh hermes     # -> ~/.hermes/agent-aegis-sentinel/
```

Each install gets `sentinel/` (the subsystem), `config.json` (this agent's
dedicated L2/L3 config, with `stateDir` pre-pointed at that agent's events dir so
L1 + L2/L3 events show together), and `start-sentinel.sh`. Launch it as root:

```bash
sudo bash ~/.openclaw/agent-aegis-sentinel/start-sentinel.sh
```

Configure it by editing `<install>/config.json`, or visually from the **WebUI
Config page → Kernel Defense (L2/L3)** section (it reads/writes this exact file
via `GET/PUT /api/v1/sentinel-config`):

```json
{
  "stateDir": "/root/.openclaw/plugins/agent-aegis",
  "nativeJudge": { "mode": "observe", "sensitivePaths": ["/etc/shadow"], "scratchDirs": [] },
  "probes": { "ebpf": { "enabled": true }, "uprobe": { "enabled": false }, "lsm": { "enabled": false, "minSeverity": "high" } }
}
```

For active in-kernel blocking set `nativeJudge.mode: enforce` **and**
`probes.lsm.enabled: true` (the `ebpf`/`uprobe` probes are observe-only; `lsm`
is what blocks in-kernel). Extend coverage without code via
`nativeJudge.sensitivePaths` / `nativeJudge.scratchDirs`. Changes apply on the
**next sidecar restart** (no hot reload) — see `sentinel/sidecar/README.md`.

> Hermes can alternatively enable the same probes in-process from its plugin
> `config.yaml` (`nativeJudge` / `probes` block, shipped disabled) instead of
> running the sidecar — but the sidecar is the recommended per-agent path for
> both runtimes.

**Requirements:** a Linux kernel with eBPF, root, BCC (`bpfcc-tools`,
`python3-bpfcc`), and `/sys/kernel/debug` mounted. On macOS/Windows use the
Docker harnesses below (privileged Linux container via OrbStack / Docker Desktop).
Probes fail-open — if they can't attach, it's logged and the agent keeps running.

### Standalone eBPF launch (any runtime, incl. OpenClaw)

The probes are decoupled from the plugin — run them straight from the cloned repo,
no agent required. Three levels, simplest first:

```bash
# L0 — raw probe (Linux + root + BCC): syscalls as JSONL on stdout
sudo python3 sentinel/probes/ebpf/runner/probe.py --targets execve,openat,connect
#   then, in another shell: cat /etc/shadow ; ls /etc
#   → {"kind":"ready",...} then {"kind":"syscall","syscall":"openat","path":"/etc/shadow",...}

# L1 — full pipeline (probe → native judge → verdict), no Docker (Linux + root)
npm run build && sudo node sentinel/probes/ebpf/verify-e2e.mjs   # PASS = cat /etc/shadow → BLOCK
```

For a containerized run that works on any OS (macOS/Windows via OrbStack / Docker
Desktop), use the one-command harnesses in **Verify** below.

### Verify (one command, any OS with Docker)

```bash
npm run e2e:ebpf    # eBPF tracepoints catch `cat /etc/shadow`; native judge → block (enforce)
npm run e2e:lsm     # LSM-BPF denies the syscall in-kernel (enforce)
npm run e2e:uprobe  # user-space libc / OpenSSL symbol probe

# Observe mode + WebUI: detect-but-don't-block, forward detections to the
# WebUI on http://localhost:3800, and open the browser:
npm run observe:live      # OpenClaw-style wiring (noop runtime + eBPF probe)
npm run observe:hermes    # drives the REAL Hermes RPC init path (rpc-server.js)
```

Each harness builds a privileged Linux container, triggers `cat /etc/shadow`,
and asserts the native judge produced the expected verdict (block in enforce,
observed in observe mode). See `sentinel/README.md` for the subsystem's
directory layout, dependency rules, and how to add new probes / judges.

---

## 🖥️ WebUI

AgentAegis includes a standalone Web management panel for visually configuring defense policies, viewing security status, browsing event logs, and managing Skill scans.

### Starting the WebUI

The **[Quick Start](#-quick-start)** above already covers starting the WebUI for each runtime. In short, the panel runs on `http://localhost:3800`:

- **OpenClaw:** `npm install && npm run build && npm start` from `~/.openclaw/extensions/agent-aegis/web`
- **Hermes:** `./start-web-hermes.sh` from the cloned repo (or set `webPort: 3800` in the plugin `config.yaml`)

For development mode with hot-reload:

```bash
npm run dev
```

### Feature Pages

**Dashboard** — Defense status overview, 12-defense status matrix, self-integrity status, Trusted Skills count, and recent security events.

<p align="center">
  <img src="docs/webui-dashboard-en.png" alt="WebUI Dashboard" width="90%" />
</p>

**Config** — Master controls (global toggle + default blocking mode), per-defense cards, Protected Assets tag editor, a **Kernel Defense (L2/L3)** section that edits this agent's sidecar config, and Advanced options. Supports dirty-state tracking with Save / Reset to Defaults.

<p align="center">
  <img src="docs/webui-config-en.png" alt="WebUI Config" width="90%" />
</p>

**Events** — Security event log with filtering by defense type and result (blocked / observed / clear), auto-refreshing every 10 seconds.

<p align="center">
  <img src="docs/webui-events-en.png" alt="WebUI Events" width="90%" />
</p>

**Skills** — Trusted Skills list (path, hash, size, scan time) with manual removal support.

<p align="center">
  <img src="docs/webui-skills-en.png" alt="WebUI Skills" width="90%" />
</p>

### Configuration Parameters

AgentAegis defense parameters are stored in `openclaw.plugin.json` under the `userConfig` field. You can modify them in two ways:

**Method 1: Via WebUI (Recommended)**

Open the WebUI Config page, toggle switches and select modes visually, then click **Save**.

**Method 2: Via JSON**

Edit `openclaw.plugin.json` directly and add or modify the `userConfig` field:

```json
{
  "userConfig": {
    "allDefensesEnabled": true,
    "defaultBlockingMode": "enforce",
    "selfProtectionEnabled": true,
    "selfProtectionMode": "enforce",
    "commandBlockEnabled": true,
    "commandBlockMode": "enforce",
    "memoryGuardEnabled": true,
    "memoryGuardMode": "observe",
    "protectedPaths": ["/path/to/sensitive/file"],
    "protectedSkills": ["my-important-skill"],
    "protectedPlugins": ["audit-guard"]
  }
}
```

**Parameter Reference:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allDefensesEnabled` | boolean | `true` | Master switch for all defenses |
| `defaultBlockingMode` | `off` / `observe` / `enforce` | `enforce` | Default mode for all blocking defenses |
| `selfProtectionEnabled` | boolean | `true` | Protect sensitive paths, skills, and plugins |
| `selfProtectionMode` | `off` / `observe` / `enforce` | `enforce` | Mode for protected-path defenses |
| `commandBlockEnabled` | boolean | `true` | Block high-risk shell commands (e.g., `rm -rf /`, `curl \| sh`) |
| `commandBlockMode` | `off` / `observe` / `enforce` | `enforce` | Mode for command blocking |
| `encodingGuardEnabled` | boolean | `true` | Detect encoded/obfuscated payloads |
| `encodingGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for encoding guard |
| `scriptProvenanceGuardEnabled` | boolean | `true` | Track and block risky scripts written in current run |
| `scriptProvenanceGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for script provenance guard |
| `memoryGuardEnabled` | boolean | `true` | Reject suspicious memory writes |
| `memoryGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for memory guard |
| `loopGuardEnabled` | boolean | `true` | Stop repeated mutating tool calls |
| `loopGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for loop guard |
| `exfiltrationGuardEnabled` | boolean | `true` | Block SSRF/exfiltration chains |
| `exfiltrationGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for exfiltration guard |
| `dispatchGuardEnabled` | boolean | `true` | Intercept dangerous messages targeting protected resources |
| `dispatchGuardMode` | `off` / `observe` / `enforce` | `enforce` | Mode for dispatch guard |
| `userRiskScanEnabled` | boolean | `true` | Detect jailbreak and tampering in user messages |
| `skillScanEnabled` | boolean | `true` | Enable skill scanning |
| `toolResultScanEnabled` | boolean | `true` | Scan tool results for injection patterns |
| `outputRedactionEnabled` | boolean | `true` | Mask API keys and tokens in output |
| `promptGuardEnabled` | boolean | `true` | Inject safety reminders into prompts |
| `toolCallEnforcementEnabled` | boolean | `true` | Require destructive ops to go through tool calls |
| `protectedPaths` | string[] | `[]` | Additional paths to protect |
| `protectedSkills` | string[] | `[]` | Additional skill IDs to protect |
| `protectedPlugins` | string[] | `[]` | Additional plugin IDs to protect |
| `startupSkillScan` | boolean | `true` | Run skill scan at startup |

> **Mode values**: `enforce` = block and log, `observe` = log only (allow through), `off` = disabled.

---

## 🎬 Visualization

OpenClaw can be deployed locally by individual users or remotely by service providers — both scenarios introduce distinct security risks. The demos below illustrate how AgentAegis defends against real-world threats in each context.

### For Individual Users (To C)

Locally deployed agents face risks from ambiguous intent, resource waste, and skill poisoning that directly impact the user's files, tokens, and privacy.

<div align="center">
<table>
<tr>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">Ambiguous Intent Causes File Deletion</p><video title="Ambiguous Intent - File Deletion" alt="A vague user instruction leads the agent to delete all project files" src="https://github.com/user-attachments/assets/230fcc05-acaa-4e79-8839-afd623639ef3" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">Skill Poisoning Leaks Privacy</p><video title="Skill Poisoning - Privacy Leakage" alt="A poisoned skill exfiltrates sensitive user data to an external server" src="https://github.com/user-attachments/assets/37524f92-cf8c-4c79-a503-ca3a60642439" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
</tr>
</table>
</div>

### For Service Providers (To B)

Remotely deployed agents face risks from API key theft, dangerous command execution, and indirect prompt injection that threaten service availability and data security.

<div align="center">
<table>
<tr>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">API Key Leakage — Token Theft</p><video title="API Key Leakage - Token Theft" alt="An attacker reads ~/.openclaw/agents/main/agent/models.json to steal the API key" src="https://github.com/user-attachments/assets/78b60004-a500-4446-bfbb-a5dab87ddcde" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">Indirect Prompt Injection — Data Leakage</p><video title="Indirect Prompt Injection - Data Leakage" alt="Injected instructions in external content cause the agent to exfiltrate data" src="https://github.com/user-attachments/assets/ed72a4b8-0f5b-409d-8d1e-447fb3f1ec09" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
</tr>
</table>
</div>

---

## 🔭 Future Work

- Provenance-aware trust scoring for skills, memory entries, tool outputs, and generated scripts, enabling policies that react to origin and historical behavior.
- Cross-session and cross-agent attack graphing to correlate risky intent, tool calls, tool results, memory writes, and outbound requests into unified incident timelines.
- Adaptive policies that automatically tune `observe` and `enforce` decisions based on deployment environment, task type, and operator feedback.
- Autonomous containment workflows that quarantine risky skills, freeze sensitive memory namespaces, and recommend recovery actions.
- Shared safety state for multi-agent systems, enabling collaborating agents to exchange risk context and coordinate containment.
- Continuous red-team evaluation pipelines that replay emerging jailbreaks, encoded payloads, skill-poisoning samples, and tool-chain abuse techniques against new releases.
- Explainable defense reports that translate low-level detections into human-readable incident summaries and reusable response playbooks.

---

## 📨 Authors

[Xinhao Deng](https://xinhao-deng.github.io), [Xiaohu Du](https://xhdu.github.io), [Jialuo Chen](https://testing4ai.github.io), [Jianan Ma](https://github.com/nninjn), Ruixiao Lin, Yuqi Qing, Sibo Yi, Yidou Liu, Siyi Cao, Yan Wu, Shiwen Cui, Xiaofang Yang, Changhua Meng, Weiqiang Wang

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE). See [LEGAL.md](LEGAL.md) for additional legal information.

---

## 📖 Citation

```bibtex
@misc{deng2026tamingopenclawsecurityanalysis,
      title={Taming OpenClaw: Security Analysis and Mitigation of Autonomous LLM Agent Threats},
      author={Xinhao Deng and Yixiang Zhang and Jiaqing Wu and Jiaqi Bai and Sibo Yi and Zhuoheng Zou and Yue Xiao and Rennai Qiu and Jianan Ma and Jialuo Chen and Xiaohu Du and Xiaofang Yang and Shiwen Cui and Changhua Meng and Weiqiang Wang and Jiaxing Song and Ke Xu and Qi Li},
      year={2026},
      eprint={2603.11619},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2603.11619},
}
```