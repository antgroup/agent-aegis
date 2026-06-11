# AgentAegis
<p align="center"> 
  <a href="README.md">English</a>
  |
  <a href="README_zh.md">简体中文</a>
</p>


> AgentAegis为OpenClaw类智能体构建了一套多维度的智能体安全纵深防御架构，实现从大模型智能体在各种Claw从初始化到执行的全生命周期五层安全防御，覆盖智能体执行服务中的安全性和可靠性风险，包括skill投毒、记忆污染、意图对齐、恶意执行、资源耗尽等。作为内置的轻量化安全插件，AgentAegis可以在OpenClaw的关键阶段主动发起防御机制，动态保障智能体运行时的安全。此外，AgentAegis还面向安全运营人员提供风险识别与处置策略可配置能力，以灵活、可拓展地应对智能体运行时安全威胁；面向普通用户提供敏感文件及Skill资产保护能力，以保障个人隐私和资产安全。
> 



---

## 💫 架构

<p align="center">
  <img src="https://github.com/user-attachments/assets/9900dc9e-924e-4bac-a7c7-3133565e7932" alt="AgentAegis 架构" width="100%" />
</p>

AgentAegis 为 OpenClaw 构建了一套多维度的纵深防御架构，实现从初始化到执行终端的全生命周期安全闭环。该体系由以下五个核心防护层组成：

- **可信基座层防御** — 确保底层环境的可信度，从初始化阶段夯实系统安全根基。
- **感知输入层防御** — 对内部和外部指令进行严格过滤与审核，拦截恶意注入或高风险请求。
- **认知状态层防御** — 实时监控智能体的内部状态，防止记忆恶化上下文污染。
- **决策对齐层防御** — 在逻辑生成环节进行意图校验，确保输出决策与用户真实意图一致，模糊意图要求用户二次确认，消除意图偏离风险。
- **执行控制层防御** — 在最终操作前实施权限管理，确保所有指令都在安全边界内受控执行。

通过这种层层递进的机制，AgentAegis 确保了 OpenClaw 在每一个关键链路环节都具备细致的风险对冲能力，将潜在威胁消弭于无形。此外，作为内置的安全插件，不同于提示词、Skill类防御等被动防御机制，AgentAegis可以在OpenClaw的关键阶段主动发起防御机制，动态保障运行时的安全。

---

## 🚀 快速开始

AgentAegis 可运行在两种智能体运行时上。下面每一节都是自包含的：**安装 → 启用 → 启动 WebUI**。

### 针对 OpenClaw —— `openclaw@latest`

**前置条件：** Node.js ≥ 20，以及最新版 OpenClaw CLI。

```bash
npm install -g openclaw@latest
openclaw --version
```

**1.** 克隆并构建插件（插件以 TypeScript 形式提供）：

```bash
git clone https://github.com/antgroup/AgentAegis.git
cd AgentAegis
npm install && npm run build
```

**2.** 安装到 OpenClaw —— 这会把插件复制到 `~/.openclaw/extensions/agent-aegis`：

```bash
openclaw plugins install ./AgentAegis
```

> ℹ️ 内核探针（`sentinel/probes/{ebpf,uprobe,lsm}`）**不在**此安装包内 —— 它们通过
> `node:child_process` 拉起辅助进程，而 OpenClaw 的插件扫描器会拦截 `child_process`。
> L1 工具调用层防御照常安装运行；要在 OpenClaw 上验证 eBPF/内核层，请**单独启动**探针
> （见下文 *内核级防御 → 独立启动 eBPF 探针*）。

**3.** 信任该插件并重启 gateway 使其加载。在 `~/.openclaw/openclaw.json` 的 `plugins.allow` 中加入 `agent-aegis`，然后验证：

```bash
openclaw plugins list      # agent-aegis -> enabled
```

**4.**（可选）通过 `openclaw.plugin.json` 中的 `userConfig` 字段调整防御 —— 先以 `observe` 上线，再将高置信度防御提升为 `enforce`：

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

**5.** 启动 WebUI（从已安装插件的 `web/` 目录启动）：

```bash
# macOS / Linux
cd ~/.openclaw/extensions/agent-aegis/web
# Windows: cd %USERPROFILE%\.openclaw\extensions\agent-aegis\web
npm install && npm run build && npm start
```

打开 `http://localhost:3800`。

### 针对 Hermes Agent —— `hermes-agent@latest`

**前置条件：** Node.js ≥ 20、Python 3，以及已安装的最新版 Hermes Agent（`hermes --version`）。

**1.** 克隆仓库并运行自动化安装脚本。它会构建引擎 + WebUI，并把全部内容安装到 `~/.hermes/plugins/agent-aegis`（引擎、RPC server、配置、状态目录）：

```bash
git clone https://github.com/antgroup/AgentAegis.git
cd AgentAegis
bash adapters/hermes/install.sh
```

**2.** 启用插件 —— 用 CLI（它会写入 `~/.hermes/config.yaml` 的 `plugins.enabled`）：

```bash
hermes plugins enable agent-aegis
hermes plugins list                 # agent-aegis -> enabled
```

> 等价的手动改法（不用 CLI）：在 `~/.hermes/config.yaml` 的 `plugins.enabled` 下加一行 `agent-aegis`。

**（可选）让 AgentAegis 独占拦截。** AgentAegis 的防御与 Hermes 自身的审批模式无关、两者独立都生效。但若 Hermes `approvals.mode` 为 `manual`/`smart`，同一个危险操作会被 **Hermes 和 AgentAegis 各拦一次**（重复提示），且 `manual` 在非交互运行下可能卡住等待确认。想让 AgentAegis 做唯一关口，在 `~/.hermes/config.yaml` 设 `approvals.mode: off`：

```yaml
approvals:
  mode: off
```

若你刻意想保留 Hermes 的人工审批作为额外一层，维持 `manual` 即可。

**3.** 重启 Hermes。在 `~/.hermes/plugins/agent-aegis/config.yaml` 中查看并调整防御配置。

**4.** 使用独立启动脚本启动 WebUI（在克隆的仓库根目录运行）：

```bash
cd AgentAegis
./start-web-hermes.sh
```

打开 `http://localhost:3800`。或者在 `~/.hermes/plugins/agent-aegis/config.yaml` 中设置 `webPort: 3800`，让 WebUI 随智能体一起自动启动。

---

## ⚠️ 运维提示

- **改配置后需重启。** 两种运行时都只在启动时读取防御配置。改完配置文件（Hermes 是 `config.yaml`，OpenClaw 是 `openclaw.plugin.json`）或在 WebUI 调整设置后，请重启 agent —— 运行中的会话仍用旧配置。（Hermes 还要确认旧的 `rpc-server.js` 子进程已退出再重启。）
- **`observe` 只记录、`enforce` 才拦截。** observe 模式只记录命中但放行，只有 enforce 会真正拦截。建议先以 observe 上线，再把高置信度防御提升到 enforce。
- **Hermes 必须加载插件才能防御。** 用 gateway / 交互聊天模式 —— `hermes -z`（单轮）不加载插件，防御不会运行。启动日志应出现 `N high-risk tools wrapped`（N > 0），这才表示工具调用拦截已武装。可设 `approvals.mode: off` 让 AgentAegis 独占拦截。

---

## ✨ 核心特性

### 运行时防御

AgentAegis 提供一组覆盖智能体全生命周期的内置运行时防御能力，无需额外配置即可自动检测和缓解威胁。

- **五层纵深防御** — 覆盖意图扫描、工具调用治理、工具结果审查、资产保护和输出安全，贯穿九个OpenClaw生命周期钩子。
- **Skill投毒防御** — 启动时及运行期间持续扫描Skill内容，检测试图绕过审批、禁用安全控制或篡改受保护资产的恶意载荷。
- **记忆污染防护** — 拒绝对持久化记忆存储（`memory_store`、`MEMORY.md`、`SOUL.md`、`memory/`）的可疑或超大写入，防止跨会话的持久化提示词投毒。
- **意图与提示词安全** — 检测用户消息中的越狱尝试、密钥窃取请求和插件篡改意图，并向提示词注入安全上下文以影响后续模型推理。
- **工具调用治理** — 在工具执行前拦截高危Shell命令、编码/混淆载荷、写后执行链、重复变异循环以及SSRF/数据泄露链。
- **工具结果审查** — 将外部工具输出视为不可信输入，扫描其中的提示词注入、密钥请求和权限提升模式，防止其影响下一步推理。
- **输出脱敏** — 在助手输出发送或存储前，遮蔽API密钥、令牌及类似敏感值。

### 进阶可配置防御

在内置运行时防御之上，AgentAegis 为安全运营人员和终端用户提供可配置的控制面，支持进阶风险管理和资产保护。

- **可配置安全运营** — 运营人员可通过 `allDefensesEnabled` 全局启用所有防御，通过 `defaultBlockingMode` 设置全局基线，并可逐项覆盖 `selfProtectionMode`、`commandBlockMode`、`memoryGuardMode`、`exfiltrationGuardMode` 等独立控制。每项防御均支持 `enforce`、`observe` 和 `off` 三种模式，实现从监控到主动拦截的渐进式部署。运营人员还可定义 `protectedPaths`、`protectedSkills` 和 `protectedPlugins` 来匹配其环境中的关键资产，并通过 `startupSkillScan` 提前识别风险Skill。检测结果以运行时观测、拦截动作和提升的提示词告警形式呈现，为防御者提供可操作的分类与响应信号。
- **敏感文件与Skill资产保护** — 敏感文件和目录可添加到 `protectedPaths`，对未授权的读取、写入、删除和篡改进行拦截或观测。高价值Skill和重要插件可通过 `protectedSkills` 和 `protectedPlugins` 注册，防止Skill和插件资产被删除、覆盖或补丁式篡改。自保护机制降低智能体关闭自身防御或静默改写安全配置的风险。对个人用户而言，这意味着私人笔记、文档和自定义Skill得到更安全的处理；对组织而言，这意味着运维手册、审计插件和安全关键配置获得更强的保护。

---

## 🛠️ 项目结构

```
AgentAegis/
├── index.ts                    # OpenClaw 插件入口 —— 注册生命周期钩子
├── runtime-api.ts              # OpenClaw 插件 API 类型定义
├── rpc-server.ts               # 暴露引擎的 JSON-RPC server（由 Hermes 桥接驱动）
├── rpc-handlers.ts             # RPC 方法处理器（check_before_tool、check_user_input 等）
├── __init__.py                 # Hermes 代理入口 —— 委托给 adapters/hermes/
├── openclaw.plugin.json        # OpenClaw 清单（配置 Schema + UI 提示）
├── plugin.yaml                 # Hermes 插件清单
├── package.json                # 包元数据（@openclaw/agent-aegis）
├── start-web-hermes.sh         # Hermes WebUI 独立启动脚本
│
├── src/                        # 检测引擎 —— 两种运行时共享
│   ├── engine.ts               # 核心防御引擎 + 防御事件落盘
│   ├── handlers.ts             # 生命周期钩子处理器 / 运行时逻辑
│   ├── rules.ts                # 检测规则与扫描逻辑
│   ├── security-strategies.ts  # 防御策略定义与模式
│   ├── command-obfuscation.ts  # Shell 命令混淆检测
│   ├── encoding-guard.ts       # 编码载荷检测
│   ├── scan-service.ts         # Skill 扫描服务及队列管理
│   ├── scan-worker.ts          # 单个 Skill 扫描 Worker
│   ├── state.ts                # 内存与持久化状态管理
│   ├── config.ts               # 配置解析与常量
│   └── types.ts                # 核心领域类型（TurnSecurityState 等）
│
├── adapters/hermes/            # Hermes Agent 适配器（Python ↔ Node 桥接）
│   ├── __init__.py             # 插件 register() —— 挂钩子 + 包裹工具
│   ├── bridge.py               # 拉起 rpc-server.js；通过 stdio 走 JSON-RPC
│   ├── tool_wrappers.py        # 包裹高危工具以实现执行期拦截
│   ├── paths.py                # 解析插件 / 状态 / 配置路径
│   ├── web-server.py           # 管理 WebUI 子进程
│   ├── install.sh              # Hermes 自动化安装脚本
│   ├── plugin.yaml             # Hermes 清单
│   └── config.yaml             # 默认防御配置模板
│
├── web/                        # WebUI 管理面板
│   ├── shared/                 # 前后端共享的类型、Zod 校验 schema、防御分组元数据
│   ├── api/                    # Express 后端（路由：config / status / events / skills）
│   └── frontend/               # React + Vite + TailwindCSS 前端（Dashboard、Config、Events、Skills）
│
└── docs/                       # WebUI 截图
```

---

## 🛡️ 内核级防御 —— eBPF / Sentinel（实验性，Linux）

上述防御工作在 **L1** —— 智能体的工具调用层（prompt / tool / tool-result 钩子）。
框架无关的 `sentinel/` 子系统在其下增加了直接观测原始 **syscall** 的更深层防御，
因此能捕获那些根本不经过智能体工具注册表的威胁：混淆的 `execve` 载荷、子进程文件
访问、以及直接的内核级数据外泄。

| 层 | 探针 | 观测内容 |
|---|---|---|
| **L1** | tool-call 钩子 | 智能体级工具意图（始终开启） |
| **L2** | `uprobe` | 用户态 libc / OpenSSL 符号（`execve`、`openat`、`connect`、`SSL_read/write`） |
| **L3** | `ebpf` tracepoint | 系统级 syscall（观测） |
| **L3** | `lsm`（LSM-BPF） | 内核级 **enforce** —— 在 syscall 完成前拒绝高危判定 |

捕获到的 syscall 由 **native judge**（`sentinel/judges/native.ts`）评分：敏感路径
访问（如任何对 `/etc/shadow` 的读取）、从临时目录（`/tmp`、`/dev/shm`、`/var/tmp`）
发起的 `execve`、以及进程树异常。每条事件 + 判定都以 JSONL 落盘，并转发到
**WebUI 的 Events 页面**。

### 模式

- **observe（观测，默认）** —— 检测、记录并呈现到 WebUI，但**不拦截**（操作照常执行）。
  适合灰度上线 / 数据采集。
- **enforce（强制）** —— `lsm` 探针在内核内拒绝高危 syscall。

### 启用

内核探针是**按需开启**的（仅 Linux），并通过 `node:child_process` 拉起各自的 runner。
OpenClaw 的插件扫描器会拦截 `child_process`，因此这些探针**已从 OpenClaw 插件包中排除** ——
L1 防御照常安装运行，内核层则通过**单独启动**探针来验证（见下一小节）。Hermes 仍随插件分发
探针，并在 `config.yaml` 中启用。

**Hermes** —— 编辑 `~/.hermes/plugins/agent-aegis/config.yaml`（安装脚本已写入该段，默认关闭），重启 Hermes：

```yaml
nativeJudge:
  mode: observe
probes:
  ebpf:
    enabled: true
  lsm:
    enabled: false
    minSeverity: high
```

要启用内核级实拦截，设 `nativeJudge.mode: enforce` **且** `probes.lsm.enabled: true`
（`ebpf` tracepoint 探针只能观测，`lsm` 才在内核内拦截）。通过
`nativeJudge.sensitivePaths` / `nativeJudge.scratchDirs` 可不改代码扩展覆盖范围。

**前置要求：** 支持 eBPF 的 Linux 内核、root、BCC（`bpfcc-tools`、`python3-bpfcc`）、
以及已挂载的 `/sys/kernel/debug`。macOS/Windows 上请用下面的 Docker 一键验证（通过
OrbStack / Docker Desktop 跑特权 Linux 容器）。探针 fail-open —— 挂不上时只记日志，智能体照常运行。

### 独立启动 eBPF 探针（任意运行时，含 OpenClaw）

探针已与插件解耦 —— 直接在克隆好的仓库里运行即可，无需任何智能体。三个层级，由简到全：

```bash
# L0 —— 裸探针（Linux + root + BCC）：syscall 以 JSONL 打到 stdout
sudo python3 sentinel/probes/ebpf/runner/probe.py --targets execve,openat,connect
#   然后在另一个 shell 触发：cat /etc/shadow ; ls /etc
#   → {"kind":"ready",...} 然后 {"kind":"syscall","syscall":"openat","path":"/etc/shadow",...}

# L1 —— 全链路（探针 → native judge → 判定），不用 Docker（Linux + root）
npm run build && sudo node sentinel/probes/ebpf/verify-e2e.mjs   # PASS = cat /etc/shadow → BLOCK
```

要跑能在任意 OS（macOS/Windows 经 OrbStack / Docker Desktop）工作的容器化验证，
用下文 **一键验证** 里的命令。

### 一键验证（任意 OS，需 Docker）

```bash
npm run e2e:ebpf    # eBPF tracepoint 捕获 `cat /etc/shadow`；native judge → block（enforce）
npm run e2e:lsm     # LSM-BPF 在内核内拒绝该 syscall（enforce）
npm run e2e:uprobe  # 用户态 libc / OpenSSL 符号探针

# 观测模式 + WebUI：检测但不拦截，把检测结果转发到 http://localhost:3800 的
# WebUI 并自动打开浏览器：
npm run observe:live      # OpenClaw 式接线（noop runtime + eBPF 探针）
npm run observe:hermes    # 驱动真实的 Hermes RPC init 路径（rpc-server.js）
```

每个 harness 都会构建特权 Linux 容器，触发 `cat /etc/shadow`，并断言 native judge
产出预期判定（enforce 下为 block，observe 下为 observed）。子系统的目录约定、依赖方向
规则、以及如何新增 probe / judge 详见 `sentinel/README.md`。

---

## 🖥️ WebUI

AgentAegis 附带独立的 Web 管理面板，用于可视化配置防御策略、查看安全状态、浏览事件日志和管理 Skill 扫描。

### 启动 WebUI

上面的 **快速开始** 一节已经覆盖了两种运行时各自的 WebUI 启动方式。简而言之，面板运行在 `http://localhost:3800`：

- **OpenClaw：** 在 `~/.openclaw/extensions/agent-aegis/web` 下执行 `npm install && npm run build && npm start`
- **Hermes：** 在克隆的仓库根目录执行 `./start-web-hermes.sh`（或在插件 `config.yaml` 中设置 `webPort: 3800`）

开发模式（支持热更新）：

```bash
npm run dev
```

### 功能页面

**Dashboard（仪表盘）** — 防御状态统计卡片、12项防御机制状态矩阵、插件自完整性状态、Trusted Skills计数、最近安全事件列表。

<p align="center">
  <img src="docs/webui-dashboard-zh.png" alt="WebUI 仪表盘" width="90%" />
</p>

**Config（配置编辑器）** — Master Controls（全局防御开关 + 默认拦截模式）、每项防御独立卡片、Protected Assets标签式编辑器、可折叠高级选项。支持脏状态追踪，Save / Reset to Defaults按钮。

<p align="center">
  <img src="docs/webui-config-zh.png" alt="WebUI 配置编辑器" width="90%" />
</p>

**Events（安全事件日志）** — 支持按防御类型和结果（blocked / observed / clear）筛选，自动每10秒刷新。

<p align="center">
  <img src="docs/webui-events-zh.png" alt="WebUI 事件日志" width="90%" />
</p>

**Skills（Skill扫描管理）** — Trusted Skills列表（路径、哈希、大小、扫描时间），支持手动移除。

<p align="center">
  <img src="docs/webui-skills-zh.png" alt="WebUI Skill管理" width="90%" />
</p>

### 配置参数说明

AgentAegis 的防御参数存储在 `openclaw.plugin.json` 的 `userConfig` 字段中。可通过以下两种方式修改：

**方式一：通过 WebUI 修改（推荐）**

打开 WebUI 的 Config 页面，可视化切换开关和选择模式，点击 **Save** 保存。

**方式二：直接编辑 JSON 文件**

编辑 `openclaw.plugin.json`，添加或修改 `userConfig` 字段：

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

**参数一览：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `allDefensesEnabled` | boolean | `true` | 全局防御总开关 |
| `defaultBlockingMode` | `off` / `observe` / `enforce` | `enforce` | 所有拦截类防御的默认模式 |
| `selfProtectionEnabled` | boolean | `true` | 保护敏感路径、Skill和插件 |
| `selfProtectionMode` | `off` / `observe` / `enforce` | `enforce` | 敏感路径防御的模式 |
| `commandBlockEnabled` | boolean | `true` | 拦截高危Shell命令（如 `rm -rf /`、`curl \| sh`） |
| `commandBlockMode` | `off` / `observe` / `enforce` | `enforce` | 命令拦截的模式 |
| `encodingGuardEnabled` | boolean | `true` | 检测编码/混淆载荷 |
| `encodingGuardMode` | `off` / `observe` / `enforce` | `enforce` | 编码检测的模式 |
| `scriptProvenanceGuardEnabled` | boolean | `true` | 追踪并拦截当前运行期间写入的风险脚本 |
| `scriptProvenanceGuardMode` | `off` / `observe` / `enforce` | `enforce` | 脚本溯源防御的模式 |
| `memoryGuardEnabled` | boolean | `true` | 拒绝可疑的记忆写入 |
| `memoryGuardMode` | `off` / `observe` / `enforce` | `enforce` | 记忆防护的模式 |
| `loopGuardEnabled` | boolean | `true` | 阻止重复的变异工具调用 |
| `loopGuardMode` | `off` / `observe` / `enforce` | `enforce` | 循环防护的模式 |
| `exfiltrationGuardEnabled` | boolean | `true` | 拦截SSRF/数据泄露链 |
| `exfiltrationGuardMode` | `off` / `observe` / `enforce` | `enforce` | 泄露防护的模式 |
| `dispatchGuardEnabled` | boolean | `true` | 拦截针对受保护资源的危险消息 |
| `dispatchGuardMode` | `off` / `observe` / `enforce` | `enforce` | 消息分发防护的模式 |
| `userRiskScanEnabled` | boolean | `true` | 检测用户消息中的越狱和篡改意图 |
| `skillScanEnabled` | boolean | `true` | 启用Skill扫描 |
| `toolResultScanEnabled` | boolean | `true` | 扫描工具结果中的注入模式 |
| `outputRedactionEnabled` | boolean | `true` | 遮蔽输出中的API密钥和令牌 |
| `promptGuardEnabled` | boolean | `true` | 向提示词注入安全提醒 |
| `toolCallEnforcementEnabled` | boolean | `true` | 要求破坏性操作必须通过工具调用 |
| `protectedPaths` | string[] | `[]` | 额外受保护的路径列表 |
| `protectedSkills` | string[] | `[]` | 额外受保护的Skill ID列表 |
| `protectedPlugins` | string[] | `[]` | 额外受保护的插件ID列表 |
| `startupSkillScan` | boolean | `true` | 启动时运行Skill扫描 |

> **模式说明**：`enforce` = 拦截并记录，`observe` = 仅记录（放行），`off` = 关闭。

---

## 🎬 效果展示

OpenClaw既可以由个人用户部署在本地，也可以由服务商部署在远端——两种场景都面临不同的安全风险。以下演示展示了AgentAegis如何在各场景中防御真实威胁。

### 面向个人用户（To C）

本地部署的智能体面临模糊意图、资源浪费和Skill投毒等风险，直接影响用户的文件、Token和隐私。

<div align="center">
<table>
<tr>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">模糊意图导致文件被删除</p><video title="模糊意图 - 文件删除" alt="模糊的用户指令导致智能体删除所有项目文件" src="https://github.com/user-attachments/assets/230fcc05-acaa-4e79-8839-afd623639ef3" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">Skill投毒泄露隐私</p><video title="Skill投毒 - 隐私泄露" alt="被投毒的Skill将用户敏感数据泄露到外部服务器" src="https://github.com/user-attachments/assets/37524f92-cf8c-4c79-a503-ca3a60642439" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
</tr>
</table>
</div>

### 面向服务商（To B）

远端部署的智能体面临API密钥盗用、危险命令执行和间接提示词注入等风险，威胁服务可用性和数据安全。

<div align="center">
<table>
<tr>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">API密钥泄露 — Token被盗用</p><video title="API密钥泄露 - Token盗用" alt="攻击者读取~/.openclaw/agents/main/agent/models.json窃取API密钥" src="https://github.com/user-attachments/assets/78b60004-a500-4446-bfbb-a5dab87ddcde" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
<td align="center" width="50%"><p style="margin:0 0 8px 0; color:#666; font-size:13px;">间接提示词注入 — 数据泄露</p><video title="间接提示词注入 - 数据泄露" alt="外部内容中的注入指令导致智能体泄露数据" src="https://github.com/user-attachments/assets/ed72a4b8-0f5b-409d-8d1e-447fb3f1ec09" controls preload="metadata" style="width:100%; max-width:400px; height:225px; object-fit:cover;"></video></td>
</tr>
</table>
</div>

---

## 🔭 未来规划

- 面向Skill、记忆条目、工具输出和生成脚本的溯源感知信任评分，使策略能够基于来源和历史行为进行响应。
- 跨会话和跨智能体的攻击图谱，将风险意图、工具调用、工具结果、记忆写入和出站请求关联为统一的事件时间线。
- 自适应策略，根据部署环境、任务类型和运营人员反馈自动调优 `observe` 和 `enforce` 决策。
- 自主遏制工作流，支持隔离风险Skill、冻结敏感记忆命名空间并推荐恢复措施。
- 多智能体系统的共享安全状态，使协作智能体能够交换风险上下文并协调遏制决策。
- 持续红队评估流水线，针对新版本回放新兴越狱手法、编码载荷、Skill投毒样本和工具链滥用技术。
- 可解释的防御报告，将底层检测转化为人类可读的事件摘要和可复用的响应手册。

---

## 📨 作者

[Xinhao Deng](https://xinhao-deng.github.io), [Xiaohu Du](https://xhdu.github.io), [Jialuo Chen](https://testing4ai.github.io), [Jianan Ma](https://github.com/nninjn), Ruixiao Lin, Yuqi Qing, Sibo Yi, Yidou Liu, Siyi Cao, Yan Wu, Shiwen Cui, Xiaofang Yang, Changhua Meng, Weiqiang Wang

---

## 📄 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源。更多法律信息详见 [LEGAL.md](LEGAL.md)。

---

## 📖 引用

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