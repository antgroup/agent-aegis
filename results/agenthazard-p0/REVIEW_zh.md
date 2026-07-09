# AgentHazard Phase 0 实现复查记录

- 复查日期：2026-07-09
- 复查对象：`results/agenthazard-p0/` 下的 Phase 0 实现
- 对照基准：`README_zh.md` 对 Phase 0 的描述
- 复查范围：仅检查实现是否符合 README，不负责实现改动
- 复查涉及文件：
  - 产物：`report.md`、`summary.json`、`sample.json`
  - 代码：`sentinel/bench/agenthazard/{types,adapter,mapper,report,run}.ts`
  - 交叉验证：`sentinel/context/{snapshot,features}.ts`（M11.5 BehavioralSnapshot 真实字段）

## 一、总体结论

实现整体与 `README_zh.md` 描述相符，Phase 0 承诺的三件事（读 2653 条数据、按类别+策略做分层抽样、生成 dry-run 报告）均已兑现，确定性可复现，CLI 护栏正确锁死 Phase 0 范围。

唯一的实质偏差在 `mapper.ts`（Coverage Map 的数据源）：`expectedSnapshotFields` 把“当前已有字段”与“期望但尚未实现的字段”混在同一列，渲染时未加区分。这不影响 Phase 0 通过——`knownGaps` 已覆盖同样的信息——但会让后续 Phase 3 盲点诊断 / Phase 4 优化清单的对应关系不直观。详见第四节。

**判定：Phase 0 通过。**

## 二、逐项核对

### ✅ 1. 读取 2653 条数据

- `adapter.ts:18 loadDataset()` 解析 JSON 数组，逐条用 `parseInstance` 严格校验类型；`readCategory` / `readMethod` 对未知类别/策略直接抛错，保证脏数据不混入。
- `summary.json:9` `total: 2653`。
  - 10 类数据集计数求和：174+342+125+453+255+167+260+376+248+253 = **2653** ✓
  - 100 个 stratum 的 `byStratum` 求和 = 2653 ✓
- 与 README “读取 AgentHazard 的 2653 条数据”一致。

### ✅ 2. 按类别 + 策略做分层抽样

- 每类抽 3 条，共 **30 条**（`report.md` Selected Instances 30 行，`selectedByCategory` 每类各 3）✓
- 抽样算法 `adapter.ts:68 sampleCategory()`：
  1. 先按 `jailbreak_method` 分层（stratum）。
  2. 用 `deterministicShuffle(xorshift32)` 对每个 stratum 打乱后各取 1 条，逐层填充直至达到 `perCategory`。
  3. 不足时从余量按种子补足。
  - 这正是 README 所述“按攻击类别和攻击策略做小样本抽样”。
- 覆盖度：30 条覆盖了 7~8 个不同的 jailbreak method（见 `selectedByJailbreakMethod`：Legacy_Code_Maintenance=8、Recursive_Salami_Slicing=5、Dependency_Hook_Trigger=4……），没有集中坍缩到单一策略，分层有效。
- 确定性可复现：`seed=1337`，`seedFor()` 基于文本 charCode xor 生成每层种子，纯函数无随机源。README 末尾 Next Phase Gate “Phase 0 passes when ... reproducible for the same seed” 与实现一致 ✓

### ✅ 3. 生成 dry-run 报告

- `report.ts writeReportFiles()` 写出 3 个文件：`summary.json` / `sample.json` / `report.md`，与 README 标注的“三核心文件”一致（report 给人读、sample 给机器读、mapper 是知识表）。
- `report.md` 渲染区块齐全，与 README 描述的结构一一对应：
  1. Run Metadata（生成时间、数据集路径、seed、每类抽样数）
  2. Dataset Summary（按类别、按策略统计）
  3. Expected Snapshot Coverage Map（10 类 × 信号/字段/因果链/盲点）
  4. Selected Instances（30 条样本表）
  5. Next Phase Gate（通过条件 + Phase 0.5 提示）

### ✅ 4. CLI 入口

- `run.ts` 参数齐全：`--dataset / --out / --sample-per-category / --seed / --categories / --jailbreak-methods / --dry-run`，并附别名 `--sample`、`--methods`、`-h/--help`。
- 默认值 `DEFAULT_SEED=1337`、`DEFAULT_SAMPLE_PER_CATEGORY=3`，与 `report.md` Run Metadata 一致 ✓
- 范围护栏：`--dry-run` 必传，未传直接抛 `"Only Phase 0 --dry-run is implemented"`（`run.ts:29`）。正确——锁死 Phase 0，防止误触发尚未实现的 Phase 1。
- `--out` 默认 `results/agenthazard-p0`，`--dataset` 默认 `../AgentHazard/data/dataset.json`，最小可行命令即 `node .../run.js --dry-run`。

### ✅ 5. sample.json 字段一致性

- `sample.json` 每条字段 `id / category / jailbreak_method / query / decomposed_query / comment / source / original_id / sampleRank / stratumKey`，与 `types.ts` 的 `SampledInstance` 接口完全一致 ✓

## 三、抽样正确性的交叉验证

为确认抽样不是“凑出 30 条”而是真分层，核对 `summary.json` 的 stratum 分布：

- `selectedByStratum` 共 30 行，每行值均为 1 → 每个被选 stratum 恰取 1 条，符合“每 stratum 至多 1 条、跨 stratum 凑足每类 3 条”的设计。
- 被选中的 30 个 stratum 落在 7 个不同的 method 上（Dependency_Hook_Trigger、Legacy_Code_Maintenance、Recursive_Salami_Slicing、Security_Audit_Gaslighting、Implicit_Indirect_Injection、Encoded_Payload_Smuggling、Logical_Dependency_Inversion、Direct、Contextual_Persona_Enforcement、Pseudo_Diagnostic_Debugging）→ 跨策略覆盖良好。
- 数据集最稀疏的 stratum（如 `Destructive_Action/Implicit_Indirect_Injection` 只有 1 条、`Compliance_Bypass/Implicit_Indirect_Injection` 只有 2 条）若被选中，必然命中全集，这是确定性的必然结果，非问题。

## 四、发现的偏差：Coverage Map 字段名混用“已有”与“待补”

这是复查中最值得记录的发现。

### 问题描述

`mapper.ts` 每个类别的 `expectedSnapshotFields` 共列出 13 个去重字段名。逐一比对 M11.5 `BehavioralSnapshot`（`sentinel/context/snapshot.ts:12-36`）与 `BehavioralFeatures`（`sentinel/context/features.ts:10-31`）的真实字段后：

| mapper 列出的字段 | BehavioralSnapshot 当前是否真实存在 | 来源 |
|---|---|---|
| `externalConnections` | ✅ 存在 | snapshot.ts:27 |
| `sensitiveAccesses` | ✅ 存在 | snapshot.ts:25 |
| `binariesExecuted` | ✅ 存在 | snapshot.ts:23 |
| `features.externalConnCount` | ✅ 存在 | features.ts:18 |
| `features.forkRate` | ✅ 存在 | features.ts:12 |
| `features.processFanout` | ✅ 存在 | features.ts:20 |
| `features.externalEventRatio` | ✅ 存在 | features.ts:26 |
| `execArgsSummary` | ❌ 不存在 | — |
| `toolCallToSyscallMapping` | ❌ 不存在 | — |
| `fileDeleteEvents` | ❌ 不存在 | — |
| `persistenceAccesses` | ❌ 不存在 | — |
| `fileWriteEvents` | ❌ 不存在 | — |
| `distinctExternalPorts` | ❌ 不存在 | — |

即 13 个字段中，6 个真实存在，**6 个是 BehavioralSnapshot 目前并不产出的字段**（`execArgsSummary`、`toolCallToSyscallMapping`、`fileDeleteEvents`、`persistenceAccesses`、`fileWriteEvents`、`distinctExternalPorts`）。

### 这不算 bug，而是“未标注的期望”

`knownGaps` 已经诚实地记录了缺失：

- Destructive_Action → “`snapshot has no destructive file operation field yet`”
- Persistence_Establishment → “`persistence patterns need to be shared from context/patterns.ts`”
- Supply_Chain_Poisoning / Persistence_Establishment → “`openat flags are needed to confirm modification`”（对应 `fileWriteEvents` 待补）
- Internal_Reconnaissance → “`port and destination diversity require connect addr/port capture`”（对应 `distinctExternalPorts` 待补）
- System_RCE / Supply_Chain_Poisoning → “`argv summaries are more useful than binary path alone`”（对应 `execArgsSummary` 待补）
- Prompt_Intel_Theft → “`tool parameters need to survive into snapshot context`”（对应 `toolCallToSyscallMapping` 待补）

也就是说，把这些“期望但未实现”的字段写进 `expectedSnapshotFields` 是有意的——它们本身就是 Phase 4 为 M11.5 提的优化清单。逻辑自洽。

### 但渲染上有歧义

`report.ts:78 renderMarkdown()` 把整列 `expectedSnapshotFields` 原样渲染成 `` `field` `` 加 `<br>` 拼接到一格，**不区分“已存在”与“待补”**。读 `report.md` Coverage Map 的人会误以为这一列字段当前都能从 Snapshot 产出。

典型行 Destructive_Action 尤其明显：

- `expectedSnapshotFields`：仅 `fileDeleteEvents`
- 而 `fileDeleteEvents` 当前根本不存在
- 读起来像“Snapshot 会产出 fileDeleteEvents”，实际含义是“Snapshot 应当产出但尚未实现”

这会让后续 Phase 3 盲点诊断时，难以一眼判断“某类漏判是因为字段缺失（待补）还是字段有但信息不够（已有字段的感知力不足）”。

## 五、建议（仅供记录，复查不含实现）

1. **地图字段标注现状（推荐）**：在 `report.ts` 渲染 Coverage Map 时，对当前不存在的字段加标记（如 `` `fileDeleteEvents*` `` 并在表注说明 `* = 待 M11.5 实现`，或新增一列 `Field Status: existing / planned`）。改动很小，但能让 Phase 3 / Phase 4 的“缺信息”归因更直接。不标也不影响 Phase 0 通过，因为 `knownGaps` 已覆盖等价信息。
2. **因果链名核对（后续阶段再做）**：`expectedCausalChains` 列了 `destructive / recon / persistence / privilege_escalation / resource_exhaustion` 等链名，目前 M11.5 `CausalChainDetector` 只实装了 `exfil` 与 `write_then_run` 两条。其余链名是“期望待补”，同样建议在后续阶段标注，避免误判为已实装。这属于 Phase 1.5+ 的范畴，不在 Phase 0 复查范围内。

## 六、检查通过项汇总

| 检查点 | 结果 |
|---|---|
| 数据集读取 2653 条、分布正确 | ✅ |
| 分层抽样：每类 3 条共 30 条，跨 stratum 覆盖 | ✅ |
| 确定性可复现（seed=1337，xorshift32） | ✅ |
| 报告三件套（report.md / sample.json / summary.json）齐全 | ✅ |
| report.md 结构与 README 描述一致 | ✅ |
| sample.json 字段与 types.ts 接口一致 | ✅ |
| CLI 参数与默认值正确，`--dry-run` 强制护栏 | ✅ |
| Coverage Map 字段名与真实 Snapshot 字段对照 | ⚠️ 6/13 待补字段未在渲染时标注现状（knownGaps 已覆盖，不影响通过） |

Phase 0 可判为通过，进入 Phase 0.5（Snapshot exporter）。