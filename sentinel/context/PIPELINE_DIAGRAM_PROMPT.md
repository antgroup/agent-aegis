# M11.5 上下文管道示意图 — Image Prompt

> 生成工具：DALL-E / Imagen 等图像生成模型

---

**Image Prompt:**

```
A detailed technical infographic diagram on a dark navy background (#0a1628) showing a real-time AI-agent security monitoring pipeline, in a flat schematic style with glowing cyan (#00d4ff), amber (#ffa726), and red (#ff5252) accent lines. 16:9 aspect ratio.

The diagram is organized into FOUR horizontal tiers connected by directional flow lines.

═══════ 第一层（顶部）："事件捕获与归因溯源" ═══════

左侧 — "探针事件流"：
6个事件小卡片垂直流入交汇点，标签分别为："openat /etc/shadow" "fork childPid=2000" "execve /bin/bash" "connect 8.8.8.8" "tool_call terminal" "exit pid=2000"。每张卡片有来源徽章："eBPF"（绿色）、"L1-hook"（紫色）、"uprobe"（青色）。

中央 — "归因引擎"发光框，内含两个溯源子模块（实线边框）和一个模式检测子模块（虚线边框）：

  ▸ 进程树（归因溯源核心，实线绿色边框）：
  一个小型树形可视化，PID 1000为根节点（标注"Agent"），子节点PID 2000（标注"bash"），孙节点PID 3000（标注"curl"）。
  左侧标注三条更新路径：
    — "fork事件" → 箭头指向树，标注"+onFork 创建子节点"
    — "exec事件" → 箭头指向树，标注"+onExec 更新comm/exe"
    — "syscall事件" → 箭头指向树，标注"+onSyscall + 从/proc回溯祖先链"
  从孙节点PID 3000向上的虚线标注"从/proc回溯祖先链"，面包屑为"3000→2000→1000"，每个ancestor节点通过虚线补全ppid链接。
  每个节点有颜色：绿色=agent，蓝色=descendant。
  树下方输出箭头标注："attribution: agent / descendant / external"
  小字注释："来源: 进程树"

  ▸ 关联窗口（tool_call溯源，实线青色边框）：
  一条横跨30秒的水平时间线。
  时间线上方一个方括号表示"tool_call terminal"事件打开了一个窗口（标注"打开窗口"），两个syscall事件（execve、openat）落入方括号内，用虚线连接并标注"correlationId = tc-1"。
  同时展示协作关系：syscall事件的PID 2000是tool_call PID 1000的后代（来自进程树判定），用一条弧线从进程树连到关联窗口，弧线标注"PID 2000 是 PID 1000 后代 → 匹配窗口"。
  窗口下方输出箭头标注："correlationId: tc-1"
  小字注释："来源: 关联窗口"

  ▸ 因果链检测（虚线红色边框，标注"模式检测，非溯源"）：
  一个小型模式匹配图，两个已归因的事件状态通过箭头连接：
  状态1显示"openat(敏感路径) [attr=descendant]"，
  状态2显示"connect(外部地址) [attr=descendant]"，
  匹配条件标注"同进程树 + 60秒窗口内"，
  匹配指示器发出红色光芒，标注"exfil ⚠"。
  下方输出箭头标注："causalFlags: [exfil]"
  小字注释："来源: 模式检测"

第一层右侧 — 归因输出汇总：
三条带标签的箭头从归因引擎框向下发出：
  → "attribution: descendant"（蓝色标签）
  → "correlationId: tc-1"（青色标签）
  → "causalFlags: [exfil]"（红色标签，脉冲发光）

═══════ 第二层（中部）："会话事件缓冲区" ═══════

一个横跨全宽的宽容器，标注"会话事件缓冲区（per-session滚动窗口）"。内部显示3条水平会话行：
  ▸ "sess-A"：包含8个事件小卡片的水平滚动列表，每个都带有彩色归因标签（绿/蓝/灰）和correlationId标记。最左边的2张卡片半透明，带有淡出的"已丢弃"X标记，展示最旧事件被淘汰。徽章标注"上限: 200条/会话"。
  ▸ "sess-B"：类似但较短（4个事件）。
  ▸ "sess-C"：类似（6个事件）。
  右侧小型LRU淘汰指示器标注"空闲超时: 5分钟"和"最大会话数: 64"，带时钟图标。
  容器左上方有一条箭头从第一层汇入，标注"富化后事件入缓冲（含attribution/correlationId/causalFlags）"。

═══════ 第三层（下部）：三个并行输出面板 ═══════

面板A（左） — "行为快照"：
一张结构化卡片，等宽字体显示字段标签和值：
  • 会话: sess-A
  • 调用工具: ["terminal", "file_read"]
  • 执行二进制: ["/bin/bash", "/usr/bin/curl"]
  • 敏感路径访问: ["/etc/shadow"] ← 红色高亮
  • 外部网络连接: ["203.0.113.5:443"] ← 琥珀色高亮
  • 因果链: ["exfil"] ← 红色徽章带⚠
  • 归因分布: {agent: 3, descendant: 2, external: 0}

面板B（中） — "特征提取器"（数值仪表盘）：
5个小型水平条形仪表，带数值和颜色编码：
  • fork率: ████░░ 3.2/分钟
  • 唯一二进制数: ██░░░░ 2
  • 敏感路径命中: ██░░░░ 1 ← 琥珀色
  • 外部连接数: ██░░░░ 1 ← 琥珀色
  • 标记事件数: ██░░░░ 1 ← 红色

面板C（右） — "事件图 / 因果拓扑"：
这是一个有向图可视化，不是扁平列表。展示小型节点-边图：
  • 节点为圆角矩形，标注事件摘要：
    — 节点A: "tool_call terminal"（紫色，来源=l1-hook）
    — 节点B: "fork → pid 2000"（绿色）
    — 节点C: "execve /bin/bash"（蓝色，归属=descendant）
    — 节点D: "openat /etc/shadow"（蓝色，归属=descendant）
    — 节点E: "connect 203.0.113.5"（蓝色，归属=descendant）
  • 边为彩色箭头，展示关系类型：
    — A→B: 标注"触发"（虚线青色，来自correlationId）
    — B→C: 标注"派生"（实线绿色，来自进程树）
    — C→D: 标注"时序"（实线灰色，时间顺序）
    — D→E: 标注"exfil链"（粗红线，发光，来自causalFlags）
  • 角落小图例：实线绿色=进程树边，虚线青色=关联边，粗红线=因果链边
  • D→E边应有脉冲红色发光，表示活跃威胁检测

═══════ 第四层（底部）："提示词模板 → 大模型" ═══════

底部中央一个文档形状元素，展示精简的提示词预览：
  ┌─────────────────────────────┐
  │ ## 会话概览                  │
  │ - 会话: sess-A              │
  │ - 归因: agent=3 ...         │
  │ ## ⚠ 因果链                  │
  │ - exfil                     │
  │ ## 行为特征                  │
  │ - fork率: 3.2/分钟 ...       │
  │ ## 事件图                    │
  │ [图以文本形式渲染]             │
  │ ## 当前事件                   │
  │ - openat /etc/shadow ...    │
  │ ## 安全策略                   │
  │ 监控: 数据外泄, ...          │
  └─────────────────────────────┘
一条粗箭头向右伸出，标注"→ 大模型 API"，指向一个小型云图标。

═══════ 整体风格 ═══════
扁平设计，无3D效果。等宽字体用于所有数据/代码。细1px连接线带小箭头。柔和点阵背景。绿/蓝/灰/红颜色编码全文一致。因果链"exfil"相关元素（快照和事件图中）应有柔和脉冲红色发光。纯白色文字标签。所有标签使用中文。溯源模块使用实线边框，模式检测模块使用虚线边框以区分职责。
```

---

## 设计说明

### 四层结构

| 层级 | 名称 | 核心职责 |
|---|---|---|
| 第一层 | 事件捕获与归因溯源 | 探针事件 → 进程树(归因) + 关联窗口(溯源) + 因果链(模式检测) |
| 第二层 | 会话事件缓冲区 | 富化后事件入 per-session 滚动缓冲，LRU+TTL 淘汰 |
| 第三层 | 三种输出形态 | 行为快照(结构化摘要) / 特征提取(数值向量) / 事件图(因果拓扑) |
| 第四层 | 提示词模板 → 大模型 | 三种输出 + 安全策略 → 渲染成 LLM prompt |

### 归因 vs 模式检测的区分

- **实线边框**：进程树 + 关联窗口 = 归因溯源层（回答"这个事件是谁干的"）
- **虚线边框**：因果链检测 = 模式检测层（回答"这些事件是否构成攻击模式"），消费归因结果，不参与溯源

### 事件图边类型

| 边类型 | 颜色/样式 | 来源 | 含义 |
|---|---|---|---|
| 进程树边 | 实线绿色 | ProcessTree.onFork | 父进程派生了子进程 |
| 关联边 | 虚线青色 | CorrelationWindow | tool_call 触发了 syscall |
| 时序边 | 实线灰色 | 事件时间戳 | 按时间顺序先后发生 |
| 因果链边 | 粗红线(发光) | CausalChainDetector | 跨事件攻击模式 |