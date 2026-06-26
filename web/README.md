# Claw Aegis WebUI

Claw Aegis 安全插件的独立 Web 管理面板，用于可视化配置防御策略、查看安全状态、浏览事件日志和管理 Skill 扫描。

## 快速开始

安装插件后，进入插件目录启动 WebUI：

```bash
# macOS / Linux
cd ~/.openclaw/extensions/claw-aegis/web

# Windows
cd %USERPROFILE%\.openclaw\extensions\claw-aegis\web
```

```bash
npm install
npm run build
npm start
```

启动后访问 `http://localhost:3800` 即可打开管理面板。

## 开发模式

```bash
npm run dev
```

开发模式下 API 服务运行在 `:3800`，Vite 前端开发服务器运行在 `:3801`（自动代理 API 请求）。

## 项目结构

```
web/
├── shared/          # 前后端共享的类型定义、Zod 校验 schema、防御分组元数据
├── api/             # Express 后端服务
│   └── src/
│       ├── routes/          # API 路由（config、status、events、skills）
│       └── services/        # 业务逻辑（配置读写、状态读取、事件管理、文件监听）
└── frontend/        # React + Vite + TailwindCSS 前端
    └── src/
        ├── api/             # API 客户端封装 + React Query hooks
        ├── pages/           # 页面组件（Dashboard、Config、Events、Skills）
        └── components/      # UI 组件（布局、仪表盘、配置编辑器、通用控件）
```

## 功能页面

### Dashboard（仪表盘）

- 防御状态统计卡片（Enforce / Observe / Off 数量）
- 12 项防御机制状态矩阵
- 插件自完整性状态
- Trusted Skills 计数
- 最近安全事件列表

### Config（配置编辑器）

- **Master Controls**：全局防御开关 + 默认拦截模式（off / observe / enforce）
- **Execution Guards**：7 个执行层防御卡片，每个可独立开关并选择模式
- **Scanning & Output**：5 个扫描和输出相关防御开关
- **Protected Assets**：标签式编辑器，管理受保护的路径、Skill ID、Plugin ID
- **Advanced**：可折叠的高级选项（启动时 Skill 扫描等）
- 脏状态追踪，Save / Reset to Defaults 按钮

### Events（安全事件日志）

- 支持按防御类型和结果（blocked / observed / clear）筛选
- 表格展示时间、防御名称、结果、工具名、拦截原因
- 自动每 10 秒刷新

### Skills（Skill 扫描管理）

- Trusted Skills 列表（路径、哈希、大小、扫描时间）
- 手动移除 Trusted Skill（移除后下次扫描会重新评估）

## API 接口

所有接口前缀为 `/api/v1/`，响应格式统一为 `{ ok: true, data: ... }` 或 `{ ok: false, error: "..." }`。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/config` | 获取当前配置（合并默认值后） |
| PUT | `/config` | 更新配置（Zod 校验后写入文件） |
| POST | `/config/reset` | 重置为默认配置 |
| GET | `/status` | 获取防御状态总览 |
| GET | `/events` | 获取安全事件日志，支持 `?limit=&offset=&defense=&result=` |
| GET | `/skills` | 获取 Trusted Skills 列表 |
| DELETE | `/skills/:path` | 移除指定 Trusted Skill |
| GET | `/health` | 健康检查 |

## 防御参数配置教程

ClawAegis 的防御参数存储在 `openclaw.plugin.json` 的 `userConfig` 字段中。可通过以下两种方式修改：

### 方式一：通过 WebUI 修改（推荐）

打开 WebUI 的 Config 页面，可视化切换开关和选择模式，点击 **Save** 保存。

### 方式二：直接编辑 JSON 文件

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

### 参数一览

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

## WebUI 服务配置

通过环境变量或命令行参数配置：

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `AEGIS_PORT` | API 服务端口 | `3800` |
| `AEGIS_HOST` | 监听地址。默认仅本机回环，**不对局域网/公网暴露**；如需远程访问设为 `0.0.0.0` 并务必配合 `AEGIS_TOKEN` | `127.0.0.1` |
| `AEGIS_TOKEN` | 写接口鉴权 token。设置后从环境带外提供（最强模式，不落盘）；不设置则自动生成并写入 `.aegis-webui-token` | 空（自动生成） |
| `AEGIS_ALLOWED_ORIGINS` | 额外允许的浏览器跨域 Origin（逗号分隔），追加到默认的本机白名单 | 空 |
| `AEGIS_CONFIG_DIR` | `openclaw.plugin.json` 所在目录 | 当前工作目录 |
| `AEGIS_STATE_DIR` | 插件状态目录（trusted-skills.json 等） | 空（不读取状态文件） |

命令行参数形式：

```bash
npm start -- --port=3800 --host=127.0.0.1 --config-dir=/path/to/plugin --state-dir=~/.openclaw/plugins/claw-aegis
```

> **安全说明**
>
> - **绑定**：管理 API 默认绑定 `127.0.0.1`，不对局域网/公网暴露。
> - **CORS**：仅放行本机白名单 Origin，不再返回 `*`。
> - **写接口鉴权**：所有变更类请求（`PUT`/`POST`/`DELETE`）必须携带 token（`x-aegis-token` 头、`Authorization: Bearer` 或 `?token=`）。token 默认自动生成、打印到控制台并写入 `AEGIS_CONFIG_DIR/.aegis-webui-token`（权限 `0600`）；同源 UI 会自动注入该 token，本地 CLI 可从该文件读取。只读 `GET` 不需要 token，UI 加载无摩擦。
> - 这一并关闭了「本地非浏览器调用者（如被注入的 agent 直接发 HTTP PUT）经 WebUI 绕过 agent-aegis 自身清单保护」的混淆代理向量。
>
> **默认模式 vs 强化模式**
>
> - **默认模式（不设 `AEGIS_TOKEN`）**：自动生成 token 并注入到同源页面，浏览器 UI 零配置可用。但该 token 会随页面 HTML 提供，**已取得本机代码执行能力的攻击者（如被注入的 agent）可通过 `GET /` 读取页面里的 token 后调用写接口**——默认模式不防这种本地攻击者。
> - **强化模式（设置 `AEGIS_TOKEN`）**：token 由环境带外提供，**不会注入页面、不随 HTML 下发**。首次在 UI 执行写操作（保存/重置）时会弹窗要求输入 token（从控制台日志或自设的 `AEGIS_TOKEN` 取得），输入后存于浏览器 localStorage。这样被注入的 agent 无法从页面拿到 token。如需更彻底,可将 `AEGIS_CONFIG_DIR` 指向 agent-aegis 受保护路径,使 agent 也读不到 `.aegis-webui-token`。

## 配置读写机制

WebUI 独立于 OpenClaw 运行，通过直接读写 `openclaw.plugin.json` 管理配置：

- 读取时从 `configSchema.properties` 提取默认值，从 `userConfig` 字段读取用户覆盖配置，合并后返回
- 写入时将用户修改合并到 `userConfig` 字段，使用原子写入（临时文件 + rename）确保安全
- 配置解析逻辑与插件运行时的 `resolveClawAegisPluginConfig` 对齐，保证 WebUI 展示的状态与实际运行一致

## 状态文件

当配置了 `AEGIS_STATE_DIR` 后，WebUI 会读取以下文件：

- `trusted-skills.json` — Skill 扫描器标记为可信的 Skill 记录
- `self-integrity.json` — 插件自完整性校验记录（文件指纹、受保护根目录）

后端通过 chokidar 监听这些文件的变更，自动记录为安全事件。

## 技术栈

- **前端**：React 18 + Vite + TailwindCSS + React Query + Recharts + Lucide Icons
- **后端**：Express + chokidar
- **共享**：Zod 校验 + TypeScript 类型
- **构建**：npm workspaces monorepo

## 生产部署

```bash
npm run build
npm start
```

生产模式下 Express 同时托管 API 和前端静态文件，只需暴露一个端口。
