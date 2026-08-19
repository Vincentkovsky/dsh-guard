# DSH Guard v0.2 开发计划

> 状态：v0.2 本地 alpha 基线完成
> 日期：2026-08-19
> 设计依据：[DSH Guard v2 产品与架构设计](./2026-08-19-dsh-guard-v2-design.md)
> 当前基线：`codex/local-alpha-baseline`，提交 `3bf7365`

## 1. 目标

在不重写现有 Trust Gate 的前提下，把精确工具名 `deny / ask` 升级为可测试、可解释、带短时授权和审计记录的本地 Action Gate。

v0.2 完成时，用户应能安全区分普通源码操作和高风险凭据读取、越界删除、危险命令及未授权外发。

## 2. 执行原则

1. 先冻结 schema 和策略语义，再接 DSH Hook 和 UI。
2. 策略内核必须是无 DSH、无 UI、无模型依赖的纯逻辑。
3. 每个工具适配器必须有原始输入 fixture 和预期 ActionRequest。
4. 高风险路径不允许因异常、超时或未知状态自动放行。
5. 现有 scan、approve、install、verify 和 E2E 必须持续通过。
6. 计划能力不得提前出现在 README 的“已实现”列表中。
7. 所有开发和 E2E 继续使用隔离的 DSH/Guard home。

## 3. 当前代码处置

| 当前能力 | 决策 | v0.2 动作 |
|---|---|---|
| artifact、scanner、staging、install、verify | 保留 | 只做回归测试，不重构 |
| `DEFAULT_POLICY` 供应链策略 | 保留 | 与 Action Policy 分开版本化 |
| 精确 `denyTools` / `askTools` | 兼容保留 | 作为 Action Policy 的兼容入口 |
| `tools/pre-execute` Hook | 改造 | 接入标准化、策略和 grant |
| Sidecar | 降级 | 不进入 v0.2 核心路径 |
| 告警栈与安全中心 | 小幅扩展 | 展示 Action Event 和 grant，不重做视觉系统 |
| `GuardEvent` | 保留 | 新建独立 `ActionEventV1`，不塞入旧 schema |

## 4. 里程碑总览

| 里程碑 | 目标 | 退出条件 |
|---|---|---|
| M0 文档与契约冻结 | 设计、计划和安全声明一致 | 文档审查、类型草案和边界确认完成 |
| M1 Action Policy Core | 纯策略内核可独立测试 | 默认策略与 grant 测试全绿 |
| M2 CLI Simulator | 在接 DSH 前验证规则和误报 | `policy check` 支持 human/JSON 输出 |
| M3 DSH Action Gate | 正规工具调用可 allow/ask/deny | pre-execute/result 集成测试通过 |
| M4 Grants & Events | 短时授权和审计闭环 | TTL、撤销、脱敏、轮转通过 |
| M5 Security Center UX | 用户能理解并管理当前授权 | UI、键盘和错误状态 QA 通过 |
| M6 Local Alpha | 真实工作流可用 | 全套 check、E2E、兼容与安全评审通过 |

## 5. M0 — 文档与契约冻结

### M0.1 文档对齐

- [x] 确认首发用户为本机单个 DSH 开发者。
- [x] 确认 v0.2 只覆盖正规 Tool Registry 调用。
- [x] 确认高风险失败关闭、低风险可用性优先。
- [x] 确认 v0.2 不新增 daemon。
- [x] 新建 v2 设计和开发计划。
- [x] README、v1 设计和安全模型增加版本导航。
- [x] 检查所有“运行时防护”表述是否包含覆盖边界。

### M0.2 类型与命名评审

- [x] 冻结 `ActionRequestV1`。
- [x] 冻结 `ActionDecisionV1`。
- [x] 冻结 `ActionGrantV1`。
- [x] 冻结 `ActionEventV1`。
- [x] 冻结 `ActionCapability`、`ActionResource` 和稳定错误码。
- [x] 决定 `taskId` 在 DSH rc.6 中的可靠来源和缺失语义：rc.6 不提供可靠 task/goal ID，请求省略该字段，且不从 `rootCallId` 推断。

验收：schema 能表达五个发布场景，不需要持久化原始秘密或完整工具输出。

## 6. M1 — Action Policy Core

### M1.1 新建 Action 模块

建议文件：

```text
packages/core/src/action/
├── types.ts
├── schema.ts
├── normalize.ts
├── policy.ts
├── grants.ts
├── redact.ts
└── index.ts
```

任务：

- [x] 为所有持久对象增加严格 runtime schema。
- [x] 实现稳定 JSON digest 和版本化序列化。
- [x] 实现路径、URL、命令和外部目标的资源类型。
- [x] 保证错误消息不回显原始 secret。

### M1.2 默认策略

- [x] 实现 `hard deny → grant → ask → allow → default` 优先级。
- [x] 区分工作区内、工作区外和无法规范化的路径。
- [x] 定义敏感路径和敏感文件名默认集。
- [x] 定义只读开发命令、危险命令和下载后执行检测。
- [x] 定义网络域名 allowlist 与疑似 secret 参数检测。
- [x] 未知副作用工具默认 `ask`，未知只读工具允许并通过稳定 rule ID 标记。

### M1.3 Grant

- [x] 一次性 grant 首次匹配即消费。
- [x] 任务 grant 绑定 session、task、tool、operation 和 resource constraints。
- [x] 支持 TTL、撤销、policy hash 变化失效。
- [x] 损坏或未知版本 grant fail closed。

### M1.4 测试

- [x] 正常源码读取和 `git status` 允许。
- [x] `.ssh`、`.env` 和已知凭据路径询问或拒绝。
- [x] 工作区外删除拒绝。
- [x] 批量覆盖询问。
- [x] 下载后执行和明显破坏命令拒绝。
- [x] 未授权域名询问，疑似 secret 外发询问或根据显式外传信号拒绝。
- [x] grant 范围、消费、TTL 和撤销测试。

验收：Action Core 不导入 DSH、React、模型 SDK 或 Companion 代码，单元测试可独立运行。

## 7. M2 — CLI Policy Simulator

### M2.1 命令

增加：

```bash
dsh-guard policy show
dsh-guard policy check <action-request.json>
cat action-request.json | dsh-guard policy check - --json
```

任务：

- [x] `policy show` 输出当前 policy ID、hash 和稳定配置摘要。
- [x] `policy check` 从文件或 stdin 读取 fixture，不执行工具。
- [x] human 输出显示 effect、risk、rule、reason 和资源。
- [x] `--json` 输出版本化 `ActionDecisionV1`。
- [x] 无效 JSON、未知 schema、输入上限和秘密回显有回归测试。

### M2.2 误报基准

已在 `packages/cli/test/fixtures/action` 建立固定 workflow corpus：

- 搜索代码、读取源码、`git status`、运行安全测试。
- 修改工作区普通文件。
- 读取敏感文件。
- 工作区外删除。
- 未授权网络发送。
- 编码命令、下载后执行和 shell 链。

验收：在接入 DSH 前能够重复计算所有预期裁决，并保存基准误报结果。

## 8. M3 — DSH Action Gate

### M3.1 Compatibility spike

- [x] 钉死 rc.6 `tools/pre-execute` 的事件字段、返回值和 approval 交互。
- [x] 确认 `tools/post-execute` 是可改写中间结果，最终审计改用深度冻结、失败隔离的 `tools/result`。
- [x] 确认 session ID、cwd、工具 schema 和 task/goal 标识的可用性。
- [x] 对缺失字段定义显式降级，不从展示名称或 `rootCallId` 推断安全身份。

### M3.2 Tool adapters

优先顺序：

1. 文件读取、写入和删除。
2. Bash/PowerShell 和子进程。
3. Web/HTTP 发送与获取。
4. 其他明确产生副作用的内置工具。

每个适配器必须提供：

- [x] 通过 Companion exact peerDependencies 把适配器支持范围固定为 DSH `0.1.0-rc.6`；升级版本必须重跑 compatibility spike。
- [x] 原始输入适配器测试。
- [x] 建立固定 rc.6 工具输入 → 标准化 ActionRequest 字段 corpus。
- [x] 无法理解参数时失败关闭，未知工具默认 `ask`。

### M3.3 Hook orchestration

- [x] pre-execute 调用 normalizer、policy 和 grant store。
- [x] `allow` 直接继续并记录 decision。
- [x] `deny` 返回稳定错误和用户可读原因。
- [x] `ask` 通过 DSH approval 请求用户选择。
- [x] approval 不可用或拒绝时不自动允许；取消由 DSH 失败关闭。
- [x] 使用 `tools/result` 关联最终结果并记录 approved/denied/succeeded/failed。
- [x] orphan request 超时后标记 unknown，插件卸载时在途请求也以 `GATE_DISPOSED` 收口。

验收：隔离 profile 中三种裁决和权威 `tools/result` 结果均有自动化集成测试。

## 9. M4 — Grants、事件与本地状态

### M4.1 存储

- [x] 新建 versioned policy、grant 和 action event store。
- [x] grant 使用私有锁、临时文件、fsync 和原子 rename。
- [x] Action Event 使用 append-only JSONL、大小上限和轮转。
- [x] 不把 Action Event 混入旧 `GuardEvent` schema。
- [x] `doctor` 检查目录权限、schema 和轮转状态。

### M4.2 隐私与脱敏

- [x] 环境变量值、Authorization/Cookie、私钥正文永不持久化。
- [x] URL query 不进入资源摘要，命令参数和路径中的 token 模式脱敏。
- [x] 保存资源摘要和 digest，不保存完整参数、文件/HTTP body 或工具输出。
- [x] 畸形参数 fuzz corpus 确保适配/序列化失败关闭而不崩溃。

### M4.3 生命周期

- [x] Agent/session disposal 时撤销相关 grant。
- [x] TTL 到期时 grant 失效；rc.6 没有可靠 task ID，因此不创建或展示任务 grant，也不存在可安全监听的 task 变化。
- [x] policy hash 变化时使旧 grant 失效。
- [x] 用户可通过 CLI 立即撤销单个或全部 grant。

验收：状态损坏、进程重启和轮转失败均不存在授权扩张或错误绿灯。

## 10. M5 — Security Center UX

### M5.1 审批

- [x] 在 DSH 原生 approval reason 中显示 session、工具、操作、资源、规则、风险和可逆性；rc.6 没有更强的独立 Agent 身份。
- [x] 复用 DSH 原生“阻止”“仅本次允许”；只有未来 DSH 提供可靠 task ID 后才显示“本任务允许”。
- [x] Companion 不增加自定义批准按钮；真实 DSH 页面验证快速详情默认焦点、Esc 关闭、焦点恢复和 focus-visible。
- [x] 不展示单一安全分数，不使用诱导性颜色或文案。

### M5.2 安全中心

- [x] 新增最近 Action Event 列表，并显示 session 或 legacy 身份缺失状态。
- [x] 新增当前 profile 的有效 grant 及到期时间。
- [x] 支持通过严格同源、仅撤销的 Host API 立即撤销 grant。
- [x] 显示审计/状态降级、policy 状态损坏、unknown outcome 和门禁被配置关闭。
- [x] 明确提示“不能拦截插件直接 Node.js 调用”。

### M5.3 Sidecar 与告警

- [x] Sidecar 不进入审批路径。
- [x] Action 解释失败不改变 decision。
- [x] 只为 critical deny、审计/授权降级或重复危险请求产生持久告警。
- [x] 普通 allow 不制造通知噪声。

验收：真实 DSH 页面完成正常、空状态、错误状态、键盘和 reduced-motion QA。

## 11. M6 — Local Alpha

### M6.1 发布场景

- [x] 固定普通编码 corpus（源码读写、搜索、`git status`）不产生多余审批；真实 alpha 频率继续采集。
- [x] 凭据读取被拦截。
- [x] 字面 `rm` 危险删除展示规范化路径和目标数量；越界目标拒绝，无法解析的 shell 表达式不伪装成精确理解。
- [x] 未授权网络目标进入询问，显式 secret 外发被拒绝。
- [x] grant 范围、一次消费、TTL、policy hash 和撤销符合预期；rc.6 不创建任务 grant。
- [x] 事件可通过真实 Security Center 和 CLI 解释，空状态与损坏状态不会出现错误绿灯。

### M6.2 回归

- [x] `pnpm check` 全绿。
- [x] 现有 Trust Gate 单元、构建和隔离 E2E 全绿。
- [x] Action Core、CLI、Companion 集成和 Host API E2E 全绿；真实 rc.6 `ToolRuntime` 覆盖 allow / ask / deny / result。
- [x] Node `22.23.1` 和目标 DSH `0.1.0-rc.6` compatibility spike 通过。
- [x] README、安全模型、v1 基线、v2 设计、运行手册和实际代码完成一致性审查。

### M6.3 Alpha 评审

- [x] 威胁模型复审：运行时只声称覆盖 DSH Tool Registry，不声称阻止直接 Node.js 调用。
- [x] 默认策略误报复审：普通 corpus allow；未知、敏感和非只读操作保持 ask/deny。
- [x] grant 扩权与持久化复审：hard deny 优先，严格 profile/session/resource/policy hash，损坏状态不授权。
- [x] 敏感数据持久化复审：事件与 Host API 只返回摘要/digest，E2E 注入 secret 未泄漏。
- [x] 已知绕过和用户提示复审：Security Center Boundary 与运行手册列出 direct Node、语义外传、task identity、repair/uninstall 等限制。

## 12. 明确延后

以下工作不进入 v0.2：

- 进程外 Guard daemon。
- 网络出口代理和 Secret Broker。
- 宿主插件 Node.js API 强制隔离。
- 多 Agent 强身份与委托证明。
- 企业 RBAC、云端策略和 SIEM。
- 通用策略语言和第三方规则市场。
- Windows/Linux 支持。

## 13. 建议提交顺序

1. `docs: define v0.2 action gate`
2. `feat(core): add action schemas and policy engine`
3. `feat(cli): add action policy simulator`
4. `feat(companion): normalize and gate tool actions`
5. `feat(core): add scoped grants and action events`
6. `feat(companion): add action approvals and security center views`
7. `test: add action gate integration and e2e coverage`
8. `docs: publish v0.2 local alpha runbook`

每个提交必须独立通过相关测试，不把 schema、DSH Hook 和 UI 混在同一个不可审查提交中。

## 14. Definition of Done

一项 v0.2 任务只有同时满足以下条件才算完成：

- 行为和安全边界在设计中有依据。
- 类型和持久对象有严格 schema。
- 正常、失败、损坏和绕过场景有测试。
- 错误不会把高风险决策降级为 allow。
- 持久数据经过脱敏检查。
- human 与 JSON 输出契约一致。
- 现有 Trust Gate 回归测试未退化。
- README 只把真正实现的能力标为已实现。
