# DSH Guard 插件优先产品边界设计

> 状态：已确认
> 日期：2026-08-19
> 适用基线：DSH Guard v0.4 本地 alpha、DeepSeek Harness 0.1.0-rc.7

## 1. 决策

DSH Guard 的默认产品定位恢复为 **DeepSeek Harness 第三方插件的本地供应链与生命周期防护工具**。

现有 Action Gate 保留，但更名为 **Agent 操作保护**，作为独立、默认关闭的可选能力。它保护所有经过 DSH Tool Registry 的工具调用，不能按 npm 包或插件发布者可靠归因，因此不得再被描述为“恶意插件运行时拦截”。

## 2. 用户心智

默认安装 DSH Guard 后，用户得到：

- 插件安装前的制品固定、静态能力扫描和隔离 staging。
- 扫描结果与审批、目标 profile 和最终安装内容的绑定。
- 受管插件 inventory、更新、卸载、修复、回滚和漂移告警。
- DSH 内的插件安全状态、受管插件列表和高危生命周期事件。

用户不会默认得到：

- 对主 Agent 的文件、Shell、网络工具门禁。
- 已运行 Host 插件的逐插件进程隔离。
- 对插件直接调用 Node.js `fs`、`fetch`、`net` 或 `child_process` 的拦截。

如果用户显式启用 Agent 操作保护，文件、Bash 和 Web 等所有正规工具调用都按 `allow / ask / deny` 策略评估。审批和阻止对象是 **Agent 工具动作**，不是插件身份。

## 3. 为什么不做“只拦插件工具”

DSH rc.7 的 `ToolExecution` 提供 Agent、工具名、参数和调用关联，但没有可靠的 npm 包注册来源。根据名称、加载顺序或静态扫描结果猜测工具归属会产生可绕过的安全声明。

即使能标记插件注册的工具，也仍会漏掉两条路径：

1. 插件通过提示或上下文诱导主 Agent 调用内置 `read`、`bash` 或网络工具。
2. Host 插件绕开 Tool Registry，直接调用 Node.js API。

因此 DSH Guard 不实现推断式逐插件 Action Gate。未来若 DSH 提供不可伪造的注册 provenance，它可用于审计展示，但仍不能替代进程隔离。

## 4. 产品架构

### 4.1 默认启用：插件安全

- **Trust Gate**：`scan → approve → install → verify`。
- **Plugin Lifecycle**：受管 generation、update、uninstall、repair、rollback。
- **Companion 可见性**：插件安全状态、受控插件、高危生命周期告警、CLI 验证入口。

这些能力不注册全局工具门禁，不应改变主 Agent 的正常调用。

### 4.2 默认关闭：Agent 操作保护

`actionPolicyEnabled: true` 是显式 opt-in。启用后才注册 `tools/pre-execute` 和 `tools/result`，并显示动作事件与授权。关闭时：

- 不注册 contextual 或 exact-name 工具策略。
- `denyTools`、`askTools` 和 `askUnknownTools` 不产生运行时效果。
- 历史动作事件可以只读展示，但界面明确标记保护已关闭。

### 4.3 实验性：整进程隔离

`dsh-guard sandbox run` 继续作为显式实验模式。它把 DSH Core、主 Agent、Companion 和所有 Host 插件放进同一 OS sandbox，因此会同时限制主 Agent。界面和文档必须始终称其为“整进程隔离”，不能称为逐插件沙箱。

真正的插件运行时隔离需要独立插件进程、最小能力 IPC 和进程外文件/网络/凭据代理；这属于后续架构，不在本次默认行为修正中实现。

## 5. 界面与文案

安全中心按以下顺序展示：

1. **插件安全**：profile 状态、报告指标、受控插件、高危生命周期事件、完整验证命令。
2. **Agent 操作保护（可选）**：独立边界卡片、启用状态、覆盖范围、历史动作和授权。

动作告警使用“已阻止 Agent 高危工具操作”。生命周期告警继续使用“发现未纳管插件”“插件生命周期状态损坏”等插件语义。两类事件不得混称。

## 6. 配置与迁移

新安装的 Companion patch 和 schema 默认值均为：

```yaml
actionPolicyEnabled: false
```

已有 profile 若显式保存了 `true`，升级不会偷偷覆盖用户配置；用户必须把完整 Companion 配置中的字段改为 `false` 并重启 DSH，或通过受控插件更新安装新的默认 patch。

启用时必须使用显式配置，并在安全中心显示“会检查主 Agent 和所有其他 Agent 的正规工具调用”。关闭不是卸载，不影响插件扫描、安装、验证和生命周期管理。

## 7. 错误处理

- Agent 操作保护关闭时，不读取 grant 作为放行依据，也不注册任何工具拦截 Hook。
- 启用后沿用现有高风险 fail-closed、审计轮转和授权撤销规则。
- 插件 inventory 或 lifecycle state 损坏仍进入 `needs-repair`，与 Agent 操作保护开关无关。
- OS sandbox 计划或启动失败时继续拒绝降级为普通启动。

## 8. 验收与测试

1. Config schema 和 `cordis.patch.yml` 的 `actionPolicyEnabled` 默认均为 `false`。
2. 默认 Companion 启动后，主 Agent 读取、Shell 和未知工具调用不经过 DSH Guard 门禁。
3. 显式设为 `true` 后，现有 Action Gate allow/ask/deny、审计和授权测试全部继续通过。
4. `false` 且 `denyTools`/`askTools` 非空时仍不注册精确工具策略。
5. 安全中心先展示插件安全，再展示可选 Agent 操作保护。
6. UI、README 和运行手册不把 Agent 工具阻止描述成插件拦截。
7. Trust Gate、Plugin Lifecycle、Host API、sandbox 和 rc.7 E2E 回归保持通过。

## 9. 后续路线

- 研究 DSH 是否能提供不可伪造的工具注册 provenance，用于审计而非安全边界。
- 设计独立插件 worker 与能力代理原型。
- 在独立进程边界成立前，不发布“运行时拦截恶意插件”的声明。
