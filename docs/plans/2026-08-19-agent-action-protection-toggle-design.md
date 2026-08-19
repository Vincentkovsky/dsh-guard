# Agent 操作保护开关设计

## 目标

在 Security Center 的“Agent 操作保护”区域提供按 profile 生效的二态开关。默认关闭；开启后，主 Agent 与其他 Agent 通过 DSH tool registry 发起的调用进入现有 Action Gate。关闭只影响 Agent 工具调用保护，不影响插件扫描、受控安装、生命周期、漂移检测或 Guarded Launch。

## 状态与边界

运行时设置保存在 `$DSH_GUARD_HOME/action-protection.json`，不写入 DSH profile，因此不会改变受管 generation 的 fingerprint。文件使用版本化严格 schema、0600 权限、拒绝符号链接、原子写入和进程锁，并按 profile 记录 `enabled` 与 `updatedAt`。

Companion 启动时始终注册 Action Gate 事件处理器。首次工具调用、状态读取和设置写入都会等待设置加载完成；设置文件损坏时失败关闭为“保护开启”并报告降级，不能静默绕过。关闭时撤销全部临时授权，历史动作事件保留用于审计。

Host 只在 loopback Web 服务上提供同源 POST `/dsh-guard/api/action-protection`。请求体只接受 `{ "enabled": boolean }`。更新成功后写入独立设置文件、更新内存状态、记录审计并返回最新状态。Host 插件直接调用 Node.js API 仍不在 Action Gate 覆盖范围内。

## 界面

区域标题右侧显示可访问的二态 switch，并明确显示“开启/关闭”。关闭时说明不会检查主 Agent 工具调用，同时重申插件保护仍有效；开启时说明正规工具调用会经过策略。关闭时指标名称使用“历史事件”，避免把保留的审计记录误解为当前仍在拦截。

关闭保护需要一次确认；开启不需要确认。提交期间 switch 禁用并显示处理中状态，失败时恢复服务端权威状态并显示错误。Host API 不可用或状态降级时不得伪装成功。

## 验收

1. 新安装且无运行时设置时默认关闭。
2. 页面开启后无需重启即可拦截高危工具调用，刷新页面仍保持开启。
3. 页面关闭后普通工具调用直通，全部现有 grant 被撤销，历史事件仍可查看。
4. 设置文件损坏、权限过宽或为符号链接时失败关闭并展示降级。
5. 切换不修改 `$DSH_HOME/profiles/<name>` 中任何文件，`dsh-guard verify` 继续返回 `verified`。
