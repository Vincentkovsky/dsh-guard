# DSH Guard Guarded Launch 设计

日期：2026-08-19
状态：已确认，进入实现

## 目标与边界

本阶段把 DSH Guard 从“能发现 profile 漂移”推进到“漂移内容不会经由受保护入口加载”。新增 `dsh-guard start --profile <name> -- [DSH 应用参数]`：它在创建 DSH 子进程前验证 profile 必须精确匹配当前受管 generation，且不能包含未纳管 bundle。验证失败时，DSH 进程不会创建；可疑文件保留在原位，供用户检查、修复或重新扫描审批。

Guarded Launch 只约束插件供应链和 profile 完整性。它不注册 Agent 工具钩子，不改变主 Agent、DSH 内置工具或模型行为，也不承诺对已经批准且正在运行的插件做进程内权限隔离。需要 OS 级限制时仍使用实验性的 `sandbox run`。

## 方案选择

不采用 Companion 进程内拦截。DSH 基于 Cordis 组合插件树，Companion 与其他插件是普通兄弟节点；恶意插件可能在 Companion 之前执行，因而无法形成可靠的启动前边界。

不采用自动删除或改写可疑插件。自动修改 profile 会扩大误伤面，并可能破坏用户配置或丢失取证材料。

采用独立 Guarded Launcher。它位于 DSH 进程之前，复用现有不可变 generation、profile fingerprint、未纳管 bundle 检测和审计记录。失败关闭时“隔离”的含义是拒绝加载整个不可信 profile，而不是删除文件。

## 数据流与安全规则

1. 解析并验证启动参数；拒绝 `--profile`、`--patch` 等可绕过受管 profile 的覆盖参数。
2. 初始化 Guard 私有状态并定位 DSH 启动器。
3. 调用 `verifyProfile`，同时刷新 Companion 使用的 `status.json`。
4. 只有 `verified` 才继续；`unknown`、`drifted`、`needs-repair` 全部失败关闭并写入脱敏审计。
5. 在真正 spawn 前再次读取五个 profile 控制文件并比较 fingerprint，缩小校验到启动之间的竞态窗口。
6. 使用明确的 profile、DSH_HOME 和 Guard 状态目录启动 DSH，转发 SIGINT/SIGTERM，并继承子进程退出码。

启动器使用真实 DSH_HOME，以保留 sessions、storages、settings 和凭据的正常体验。它会移除 `NODE_OPTIONS`、`NODE_PATH`、`DYLD_*`、`LD_*` 等进程注入变量，但不会过滤正常模型 API 环境变量。批准插件仍与 DSH 共享宿主权限；这不是 sandbox 的替代品。

## 错误处理与可恢复性

拒绝启动不会修改 profile，也不会自动执行 repair。错误信息必须说明当前状态、未纳管 bundle（若有）以及下一步命令。用户可以执行 `dsh-guard verify` 查看证据，使用 `plugins repair` 恢复当前 generation，或对新插件重新走 scan、approve、install。

原始 `dsh web` 无法被普通 npm 包从系统层面禁止，因此属于显式绕过路径。README 必须明确：只有通过 `dsh-guard start` 启动的进程受到启动前安检保护。后续版本可以提供可选 shell shim，但本阶段不自动改写 PATH 或用户 shell 配置。

## 验收标准

- 已验证 profile 能以原参数启动，退出码和信号正确传递。
- 未纳管 bundle、任意控制文件漂移或无受管状态时，DSH runner 调用次数为零。
- `--profile` 和 `--patch` 覆盖被拒绝。
- 校验后、spawn 前发生的二次漂移被拒绝。
- 启动允许和拒绝都留下不包含凭据值的审计记录，并刷新 UI 状态文件。
- Agent 操作保护保持默认关闭；现有扫描、安装、生命周期和 sandbox 测试全部继续通过。
