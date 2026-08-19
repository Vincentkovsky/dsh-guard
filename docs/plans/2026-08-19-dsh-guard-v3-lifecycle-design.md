# DSH Guard v0.3 Plugin Lifecycle 设计

> 状态：v0.3 本地 alpha 基线完成
> 日期：2026-08-19
> 前置基线：v0.1 Trust Gate、v0.2 Action Gate 本地 alpha

## 1. 为什么做这一版

v0.2 已经能在安装前检查插件、绑定审批并在安装后检测 profile 漂移，但安装记录仍是“每个 profile 只记最后一次安装”。用户不能可靠回答以下问题：当前有哪些插件由 Guard 管理、一次更新改变了什么、发生漂移后应该恢复到哪一版、如何安全卸载。

v0.3 的目标是把单次安全安装升级为可恢复的插件生命周期：

- 列出每个 profile 的受管插件和当前状态。
- 更新仍然经过 scan → approve → 隔离 staging，不存在静默升级。
- 卸载先在隔离 profile 演练，再在真实 profile 执行并比对。
- repair 恢复当前已批准 generation。
- rollback 恢复历史 generation，同时保留新的审计记录，不改写历史。

本版不把 DSH Guard 变成通用包管理器，也不扩大 v0.2 的运行时隔离声明。

## 2. 方案选择

### 方案 A：为现有 DSH 命令增加薄包装

实现快，但无法证明卸载或更新后的 profile 与用户批准的结果一致，也没有可靠修复目标。拒绝。

### 方案 B：由 Guard 重写 DSH 的 profile 与依赖管理

控制力最强，但会复制 pnpm 和 DSH bundle reconciliation 语义，升级风险过高。拒绝。

### 方案 C：受管 generation + DSH 原生命令（采用）

Guard 继续让精确版本的 DSH 执行 add/remove/install，同时在隔离副本中预演，并把受控结果保存为不可变 generation。真实执行后必须与预演结果一致；repair/rollback 通过私有快照和 offline frozen hydration 恢复。

该方案复用已经验证的 Trust Gate、内容寻址 artifact、profile 锁和 DSH rc.6 行为，同时建立缺失的恢复语义。

## 3. 用户模型

用户看到的是“受管插件”，不是内部报告文件：

```text
Profile web
├── @dsh-guard/companion 0.1.0   verified
├── example-plugin 2.3.1         verified
└── generation gen_...           current
```

命令面：

```bash
dsh-guard plugins list [--profile web] [--json]
dsh-guard plugins history --profile web [--json]
dsh-guard plugins update <approved-report-id>
dsh-guard plugins uninstall <package> --profile web --confirm <package>
dsh-guard plugins repair --profile web --confirm web
dsh-guard plugins rollback --profile web --to <generation-id> --confirm <generation-id>
```

`install <report-id>` 只安装尚未受管的包；已受管包必须使用 `plugins update`。update 接受已经完成 scan 和 approve 的报告，因此版本、artifact、profile 和 policy 绑定不变。

## 4. 数据模型

新增私有状态：

```text
~/.dsh-guard/
├── managed-profiles/<profile>.json
└── generations/<profile>/<generation-id>/
    ├── manifest.json
    ├── package.json
    ├── pnpm-lock.yaml
    ├── pnpm-workspace.yaml
    ├── cordis.yml
    └── cordis.patch.yml
```

`ManagedProfileV1` 保存：

- profile 名称和当前 generation ID。
- 有界的 generation 元数据列表。
- 每个 generation 的父节点、动作、时间、profile 指纹、组合配置哈希。
- generation 当时完整的受管插件集合。

`ManagedPluginV1` 保存 package、version、report、artifact digest、首次安装时间、最近更新时间和它引入的 bundle。它不保存插件源码、工具参数或 secret。

快照目录权限为 `0700`，文件为 `0600`。manifest 对每个控制文件保存 SHA-256 或明确的 missing 标记。读取时拒绝 symlink、未知 schema、重复 generation、越界 snapshot ID、指纹不一致和 current generation 缺失。状态更新使用临时文件、fsync 和原子 rename。

历史 generation 默认最多保留 20 个；实现清理前不自动删除，以免在 alpha 中误删唯一恢复点。

## 5. 操作语义

### 5.1 安装与更新

共同前置条件：报告不为 blocked、staging 成功、审批哈希有效、artifact 未变化、真实 profile 与报告基线一致、profile 未运行、独占锁成功。

安装要求 package 尚未受管；更新要求 package 已受管且 artifact digest 或 version 发生变化。真实 `dsh plugin add` 后必须同时匹配 staging 的 lock hash、profile fingerprint、bundle 列表和组合配置 hash。成功后才写 generation；状态写入失败也视为操作失败并恢复执行前快照。

### 5.2 卸载

只允许卸载当前 inventory 中的精确 package 名。用户必须用 `--confirm` 重述 package。Guard 在 sibling DSH home 中恢复依赖、执行 rc.6 `plugin remove`、运行 `--dump-config` 并形成 proposal；真实操作必须完全匹配 proposal。不会提供 `--force`。

### 5.3 Repair

repair 的目标只能是当前 generation，不会猜测“看起来正常”的状态。用户必须用 `--confirm` 重述 profile。Guard 先备份当前漂移状态，再恢复 generation 的五个控制文件，执行 `plugin install --frozen-lockfile --offline --ignore-scripts`，最后验证指纹和配置哈希。

### 5.4 Rollback

rollback 需要显式 generation ID 和相同的 `--confirm` 值。它恢复目标快照和当时的完整 inventory，然后创建一个新的 rollback generation；旧历史保持不可变。当前 profile 如果已漂移，默认拒绝，只有显式 `--allow-drift` 才能在保留操作前备份后继续。

## 6. 失败、恢复与并发

所有写操作共享 profile 级独占锁，并在 DSH profile 运行时拒绝执行。每次真实修改前建立操作备份。失败时：

1. 恢复执行前五个控制文件。
2. 用执行前 lockfile 做 offline frozen hydration。
3. 验证执行前 profile fingerprint。
4. 记录 `*-failed-recovered`；如果失败则记录 `needs-repair`、保留两个恢复点并返回退出码 5。

进程崩溃留下的锁不会自动偷走。`doctor` 负责报告锁文件和 lifecycle state 问题；后续可以增加带 PID/boot identity 的 stale-lock recovery，但本版不凭时间删除锁。

## 7. 兼容与迁移

现有 `installs/<profile>.json` 继续读取。只有当真实 profile 仍与旧记录指纹一致时，才允许把它导入为 `legacy-import` generation 并捕获可信快照；漂移的旧状态不会被固化成新基线。

`verify` 优先使用新 inventory；没有新状态时回退旧记录。Security Center 的 `managedPackages` 改为显示当前 generation 中的全部插件。旧 Host API schemaVersion 保持 1，新增数组内容是向后兼容扩展。

## 8. 安全边界

- update 不访问“最新版本”或自动解析新版本；用户必须显式 scan 一个 spec。
- uninstall 不接受路径、glob、别名或不受管包。
- repair/rollback 不执行候选 lifecycle scripts。
- snapshot 只覆盖五个 DSH profile 控制文件，不备份 `node_modules`、用户 workspace 或插件运行数据。
- offline hydration 依赖 Guard cache；缺失 artifact/store 时失败关闭。
- 同用户恶意进程仍可篡改 Guard 与 profile；进程外隔离不在 v0.3 范围。

## 9. 验收场景

1. 连续安装两个插件后 inventory 同时显示两个，verify 仍为 verified。
2. 对已受管包使用 install 被拒绝；批准后的 update 生成新 generation。
3. 卸载 proposal 与真实结果一致，目标包和其 bundle 消失，另一受管包保留。
4. 手工修改控制文件后 verify 为 drifted；repair 恢复 current generation。
5. rollback 恢复旧版本、旧 bundle 集合和旧 inventory，并产生新 generation。
6. 错误确认值、运行中的 profile、损坏状态、symlink 快照、缺失 cache、并发锁全部失败关闭。
7. 任一步骤失败时要么恢复到执行前指纹，要么进入 needs-repair，不能产生错误绿灯。
8. v0.1/v0.2 单元、Action Gate、Companion 和隔离 DSH E2E 持续通过。
