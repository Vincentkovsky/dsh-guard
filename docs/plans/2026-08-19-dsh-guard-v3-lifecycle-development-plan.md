# DSH Guard v0.3 Plugin Lifecycle 开发计划

> 状态：v0.3 本地 alpha 基线完成
> 日期：2026-08-19
> 设计依据：[v0.3 Plugin Lifecycle 设计](./2026-08-19-dsh-guard-v3-lifecycle-design.md)

## 1. M0 — 契约与基线

- [x] 核对 DSH `0.1.0-rc.6` plugin forwarder 的 add/remove/install 与 bundle reconciliation 语义。
- [x] 冻结受管插件、generation、snapshot manifest 和操作结果类型。
- [x] 明确 update 不自动解析最新版本，继续使用 scan/approve 报告。
- [x] 明确 repair、rollback 和 uninstall 的确认及失败关闭语义。
- [x] 保存 v0.2 全量测试与隔离 E2E 基线。

## 2. M1 — Lifecycle State

- [x] 新增严格 `ManagedProfileV1`、`ProfileGenerationV1`、`ManagedPluginV1` schema。
- [x] 新增私有 generation snapshot 的创建、校验和恢复。
- [x] 新增原子 inventory 存储和 profile 级读取。
- [x] 在真实 profile 与旧 InstallRecord 一致时执行安全迁移。
- [x] 损坏、symlink、重复 ID、current 缺失和 snapshot digest 不匹配测试。

## 3. M2 — 多插件安装与验证

- [x] install 成功后记录完整 generation 和受管 package。
- [x] 已受管 package 通过 install 失败并指向 update。
- [x] update 复用 scan/approve/staging，要求 package 已受管。
- [x] verify 以 current generation 为权威，并返回全部 managed packages。
- [x] Security Center status 显示全部受管插件。

## 4. M3 — Uninstall

- [x] 在隔离 sibling DSH home 中运行 remove proposal。
- [x] 真实 remove 共享停机检查、锁、备份和精确比对。
- [x] 精确 package 与 `--confirm` 验证。
- [x] 保留其他受管插件、bundle 和 generation。
- [x] 失败恢复与 needs-repair 测试。

## 5. M4 — Repair 与 Rollback

- [x] repair 恢复 current generation 并 offline frozen hydrate。
- [x] repair no-op、漂移恢复、cache 缺失和恢复失败测试。
- [x] history 列出可恢复 generation。
- [x] rollback 恢复目标 snapshot 与 inventory并创建新 generation。
- [x] rollback 默认拒绝漂移，`--allow-drift` 显式覆盖。

## 6. M5 — CLI 与诊断

- [x] `plugins list/history/update/uninstall/repair/rollback` human/JSON 输出。
- [x] destructive 命令要求 exact confirmation。
- [x] `doctor` 检查 lifecycle state、snapshot 和 lock。
- [x] 错误信息脱敏，退出码与现有契约一致。

## 7. M6 — Alpha 回归

- [x] 单元、CLI、Companion、typecheck 和 build 全绿。
- [x] 隔离 E2E 覆盖 install → list → drift → repair → update/uninstall → rollback。
- [x] 精确 DSH rc.6 + Node 22.22+ compatibility 复核。
- [x] README、安全模型和运行手册与实际行为一致。
- [x] 工作树无敏感数据、临时状态或真实 profile 内容。

## 8. 提交顺序

1. `docs: define v0.3 plugin lifecycle`
2. `feat(core): persist managed profile generations`
3. `feat(core): manage plugin lifecycle transactions`
4. `feat(cli): add plugin lifecycle commands`
5. `test: cover lifecycle recovery and e2e`
6. `docs: publish v0.3 local alpha runbook`
