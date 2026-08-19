# DSH Guard Guarded Launch 开发计划

日期：2026-08-19

## 1. 核心启动器

- [x] 新增 Guarded Launch 参数校验、环境构造、子进程与信号转发。
- [x] 拒绝 profile/patch 覆盖和进程注入环境变量。
- [x] 导出可注入、可单测的 runner。

## 2. CLI 安检门

- [x] 新增 `dsh-guard start --profile <name> -- [args...]`。
- [x] 启动前执行 verify、写入 status、记录 allow/deny 审计。
- [x] spawn 前二次 fingerprint 校验，竞态时失败关闭。
- [x] 保留 DSH 子进程退出码。

## 3. 产品说明

- [x] README 把 Guarded Launch 设为推荐启动方式。
- [x] 明确原始 `dsh` 是绕过路径，以及 Guarded Launch 与 sandbox 的差别。
- [x] 更新本地 Alpha 验证步骤。

## 4. 测试与验收

- [x] 单测参数、环境、信号和 runner。
- [x] CLI 测试 verified、unknown/drifted/needs-repair、二次漂移和审计。
- [x] 真实 rc.7 E2E：可信 profile 可启动；加入未审批漂移后子进程完全不启动。
- [x] 运行 `pnpm check`，确认现有功能无回归。
