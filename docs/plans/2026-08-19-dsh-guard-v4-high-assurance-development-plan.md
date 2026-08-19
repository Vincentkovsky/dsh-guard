# DSH Guard v0.4 实验性 OS Sandbox Launcher 开发计划

> 状态：执行中
> 日期：2026-08-19
> 设计依据：[v0.4 High-Assurance Launcher 设计](./2026-08-19-dsh-guard-v4-high-assurance-design.md)

## M0 — Compatibility Spike

- [x] 确认 macOS 26.4.1 仍提供 deprecated `/usr/bin/sandbox-exec`。
- [x] 证明 deny-default 策略可运行 Node 22.23.1。
- [x] 证明工作区读取允许，home 读取、child process 和公网连接返回 `EPERM`。
- [x] 证明精确 DSH `0.1.0-rc.6` 可在最小路径策略中执行 `--dump-config`。
- [x] 核对 DSH launcher 参数转发和 `--profile` 语义。

## M1 — Policy Core

- [x] 新增严格 `SandboxPlanV1` schema 和稳定 hash。
- [x] 实现 realpath、文件类型、宽泛 root、祖先 metadata 和重叠路径校验。
- [x] 实现 SBPL 字符串转义和 deny-default policy compiler。
- [x] 实现 deny/loopback/unrestricted 网络规则。
- [x] 实现严格环境 allowlist、保留变量和 secret warning。
- [x] 单元测试正常、损坏、symlink、注入和跨平台失败路径。
- [x] 根据真实 rc.6 行为增加 verified profile 一次性副本，避免启动写入真实 `cordis.yml`。

## M2 — CLI Plan

- [x] `sandbox plan --profile --workspace --network` human/JSON 输出。
- [x] 计划显示能力、warning、路径和 policy hash，不显示环境值。
- [x] 支持重复 workspace 与 allow-env，稳定去重排序。
- [x] 校验 `--host` 只允许 loopback。

## M3 — Sandbox Run

- [x] 非 verified profile 失败关闭。
- [x] 使用精确 Node/DSH realpath 和 `/usr/bin/sandbox-exec`，不经过 shell。
- [x] 使用收缩环境、workspace cwd 和原始 DSH app args。
- [x] 继承 stdio、处理信号并传播原始退出码。
- [x] 审计只记录 policy/workspace digest、来源 fingerprint 和环境名。
- [x] sandbox 启动失败不回退普通 DSH。

## M4 — Verification

- [x] Core/CLI 对抗性测试通过。
- [x] macOS 真实隔离 probe 覆盖文件、进程、loopback 与公网网络。
- [x] 一次性 profile 中的 DSH rc.6 `--dump-config` 通过。
- [x] v0.3 双插件 lifecycle E2E 与 Action Gate 回归通过。
- [x] README、安全模型和运行手册与实现一致。
- [x] 工作树无临时策略、真实 profile 内容或 secret。

## 提交顺序

1. `docs: define v0.4 sandbox launcher`
2. `feat(core): compile macOS sandbox plans`
3. `feat(cli): add sandbox plan and run`
4. `test: verify macOS sandbox boundary`
5. `docs: publish v0.4 experimental runbook`
