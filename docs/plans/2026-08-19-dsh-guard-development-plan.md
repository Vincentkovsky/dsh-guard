# DSH Guard 开发计划

> 基线日期：2026-08-19
> 当前状态：功能原型已实现并通过 12 个测试、隔离 E2E 和真实 DSH UI QA；仓库尚无提交
> 计划目标：把“可运行原型”推进到“可审计的本地 alpha”，再决定是否进入 beta/发布

## 1. 执行原则

1. 先冻结安全声明和数据模型，再扩功能。
2. 每个里程碑必须能独立验收；失败时不影响前一里程碑的可用性。
3. 任何 blocker 都由确定性规则产生，Sidecar 只解释。
4. 不以“测试通过”替代威胁模型审查，也不以“UI 正常”替代安装链验证。
5. 所有开发和 E2E 使用隔离的 `DSH_HOME` / `DSH_GUARD_HOME`，禁止修改真实 `web` profile。
6. 当前所有文件均未提交；首次提交前先完成基线审计，避免把原型状态误标为 release。

## 2. 当前实现盘点

| 能力 | 状态 | 主要位置 | 备注 |
|---|---|---|---|
| public npm / directory / `.tgz` 来源 | 原型完成 | `packages/core/src/source.ts` | 只支持 npmjs public registry |
| 内容寻址缓存与归档校验 | 原型完成 | `source.ts`, `archive.ts` | 临时目录清理仍需硬化 |
| manifest / AST / patch 扫描 | 原型完成 | `scanner.ts` | 只深扫根包 |
| profile staging / dump-config | 原型完成 | `profile.ts` | 仅 DSH rc.6/macOS 验证 |
| approve / offline install / verify | 原型完成 | `install.ts`, `profile.ts` | 恢复为 best effort |
| CLI 六命令与退出码 | 原型完成 | `packages/cli` | 缺 CLI 级测试 |
| Companion Host / UI / alerts | 原型完成 | `packages/dsh-plugin` | 状态逻辑与 core 重复 |
| deny/ask / Sidecar | 原型完成 | `dsh-plugin/src/index.ts` | Sidecar 缺超时/取消 |
| 单元、构建、隔离 E2E | 已通过 | `packages/*/test`, `scripts/e2e.mjs` | 共 12 个测试 |
| 多插件 inventory、update/remove/repair | 未实现 | — | beta 前核心缺口 |
| 发布、CI、版本迁移 | 未实现 | — | alpha 前需完成最小集 |

## 3. 优先级

- **P0**：错误会破坏安全不变量、产生错误绿灯或导致不可恢复状态。
- **P1**：不会直接绕过安全边界，但影响可维护性、证据质量或用户可用性。
- **P2**：扩展能力或后续版本工作。

## 4. 里程碑总览

| 里程碑 | 目标 | 当前状态 | 退出条件 |
|---|---|---|---|
| M0 设计与基线冻结 | 文档、声明、版本、仓库状态一致 | 进行中 | 设计/计划通过审阅，首次基线提交可创建 |
| M1 Scanner Hardening | 输入处理和证据链可审计 | 原型完成，待硬化 | 恶意 fixtures、资源清理、schema 校验全部通过 |
| M2 Install Gate Hardening | 无错误绿灯，可诊断恢复 | 原型完成，待硬化 | 多 generation 基线、锁恢复、repair 流程通过 |
| M3 Companion Hardening | UI/Host 不扩大攻击面 | 原型完成，待硬化 | 共享 schema、API/Sidecar/a11y 测试通过 |
| M4 Local Alpha | 可重复安装、验证和升级 | 未开始 | CI、打包、兼容矩阵、alpha runbook 完成 |
| M5 Beta 决策 | 评估多平台/OS 隔离/发布 | 未开始 | 根据 alpha 数据做 go/no-go |

建议按 M0 → M1 → M2 → M3 → M4 顺序执行。M1 与 M3 的部分测试可并行，但 M2 数据模型确定前不要扩展 Security Center 的多包 UI。

## 5. M0 — 设计与基线冻结

目标：把当前原型变成可评审基线，避免继续在未提交代码上扩张。

### M0.1 文档对齐（P0）

- [x] 新建设计文档，覆盖威胁模型、架构、数据流、错误处理和测试。
- [x] 新建开发计划，区分原型完成、待硬化和不在 v1。
- [ ] 在 README 增加设计与开发计划入口。
- [ ] 逐条比对 README、安全模型和代码中的安全声明。
- [ ] 将“每 profile 最近一次整体基线”限制明确写入用户文档。

验收：文档中不存在“防篡改”“原子回滚”“按包可靠拦截工具”“识别所有恶意插件”等超出实现的表述。

### M0.2 运行时与包元数据（P0）

- [ ] 将根包、core、CLI、Companion 的 `engines.node` 统一为 `>=22.22.0`。
- [ ] 明确 `packageManager` 与 lockfile 版本，记录用于验证的 pnpm 版本。
- [ ] 添加 `doctor` 回归测试，覆盖 Node 下限、DSH_BIN 缺失和目录权限。
- [ ] 确认所有 package `files/exports/bin` 与实际构建产物一致。

验收：在不满足运行时下限时 fail fast，不出现“安装成功但 Host 无法启动”。

### M0.3 首次基线提交（P0）

- [ ] 运行 secret scan、`git diff --check`、`pnpm check`、隔离 E2E。
- [ ] 确认没有真实 profile、缓存 artifact、报告、备份或凭据进入仓库。
- [ ] 形成单一可回退的 initial baseline commit；不混入发布标签。

验收：干净 checkout 可通过 `pnpm install --ignore-scripts && pnpm check`。

## 6. M1 — Scanner Hardening

目标：加强无执行输入链、报告可信度和资源安全。

### M1.1 临时资源生命周期（P0）

涉及：`source.ts`, `archive.ts`, `profile.ts`。

- [ ] 为 directory pack、npm download、artifact extract 和 staging 统一实现 `withTempDir()`。
- [ ] 正常、异常、SIGINT/SIGTERM 路径均清理临时目录。
- [ ] 清理前验证前缀和 realpath，禁止宽路径递归删除。
- [ ] 添加“解析失败/解压失败/staging 失败后无残留”的测试。

验收：连续运行 100 次 fixture scan 后，允许前缀下无遗留临时目录。

### M1.2 持久 schema 验证（P0）

涉及：`types.ts`, `state.ts`，建议新增 `schema.ts`。

- [ ] 为 report、approval、install、event、status 实现运行时 schema 校验。
- [ ] 读取未知 `schemaVersion` 时拒绝并给出迁移提示。
- [ ] 对 JSONL torn tail 保持容错，但拒绝结构合法性不足的记录。
- [ ] 给 stable JSON/digest 增加 golden tests。

验收：篡改字段类型、遗漏绑定字段或未来版本记录不能被当作有效审批/基线。

### M1.3 恶意与正常 fixtures（P0）

建议新增 `fixtures/`：

- [ ] `.env` / `~/.ssh` 读取与网络外传。
- [ ] `postinstall`、缺失 build output、下载后执行。
- [ ] path traversal、绝对路径、越界 symlink、link chain、压缩炸弹预算。
- [ ] `eval/new Function/vm/dynamic import` 和长行混淆。
- [ ] protected Cordis row 覆盖与普通扩展。
- [ ] 正常主题、通知、搜索插件，记录误报基线。

验收：每个 blocker 都有独立 fixture；正常样本不会被错误标记为 `blocked`。

### M1.4 依赖证据分层（P1）

- [ ] 把当前 `dependencyGraph` 更名或明确为 `declaredDependencies`，避免误解为解析后的完整图。
- [ ] 从 staged lockfile 提取 resolved dependency graph 和 lock diff。
- [ ] 根插件完整扫描；直接可达运行时依赖做重点能力传播；其他传递依赖只采集 integrity、script、native 和版本变化。
- [ ] 报告区分 `direct`、`reachable-dependency`、`transitive-evidence`。

验收：报告不会把依赖中的能力伪装成根插件直接调用，也不会对全部 node_modules 产生不可用噪音。

### M1.5 供应链元数据（P1）

- [ ] 记录版本年龄、repository/homepage、maintainer 集合和入口变化。
- [ ] 记录 npm provenance/signature 可用性，但 v1 不因缺失直接阻断。
- [ ] 对比上一受控版本的脚本、native dependency、域名和依赖差异。
- [ ] 加入可解释的近似包名提示，不输出单一“风险分”。

验收：所有供应链提示均带来源字段和解释，不把弱信号升级为确定性恶意结论。

## 7. M2 — Install Gate Hardening

目标：让受控安装支持长期使用，并对失败状态给出可操作恢复路径。

### M2.1 Profile generation 数据模型（P0）

当前 `installs/<profile>.json` 只保存最近包和整体 profile 基线。建议升级为：

```text
ProfileGenerationV2
├── generationId
├── parentGenerationId
├── profileFingerprint
├── lockHash
├── bundles[]
├── managedArtifacts[name] -> version/hash/reportId
└── createdAt / verifiedAt
```

- [ ] 先写 V2 schema 与 V1 只读迁移测试。
- [ ] 每次 add/update/remove 生成新 generation，不原地覆盖逐包历史。
- [ ] verify 以 generation 为权威，并能列出每个 managed/unmanaged package。
- [ ] Security Center 暂不接 V2，先保证 CLI 状态正确。

验收：连续安装两个插件后，两者都显示为受控；修改任一制品或 bundle 都能定位漂移。

### M2.2 操作锁和崩溃恢复（P0）

- [ ] 锁文件写入 PID、profile、operation、startedAt 和随机 nonce。
- [ ] `doctor` 检测 stale lock，不自动删除活跃锁。
- [ ] 提供显式 `unlock --stale`，要求 PID 不存在且 profile 已停止。
- [ ] 对 SIGINT/SIGTERM 保证句柄关闭；对 SIGKILL 由 doctor/repair 接管。

验收：崩溃不会永久阻塞 profile，也不会误删另一个活跃进程的锁。

### M2.3 Repair 设计与实现（P0）

- [ ] 先实现只读 `repair --plan <profile>`：列出基线、当前差异、备份和精确命令。
- [ ] 再实现 `repair --restore <backup-id>`，重复停机、锁和结果验证。
- [ ] 不能恢复时保持 `needs-repair`，不得写入绿色基线。
- [ ] node_modules/store 不承诺字节级回滚；修复通过重新安装 generation 的确切 artifacts 完成。

验收：模拟在 manifest、lockfile、patch 和 node_modules 更新之间失败，能够恢复到一个可验证 generation 或明确保持 needs-repair。

### M2.4 Update / Remove（P1）

- [ ] `update` 被建模为“基于当前 generation 的新 artifact 提案”。
- [ ] `remove` 在 staging 中预演依赖和 config diff，再生成新 generation。
- [ ] 两者复用 scan/approve/install 协议，不新增旁路命令。
- [ ] update report 显示 maintainer、入口、脚本、依赖、域名和 capability diff。

验收：任何 update/remove 都必须经过成功 staging 与显式审批。

### M2.5 CLI 测试（P1）

- [ ] 为所有命令补 commander 级测试和 stdout/stderr snapshot。
- [ ] 锁定退出码 `0/2/3/4/5`。
- [ ] `--json` 保证 stdout 只有 JSON，诊断进入 stderr。
- [ ] 错误不泄露 token、完整本机路径或未裁剪子进程输出。

## 8. M3 — Companion Hardening

目标：让 DSH 内嵌层保持只读、可维护、可访问，并避免与 CLI 状态逻辑分叉。

### M3.1 共享 schema 和状态计算（P0）

- [ ] 从 core 导出只读 status/event schema，Companion 不再复制类型和 fingerprint 规则。
- [ ] 将 quick verify 的最小共享逻辑抽到无副作用模块。
- [ ] Companion 读取 V2 generation，展示全部 managed packages。
- [ ] 对未知 schema 显示灰色“状态未知”，绝不沿用旧绿灯。

验收：同一 profile 的 CLI `verify --json` 与 Host `/status` 对状态、事件和 managed packages 给出一致结果。

### M3.2 Host API 安全测试（P0）

- [ ] 覆盖 Host header、Origin、无 Origin POST、非 loopback bind、body >64 KiB、非法 JSON。
- [ ] 明确是否支持 `localhost`/`::1`；不支持时 doctor 给出解释。
- [ ] 对响应字段做 schema validation 和最大数量/长度裁剪。
- [ ] 添加并发 acknowledge/analyze/status 测试。

验收：非同源写请求和非 loopback 部署无法读取/修改本地安全状态。

### M3.3 Sidecar 生命周期（P0）

- [ ] 添加 20–30 秒超时、AbortSignal 和 handle dispose 保证。
- [ ] 限制输入/输出字符、数组长度和生成次数。
- [ ] schema 不合法、模型不可用、超时均以局部 UI 错误结束。
- [ ] 添加 prompt injection fixture，确认输出不产生命令 URI、raw HTML 或外部资源。

验收：Sidecar 不能阻塞 Host、不能调用工具、不能改变 verdict，失败不影响 status/acknowledge。

### M3.4 UI 与可访问性（P1）

- [ ] 为 loading/empty/error/unknown/review/drifted/needs-repair 建立组件测试。
- [ ] 告警上限 3、fingerprint 去重、确认不解决风险、Quick View 行为测试。
- [ ] 键盘导航、焦点管理、读屏标签、对比度和 reduced-motion QA。
- [ ] 在窄屏和 DSH light/dark token 下做截图回归。
- [ ] 保持 UI 无 approve/install/trust/force 动作。

验收：真实 DSH 页面视觉 QA 与自动组件/可访问性测试同时通过。

### M3.5 工具策略配置（P1）

- [ ] 对重复/交叉的 deny/ask 工具名定义优先级：deny 胜出。
- [ ] 配置加载时拒绝空字符串、glob 和包名伪语法，只接受精确工具名。
- [ ] ask 服务不可用时 fail closed，并在 UI 中给出可解释状态。
- [ ] denial 聚合测试覆盖时间窗、跨分钟 fingerprint 和事件风暴。

## 9. M4 — Local Alpha

目标：让另一位本地开发者可以按文档复现，不依赖当前机器的隐式状态。

### M4.1 可重复构建与 CI（P0）

- [ ] 新增 CI：install with `--ignore-scripts`、typecheck、test、build、package dry-run。
- [ ] 固定 Node `22.22.x` 与 pnpm `10.12.1` 的主验证组合。
- [ ] 对 DSH rc.6 E2E 使用显式缓存/fixture，不读取 CI 主机真实 profile。
- [ ] 检查生成包不包含 source fixtures、报告、缓存、`.env` 或绝对本机路径。

### M4.2 安装与升级 runbook（P0）

- [ ] 文档化 CLI 安装、Companion 自扫描、自批准和自安装流程。
- [ ] 文档化 DSH 停机、备份位置、verify 和 repair。
- [ ] 文档化从 alpha N 升级到 N+1 的 schema/policy 变化。
- [ ] 给出完整卸载步骤，但不自动删除用户报告与审计记录。

### M4.3 兼容性矩阵（P1）

- [ ] Node：最低支持版本和当前 LTS 22 最新 patch。
- [ ] DSH：严格 rc.6；下一版本只做 compatibility spike，不直接放宽 peer range。
- [ ] macOS：至少一台 Intel/Apple Silicon 或明确只验证当前架构。
- [ ] DSH client loader、`package.json` export、三个 slots、tools guard、agents API、dump-config 均列为升级检查点。

### M4.4 Alpha 安全评审（P0）

- [ ] 按设计文档重新做威胁建模 walk-through。
- [ ] 手工尝试 scan/approve/install TOCTOU、状态文件篡改、stale lock、Host API 越权和 prompt injection。
- [ ] 记录已知限制和残余风险；P0 未关闭不得标记 alpha ready。

验收：从干净 checkout 到隔离 profile `verified` 有单一、可复制 runbook；所有 P0 关闭。

## 10. M5 — Beta / 后续方向

以下工作不进入 local alpha，先收集真实误报、恢复和兼容数据：

- OS 级外部沙箱启动器，限制文件、网络、环境变量和子进程。
- 不同 OS 身份的后台验证服务、Keychain/code-signing 和更强的状态完整性。
- Windows/Linux 支持。
- private registry、企业 CA、组织策略和签名要求。
- 信誉数据、CVE/恶意包情报；必须允许离线并避免上传源码。
- 在一次性容器/microVM 中构建需要 lifecycle script 的包，再重新固定和扫描产物。

Beta go/no-go 指标：

- 正常插件误 `blocked` 率和 `review` 噪音可接受。
- 连续 20 次隔离 install/verify 无不可恢复失败。
- DSH 升级兼容工作量可控。
- 多插件 generation 模型能准确解释每次变化。
- 用户不会把 Companion 或绿色状态误解为完备防护。

## 11. 测试矩阵

| 层级 | 必测内容 | 命令/产物 |
|---|---|---|
| 静态 | type safety、lint-like checks、构建 | `pnpm typecheck`, `pnpm build` |
| 单元 | artifact、scanner、schema、policy、state | `pnpm --filter @dsh-guard/core test` |
| CLI | 参数、输出、退出码、错误脱敏 | 新增 CLI tests |
| Companion | bundle contracts、Host API、Sidecar、UI | `pnpm --filter @dsh-guard/companion test` |
| 集成 | staging、generation、lock、repair | 临时 DSH_HOME fixtures |
| E2E | scan→approve→install→Host→verify | `pnpm test:e2e` |
| 视觉/a11y | 三个 slot、主题、键盘、读屏 | 真实 DSH 页面 + 截图/axe |
| 安全回归 | malicious fixtures、TOCTOU、CSRF、prompt injection | 每个 P0 独立测试 |

## 12. 任务完成定义（Definition of Done）

每个任务只有同时满足以下条件才算完成：

- 行为与设计文档一致，没有扩大安全声明。
- 新逻辑至少有正常、失败和对抗性测试。
- 错误默认 fail closed，且给出可操作诊断。
- 不读取、修改或依赖真实 `~/.dsh/profiles/web`。
- `pnpm check` 通过；涉及安装链/Companion 时隔离 E2E 通过。
- README、安全模型、设计和计划同步更新。
- `git diff --check` 通过，提交不包含缓存、构建外多余产物或敏感数据。

## 13. 建议的下一批提交

为了让审查粒度清晰，建议按以下顺序形成小提交：

1. `docs: add design baseline and development plan`
2. `chore: align Node engine and package metadata`
3. `test: add persisted schema and malicious fixtures`
4. `refactor: centralize temporary directory lifecycle`
5. `feat: add profile generation v2 model`
6. `feat: add stale lock diagnostics and repair plan`
7. `refactor: share status schemas with companion`
8. `fix: bound sidecar lifetime and Host API payloads`
9. `test: expand CLI, integration, UI, and security coverage`
10. `ci: add reproducible local-alpha verification`

每个提交都应独立通过相关测试；不要把 V2 数据迁移、UI 重构和发布配置混在同一提交中。

## 14. 立即执行顺序

1. 审阅并确认本设计文档和开发计划。
2. 完成 M0.1 README 链接与声明核对。
3. 运行当前 `pnpm check` 和隔离 E2E，保存基线结果。
4. 修正 Node engine 与 package metadata。
5. 在首次 commit 前做 secret/绝对路径/真实 profile 数据检查。
6. 从 M1.1 临时目录生命周期和 M1.2 schema 验证开始硬化。
