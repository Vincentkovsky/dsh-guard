# DSH Guard 安全模型

> 本文描述默认启用的 Trust Gate、Plugin Lifecycle 与 Guarded Launch、默认关闭的 Agent 操作保护，以及实验性 macOS OS Sandbox Launcher。产品边界以[插件优先设计](./plans/2026-08-19-dsh-guard-plugin-first-product-design.md)为准；逐插件隔离、可靠任务身份和跨平台 provider 仍是明确限制。

## 目标

DSH Guard 在候选插件进入真实 DSH profile 前建立一个可审计的控制点，并在安装后发现关键文件漂移。权威边界是独立 CLI；运行在 DSH 内的 Companion 仅提供 defense-in-depth、状态展示和及时告警。

```text
source spec
   │
   ▼
immutable artifact ── hash/integrity ──► static report
   │                                      │
   │                         profile + policy + report hash
   │                                      ▼
   └──────── isolated DSH stage ──────► explicit approval
                                          │
                                          ▼
                               offline exact installation
                                          │
                                  verify / quick drift check
```

## 信任边界

1. **CLI 是主边界。** 候选包不能被 import、eval 或执行；生命周期脚本在 scan、stage 和 install 中始终关闭。
2. **Agent 操作保护默认关闭且不是插件沙箱。** 只有显式启用后，它才保护所有 Agent 经过 DSH Tool Registry 的正规调用；它不能按 npm 插件归因，恶意插件也可直接调用 Node.js API。只有用户通过 `dsh-guard sandbox run` 启动时，整个 Host 才额外受 OS policy 约束。
3. **Guarded Launch 是启动边界，原生 DSH 命令仍可绕过。** `dsh-guard start` 在 DSH 进程创建前验证 profile；用户仍可直接运行 `dsh` 或 `dsh plugin`，`verify` 会把由此产生的 bundle 或文件变化标记为未纳管/漂移。
4. **本地状态防篡改能力有限。** 权限、哈希和可重算记录提供 tamper evidence，不提供对同一操作系统用户的 tamper proof。
5. **工具来源不可证明。** rc.7 inventory 不公开工具到包的稳定 provenance；策略只接受精确工具名。

## 实验性 OS Sandbox Launcher

`sandbox run` 先要求真实 profile 为 `verified`，再复制到 `~/.dsh-guard/sandbox-runs/run-*` 下的一次性 DSH_HOME，并复核五个控制文件 fingerprint。DSH rc.7 启动时需要写 `cordis.yml`，因此运行副本可写；真实 profile、真实 DSH sessions/storages 和 `.credentials.yaml` 不进入 allow policy，退出后副本被删除。

macOS SBPL 从 `deny default` 开始，只开放：

- 精确 Node 与 DSH 安装 runtime，只读；
- 一次性 DSH_HOME、Guard state、专用 temp 和显式 workspace，读写；
- loopback bind/inbound；按模式禁止 outbound、仅开放 loopback outbound，或显式开放全部 outbound；
- 精确 Node executable 和 `process-fork`，不开放 `/bin/sh`、下载后的 binary 或其他 executable。

环境从空集合重建。默认只有固定 PATH、HOME/DSH_HOME/DSH_GUARD_HOME/TMPDIR、固定 locale、可选 TERM 和 NO_COLOR；额外名称必须显式 allow。动态加载与 Node 启动注入变量永远拒绝，计划和审计只保存名称，不保存值。

这是整进程而不是逐插件边界。DSH Core、主 Agent 和所有插件共享 workspace、网络和显式环境变量；Guard state 为维持状态与可选 Agent 操作保护而可写，因此对同进程插件仍不是 tamper-proof。macOS policy 也无法区分首次 Node 与再次执行同一个 Node binary，但后者不会获得超出原 policy 的权限。`unrestricted` 网络可外传所有可见数据。该 provider 依赖 Apple 已 deprecated/private 的 `sandbox-exec`/SBPL，系统升级后可能失效，任何错误都会失败关闭而不是退回普通启动。

## Guarded Launch

`dsh-guard start` 是插件供应链的推荐启动边界。它在创建 DSH 子进程前要求 profile 为 `verified`，拒绝未纳管 bundle、任意控制文件漂移、损坏的 lifecycle state，以及 `--profile`、`--patch` 和 loader config 覆盖。验证成功后会在 spawn 前再次计算 fingerprint；变化时失败关闭。

Guarded Launch 使用真实 DSH_HOME，以保留 sessions、storages、settings 和凭据。它移除 Node/动态链接器进程注入环境变量，但不限制已批准插件的运行时宿主能力。原始 `dsh` 命令是显式绕过路径；Companion 能显示“未受保护启动”，但不能在 Cordis 进程内可靠阻止更早加载的兄弟插件。

## 可选 Agent 操作保护

该能力默认关闭。Companion 始终注册可实时启停的工具 Hook，但关闭时直接调用下游策略，不标准化或裁决动作；`denyTools`、`askTools` 和 `askUnknownTools` 不会影响主 Agent，插件扫描、安装、验证和生命周期功能照常运行。

用户可在 Security Center 按 profile 实时开启，选择保存在 Guard state 而非 DSH profile；设置损坏时按开启处理并报告降级。开启后，Companion 在 `tools/pre-execute` 中把所有 Agent 的 `read`、`read_image`、`write`、`edit`、`bash`、`web_fetch` 和 `web_search` 转成 `ActionRequestV1`。普通工作区读写和已知只读命令直接继续；敏感文件、工作区外访问、非只读命令和未授权域名进入 DSH approval；凭据读取、越界删除、破坏性命令、下载即执行和显式 secret 外传信号直接拒绝。直接字面 `rm` 目标会做 realpath-aware 规范化并显示路径与数量；shell 展开、命令链或包装器无法安全解析时退化为通用命令询问。URL userinfo、常见 secret query 和动态目标的 `curl` / `wget` secret 外传也纳入保守规则。未知工具默认询问，参数无法安全解析时失败关闭。

审计只观察深度冻结的权威 `tools/result`，不依赖可被后续 listener 改写的中间 `tools/post-execute` 结果。事件保存 profile/session、决策、结果、资源摘要、错误码和参数 digest，不保存完整参数、文件内容、HTTP body 或工具输出。新增身份字段是向后兼容的；旧事件会被标记为缺少 session 的 legacy 记录。调用 30 分钟没有 result 时记录 `RESULT_TIMEOUT / unknown`；插件卸载时在途调用记录 `GATE_DISPOSED / unknown`，迟到结果不会被猜测性合并。

rc.7 提供 Agent/session ID 和 session cwd，但没有可靠 task/goal ID。当前请求显式省略 `taskId`，`rootCallId` 只用于调用关联，不作为授权身份。DSH approval 当前只支持 `allowed-once`；任务级 grant 仍处于未启用状态。

Action state 与旧 `GuardEvent` 分开存储。grant 文件在私有锁内读取、校验、fsync 并原子替换；损坏、重复 ID、过期、policy hash 不匹配或资源不匹配都不能产生授权。once grant 在执行前原子消费，即使随后进程崩溃也不会被重复使用；Agent disposal 会撤销同 session grant。Action Event 按大小轮转，读取时报告损坏行，symlink 状态文件被拒绝。DSH 标准 `allowed-once` 不会在执行后错误转换为下一次可用的持久 grant。

## 输入限制

v1 接受：

- public npm 包名、tag 或 semver range（解析为精确版本）
- 本地目录（`npm-packlist` + 确定性 tar）
- 本地 `.tgz`

v1 拒绝 Git、GitHub shorthand、HTTP(S) tarball、private registry、npm alias、workspace/link/file install spec。此限制缩小了解析歧义和会触发构建脚本的来源面。

## Verdict

- `blocked`：identity/integrity 不匹配、归档/链接逃逸、根入口或 patch 无法解析、缺失且依赖脚本生成的发布产物、受保护 DSH 行覆盖、policy deny、staging 失败或 scan/approve/install 之间出现漂移。v1 没有 `--force`。
- `review`：生命周期脚本（永不执行）、网络、子进程、环境/凭据、动态/原生代码、混淆、新工具、普通文件读写、普通 DSH 扩展等。
- `pass`：仅表示当前规则没有发现违规，不代表无漏洞或无恶意行为。

## Staging 与安装

staging 在与真实 `DSH_HOME` 同级的临时目录中复制 profile 文件。保持相同目录深度是为了不改变 pnpm lockfile 中本地依赖的相对路径语义。随后：

1. 用 `--ignore-scripts --frozen-lockfile --offline` 恢复 baseline dependency graph。
2. 执行上游 DSH `--dump-config`；它组合 patch 但不启动插件，也不执行 `!!js`。
3. 从内容寻址缓存添加候选 artifact，仍然关闭脚本。
4. 再次 dump config，并记录 proposed lock、profile fingerprint、bundles 和 config diff。
5. 删除临时 staging home。

真实 install 要求 profile 不在运行，持有独占锁，先备份五个 profile 控制文件，再进行 `--offline --save-exact --ignore-scripts` 安装。结果必须与 staged lock 和 profile fingerprint 完全相同。失败时尝试恢复；不能恢复就返回退出码 5 并保留备份。该流程不宣称具有跨文件系统事务意义上的原子回滚。

## Plugin Lifecycle

每次受控安装、更新、卸载、修复或回滚都会形成一个 `ManagedProfileV1` generation。generation 保存当时完整的受管插件集合、profile fingerprint、bundle 顺序、组合配置 hash，并引用 `~/.dsh-guard/generations/` 下五个控制文件的私有快照。状态和快照读取拒绝 symlink、未知字段、重复 ID、缺失 current generation 和 digest 不一致。

update 不解析最新版本，必须使用新的 scan/approve 报告；对已受管包再次执行 install 会失败。uninstall 只接受 inventory 中的精确 npm package 名，并要求 `--confirm` 重述目标；它先在 sibling DSH home 中运行 rc.7 remove，再执行真实 remove 并比对 lock、profile、bundle 与组合配置。repair 只恢复 current generation。rollback 需要精确 generation ID，恢复后创建新的 generation，不改写历史。

repair 和 rollback 恢复控制文件后运行 `plugin install --frozen-lockfile --offline --ignore-scripts`，使依赖图与目标 lockfile 对齐。所有真实写操作共享 profile 锁、要求 DSH 停止并保留操作前备份；失败时恢复执行前文件并重新 hydrate。不能证明恢复成功时记录 `needs-repair`，不产生 verified 状态。

generation 只保护 `package.json`、`pnpm-lock.yaml`、`pnpm-workspace.yaml`、`cordis.yml` 和 `cordis.patch.yml`。它不备份插件运行数据、用户 workspace 或任意 `node_modules` 内容；恢复依赖 Guard 的本地 artifact/pnpm store，cache 缺失时失败关闭。

## Companion API 与 UI

Host 端只在 `webServer.host === 127.0.0.1` 时注册：

- `GET /dsh-guard/api/status`
- `POST /dsh-guard/api/acknowledge`
- `POST /dsh-guard/api/grants/revoke`
- `POST /dsh-guard/api/analyze`

写接口要求 loopback Host，且 `Origin` 的 host 与端口必须和请求 `Host` 完全一致；请求体限制 64 KiB。grant 接口只允许撤销单个或全部授权，不提供创建或扩权操作。返回值只包含裁剪、脱敏、JSON 可序列化的数据；状态按当前 profile 过滤 grant，新事件带 profile/session，历史无身份事件明确标为 legacy。前端轮询 status；不依赖 DSH build-time 固定的 forwarded-event allowlist。

Sidecar 由用户点击“查看详情”触发，通过 `ctx.agents.create()` 创建，并在 setup 中执行 `agentCtx.tools.restrict({ allow: [] })`。它只收到结构化、脱敏后的事件证据，输出必须通过 `SidecarAnalysisV1` 校验。它不能读文件、调用工具、批准报告、安装包或更改 verdict。DSH 自己也明确说明 `tools.restrict` 不是针对恶意同进程代码的安全边界，因此这里称为能力收缩，而不是沙箱。

## 尚未声称解决

- 对混淆代码、逻辑炸弹、模型提示注入和未知漏洞的完备检测
- 恶意 native addon 的动态分析
- 普通（非 `sandbox run`）方式启动恶意同用户插件之后的隔离，以及任何模式下的取证完整性
- 同一 sandbox 内不同插件之间的数据隔离
- npm maintainer 账户是否被接管
- 私有 registry 与企业签名策略
- Windows/Linux、非 `sandbox-exec` provider 和 DSH rc.7 之外版本的兼容性
- 插件运行数据和用户 workspace 的备份、迁移与恢复

升级 DSH 时必须重新运行 compatibility spike、全部测试和隔离 E2E；不能只放宽 peer range 后假设兼容。
