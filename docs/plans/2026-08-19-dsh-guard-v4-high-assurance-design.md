# DSH Guard v0.4 实验性 OS Sandbox Launcher 设计

> 状态：实现中
> 日期：2026-08-19
> 前置基线：v0.3 Plugin Lifecycle 本地 alpha

## 1. 目标

v0.3 的 Action Gate 只能保护 DSH Tool Registry。已经进入 Host 的插件仍可直接调用 Node.js `fs`、`fetch` 和 `child_process`。v0.4 增加一个用户显式启用的 macOS 启动器，把整个 DSH Host 放入 OS sandbox，限制它能读取、写入、执行和联网的范围。

该能力的准确定位是“整进程隔离模式”，不是逐插件沙箱：DSH Core、受信插件和不受信插件共享同一组允许项。任何插件都能访问被允许的工作区、目标 profile 和 Guard state，因此策略的最小化比插件来源标签更重要。

## 2. 方案选择

### A. 同进程 monkey patch

覆盖 `fs`、`fetch` 或 `child_process` 容易被 native binding、缓存引用和新 API 绕过，不能成为安全边界。拒绝。

### B. 整个 DSH Host 使用 macOS sandbox（采用）

无需修改 DSH 插件协议，即可让内核拒绝越界文件、网络和进程操作。缺点是粒度粗、`sandbox-exec` 已被 Apple 标记为 deprecated，并依赖私有 SBPL 语义。作为显式实验模式可接受，不能宣称跨平台或长期稳定。

### C. 容器或 microVM

边界更强，也便于独立网络命名空间，但本地 GUI、Keychain、文件性能和安装体积成本高。保留为后续高保障运行器，不在 v0.4 顺带实现。

## 3. 用户命令

```bash
dsh-guard sandbox plan \
  --profile web \
  --workspace /absolute/project \
  --network loopback

dsh-guard sandbox run \
  --profile web \
  --workspace /absolute/project \
  --network loopback \
  -- --port 8080
```

`plan` 只生成、校验并显示 `SandboxPlanV1`，不启动 DSH。`run` 会重新生成计划、要求 profile 当前为 `verified`、记录审计摘要，然后以收缩环境启动精确 DSH runtime。

支持三个网络模式：

- `deny`：允许 DSH 在 loopback 绑定 UI，但禁止所有 outbound。
- `loopback`：额外允许连接本机 TCP 服务，适合本地模型；默认。
- `unrestricted`：允许公网 outbound；必须显式选择，并明确提示无法阻止工作区数据外传。

v0.4 默认不允许 DSH 启动子进程。后续如果增加 `--allow-process`，必须作为单独威胁模型和版本能力，不能偷偷放宽。

## 4. `SandboxPlanV1`

计划是不可变、可哈希的纯数据：

```ts
interface SandboxPlanV1 {
  schemaVersion: 1
  id: string
  createdAt: string
  platform: 'darwin'
  profile: string
  network: 'deny' | 'loopback' | 'unrestricted'
  nodePath: string
  dshBin: string
  dshRuntimeRoot: string
  sourceDshHome: string
  sourceProfile: string
  dshHome: string
  guardHome: string
  tempRoot: string
  workspaceRoots: string[]
  readOnlyPaths: string[]
  readWritePaths: string[]
  allowedEnvironmentNames: string[]
  policy: string
  policyHash: string
  warnings: string[]
}
```

`sourceDshHome/sourceProfile` 是已验证的真实来源；`dshHome` 是 `~/.dsh-guard/sandbox-runs/run-*/dsh-home` 下的一次性运行副本。所有路径先 `realpath`，必须绝对、存在且类型正确。profile、环境变量名和网络枚举使用严格 schema。计划不保存环境变量值、profile 内容或用户文件内容。

## 5. 文件系统策略

DSH rc.6 在启动和 `--dump-config` 时都会重写 `cordis.yml`，因此不能直接以只读方式运行真实 profile。`plan`/`run` 会把目标 profile 复制到 Guard 管理的一次性目录，只复制普通 profile 文件、`settings.yaml` 和匿名 ID，不复制 `.credentials.yaml`。`run` 在复制后重新计算五个控制文件的 fingerprint，必须与刚刚 verified 的真实 profile 完全一致；退出后安全删除副本。

策略从 `(deny default)` 开始并导入 macOS `system.sb` 的最小系统运行规则。允许：

- Node runtime 根目录，只读。
- DSH 安装 runtime 根目录，只读。
- 一次性 DSH profile、sessions、storages 与临时目录，读写；真实 `~/.dsh` 不进入 allow policy。
- `~/.dsh-guard`，读写，以维持 Action Gate、事件和状态；这是已知的同进程 tamper 限制。
- 每个显式 workspace root，读写。

不允许 `~/.ssh`、`~/.gnupg`、云凭据目录、浏览器数据、Keychain 文件、其他项目、真实 `~/.dsh` 或未列入的 home 内容；这些敏感根也不能伪装成 workspace。路径祖先只获得 metadata 权限，不获得内容读取权限。策略字符串对引号、反斜杠和控制字符做 SBPL 转义，拒绝 NUL。

允许的 workspace 对所有 Host 插件都可见，因此用户不应把 home 或宽泛父目录作为 workspace。`/`、home、`~/.dsh` 和 `~/.dsh-guard` 不能作为 workspace root。

## 6. 进程与网络

只允许执行精确 realpath 后的 Node binary。没有通用 `process-exec`，因此 `/bin/sh`、DSH Bash 工具和下载后执行其他 executable 都会由内核拒绝。策略仍允许 `process-fork`，也无法区分首次 Node 与再次启动同一个 Node binary；后者仍受同一文件和网络 policy 约束。

所有模式允许 loopback bind/inbound，供 DSH Web UI 使用。传入 `--host` 时只接受 `127.0.0.1`、`localhost` 或 `::1`；`0.0.0.0` 和非本机地址在启动前拒绝。

`loopback` 只允许 localhost outbound。`unrestricted` 允许 outbound，但仍保留文件和进程边界。macOS sandbox 不能按 DNS 域名可靠过滤网络，因此不会伪造域名 allowlist；真正的域名控制需要进程外代理。

## 7. 环境收缩

默认子进程环境只包含：

- `PATH`（Node bin、`/usr/bin`、`/bin`）
- `HOME`、`DSH_HOME`、`DSH_GUARD_HOME`、`TMPDIR`
- `LANG`、`LC_ALL`、`TERM`、`NO_COLOR`

用户可以重复传 `--allow-env NAME`。计划只记录变量名；值在 spawn 时从父环境读取。名称必须匹配大写 POSIX 标识符。`NODE_OPTIONS`、`NODE_PATH`、`DYLD_*`、`LD_*`、`PATH`、`HOME` 和 Guard/DSH 路径变量永远不能透传，避免启动前注入或边界替换。

显式传入 credential/token 类变量会产生高风险 warning，因为同进程插件仍能读取该值。v0.4 没有 Secret Broker。

## 8. 启动与审计

`sandbox run` 的顺序：

1. 确认平台为 macOS，定位精确 Node、DSH bin、真实 profile、Guard state 和 workspace realpath。
2. 运行 `verifyProfile`，非 `verified` 直接拒绝。
3. 创建一次性 DSH_HOME，复制 profile（不复制 credentials），并复核控制文件 fingerprint。
4. 生成并严格解析计划，重新计算 policy hash。
5. 向 `audit.jsonl` 记录 profile、来源 fingerprint、network、workspace digest、环境变量名、policy hash；不记录值。
6. 验证 `/usr/bin/sandbox-exec` 后使用无 shell spawn 启动精确 Node 和 DSH bin。
7. 继承 stdin/stdout/stderr，转发 SIGINT/SIGTERM，返回 DSH 原始退出码并安全清理运行副本。

计划生成失败、平台不支持、profile 漂移、危险 host、无效环境名或 sandbox 退出均不会回退到非 sandbox DSH。

## 9. 已知限制

- `sandbox-exec` 和 SBPL 是 Apple deprecated/private interface，系统升级后可能失效。
- 整进程策略无法区分 DSH Core 与插件；允许项对所有插件开放。
- 默认禁止 Bash 和其他 executable；这会减少 Agent 能力。
- 再次启动同一个 Node binary 在内核策略上无法与首次 Node 区分，但不会获得额外文件或网络权限。
- `unrestricted` 网络不能阻止已允许数据被直接外传。
- Guard state 对 sandbox 内插件可写，仍不是 tamper-proof。
- `.credentials.yaml` 不会进入运行副本；需要凭据的模型调用必须显式通过受审环境变量或未来 Secret Broker，默认可能不可用。
- profile 与插件代码必须可读，因此已安装插件可以读取彼此代码。
- 只支持 macOS；Linux/Windows 必须使用不同 provider。

## 10. 验收

1. 纯策略测试覆盖路径 canonicalization、祖先 metadata、SBPL 转义、宽泛 workspace 拒绝和三个网络模式。
2. 默认环境不包含父进程 secret；危险注入变量不能 allow。
3. CLI plan 的 human/JSON 输出不包含环境值。
4. run 对 drifted/unmanaged profile、非 loopback host 和非 macOS 失败关闭。
5. 真实 macOS probe：工作区读写允许；home 外文件读取、子进程和公网连接返回 `EPERM`。
6. 精确 DSH rc.6 从一次性 profile 完成 `--dump-config`，真实 profile fingerprint 不变且副本被清理。
7. 原有 115 个测试与 v0.3 生命周期 E2E 持续通过。
