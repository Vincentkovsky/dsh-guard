# DSH Guard

DSH Guard 是 DeepSeek Harness（DSH）插件的本地供应链扫描器、受控安装器和运行时安全伴侣。它解决的是“这个插件会带来哪些能力、我批准的是否正是最后安装的那一份、安装后 profile 有没有漂移”，不是一款声称能识别所有恶意行为的杀毒软件。

当前版本针对 **DSH `0.1.0-rc.6`、macOS、Node `22.22+`** 做过验证。

## 设计与开发计划

- [完整设计文档](./docs/plans/2026-08-19-dsh-guard-design.md)
- [开发计划](./docs/plans/2026-08-19-dsh-guard-development-plan.md)
- [安全模型](./docs/security-model.md)

## 已实现

- `dsh-guard scan`：固定 npm 版本与 integrity；按 npm packlist 确定性打包本地目录；校验 `.tgz`；不执行候选代码或生命周期脚本。
- AST/CST 静态分析：文件、环境变量/凭据、网络、监听端口、子进程、动态/原生代码、工具注册、DSH profile 覆盖等能力。
- 隔离 staging：克隆目标 profile，在相邻临时 `DSH_HOME` 中使用 `--ignore-scripts` 安装，并通过 DSH `--dump-config` 比较组合前后配置。
- `approve`：审批同时绑定报告、artifact、profile 和 policy 哈希。
- `install`：profile 停机检查、操作锁、备份、离线精确安装、与 staged proposal 对比、尽力恢复。
- `verify`：检测受控状态、profile 漂移和未纳管 bundle。
- DSH Companion：Plugins 设置内的安全中心、侧栏盾牌、右下角高危告警，以及无工具 sidecar 分析。
- 精确工具名策略：`deny` 使用单调 `ctx.tools.guard()`；`ask` 使用 `tools/pre-execute`，没有审批服务时自动拒绝。

## 安装开发版

```bash
cd /Users/vincentjin/CodingProject/dsh-guard
pnpm install --ignore-scripts
pnpm check
pnpm --filter dsh-guard link --global
```

如果 `dsh` 不在 `PATH`，为 CLI 指向 DSH rc.6 的入口：

```bash
export DSH_BIN=/path/to/@deepseek-ai/dsh/lib/bin.js
```

先运行诊断：

```bash
dsh-guard doctor
```

> DSH rc.6 的实际依赖使用了较新的 Node 22 API。虽然上游包声明 `>=22`，本项目的真实 Host 启动测试要求 Node `22.22+`。

## 使用流程

扫描 public npm 包、目录或 `.tgz`：

```bash
dsh-guard scan some-public-plugin@1.2.3 --profile web
dsh-guard scan ./my-plugin --profile web
dsh-guard scan ./my-plugin-1.2.3.tgz --profile web --json
```

退出码：`0=通过`、`2=需要人工审查`、`3=阻止`、`4=运行时/兼容性错误`、`5=需要修复`。`pass` 只表示“没有检测到策略违规”，不是安全证明。

查看并批准报告：

```bash
dsh-guard report <report-id>
dsh-guard approve <report-id>
```

关闭目标 DSH GUI 后安装：

```bash
dsh-guard install <report-id>
```

安装不会自动重启 GUI。手动重新打开 DSH 后，Plugins 设置中会出现“安全中心”，侧栏底部会出现状态盾牌。

验证 profile：

```bash
dsh-guard verify --profile web
```

## 安装 Companion 本身

Companion 也必须经过相同边界，而不能自我信任：

```bash
dsh-guard scan /Users/vincentjin/CodingProject/dsh-guard/packages/dsh-plugin --profile web
dsh-guard approve <report-id>
# 先退出 DSH GUI
dsh-guard install <report-id>
```

它会被标记为 `review`，因为确实使用了本地文件读取、同源 Host 通信和环境路径。这是能力披露，不是恶意标签。

## 高危告警

右下角只为以下事件弹出持久告警：

- `verified → drifted`
- 新的未纳管插件/bundle
- 受保护的 DSH 配置发生变化
- 安装恢复失败、profile 进入 `needs-repair`
- 同一高风险工具在 60 秒内被拒绝至少三次

告警最多同时显示三条，并按稳定 fingerprint 去重。“知道了”只确认告警，不表示风险已经解决；界面里没有“信任、批准、安装”按钮。

## 工具策略

在用户 profile 的 patch 中覆盖 `dsh-guard` 行时，需要完整重述配置，因为 DSH patch 会替换整个 `config`：

```yaml
- id: dsh-guard
  config:
    profile: web
    statusPollMs: 15000
    denyTools: [dangerous_exact_tool]
    askTools: [sensitive_exact_tool]
```

v1 只按**精确工具名**执行规则。DSH rc.6 的工具 inventory 不提供可靠的包来源，因此 DSH Guard 不会伪装成能够按发布者或包名执法。

## 数据与边界

本地状态位于 `~/.dsh-guard`，目录权限 `0700`、文件权限 `0600`：

```text
~/.dsh-guard/
├── reports/
├── approvals/
├── installs/
├── cache/
├── locks/
├── backups/
├── audit.jsonl
├── events.jsonl
└── status.json
```

Companion 的 Host API 只在 DSH web server 绑定 `127.0.0.1` 时注册；若 DSH 绑定 `0.0.0.0`，安全中心会显示断开状态，不会把本地安全数据暴露给局域网。证据始终按文本渲染，不注入 raw HTML、外部图片或自动链接预览。

限制详见 [安全模型](./docs/security-model.md)。

## 验证

```bash
pnpm check

# 使用隔离的 guard-e2e profile 跑 scan → approve → install → Host API → verify
DSH_NODE=/path/to/node-22.22-or-newer \
DSH_BIN=/path/to/@deepseek-ai/dsh/lib/bin.js \
pnpm test:e2e
```

E2E 脚本只创建临时 sibling `DSH_HOME` 和临时 Guard state，并在结束时验证路径前缀后清理；不会修改真实 `~/.dsh/profiles/web`。
