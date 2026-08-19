# DSH Guard 安全模型

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
2. **Companion 不是沙箱。** 它与其他 Host 插件处于同一用户、同一 DSH 进程。已经运行的恶意插件可攻击同权限数据，DSH Guard 不声称在此之后仍能可靠防护。
3. **原生 DSH 命令仍可绕过。** 用户可以直接运行 `dsh plugin`；`verify` 会把由此产生的 bundle 或文件变化标记为未纳管/漂移。
4. **本地状态防篡改能力有限。** 权限、哈希和可重算记录提供 tamper evidence，不提供对同一操作系统用户的 tamper proof。
5. **工具来源不可证明。** rc.6 inventory 不公开工具到包的稳定 provenance；策略只接受精确工具名。

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

## Companion API 与 UI

Host 端只在 `webServer.host === 127.0.0.1` 时注册：

- `GET /dsh-guard/api/status`
- `POST /dsh-guard/api/acknowledge`
- `POST /dsh-guard/api/analyze`

写接口要求同源 loopback `Origin`，请求体限制 64 KiB。返回值只包含裁剪、脱敏、JSON 可序列化的数据。前端轮询 status；不依赖 DSH build-time 固定的 forwarded-event allowlist。

Sidecar 由用户点击“查看详情”触发，通过 `ctx.agents.create()` 创建，并在 setup 中执行 `agentCtx.tools.restrict({ allow: [] })`。它只收到结构化、脱敏后的事件证据，输出必须通过 `SidecarAnalysisV1` 校验。它不能读文件、调用工具、批准报告、安装包或更改 verdict。DSH 自己也明确说明 `tools.restrict` 不是针对恶意同进程代码的安全边界，因此这里称为能力收缩，而不是沙箱。

## 尚未声称解决

- 对混淆代码、逻辑炸弹、模型提示注入和未知漏洞的完备检测
- 恶意 native addon 的动态分析
- 已启动恶意同用户插件之后的隔离与取证完整性
- npm maintainer 账户是否被接管
- 私有 registry 与企业签名策略
- Windows/Linux 和 DSH rc.6 之外版本的兼容性

升级 DSH 时必须重新运行 compatibility spike、全部测试和隔离 E2E；不能只放宽 peer range 后假设兼容。
