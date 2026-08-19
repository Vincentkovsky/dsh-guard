# DSH Guard — DSH 0.1.0-rc.7 兼容与真实安装设计

> 日期：2026-08-19
> 状态：执行中

## 背景

不带版本运行 `npx @deepseek-ai/dsh web` 当前解析到 `@deepseek-ai/dsh@0.1.0-rc.7`。DSH Guard v0.4 的 Companion peer/dev dependencies 和 E2E 基线仍固定在 rc.6；真实 `web` profile 也尚未包含 `@dsh-guard/companion`。源码构建完成不会使 DSH 自动加载本地插件。

## 选择

1. 继续固定 rc.6：改动最少，但与用户实际 `npx` 行为不一致，拒绝。
2. 只把 peer range 放宽到 rc.7：安装警告会消失，但没有证明 API、UI 和生命周期兼容，拒绝。
3. 把编译、peer、真实 Host 和 E2E 基线统一升级到精确 rc.7：采用。

本次不同时声称 rc.6/rc.7 双版本兼容。精确单基线更容易在 rc 阶段失败关闭；需要双版本时应建立版本矩阵，而不是使用未经验证的 semver range。

## 改动

- Companion 中全部 `@deepseek-ai/dsh-*` peer/dev dependencies 从 `0.1.0-rc.6` 升至 `0.1.0-rc.7`。
- 产品版本升级为 `0.4.0-alpha.1`，CLI/README/安全模型/运行手册统一标记 rc.7。
- 使用当前 rc.7 `lib/bin.js` 运行 build、135+ 单元回归、macOS sandbox probe 和完整隔离 E2E。
- 不通过扫描结果自我信任 Companion：仍执行 `scan → approve → install → verify`。
- 写真实 profile 前停止当前 web Host；安装逻辑先备份并在失败时恢复。
- 安装完成后使用同一 rc.7 重新启动 `web`，通过 profile bundles、Plugin inventory、Guard Host API 和页面可见性确认结果。

## 失败处理

- 类型或 Host API 不兼容：停止真实安装，修复后重跑全部验证。
- staging 与 rc.7 组合失败：不批准、不安装。
- 真实安装失败：使用既有 lifecycle 恢复；无法恢复时进入 `needs-repair`，不启动 DSH。
- UI 不可见但 Host 正常：检查 rc.7 client manifest/injection 和浏览器资源，不重复安装。
- Host/配置无法启动：停止新进程，保留 Guard 备份和审计证据。

## 验收

1. `pnpm check` 全绿。
2. `pnpm test:sandbox` 维持工作区 allow、越界/其他 executable/公网 `EPERM`、loopback allow。
3. rc.7 完整 E2E 通过 scan、双插件 lifecycle、Host API、Action Gate 与 sandboxed dump-config。
4. 真实 `web/package.json` 同时保留现有股票插件并新增 `@dsh-guard/companion`。
5. `dsh-guard verify --profile web` 为 `verified`。
6. rc.7 web 启动后 Guard Host API 返回 profile `web`，Plugins 设置可见安全中心。
