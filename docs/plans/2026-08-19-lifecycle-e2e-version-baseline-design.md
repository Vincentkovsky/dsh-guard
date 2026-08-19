# Lifecycle E2E 版本基线设计

## 问题

生命周期 E2E 曾把 Companion 的发布版本写死为 `0.4.0-alpha.2`。工作区升级到 `0.5.0-alpha.1` 后，实际回滚已经恢复了正确 generation，但测试仍因旧常量失败。这是测试基线漂移，不是回滚实现失败。

## 决策

测试在首次受控安装完成后，从 `plugins list --json` 返回的 inventory 中按包名找到 `@dsh-guard/companion`，并保存它的真实初始版本。完成更新、卸载和回滚后，再次按包名找到该插件，并将回滚版本与首次记录的版本比较。

不从源码 `package.json` 读取版本，也不保留发布版本常量。这样 E2E 验证的是用户实际看到的生命周期状态，同时避免数组顺序或后续版本升级产生误报。

## 保持不变的安全约束

- 回滚仍必须返回请求的 `restoredGenerationId`。
- 回滚后的 profile 仍必须通过完整 `verify`。
- inventory 必须只有预期插件，不能用宽松匹配掩盖额外插件。
- generation 快照和不可变历史的生产实现不做改动。

## 验证

- `pnpm check`
- 使用 DSH `0.1.0-rc.7` 执行 `pnpm test:e2e`
- macOS 执行 `pnpm test:sandbox`
