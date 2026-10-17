# 更新日志（CHANGELOG）

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-17

首个开源版本。基线：IDM **6.43 Build 15**，24 点全量补丁（`eca4afdc…`），实机装机 MATCH。

### 新增

- `src/idm_engine.py`：极简 PE 解析器（零依赖）+ 特征码定位器 + 补丁施加器（P1–P15）。
- `src/IDM-Activator.py`：一键工具（层 A 注册状态 / 层 B 补丁 / 层 C 防回退 / 回滚），
  自动提权、自证式完整性校验、系统级护栏。
- `src/IDM-Unlock.py`：最小可用解锁器（P1–P3），保留作为参考实现。
- `src/scripts/apply_p8_idmgrhlp.py`：`IDMGrHlp.exe` 的 P8 独立施加器（幂等 + 断言 + 备份）。
- `tools/probe-scripts/`：Frida 弹窗/IO 探针、PE 资源探针、XOR 字符串全扫、
  331 个弹窗调用点全量审计脚本。
- `tools/verify/`：端到端验证脚本（soak、下载回归、P19 验收、UIA 读对话框）。
- `docs/`：11 份深度分析报告 + 锚点字典（b15 / b8）+ 完整实现细节 + 交接文档。

### 关键设计决策

- **删除守护模型**：旧版 30 分钟一次的计划任务守护**本身就是故障源**
  （伪造序列号 → counterfeit → `MData` + `ExitProcess(0)` → 守护删标记并换新假号 → 循环）。
  改为静态三层 + ACL 不可变（预防而非修补）。
- **P14 wrapper 级短路**：`sub_474D20` 入口按 `uType == 0x41030` 直接返回 0
  ⇒ **一处覆盖全部显示点 + 未来路径**，其余 244 处调用不受影响。
- **P12 标为 RETIRED**：`license_valid` 实测 12/12 注册框照弹，被否证，保留实现作为记录。
- **P8 独立 CLI**：`IDMGrHlp.exe` 不在 `IDMan.exe` 的打包范围内，需单独施加。

### 修复（开发期踩过的坑，均已固化进代码）

- 只写 hosts 不刷 DNS 缓存 → 屏蔽**静默失效**（`ping` 仍解析真实 IP）。
- 按 marker 字符串统计 hosts 生效行 → 被 `#` 注释的行也算数（3/6 行误报成功）。
- 脏备份（在屏蔽生效后才创建）→ 还原**静默失败**；改为「备份不含 marker 才允许还原」。
- 补丁点表在已打补丁的文件上失效 → 改用**自证式**完整性校验。
- `--install-dir` 不覆盖系统级路径 → 引入 `system_changes_allowed()` 硬护栏。
- P9 锚点过严（`call+10` 必为 `RegFlushKey`）导致漏点 `0x120A54` → 改为仅保留可达性排除。
- P9 用 `call [ExitProcess]` 当锚点 → P5 施加后被打成 NOP，幂等被破坏 → 移除该锚点。
- P14 曾因「`call+5` 必须 `83 C4 10`」误拒 `0x75710`（清栈在 `call+0x0B`）→ 改为逐站点判定。

### 已知限制

- 非 NTFS 卷不支持 ACL 不可变（会跳过并明确报告）。
- DNS-over-HTTPS / 代理 / VPN 环境下 hosts 屏蔽可能失效。
- `--status` 会发 6 次 ping（只读，但非零网络活动）。
- P11 为预防性补丁，无已知触发路径，无法动态验证。

---

## 历史（未开源阶段）

| 版本 | 日期 | 说明 |
| --- | --- | --- |
| b8 方案 | 2026-08 | IDM 6.43 Build 8：P1–P3，`g_registered @ 0x779CDC`，实测 Full + 9999 |
| b15 方案 | 2026-10 | IDM 6.43 Build 15：根因确认（counterfeit 自伤闭环），P1–P15 全量 24 点 |
