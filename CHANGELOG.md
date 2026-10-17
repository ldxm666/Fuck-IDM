# 更新日志（CHANGELOG）

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.1] - 2026-10-17

修复实机反馈的 **「后台挂一段时间后弹 `IDM is corrupt`（主程序已损坏）」**。

### 根因

IDM 会**绕过 hosts** 直连授权/更新服务器做联网校验，发现主程序被修改后弹损坏提示。
两条独立证据：

1. **官方自述**：`Languages\*.lng` 里原文写着
   *"IDM will check for updates successfully even with your damaged hosts file."*
2. **实测**：hosts 6/6 全绿时，`www.` / `secure.` / `register.internetdownloadmanager.com`
   仍解析到 `67.18.60.145` / `67.18.140.140`，`ping` 可达。

### 修复

- **新增层 C 第三层：防火墙出站阻断**（`FuckIDM-Block-AuthServers`）
  - `dir=out action=block program=<IDMan.exe> remoteip=67.18.0.0/16 profile=any`
  - 只挡 IDM 服务器网段，**不影响正常下载**
  - `--activate` 施加 / `--uninstall` 移除 / `--status` 显示
- **修掉一个真 bug：hosts 3 行被注释导致「生效 3/6 却判成功」**
  - `HOSTS_DOMAINS` 从 6 个扩到 **11 个**：补 `update.` / `support.` / `idm.` 与
    `secure.tonec.com` / `register.tonec.com`
  - 起因：hosts 是**精确匹配**，写 `internetdownloadmanager.com` 并不覆盖
    `www.internetdownloadmanager.com` —— 父域名屏蔽 ≠ 子域名屏蔽
- `firewall_state()` 区分「无规则」与「无权查询」：非管理员下 `netsh` 返回
  `requires elevation` 时返回 `unknown`，**不再误报「未设置」**

### 排查记录（供后续复现）

| 观测 | 结论 |
| --- | --- |
| 补丁完整性 | ✅ 20/24 点认回，自证哈希 = 装机 `B6C45453…` |
| PE CheckSum | ✅ stored = 计算值（引擎 `ensure_pe_checksum` 已处理） |
| 数字签名校验 | ❌ IDM **没有** `WinVerifyTrust` 导入 → corrupt 不是签名问题 |
| 「检查更新」菜单（网络放开 A/B） | 90 s 无弹窗 → 不是这条命令直接触发 |
| 下载触发（1 MB 本地 HTTP） | 150 s 无弹窗 |
| 文案定位 | `The main IDM executive file is damaged.` @ `.data` VA `0x37C5CC`（XOR `0x3D`） |
| 完整正文 | **不在本地任何文件**（11 个 exe/dll/lng 全扫）→ 服务端下发 |

### 新增

- `README` 新增 FAQ **Q5**（corrupt 弹窗的成因与三层防御）
- `docs/FAQ.md` 同步该章节

---

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
